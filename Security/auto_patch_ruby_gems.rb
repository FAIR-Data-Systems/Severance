#!/usr/bin/env ruby
# frozen_string_literal: true

# Attempts to auto-patch Ruby gem CVEs found by a Trivy scan, for an owned image built from source.
#
# Scope, deliberately: this only ever touches Gemfile/Gemfile.lock/Dockerfile in `build_dir`, never
# pushes an image or touches git itself -- the caller (security-patch.sh) decides what to do with the
# result (rebuild, test, and either keep or `git checkout --` revert the changes). This script's job is
# just "given a scan, make the best safe attempt, and say clearly what happened."
#
# Two fix strategies, matching what was proven by hand this session (see CHANGELOG.md's net-imap/erb/
# resolv/puma entries):
#
# 1. **Declared dependency** (the gem is in Gemfile.lock -- something we actually use, e.g. puma):
#    `bundle update <gem>`, constrained by whatever the Gemfile *already* says. Never loosens the
#    existing constraint -- if the resolved version still doesn't reach a fixed version, that means the
#    fix requires a constraint change (a real decision, e.g. a major version bump), which this script
#    deliberately does NOT make on its own. Flagged as skipped, not silently left half-changed.
#
# 2. **Phantom default gem** (not in Gemfile.lock at all -- a stale copy baked into the Ruby base image,
#    unused by our own code, e.g. net-imap/erb/resolv): `bundle add` to resolve a real patched version,
#    then rewritten to an exact pin (not `~>`) -- since nothing calls into it, there's no compatibility
#    range worth protecting, matching the existing net-imap/erb/resolv precedent. Also adds a
#    `gem uninstall ... || true` line to the Dockerfile if one doesn't already exist for that gem,
#    anchored after the last existing such line (every Dockerfile this targets already has at least one,
#    from the net-imap fix).
#
# Usage: ruby auto_patch_ruby_gems.rb <build_dir> <trivy_scan.json>
# Exit status: 0 always, unless invoked wrong -- a skipped/unfixable gem is not a script failure, it's
# a normal, expected outcome to report. Prints one PATCHED/SKIPPED/CLEAN line per candidate gem to
# stdout, and a final "CHANGED" or "NO_CHANGES" line the caller can grep for.

require 'json'
require 'fileutils'
require 'rubygems/requirement'
require 'shellwords'
require 'English'
require 'bundler'

def usage_and_exit
  warn 'Usage: ruby auto_patch_ruby_gems.rb <build_dir> <trivy_scan.json>'
  exit 1
end

build_dir, scan_path = ARGV
usage_and_exit unless build_dir && scan_path && File.directory?(build_dir) && File.exist?(scan_path)

gemfile_path = File.join(build_dir, 'Gemfile')
lockfile_path = File.join(build_dir, 'Gemfile.lock')
dockerfile_path = File.join(build_dir, 'Dockerfile')
usage_and_exit unless File.exist?(gemfile_path) && File.exist?(lockfile_path) && File.exist?(dockerfile_path)

# Trivy's FixedVersion is a comma-separated list of ALTERNATIVES (fixed on any ONE branch clears the
# CVE), not a combined AND -- e.g. "~> 4.0.3.1, ~> 4.0.4.1, ~> 6.0.1.1, >= 6.0.4" means "4.0.3.1+ OR
# 4.0.4.x+ OR 6.0.1.1+ OR 6.0.4+", not all four at once. Gem::Requirement.new on the whole string would
# wrongly AND them together.
def fixed_version_alternatives(raw)
  raw.split(',').map { |clause| Gem::Requirement.new(clause.strip) }
end

def satisfies_any?(version_str, alternatives)
  version = Gem::Version.new(version_str)
  alternatives.any? { |req| req.satisfied_by?(version) }
end

def resolved_version(lockfile_path, gem_name)
  lock = Bundler::LockfileParser.new(File.read(lockfile_path))
  spec = lock.specs.find { |s| s.name == gem_name }
  spec&.version&.to_s
end

def declared?(lockfile_path, gem_name)
  !resolved_version(lockfile_path, gem_name).nil?
end

def run(cmd, chdir:)
  out = `cd #{chdir.shellescape} && #{cmd} 2>&1`
  [out, $CHILD_STATUS.success?]
end

def git_revert(build_dir, *paths)
  system('git', '-C', build_dir, 'checkout', '--', *paths, out: File::NULL, err: File::NULL)
end

scan = JSON.parse(File.read(scan_path))
gemspec_results = (scan['Results'] || []).select { |r| r['Class'] == 'lang-pkgs' && r['Type'] == 'gemspec' }
findings = gemspec_results.flat_map { |r| r['Vulnerabilities'] || [] }
                          .select { |v| v['FixedVersion'] && v['FixedVersion'] != 'N/A' }
                          .group_by { |v| v['PkgName'] }

if findings.empty?
  puts 'No fixable gemspec findings in this scan.'
  puts 'NO_CHANGES'
  exit 0
end

any_change = false

findings.each do |pkg_name, vulns|
  cve_ids = vulns.map { |v| v['VulnerabilityID'] }.join(', ')
  # Trivy repeats the same FixedVersion string for every CVE against a given installed version of a
  # package in practice; take the first, they're consistent within one scan.
  alternatives = fixed_version_alternatives(vulns.first['FixedVersion'])

  if declared?(lockfile_path, pkg_name)
    # === Strategy 1: a real, used dependency -- bundle update within the EXISTING Gemfile constraint ===
    before = resolved_version(lockfile_path, pkg_name)
    out, ok = run("bundle update #{pkg_name.shellescape}", chdir: build_dir)
    unless ok
      puts "SKIPPED #{pkg_name} (#{cve_ids}): `bundle update` failed -- #{out.lines.last&.strip}"
      git_revert(build_dir, 'Gemfile.lock')
      next
    end

    after = resolved_version(lockfile_path, pkg_name)
    if !satisfies_any?(after, alternatives)
      puts "SKIPPED #{pkg_name} (#{cve_ids}): existing Gemfile constraint can't reach a fixed version " \
           "(resolved #{after}, need one of #{alternatives.map(&:to_s).join(' | ')}) -- needs a deliberate " \
           'constraint change, not attempted automatically'
      git_revert(build_dir, 'Gemfile.lock')
    elsif after == before
      # Already at (or past) a fixed version before this ran -- e.g. shallot-facade's erb/resolv are
      # *declared* (exact-pinned) from an earlier manual fix, so this hits the declared-dependency
      # branch, but there's nothing left to do. Not a real change: don't report PATCHED, don't trigger
      # a pointless rebuild/retest/commit cycle upstream.
      puts "CLEAN #{pkg_name} #{after} already satisfies a fixed version (#{cve_ids}) -- nothing to do " \
           '(Trivy may still flag an unrelated stale on-disk copy; see annotate_gem_shadowing.rb)'
      git_revert(build_dir, 'Gemfile.lock') # bundle update may have touched unrelated transitive pins
    else
      puts "PATCHED #{pkg_name} #{before} -> #{after} (#{cve_ids}) [existing constraint, declared dependency]"
      any_change = true
    end
  else
    # === Strategy 2: a phantom default gem -- bundle add, then rewrite to an exact pin ===
    target = alternatives.last.to_s # the open-ended ">= x.y.z" branch, by convention the last one Trivy lists
    out, ok = run("bundle add #{pkg_name.shellescape} --version #{target.shellescape}", chdir: build_dir)
    unless ok
      puts "SKIPPED #{pkg_name} (#{cve_ids}): `bundle add` failed -- #{out.lines.last&.strip}"
      git_revert(build_dir, 'Gemfile', 'Gemfile.lock')
      next
    end

    resolved = resolved_version(lockfile_path, pkg_name)
    unless resolved && satisfies_any?(resolved, alternatives)
      puts "SKIPPED #{pkg_name} (#{cve_ids}): resolved #{resolved.inspect} doesn't satisfy a fixed version"
      git_revert(build_dir, 'Gemfile', 'Gemfile.lock')
      next
    end

    # Rewrite the line bundle add just appended (always at the end of the file, in "gem "x", "y""
    # double-quoted style) into an exact pin, single-quoted to match this codebase's own style, and
    # move it to sit alongside the file's other top-level gem declarations rather than trailing after
    # a `group do...end` block -- matching the net-imap/erb/resolv precedent this mirrors.
    gemfile_lines = File.readlines(gemfile_path)
    added_index = gemfile_lines.rindex { |l| l =~ /^gem\s+["']#{Regexp.escape(pkg_name)}["']/ }
    if added_index
      added_line = "gem '#{pkg_name}', '#{resolved}'\n"
      gemfile_lines.delete_at(added_index)
      # Insert after the last top-level (non-grouped, non-comment) gem line, before any `group do`.
      insert_at = gemfile_lines.rindex { |l| l =~ /^gem\s/ && !l.start_with?('  ') }
      insert_at ||= gemfile_lines.length
      gemfile_lines.insert(insert_at + 1, added_line)
      # `bundle add` leaves a blank separator line where its own appended line used to be; strip any
      # trailing blank lines so removing that line doesn't leave stray whitespace at EOF.
      gemfile_lines.pop while gemfile_lines.last&.strip == ''
      File.write(gemfile_path, "#{gemfile_lines.join.rstrip}\n")
      run('bundle install', chdir: build_dir)
    end

    # Add a Dockerfile uninstall line for this gem's stale default-gem copy, if not already present.
    dockerfile = File.read(dockerfile_path)
    unless dockerfile.include?("gem uninstall") && dockerfile.match?(/gem uninstall[^\n]*\s#{Regexp.escape(pkg_name)}\s/)
      ruby_minor = dockerfile[/FROM ruby:(\d+\.\d+)/, 1] || '3.2'
      new_line = "RUN gem uninstall -i /usr/local/lib/ruby/gems/#{ruby_minor}.0 #{pkg_name} --all --force || true\n"
      lines = dockerfile.lines
      anchor = lines.rindex { |l| l.include?('gem uninstall') && l.include?('|| true') }
      if anchor
        lines.insert(anchor + 1, new_line)
      else
        # No existing anchor (shouldn't happen for the images this targets, which all already have a
        # net-imap uninstall line) -- fall back to right before the ARG *_VERSION line.
        arg_index = lines.index { |l| l.start_with?('ARG ') } || lines.length
        lines.insert(arg_index, new_line, "\n")
      end
      File.write(dockerfile_path, lines.join)
    end

    puts "PATCHED #{pkg_name} (was a phantom default gem) -> exact-pinned #{resolved} (#{cve_ids})"
    any_change = true
  end
end

puts(any_change ? 'CHANGED' : 'NO_CHANGES')
