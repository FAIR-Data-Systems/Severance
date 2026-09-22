#!/usr/bin/env ruby
# frozen_string_literal: true

# Annotates a Trivy scan JSON's gemspec findings with whether the flagged on-disk copy is actually the
# one `bundle exec` loads at runtime -- the erb/resolv situation (see CHANGELOG.md): a compiled default
# gem's stale, vulnerable copy can't be uninstalled and stays physically present (so Trivy correctly
# keeps flagging it), but the app only ever runs via `bundle exec`, which resolves the newer,
# Gemfile-pinned copy first. Without this, a scan/CSV/register reader has no way to tell "still really
# exploitable" apart from "physically present, never loaded" without redoing this exact investigation
# by hand each time.
#
# Mutates the scan JSON in place, adding two keys to each gemspec Vulnerability entry:
#   - "ShadowedByBundler": true / false -- only ever set (not nil) for gemspec-class findings
#   - "ShadowedDetail": a short human-readable explanation
#
# Must run while `build_dir` (and its Gemfile.lock) still exists -- i.e. from security-patch.sh's
# patch_image(), before any cleanup (a cloned build_dir like beacon-facade's gets rm -rf'd once that
# image's patch_image call returns).
#
# Usage: ruby annotate_gem_shadowing.rb <scan.json> <build_dir>

require 'json'
require 'bundler'

def usage_and_exit
  warn 'Usage: ruby annotate_gem_shadowing.rb <scan.json> <build_dir>'
  exit 1
end

scan_path, build_dir = ARGV
usage_and_exit unless scan_path && build_dir && File.exist?(scan_path)

lockfile_path = File.join(build_dir, 'Gemfile.lock')

resolved_versions =
  if File.exist?(lockfile_path)
    Bundler::LockfileParser.new(File.read(lockfile_path)).specs.to_h { |s| [s.name, s.version.to_s] }
  else
    {}
  end

scan = JSON.parse(File.read(scan_path))

(scan['Results'] || []).each do |result|
  next unless result['Class'] == 'lang-pkgs' && result['Type'] == 'gemspec'

  (result['Vulnerabilities'] || []).each do |vuln|
    pkg = vuln['PkgName']
    resolved = resolved_versions[pkg]
    flagged = vuln['InstalledVersion']

    if resolved && resolved != flagged
      vuln['ShadowedByBundler'] = true
      vuln['ShadowedDetail'] = "bundle exec loads #{pkg} #{resolved} (Gemfile-pinned); the flagged " \
                                "#{flagged} is a stale copy on disk, never loaded at runtime"
    else
      vuln['ShadowedByBundler'] = false
      vuln['ShadowedDetail'] = resolved ? "bundle exec also loads the flagged #{flagged} -- real, unaddressed" \
                                         : "#{pkg} is not declared in Gemfile.lock at all -- real, unaddressed"
    end
  end
end

File.write(scan_path, JSON.pretty_generate(scan))
puts "Annotated #{scan_path} against #{lockfile_path}"
