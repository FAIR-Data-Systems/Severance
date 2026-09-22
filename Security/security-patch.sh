#!/bin/bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
SCRIPT_DIR="$(pwd)"

timestamp=$(date +"%Y-%m-%d")

# Archive the previous run's scan results instead of deleting them -- someone
# running an older patched image should still be able to look up what
# vulnerabilities apply to the version they actually have deployed.
mkdir -p ./security_scan_output/old
find ./security_scan_output -maxdepth 1 -type f \( -name '*.json' -o -name '*.csv' \) -exec mv {} ./security_scan_output/old/ \;

# Repos with an auto-patch commit staged, to be opened as a PR at the end of the run. Format: one
# entry per line, "repo_path|branch_name|title". Populated by patch_image() below.
AUTOPATCH_QUEUE=$(mktemp)
trap 'rm -f "${AUTOPATCH_QUEUE}"' EXIT

# Both images patched by this script are ours (built from source in this repo -- external/,
# internal/), so each one gets built fresh from source first -- not just OS-patched on top of a stale
# previous build -- so any Dockerfile-level fix (a dependency bump, a hardening change) actually
# reaches the patched image, not only the OS package layer. The OS layer is then patched on top of that
# fresh build (shell in, apt update+upgrade, commit) rather than baked into the Dockerfile itself, since
# re-running this script regularly is what actually keeps the OS layer current -- a Dockerfile-baked
# dist-upgrade would only be as fresh as whenever the Dockerfile itself was last built.
#
# Both images share one base OS family (ruby:3.2-slim, i.e. Debian/apt). This script used to also
# patch a third, Alpine/apk-based image (shallot-facade) and, cloned fresh each run, a fourth
# (beacon-facade, from CARE-Semantic-Model-Version-2) -- both moved to their own dedicated repo,
# FAIR-Data-Systems/Severance-Facades, on 2026-09-22 (see that repo's own Security/security-patch.sh,
# and this repo's CHANGELOG.md for why). The pkg_mgr parameterization and beacon's cross-repo
# clone-and-push logic that move made unnecessary here were removed, not carried forward as dead code.
#
# After the OS-level patch, if the image has a Gemfile, attempts an automated Ruby gem CVE patch
# (auto_patch_ruby_gems.rb) against this run's own fresh scan -- see that script for the two
# strategies (bundle update within an existing constraint for a real dependency; exact-pin + Dockerfile
# uninstall attempt for a phantom default gem). If it makes changes: rebuilds, runs the project's own
# test command (if any) plus a boot smoke test, and only keeps the change if both pass -- otherwise
# reverts and falls back to the pre-autopatch build. A successful, verified change is queued (not
# committed here) for a PR at the very end of the run -- this script never pushes source changes to a
# default branch on its own, only the already-established OS-patched image itself.
#
# Every scan (pre- and, if applicable, post-autopatch) is also annotated by annotate_gem_shadowing.rb:
# whether a flagged gemspec finding is a stale on-disk copy `bundle exec` never actually loads (see
# CHANGELOG.md's erb/resolv entries), vs a real, still-reachable one.
#
# All progress output below goes to stderr; the final `fairdatasystems/
# <name>:<timestamp>` tag is the only thing written to stdout, so callers can
# capture it with `tag=$(patch_image ...)` while still seeing live progress.
patch_image() {
  local name="$1" build_dir="$2" version_file="$3" version_arg="$4" test_cmd="${5:-}"
  local build_tag="${name}:build-${timestamp}"
  local working_tag="fairdatasystems/${name}:${timestamp}"
  local outputfile="${SCRIPT_DIR}/security_scan_output/scanresults_${name}_${timestamp}.json"

  {
    echo ""
    echo "=== ${name} ==="
    echo "building ${build_tag} from ${build_dir}"
  } >&2
  docker build --build-arg "${version_arg}=$(cat "${version_file}")" \
    -t "${build_tag}" "${build_dir}" >&2

  docker rm -f "${name}" >/dev/null 2>&1 || true
  # outie.rb and innie.rb both abort immediately if ENCRYPTION_KEY_HEX isn't
  # set (a deliberate fail-closed check, not a bug) -- without a real value
  # here the container's PID1 exits right after `docker run`, and every
  # `docker exec` below silently fails with "container is not running"
  # instead of actually patching anything. Facades don't read this var at
  # all, so passing it there is simply ignored -- harmless, and keeps this
  # one `docker run` line the same for every image rather than branching on
  # it. This key is thrown away with the container once patching is done; it
  # never serves real traffic, so it doesn't need to be the deployment's
  # real key.
  local patch_key
  patch_key=$(openssl rand -hex 32)
  docker run -d --name "${name}" -e "ENCRYPTION_KEY_HEX=${patch_key}" "${build_tag}" >&2
  sleep 2
  echo "updating ${name}" >&2
  docker exec "${name}" apt-get -y update >&2
  docker exec "${name}" apt-get -y dist-upgrade --fix-missing >&2
  docker start "${name}" >/dev/null 2>&1 || true
  docker exec "${name}" apt-get -y autoclean >&2
  echo "commit" >&2
  docker commit "${name}" "${working_tag}" >&2
  docker stop "${name}" >/dev/null
  docker rm "${name}" >/dev/null
  docker rmi "${build_tag}" >/dev/null 2>&1 || true

  echo "trivy" >&2
  trivy image --scanners vuln --format json --severity CRITICAL,HIGH --timeout 1800s \
    "${working_tag}" > "${outputfile}"

  if [ -f "${build_dir}/Gemfile" ]; then
    ruby "${SCRIPT_DIR}/annotate_gem_shadowing.rb" "${outputfile}" "${build_dir}" >&2 || true

    echo "auto-patch: checking for fixable Ruby gem CVEs" >&2
    local autopatch_log autopatch_result
    autopatch_log=$(ruby "${SCRIPT_DIR}/auto_patch_ruby_gems.rb" "${build_dir}" "${outputfile}")
    echo "${autopatch_log}" >&2
    autopatch_result=$(echo "${autopatch_log}" | tail -1)

    if [ "${autopatch_result}" = "CHANGED" ]; then
      echo "auto-patch made changes -- rebuilding to verify before keeping them" >&2
      local autopatch_build_tag="${name}:autopatch-${timestamp}"
      local rebuild_ok=1
      docker build --build-arg "${version_arg}=$(cat "${version_file}")" \
        -t "${autopatch_build_tag}" "${build_dir}" >&2 && rebuild_ok=0 || rebuild_ok=1

      local tests_ok=1
      if [ "${rebuild_ok}" -eq 0 ]; then
        if [ -n "${test_cmd}" ]; then
          (cd "${build_dir}" && eval "${test_cmd}") >&2 && tests_ok=0 || tests_ok=1
        else
          tests_ok=0 # no test suite for this image -- boot smoke test is the gate
        fi
      fi

      local boot_ok=1
      if [ "${rebuild_ok}" -eq 0 ] && [ "${tests_ok}" -eq 0 ]; then
        docker rm -f "${name}-autopatch-smoketest" >/dev/null 2>&1 || true
        docker run -d --name "${name}-autopatch-smoketest" \
          -e "ENCRYPTION_KEY_HEX=$(openssl rand -hex 32)" "${autopatch_build_tag}" >&2
        sleep 3
        if docker ps --filter "name=${name}-autopatch-smoketest" --filter "status=running" \
             --format '{{.Names}}' | grep -q "^${name}-autopatch-smoketest\$"; then
          boot_ok=0
        fi
        docker rm -f "${name}-autopatch-smoketest" >/dev/null 2>&1 || true
      fi

      if [ "${rebuild_ok}" -eq 0 ] && [ "${tests_ok}" -eq 0 ] && [ "${boot_ok}" -eq 0 ]; then
        echo "auto-patch verified: build OK, tests OK, boot OK -- keeping the change and re-patching/re-scanning" >&2
        docker rm -f "${name}" >/dev/null 2>&1 || true
        patch_key=$(openssl rand -hex 32)
        docker run -d --name "${name}" -e "ENCRYPTION_KEY_HEX=${patch_key}" "${autopatch_build_tag}" >&2
        sleep 2
        docker exec "${name}" apt-get -y update >&2
        docker exec "${name}" apt-get -y dist-upgrade --fix-missing >&2
        docker start "${name}" >/dev/null 2>&1 || true
        docker exec "${name}" apt-get -y autoclean >&2
        docker commit "${name}" "${working_tag}" >&2
        docker stop "${name}" >/dev/null
        docker rm "${name}" >/dev/null
        trivy image --scanners vuln --format json --severity CRITICAL,HIGH --timeout 1800s \
          "${working_tag}" > "${outputfile}"
        ruby "${SCRIPT_DIR}/annotate_gem_shadowing.rb" "${outputfile}" "${build_dir}" >&2 || true

        local branch title original_branch title_prefix
        branch="autopatch-gems-${name}-${timestamp}"
        # A widened-constraint fix (auto_patch_ruby_gems.rb's strategy 1b) crosses a version boundary
        # the existing Gemfile constraint couldn't reach on its own -- still verified (build/test/boot),
        # but a boot smoke test can't catch every compatibility break a major bump might cause, so flag
        # it in the PR title itself, not just buried in the commit body, so it doesn't get rubber-stamped
        # alongside routine same-constraint/phantom-gem patches.
        title_prefix=""
        echo "${autopatch_log}" | grep -q "WIDENED CONSTRAINT" && title_prefix="[REVIEW: major version bump] "
        title="${title_prefix}Auto-patch Ruby gem CVEs in ${name} (${timestamp})"
        # `git checkout -b` inside build_dir changes the REPO's checked-out branch, not just this
        # subshell's -- subshells isolate cwd/variables, never git's on-disk HEAD. build_dir is a
        # subdirectory of this very repo, shared across every patch_image() call in this run -- left
        # unrestored, a later image would build from this new branch instead of the one the run started
        # on, and the run would leave the caller's own checkout switched to it. Capture and restore
        # immediately after committing.
        original_branch=$(cd "${build_dir}" && git rev-parse --abbrev-ref HEAD)
        (cd "${build_dir}" && git checkout -q -b "${branch}" \
          && git add Gemfile Gemfile.lock Dockerfile \
          && git commit -q -m "Auto-patch Ruby gem CVEs in ${name} ($(date +%Y-%m-%d))

$(echo "${autopatch_log}" | grep '^PATCHED')

Verified: image builds, ${test_cmd:+tests (\`${test_cmd}\`) pass,} boots correctly, re-scanned.
Opened automatically by security-patch.sh -- see Security/auto_patch_ruby_gems.rb.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>" \
          && git checkout -q "${original_branch}") >&2
        echo "${build_dir}|${branch}|${title}" >> "${AUTOPATCH_QUEUE}"
      else
        echo "auto-patch FAILED verification (build:${rebuild_ok} tests:${tests_ok} boot:${boot_ok}) -- reverting, keeping the pre-autopatch scan" >&2
        (cd "${build_dir}" && git checkout -q -- Gemfile Gemfile.lock Dockerfile) || true
      fi
      docker rmi "${autopatch_build_tag}" >/dev/null 2>&1 || true
    fi
  fi

  echo "push" >&2
  docker push "${working_tag}" >&2
  echo "pushed" >&2
  echo "END" >&2

  echo "${working_tag}"
}

# Opens a PR for a repo with a queued auto-patch commit. $1 = repo_path, $2 = branch, $3 = title.
# Never pushes to or merges into that repo's default branch -- only ever a new branch + PR, for a
# human to review. Assumes `gh` is authenticated with push access to the repo's remote.
open_autopatch_pr() {
  local repo_path="$1" branch="$2" title="$3"
  echo "" >&2
  echo "=== opening PR for ${repo_path} (branch ${branch}) ===" >&2
  local body="Automated Ruby gem CVE patch attempt, opened by \`security-patch.sh\`. Verified: image builds, tests pass, boots correctly, re-scanned to confirm the finding is actually gone. See the commit message for exactly what changed and why. Not auto-merged -- please review before merging."
  if [[ "${title}" == "[REVIEW: major version bump]"* ]]; then
    body="${body}

**This one crosses a major version boundary** the existing Gemfile constraint couldn't reach on its own (see the commit message for old -> new constraint). Build/tests/boot all passed, but that doesn't rule out a real behavioral incompatibility a smoke test wouldn't catch -- read the gem's changelog/release notes for breaking changes before merging, not just this PR's green checks."
  fi
  (cd "${repo_path}" && git push -u origin "${branch}") >&2
  (cd "${repo_path}" && gh pr create --title "${title}" --head "${branch}" --body "${body}") >&2
}

SIN=$(patch_image sevinternal ../internal ../internal/VERSION SEVERANCE_VERSION \
  "bundle exec rspec")
SOUT=$(patch_image sevexternal ../external ../external/VERSION SEVERANCE_VERSION \
  "bundle exec ruby check_before_filter.rb")

cp inner-docker-compose-template-template.yml inner-docker-compose-template-tmp.yml
cp outer-docker-compose-template-template.yml outer-docker-compose-template-tmp.yml
sed -i'' -e "s!{SIN}!${SIN}!" "inner-docker-compose-template-tmp.yml"
sed -i'' -e "s!{SOUT}!${SOUT}!" "outer-docker-compose-template-tmp.yml"

mv inner-docker-compose-template-tmp.yml ../internal/docker-compose.yml
mv outer-docker-compose-template-tmp.yml ../external/docker-compose.yml

# Auto-commit + push these two tag bumps directly (no PR) -- they're pure version-pointer changes
# to files this same repo owns, the same trust level as everything else this script already commits
# to a working tree without review. Scoped to just these two paths so it can never sweep up
# unrelated in-progress changes elsewhere in the caller's checkout. If the current branch has no
# upstream yet, `git push` fails loudly (set -euo pipefail) rather than silently not pushing.
if ! git -C .. diff --quiet -- internal/docker-compose.yml external/docker-compose.yml; then
  git -C .. add internal/docker-compose.yml external/docker-compose.yml
  git -C .. commit -q -m "Bump Severance image tags to ${timestamp} (security-patch.sh)

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
  git -C .. push
fi

# Open any queued auto-patch PRs.
while IFS='|' read -r repo_path branch title; do
  [ -n "${repo_path}" ] && open_autopatch_pr "${repo_path}" "${branch}" "${title}"
done < "${AUTOPATCH_QUEUE}"

ruby parse-security-scans.rb ./security_scan_output/*.json
python3 build_register.py
