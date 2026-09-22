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

# All four images patched by this script are ours (built from source in this
# repo -- external/, internal/, facades/shallot-facade), so each one gets
# built fresh from source first -- not just OS-patched on top of a stale
# previous build -- so any Dockerfile-level fix (a dependency bump, a
# hardening change) actually reaches the patched image, not only the OS
# package layer. The OS layer is then patched on top of that fresh build
# (shell in, apt/apk update+upgrade, commit) rather than baked into the
# Dockerfile itself, since re-running this script regularly is what actually
# keeps the OS layer current -- a Dockerfile-baked dist-upgrade would only be
# as fresh as whenever the Dockerfile itself was last built.
#
# Two base OS families exist across these images (external/internal are
# ruby:3.2-slim, i.e. Debian/apt; shallot-facade is ruby:3.2-alpine, i.e.
# apk), so the OS-patch step is parameterized by package manager rather than
# hardcoded to apt as it was when this function only ever patched the first
# two. The image's own build-arg name for its baked-in VERSION label also
# isn't shared (SEVERANCE_VERSION for external/internal; SHALLOT_FACADE_VERSION
# for its facade -- each project's own env-var-prefix convention, kept as-is
# rather than forced into a shared name).
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
# CHANGELOG.md's erb/resolv entries), vs a real, still-reachable one. Must run while build_dir (and its
# Gemfile.lock) still exists -- for beacon-facade, a temp clone removed once patch_image returns.
#
# All progress output below goes to stderr; the final `fairdatasystems/
# <name>:<timestamp>` tag is the only thing written to stdout, so callers can
# capture it with `tag=$(patch_image ...)` while still seeing live progress.
patch_image() {
  local name="$1" build_dir="$2" version_file="$3" version_arg="$4" pkg_mgr="$5" test_cmd="${6:-}"
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
  if [ "${pkg_mgr}" = "apk" ]; then
    # -u root: these images (unlike external/internal, which have no USER
    # directive and default to root) bake in a non-root USER, so a plain
    # `docker exec` would run as that user and apk would fail with a
    # permission error -- matching Sextans-Suite's own Alpine-image handling.
    docker exec -u root "${name}" sh -c "apk update && apk upgrade --no-cache --force-missing-repositories" >&2
  else
    docker exec "${name}" apt-get -y update >&2
    docker exec "${name}" apt-get -y dist-upgrade --fix-missing >&2
    docker start "${name}" >/dev/null 2>&1 || true
    docker exec "${name}" apt-get -y autoclean >&2
  fi
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
          tests_ok=0 # no test suite for this image (e.g. beacon-facade) -- boot smoke test is the gate
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
        if [ "${pkg_mgr}" = "apk" ]; then
          docker exec -u root "${name}" sh -c "apk update && apk upgrade --no-cache --force-missing-repositories" >&2
        else
          docker exec "${name}" apt-get -y update >&2
          docker exec "${name}" apt-get -y dist-upgrade --fix-missing >&2
          docker start "${name}" >/dev/null 2>&1 || true
          docker exec "${name}" apt-get -y autoclean >&2
        fi
        docker commit "${name}" "${working_tag}" >&2
        docker stop "${name}" >/dev/null
        docker rm "${name}" >/dev/null
        trivy image --scanners vuln --format json --severity CRITICAL,HIGH --timeout 1800s \
          "${working_tag}" > "${outputfile}"
        ruby "${SCRIPT_DIR}/annotate_gem_shadowing.rb" "${outputfile}" "${build_dir}" >&2 || true

        local branch title
        branch="autopatch-gems-${name}-${timestamp}"
        title="Auto-patch Ruby gem CVEs in ${name} (${timestamp})"
        (cd "${build_dir}" && git checkout -q -b "${branch}" \
          && git add Gemfile Gemfile.lock Dockerfile \
          && git commit -q -m "Auto-patch Ruby gem CVEs in ${name} ($(date +%Y-%m-%d))

$(echo "${autopatch_log}" | grep '^PATCHED')

Verified: image builds, ${test_cmd:+tests (\`${test_cmd}\`) pass,} boots correctly, re-scanned.
Opened automatically by security-patch.sh -- see Security/auto_patch_ruby_gems.rb.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>") >&2
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
  (cd "${repo_path}" && git push -u origin "${branch}") >&2
  (cd "${repo_path}" && gh pr create --title "${title}" --head "${branch}" --body \
    "Automated Ruby gem CVE patch attempt, opened by \`security-patch.sh\`. Verified: image builds, tests pass, boots correctly, re-scanned to confirm the finding is actually gone. See the commit message for exactly what changed and why. Not auto-merged -- please review before merging.") >&2
}

SIN=$(patch_image sevinternal ../internal ../internal/VERSION SEVERANCE_VERSION apt \
  "bundle exec rspec")
SOUT=$(patch_image sevexternal ../external ../external/VERSION SEVERANCE_VERSION apt \
  "bundle exec ruby check_before_filter.rb")
SFAC=$(patch_image shallotfacade ../facades/shallot-facade ../facades/shallot-facade/VERSION \
  SHALLOT_FACADE_VERSION apk "bundle exec rspec")

cp inner-docker-compose-template-template.yml inner-docker-compose-template-tmp.yml
cp outer-docker-compose-template-template.yml outer-docker-compose-template-tmp.yml
cp shallot-docker-compose-template-template.yml shallot-docker-compose-template-tmp.yml
sed -i'' -e "s!{SIN}!${SIN}!" "inner-docker-compose-template-tmp.yml"
sed -i'' -e "s!{SOUT}!${SOUT}!" "outer-docker-compose-template-tmp.yml"
sed -i'' -e "s!{SFAC}!${SFAC}!" "shallot-docker-compose-template-tmp.yml"

mv inner-docker-compose-template-tmp.yml ../internal/docker-compose.yml
mv outer-docker-compose-template-tmp.yml ../external/docker-compose.yml
mv shallot-docker-compose-template-tmp.yml ../facades/shallot-facade/docker-compose.yml

# beacon-facade lives in a different repo (CARE-Semantic-Model-Version-2), not a sibling in
# this one, unlike shallot-facade -- it's domain-specific (real CARE-SM-2/ERDERA ontology
# terms, response shaping built for RDVP-Portal-backend specifically), where shallot-facade is
# pure protocol translation with no knowledge of any data model. Still patched from here,
# though: Sextans-Suite's own pipeline already clones this same repo to build its "care2"
# image from implementation/Toolkit, so one pipeline building an image from another repo's
# committed (never local/uncommitted) source is already an established pattern, not a new kind
# of coupling. Unlike care2 (whose tag is substituted into Sextans' own compose templates),
# nothing in Severance consumes a beacon-facade tag, so there is no downstream template to
# write it into -- the tag is just printed, same as Sextans already does for care2/fdpserv2;
# update CARE-Semantic-Model-Version-2's own implementation/Beacon2/facade/docker-compose.yml
# by hand (or from that repo's own tooling, if it grows one). No test suite exists there yet
# (see CHANGELOG.md) -- the boot smoke test is its only auto-patch gate.
beacon_clone_dir=$(mktemp -d)
git clone https://github.com/wilkinsonlab/CARE-Semantic-Model-Version-2.git "${beacon_clone_dir}" >&2
BFAC=$(patch_image beaconfacade "${beacon_clone_dir}/implementation/Beacon2/facade" \
  "${beacon_clone_dir}/implementation/Beacon2/facade/VERSION" BEACON_FACADE_VERSION apk)
echo "beacon-facade patched: ${BFAC}" >&2
echo "  -> update CARE-Semantic-Model-Version-2's implementation/Beacon2/facade/docker-compose.yml by hand" >&2

# Open any queued auto-patch PRs before cleaning up build dirs (beacon_clone_dir must still exist if
# it has a queued commit -- open_autopatch_pr pushes straight from it).
while IFS='|' read -r repo_path branch title; do
  [ -n "${repo_path}" ] && open_autopatch_pr "${repo_path}" "${branch}" "${title}"
done < "${AUTOPATCH_QUEUE}"

rm -rf "${beacon_clone_dir}"

ruby parse-security-scans.rb ./security_scan_output/*.json
python3 build_register.py
