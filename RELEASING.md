# Releasing Severance

Versioning and release mechanics for maintainers. If you're looking to install or use Severance, see
[`README.md`](README.md) instead.

## Version files

`VERSION`, `external/VERSION`, and `internal/VERSION` are copies kept in sync for each component's own
Docker build context -- **bump all three together when releasing.**

Both `external/Dockerfile` and `internal/Dockerfile` bake this in as an
`org.opencontainers.image.version` label via a `SEVERANCE_VERSION` build arg, e.g.:

    docker build --build-arg SEVERANCE_VERSION="$(cat VERSION)" -t sevexternal:$(cat VERSION) external/
    docker build --build-arg SEVERANCE_VERSION="$(cat VERSION)" -t sevinternal:$(cat VERSION) internal/

The running services also report it themselves: External's `GET /severance` includes it in its
plain-text response, and Internal logs it once at startup (it has no HTTP endpoint of its own to query
it from).

## Cutting a release

1. Bump `VERSION`, `external/VERSION`, and `internal/VERSION` together to the new version number.
2. Move `CHANGELOG.md`'s `## [Unreleased]` content under a new `## [<version>] - <date>` heading,
   leaving a fresh empty `## [Unreleased]` at the top.
3. Update the version number in `README.md`'s one-line version callout.
4. Commit, then tag and push:

       git tag -a v<version> -m "Release <version>"
       git push origin v<version>

5. Create a GitHub release from the tag, with notes pulled from the `CHANGELOG.md` section for that
   version:

       gh release create v<version> --title "<version>" --notes-file <(awk '/^## \[<version>\]/{flag=1; next} /^## \[/{flag=0} flag' CHANGELOG.md)

## Security patching

`Security/security-patch.sh` handles OS-level and Ruby-gem CVE patching independently of version
releases above -- it pushes dated image tags (`fairdatasystems/sevexternal:<date>`,
`fairdatasystems/sevinternal:<date>`) to Docker Hub and regenerates `external/docker-compose.yml`/
`internal/docker-compose.yml` accordingly, without touching `VERSION`. See
`Security/VULNERABILITY_TRIAGE.md` for that process. Facades (`shallot-facade`, `beacon-facade`) have
their own separate release/patch process in
[`FAIR-Data-Systems/Severance-Facades`](https://github.com/FAIR-Data-Systems/Severance-Facades).
