# Changelog

All notable changes to this project are documented here. Format loosely follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Changed

- The vulnerability register's `ACCEPT` decision is now called `NOT REACHABLE`. The meaning is unchanged --
  reviewed individually, and nothing in Severance can reach the vulnerable code -- but "accepted" reads as
  "known risk, tolerated", which it never meant.

## [2.0.0] - 2026-11-06

**Breaking -- read [Upgrading from 1.1.0](external/README.md#upgrading-from-110) first.** New required
settings on both components (`INNIE_TOKEN`, a 32+ character `AUTH_TOKEN`), and External and Internal
must be upgraded together. Example queries are no longer installed automatically.

### Security

- External no longer accepts `multipart/form-data` request bodies (`415`), and they are refused before
  anything parses them. Sinatra parses request parameters before the authentication filter runs, so
  Rack's multipart parser was reachable without a token. No Severance route or known facade uses
  multipart. **If you run your own client or facade that sends multipart, switch it to JSON.**
- `rack` 3.2.7 -> 3.2.8 in External (GHSA-5v64-555j-wjxm, multipart memory exhaustion).
- Both images now use a multi-stage build: the compiler toolchain (`build-essential`, and the
  `linux-libc-dev` kernel headers it brings in) stays in the build stage. On 2026-11-06 this took each
  image from 243 Trivy findings to 52, including from 2 CRITICALs to none, and from about 637 MB to
  about 157 MB.
- First individual reachability research on every remaining finding (`Security/build_register.py`,
  `MANUAL_DECISIONS`), replacing the bulk "patch immediately" default that the register previously
  applied to every row -- including rows with no fix available.
- **Example queries are no longer copied into Internal's `./queries` automatically.** Every query there
  is live to anyone with `AUTH_TOKEN`, and one example (`patient_filter.rq`) returns person-level rows.
  Set `SEED_DEMO_QUERIES=true` to copy them in for testing. **Existing installs: delete any example
  in `./queries` you have not approved.**
- Internal refuses any query containing a SPARQL Update operation (`INSERT`, `DELETE`, `DROP`, `CLEAR`,
  `LOAD`, ...): it is left out of the catalogue and never run. Previously `validate_query` was a stub,
  and a read-only triplestore account was the only safeguard.
- `#+ enumerate:` lists are now enforced: a binding with an unlisted value is refused. They were
  advertised to callers but never checked -- and the parser silently dropped every one of them (a list
  item like `- country:` was taken for a section header).
- Uncollected results, and jobs stuck in "processing", are deleted after `RESULT_TTL_HOURS` (default 168,
  i.e. 7 days). Pending jobs are never expired.
- Secrets can be read from files: `ENCRYPTION_KEY_HEX_FILE`, `AUTH_TOKEN_FILE`, `INNIE_TOKEN_FILE`,
  `TRIPLESTORE_PASS_FILE` (e.g. Docker secrets), keeping them out of the container environment.
- **The published 2026-09-22 images still trust the compromised eMudhra/emSign certificate hierarchy**
  (`emSign ECC Root CA - G3`, `AAA Certificate Services`; October 2026, Debian DSA-6572-1). Images
  built from this release do not. Until you upgrade, don't let Internal reach External over a network
  you don't trust.
- `docker-compose.yml` files now pin each image by digest (`tag@sha256:...`), not by tag alone, so an
  image replaced under the same tag on Docker Hub is refused -- what happened to Vantage6's registry in
  March 2026.
- External accepts a result only for a job Internal has actually taken from the queue (`409`
  otherwise). Previously anything holding Internal's credentials could plant an answer under any job id.
- `Security/PEER_ADVISORIES.md`: every published Vantage6 security problem (39 advisories, plus two
  incidents they never published as advisories) mapped onto Severance -- fixed, safe by design, or
  still OPEN.

- Query bindings are now substituted in a single pass over the original query text.
- Internal authenticates its calls to External with a new required `INNIE_TOKEN` (in addition to the
  `ALLOWED_INTERNAL_IPS` filter). **Breaking:** set `INNIE_TOKEN` in both `.env` files.
- `AUTH_TOKEN` is now required (>= 32 characters); External no longer starts with authentication disabled
  or with the example value. Token comparison is constant-time and case-sensitive; repeated failures from one
  IP are throttled (`AUTH_FAIL_LIMIT`, `AUTH_FAIL_WINDOW`) on caller routes. Internal's routes are exempt
  from the throttle, so failed caller logins (including ones spoofing Internal's address via
  `X-Forwarded-For`) can never lock Internal out.
- Results are encrypted with the job UUID as authenticated data. **Breaking:** drain the queue and delete any
  uncollected `*.enc` results before upgrading.
- Job ids are validated as UUIDs; request/result sizes and the pending queue length are capped
  (`MAX_REQUEST_BYTES`, `MAX_CATALOG_BYTES`, `MAX_RESULT_BYTES`, `MAX_PENDING_JOBS`).
- Binding values and bound query text are no longer written to logs.
- `.env` files and runtime data directories are git-ignored.

### Changed

- New optional External settings: `PUBLIC_BASE_URL` (used for the `Location` header instead of the request's
  `Host`), plus the size/queue/throttle limits above. All are documented in `external/README.md`.
- `external/check_before_filter.rb` updated to the two-token auth model.
- Scan pipeline: Trivy runs at every severity; Ruby gem findings are recorded at every severity (a MEDIUM
  `rack` bug that let a forged `Host` into External's `Location` header was hidden by the old
  CRITICAL/HIGH filter), OS findings at CRITICAL/HIGH and unscored (`UNKNOWN`, e.g. DSA-6572-1).
  `security-patch.sh` refuses to patch or push an image that does not start.
- `Security/advisory_watch.py` (notify-only; e.g. for a scheduled Hermes job): reports new peer-project
  advisories, security lines in their release notes, security-related news articles, gem advisories
  (RubySec and OSV) for our pinned versions, and Debian security announcements for packages in our
  images. Each source exists because a real 2026 event appeared there and nowhere else.
- A job Internal refuses (unknown `query_id`, missing query file, malformed bindings, unlisted
  `enumerate` value, update query) now gets an empty answer promptly, instead of saying "processing"
  forever. Internal no longer logs "Registration completed" after a failed registration, and a 401 there
  now points at a mismatched `INNIE_TOKEN`.
- Test-only gems (`rspec`, plus `rack-test` for External) are in a `test` group, excluded from both
  images. `security-patch.sh` now runs External's spec as well as `check_before_filter.rb`, and runs
  `bundle install` before testing. Internal's suite passes again (the enumerate parser bug above was
  its one failure), so the pipeline's Internal auto-patches are no longer always reverted.
- `Security/security-patch.sh` gives every container it starts throwaway `AUTH_TOKEN`/`INNIE_TOKEN`
  values as well as the encryption key. Since the token requirement above, both services refused to start
  with only the key, so every OS-patch step and boot smoke test would silently have done nothing.
- `Security/build_register.py`: researched dispositions can be keyed per image (`(image, cve)`, which
  wins over a CVE-only entry); package-wide rules (`PACKAGE_DECISIONS`); unresearched findings with no
  fix available now default to `TRACK` instead of `PATCH`; rows the script generated are recomputed each
  run instead of being kept forever. Precedence is documented in `Security/VULNERABILITY_TRIAGE.md`.

### Documentation

- New "Upgrading from 1.1.0" section in `external/README.md` (covers both components), linked from the
  top-level and Internal READMEs. Install docs updated for the two required tokens, the new limits, and an
  error-code table.
- Fixed pre-existing errors in `external/README.md`: a still-pending job returns `202 Accepted`, not
  `201 Created`; an uninstalled `query_id` is not rejected with an error but sits as `"processing"`
  forever; undeclared bindings are ignored, not rejected. Curl examples no longer use the `YesItsMe` token.
- `Security/VULNERABILITY_TRIAGE.md` now opens with a section for partners deciding whether to deploy an
  image: where the full scan results are, what each `Decision` means for their deployment, and what the
  register cannot check for them (their host kernel). Linked from the top-level, External and Internal
  READMEs, which previously did not mention it at all.

### Credits

- Mark Wilkinson commissioned an independent review of 1.1.0 that produced the security patches above, and
  directed applying them and updating the install docs. The patches were re-tested here against the real
  Gemfiles (Sinatra 4.2.1 / Rack 3.2.7), and that pass found and fixed the Internal-lockout issue in the
  new throttle before release.
- Mark Wilkinson set the priority for the vulnerability-transparency work: Severance needs at least as
  much transparency as Sextans-Suite, because External is where data is actually exposed. That framing is
  why the work went past documentation into the first individual research on every finding, which found
  the build-toolchain root cause and the token-free multipart path.
- Mark Wilkinson brought the Vantage6 disclosures into scope (asking whether Severance had dealt with the
  same problems, and whether Trivy would have caught them), and then suspected that Vantage6's own
  advisories understated what happened and asked for a wider search. He was right: the search found two
  incidents never published as advisories -- the compromise of their image registry, which led to the
  digest pinning here, and the eMudhra CA compromise, which turned out to affect every published
  Severance and facade image. He also decided that beacon-facade must refuse to run without its key.

## [1.1.0] - 2026-09-22

### Changed

- `facades/shallot-facade` moved to its own dedicated repo,
  [`FAIR-Data-Systems/Severance-Facades`](https://github.com/FAIR-Data-Systems/Severance-Facades),
  alongside `beacon-facade` (which moved there from `CARE-Semantic-Model-Version-2`). Neither facade
  had a real code dependency on the repo it previously lived in, and consolidating them eliminated the
  cross-repo clone-and-push complexity `Security/security-patch.sh` had grown to patch beacon-facade
  from here. `Security/security-patch.sh` here now only patches `sevinternal`/`sevexternal`; the
  `pkg_mgr` (apt/apk) parameterization it needed for the Alpine-based facade images was removed along
  with them. Full pre-move commit history for both facades is preserved in the new repo's own git log.

### Fixed

- `facades/shallot-facade`'s image carried the base `ruby:3.2-alpine` image's own stale, vulnerable
  `net-imap` default gem (`0.3.9`, `CVE-2026-42257`) -- an unused-by-this-app default gem, same class of
  finding `external`/`internal` already fixed. First real run of the (newly extended)
  `Security/security-patch.sh` pipeline caught it. Fixed the same way: pinned `net-imap ~> 0.5` in the
  `Gemfile` (resolves to `0.6.7`, a fixed version) and explicitly uninstalled the base image's stale
  copy in the Dockerfile (pinning alone installs the patched version alongside the old one, not in
  place of it, since Bundler and RubyGems' default-gem installs use different paths). Verified live:
  rebuilt image has only `net-imap 0.6.7` present, and still boots and serves correctly.

### Security tooling

- `Security/security-patch.sh` now also patches `facades/shallot-facade` (in-repo, Alpine/`apk`,
  regenerates its `docker-compose.yml` from a new `shallot-docker-compose-template-template.yml`) and
  `beacon-facade` (a different repo, `CARE-Semantic-Model-Version-2/implementation/Beacon2/facade` --
  cloned fresh from `origin/main` each run, built/patched/pushed/scanned, tag printed but not written
  back, matching how Sextans-Suite's own pipeline already treats that repo's `care2`/`fdpserv2`
  images). `build_register.py`'s `IMAGE_INFO` updated for both.

### Added

- **`facades/shallot-facade/`** -- a new Sinatra app that makes Severance look like a
  [Shallot](https://github.com/wilkinsonlab/shallot)/GRLC-shaped service to any caller: one synchronous
  `GET /<query_id>?param=...` route per query, plus a Swagger 2.0 document at `GET /openapi.json`, both
  built dynamically from `GET /severance/available_queries` -- no `.rq` files read directly, no
  domain-specific knowledge, so it works unmodified for any project's queries. Exists so callers built
  against Shallot's interface (e.g. the FLAIR-GG Virtual Platform's data-service layer) can call a
  Severance-backed query with no code change of their own. Structured like the existing
  CARE-SM-2-specific `Beacon2/facade` (a sibling project, not in this repo), but domain-agnostic, so it
  lives here as a reusable capability of Severance itself. Needs the `before`-filter fix above to reach
  `GET /severance/jobs/:uuid` and `GET /severance/available_queries` at all. See
  `facades/shallot-facade/README.md`. **Verified end to end** against a real Severance External +
  Internal + Virtuoso instance, using FLAIR-GG's actual `IUCN_categories.rq` and `species_location.rq`
  unchanged -- see the three "Fixed" entries below, all found only by that run. Also has its own
  hardened `docker-compose.yml` (same pattern as `external/`/`internal/`) and a **verified real Docker
  build** -- see the two more "Fixed" entries below that build surfaced.

### Fixed

- `facades/shallot-facade/Dockerfile`'s runtime stage never copied `Gemfile`/`Gemfile.lock`, only the
  already-vendored gems -- `bundle exec` needs the Gemfile itself present to resolve/activate them.
  Every container exited immediately with "Could not locate Gemfile". Found by actually building and
  running the image for the first time (while adding `docker-compose.yml`); the same bug was found and
  fixed identically in `Beacon2/facade`'s Dockerfile (a separate repo, this facade's sibling project),
  which had the identical omission and had also never actually been run before.
- `facades/shallot-facade/lib/severance_client.rb#available_queries` only wrapped HTTP-status failures
  into `CatalogueFetchFailed`, not connection-level ones (`Errno::ECONNREFUSED`/`SocketError`/
  `Timeout::Error`). `QueryCatalogue#refresh`'s single rescue clause never caught those, so `GET /` and
  `GET /openapi.json` leaked a full stack trace (file paths, gem versions) to the caller whenever
  Severance was unreachable -- confirmed live with `RACK_ENV=production` set. `show_exceptions
  :after_handler` renders Sinatra's detailed exception page for any uncaught exception in every
  environment; this is the exact class of bug the earlier Severance pentest found and fixed in
  `external/outie.rb`. Now wrapped the same way; a generic `error StandardError` handler added as a
  backstop against the same mistake in any future route (also added, as defense in depth, to
  `Beacon2/facade/app.rb`, where it isn't currently reachable but the identical `show_exceptions`
  setting exists).
- `external/outie.rb`'s `before` filter also matched `POST /severance/available_queries` (Innie pushing
  its query catalogue on startup) as a Bearer-gated caller-facing route, after the fix below split its
  `GET` counterpart out from the internal-IP-only branch. `innie.rb` never sends a Bearer token for this
  push, so Internal's queries stopped registering with External at all. `POST` to this path is now
  always IP-gated (Innie's own trust boundary, like `queue/pull` and the result push), while `GET`
  (a caller reading the catalogue) stays Bearer-gated. Found only by a real end-to-end run --
  `check_before_filter.rb` extended to cover all three of Innie's own routes explicitly, by method.
- `internal/innie.rb`'s `substitute_grlc_bindings` required a `_type` suffix on every placeholder
  (`?_key_type`/`?__key_type`), the same limitation `extract_parameters` had before the fix below it. A
  parameter declared only via a `#+ parameters:` block, with a bare `?_key` placeholder and no suffix --
  exactly FLAIR-GG's real `species_location.rq` (`?_speciesname`) -- was silently left unreplaced in the
  query sent to the triplestore: an unbound SPARQL variable, always zero rows, no error anywhere in the
  chain. Found only by a real end-to-end run against real data (unit specs for the parser alone didn't
  catch it); new `internal/spec/innie_spec.rb` covers `substitute_grlc_bindings` directly, now possible
  since the main polling loop is guarded behind `if __FILE__ == $PROGRAM_NAME` so the file can be
  required from a spec.
- `facades/shallot-facade/lib/openapi_builder.rb` looked for a query's parameter defaults under a
  `defaults` key that Severance's real `available_queries` catalogue never has -- see
  `internal/innie.rb#process_queries`, which folds `#+ defaults:` (and `#+ enumerate:`) values into
  `examples` instead. A required, defaulted parameter's OpenAPI `default` was therefore always silently
  missing. Found only by inspecting the real doc served against a live catalogue.
- `external/outie.rb`'s `before` filter matched `/severance/jobs/` as a path *prefix* for its
  internal-IP-only branch, which also caught the caller-facing `GET /severance/jobs/:uuid` (polling for
  a result) and `GET /severance/available_queries` -- not just Innie's own
  `POST /severance/jobs/:uuid/result`. An external caller with a valid `AUTH_TOKEN` could never poll for
  its own result or list queries; it got a 403 unless it also happened to be on an allowlisted IP,
  contradicting `external/README.md`'s own documented curl examples. Now only
  `GET /severance/queue/pull` and `POST /severance/jobs/:uuid/result` (Innie's own routes) are
  IP-restricted; `GET /severance/jobs/:uuid` and `GET /severance/available_queries` are Bearer-checked
  like every other caller-facing route. Covered by a new standalone check,
  `external/check_before_filter.rb` (uses `Rack::MockRequest`, already available transitively via
  `sinatra`/`rackup` -- no new gem added to `external/`, which carries no test framework by design).
- `internal/annotation_parser.rb` ignored a query's `#+ parameters:` block entirely -- GRLC's own
  dialect for declaring a parameter that has no type-suffixed inline placeholder (`?_name` rather than
  `?_name_type`), used by e.g. FLAIR-GG's `species_location.rq`. A parameter declared only this way
  produced empty `variables`/`variable_types`, and a continuation line of the block (e.g. `type:
  string`) was misread as a new top-level metadata key, also silently resetting the parser's list-item
  tracking. Now folded into `variables`/`variable_types`/`defaults`/(new) `required`, without
  overwriting anything already found inline or via an explicit `#+ defaults:` block.

### Changed

- `ALLOWED_INTERNAL_IPS` entries may now be a CIDR range (e.g. `192.168.1.0/24`) in addition to a bare IP or the `localhost` keyword. A malformed entry is skipped (logged) rather than rejecting every request. Closes #5.
- `external/Gemfile` now explicitly pins `json` (previously undeclared, relying on the base image's bundled default version) to match `internal/Gemfile`'s existing pin. Both Dockerfiles document why the older default-gem copy of `json`/`net-imap` can (or, for `json`, can't) be removed from the image.

- `Security/security-patch.sh` rebuilds both images from source, applies an OS-level `apt` update/dist-upgrade, scans with Trivy, pushes, and regenerates `external/docker-compose.yml`/`internal/docker-compose.yml` from new `Security/*-docker-compose-template-template.yml` masters -- keeping those two live compose files in sync with any hardening changes made here. `Security/parse-security-scans.rb` and `Security/build_register.py` (adapted for this repo's two images) turn scan output into `Security/vulnerability-register.csv`.
- Both Dockerfiles now remove the stale `net-imap` default gem after `bundle install`; both Gemfiles pin `net-imap`/`rack-session` to current patch versions.
- Removed the optional Beacon v2 facade section from `external/docker-compose.yml` and its references elsewhere in the docs.
- `query_id` (on `POST /severance/queries`) must now match a fixed, slash-free character whitelist before a job is queued (`external/outie.rb`); `internal/innie.rb` independently requires `query_id` to exactly match an entry in its own scanned query registry before doing any file lookup.
- Request bodies to `external/outie.rb`'s JSON endpoints, and binding values processed by `internal/innie.rb`, are now validated as well-formed UTF-8 before use (`external/outie.rb`'s `read_utf8_body!`; `internal/innie.rb`'s `substitute_grlc_bindings`, alongside its existing IRI validation).
- `external/outie.rb`'s failed-authentication log line no longer includes the Authorization header value or the configured `AUTH_TOKEN` -- it logs only whether the header was present, plus the caller's IP.
- **`internal/innie.rb` now connects to Virtuoso instead of GraphDB.** Added an `execute_sparql_query` helper that performs HTTP Digest authentication (via the `net-http-digest_auth` gem) against a `/sparql-auth`-style endpoint using a form-encoded `query=` body, when `TRIPLESTORE_USER`/`TRIPLESTORE_PASS` are configured; falls back to a plain unauthenticated request otherwise.
  - `TRIPLESTORE_URL`'s documented convention, `internal/env_template`, `internal/.env`, and `internal/README.md`'s prerequisites are updated accordingly (`http://host:8890/sparql-auth`).
  - Verified live end-to-end against a Virtuoso instance.
  - Uses `URI.encode_www_form_component` (from the `uri` stdlib, already loaded transitively) for the form-encoded query body rather than pulling in the `cgi` library for one method call.
  - Triplestore responses are now checked for success before being processed and encrypted; a failure to reach the triplestore at all is now handled the same way External's own polling failures already were, instead of stopping Internal.
- Both `external/outie.rb` and `internal/innie.rb` now require `ENCRYPTION_KEY_HEX` to be set to a value other than the documented example before starting.
- `external/docker-compose.yml` and `internal/docker-compose.yml`: added `restart: always`, `security_opt: no-new-privileges`, `cap_drop: [ALL]` (with a minimal `cap_add` on External for its existing chown-then-drop-privileges startup step), and resource limits.
- `internal/docker-compose.yml` no longer uses `network_mode: host` -- Internal never listens on a port, so ordinary bridge networking reaches External/the triplestore on a separate server exactly as before; `extra_hosts: [host.docker.internal:host-gateway]` is added for the same-host testing case, documented in `internal/README.md`.
- `external/Dockerfile`: the `severance` user's UID is now pinned to 1000, matching `internal/Dockerfile`'s existing convention and `entrypoint.sh`'s own volume-ownership step.
- `external/outie.rb`: Rack's default Host-header check is now disabled directly rather than through Sinatra's `set :protection, except:` option.

**Note:** `internal/sample_queries/count.rq` and `patient_filter.rq` are still written against CARE-SM v1's shape; they have not yet been checked against CARE-SM-2 data and will be updated in a follow-up commit.

### Security

- **Fixed a SPARQL injection vulnerability in `internal/innie.rb`'s binding substitution.** Any variable declared `iri` in a query's GRLC annotation (e.g. `?_disease_iri`) was wrapped in `<...>` with no validation of its contents. Since a SPARQL `IRIREF` has no escaping mechanism of its own (unlike a quoted string literal), a caller-supplied value containing a literal `>` could close the angle bracket early and inject arbitrary additional SPARQL — an extra `UNION`, `FILTER`, or graph pattern — directly into an otherwise pre-approved, named query. This defeated "queries are named and pre-approved, not arbitrary" as a security boundary: no new `query_id` was needed, only one existing `iri`-typed variable in any installed query, to read data well outside what that query's author intended (bounded only by whatever the Internal triplestore's own read-only credential can see, i.e. typically the whole repository).
  - Fixed by validating every `iri`-typed binding against the SPARQL 1.1 `IRIREF` grammar's disallowed character set (`< > " { } | ^` \` `\`, and control/whitespace characters) before substitution, and rejecting the job outright — with a safe, zero-row result pushed back so the caller resolves promptly rather than hanging — if it fails. There is no safe way to escape an invalid IRI value the way a string literal can be escaped; an invalid one must be refused, not sanitized and passed through.
  - The rejection path never executes the tainted query and never echoes the offending value back to the caller or into logs (only the variable name is logged), to avoid handing an attacker a probing oracle or a secondary log-injection surface.
  - Found while designing a Beacon v2 facade for CARE-SM-2
    (`CARE-Semantic-Model-Version-2` repo,
    `implementation/Beacon2/`) that itself relies on several `iri`-typed
    bindings (`sex`, `disease`, `symptom`) — the facade passes filter
    values through with no sanitization of its own, so it depended
    entirely on Severance's own escaping being correct. It wasn't; this
    fix closes that gap at the layer that actually needs to own it
    (Internal, where the query text and substitution logic live), rather
    than pushing validation out to every client integration individually.

### Added

- `CHANGELOG.md` (this file).
- `AUTH_TOKEN`'s real security properties (static bearer secret, replayable if ever exposed, blast radius bounded by the named-query design rather than the token itself) now documented explicitly in the top-level `README.md`'s "Possible Attacks?" list, `external/README.md`, and as a comment on the `AUTH_TOKEN` line in `external/env_template`.
