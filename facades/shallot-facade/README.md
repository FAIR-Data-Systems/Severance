# shallot-facade

**Version: see [`VERSION`](VERSION).**

A Sinatra app that makes [Severance](https://github.com/FAIR-Data-Systems/Severance) look like a
[Shallot](https://github.com/wilkinsonlab/shallot) service to any caller: one synchronous
`GET /<query_id>?param=...` route per query Severance Internal has installed, plus a Swagger 2.0
document describing them, built dynamically from Severance's own `GET /severance/available_queries`
catalogue. (Shallot's own query-annotation format and variable-naming convention come from
[GRLC](https://github.com/CLARIAH/grlc) -- referenced here only for that, not as this facade's own
name or interface: GRLC's own server has a known, unpatched security history, which is exactly why
FLAIR-GG runs the hardened Shallot fork instead, and why this facade is named and documented as a
Shallot-shaped service throughout.) It exists so callers built against Shallot's interface -- like the
FLAIR-GG Virtual Platform's data-service layer
(`VP/vp-interface/lib/services.rb`) -- can call a Severance-backed query with **no code change of
their own**: register it in the FAIR Data Point exactly like a Shallot query
(`dcat:endpointURL` = `<this facade>/<query_id>`, `dcat:endpointDescription` =
`<this facade>/openapi.json`, same `dcterms:type` as the equivalent Shallot query).

**Domain-agnostic on purpose.** Unlike
[`Beacon2/facade`](https://github.com/wilkinsonlab/CARE-Semantic-Model-Version-2) (CARE-SM-2-specific:
hardcoded query IDs, an ontology filter-mapper), this facade has zero knowledge of any particular data
model. It works for FLAIR-GG's queries, CARE-SM-2's, or anyone else's, unmodified -- it only ever talks
to Severance External's own public API (`available_queries`, `queries`, `jobs/:uuid`), never a `.rq`
file directly. That's also why it lives in this repo rather than a domain-specific one: it's a reusable
capability of Severance itself, not of any one project that happens to use Severance.

## Setup

1. `bundle install`
2. Copy `env_template` to `.env` and edit `SHALLOT_FACADE_SEVERANCE_URL` /
   `SHALLOT_FACADE_SEVERANCE_AUTH_TOKEN` to match your Severance External deployment, and
   `SHALLOT_FACADE_BASE_URL` to this facade's own externally-reachable base URL (see below for why that
   has to be right).
3. Install your query `.rq` files into Severance Internal's `./queries` folder as usual -- nothing
   about them needs to change for this facade; it only reads what Internal has already parsed and
   pushed to External's `available_queries`.
4. Requires the Severance `before`-filter fix (see the top-level `CHANGELOG.md`'s "Fixed" entry,
   2026-09) -- without it, `GET /severance/jobs/:uuid` and `GET /severance/available_queries` are
   unreachable for a Bearer-authenticated external caller like this facade.
5. `bundle exec rackup` (reads `SHALLOT_FACADE_PORT`/`SHALLOT_FACADE_BIND` from the environment, defaulting
   to `4567`/`0.0.0.0`)

## Docker

`docker compose up` (after step 2 above -- `docker-compose.yml` reads `.env`, and `SHALLOT_FACADE_PORT`
if you changed it from the default). Hardened the same way as Severance's own `external/` and
`internal/` compose files: `restart: always`, `security_opt: no-new-privileges`, `cap_drop: [ALL]`
(no `cap_add` needed here -- this Dockerfile never runs as root at all, unlike `external/`'s
chown-then-`gosu` step, since there are no volumes to chown), `mem_limit`/`cpus` ceilings.

**Covered by `Security/security-patch.sh`**, alongside `external`/`internal` -- it builds this image
fresh from source, OS-patches it (`apk`, this being Alpine-based unlike the other two's Debian-based
`apt`), pushes `fairdatasystems/shallotfacade:<date>`, Trivy-scans it, and rewrites this file's `image:`
to the newly patched tag (from `Security/shallot-docker-compose-template-template.yml`). Until that's
been run at least once, `docker-compose.yml` here still points at a `:local` tag built with `build: .`
(what a real run replaces) -- run `docker build -t fairdatasystems/shallotfacade:local .` yourself in
the meantime, or run the pipeline.

## Configuration reference

| Env var | Meaning |
| --- | --- |
| `SHALLOT_FACADE_PORT` / `SHALLOT_FACADE_BIND` | listen port/address, default `4567`/`0.0.0.0` |
| `SHALLOT_FACADE_BASE_URL` | this facade's own externally-reachable base URL -- see `GET /openapi.json` below |
| `SHALLOT_FACADE_SEVERANCE_URL` / `SHALLOT_FACADE_SEVERANCE_AUTH_TOKEN` | the Severance External this facade submits queries to, and its Bearer token |
| `SHALLOT_FACADE_POLL_INTERVAL` / `SHALLOT_FACADE_POLL_CEILING` | blocking poll loop tuning while waiting for Severance Internal to answer a job |
| `SHALLOT_FACADE_PRODUCES` | content type(s) this Severance deployment's `RESULT_FORMAT` actually returns -- documentation only, in the OpenAPI doc |

## Endpoints

- `GET /` -- minimal banner (facade version, known query IDs). Unauthenticated.
- `GET /openapi.json` -- a Swagger 2.0 document, one path per known query, built from Severance's
  `available_queries` catalogue. This is what `dcat:endpointDescription` should point to. Modeled on
  the shape Shallot itself serves (see
  `FLAIR-GG/Data Service Configs/Shallot/shared-queries/current_yaml.json`), since that exact shape is
  already proven to round-trip through the VP's swagger-converter -> Openapi3Parser pipeline. Its
  `host`/`basePath`/`schemes` are derived from `SHALLOT_FACADE_BASE_URL` -- **this must match the
  scheme/host/path prefix a caller registers as `dcat:endpointURL`** for the corresponding query
  (`<SHALLOT_FACADE_BASE_URL>/<query_id>`), since callers that fetch this doc (like the VP) compare the
  two to find the operation's parameters.
- `GET /<query_id>?param1=val1&param2=val2...` -- one route per catalogue entry, e.g. `GET
  /IUCN_categories`, `GET /species_location?speciesname=Arabidopsis`. Query-string params map directly
  to Severance `bindings` by name -- no translation, since Severance's binding names already are the
  Shallot variable names. Internally: `POST /severance/queries`, poll `GET /severance/jobs/:uuid`
  (blocking), then return the result synchronously with whatever `Content-Type` Severance itself sent
  (CSV or `application/sparql-results+json`, per that deployment's `RESULT_FORMAT`).
  - `404` if `query_id` doesn't match any known query (after one catalogue refresh, in case it was
    just installed on Internal).
  - `502` if Severance itself rejects the query or is unreachable; `504` if the poll ceiling
    (`SHALLOT_FACADE_POLL_CEILING`) is reached first.

No caller-facing auth on this facade's own routes, matching Shallot's current behavior (the VP sends
none today -- see the commented-out `"auth-key"` in `VP/vp-interface/lib/services.rb`). This facade
holds its own Severance `AUTH_TOKEN` internally (`SHALLOT_FACADE_SEVERANCE_AUTH_TOKEN`), never exposed to
callers.

## Structure

- `app.rb` -- routes; boots a `SeveranceClient` and a `QueryCatalogue`, serves `/`, `/openapi.json`, and
  the dynamic `/:query_id` route.
- `lib/severance_client.rb` -- fetches `available_queries`; owns the submit -> poll -> fetch cycle for
  a single query. Returns results as opaque bytes plus a content type -- unlike its Beacon-facade
  sibling, this never parses result rows into a Ruby structure, since it isn't reshaping anything.
- `lib/query_catalogue.rb` -- caches `available_queries` by `query_id`, refreshing on a lookup miss
  (a query might have just been installed on Internal) rather than on a timer -- no background thread,
  nothing to configure.
- `lib/openapi_builder.rb` -- catalogue -> Swagger 2.0 document.

## Known gaps

- **Verified end to end** (2026-09-22) against a real Severance External + Internal + Virtuoso
  instance, using FLAIR-GG's actual `IUCN_categories.rq` and `species_location.rq` unchanged: `GET
  /IUCN_categories` and `GET /species_location?speciesname=...` both returned correct real data through
  the full chain. That run also caught and fixed real bugs in Severance itself (see the top-level
  `CHANGELOG.md`) and, separately, a stack-trace leak on `GET /`/`GET /openapi.json` when Severance was
  unreachable -- `SeveranceClient#available_queries` now wraps connection-level failures, and a generic
  `error StandardError` handler in `app.rb` is the backstop against the same class of mistake in any
  future route (`show_exceptions :after_handler` otherwise renders a full backtrace for anything
  uncaught, in every environment).
- `QueryCatalogue`'s refresh-on-miss means a query *removed* from Internal stays visible here (and
  routable, until Severance itself rejects the `query_id`) until the process restarts or another
  lookup happens to trigger a refresh that drops it. Not a correctness problem (Severance is still the
  source of truth for whether a query actually runs), just a stale-listing edge case.
- The Docker image build **is verified** -- `docker build` succeeds and the container runs correctly as
  its non-root user (fixed a missing `Gemfile`/`Gemfile.lock` copy in the runtime stage that made every
  container exit immediately with "Could not locate Gemfile", found by actually running it for the
  first time).
