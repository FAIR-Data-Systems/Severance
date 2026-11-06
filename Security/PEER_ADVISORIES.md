# What other projects' security problems mean for Severance

**A scanner can NOT find Severance's own design flaws -- only someone looking for them can!** Trivy
and similar tools report known bugs in the libraries we use. They will never tell you that Severance
gives every caller the same token, or trusts something it shouldn't. The fastest way to find that
kind of flaw is to watch similar projects: when one of them publishes a flaw in *its* design, we ask
**"could Severance have the same kind of flaw?"** -- and write the answer here, for every one.

`Security/advisory_watch.py` tells us when a peer publishes something new (see its header for what it
watches). This file is the result of mapping each one onto Severance.

**"FIXED" means fixed in our source code.** It reaches your deployment only with the first image
release after it -- check the `CHANGELOG.md` for the version that contains it, and the image tag in
your `docker-compose.yml`. **Every fix listed here is newer than the 2026-09-22 images**, so as of
2026-11-06 none of them is in a published image yet!

| Status | Meaning |
| --- | --- |
| **FIXED** | Severance had the same kind of flaw, and it is fixed in source (date given). |
| **SAFE BY DESIGN** | Severance has the same kind of risk area, but is built so that this flaw cannot happen -- the reason is given. |
| **PARTLY** | Reduced, not eliminated. Says what is left. |
| **OPEN** | Severance has the same kind of flaw today. **Read these!** |
| **NOT APPLICABLE** | Depends on a feature Severance does not have (user accounts, e-mail, plugins, ...). |

## Vantage6 (federated analysis platform) -- reviewed 2026-11-06

All 39 GitHub security advisories of [vantage6/vantage6](https://github.com/vantage6/vantage6/security/advisories),
plus two serious incidents that were **never published as advisories** -- found on their news page
and in their release notes. Grouped by the kind of flaw.

### Incidents that never became advisories

| What happened to Vantage6 | Could Severance have it? | Status |
| --- | --- | --- |
| **Their image registry was broken into (24 March - 2 April 2026).** An attacker with admin access put a malware downloader into published images *under their existing tags*; everyone who pulled those tags got it. ([notice](https://distributedlearning.ai/news/unauthorized-access-to-our-vantage6-image-registry/)) | Yes. Our images live on Docker Hub, and our `docker-compose.yml` files named them **by tag only** -- anyone who got into that account could replace an image under the same tag, and you would pull it without noticing. | **FIXED 2026-11-06** (from the next release): the compose files pin each image **by digest** (`tag@sha256:...`), so Docker refuses an image whose content has changed. **Still yours to do: take new compose files from the repo only.** |
| **The eMudhra / emSign certificate authority was compromised (October 2026).** Eight intermediate CA keys turned out to be recoverable, so anyone could make "valid" certificates for any website. Vantage6 had to update the trusted-certificate bundles in its images. | **Yes -- this one hits us directly.** Internal makes HTTPS connections (to External and the triplestore) and trusts the operating system's certificate bundle. **The published 2026-09-22 images (Severance AND both facades) still trust the compromised `emSign ECC Root CA - G3`** (Severance's also `AAA Certificate Services`) -- so someone holding a forged certificate could pretend to be External. | **FIXED in source / next release**: images built now carry Debian's DSA-6572-1 (`ca-certificates 20250419+deb13u1`) and Alpine's updated bundle, without either root (verified 2026-11-06). **Until you have upgraded: do not let Internal reach External over a network you don't trust.** |

### Caller input reaching something that executes it

Vantage6: [GHSA-98jv](https://github.com/vantage6/vantage6/security/advisories/GHSA-98jv-c22f-3qrp) (HIGH, code injection through expressions passed to pandas `eval`), [GHSA-w9h2](https://github.com/vantage6/vantage6/security/advisories/GHSA-w9h2-px87-74vx) (code injection through environment variables), [GHSA-5m22](https://github.com/vantage6/vantage6/security/advisories/GHSA-5m22-cfq9-86x6) (unsafe `pickle` deserialization).

**FIXED / SAFE BY DESIGN.** The only caller input that reaches the triplestore is binding values, and
they are validated (IRIs against the SPARQL grammar, refused if invalid), escaped, substituted in a
single pass (FIXED 2026-10-23 -- the earlier binding-by-binding substitution could be injected), and
must be one of the query's allowed values if it lists them (FIXED 2026-11-06). Severance never
deserializes objects from callers -- JSON only.

### Trusting what the other component says

Vantage6: [GHSA-82rc](https://github.com/vantage6/vantage6/security/advisories/GHSA-82rc-cpqj-9926) (server trusted data sent by nodes), [GHSA-j43v](https://github.com/vantage6/vantage6/security/advisories/GHSA-j43v-wwjr-9grj) (node did not verify an algorithm was really approved), [GHSA-vc3v](https://github.com/vantage6/vantage6/security/advisories/GHSA-vc3v-ppc7-v486) (node ran non-approved algorithms from a malicious server), [GHSA-4998](https://github.com/vantage6/vantage6/security/advisories/GHSA-4998-q23j-7w5r) (an approval check did not cover every case).

**FIXED / SAFE BY DESIGN.** Internal only ever runs query files from its own folder, checks every job
it receives itself (canonical job id, a query it actually has, bindings that are an object, allowed
values, no SPARQL Update), and never trusts External's copy of the catalogue. In the other direction,
External accepted an answer from Internal for *any* job id -- including jobs Internal had never
taken: **FIXED 2026-11-06**, a result is now accepted only for a job in progress.

### Allow-by-default and default credentials

Vantage6: [GHSA-hx2w](https://github.com/vantage6/vantage6/security/advisories/GHSA-hx2w-rjmx-934x) (nodes allowed every algorithm by default), [GHSA-fgmc](https://github.com/vantage6/vantage6/security/advisories/GHSA-fgmc-2hqj-86v4) (built-in `root`/`root` account), [GHSA-m3mq](https://github.com/vantage6/vantage6/security/advisories/GHSA-m3mq-f375-5vgh) (weak JWT secret).

- **FIXED 2026-11-06:** Internal used to copy its example queries into `./queries` on every new
  install -- live to any token holder, one of them returning individual people's records. Examples
  are now opt-in (`SEED_DEMO_QUERIES=true`).
- **FIXED 2026-10-23:** Severance refuses to start with the example token (`YesItsMe`), a short token,
  or the example encryption key. **FIXED 2026-11-06:** the facades no longer fall back to `YesItsMe`.
- **OPEN (beacon-facade):** with `BEACON_FACADE_AUTH_KEY` unset, every caller is treated as trusted and
  gets counts instead of yes/no answers. Documented as testing-only; it should probably refuse to run
  in production without the key -- a decision for whoever deploys it with ERDERA.

### Data not tied to the caller who asked for it

Vantage6: [GHSA-47f9](https://github.com/vantage6/vantage6/security/advisories/GHSA-47f9-q832-gc8q), [GHSA-c676](https://github.com/vantage6/vantage6/security/advisories/GHSA-c676-7h46-8725), [GHSA-3q9m](https://github.com/vantage6/vantage6/security/advisories/GHSA-3q9m-83r4-x32j), [GHSA-gc57](https://github.com/vantage6/vantage6/security/advisories/GHSA-gc57-xhh5-m94r), [GHSA-69vq](https://github.com/vantage6/vantage6/security/advisories/GHSA-69vq-j3qr-vg8x), [GHSA-7x94](https://github.com/vantage6/vantage6/security/advisories/GHSA-7x94-6g2m-3hp2), [GHSA-vvjv](https://github.com/vantage6/vantage6/security/advisories/GHSA-vvjv-97j8-94xh), [GHSA-99r4](https://github.com/vantage6/vantage6/security/advisories/GHSA-99r4-cjp4-3hmx) -- one user or node reaching another's tasks, results or data.

**OPEN.** All callers of one Severance share one `AUTH_TOKEN`, so Severance cannot tell callers apart:
**anyone holding the token who learns a job id can collect that answer -- and, since an answer can be
collected only once, take it away from the caller who asked.** What limits this today: job ids are
random 122-bit UUIDs that only the submitting caller is ever told, and every answer is encrypted for
its own job. Closing it needs per-caller tokens -- a design change that also affects the facades.

### Running code with more power than it needs

Vantage6: [GHSA-2rch](https://github.com/vantage6/vantage6/security/advisories/GHSA-2rch-7f67-gqmx) (HIGH, node's Kubernetes account could control the whole cluster), [GHSA-x9f6](https://github.com/vantage6/vantage6/security/advisories/GHSA-x9f6-9rvm-mmrg) (algorithms could read each other's files), [GHSA-27gf](https://github.com/vantage6/vantage6/security/advisories/GHSA-27gf-8rcw-jqgh) ("read-only" database mount not applied), [GHSA-2wgc](https://github.com/vantage6/vantage6/security/advisories/GHSA-2wgc-48g2-cj5w) (insecure SSH in containers).

**SAFE BY DESIGN / FIXED.** No caller-supplied code ever runs in Severance. Both containers run as an
unprivileged user, with all Linux capabilities dropped (External keeps five, used only by its startup
script before it drops to that user), `no-new-privileges`, no SSH, no Docker socket. "Read-only" was
enforced only by the triplestore account you configure: **FIXED 2026-11-06**, Internal now also refuses
any query that would change data.

### Credentials: lifetime, storage, purpose

Vantage6: [GHSA-m879](https://github.com/vantage6/vantage6/security/advisories/GHSA-m879-xx69-79f2) and [GHSA-4w59](https://github.com/vantage6/vantage6/security/advisories/GHSA-4w59-c3gc-rrhp) (tokens that never expire), [GHSA-r5cm](https://github.com/vantage6/vantage6/security/advisories/GHSA-r5cm-8vc3-5333) (private key in a plain-text file), [GHSA-v995](https://github.com/vantage6/vantage6/security/advisories/GHSA-v995-8jhw-349w) (a component re-used a user's token to talk to another service).

- **FIXED 2026-10-23:** Internal has its own `INNIE_TOKEN`, never the callers' `AUTH_TOKEN`.
- **PARTLY (2026-11-06):** secrets can be given as files (`*_FILE`, e.g. Docker secrets) instead of
  environment variables. They are still plain text on disk -- keep those files readable by the
  service only.
- **OPEN:** `AUTH_TOKEN` and `INNIE_TOKEN` never expire; rotating them is manual (and `AUTH_TOKEN` must
  be changed at every caller at once).

### Login and account weaknesses

Vantage6: [GHSA-942q](https://github.com/vantage6/vantage6/security/advisories/GHSA-942q-gcpr-gh5q) (failed login left the connection open), [GHSA-j6g5](https://github.com/vantage6/vantage6/security/advisories/GHSA-j6g5-p62x-58hw) (no brute-force protection), [GHSA-45gq](https://github.com/vantage6/vantage6/security/advisories/GHSA-45gq-q4xh-cp53) (timing attack), [GHSA-5h3x](https://github.com/vantage6/vantage6/security/advisories/GHSA-5h3x-6gwf-73jm) and [GHSA-36gx](https://github.com/vantage6/vantage6/security/advisories/GHSA-36gx-9q6h-g429) (username enumeration), [GHSA-4c5c](https://github.com/vantage6/vantage6/security/advisories/GHSA-4c5c-2vc3-x5w2) and [GHSA-5549](https://github.com/vantage6/vantage6/security/advisories/GHSA-5549-c5q7-fj65) (MFA reset by e-mail).

**FIXED 2026-10-23 / NOT APPLICABLE.** Severance has no user accounts, passwords or e-mail. Every
request is checked on its own (a wrong token gets `401`, nothing stays open); tokens are compared in
constant time; repeated wrong tokens from one address are throttled.

### Data leaking into logs or left behind

Vantage6: [GHSA-rm37](https://github.com/vantage6/vantage6/security/advisories/GHSA-rm37-7322-qvgg) (HIGH, algorithm logs shared despite the setting), [GHSA-rf54](https://github.com/vantage6/vantage6/security/advisories/GHSA-rf54-7qrr-96j6) (deleting a collaboration left its resources), [GHSA-rjmv](https://github.com/vantage6/vantage6/security/advisories/GHSA-rjmv-52mp-gjrr) (unencrypted task in an encrypted collaboration).

**FIXED / SAFE BY DESIGN.** Binding values and filled-in queries are no longer logged (FIXED
2026-10-23). Answers nobody collects are deleted after 7 days (FIXED 2026-11-06). Results are always
encrypted -- there is no unencrypted mode to fall into.

### Not applicable to Severance

[GHSA-4946](https://github.com/vantage6/vantage6/security/advisories/GHSA-4946-85pr-fvxh) (overly permissive CORS -- Severance sends no CORS headers, so browsers block cross-site reads),
[GHSA-82cm](https://github.com/vantage6/vantage6/security/advisories/GHSA-82cm-vgqg-chcw) (changing another organisation's public key -- Severance has no per-organisation keys),
[GHSA-47w6](https://github.com/vantage6/vantage6/security/advisories/GHSA-47w6-gwp4-w6vc) (editing another developer's algorithm under review -- Severance has no online authoring; queries are files on Internal, protected by that server's own access control).

## Adding to this file

When `advisory_watch.py` reports a new peer advisory, release note or news article, add it under the
right kind of flaw (or a new one), with a status and the reason. If the answer is OPEN or a fix, it
also goes into `CHANGELOG.md`. Keep the reasoning short enough that a partner can check it.
