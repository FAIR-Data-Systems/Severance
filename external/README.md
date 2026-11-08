<img src="../docs/SeverenceSMW.png"/>

# Severance: Secure SPARQL Service

# Installing the External Component

**Read this first.** External is the *only* part of Severance that the outside world ever talks to.
You CAN submit a pre-approved, named query and get an answer back. You CANNOT run arbitrary SPARQL --
Severance will refuse anything that isn't a query the data provider has already installed on Internal.
Keep that in mind while you read the rest of this file.

**Upgrading an install that is already running?** Read [Upgrading from 1.1.0](#upgrading-from-110)
first! This release needs new settings on BOTH External and Internal, and upgrading only one of them
breaks the pair.

**External is the part of Severance that is exposed to the network -- check its known
vulnerabilities before you deploy or update it!** Every finding for the exact image tag in your
`docker-compose.yml` is published, with our reasoning, in
[Security/VULNERABILITY_TRIAGE.md](../Security/VULNERABILITY_TRIAGE.md). Pay special attention to
any `PATCH` row for `sevexternal`, and ask us about it.

## What you need before you start

1. `docker compose` installed on your server.
2. **Two different secrets, each at least 32 characters long.** Run `openssl rand -hex 32` twice and
   keep both outputs. One becomes `AUTH_TOKEN` (for your callers), the other `INNIE_TOKEN` (for
   Internal only). **External refuses to start without both of them!** It also refuses a short one, an
   example value like `YesItsMe`, or the same value used for both.

## Step-by-step setup

1. **Create a new, empty folder** for your External server.
2. **Inside it, create a `./data` folder and a `./queries-metadata` folder.** Do this as yourself --
   **DO NOT do this as root!**
3. **Copy the latest `docker-compose.yml`** from the Severance repo's `./external` folder into your new
   folder. **DO NOT write your own from scratch** -- the one in the repo already has every security
   patch applied. Copy it fresh every time you update.
4. **Copy `env_template` to `.env`** in that same folder, then edit `.env` as described below.

### Editing `.env`

    ENCRYPTION_KEY_HEX=<generate with: openssl rand -hex 32>
    RESULT_FORMAT=csv                  # or "json"
    QUERY_DIR=/queries   # DO NOT CHANGE THIS unless you really know what you're doing
    QUEUE_DIR=/data/queue  # DO NOT CHANGE THIS unless you really know what you're doing
    RESULTS_DIR=/data/results  # DO NOT CHANGE THIS unless you really know what you're doing
    AUTH_TOKEN=<output of: openssl rand -hex 32>
    INNIE_TOKEN=<a different output of: openssl rand -hex 32>
    ALLOWED_INTERNAL_IPS=172.31.0.1,127.0.0.1,::1,192.168.1.100   # CHANGE 192.168.1.100 to the IP of Internal 
    METADATA_DIR=/queries-metadata  # Don't change this unless you know what you're doing

- **`ENCRYPTION_KEY_HEX`** -- generate your own with `openssl rand -hex 32`. **DO NOT leave the
  placeholder text in place** -- both External and Internal refuse to start if you do. This exact same
  key **must** also be set on Internal, or nothing will decrypt correctly.
- **`AUTH_TOKEN`** -- your callers' shared secret. **REQUIRED, at least 32 characters.** Anyone who has
  it can call your service, so give it only to the callers (and facades) you mean to serve. See the
  warning below for what this does and does not protect against.
- **`INNIE_TOKEN`** -- the secret Internal presents to External, and ONLY Internal. **REQUIRED, at least
  32 characters, and it MUST be different from `AUTH_TOKEN`!** Put the exact same value in Internal's
  `.env`. **NEVER give this one to a caller or a facade!** It is what lets something pull your queued
  requests and push answers back.
- **`ALLOWED_INTERNAL_IPS`** -- the addresses Internal is allowed to call from. Each entry can be a bare
  IP (`192.168.1.100`), a CIDR range (`192.168.1.0/24`), or the word `localhost`. **This is NOT a
  replacement for `INNIE_TOKEN`!** A request to Internal's part of the API must come from one of
  these addresses AND carry `INNIE_TOKEN`. An IP address is not proof of identity: proxies and Docker
  networking can make a stranger's traffic look like it comes from an allowed address. **Keep this
  list as short as possible.** During testing you can include `localhost`/`127.0.0.1`; in production
  it should contain only Internal's real address.
- **Everything marked "DO NOT CHANGE"** -- leave it alone unless you have read the code and know exactly
  what you're doing.

**Optional settings.** These are not in `env_template`. The defaults are fine for most installs. Add a
line to `.env` only if you have a real reason to change one:

| Setting | Default | What it does |
| --- | --- | --- |
| `MAX_PENDING_JOBS` | `1000` | Most requests that can wait in the queue. Beyond this, new requests get `429 queue_full`. |
| `MAX_REQUEST_BYTES` | `65536` (64 KB) | Largest query request a caller may send. |
| `MAX_RESULT_BYTES` | `268435456` (256 MB) | Largest (encrypted) answer Internal may push back. **If your queries return bigger answers than this, raise it, or they will be refused!** |
| `MAX_CATALOG_BYTES` | `2097152` (2 MB) | Largest query catalogue Internal may register. |
| `AUTH_FAIL_LIMIT` / `AUTH_FAIL_WINDOW` | `10` / `60` | After this many failed logins from one address within this many seconds, that address gets `429` until the window passes. This applies to callers only, never to Internal. |
| `RESULT_TTL_HOURS` | `168` (7 days) | Answers nobody collects, and requests Internal took but never answered, are deleted after this long. Requests still waiting in the queue are never deleted. `0` turns this off. |
| `ENCRYPTION_KEY_HEX_FILE`, `AUTH_TOKEN_FILE`, `INNIE_TOKEN_FILE` | *(unset)* | The path of a file holding that secret (e.g. a Docker secret under `/run/secrets/`), instead of putting it in `.env`. A value in `.env` ends up in the container's environment, where anyone who can run `docker inspect` can read it. |
| `PUBLIC_BASE_URL` | *(unset)* | Behind a reverse proxy, set this to the public address callers use (e.g. `https://severance.example.org`), so the `Location` header points there and not at the proxy's internal address. |

**Behind a reverse proxy?** Make sure it passes on each caller's real address. If it doesn't, every
caller looks like the same address, and **one caller with a wrong token locks ALL your callers out**
for `AUTH_FAIL_WINDOW` seconds!

**What `AUTH_TOKEN` actually protects against -- read this, don't assume.** `AUTH_TOKEN` is a static,
unsigned secret. **Anyone who ever obtains it can replay it indefinitely, from anywhere** -- a leaked
`.env` file, a compromised client machine, or a value exposed in a browser's own Network tab if a
client handles it there. External has no way to tell a legitimate call from a replayed one. Treat
`AUTH_TOKEN` as a basic filter against casual or accidental access -- **not** as proof of who is really
calling.

What actually limits the damage if a token leaks is Severance's named-query design: a stolen
`AUTH_TOKEN` only ever lets someone submit one of the queries **you have already pre-approved and
installed on Internal**, with attacker-chosen values for that query's own variables. It CANNOT be used
to run arbitrary SPARQL, and it CANNOT reveal the query text itself. Choose what queries you install
with that in mind, and rotate `AUTH_TOKEN` immediately if you ever suspect it has been exposed.

### The `docker-compose.yml` you copied looks like this

(Do not type this by hand -- this is here so you know what to expect. Copy the real file, per step 3
above.)

    services:
        external:
            image: XXXXX  # the docker-compose.yml in the external/ folder of the repo points to the latest patch -- copy that file, don't type this by hand
            restart: always
            security_opt:
                - "no-new-privileges:true"
            cap_drop:
                - ALL
            cap_add:
                # entrypoint.sh runs as root to chown the mounted volumes to the
                # severance user before dropping privileges via gosu -- these
                # are the only capabilities that step needs.
                - CHOWN
                - DAC_OVERRIDE
                - FOWNER
                - SETUID
                - SETGID
            mem_limit: 512m
            cpus: 1
            ports: ["3000:3000"]  # runs on 3000 internally
            env_file:
                - .env
            volumes:
                - "./data:/data"
                - "./queries-metadata:/queries-metadata"
            environment:
                - RACK_ENV=production
                - APP_ENV=production     # both for redundancy

### Start it

Run:

    docker-compose up -d

Then look for errors. If you see any, stop and fix them before continuing -- do not move on to
installing Internal with a broken External.

## Test that it's working

**Do these tests in order.** Do not skip ahead.

First, put your `AUTH_TOKEN` in a shell variable, so you can paste the commands below exactly as
written. **Use AUTH_TOKEN here, NOT INNIE_TOKEN!** INNIE_TOKEN is refused on every caller route.

    export AUTH_TOKEN=<paste the AUTH_TOKEN value from your .env here>

### 1. Is it alive?

    curl -v -H "Authorization: Bearer $AUTH_TOKEN" http://localhost:3000/severance

If you see an error here, **stop -- something is wrong.** Check the error message, and check that the
Auth token you used matches `AUTH_TOKEN` in your `.env` file exactly. **The token is case-sensitive!**
If you get `429 Too many failed attempts`, you tried a wrong token too many times. Wait a minute
before trying again.

### 2. Does it know about any queries yet?

    curl -X GET http://localhost:3000/severance/available_queries -H "Authorization: Bearer $AUTH_TOKEN" -H "Accept: application/json"

This returns a JSON list of every query Internal has installed. See the
[`/severance/available_queries`](#severanceavailable_queries) section further down for exactly what
each field in that response means. **If this list is empty, that's expected right now** -- you haven't
started Internal yet, so it hasn't told External about any queries. Keep going.

### 3. Submit a query request

This test asks for `count`, one of Severance's example queries. **Internal only has it if you start
Internal with `SEED_DEMO_QUERIES=true` for this test** -- see
[Managing your queries](../internal/README.md#managing-your-queries). Otherwise, use the `query_id`
of a query you have installed yourself.

    curl -v -X POST http://localhost:3000/severance/queries -H "Content-Type: application/json" -H "Authorization: Bearer $AUTH_TOKEN" -d '{
        "query_id": "count",
        "bindings": {
          "orphacode": "http://www.orpha.net/ORDO/Orphanet_730"
        }
      }'

You should get back:

    HTTP/1.1 201 Created
    Location:  http://localhost:3000/severance/jobs/0b7e3c52-1f4a-4c8e-9d2b-6a5f0e8c1d37
    ...
    ...

The long ID at the end of `Location` is your job ID. **Yours will be different -- use YOUR job ID in
the commands below, not the one shown here!**

### 4. Check the status of what you just submitted

    curl -i -X GET http://localhost:3000/severance/jobs/0b7e3c52-1f4a-4c8e-9d2b-6a5f0e8c1d37 -H "Authorization: Bearer $AUTH_TOKEN" -H "Accept: application/json"

Right now, with Internal not yet running, you should get:

    HTTP/1.1 202 Accepted
    retry-after: 10
    ...
    {"status":"processing"}

**This is expected and correct.** Your request is queued and waiting. It will sit there safely -- no
data is lost -- until Internal comes online and picks it up.

## Now install and start Internal

See [Installing Internal](../internal/README.md). **You will need your `INNIE_TOKEN` and
`ENCRYPTION_KEY_HEX` values there -- copy them exactly!**

The moment Internal starts, it will ask External if it has any queries waiting. Your request from step
3 above will be picked up and answered automatically -- **you do not need to resubmit it.**

### 5. Check the status again, once Internal is running

    curl -i -X GET http://localhost:3000/severance/jobs/0b7e3c52-1f4a-4c8e-9d2b-6a5f0e8c1d37 -H "Authorization: Bearer $AUTH_TOKEN" -H "Accept: application/json"

Now you should get:

    HTTP/1.1 200 OK
    Content-type:  text/csv
    ...
    ...
    count
    123

If you see this, **your installation works end to end.** If you get `200 OK` but an EMPTY answer,
Internal does not have a query called `count` -- see step 3. If you still see `"status": "processing"`
after a reasonable wait, check that Internal actually started without errors and can reach both
External and your triplestore -- see [Installing Internal](../internal/README.md). If External's log
shows `Auth failed` every time Internal polls, **Internal's `INNIE_TOKEN` does not match External's.**

## Upgrading from 1.1.0

**This upgrade changes BOTH components, and they only work as a matched pair!** A new External
refuses an old Internal (the old one sends no `INNIE_TOKEN`). A new Internal's answers cannot be
read by an old External. **Upgrade both at the same time. DO NOT upgrade one and leave the other for
later!**

1. **Let your callers collect any answers that are waiting.** Answers left uncollected from before the
   upgrade CANNOT be read by the new version. They come back as `500 Decryption error`. Requests
   still waiting in the queue are fine -- they will be answered after the upgrade.
2. **Stop Internal, then External.**
3. **Delete any leftover answers:** remove everything in External's `./data/results/` folder.
4. **Edit External's `.env`:**
   - Set `AUTH_TOKEN` to a new value from `openssl rand -hex 32`. **The old `YesItsMe` example, or any
     token shorter than 32 characters, now stops External from starting!**
   - Add `INNIE_TOKEN=` with a *different* value from `openssl rand -hex 32`.
5. **Edit Internal's `.env`:** add the exact same `INNIE_TOKEN` line.
   **Then look in Internal's `./queries` folder!** Older versions copied the example queries in
   automatically, and every query in that folder can be run by anyone with `AUTH_TOKEN`. **Delete
   every example you have not approved** -- `patient_filter.rq` returns individual people's records.
6. **Copy the new `docker-compose.yml` files** from the repo into both folders, as you did when you
   installed.
7. **Start External, then Internal**, and run the tests above again.
8. **Give the new `AUTH_TOKEN` to every caller and facade you serve.** They get `401 Unauthorized`
   until they switch. **NEVER give them `INNIE_TOKEN`!**

# API reference

**Every request needs `Authorization: Bearer <your AUTH_TOKEN>`.** The token is case-sensitive.
These are the errors you can get back, and what they mean:

| Status | Meaning |
| --- | --- |
| `401 Unauthorized` | No token, or the wrong one. |
| `429 Too many failed attempts` | Too many wrong tokens from your address. Wait for the time in `Retry-After`, then try again with the right token. |
| `429 queue_full` | Too many requests are already waiting. Try again later; `Retry-After` says when. |
| `415` | You sent a `multipart/form-data` body. **Severance never accepts multipart!** Send JSON (or a url-encoded form). |
| `413 payload_too_large` | Your request is too big. Query requests are limited to 64 KB by default. |
| `400` | The request is malformed: bad JSON, not UTF-8, a missing `query_id` or one with characters other than letters, digits, `_` and `-`, or `bindings` that isn't a JSON object. |
| `404` | No such job -- or the job ID is not a properly formed UUID. **Answers can be collected only ONCE!** After you have fetched one, its job is gone. Answers nobody collects are deleted after 7 days (`RESULT_TTL_HOURS`). |

## `/severance/available_queries`

**What it does:** returns a JSON list of every named query Internal has installed and made available.
This is how you find out what you're allowed to ask for -- you CANNOT submit a query that isn't in
this list.

**Request:**

    curl -X GET http://localhost:3000/severance/available_queries -H "Authorization: Bearer $AUTH_TOKEN" -H "Accept: application/json"

**Response:**
```
[
    "query_id": "count",
    "title": "Count matching patients",
    "summary": "Returns the number of patients in the registry with the corresponding disease code",
    "tags": [
      "Patient Count"
    ],
    "variables": [
      "orphacode"
    ],
    "variable_types": {
      "orphacode": "iri"
    },
    "examples": {
      "orphacode": "http://www.orpha.net/ORDO/Orphanet_730"
    },
    "endpoint_in_url": false
  }
]
```

This response tells you everything you need to build a query request:

1. **The query identifier** (`query_id`) -- the name you must use, exactly.
2. **The query's variables** -- what you're allowed to fill in.
3. **The type of data each variable expects.**
4. **An example value.** This is for illustration only -- **there is no guarantee it will match any
   real data.**

Using the example above, a valid request body would be:

```
{
    "query_id": "count",
    "bindings": {
      "orphacode": "http://www.orpha.net/ORDO/Orphanet_730"
    }
}
```

**Note:** submit URLs as plain strings. **DO NOT wrap them in `<...>` angle brackets.**

## `/severance/queries`

**What it does:** submits a query request and adds it to the queue.

**You CAN** submit any `query_id` that appears in `available_queries`, with values for exactly the
variables it declares.

**You CANNOT** run a `query_id` that Internal hasn't installed -- Internal refuses to run it. **But you
will NOT get an error!** External can't see which queries Internal has, so it accepts the request,
and the answer you get back is simply EMPTY -- exactly what you would get if no data matched. **An
empty answer does NOT prove there is no matching data!** Always check `available_queries` first, and
spell the `query_id` exactly.

**You CANNOT** add or invent new variables either. Any binding the query doesn't declare is simply
ignored -- it never reaches the query.

**You CANNOT** send a value a query doesn't allow. If a query lists its allowed values (an array in its
`examples`, in `available_queries`), any other value gets the same EMPTY answer -- not an error.

**`bindings` MUST be a JSON object** (`{"name": "value", ...}`), not a list -- anything else is
refused with `400`.

**Request:**
```
curl -v -X POST http://localhost:3000/severance/queries -H "Content-Type: application/json" \
  -H "Authorization: Bearer $AUTH_TOKEN" -d '{ \
    "query_id": "count", \
    "bindings": { \
      "orphacode": "http://www.orpha.net/ORDO/Orphanet_730" \
    } \
  }'
```

The response's `Location` header tells you the exact address to poll for your answer (see step 4
above). **How often the queue is actually checked is entirely up to whoever runs Internal** -- it could
be seconds, minutes, or much longer. Don't assume an instant answer.
