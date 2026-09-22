<img src="../docs/SeverenceSMW.png"/>

# Severance: Secure SPARQL Service

# Installing the External Component

**Read this first.** External is the *only* part of Severance that the outside world ever talks to.
You CAN submit a pre-approved, named query and get an answer back. You CANNOT run arbitrary SPARQL --
Severance will refuse anything that isn't a query the data provider has already installed on Internal.
Keep that in mind while you read the rest of this file.

## What you need before you start

1. `docker compose` installed on your server.
2. An Auth token. Generate one yourself, or use whatever mechanism you like to generate one -- Severance
   doesn't care how you make it, only that you keep it secret afterward.

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
    AUTH_TOKEN=YesItsMe
    ALLOWED_INTERNAL_IPS=172.31.0.1,127.0.0.1,::1,192.168.1.100   # CHANGE 192.168.1.100 to the IP of Internal 
    METADATA_DIR=/queries-metadata  # Don't change this unless you know what you're doing

- **`ENCRYPTION_KEY_HEX`** -- generate your own with `openssl rand -hex 32`. **DO NOT leave the
  placeholder text in place** -- both External and Internal refuse to start if you do. This exact same
  key **must** also be set on Internal, or nothing will decrypt correctly.
- **`AUTH_TOKEN`** -- your callers' shared secret. Anyone who has it can call your service. See the
  warning below for what this does and does not protect against.
- **`ALLOWED_INTERNAL_IPS`** -- a whitelist of addresses allowed to reach the parts of the API that
  don't require an Auth token (this is how Internal talks to External). Each entry can be a bare IP
  (`192.168.1.100`), a CIDR range (`192.168.1.0/24`), or the word `localhost`. **Keep this list as short
  as possible.** During testing you can include `localhost`/`127.0.0.1`; in production it should
  contain only Internal's real address.
- **Everything marked "DO NOT CHANGE"** -- leave it alone unless you have read the code and know exactly
  what you're doing.

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

### 1. Is it alive?

    curl -v -H "Authorization: Bearer YesItsMe" http://localhost:3000/severance

If you see an error here, **stop -- something is wrong.** Check the error message, and check that the
Auth token you used matches `AUTH_TOKEN` in your `.env` file exactly.

### 2. Does it know about any queries yet?

    curl -X GET http://localhost:3000/severance/available_queries -H "Authorization: Bearer YesItsMe" -H "Accept: application/json"

This returns a JSON list of every query Internal has installed. See the
[`/severance/available_queries`](#severanceavailable_queries) section further down for exactly what
each field in that response means. **If this list is empty, that's expected right now** -- you haven't
started Internal yet, so it hasn't told External about any queries. Keep going.

### 3. Submit a query request

    curl -v -X POST http://localhost:3000/severance/queries -H "Content-Type: application/json" -H "Authorization: Bearer YesItsMe" -d '{
        "query_id": "count",
        "bindings": {
          "orphacode": "http://www.orpha.net/ORDO/Orphanet_730"
        }
      }'

You should get back:

    HTTP/1.1 201 Created
    Location:  http://localhost:3000/severance/jobs/ABC123
    ...
    ...

### 4. Check the status of what you just submitted

    curl -X GET http://localhost:3000/severance/jobs/ABC123 -H "Authorization: Bearer YesItsMe" -H "Accept: application/json"

Right now, with Internal not yet running, you should get:

    ...
    HTTP/1.1 201 Created...
    Location:  http://localhost:3000/severance/jobs/ABC123
    retry-after: 10
    ...
    {"status": "processing"}

**This is expected and correct.** Your request is queued and waiting. It will sit there safely -- no
data is lost -- until Internal comes online and picks it up.

## Now install and start Internal

See [Installing Internal](../internal/README.md).

The moment Internal starts, it will ask External if it has any queries waiting. Your request from step
3 above will be picked up and answered automatically -- **you do not need to resubmit it.**

### 5. Check the status again, once Internal is running

    curl -X GET http://localhost:3000/severance/jobs/ABC123 -H "Authorization: Bearer YesItsMe" -H "Accept: application/json"

Now you should get:

    HTTP/1.1 200 OK
    Content-type:  text/csv
    ...
    ...
    count
    123

If you see this, **your installation works end to end.** If you still see `"status": "processing"`
after a reasonable wait, check that Internal actually started without errors and can reach both
External and your triplestore -- see [Installing Internal](../internal/README.md).

# API reference

## `/severance/available_queries`

**What it does:** returns a JSON list of every named query Internal has installed and made available.
This is how you find out what you're allowed to ask for -- you CANNOT submit a query that isn't in
this list.

**Request:**

    curl -X GET http://localhost:3000/severance/available_queries -H "Authorization: Bearer YesItsMe" -H "Accept: application/json"

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

**You CANNOT** submit a `query_id` that Internal hasn't installed, and you CANNOT add or invent new
variables -- either will be rejected.

**Request:**
```
curl -v -X POST http://localhost:3000/severance/queries -H "Content-Type: application/json" \
  -H "Authorization: Bearer YesItsMe" -d '{ \
    "query_id": "count", \
    "bindings": { \
      "orphacode": "http://www.orpha.net/ORDO/Orphanet_730" \
    } \
  }'
```

The response's `Location` header tells you the exact address to poll for your answer (see step 4
above). **How often the queue is actually checked is entirely up to whoever runs Internal** -- it could
be seconds, minutes, or much longer. Don't assume an instant answer.
