<img src="../docs/SeverenceSMW.png"/>

# Severance: Secure SPARQL Service

# Installing the Internal Component

**Read this first.** Internal is the only part of Severance that can actually see your triplestore.
It NEVER listens on a network port and NEVER accepts a connection from outside -- it only ever reaches
*out* to External and your triplestore. **DO NOT install Internal before you have External installed
and working** -- see [Installing External](../external/README.md) first if you haven't already.

## What you need before you start

1. **A Virtuoso instance, up and running**, containing your data.
2. **Patient Registry data following the CARE-SM-2 model**, loaded into a named graph. (Virtuoso is
   one-instance-one-database, with no separate "repository" concept the way GraphDB has -- your
   installs are isolated from each other by named graph, not by repository name.)
3. **A Virtuoso user with read-only (`SPARQL_SELECT`) access to that data.** This CANNOT be an
   anonymous account -- see the note on `TRIPLESTORE_USER`/`TRIPLESTORE_PASS` below for why.
4. **An instance of Severance External already running**, in your DMZ.
5. **A network path from this server to that External instance.** If this server cannot reach
   External's API URL, nothing else in this guide will work.

## Step-by-step setup

1. **Start with an empty folder.** As yourself, NOT as root, create a subfolder inside it called
   `./queries`.
2. **Copy `env_template` to `.env`** in that same folder, and edit it as described below.
3. **Create a `docker-compose.yml`** as shown below.

### Editing `.env`

    # must be the same key as the External component!
    ENCRYPTION_KEY_HEX=<generate with: openssl rand -hex 32>
    RESULT_FORMAT=csv  # must be the same as the External component!
    QUERY_DIR=/queries  # DO NOT CHANGE THIS unless you really know what you're doing
    EXTERNAL_URL=http://111.111.111.111:3000   # The URL to the External API.  
    TRIPLESTORE_URL=http://localhost:8890/sparql-auth  # Virtuoso's Digest-authenticated SPARQL endpoint
    TRIPLESTORE_USER = <your Virtuoso read-only username>
    TRIPLESTORE_PASS = <your Virtuoso read-only password>
    POLL_INTERVAL=10  # seconds
    UID=1000   #  at terminal:   id -u
    GID=1000   # at terminal:  id -g

- **`ENCRYPTION_KEY_HEX`** -- **must be the exact same value you set on External.** Generate it once
  with `openssl rand -hex 32`, then copy it to both `.env` files. **DO NOT leave the placeholder text
  in place** -- Internal refuses to start if you do.
- **`RESULT_FORMAT`** -- must also match External's setting, exactly.
- **`EXTERNAL_URL`** -- the real, reachable address of your External instance.
- **`TRIPLESTORE_URL`/`TRIPLESTORE_USER`/`TRIPLESTORE_PASS`** -- read the warning below before you set
  these.
- **`UID`/`GID`** -- run `id -u` and `id -g` at your terminal and put the real numbers here. Do not
  guess. See the warning below.

**A warning about `TRIPLESTORE_URL`/`TRIPLESTORE_USER`/`TRIPLESTORE_PASS` -- read this, don't skip
it.** Virtuoso's plain `/sparql` endpoint serves the anonymous `nobody` account, which -- unless a
deployment has deliberately locked it down -- **can read every graph in the store with no credentials
at all.** Internal will only use the safer, authenticated `/sparql-auth` endpoint if you set
`TRIPLESTORE_USER`/`TRIPLESTORE_PASS`. If you leave those blank, Internal falls back to an
**unauthenticated** request -- only acceptable if your triplestore genuinely doesn't require auth for
reads. **When credentials are set, they must be a real Digest-authenticated account** -- Virtuoso
rejects Basic auth outright on its authenticated endpoints.

Once you've edited it, save it as `.env` in your folder. `UID`/`GID` are what let *you* modify the
`./queries` folder later, not just the container.

**Before going further, test that this server can actually reach External:** call, e.g.
`http://111.111.111.111:3000/severance` from this machine. You should get either a plain message back,
or an "Unauthorized" response -- both mean the connection works. **Any other kind of error means this
server cannot see External, and nothing else in this guide will work until you fix that.**

### Creating `docker-compose.yml`

**Three rules. Follow all three, or the container will not run correctly, if at all:**

1. **NEVER start this container as root.** You have been warned.
2. **`UID` and `GID` must be the real values for your user**, not a guess. Run `id -u` and `id -g` at
   your terminal and use exactly what they print. The default of `1000`/`1000` is *usually* right on a
   fresh Linux install, but don't assume it -- check.
3. **DO NOT use `network_mode: host`.** Internal never listens on a port of its own, so it doesn't need
   it, and it makes the container reachable in ways it shouldn't be.

**Internal must be able to reach External and your triplestore**, exactly as you tested above.

**The normal case -- Internal and External on separate servers (the expected "Severed" deployment
topology):** you don't need to do anything extra. Ordinary Docker bridge networking already reaches any
real IP address or domain name on your LAN or the internet -- this is standard outbound connectivity,
unrelated to `network_mode: host`. Just set `EXTERNAL_URL`/`TRIPLESTORE_URL` to the real address of
those servers.

**The one case that needs something extra -- testing with Internal and External on the *same*
machine:** inside a container, `localhost` means the container itself, not your host machine. If
you're running everything on one box for testing, point `EXTERNAL_URL`/`TRIPLESTORE_URL` at
`host.docker.internal` instead of `localhost` -- the `extra_hosts` entry below makes that work.

**Do not type the block below by hand** -- copy the real `docker-compose.yml` from the `internal/`
folder of the repo. This is here so you know what to expect:

    services:
      internal:
        image: XXXXX  # the docker-compose.yml in the internal/ folder of the repo points to the latest patch -- copy that file, don't type this by hand
        restart: always
        security_opt:
          - "no-new-privileges:true"
        cap_drop:
          - ALL
        mem_limit: 512m
        cpus: 1
        extra_hosts:
          - "host.docker.internal:host-gateway"   # a localhost-equivalent for same-host testing
        env_file: .env
        volumes:
          - "./queries:/queries"
        tmpfs:
          - /tmp:size=64m,noexec,nosuid,nodev
        environment:
          - TMPDIR=/tmp
          - UID=${UID:-1000}   #the output of  id -u at the terminal, set in .env
          - GID=${GID:-1000}   #the output of  id -g at the terminal, set in .env
        user: "${UID:-1000}:${GID:-1000}"   # Run container as your host user, or 1000 fallback (which is usually the first non-root user created on a Linux system)  

### Start it

**DO NOT start Internal until you have installed and tested External.** You'll need to run some tests
on External that would be interrupted by Internal's own polling.

Once External is confirmed working:

    docker-compose up -d

## Managing your queries

Your `./queries` folder holds the queries Severance is allowed to run -- **nothing outside this folder
can ever be queried.**

- On first start, this folder is populated with example queries.
- **You CAN edit or add queries here** -- your changes survive a `compose down`/`compose up`.
- **You CAN reset to the examples** -- delete everything in `./queries` and restart; it will be
  re-populated.
- **The folder is re-read every time Internal polls External** -- you can change queries here at any
  time and they'll take effect on the next polling cycle, with no restart needed.

See [the query-authoring guide](./sample_queries/README.md) for how to write a query so Severance (and
the UI on the External side) can understand it correctly. (That guide lives next to the example queries
themselves, which is also where your running `./queries` folder gets its starting content from.)
