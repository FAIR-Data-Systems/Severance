<img src="./docs/SeverenceSMW.png"/>

# Severance: Secure SPARQL Service

A highly secure, very lightweight, query system that lets outside applications run pre-approved
SPARQL queries against a protected internal triplestore -- without ever exposing the triplestore,
the query text, or an open SPARQL endpoint to the outside world. **Users are Outside, Queries stay
Inside.**

The name comes from the popular TV series [Severance](en.wikipedia.org/wiki/Severance_(TV_series))
where there is no communication between someone's "public facing self" and their "work self." The
transition happens while riding the elevator to their office (the project logo). The outside world
is completely excluded from the internal, very sensitive business.

**Version:** `1.1.0` (see [`VERSION`](VERSION); the running services also report it themselves --
External's `GET /severance` includes it in its plain-text response, and Internal logs it once at
startup). Maintaining/releasing this project? See [`RELEASING.md`](RELEASING.md).

## Getting started (do things in this order!)

* [Installing External](./external/README.md)
* [Installing Internal](./internal/README.md)

Both must be running for the system to actually answer anything! Deploy only External and it will
queue requests forever without ever returning a result -- it never talks to the triplestore itself,
only Internal does.

## Using Severance from another application (Facades)

A caller that needs Severance's query results in some other Interface (REDCap, GA4GH Beacon v2, a Shallot/GRLC-shaped service, or anything else) doesn't talk to External directly -- it goes through a
**facade**: a thin translation layer that speaks the external API on one side and only ever calls
External's own public API (`available_queries`, `queries`, `jobs/:uuid`) on the other. Facades live in
their own repo, [`FAIR-Data-Systems/Severance-Facades`](https://github.com/FAIR-Data-Systems/Severance-Facades)
-- see that repo's README for the two existing examples (`shallot-facade`, `beacon-facade`) and a
"How to implement a new facade" guide if you're building another one.  Note that EURO-NMD have implemented their own "facade" for REDCap, and can provide advice on how to do that.

**Building or installing a facade does NOT give you access to any data!** A facade only provides an
interface to queries the data provider has already approved and registered in Severance Internal. If
the query you need doesn't exist there yet, you must negotiate with the data provider to get it added
-- no facade, however cleverly built, can get you data through a query that was never registered.

## How it works: the security model

**Query Flow Diagram**

<img src="./docs/Severence%20Functionality.png"/>

**Interoperability and Security Features:**

1. Requires an authorization token (from whatever mechanism you wish).
2. Queries are named and pre-approved, not arbitrary -- **you cannot run arbitrary SPARQL through Severance, ever, no matter what token or facade you have.**
3. The query itself is never passed -- it exists only in the internal component, referred to by name.
4. Follows web standards for queued processes.
5. External and Internal components are fully independent (containers); Internal can be switched off and External will continue to queue (no lost requests).
6. No external connection to the secure area -- Inside to Outside only.
7. Impossible to DoS the Internal component -- the queue is accessed one query at a time.
8. Data in the "intermediate store" is immediately encrypted upon arrival from the Triplestore.
9. Data is decrypted and deleted as soon as it is called by the user -- no second chances, but also lower risk.
10. Unencrypted data never touches the disk; on both Internal and External, it is only ever held in-memory.
11. Variables containing unencrypted data, and the web server cache, are "zero'd out" and cleared from memory immediately after data is encrypted, minimizing the time unencrypted data is stored in memory.
12. The Internal component runs with a RAM-based tempfile system, so attempts to write to `/tmp` do not go to disk.
13. Code content of the Docker containers is minimal -- a very low profile for security risks.
14. Containers both run as unprivileged users.
15. Incoming query bindings are cleansed before being placed into a query, not merely quoted: `iri`-typed bindings are validated against the SPARQL 1.1 `IRIREF` grammar's disallowed characters and rejected outright (not sanitized and passed through) if invalid, and other typed bindings are quote-escaped. This closes off using a pre-approved query's own parameters as an injection vector to reach data outside that query's intended scope -- see `CHANGELOG.md` for the vulnerability this fixed.

### Threat model

**A note on how this and the list below are produced:** several of the items above and the attack
scenarios below (including the injection fix referenced in #15) were identified through
simulated/predicted attack analysis performed with Claude AI, not from a professional penetration
test or formal security audit. This is a useful additional lens, but it is not a substitute for one,
and there is no guarantee it has found every vulnerability. Treat this list as "known issues
considered and addressed so far," not as "a certified list of everything that could go wrong."

**Possible Attacks?**

1. **Modify queries** -- high-impact attack. Likelihood? An attacker needs to either a) secretly change the query in GitHub so that a corrupted query is pulled by the Inside; b) count on the Inside forgetting to vet the queries they author or pull from GitHub (since this is voluntary and manual!); or c) already be inside the protected space with file-level access to modify the query -- in which case there are bigger problems! The most likely attacker profile for all of these is a rogue employee.
2. **Modification of the Docker image** -- high-impact attack, similar risk profile to above.
3. All other attacks we can imagine already require the attacker to be inside the Secure Zone, which is already the highest level of impact regardless of this software's security.
4. **`AUTH_TOKEN` capture/replay** -- real, and worth understanding rather than assuming away. `AUTH_TOKEN` is a static, unsigned bearer value: whoever configures a client (a browser app, RedCap, a custom facade, etc.) to send it must keep it secret, but nothing in the protocol itself binds it to a specific request, a specific time window, or a specific caller. Anyone who ever sees the value -- a leaked config file, a compromised client host, a value visible in a client's own browser devtools/Network tab if it's ever handled client-side -- can replay it indefinitely from anywhere. **This is bounded, not eliminated, by the named-query design**: a stolen token only ever grants "submit one of the pre-approved `query_id`s with attacker-chosen binding values" -- never arbitrary SPARQL, never discovery of the query text itself (which never leaves Internal). Don't rely on `AUTH_TOKEN` as strong evidence of *who* is calling, only as a basic filter against casual/accidental access; if a specific integration needs real per-caller distinction, that has to be built into the query design (bindings, tighter per-query allow-lists) rather than assumed from the token.
