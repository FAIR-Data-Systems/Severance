<img src="./docs/SeverenceSMW.png"/>

# Severance: Secure SPARQL Service

A highly secure, very lightweight, query system

The name comes from the popular TV series [Severance](en.wikipedia.org/wiki/Severance_(TV_series)) where there is no communication between someone's "public facing self", and their "work self".  The transition happens while riding the elevator to their office (the project logo). The outside world is completely excluded from the internal, very sensitive business.

##  Install instructions (do things in this order!)

* [Installing External](./external/README.md)
* [Installing Internal](./internal/README.md)


## Severed for Security: Users are Outside, Queries stay Inside

**Query Flow Diagram**

<img src="./docs/Severence%20Functionality.png"/>

**Interoperability and Security Features:**
1. Requires an authorization token (from whatever mechanism you wish)
2. Queries are named and pre-approved, not arbitrary;
3. The query itself is never passed.  It exists only in the internal component. refered-to by name
4. Follows Web standards for queued processes
5. External and Internal components are fully independent (containers); internal can be switched off and external will continue to queue (no lost requests)
6. No external connection to the secure area→ Inside to Outside only
7. Impossible to DoS the Internal component - queue is accessed one-query-at-a-time
8. Data in the “intermediate store” is immediately encrypted upon arrival  (in principle, it could be sent encrypted, if we ensure both sides share an encryption key)
10. Data is decrypted and deleted as soon as it is called by the user - no second chances, but also lower risk
11. Unencrypted data never touches the disk. It is only ever held in-memory - coming from Internal or being requested by the user.
12. Variables containing unencrypted data are "zero'd out" and cleard immediately after data is encrypted
13. The Internal component runs with a RAM-based tempfile system, such that attempts to write to /tmp do not go to disk
14. Code content of the Docker Containers is minimal - very low profile for security risks.
15. Containers both run as unprivileged users
16. Current codebase allows both CSV and JSON responses

**Possible Attacks?**
1. Modify queries - high impatct attack.  Likelihood?  Attacker needs to either a) secretly change the query in the GitHub so that a corrupted query is pulled by the Inside.  b) the Inside needs to forget to vet the queries they author or pull from GitHub (since this is voluntary and manual!) or c) the attacker is already inside the protected space and has file-level access to modify the query - in that case, there are bigger problems!  Most likely attacker profile for all of these is a rogue employee
2. Modification of Docker Image - high-impact attack.  Similar risk profile as above.
3. All other attacks we can imagine already require the attacker to be inside of the Secure Zone, which is already at the highest level of impact regardless of this software security.
