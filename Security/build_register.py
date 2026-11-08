#!/usr/bin/env python3
"""
Builds/updates vulnerability-register.csv from the Trivy scan CSVs in
security_scan_output/. Existing decisions in the register are preserved
across re-runs (keyed on Image+VulnerabilityID); only genuinely new
CVE/image combinations get a fresh default disposition and land in the
"needs review" bucket.

Usage: python3 build_register.py
"""
import csv
import glob
import os
import collections

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SCAN_DIR = os.path.join(SCRIPT_DIR, "security_scan_output")
REGISTER_PATH = os.path.join(SCRIPT_DIR, "vulnerability-register.csv")

# Static per-image classification. Update this as the fleet changes.
# exposure: 1 = network-exposed (directly or one hop via a proxy in front
#               of it)
#           2 = internal-only (reachable only from other containers on the
#               private network, or not currently deployed at all)
#           3 = inert (bundled but never invoked by our deployment)
# control:  owned   = we build this image ourselves from source in this
#                      repo -- every finding is ours to patch directly
IMAGE_INFO = {
    "sevexternal": {"exposure": 1, "control": "owned",
                     "note": "External: the DMZ-facing component. Publishes port 3000 "
                              "directly to the network by design (the whole point of "
                              "Severance's 'severed' model is that this is the only side "
                              "anything outside the secure zone ever talks to). Built from "
                              "our own Dockerfile (external/Dockerfile) -- every finding "
                              "here is ours to patch directly, at the OS layer (this "
                              "pipeline) or the app layer (Gemfile/Dockerfile changes)."},
    "sevinternal": {"exposure": 2, "control": "owned",
                     "note": "Internal: the polling component that talks to the triplestore. "
                              "Never listens on a port (see internal/docker-compose.yml -- no "
                              "network_mode: host, no ports: mapping) and only ever makes "
                              "outbound requests to External and the configured "
                              "TRIPLESTORE_URL, both of which should be on a private/internal "
                              "network in a real deployment. Built from our own Dockerfile "
                              "(internal/Dockerfile) -- every finding here is ours to patch "
                              "directly."},
}
# shallot-facade and beacon-facade used to be patched from here too -- both moved to their own
# dedicated repo, FAIR-Data-Systems/Severance-Facades, on 2026-09-22 (see this repo's CHANGELOG.md).

# Manually researched dispositions, from individual research on each finding (see
# VULNERABILITY_TRIAGE.md). Keys are either a VulnerabilityID (applies to every image) or an
# (Image, VulnerabilityID) tuple (applies to that image only, and wins over a VulnerabilityID-only
# entry). Prefer the tuple form: reachability evidence is about one image's code paths, and a
# CVE-only entry silently re-applies to any other image that later reports the same CVE -- exactly
# how a RESOLVED disposition researched for one image got misapplied to another, still-vulnerable
# one in Sextans-Suite's copy of this pipeline (2026-11-06). Use the CVE-only form only when the
# reasoning is genuinely about the package itself, not about how one image uses it.
#
# Researched 2026-11-06 against images built from external/ and internal/ with the multi-stage
# Dockerfiles (runtime stage = ruby:3.2-slim, Debian 13), after the pipeline's dist-upgrade step.
_OS_NO_FIX = ("Debian has published no fix yet; the next security-patch.sh run picks one up "
              "automatically via dist-upgrade once it exists.")
MANUAL_DECISIONS = {
    # --- Debian base-OS packages (from ruby:3.2-slim itself), identical in both images ---------
    # Neither service runs as root after startup (gosu / `user:`), both compose files set
    # no-new-privileges (so setuid binaries gain nothing), External drops all capabilities except
    # the five its entrypoint needs to chown its volumes, and neither container has an fstab, a
    # login session, or any tool below invoked by our code.
    "CVE-2026-76642": ("ACCEPT", "util-linux mount(8) post-hook privilege escalation: needs a "
                       "local user running setuid mount against fstab entries. No fstab entries, "
                       "no-new-privileges set, mount never invoked. " + _OS_NO_FIX),
    "CVE-2026-78408": ("ACCEPT", "util-linux `nsenter --join-cgroup`: needs a privileged operator "
                       "to run nsenter into an attacker-controlled target. nsenter is never run in "
                       "these containers. " + _OS_NO_FIX),
    "CVE-2026-78409": ("ACCEPT", "util-linux X-mount.subdir symlink escape: needs an "
                       "fstab-authorized X-mount.subdir entry and setuid mount. Neither exists "
                       "here. " + _OS_NO_FIX),
    "CVE-2026-78410": ("ACCEPT", "util-linux restricted bind mount source redirection: needs fstab "
                       "entries and setuid mount. Neither exists here. " + _OS_NO_FIX),
    "CVE-2026-54369": ("ACCEPT", "libacl symlink traversal: needs a privileged process calling "
                       "acl_get/set_file on attacker-controlled paths. Ruby and our code never call "
                       "libacl. " + _OS_NO_FIX),
    "CVE-2025-69720": ("ACCEPT", "ncurses: stack overflow in the `infocmp` command-line tool only. "
                       "Never run. " + _OS_NO_FIX),
    "CVE-2026-119373": ("ACCEPT", "SQLite FTS5 heap overflow: needs attacker-populated FTS5 "
                        "tables. libsqlite3 is in the base image but nothing in Severance opens a "
                        "SQLite database. " + _OS_NO_FIX),
    "CVE-2026-119374": ("ACCEPT", "SQLite FTS5 secure-delete overflow: needs an attacker-supplied "
                        "database file. Severance never opens one. " + _OS_NO_FIX),
    "CVE-2026-119379": ("ACCEPT", "SQLite session-extension changeset overflow: needs "
                        "attacker-supplied changesets. Severance never uses SQLite. " + _OS_NO_FIX),
    "CVE-2026-16742": ("ACCEPT", "systemd-homed privilege escalation: homed is not running (no "
                       "systemd at all in these containers; libsystemd0/libudev1 are just shared "
                       "libraries). " + _OS_NO_FIX),
    "CVE-2026-9538": ("ACCEPT", "Perl Archive::Tar memory exhaustion on a crafted tar: perl-base "
                      "is only used by dpkg/debconf maintainer scripts, never on untrusted tar "
                      "files. Debian status: fix_deferred. " + _OS_NO_FIX),
    "CVE-2026-76844": ("ACCEPT", "zlib gz_write() overflow after a failed write(): only in zlib's "
                       "gzFile API (gzwrite/gzprintf). Ruby's Zlib extension implements gzip on the "
                       "z_stream deflate API and never calls the gzFile functions; no other "
                       "process here uses zlib. (Trivy's title for this entry wrongly names "
                       "webpack-dev-middleware; the description is the zlib bug.) " + _OS_NO_FIX),
    "CVE-2026-85091": ("ACCEPT", "zlib gz_vacate() overflow via gzprintf() after a write stall: "
                       "gzFile API only, never called (see CVE-2026-76844). " + _OS_NO_FIX),

    # --- Ruby default gems: per image, because reachability differs -----------------------------
    # sevinternal runs plain `ruby innie.rb`, not `bundle exec`, so annotate_gem_shadowing.rb's
    # bundle-exec-based check does not apply to it. Since the 2026-11-08 auto-patch (Gemfile pins
    # erb 6.0.7 / resolv 0.8.1, installed into the image), RubyGems activates the newest installed
    # version even without Bundler: verified in the published image fairdatasystems/sevinternal:
    # 2026-11-08 that `require 'resolv'` loads resolv-0.8.1. The flagged default copies cannot be
    # uninstalled (RubyGems refuses for default gems), so they stay on disk, unloaded.
    ("sevinternal", "CVE-2026-80212"): ("SHADOWED", "resolv 0.2.3 is Ruby's default copy, still on disk "
                       "but not loaded: innie.rb loads the installed resolv 0.8.1 (verified in the "
                       "published 2026-11-08 image). Before that fix it was loaded, but only for "
                       "net-http's IPv4/IPv6 address regexes -- the vulnerable DNS decoder "
                       "(Resolv::DNS) never ran, since lookups use getaddrinfo."),
    ("sevinternal", "CVE-2026-80213"): ("SHADOWED", "resolv 0.2.3 is Ruby's default copy, still on disk "
                       "but not loaded: innie.rb loads the installed resolv 0.8.1 (verified in the "
                       "published 2026-11-08 image). The bug (Resolv::DNS::MessageEncoder) was never "
                       "reachable anyway: Resolv::DNS never encodes or sends a query here."),
    ("sevinternal", "CVE-2026-41316"): ("SHADOWED", "erb 4.0.2 is Ruby's default copy, on disk but never "
                       "loaded by innie.rb (verified via $LOADED_FEATURES); erb 6.0.7 is installed "
                       "too since 2026-11-08. The bug also needs Marshal.load of attacker data, which "
                       "innie.rb never does."),

    # --- Network-exposed and genuinely reachable: fixed in source, drops out once rebuilt ------
    ("sevexternal", "GHSA-5v64-555j-wjxm"): ("PATCH", "REACHABLE WITHOUT A TOKEN. Rack's multipart "
                       "parser keeps a crafted body in memory in full, and Sinatra parses request "
                       "params (incl. multipart) before outie.rb's auth filter runs -- enough to "
                       "OOM the 512 MB container. Fixed in source 2026-11-06: rack 3.2.7 -> 3.2.8, "
                       "plus outie.rb now refuses multipart bodies before anything parses them. "
                       "This row disappears once an image built from that source is published."),
}

# Package-wide dispositions, for packages whose findings all share the same reachability argument
# regardless of the individual CVE. Checked after MANUAL_DECISIONS, before the defaults.
PACKAGE_DECISIONS = {
    "linux-libc-dev": ("ACCEPT", "Kernel CVE reported against linux-libc-dev, which contains only "
                       "C header files (2,558 .h files, no executable code -- verified "
                       "2026-11-06). A container never runs its image's kernel; it runs the host's. "
                       "This package should not be in the runtime image at all (it comes with "
                       "build-essential, which the multi-stage Dockerfiles keep in the build stage "
                       "only) -- if it is back, find out why. The bug itself matters only for the "
                       "HOST kernel: keep your host patched."),
}

# Defaults for findings nobody has individually researched yet. Split on whether a fix exists:
# telling a reader to "patch immediately" when there is nothing to patch to is wrong, and was
# true of almost every row the register held before 2026-11-06.
DEFAULT_DECISIONS = {
    (1, "owned", True): ("PATCH", "Network-exposed, and we build this image directly; a fix "
                                  "exists -- patch immediately (bump the pinned dependency, or "
                                  "confirm the next security-patch.sh run's OS-level "
                                  "dist-upgrade already resolves it). Not yet individually "
                                  "reviewed for reachability."),
    (2, "owned", True): ("PATCH", "Internal-only, and we build this image directly; a fix exists "
                                  "-- patch at the next opportunity. Not yet individually "
                                  "reviewed for reachability."),
    (1, "owned", False): ("TRACK", "Network-exposed image, no fix published upstream yet -- the "
                                   "next security-patch.sh run applies one automatically once it "
                                   "exists. Not yet individually reviewed for reachability."),
    (2, "owned", False): ("TRACK", "Internal-only image, no fix published upstream yet -- the "
                                   "next security-patch.sh run applies one automatically once it "
                                   "exists. Not yet individually reviewed for reachability."),
}

SHADOWED_DECISION = (
    "SHADOWED",
    "Flagged copy present on disk but never loaded at runtime -- bundle exec resolves a "
    "newer, Gemfile-pinned version instead (RubyGems refuses to uninstall this compiled "
    "default gem). See the per-image CSV's BundlerShadowedDetail column. Not currently "
    "exploitable via this app's own code path; still worth clearing eventually if Trivy "
    "ever adds a way to suppress filesystem-only findings like this.",
)

# Notes text this script generates by itself. A prior row carrying one of these was never a human
# decision, so it is recomputed every run rather than kept -- otherwise improving a default (or
# adding research above) could never replace what an earlier run wrote. The two strings are the
# pre-2026-11-06 defaults, which older registers still carry.
_GENERATED_NOTES = {n for _, n in DEFAULT_DECISIONS.values()} | {SHADOWED_DECISION[1]} | {
    "Network-exposed, and we build this image directly -- patch immediately (bump the pinned "
    "dependency, or confirm the next security-patch.sh run's OS-level dist-upgrade already "
    "resolves it).",
    "Internal-only, and we build this image directly -- patch at the next opportunity; lower "
    "urgency than (1, owned) given no direct network exposure, but still ours to fix, not to track.",
}


def decide(image, cve, packages, exposure, control, has_fix, shadowed, prior):
    """Disposition for one (image, cve) row. Precedence: researched (image, cve) > researched cve >
    package-wide rule > a prior human decision kept in the register > shadowed > default."""
    if (image, cve) in MANUAL_DECISIONS:
        return MANUAL_DECISIONS[(image, cve)]
    if cve in MANUAL_DECISIONS:
        return MANUAL_DECISIONS[cve]
    if packages and all(p in PACKAGE_DECISIONS for p in packages):
        decisions = {PACKAGE_DECISIONS[p] for p in packages}
        if len(decisions) == 1:
            return decisions.pop()
    if prior and prior[1] not in _GENERATED_NOTES:
        # Sticky human decision -- unless the finding has since become shadowed (the Gemfile now
        # pins a fixed version and annotate_gem_shadowing.rb confirmed bundle exec never loads the
        # flagged copy): that decision predates the fix and was never reviewed against it.
        if not (prior[0] != "SHADOWED" and shadowed == "yes"):
            return prior
    if shadowed == "yes":
        return SHADOWED_DECISION
    return DEFAULT_DECISIONS[(exposure, control, has_fix)]


def load_rows():
    rows = collections.defaultdict(lambda: {
        "packages": set(), "installed": set(), "fixed": set(),
        "severity": None, "title": None, "url": None,
        "shadowed": set(), "shadowed_detail": set(),
    })
    # Only the current run's CSVs live directly in SCAN_DIR (non-recursive glob);
    # everything superseded gets moved into SCAN_DIR/old/ by security-patch.sh
    # and is intentionally excluded from the register.
    for path in sorted(glob.glob(os.path.join(SCAN_DIR, "*.csv"))):
        image = os.path.basename(path).split("_")[1]
        with open(path, newline="") as f:
            for row in csv.DictReader(f):
                key = (image, row["VulnerabilityID"])
                agg = rows[key]
                agg["packages"].add(row["Package"])
                agg["installed"].add(row["InstalledVersion"])
                fv = row["FixedVersion"].strip()
                if fv and fv != "N/A":
                    agg["fixed"].add(fv)
                agg["severity"] = row["Severity"]
                agg["title"] = row["Title"]
                agg["url"] = row["PrimaryURL"]
                # See annotate_gem_shadowing.rb -- set only for gemspec findings it ran against.
                shadowed = (row.get("BundlerShadowed") or "").strip()
                if shadowed:
                    agg["shadowed"].add(shadowed)
                detail = (row.get("BundlerShadowedDetail") or "").strip()
                if detail:
                    agg["shadowed_detail"].add(detail)
    return rows


def shadowed_summary(agg):
    """'yes' only if every contributing package/row was shadowed; 'no' if any real, unaddressed one
    exists; '' if annotate_gem_shadowing.rb never ran against this row (OS packages, or a gemspec
    finding scanned before that annotation step existed)."""
    if not agg["shadowed"]:
        return ""
    return "yes" if agg["shadowed"] == {"yes"} else "no"


def load_existing_decisions():
    existing = {}
    if os.path.exists(REGISTER_PATH):
        with open(REGISTER_PATH, newline="") as f:
            for row in csv.DictReader(f):
                key = (row["Image"], row["VulnerabilityID"])
                existing[key] = (row["Decision"], row["Notes"])
    return existing


def main():
    rows = load_rows()
    existing = load_existing_decisions()

    out_rows = []
    for (image, cve), agg in sorted(rows.items()):
        info = IMAGE_INFO[image]
        exposure, control = info["exposure"], info["control"]

        shadowed = shadowed_summary(agg)
        decision, notes = decide(image, cve, agg["packages"], exposure, control,
                                 bool(agg["fixed"]), shadowed, existing.get((image, cve)))

        out_rows.append({
            "Image": image,
            "VulnerabilityID": cve,
            "Severity": agg["severity"],
            "ExposureTier": exposure,
            "Control": control,
            "Package": "; ".join(sorted(agg["packages"])),
            "InstalledVersion": "; ".join(sorted(agg["installed"])),
            "FixedVersion": "; ".join(sorted(agg["fixed"])) or "N/A",
            "Decision": decision,
            "Notes": notes,
            "Title": agg["title"],
            "PrimaryURL": agg["url"],
            "BundlerShadowed": shadowed,
        })

    # Sort: CRITICAL first, then by exposure tier, then image, then CVE
    sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    out_rows.sort(key=lambda r: (sev_rank.get(r["Severity"], 9), r["ExposureTier"],
                                  r["Image"], r["VulnerabilityID"]))

    fieldnames = ["Image", "VulnerabilityID", "Severity", "ExposureTier", "Control",
                  "Package", "InstalledVersion", "FixedVersion", "Decision", "Notes",
                  "Title", "PrimaryURL", "BundlerShadowed"]
    with open(REGISTER_PATH, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(out_rows)

    counts = collections.Counter(r["Decision"] for r in out_rows)
    print(f"Wrote {len(out_rows)} rows to {REGISTER_PATH}")
    for d, n in counts.most_common():
        print(f"  {d}: {n}")


if __name__ == "__main__":
    main()
