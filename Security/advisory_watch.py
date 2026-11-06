#!/usr/bin/env python3
"""
Reports NEW security advisories that might matter to Severance -- it does not judge or fix
anything. Meant to run on a schedule (e.g. a Hermes cron job) and be relayed to a human as-is.

Two sources, because the 2026-11-06 Vantage6 case showed neither is enough on its own:

1. PEER PROJECTS' OWN ADVISORIES, read straight from each repository. A peer's advisories describe
   design flaws (missing authorization checks, allow-by-default, tokens that never expire) that no
   scanner can find in OUR code -- but the same kind of flaw can exist here. Read from the repo
   itself because GitHub's global advisory database and OSV (what Trivy uses) can lag by weeks or
   never get them: Vantage6's HIGH advisories of 2026-09-22 were still absent from both on
   2026-11-06.
   Plus the peer's own release notes and news page, because some of the most serious events never
   become advisories at all (see PEER_PAGES).
2. OUR OWN DEPENDENCIES: every gem version pinned in the lockfiles below, checked against RubySec
   and OSV; and Debian's security announcements for the packages inside our images.

Prints exactly "NO NEW ADVISORIES" when there is nothing new. Any source that fails is reported
as "WATCHER ERROR: ..." -- a silently broken watcher is worse than none. The first run records
everything already published as seen, and shows only the last 30 days.

Usage: python3 advisory_watch.py            (state file next to this script)
       ADVISORY_WATCH_STATE=/path/state.json python3 advisory_watch.py
Optional: GITHUB_TOKEN (any token, no scopes needed) raises GitHub's rate limit from 60/hour.
Standard library only.
"""
import datetime
import json
import os
import re
import sys
import urllib.error
import urllib.request

# Projects similar enough to Severance that their design flaws are worth checking for here.
# Add any you hear about -- one "owner/repo" per entry.
PEER_REPOS = [
    "vantage6/vantage6",
]

# Places where peer projects announce security fixes and incidents that NEVER become GitHub advisories.
# Vantage6's two biggest events of 2026 were in neither: the April compromise of their image registry
# (malware injected into published images -- only on their news page) and the October eMudhra CA
# incident (only in their release notes). Modes:
#   "lines" -- report new lines of the page that mention security (for release notes / changelogs)
#   "links" -- report new articles linked under the given path whose text mentions security (news pages)
PEER_PAGES = [
    ("vantage6 release notes", "https://docs.vantage6.ai/en/latest/release_notes.html", "lines", None),
    ("vantage6 news", "https://distributedlearning.ai/news/", "links", "/news/"),
]
# "security", not "secur": vantage6's site puts "Secure Insight eXchange" on every page.
SECURITY_WORDS = re.compile(r"\bsecurity\b|vulnerab|\bCVE-|\bGHSA-|compromis|malicious|malware|unauthori[sz]ed|"
                            r"breach|incident|exploit|attack|leak|inject|distrust", re.I)

# Debian's security announcements, for the Debian source packages inside Severance's runtime images
# (ruby:3.2-slim, Debian 13). An announcement can arrive here before Trivy scores it -- DSA-6572-1
# (ca-certificates still trusting the compromised eMudhra CA hierarchy) was only ever UNKNOWN in Trivy.
# Regenerate the list after a base-image change with, in each runtime image:
#   dpkg-query -W -f '${source:Package}\n' | sort -u
DEBIAN_DSA_FEED = "https://www.debian.org/security/dsa-long.rdf"
DEBIAN_SOURCE_PACKAGES = set("""
acl apt attr audit base-files base-passwd bash bzip2 ca-certificates cdebconf coreutils dash db5.3
debconf debian-archive-keyring debianutils diffutils dpkg findutils gcc-14 glibc gmp gosu grep gzip
hostname init-system-helpers libbsd libcap2 libcap-ng libffi libmd libseccomp libselinux libsemanage
libsepol libxcrypt libyaml libzstd lz4 mawk ncurses nettle openssl pam pcre2 perl readline
rust-sequoia-sqv sed shadow sqlite3 systemd sysvinit tar tzdata util-linux xxhash xz-utils zlib
""".split())

# Lockfiles of everything we ship, as public raw URLs.
LOCKFILES = {
    "Severance external": "https://raw.githubusercontent.com/FAIR-Data-Systems/Severance/master/external/Gemfile.lock",
    "Severance internal": "https://raw.githubusercontent.com/FAIR-Data-Systems/Severance/master/internal/Gemfile.lock",
    "beacon-facade": "https://raw.githubusercontent.com/FAIR-Data-Systems/Severance-Facades/main/beacon-facade/Gemfile.lock",
    "shallot-facade": "https://raw.githubusercontent.com/FAIR-Data-Systems/Severance-Facades/main/shallot-facade/Gemfile.lock",
}

STATE_PATH = os.environ.get("ADVISORY_WATCH_STATE") or os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "advisory_watch_state.json")
FIRST_RUN_DAYS = 30
TIMEOUT = 30


def http_json(url, data=None):
    headers = {"User-Agent": "severance-advisory-watch", "Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(data).encode()
    if url.startswith("https://api.github.com/") and os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = "Bearer " + os.environ["GITHUB_TOKEN"]
    with urllib.request.urlopen(urllib.request.Request(url, data=data, headers=headers), timeout=TIMEOUT) as r:
        return json.load(r)


def http_text(url):
    req = urllib.request.Request(url, headers={"User-Agent": "severance-advisory-watch"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return r.read().decode("utf-8")


def peer_advisories(repo):
    """Published advisories of one repository, newest first."""
    url = (f"https://api.github.com/repos/{repo}/security-advisories"
           "?state=published&sort=published&direction=desc&per_page=100")
    items = []
    for a in http_json(url):
        items.append({
            "key": f"peer:{repo}:{a['ghsa_id']}",
            "published": (a.get("published_at") or "")[:10],
            "text": (f"[PEER PROJECT] {repo}  {(a.get('severity') or '?').upper()}  {a['ghsa_id']}"
                     f"{'  (' + a['cve_id'] + ')' if a.get('cve_id') else ''}"
                     f"  published {(a.get('published_at') or '?')[:10]}\n"
                     f"  {a.get('summary') or ''}\n"
                     f"  {a.get('html_url') or ''}\n"
                     "  -> To consider: could Severance have the same KIND of flaw?"),
        })
    return items


def page_text(html_text):
    """Visible text of an HTML page, one block per line, whitespace normalised."""
    import html
    html_text = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", html_text)
    # Blocks end only at block-level tags: source HTML often wraps a single sentence over several lines.
    html_text = re.sub(r"(?i)<(br|/p|/li|/h\d|/div|/tr|/dd|/dt|/section|/article|/nav|/footer)\b[^>]*>",
                       "\x00", html_text)
    text = html.unescape(re.sub(r"<[^>]+>", " ", html_text))
    return [b for b in (re.sub(r"\s+", " ", block).strip() for block in text.split("\x00")) if b]


def page_lines(label, url):
    """New security-relevant lines of a release-notes page. No date is known for a line, so on a first
    run they are recorded silently rather than shown."""
    import hashlib
    items = []
    for line in page_text(http_text(url)):
        if len(line) >= 20 and SECURITY_WORDS.search(line):
            digest = hashlib.sha1(line.encode()).hexdigest()[:16]
            items.append({"key": f"page:{label}:{digest}", "published": "",
                          "text": (f"[PEER RELEASE NOTES] {label}\n  {line[:400]}\n  {url}\n"
                                   "  -> To consider: does this fix a KIND of flaw Severance could have?")})
    return items


def page_links(label, url, prefix, first_run):
    """New articles linked from a news page under `prefix`. Each new one is fetched (only when new) and
    reported if its text mentions security; others are just recorded as seen."""
    from urllib.parse import urljoin, urlparse
    host = urlparse(url).netloc
    index_html = http_text(url)
    # Text every page of the site shares (menus, footer, taglines) -- removed from articles before they
    # are checked, so boilerplate never makes an article look security-related.
    boilerplate = set(page_text(index_html))
    links = set()
    for href in re.findall(r'href="([^"#]+)', index_html):
        full = urljoin(url, href)
        path = urlparse(full).path
        if urlparse(full).netloc == host and path.startswith(prefix) and path.rstrip("/") != prefix.rstrip("/"):
            links.add(full)
    items = []
    for link in sorted(links):
        item = {"key": f"news:{label}:{link}", "published": "", "relevant": False, "link": link,
                "label": label, "boilerplate": boilerplate}
        items.append(item)
    return items


def describe_news(item):
    """Fetches a new article and decides whether it mentions security."""
    try:
        text = " ".join(b for b in page_text(http_text(item["link"])) if b not in item["boilerplate"])
    except (urllib.error.URLError, OSError, ValueError) as e:
        item["relevant"] = True  # can't tell -- report it rather than risk missing an incident notice
        text = f"(could not fetch the article to check it: {type(e).__name__})"
    match = SECURITY_WORDS.search(text) or SECURITY_WORDS.search(item["link"])
    if match:
        item["relevant"] = True
        start = max(0, match.start() - 150)
        title = item["link"].rstrip("/").rsplit("/", 1)[-1].replace("-", " ")
        item["text"] = (f"[PEER NEWS] {item['label']}: \"{title}\"\n  ...{text[start:start + 350]}...\n"
                        f"  {item['link']}\n"
                        "  -> To consider: is this an incident (e.g. compromised images or keys) that touches "
                        "anything we use, or a kind of flaw Severance could have?")
    return item


def debian_dsas():
    """Debian security announcements for packages inside our images."""
    import xml.etree.ElementTree as ET
    req = urllib.request.Request(DEBIAN_DSA_FEED, headers={"User-Agent": "severance-advisory-watch"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        root = ET.fromstring(r.read())
    ns = {"rss": "http://purl.org/rss/1.0/", "dc": "http://purl.org/dc/elements/1.1/"}
    items = []
    for it in root.findall("rss:item", ns):
        title = (it.findtext("rss:title", "", ns) or "").strip()
        m = re.match(r"^(DSA-\d+-\d+)\s+(\S+)", title)
        if not m or m.group(2) not in DEBIAN_SOURCE_PACKAGES:
            continue
        date = (it.findtext("dc:date", "", ns) or "")[:10]
        items.append({"key": f"dsa:{m.group(1)}", "published": date,
                      "text": (f"[OUR BASE OS] Debian {title}  published {date or '?'}\n"
                               f"  {(it.findtext('rss:description', '', ns) or '').strip()[:300]}\n"
                               f"  {(it.findtext('rss:link', '', ns) or '').strip()}\n"
                               "  -> To consider: this package is inside Severance's images; the next "
                               "security-patch.sh run applies the fix -- run it sooner?")})
    return items


def locked_gems(lockfile_text):
    """(name, version) for every gem in a Gemfile.lock's GEM specs (4-space-indented lines)."""
    gems = set()
    for name, version in re.findall(r"^    ([A-Za-z0-9_.\-]+) \(([^)\s]+)\)$", lockfile_text, re.M):
        # Platform gems look like "nokogiri (1.16.0-x86_64-linux)"; OSV wants the bare version.
        gems.add((name, re.sub(r"-(?=[a-z]).*$", "", version)))
    return sorted(gems)


# --- RubySec (rubysec/ruby-advisory-db): what bundler-audit and Trivy use for gems. Checked as well
# as OSV because it can be ahead of it: rack's GHSA-5v64-555j-wjxm (2026-10-30) was in RubySec, but
# in neither OSV nor GitHub's global database, on 2026-11-06.
RUBYSEC_TARBALL = "https://codeload.github.com/rubysec/ruby-advisory-db/tar.gz/refs/heads/master"


def gem_version(v):
    """RubyGems-style ordering key: numeric segments compare as numbers; a letter segment marks a
    pre-release, which sorts before the release ("3.2.0.rc1" < "3.2.0")."""
    return [(1, int(s)) if s.isdigit() else (0, s) for s in re.findall(r"\d+|[A-Za-z]+", v)]


def _cmp(a, b):
    a, b = gem_version(a), gem_version(b)
    n = max(len(a), len(b))
    a, b = a + [(1, 0)] * (n - len(a)), b + [(1, 0)] * (n - len(b))
    return (a > b) - (a < b)


def satisfies(version, requirement):
    """Whether `version` meets a RubyGems requirement such as "~> 3.1.23" or ">= 1.0, < 2.0"."""
    for part in requirement.split(","):
        m = re.match(r"\s*(~>|>=|<=|!=|=|>|<)?\s*([0-9A-Za-z.\-]+)\s*$", part)
        if not m:
            return False
        op, target = m.group(1) or "=", m.group(2)
        c = _cmp(version, target)
        if op == "~>":
            segs = [s for s in re.findall(r"\d+", target)]
            upper = ".".join(segs[:-2] + [str(int(segs[-2]) + 1)]) if len(segs) > 1 else str(int(segs[0]) + 1)
            ok = c >= 0 and _cmp(version, upper) < 0
        else:
            ok = {"=": c == 0, "!=": c != 0, ">": c > 0, "<": c < 0, ">=": c >= 0, "<=": c <= 0}[op]
        if not ok:
            return False
    return True


def parse_rubysec(text):
    """The few fields we need from one advisory's YAML (stdlib has no YAML parser): scalars,
    including titles folded onto indented continuation lines, and the two version lists."""
    adv, key = {"patched_versions": [], "unaffected_versions": []}, None
    for line in text.splitlines():
        top = re.match(r"^(\w+):\s*(.*)$", line)
        if top:
            key, value = top.group(1), top.group(2).strip()
            if key not in adv:
                adv[key] = value.strip("'\"")
        elif key in ("patched_versions", "unaffected_versions") and line.strip().startswith("- "):
            adv[key].append(line.strip()[2:].strip().strip("'\""))
        elif key == "title" and line.startswith("  ") and line.strip():
            adv["title"] += " " + line.strip()
    return adv


def load_rubysec(gem_names):
    """Advisories for the given gems, as {gem: [(advisory id, fields), ...]}."""
    import io
    import tarfile
    req = urllib.request.Request(RUBYSEC_TARBALL, headers={"User-Agent": "severance-advisory-watch"})
    with urllib.request.urlopen(req, timeout=TIMEOUT * 4) as r:
        data = r.read()
    found = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        for member in tar:
            m = re.match(r"^[^/]+/gems/([^/]+)/([^/]+)\.yml$", member.name)
            if m and m.group(1) in gem_names and member.isfile():
                text = tar.extractfile(member).read().decode("utf-8", "replace")
                found.setdefault(m.group(1), []).append((m.group(2), parse_rubysec(text)))
    if not found and gem_names:
        # Every lockfile has advisories for *something* historically (rack, puma, ...); finding
        # none at all means the archive layout changed, not that everything is clean.
        raise ValueError("RubySec archive held no advisories for any of our gems -- layout changed?")
    return found


def rubysec_advisories(label, gems, db):
    items = []
    for name, version in gems:
        for adv_id, adv in db.get(name, []):
            if any(satisfies(version, r) for r in adv["patched_versions"] + adv["unaffected_versions"]):
                continue
            items.append({
                "key": f"dep:{label}:{name}:{adv_id}", "label": label, "name": name, "version": version,
                "published": adv.get("date", ""),
                "text": (f"[OUR DEPENDENCY] {label}: {name} {version}  CVSS {adv.get('cvss_v3') or '?'}"
                         f"  {adv_id}  fix: {', '.join(adv['patched_versions']) or 'none listed'}\n"
                         f"  {adv.get('title', '')}\n"
                         f"  {adv.get('url', '')}\n"
                         "  -> To consider: is this version still the one we ship, and is the code reachable?"),
            })
    return items


def dependency_advisories(label, url):
    gems = locked_gems(http_text(url))
    if not gems:
        raise ValueError("no gems found in lockfile (moved or renamed?)")
    return gems


def osv_advisories(label, gems):
    batch = http_json("https://api.osv.dev/v1/querybatch", {"queries": [
        {"package": {"name": n, "ecosystem": "RubyGems"}, "version": v} for n, v in gems]})
    items = []
    for (name, version), result in zip(gems, batch.get("results", [])):
        for v in result.get("vulns") or []:
            items.append({"key": f"dep:{label}:{name}:{v['id']}", "osv_id": v["id"],
                          "label": label, "name": name, "version": version})
    return items


def describe_dependency(item):
    """Fetches details only for advisories that are actually new (one call each)."""
    if "text" in item:  # RubySec items are already complete
        return item
    try:
        v = http_json(f"https://api.osv.dev/v1/vulns/{item['osv_id']}")
    except (urllib.error.URLError, OSError, ValueError):
        v = {}
    fixed = sorted({e["fixed"] for a in v.get("affected", []) if a.get("package", {}).get("name") == item["name"]
                    for r in a.get("ranges", []) for e in r.get("events", []) if "fixed" in e})
    severity = (v.get("database_specific") or {}).get("severity") or "?"
    item["published"] = (v.get("published") or "")[:10]
    item["text"] = (f"[OUR DEPENDENCY] {item['label']}: {item['name']} {item['version']}  {severity.upper()}"
                    f"  {item['osv_id']}  fix: {', '.join(fixed) or 'none listed'}\n"
                    f"  {v.get('summary') or ''}\n"
                    f"  https://osv.dev/vulnerability/{item['osv_id']}\n"
                    "  -> To consider: is this version still the one we ship, and is the code reachable?")
    return item


def main():
    try:
        with open(STATE_PATH) as f:
            state = json.load(f)
    except FileNotFoundError:
        state = None
    seen = set(state["seen"]) if state else set()

    errors, found = [], []
    for repo in PEER_REPOS:
        try:
            found += peer_advisories(repo)
        except Exception as e:  # noqa: BLE001 -- report every failure, never stop the others
            errors.append(f"WATCHER ERROR: peer advisories for {repo}: {type(e).__name__}: {e}")
    for label, url, mode, prefix in PEER_PAGES:
        try:
            found += page_lines(label, url) if mode == "lines" else page_links(label, url, prefix, state is None)
        except Exception as e:  # noqa: BLE001
            errors.append(f"WATCHER ERROR: {label} ({url}): {type(e).__name__}: {e}")
    try:
        found += debian_dsas()
    except Exception as e:  # noqa: BLE001
        errors.append(f"WATCHER ERROR: Debian security announcements: {type(e).__name__}: {e}")
    lockfiles = {}
    for label, url in LOCKFILES.items():
        try:
            lockfiles[label] = dependency_advisories(label, url)
        except Exception as e:  # noqa: BLE001
            errors.append(f"WATCHER ERROR: lockfile of {label}: {type(e).__name__}: {e}")
    try:
        rubysec = load_rubysec({n for gems in lockfiles.values() for n, _ in gems})
        for label, gems in lockfiles.items():
            found += rubysec_advisories(label, gems, rubysec)
    except Exception as e:  # noqa: BLE001
        errors.append(f"WATCHER ERROR: RubySec advisory database: {type(e).__name__}: {e}")
    for label, gems in lockfiles.items():
        try:
            found += osv_advisories(label, gems)
        except Exception as e:  # noqa: BLE001
            errors.append(f"WATCHER ERROR: OSV for {label}: {type(e).__name__}: {e}")

    # The same advisory can come from both RubySec and OSV under the same id; keep the first.
    found = list({i["key"]: i for i in reversed(found)}.values())[::-1]
    new = [i for i in found if i["key"] not in seen]
    new = [describe_dependency(i) if i["key"].startswith("dep:") else i for i in new]
    # News articles: on a first run just record them (no dates, and fetching every old article is
    # pointless); afterwards fetch each NEW one and keep it only if it mentions security.
    if state is None:
        new = [i for i in new if not i["key"].startswith("news:")]
    else:
        new = [describe_news(i) if i["key"].startswith("news:") else i for i in new]
        new = [i for i in new if i.get("relevant", True)]

    out = list(errors)
    if state is None:
        cutoff = (datetime.date.today() - datetime.timedelta(days=FIRST_RUN_DAYS)).isoformat()
        recent = [i for i in new if i.get("published", "") >= cutoff]
        out.append(f"FIRST RUN: recorded {len(new)} advisories that were already published, so they will not be "
                   f"reported again. Showing the {len(recent)} published in the last {FIRST_RUN_DAYS} days:")
        new = recent
    if new:
        if state is not None:
            out.append(f"NEW SECURITY ADVISORIES ({len(new)}) -- for you to consider; nothing has been changed.")
        out += [""] + [i["text"] + "\n" for i in sorted(new, key=lambda i: i.get("published", ""), reverse=True)]
    elif state is not None and not errors:
        out.append("NO NEW ADVISORIES")

    seen |= {i["key"] for i in found}
    with open(STATE_PATH + ".tmp", "w") as f:
        json.dump({"seen": sorted(seen), "updated": datetime.datetime.now().isoformat(timespec="seconds")}, f, indent=1)
    os.replace(STATE_PATH + ".tmp", STATE_PATH)

    print("\n".join(out).rstrip())
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
