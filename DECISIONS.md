# Decisions

The why, and the alternatives turned down, behind choices that are not
obvious from the code. Add an entry when a question closes.

---

## The detectors are pure functions, and WordPress is a shell around them

**Decision.** The detector, check, baseline, scanner, network, session and
page-check classes call no WordPress function. They take bytes, paths and a
`$wpdb`-shaped object and return findings. Storage, alerts, cron and the
admin page are a separate layer that calls them.

**Why.** The only way to test a malware detector honestly is against a
real infected backup, which is a directory on a laptop with no WordPress.
The same split is what lets a hundred tests run with no WordPress installed.

**Rejected.** *Detectors as methods on a WordPress class.* Testable only
inside a WordPress bootstrap, and the only bootstrap available is production.

---

## Signatures on structure where names rotate, on literals where the literal is the point

**Decision.** F10 matches the loader by shape (an IIFE opening with a numeric
variable, a numeric array of eight or more entries, an XOR) and by the
run-once flag's shape. F2 matches the dropper by its literal decoder alphabet.

**Why.** This campaign's loader builds use different variable names and
different run-once flags; a signature on either catches one build. Every
dropper shares the alphabet byte-for-byte because it is the decoder's input.

**Rejected.** *IOC-only matching.* The IOC list is kept and is CRITICAL when
it hits, but it is the layer a campaign changes first.

---

## Report only

**Decision.** Sentinel never deletes, renames, disables or blocks, with one
opt-in exception: refusing unauthenticated REST user enumeration.

**Why.** A scanner that acts on its own findings turns a false positive into
an outage, and the first scan of any real site is mostly false positives.
Evidence is preserved as an inert copy; removal follows the runbook.

---

## The baseline is signed with a key the database does not hold

**Decision.** The baseline manifest is HMAC-signed with a constant from
`wp-config.php` or the config file beside the loader. Signing requires typing
the hostname and refuses while any CRITICAL finding is open.

**Why.** This campaign holds valid administrator credentials, which means it
holds the database. A baseline it could re-sign says whatever it wants.
Re-signing is the one action that can make a live dropper permanent, and a
`confirm()` is muscle memory.

---

## The heartbeat fires only after a run completes

**Decision.** One ping, at the end of `finish()`, nowhere else.

**Why.** The heartbeat exists so an outside monitor notices silence. A ping
at the start of a run, or on every cron tick, keeps the monitor happy while
the walk dies halfway every time.

---

## Serialized values from the database are never unserialize()d

**Decision.** Session tokens, option lists and signups are read with
length-aware string parsing.

**Why.** The database is attacker-written. `unserialize()` on attacker bytes
is object injection. The first draft matched strings up to the next quote; a
user-agent with a quote in it hid the rest of the session, and the expiration
was read from the wrong session so nothing ever expired. Both caught by
tests before the code ran anywhere.

---

## An empty network allow-list means "not configured", never "nobody"

**Decision.** With no allow-list, an unknown address is OK after the
attacker, tooling and Tor checks. The shipped list is empty.

**Why.** A list containing only an office range makes every home login HIGH
on the first morning and is turned off by lunch. An empty constant is
likewise "not set", not "set to nothing".

---

## The rendered-page check fetches same-origin scripts only

**Decision.** Cross-origin scripts are named in the inventory and never
fetched.

**Why.** Sentinel does not contact hosts it does not own. A page loading a
loader from a stranger host is reported by the src alone; fetching it would
make Sentinel a client of the attacker's CDN.

---

## What first deployments changed

**Decision.** Sentinel's own source is hashed but never content-scanned.
F14 counts categories of lure text, not terms. F15 and F16 excuse known
plugins by path. The weak F16 clause and stranger script hosts (D2) are
MEDIUM. A saved server error page under an image name is MEDIUM. A 401/403
on a login page, and a 410 anywhere, are INFO. A re-seen finding takes the
detector's current severity. The D8 subject is the /24.

**Why.** A first scan of a real install produced dozens of HIGHs about
embed hosts, copy-to-clipboard buttons, push-notification workers,
e-learning packages and large plugins, and eight about Sentinel's own
signature file. A tool that pages people about a calendar widget fifty times
is a tool whose fifty-first page is filtered. Every relaxation is pinned by
a clean fixture built from the real false positive, and each guarding clause
was mutation-tested.

**Rejected.** *Allow-listing each false positive by path.* That fixes the
files seen and not the shape; the next plugin's copy button fires again.
Path allow-lists are kept only where the shape is genuinely fine.

---

## Self-integrity rides the baseline

**Decision.** Signing records sha256 of Sentinel's own files and the script
inventory of every rendered page. Every minute tick compares the plugin's
files; a difference is L8 CRITICAL.

**Why.** One signing flow, one key, one place a human says "this is clean".
A legitimate re-upload of the plugin fires L8 until re-signed, which is
correct: it is a change to the tripwire, and the person who made it re-signs.

---

## Uploaded signature files replace the shipped ones whole

**Decision.** A JSON file pasted into the settings page is validated, stored,
and replaces the shipped file entirely.

**Why.** A merge lets a stale shipped entry survive an update that meant to
remove it, and the version on the page then describes neither file.
