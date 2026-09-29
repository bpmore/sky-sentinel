# Sky Sentinel

A small WordPress must-use plugin that watches a site for the **EtherHiding /
ClickFix** campaign family: droppers that hide as `<word>-<unixtime>.php`,
loaders appended to theme JavaScript that resolve their payload from a
blockchain contract, plugins that hide themselves from the plugin list,
plugins that re-install themselves from a zip disguised as an image, service
workers that keep the lure alive in visitors' browsers, and the valid
administrator credentials the whole thing runs on.

It **reports**. It does not delete, fix, or execute anything. Removal stays
with a human and the runbook.

It is built for the situation most WordPress admins are actually in: a
managed host, FTP access, no shell, `wp-config.php` locked. Everything here
installs by FTP and is driven from wp-admin.

## What it does

**Every six hours**, a chunked file walk that fits inside a one-minute cron:

- Twenty-four content detectors (F1 to F24): the known-bad hash list, the
  dropper family by decoder alphabet and structure, the admin-hider by its
  option names and hooks, the loader by its decode-and-run shape and its
  decoder structure (variable names rotate; the numeric array and XOR do
  not), on-chain resolver calls, inline PHP echoing a loader from `wp_footer`,
  ClickFix lure text, service worker registration, self-healing plugins,
  obfuscation in theme entry files; and, for the self-healing mu-plugin
  family Wordfence documented in September 2026, a file that rewrites,
  backdates and locks itself, a substitution-cipher string decoder,
  hex-escaped SQL, a spreader walking server roots, payment-credential
  harvesting, and raw-SQL self-reactivation; and PHP that includes an image
  file. Files over 1 MB are read whole, in overlapping 1 MB pieces, because
  the loader is appended to big library files.
- Ten file-system checks (S1 to S10): plant naming, decoy packages, PHP under
  `uploads/` and `cache/`, media files whose bytes are a zip or PHP, dropper
  dotfiles, a plugin directory named like a PHP file, read-only and backdated
  PHP, a directory named like a campaign plugin, and every file and package
  that differs from a **signed baseline**.
- Eleven database checks (D1 to D11): options and content carrying a loader or
  storing a PHP file, the mu-plugin family's option names, pending
  administrator signups, the administrator set against the baseline, hidden
  users (by `count_users()` and by a real `WP_User_Query`) and hidden plugins
  (raw SQL against what the WordPress API admits to; the mismatch is the
  finding), activation changes, every administrator's live sessions
  classified by origin, administrators named like the family's rogue
  account, and a campaign plugin active anywhere, with no baseline needed.

**Every hour**, the rendered-page check: each live site's home and login page
fetched as a visitor, fresh and through the cache, plus every same-origin
script they load, against the loader detectors and against the baseline.
This is the one check that does not care *where* an injection lives: file,
database, widget, object cache, page cache, CDN. Archived, deactivated and
spam network sites are skipped here (only here), and the Dashboard names them.

**As they happen**, the live hooks (L1 to L13): an administrator logging in
from a known attacker address or its /24, a Tor exit, the campaign's tooling browser, or
a network never seen before; anyone made an administrator by any route, or an
administrator's password set outside the lost-password flow; a plugin or
theme uploaded, activated or switched; the built-in file editor; a
file-manager connector; unauthenticated user enumeration over REST; a
failed-login burst; Sentinel's own files changing; every minute, a new or
changed mu-plugin or drop-in; a **hook census** of everything listening on
the user-hiding and password hooks, resolved by Reflection to the file that
registered it, however obfuscated its source; an outbound on-chain `eth_call`
from WordPress itself; new cron schedules; and a daily count of every failed
login, so a quiet night can be told from a deaf Sentinel.

**Alerts** go by email and by a Teams or Slack webhook that never touches the
WordPress mail stack, plus a dead-man heartbeat pinged only when a run
completes, so an outside monitor notices silence. One alert per artifact, a
daily digest for the rest, and a network-admin notice while anything CRITICAL
is open.

## Status

The detectors are proven against **reconstructed fixtures** (see
`sky-sentinel/tests/fixtures/README.md`) and have run on live multisite
installs, where their first scans were mostly false positives that are now
pinned as tests. In 0.4 they were also scored file by file against a real
infected backup (kept private): every confirmed artifact but one plain-text
readme was flagged, with no HIGH or CRITICAL false positive, and the cleaned
copy came back clean. That run found three bugs no reconstructed fixture
could, now fixed and pinned. In 0.4.8 a second real backup (a multisite,
also private) was scored against a file-by-file integrity check: 0.4.6 had
missed one of its ten infected files, a loader appended to a 3.7 MB
script; 0.4.8 finds all ten, with no HIGH or CRITICAL false positive. `bin/scan.php` is how you do the same on your own
copy. The detectors for the Wordfence-documented mu-plugin family are built
from that write-up; no sample of it was available to test against.

Single-site installs are supported in code and tested at the query level.
Report what you find.

## Install

Twenty minutes. `DEPLOY.md` has the long form.

1. `sky-sentinel/bin/package.sh` builds `dist/sky-sentinel-<version>.zip`.
2. `php sky-sentinel/bin/make-config.php --label="example.org" --to="you@example.org"`
   writes `dist/example.org/sky-sentinel-config.php` with a fresh signing key
   it never prints. Add `--webhook=` and `--heartbeat=` when you have them.
3. Upload the contents of the zip's `mu-plugins/` folder into
   `wp-content/mu-plugins/` (the loader and `sky-sentinel/`), and the config
   file beside the loader. Not the sample config at the top of the zip:
   WordPress runs every `.php` in `mu-plugins/` on every request.
4. Load wp-admin. **Sentinel** in the menu means it booted. A white screen
   means delete `sky-sentinel-loader.php` over FTP.
5. Alerts and settings: send a test alert, set the networks your
   administrators log in from, turn on "refuse user enumeration".
6. Dashboard: scan now. Read every finding. Known-benign ones are
   **acknowledged**, not resolved.
7. Baseline: sign it, once you believe the install is clean. Signing over a
   live dropper makes it permanent.

Upgrading a live install is not the same as installing: the upload raises L8
and L9 CRITICAL on purpose. `DEPLOY.md` has the steps.

## Tests

    cd sky-sentinel && composer install && ./vendor/bin/pest

200 tests, no WordPress needed: every decision is in a class with no
WordPress in it. Each guarding clause was mutation-tested (put the bug back,
watch the test fail).

## Design

`DECISIONS.md` records why things are the way they are and what was turned
down, so a settled question is not quietly reopened.

## License

GPL-2.0-or-later.
