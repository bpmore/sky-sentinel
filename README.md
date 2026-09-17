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

- Seventeen content detectors (F1 to F17): the known-bad hash list, the
  dropper family by decoder alphabet and structure, the admin-hider by its
  option names and hooks, the loader by its decode-and-run shape and its
  decoder structure (variable names rotate; the numeric array and XOR do
  not), on-chain resolver calls, inline PHP echoing a loader from `wp_footer`,
  ClickFix lure text, service worker registration, self-healing plugins,
  obfuscation in theme entry files.
- Seven file-system checks (S1 to S7): plant naming, decoy packages, PHP under
  `uploads/` and `cache/`, media files whose bytes are a zip or PHP, dropper
  dotfiles, and every file and package that differs from a **signed baseline**.
- Nine database checks (D1 to D9): options and content carrying a loader,
  pending administrator signups, the administrator set against the baseline,
  hidden users and hidden plugins (raw SQL against what the WordPress API
  admits to; the mismatch is the finding), activation changes, and every
  administrator's live sessions classified by origin.

**Every hour**, the rendered-page check: each site's home and login page
fetched as a visitor, fresh and through the cache, plus every same-origin
script they load, against the loader detectors and against the baseline.
This is the one check that does not care *where* an injection lives: file,
database, widget, object cache, page cache, CDN.

**As they happen**, the live hooks (L1 to L8): an administrator logging in
from a known attacker address, a Tor exit, the campaign's tooling browser, or
a network never seen before; anyone made an administrator by any route; a
plugin or theme uploaded, activated or switched; the built-in file editor; a
file-manager connector; unauthenticated user enumeration; a failed-login
burst; and Sentinel's own files changing.

**Alerts** go by email and by a Teams or Slack webhook that never touches the
WordPress mail stack, plus a dead-man heartbeat pinged only when a run
completes, so an outside monitor notices silence. One alert per artifact, a
daily digest for the rest, and a network-admin notice while anything CRITICAL
is open.

## Status

The detectors are proven against **reconstructed fixtures** (see
`sky-sentinel/tests/fixtures/README.md`) and have run on live multisite
installs, where their first scans were mostly false positives that are now
pinned as tests. They have not been proven against a real infected backup in
this repository. `bin/scan.php` is how you do that on your own copy.

Single-site installs are supported in code and tested at the query level.
Report what you find.

## Install

Twenty minutes. `DEPLOY.md` has the long form.

1. `sky-sentinel/bin/package.sh` builds `dist/sky-sentinel-<version>.zip`.
2. `php sky-sentinel/bin/make-config.php --label="example.org" --to="you@example.org"`
   writes `dist/example.org/sky-sentinel-config.php` with a fresh signing key
   it never prints. Add `--webhook=` and `--heartbeat=` when you have them.
3. Unzip the bundle into `wp-content/mu-plugins/`, add the config file beside
   the loader.
4. Load wp-admin. **Sentinel** in the menu means it booted. A white screen
   means delete `sky-sentinel-loader.php` over FTP.
5. Alerts and settings: send a test alert, set the networks your
   administrators log in from, turn on "refuse user enumeration".
6. Dashboard: scan now. Read every finding. Known-benign ones are
   **acknowledged**, not resolved.
7. Baseline: sign it, once you believe the install is clean. Signing over a
   live dropper makes it permanent.

## Tests

    cd sky-sentinel && composer install && ./vendor/bin/pest

No WordPress needed: every decision is in a class with no WordPress in it.
Each guarding clause was mutation-tested (put the bug back, watch the test
fail).

## Design

`DECISIONS.md` records why things are the way they are and what was turned
down, so a settled question is not quietly reopened.

## License

GPL-2.0-or-later.
