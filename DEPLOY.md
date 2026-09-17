# Deploying Sky Sentinel

One install per WordPress install, each with its own name, signing key and
heartbeat, all reporting to one channel. FTP is enough.

## Once

- `sky-sentinel/bin/package.sh` builds `dist/sky-sentinel-<version>.zip`.
- Make a Teams Workflow webhook ("Post to a channel when a webhook request is
  received", URL on `logic.azure.com`) or a Slack incoming webhook. The URL is
  the secret.
- Healthchecks.io or similar: one check per site, period 6 hours, grace 6
  hours, alerting the people who will act.

## Per site

1. **Is it clean?** The baseline records what clean looks like. Signing over
   a live dropper makes it permanent. Scan and read before you sign.
2. `php sky-sentinel/bin/make-config.php --label="example.org" --webhook="..." --heartbeat="..." --to="..."`
   writes `dist/example.org/sky-sentinel-config.php`. It never prints the key
   and refuses to overwrite.
3. Upload by FTP into `wp-content/mu-plugins/`: the unzipped bundle
   (`sky-sentinel-loader.php`, `sky-sentinel-config.sample.php`,
   `sky-sentinel/`) plus the site's `sky-sentinel-config.php` beside the
   loader.
4. Load wp-admin. Sentinel in the menu means it booted. Network Admin on a
   network; the ordinary admin menu on a single site. Rollback at any time:
   delete `sky-sentinel-loader.php`.
5. Sentinel > Alerts and settings > **Send test alert**. Confirm all three
   channels. Set the network list. Tick "Refuse unauthenticated user
   enumeration".
6. Dashboard > **Scan now**. Read every finding. Real ones follow the
   runbook. Known-benign ones are **acknowledged**, not resolved: resolved
   means gone, and a persistent row marked resolved comes straight back.
7. Baseline > **Sign** once Open holds nothing CRITICAL and you believe the
   install is clean.

## Updating a live site

Upload the new `sky-sentinel/` directory over the old one. L8 goes CRITICAL
within a minute: Sentinel's own files changed. Re-sign the baseline.

## New indicators without an FTP deploy

Alerts and settings > Signatures in force. Paste the updated JSON into the
matching box. It is validated, replaces the shipped file whole, and takes
effect on the next scan. Bump the file's `version`.

## Single-site installs

Nothing to do. Sentinel notices `is_multisite()` and skips the network-only
checks and menus.
