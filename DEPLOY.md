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
3. Upload by FTP into `wp-content/mu-plugins/`: the contents of the zip's
   `mu-plugins/` folder (`sky-sentinel-loader.php` and `sky-sentinel/`), plus
   the site's `sky-sentinel-config.php` beside the loader. Nothing else: the
   sample config sits at the top of the zip, outside `mu-plugins/`, because
   WordPress runs every `.php` there on every request, and a stray sample
   defines every setting empty if the real config is ever missing.
4. Load wp-admin. Sentinel in the menu means it booted. Network Admin on a
   network; the ordinary admin menu on a single site. Rollback at any time:
   delete `sky-sentinel-loader.php`.
5. Sentinel > Alerts and settings > **Send test alert**. Confirm all three
   channels. Set the network list. Tick "Refuse unauthenticated user
   enumeration" (it refuses nothing on a site running Advanced Custom
   Fields; see the note under the checkbox).
6. Dashboard > **Scan now**. Read every finding. Real ones follow the
   runbook. Known-benign ones are **acknowledged**, not resolved: resolved
   means gone, and a persistent row marked resolved comes straight back.
7. Baseline > **Sign** once Open holds nothing CRITICAL and you believe the
   install is clean.

## Updating a live site

An upgrade looks exactly like an attacker editing the tripwire, and Sentinel
says so. Warn whoever reads the alerts first.

1. Scan on the old version and deal with anything CRITICAL first, so it is
   not folded into the upgrade.
2. Upload the new `sky-sentinel-loader.php` and `sky-sentinel/` over the old
   ones. Leave `sky-sentinel-config.php` alone: a new key invalidates the
   baseline.
3. Within a minute: **L8** (CRITICAL) for each Sentinel file that changed,
   and **L9** (CRITICAL) on the loader. Check every one names a file in the
   bundle (`unzip -l`). One that does not is not the upgrade: stop.
4. **Acknowledge** them. Do not resolve them yet: L8 and L9 run every minute,
   and a resolved finding that is seen again reopens and blocks signing.
5. Scan now on the new version and read every new finding.
6. Re-sign the baseline.
7. Resolve the upgrade's L8 and L9 findings.

### 0.4.13 to 0.4.14

The steps above; nothing to resolve. The Logins box reads the event log, so
it is full from the first page load.

### 0.4.14 to 0.4.15

The steps above; nothing to resolve.

### 0.4.12 to 0.4.13

The steps above; nothing to resolve. The Dashboard's Block list starts with
the last 14 days' L7 bursts and today's and yesterday's failed logins, and
fills in over two weeks.

### 0.4.11 to 0.4.12

The steps above. Upload the zip's `mu-plugins/` contents only, never a
checkout of the repository: tests and a renamed old copy left in
`mu-plugins/` show up as S6 findings and are read by every detector.

### 0.4.10 to 0.4.11

The steps above. On 0.4.8 to 0.4.10, resolve any open F11, D1 or P1
finding whose only indicator is `hasDemoPage`: it is a cleanup script
naming the runtime, and it does not come back.

### 0.4.9 to 0.4.10

The steps above, then resolve open S4 CRITICALs on web pages saved under a
picture's name: the next scan reopens each as MEDIUM if it carries nothing,
or CRITICAL naming what it carries.

### 0.4.8 to 0.4.9

The steps above, then resolve open S3 HIGHs on `languages/` `.l10n.php`
files and on MailPoet's `uploads/mailpoet*/cache/`. Any that 0.4.9 still
raises are not translation data or not MailPoet's cache: read them.

### 0.4.6 to 0.4.8

The steps above. Expect L8 on the signature files as well as the code. The
first scan reads every file over 1 MB for the first time: read any new F9,
F10 or F11 on one before acknowledging it. Any S10 or D11 is a campaign
plugin by name: follow the runbook. Resolve open S3 HIGHs on allow-listed
datastores under `uploads/sites/<n>/` or `blogs.dir/<n>/files/`, on an empty
`functions.php`, and open F9 HIGHs on a bundled library: none of them come
back.

### 0.3.0 to 0.4.6

The steps above, plus: delete `sky-sentinel-config.sample.php` from
`mu-plugins/` if the 0.3.0 zip put it there (L9 reports the removal as HIGH;
expected, resolve it in step 7). The first scan on 0.4.6 looks at things no
earlier scan did: L10 can name a host's own mu-plugin or an LDAP / two-factor
plugin on the `authenticate` hook (read the file; excuse a legitimate one in
`hook_census_files`), and S9 flags read-only PHP where a host locks files on
purpose. Re-signing starts L12 (cron schedules). Open L6 findings from before
the upgrade were mostly internal page-render lookups 0.4.4 stopped counting:
resolve them.

## New indicators without an FTP deploy

Alerts and settings > Signatures in force. Paste the updated JSON into the
matching box. It is validated, replaces the shipped file whole, and takes
effect on the next scan. Bump the file's `version`.

## Single-site installs

Nothing to do. Sentinel notices `is_multisite()` and skips the network-only
checks and menus.
