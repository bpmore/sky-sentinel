# Changelog

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
