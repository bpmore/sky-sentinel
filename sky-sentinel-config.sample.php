<?php
/**
 * Sky Sentinel configuration.
 *
 * Copy to wp-content/mu-plugins/sky-sentinel-config.php and fill in. Upload
 * by FTP only; never paste these values into wp-admin. This file stands in
 * for wp-config.php on a host that does not let us edit wp-config.php.
 *
 * Do not commit the filled-in copy anywhere.
 */
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Signs the baseline. 32 or more random characters. Generate one with:
//   php -r 'echo bin2hex(random_bytes(32)), PHP_EOL;'
// Change it and every existing baseline stops verifying, which is correct.
defined( 'SKY_SENTINEL_KEY' ) || define( 'SKY_SENTINEL_KEY', '' );

// Microsoft Teams Workflow webhook (or Slack). The second alert channel; it
// never touches the WordPress mail stack. Teams: in the channel, Workflows,
// "Post to a channel when a webhook request is received"; the URL it gives
// you is on logic.azure.com and ends in a sig= parameter, which IS the secret.
// Keep it out of the database and out of chat.
defined( 'SKY_SENTINEL_WEBHOOK' ) || define( 'SKY_SENTINEL_WEBHOOK', '' );

// Healthchecks.io or UptimeRobot heartbeat URL. Pinged only when a run
// completes. Set the monitor to a 6-hour period with 6 hours of grace.
defined( 'SKY_SENTINEL_HEARTBEAT' ) || define( 'SKY_SENTINEL_HEARTBEAT', '' );

// Email recipients, comma-separated. Added to whatever the settings page holds.
defined( 'SKY_SENTINEL_ALERT_TO' ) || define( 'SKY_SENTINEL_ALERT_TO', '' );

// Not a Sentinel setting, but the host will not let us put it in
// wp-config.php and this file loads early enough to count. Hardening guides
// require it and the campaign used the editor; L4 reports MEDIUM until it is true. It removes the theme and
// plugin editors from wp-admin, which is where the attacker was standing.
defined( 'DISALLOW_FILE_EDIT' ) || define( 'DISALLOW_FILE_EDIT', true );

