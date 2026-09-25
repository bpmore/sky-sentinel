#!/usr/bin/env php
<?php
/**
 * Write a per-site config file with a fresh signing key, without ever
 * printing the key.
 *
 *   php sky-sentinel/bin/make-config.php --label="example.org" \
 *       --webhook="https://prod-..logic.azure.com/..." \
 *       --heartbeat="https://hc-ping.com/..." \
 *       --to="you@example.org, colleague@example.org" \
 *       --out=dist/example.org/sky-sentinel-config.php
 *
 * Only --label is required. Everything else can be added later. The key is
 * generated here and written to the file and nowhere else; the command
 * prints the path and the key's length, never the key.
 */
// Ships inside mu-plugins, so it is reachable by URL. It is a command-line tool only.
if ( 'cli' !== PHP_SAPI ) {
	http_response_code( 404 );
	exit;
}
$opts = getopt( '', array( 'label:', 'webhook::', 'heartbeat::', 'to::', 'out::', 'no-file-edit-lock' ) );
if ( empty( $opts['label'] ) ) {
	fwrite( STDERR, "Usage: make-config.php --label=<site> [--webhook=] [--heartbeat=] [--to=] [--out=]\n" );
	exit( 2 );
}
$label = trim( (string) $opts['label'] );
$out   = (string) ( $opts['out'] ?? ( dirname( __DIR__, 2 ) . '/dist/' . preg_replace( '/[^a-z0-9.-]+/i', '-', $label ) . '/sky-sentinel-config.php' ) );
$key   = bin2hex( random_bytes( 32 ) );
$q     = fn( string $v ) => "'" . str_replace( "'", "\\'", $v ) . "'";
$lines = array(
	'<?php',
	'/**',
	' * Sky Sentinel configuration for ' . $label . '.',
	' * Generated ' . gmdate( 'Y-m-d H:i' ) . ' UTC by bin/make-config.php. Upload by FTP to',
	' * wp-content/mu-plugins/sky-sentinel-config.php. Never commit, never paste into wp-admin or chat.',
	' */',
	"if ( ! defined( 'ABSPATH' ) ) {",
	"\texit;",
	'}',
	'',
	'// How this install names itself on the shared Teams channel and in every email.',
	"defined( 'SKY_SENTINEL_SITE_LABEL' ) || define( 'SKY_SENTINEL_SITE_LABEL', " . $q( $label ) . ' );',
	'',
	'// Signs the baseline. Change it and every existing baseline stops verifying, which is correct.',
	"defined( 'SKY_SENTINEL_KEY' ) || define( 'SKY_SENTINEL_KEY', " . $q( $key ) . ' );',
	'',
	'// Teams Workflow webhook (logic.azure.com) or Slack. Empty means email only.',
	"defined( 'SKY_SENTINEL_WEBHOOK' ) || define( 'SKY_SENTINEL_WEBHOOK', " . $q( trim( (string) ( $opts['webhook'] ?? '' ) ) ) . ' );',
	'',
	'// Healthchecks.io or UptimeRobot heartbeat: one check PER SITE, pinged only when a run completes.',
	"defined( 'SKY_SENTINEL_HEARTBEAT' ) || define( 'SKY_SENTINEL_HEARTBEAT', " . $q( trim( (string) ( $opts['heartbeat'] ?? '' ) ) ) . ' );',
	'',
	'// Email recipients, comma-separated.',
	"defined( 'SKY_SENTINEL_ALERT_TO' ) || define( 'SKY_SENTINEL_ALERT_TO', " . $q( trim( (string) ( $opts['to'] ?? '' ) ) ) . ' );',
);
if ( ! isset( $opts['no-file-edit-lock'] ) ) {
	$lines[] = '';
	$lines[] = '// Not a Sentinel setting: removes the theme and plugin editors from wp-admin. Hardening guides require it; the campaign used the editor.';
	$lines[] = "defined( 'DISALLOW_FILE_EDIT' ) || define( 'DISALLOW_FILE_EDIT', true );";
}
$lines[] = '';
if ( ! is_dir( dirname( $out ) ) && ! mkdir( dirname( $out ), 0700, true ) ) {
	fwrite( STDERR, "Cannot create " . dirname( $out ) . "\n" );
	exit( 1 );
}
if ( file_exists( $out ) ) {
	fwrite( STDERR, "Refusing to overwrite {$out}: that file may hold a key a live baseline was signed with.\n" );
	exit( 1 );
}
file_put_contents( $out, implode( "\n", $lines ) );
chmod( $out, 0600 );
$check = shell_exec( 'php -l ' . escapeshellarg( $out ) . ' 2>&1' );
echo "Wrote {$out}\n";
echo 'Key: ' . strlen( $key ) . " characters, not shown. " . ( str_contains( (string) $check, 'No syntax errors' ) ? 'Lint: ok.' : 'LINT FAILED: ' . trim( (string) $check ) ) . "\n";
