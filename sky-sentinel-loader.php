<?php
/**
 * Plugin Name: Sky Sentinel (loader)
 * Description: Loads wp-content/mu-plugins/sky-sentinel/. A must-use plugin so it cannot be switched off from wp-admin.
 * Version: 0.4.6
 *
 * Copy this file to wp-content/mu-plugins/sky-sentinel-loader.php and the
 * sky-sentinel/ directory beside it. WordPress only loads top-level files
 * from mu-plugins, which is why the loader exists.
 *
 * Configuration: the host does not let us edit wp-config.php, so the
 * constants are read from wp-content/mu-plugins/sky-sentinel-config.php
 * instead (copy sky-sentinel-config.sample.php). Anything already defined in
 * wp-config.php wins; the config file only fills what is not set. The
 * property that matters is the same either way: the values are not in the
 * database, so an attacker holding wp-admin cannot silence the alerts or
 * re-sign the baseline by editing a row.
 */
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
$sky_sentinel_config = __DIR__ . '/sky-sentinel-config.php';
if ( is_readable( $sky_sentinel_config ) ) {
	require_once $sky_sentinel_config;
}
$sky_sentinel_main = __DIR__ . '/sky-sentinel/sentinel.php';
if ( is_readable( $sky_sentinel_main ) ) {
	require_once $sky_sentinel_main;
} elseif ( is_admin() ) {
	add_action( 'network_admin_notices', static function () {
		echo '<div class="notice notice-error"><p><strong>Sky Sentinel is not loaded:</strong> mu-plugins/sky-sentinel/sentinel.php is missing. If you did not remove it, treat that as an incident.</p></div>';
	} );
}
