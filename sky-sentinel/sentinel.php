<?php
/**
 * Sky Sentinel
 *
 * A targeted tripwire for the ClickFix / EtherHiding campaign family that
 * targets WordPress. Scans on a schedule, watches what changes when an
 * attacker is inside, alerts named people through two independent channels,
 * and keeps a dead-man heartbeat so silence is itself an alert.
 *
 * It reports. It does not delete, fix, or execute anything. Removal stays
 * with a human and the runbook.
 *
 * Loaded by wp-content/mu-plugins/sky-sentinel-loader.php. Not a normal
 * plugin, so it cannot be deactivated from wp-admin, which is where the
 * attacker was standing.
 *
 * Constants read from wp-config.php:
 *   SKY_SENTINEL_KEY        (required to sign a baseline; 32+ chars)
 *   SKY_SENTINEL_WEBHOOK    Teams / Slack incoming webhook URL
 *   SKY_SENTINEL_HEARTBEAT  Healthchecks.io / UptimeRobot heartbeat URL
 *   SKY_SENTINEL_ALERT_TO   comma-separated emails (in addition to the settings page)
 *   SKY_SENTINEL_DATA_DIR   override for where manifests and evidence live
 *   SKY_SENTINEL_SITE_LABEL how this install names itself on the shared Teams channel
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Sky_Sentinel {

	public const VERSION   = '0.4.11';
	public const SCAN_HOOK   = 'sky_sentinel_scan';
	public const TICK_HOOK   = 'sky_sentinel_tick';
	public const PAGES_HOOK  = 'sky_sentinel_pages';
	public const DIGEST_HOOK = 'sky_sentinel_digest';
	public const TOR_HOOK    = 'sky_sentinel_tor';
	/**
	 * Who may see Sentinel. On a network, super admins; on a single site,
	 * administrators. Read through cap() so the two never drift.
	 */
	public static function cap(): string {
		return is_multisite() ? 'manage_network' : 'manage_options';
	}

	private static ?self $instance = null;
	private Sky_Sentinel_Signatures $sig;
	private Sky_Sentinel_Findings $findings;
	private Sky_Sentinel_Alerts $alerts;
	private Sky_Sentinel_Runner $runner;

	public static function boot(): self {
		return self::$instance ??= new self();
	}

	public static function dir(): string {
		return __DIR__;
	}

	/**
	 * Where manifests, evidence and the off-database baseline copy live.
	 * ../private beside the webroot when it exists and is writable (some
	 * managed hosts provide one), else a denied folder under uploads.
	 */
	public static function data_dir(): string {
		if ( defined( 'SKY_SENTINEL_DATA_DIR' ) && is_string( SKY_SENTINEL_DATA_DIR ) ) {
			return rtrim( SKY_SENTINEL_DATA_DIR, '/' );
		}
		$private = dirname( untrailingslashit( ABSPATH ) ) . '/private';
		if ( is_dir( $private ) && is_writable( $private ) ) {
			return $private . '/sky-sentinel';
		}
		return WP_CONTENT_DIR . '/uploads/sky-sentinel';
	}

	private function __construct() {
		global $wpdb;
		foreach ( array( 'finding', 'signatures', 'content-detectors', 'fs-checks', 'baseline', 'scanner', 'db-checks', 'hook-census', 'network', 'live-rules', 'login-tally', 'session-checks', 'page-check', 'findings', 'alerts', 'runner', 'live-hooks', 'digest' ) as $c ) {
			require_once __DIR__ . "/includes/class-{$c}.php";
		}
		$this->sig      = Sky_Sentinel_Signatures::from_directory( __DIR__ . '/signatures', self::signature_overrides() );
		$this->findings = new Sky_Sentinel_Findings( $wpdb, self::data_dir() . '/evidence' );
		$this->alerts   = new Sky_Sentinel_Alerts( $this->findings, self::site_label() );
		$this->runner   = new Sky_Sentinel_Runner( $this->sig, $this->findings, $this->alerts, untrailingslashit( ABSPATH ), self::data_dir() );

		add_action( 'init', array( $this, 'install_if_needed' ) );
		add_filter( 'cron_schedules', array( $this, 'schedules' ) );
		add_action( 'init', array( $this, 'schedule' ) );
		add_action( self::SCAN_HOOK, array( $this, 'cron_scan' ) );
		add_action( self::TICK_HOOK, array( $this, 'cron_tick' ) );
		add_action( self::PAGES_HOOK, array( $this->runner, 'queue_pages' ) );
		add_action( self::DIGEST_HOOK, array( new Sky_Sentinel_Digest( $this->findings, $this->alerts ), 'send' ) );
		add_action( self::TOR_HOOK, array( $this->runner, 'refresh_tor_list' ) );

		// L1 to L7, always on. The rules are pure and tested; this wires them.
		new Sky_Sentinel_Live_Hooks( new Sky_Sentinel_Live_Rules( $this->runner->network() ), $this->findings, $this->alerts, $this->sig->rpc_hosts() );

		if ( is_admin() ) {
			// L10 from the admin side too: a hider has every reason to
			// register only when is_admin(), where the screens it lies to
			// are. Last on admin_init, at most every five minutes.
			add_action( 'admin_init', array( $this, 'admin_census' ), PHP_INT_MAX );
			require_once __DIR__ . '/admin/class-network-page.php';
			new Sky_Sentinel_Network_Page( $this->findings, $this->alerts, $this->runner, $this->sig );
		}
	}

	/**
	 * Signature files uploaded from the settings page, stored in a site
	 * option and validated on the way in. A file deploy is not the only way
	 * to teach every site a new hash.
	 *
	 * @return array<string,array>
	 */
	public static function signature_overrides(): array {
		$raw = get_site_option( 'sky_sentinel_signature_overrides', array() );
		$out = array();
		foreach ( (array) $raw as $key => $json ) {
			$decoded = is_string( $json ) ? json_decode( $json, true ) : null;
			if ( is_array( $decoded ) && null === Sky_Sentinel_Signatures::validate_override( (string) $key, $decoded ) ) {
				$out[ (string) $key ] = $decoded;
			}
		}
		return $out;
	}

	public function findings(): Sky_Sentinel_Findings {
		return $this->findings;
	}

	public function runner(): Sky_Sentinel_Runner {
		return $this->runner;
	}

	/**
	 * How this install names itself on every card, email and heartbeat. One
	 * Teams channel serves the whole estate, so the name has to say which
	 * install is talking. SKY_SENTINEL_SITE_LABEL in the config file wins;
	 * otherwise the hostname.
	 */
	public static function site_label(): string {
		if ( defined( 'SKY_SENTINEL_SITE_LABEL' ) && is_string( SKY_SENTINEL_SITE_LABEL ) && '' !== trim( SKY_SENTINEL_SITE_LABEL ) ) {
			return trim( SKY_SENTINEL_SITE_LABEL );
		}
		$host = (string) parse_url( network_home_url(), PHP_URL_HOST );
		return '' !== $host ? $host : (string) get_site_option( 'site_name', 'wordpress' );
	}

	public function install_if_needed(): void {
		if ( get_site_option( 'sky_sentinel_version' ) === self::VERSION ) {
			return;
		}
		$this->findings->install();
		$dir = self::data_dir();
		if ( ! is_dir( $dir ) ) {
			wp_mkdir_p( $dir );
		}
		// If the data dir had to fall back under uploads, deny it at the
		// server too: this is where evidence copies of droppers will sit.
		if ( str_starts_with( $dir, WP_CONTENT_DIR ) ) {
			foreach ( array( '.htaccess' => "Require all denied\nDeny from all\n", 'index.html' => '' ) as $name => $body ) {
				if ( ! file_exists( "{$dir}/{$name}" ) ) {
					@file_put_contents( "{$dir}/{$name}", $body );
				}
			}
		}
		update_site_option( 'sky_sentinel_version', self::VERSION );
		$this->findings->event( 'sentinel.installed', 0, null, null, array( 'version' => self::VERSION, 'data_dir' => $dir ) );
	}

	public function schedules( array $s ): array {
		$s['sky_sentinel_minute']   = array( 'interval' => 60, 'display' => 'Every minute (Sentinel)' );
		$s['sky_sentinel_six_hours'] = array( 'interval' => 6 * HOUR_IN_SECONDS, 'display' => 'Every six hours (Sentinel)' );
		$s['sky_sentinel_weekly']    = array( 'interval' => WEEK_IN_SECONDS, 'display' => 'Weekly (Sentinel)' );
		return $s;
	}

	public function schedule(): void {
		if ( ! wp_next_scheduled( self::SCAN_HOOK ) ) {
			wp_schedule_event( time() + 300, 'sky_sentinel_six_hours', self::SCAN_HOOK );
		}
		if ( ! wp_next_scheduled( self::TICK_HOOK ) ) {
			wp_schedule_event( time() + 60, 'sky_sentinel_minute', self::TICK_HOOK );
		}
		if ( ! wp_next_scheduled( self::PAGES_HOOK ) ) {
			wp_schedule_event( time() + 120, 'hourly', self::PAGES_HOOK );
		}
		if ( ! wp_next_scheduled( self::DIGEST_HOOK ) ) {
			// 07:00 site time, daily.
			$next = strtotime( 'tomorrow 07:00', current_time( 'timestamp' ) ) - ( (int) get_option( 'gmt_offset' ) * HOUR_IN_SECONDS );
			wp_schedule_event( $next, 'daily', self::DIGEST_HOOK );
		}
		if ( ! wp_next_scheduled( self::TOR_HOOK ) ) {
			wp_schedule_event( time() + 180, 'sky_sentinel_weekly', self::TOR_HOOK );
		}
	}

	public function admin_census(): void {
		if ( get_site_transient( 'sky_sentinel_admin_census' ) ) {
			return;
		}
		set_site_transient( 'sky_sentinel_admin_census', 1, 5 * MINUTE_IN_SECONDS );
		$this->runner->hook_census();
	}

	public function cron_scan(): void {
		$this->runner->start( 'cron' );
		$this->runner->step( 40 );
	}

	/**
	 * Every minute: if a walk is in progress, do 45 seconds of it. The host
	 * runs wp_cron.sh from system cron with a sixty-second ceiling, and this
	 * leaves it room to breathe.
	 */
	public function cron_tick(): void {
		// Cheap and first: our own files, the load path, and who is on the
		// hiding and password hooks.
		$this->runner->self_check();
		$this->runner->load_path_check();
		$this->runner->hook_census();
		if ( $this->runner->in_progress() ) {
			$this->runner->step( 40 );
			return;
		}
		// No file walk running: drain the rendered-page queue instead.
		$this->runner->step_pages( 40 );
	}
}

Sky_Sentinel::boot();
