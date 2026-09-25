<?php
/**
 * L1 to L7: the WordPress events, wired to Sky_Sentinel_Live_Rules.
 *
 * This file only knows how to catch an event, look up who and where, and
 * hand the facts to the rules. Every decision lives in class-live-rules and
 * is tested there. Findings go straight into the store and alert the same
 * way a scan's do, so a plugin upload at 03:00 is an email at 03:00, not a
 * line in a six-hourly report.
 *
 * Nothing here blocks anything. The one exception is user enumeration over
 * REST, and only when the setting says so.
 */
final class Sky_Sentinel_Live_Hooks {

	private Sky_Sentinel_Live_Rules $rules;
	private Sky_Sentinel_Findings $findings;
	private Sky_Sentinel_Alerts $alerts;
	/** @var string[] */
	private array $rpc_hosts;
	/** Set by password_reset, which core fires just before wp_set_password() in the lost-password flow. */
	private bool $in_reset = false;
	/** True while raise() runs, so our own alert's HTTP request is never inspected by L11. */
	private bool $raising = false;

	public function __construct( Sky_Sentinel_Live_Rules $rules, Sky_Sentinel_Findings $findings, Sky_Sentinel_Alerts $alerts, array $rpc_hosts = array() ) {
		$this->rules     = $rules;
		$this->findings  = $findings;
		$this->alerts    = $alerts;
		$this->rpc_hosts = $rpc_hosts;

		// L1 / L7
		add_action( 'login_init', array( $this, 'login_page_seen' ) );
		add_action( 'wp_login', array( $this, 'logged_in' ), 10, 2 );
		add_action( 'wp_login_failed', array( $this, 'login_failed' ) );
		// L2
		add_action( 'set_user_role', array( $this, 'role_set' ), 10, 3 );
		add_action( 'add_user_role', array( $this, 'role_added' ), 10, 2 );
		add_action( 'grant_super_admin', array( $this, 'super_granted' ) );
		add_action( 'user_register', array( $this, 'user_registered' ) );
		add_action( 'after_signup_user', array( $this, 'signup_created' ), 10, 4 );
		add_action( 'add_user_to_blog', array( $this, 'added_to_blog' ), 10, 3 );
		add_action( 'password_reset', array( $this, 'reset_flow' ) );
		add_action( 'wp_set_password', array( $this, 'password_changed' ), 10, 2 );
		// L3
		add_action( 'upgrader_process_complete', array( $this, 'package_landed' ), 10, 2 );
		add_action( 'activated_plugin', array( $this, 'plugin_activated' ), 10, 2 );
		add_action( 'deactivated_plugin', array( $this, 'plugin_deactivated' ), 10, 2 );
		add_action( 'switch_theme', array( $this, 'theme_switched' ), 10, 3 );
		// L4
		add_action( 'wp_ajax_edit-theme-plugin-file', array( $this, 'editor_used' ), -1 );
		add_action( 'admin_init', array( $this, 'editor_still_possible' ) );
		// L5
		add_action( 'init', array( $this, 'file_manager_request' ), 1 );
		// L6
		add_filter( 'rest_pre_dispatch', array( $this, 'rest_users' ), 10, 3 );
		// L11: first in line, so a filter that short-circuits the request
		// cannot hide it. Observes and passes $pre through untouched.
		add_filter( 'pre_http_request', array( $this, 'outbound' ), -999999, 3 );
	}

	// ---- helpers ----------------------------------------------------------

	private function actor(): string {
		$u = wp_get_current_user();
		if ( $u && $u->exists() ) {
			return $u->user_login;
		}
		return defined( 'DOING_CRON' ) && DOING_CRON ? 'wp-cron' : ( defined( 'WP_CLI' ) && WP_CLI ? 'wp-cli' : 'anonymous' );
	}

	private function ip(): string {
		return Sky_Sentinel_Network::client_ip( $_SERVER );
	}

	private function ua(): string {
		return (string) ( $_SERVER['HTTP_USER_AGENT'] ?? '' );
	}

	/** Record and, at HIGH or above, alert immediately. */
	private function raise( ?Sky_Sentinel_Finding $f ): void {
		if ( null === $f ) {
			return;
		}
		$this->raising = true;
		try {
			$new = $this->findings->record( array( $f ), untrailingslashit( ABSPATH ) );
			if ( $new ) {
				$this->alerts->send( $new );
			}
		} finally {
			$this->raising = false;
		}
	}

	private static function privileged( WP_User $user ): bool {
		return Sky_Sentinel_Live_Rules::is_privileged( (array) $user->roles, is_multisite() && is_super_admin( $user->ID ) );
	}

	// ---- L1 / L7: logins --------------------------------------------------

	/** The attacker's sequence opened with GET /wp-login.php?wp_lang=en_US. Remember the IP for five minutes. */
	public function login_page_seen(): void {
		if ( isset( $_GET['wp_lang'] ) && 'en_US' === $_GET['wp_lang'] && 'GET' === ( $_SERVER['REQUEST_METHOD'] ?? '' ) ) {
			set_site_transient( 'sky_sentinel_wplang_' . md5( $this->ip() ), 1, 300 );
		}
	}

	public function logged_in( string $login, WP_User $user ): void {
		$ip = $this->ip();
		$ua = $this->ua();
		$privileged = self::privileged( $user );
		// Every login is an event, privileged or not: the event log is the
		// record of "which networks has this person used", which L1 asks.
		$this->findings->event( 'login', get_current_blog_id(), (int) $user->ID, $ip, array( 'login' => $login, 'ua' => $ua, 'privileged' => $privileged, 'prefix' => Sky_Sentinel_Network::prefix_of( $ip ) ) );
		if ( ! $privileged ) {
			return;
		}
		$tooling = (bool) get_site_transient( 'sky_sentinel_wplang_' . md5( $ip ) );
		$this->raise( $this->rules->login( $login, true, $ip, $ua, $this->prior_prefixes( (int) $user->ID ), $tooling, get_current_blog_id() ) );
	}

	/** The /24s this user has logged in from before, from Sentinel's own log. */
	private function prior_prefixes( int $user_id ): array {
		global $wpdb;
		$rows = (array) $wpdb->get_col( $wpdb->prepare( "SELECT detail FROM {$wpdb->base_prefix}sentinel_events WHERE kind = 'login' AND user_id = %d ORDER BY at DESC LIMIT 200", $user_id ) );
		$out  = array();
		foreach ( $rows as $json ) {
			$d = json_decode( (string) $json, true );
			if ( ! empty( $d['prefix'] ) ) {
				$out[] = (string) $d['prefix'];
			}
		}
		return array_values( array_unique( $out ) );
	}

	public function login_failed( string $login ): void {
		$ip  = $this->ip();
		$key = 'sky_sentinel_fails_' . md5( $ip );
		$ts  = (array) get_site_transient( $key );
		$ts[] = time();
		$ts   = array_values( array_filter( $ts, fn( $t ) => $t > time() - Sky_Sentinel_Live_Rules::BURST_WINDOW ) );
		set_site_transient( $key, $ts, Sky_Sentinel_Live_Rules::BURST_WINDOW );
		// L13: every failure counts toward the day, burst or not, so a quiet
		// night can be told apart from a deaf Sentinel. Concurrent failures
		// can lose an increment; the count is for trends, not evidence.
		update_site_option( Sky_Sentinel_Login_Tally::OPTION, Sky_Sentinel_Login_Tally::record( (array) get_site_option( Sky_Sentinel_Login_Tally::OPTION, array() ), $ip, time() ) );
		if ( Sky_Sentinel_Live_Rules::is_burst( $ts, time() ) ) {
			$this->raise( $this->rules->burst( $ip, count( $ts ), gmdate( 'Y-m-d' ) ) );
		}
	}

	// ---- L2: becoming an administrator -----------------------------------

	public function role_set( int $user_id, string $role, array $old_roles ): void {
		if ( 'administrator' === $role && ! in_array( 'administrator', $old_roles, true ) ) {
			$u = get_userdata( $user_id );
			$this->raise( $this->rules->promoted( $u ? $u->user_login : "#{$user_id}", 'set_user_role', $this->actor(), get_current_blog_id() ) );
		}
	}

	public function role_added( int $user_id, string $role ): void {
		if ( 'administrator' === $role ) {
			$u = get_userdata( $user_id );
			$this->raise( $this->rules->promoted( $u ? $u->user_login : "#{$user_id}", 'add_user_role', $this->actor(), get_current_blog_id() ) );
		}
	}

	public function super_granted( int $user_id ): void {
		$u = get_userdata( $user_id );
		$this->raise( $this->rules->promoted( $u ? $u->user_login : "#{$user_id}", 'grant_super_admin', $this->actor() ) );
	}

	public function user_registered( int $user_id ): void {
		$u = get_userdata( $user_id );
		if ( $u && in_array( 'administrator', (array) $u->roles, true ) ) {
			$this->raise( $this->rules->promoted( $u->user_login, 'user_register', $this->actor(), get_current_blog_id() ) );
		} else {
			$this->findings->event( 'user.registered', get_current_blog_id(), $user_id, $this->ip(), array( 'by' => $this->actor(), 'login' => $u ? $u->user_login : '' ) );
		}
	}

	public function signup_created( string $user, string $email, string $key, array $meta ): void {
		if ( 'administrator' === ( $meta['new_role'] ?? '' ) ) {
			$this->raise( $this->rules->admin_signup( $user, $email, $this->actor() ) );
		} else {
			$this->findings->event( 'signup.created', 0, null, $this->ip(), array( 'by' => $this->actor(), 'login' => $user, 'role' => $meta['new_role'] ?? '' ) );
		}
	}

	public function added_to_blog( int $user_id, string $role, int $blog_id ): void {
		if ( 'administrator' === $role ) {
			$u = get_userdata( $user_id );
			$this->raise( $this->rules->promoted( $u ? $u->user_login : "#{$user_id}", 'add_user_to_blog', $this->actor(), $blog_id ) );
		}
	}

	public function reset_flow(): void {
		$this->in_reset = true;
	}

	/** wp_set_password fires with ( $password, $user_id, $old_user_data ) since WordPress 6.2. The password is never read. */
	public function password_changed( $password, $user_id ): void {
		$u = get_userdata( (int) $user_id );
		if ( ! $u ) {
			return;
		}
		$this->raise( $this->rules->password_set( $u->user_login, self::privileged( $u ), $this->actor(), $this->in_reset, gmdate( 'Y-m-d\TH:i' ), get_current_blog_id() ) );
	}

	// ---- L3: packages -----------------------------------------------------

	public function package_landed( $upgrader, array $extra ): void {
		$type   = (string) ( $extra['type'] ?? 'package' );
		$action = (string) ( $extra['action'] ?? 'update' );
		$slugs  = array();
		if ( ! empty( $extra['plugins'] ) ) {
			$slugs = (array) $extra['plugins'];
		} elseif ( ! empty( $extra['themes'] ) ) {
			$slugs = (array) $extra['themes'];
		} elseif ( ! empty( $extra['plugin'] ) ) {
			$slugs = array( (string) $extra['plugin'] );
		} elseif ( ! empty( $extra['theme'] ) ) {
			$slugs = array( (string) $extra['theme'] );
		} elseif ( is_object( $upgrader ) && ! empty( $upgrader->result['destination_name'] ) ) {
			$slugs = array( (string) $upgrader->result['destination_name'] );
		}
		// An upload arrives through the "upload-plugin" / "upload-theme" admin
		// action; an install from wordpress.org carries a slug in the request.
		$from_upload = isset( $_REQUEST['action'] ) && in_array( $_REQUEST['action'], array( 'upload-plugin', 'upload-theme' ), true );
		foreach ( $slugs ?: array( 'unknown' ) as $slug ) {
			$this->raise( $this->rules->package( $action, $type, (string) $slug, $this->actor(), $from_upload ) );
		}
	}

	public function plugin_activated( string $plugin, bool $network_wide ): void {
		$this->raise( $this->rules->package( 'activate', 'plugin', $plugin . ( $network_wide ? ' (network)' : '' ), $this->actor(), false ) );
	}

	public function plugin_deactivated( string $plugin, bool $network_wide ): void {
		$this->raise( $this->rules->package( 'deactivate', 'plugin', $plugin, $this->actor(), false ) );
	}

	public function theme_switched( string $new_name, $new_theme, $old_theme ): void {
		$slug = is_object( $new_theme ) && method_exists( $new_theme, 'get_stylesheet' ) ? $new_theme->get_stylesheet() : $new_name;
		$this->raise( $this->rules->package( 'switch_theme', 'theme', (string) $slug, $this->actor(), false ) );
	}

	// ---- L4: the editor ---------------------------------------------------

	public function editor_used(): void {
		$file = sanitize_text_field( wp_unslash( $_POST['file'] ?? '' ) );
		$this->raise( $this->rules->editor_used( $file ?: '(unknown)', $this->actor() ) );
	}

	/** Once: the editor is reachable at all. Hardening guides say to turn it off; the campaign used it. */
	public function editor_still_possible(): void {
		if ( ! defined( 'DISALLOW_FILE_EDIT' ) || ! DISALLOW_FILE_EDIT ) {
			if ( ! get_site_transient( 'sky_sentinel_editor_notice' ) ) {
				set_site_transient( 'sky_sentinel_editor_notice', 1, DAY_IN_SECONDS );
				$this->findings->record( array( new Sky_Sentinel_Finding( 'L4', 'medium', 'config:DISALLOW_FILE_EDIT', 'DISALLOW_FILE_EDIT is not set: the theme and plugin editors are reachable from wp-admin' ) ), untrailingslashit( ABSPATH ) );
			}
		}
	}

	// ---- L5: file managers ------------------------------------------------

	public function file_manager_request(): void {
		$action = (string) ( $_REQUEST['action'] ?? '' );
		if ( '' !== $action && Sky_Sentinel_Live_Rules::is_file_manager_action( $action ) ) {
			$this->raise( $this->rules->file_manager( $action, $this->actor(), $this->ip() ) );
		}
	}

	// ---- L6: REST user enumeration ---------------------------------------
	//
	// The DETECTION here is sound. The optional block below is not, on any site
	// running Advanced Custom Fields: ACF 6.4.x hooks
	// ACF_Rest_Api::initialize() to rest_pre_dispatch at priority 10 and never
	// returns the filtered value, so a WP_Error returned from this method at
	// the same priority is discarded before dispatch() reads it and the request
	// is served normally. Recording the finding is unaffected.
	//
	// Not worked around here on purpose. Refusing the route belongs to a
	// plugin that runs after ACF and gates the route's own permission
	// callback, and Sentinel's job is to report rather than to enforce. On an
	// ACF site, leave sky_sentinel_block_user_enum off.

	public function rest_users( $result, $server, $request ) {
		// Only a real REST request counts, and only a real REST request is
		// ever refused: an internal lookup made while rendering a page is the
		// page's business, and refusing it would break the page.
		if ( ! Sky_Sentinel_Live_Rules::is_enumeration( is_user_logged_in(), (string) $request->get_method(), (string) $request->get_route(), defined( 'REST_REQUEST' ) && REST_REQUEST ) ) {
			return $result;
		}
		$ip = $this->ip();
		$this->findings->record( array( $this->rules->user_enumeration( $ip, gmdate( 'Y-m-d' ) ) ), untrailingslashit( ABSPATH ) );
		if ( get_site_option( 'sky_sentinel_block_user_enum' ) ) {
			return new WP_Error( 'rest_forbidden', 'Not available.', array( 'status' => 401 ) );
		}
		return $result;
	}

	// ---- L11: outbound on-chain lookups -------------------------------------

	public function outbound( $pre, $args, $url ) {
		if ( $this->raising || ! is_string( $url ) ) {
			return $pre;
		}
		$body = $args['body'] ?? '';
		$body = is_string( $body ) ? $body : (string) wp_json_encode( $body );
		// Cheap first: nothing to parse unless it could be JSON-RPC or a known gateway.
		if ( ! str_contains( $body, 'eth_' ) && ! $this->rpc_hosts ) {
			return $pre;
		}
		$caller = Sky_Sentinel_Live_Rules::caller_from_trace( debug_backtrace( DEBUG_BACKTRACE_IGNORE_ARGS, 12 ), untrailingslashit( ABSPATH ) );
		if ( str_contains( $caller, '/sky-sentinel/' ) ) {
			return $pre; // our own webhook, heartbeat or page check
		}
		$this->raise( $this->rules->outbound_request( $url, substr( $body, 0, 65536 ), $this->rpc_hosts, $caller ) );
		return $pre;
	}
}
