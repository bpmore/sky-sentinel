<?php
/**
 * One scheduled run, start to finish, in pieces.
 *
 * A run is: walk the files in chunks (many cron ticks), then in ONE tick at
 * the end diff against the baseline, run the database checks, record every
 * finding, alert on the new ones, and ping the heartbeat. The walk state
 * lives in a site option between ticks; the manifest lives in a file in the
 * data directory.
 *
 * The heartbeat is sent from here and only here, after everything above has
 * completed. A run that dies halfway sends no heartbeat, and that is the
 * signal.
 */
final class Sky_Sentinel_Runner {

	public const STATE_OPTION    = 'sky_sentinel_scan_state';
	public const LAST_RUN_OPTION = 'sky_sentinel_last_run';
	public const BASELINE_OPTION = 'sky_sentinel_baseline';
	public const BASELINE_SIG    = 'sky_sentinel_baseline_sig';
	public const PAGES_QUEUE     = 'sky_sentinel_pages_queue';
	public const PAGES_INVENTORY = 'sky_sentinel_page_inventory';
	public const PAGES_LAST      = 'sky_sentinel_pages_last';

	private Sky_Sentinel_Signatures $sig;
	private Sky_Sentinel_Findings $findings;
	private Sky_Sentinel_Alerts $alerts;
	private string $root;
	private string $data_dir;

	public function __construct( Sky_Sentinel_Signatures $sig, Sky_Sentinel_Findings $findings, Sky_Sentinel_Alerts $alerts, string $root, string $data_dir ) {
		$this->sig      = $sig;
		$this->findings = $findings;
		$this->alerts   = $alerts;
		$this->root     = rtrim( $root, '/' );
		$this->data_dir = rtrim( $data_dir, '/' );
	}

	public function in_progress(): bool {
		$state = get_site_option( self::STATE_OPTION );
		return is_array( $state ) && empty( $state['done'] );
	}

	public function state(): ?array {
		$state = get_site_option( self::STATE_OPTION );
		return is_array( $state ) ? $state : null;
	}

	/** Begin a walk. Refuses to start over one already in progress. */
	public function start( string $trigger ): bool {
		if ( $this->in_progress() ) {
			return false;
		}
		$manifest = $this->data_dir . '/manifest-' . gmdate( 'Ymd-His' ) . '.jsonl';
		$state    = Sky_Sentinel_Scanner::start( $manifest );
		$state['trigger']  = $trigger;
		$state['findings'] = array();
		update_site_option( self::STATE_OPTION, $state );
		$this->findings->event( 'scan.started', 0, get_current_user_id() ?: null, null, array( 'trigger' => $trigger ) );
		return true;
	}

	/**
	 * Do up to $budget seconds of work. Returns progress for a caller that
	 * wants to draw a bar, and finishes the run when the walk is done.
	 */
	public function step( float $budget ): array {
		$state = $this->state();
		if ( null === $state || ! empty( $state['done'] ) ) {
			return array( 'done' => true, 'idle' => true );
		}
		$scanner = new Sky_Sentinel_Scanner( $this->root, $this->sig );
		$r       = $scanner->step( $state, $budget );
		$state   = $r['state'];
		foreach ( $r['findings'] as $f ) {
			$state['findings'][] = $f->to_array();
		}
		if ( ! empty( $state['done'] ) ) {
			$summary = $this->finish( $state );
			delete_site_option( self::STATE_OPTION );
			return array( 'done' => true ) + $summary;
		}
		update_site_option( self::STATE_OPTION, $state );
		return array( 'done' => false, 'files' => $state['files'], 'pending' => count( $state['pending'] ) );
	}

	private function finish( array $state ): array {
		$found = array();
		foreach ( $state['findings'] as $row ) {
			$found[] = new Sky_Sentinel_Finding( $row['detector'], $row['severity'], $row['subject'], $row['summary'], $row['detail'], $row['sha256'], $row['blog_id'] );
		}

		// S6 / S7 against the signed baseline, if one exists and still verifies.
		$baseline = $this->baseline();
		if ( null !== $baseline ) {
			$current = Sky_Sentinel_Scanner::read_manifest( $state['manifest_file'] );
			foreach ( Sky_Sentinel_FS_Checks::diff_against_baseline( $baseline['files'], $current, $baseline['packages'], $state['packages'] ) as $f ) {
				$found[] = $f;
			}
		} elseif ( get_site_option( self::BASELINE_OPTION ) ) {
			// There IS a stored baseline and it did not verify: somebody
			// changed it without the key. That is the finding.
			$found[] = new Sky_Sentinel_Finding( 'L8', 'critical', 'baseline', 'The stored baseline does not verify against SKY_SENTINEL_KEY: it was altered or the key changed' );
		}

		// D1 to D7.
		$checks = $this->db_checks();
		foreach ( $checks->run( $baseline['inventory'] ?? null ) as $f ) {
			$found[] = $f;
		}
		// D8 and D9: who is logged in right now, from where.
		foreach ( $this->session_checks()->run( $this->privileged_logins( $checks ), time() ) as $f ) {
			$found[] = $f;
		}

		$new     = $this->findings->record( $found, $this->root );
		$sent    = $this->alerts->send( $new );
		$summary = array(
			'at'         => gmdate( 'c' ),
			'trigger'    => $state['trigger'] ?? 'unknown',
			'files'      => $state['files'],
			'hashed'     => $state['hashed'],
			'content'    => $state['content_read'],
			'bytes'      => $state['bytes_read'],
			'seconds'    => time() - (int) $state['started_at'],
			'findings'   => count( $found ),
			'new_alerts' => count( $new ),
			'alert'      => $sent,
			'manifest'   => $state['manifest_file'],
			'packages'   => $state['packages'],
			'baseline'   => null !== $baseline,
		);
		$this->prune_manifests( 3 );

		// Last, and only on success. See the class comment. Recorded in the
		// summary too, so the dashboard can say whether the monitor heard us.
		$summary['heartbeat'] = $this->alerts->heartbeat( 'run' );
		update_site_option( self::LAST_RUN_OPTION, $summary );
		$this->findings->event( 'scan.finished', 0, null, null, $summary );
		return $summary;
	}

	/**
	 * Sign the last completed run as "clean". Requires a human, the key, and
	 * a completed manifest. Refuses if anything CRITICAL is open, because a
	 * baseline signed over a live dropper says the dropper belongs there.
	 */
	public function sign_baseline( int $user_id ): array {
		$last = get_site_option( self::LAST_RUN_OPTION );
		if ( ! is_array( $last ) || empty( $last['manifest'] ) || ! is_file( $last['manifest'] ) ) {
			return array( 'ok' => false, 'why' => 'No completed scan to sign. Run a scan first.' );
		}
		$open = $this->findings->open_counts();
		if ( $open['critical'] > 0 ) {
			return array( 'ok' => false, 'why' => "{$open['critical']} CRITICAL finding(s) are open. Resolve or acknowledge them first." );
		}
		$key = self::key();
		if ( null === $key ) {
			return array( 'ok' => false, 'why' => 'SKY_SENTINEL_KEY is not defined in wp-config.php, or is shorter than 32 characters.' );
		}
		$files     = Sky_Sentinel_Scanner::read_manifest( $last['manifest'] );
		$inventory = $this->db_checks()->inventory();
		// L8: Sentinel's own files, so a tick can tell if they changed. And
		// the rendered-page inventories, so the hourly check can say "this
		// script was not there when the site was last clean".
		$inventory['self']  = self::self_hashes();
		$inventory['pages'] = (array) get_site_option( self::PAGES_INVENTORY, array() );
		$manifest  = Sky_Sentinel_Baseline::build( $files, (array) $last['packages'], $inventory, (string) $user_id, time() );
		$signature = Sky_Sentinel_Baseline::sign( $manifest, $key );
		update_site_option( self::BASELINE_OPTION, wp_json_encode( $manifest ) );
		update_site_option( self::BASELINE_SIG, $signature );
		// A second copy off the database, for the day the database is the
		// thing that was tampered with.
		@file_put_contents( $this->data_dir . '/baseline.json', wp_json_encode( array( 'manifest' => $manifest, 'signature' => $signature ) ) );
		$this->findings->event( 'baseline.signed', 0, $user_id, null, array( 'files' => count( $files ), 'packages' => count( $last['packages'] ) ) );
		return array( 'ok' => true, 'files' => count( $files ), 'signed_at' => $manifest['signed_at'] );
	}

	/** The baseline, or null if there is none or it does not verify. */
	public function baseline(): ?array {
		$raw = get_site_option( self::BASELINE_OPTION );
		$sig = (string) get_site_option( self::BASELINE_SIG, '' );
		$key = self::key();
		if ( ! is_string( $raw ) || '' === $raw || null === $key ) {
			return null;
		}
		$manifest = json_decode( $raw, true );
		if ( ! is_array( $manifest ) || ! Sky_Sentinel_Baseline::verify( $manifest, $sig, $key ) ) {
			return null;
		}
		return $manifest;
	}

	public function baseline_status(): array {
		$raw = get_site_option( self::BASELINE_OPTION );
		if ( ! is_string( $raw ) || '' === $raw ) {
			return array( 'state' => 'none' );
		}
		$m = $this->baseline();
		if ( null === $m ) {
			return array( 'state' => 'invalid' );
		}
		return array( 'state' => 'ok', 'signed_at' => $m['signed_at'], 'signed_by' => $m['signed_by'], 'files' => count( $m['files'] ) );
	}

	public static function key(): ?string {
		if ( ! defined( 'SKY_SENTINEL_KEY' ) || ! is_string( SKY_SENTINEL_KEY ) || strlen( SKY_SENTINEL_KEY ) < 32 ) {
			return null;
		}
		return SKY_SENTINEL_KEY;
	}

	// ---- Rendered pages (plan 3.5) ---------------------------------------

	/** Hourly: queue every site's home and login page. The tick drains it. */
	public function queue_pages(): void {
		$queue = array();
		$sites = is_multisite() ? get_sites( array( 'number' => 500 ) ) : array( (object) array( 'blog_id' => 1 ) );
		foreach ( $sites as $site ) {
			$blog_id = (int) $site->blog_id;
			$home    = is_multisite() ? get_home_url( $blog_id ) : home_url();
			$host    = (string) parse_url( $home, PHP_URL_HOST );
			$queue[] = array( 'blog_id' => $blog_id, 'url' => trailingslashit( $home ), 'label' => "{$host}:home" );
			$queue[] = array( 'blog_id' => $blog_id, 'url' => trailingslashit( $home ) . 'wp-login.php', 'label' => "{$host}:login" );
		}
		update_site_option( self::PAGES_QUEUE, $queue );
	}

	/** Drain the page queue for up to $budget seconds. Returns pages done this call. */
	public function step_pages( float $budget ): int {
		$queue = (array) get_site_option( self::PAGES_QUEUE, array() );
		if ( ! $queue ) {
			return 0;
		}
		$deadline  = microtime( true ) + $budget;
		$baseline  = $this->baseline();
		$inventory = (array) get_site_option( self::PAGES_INVENTORY, array() );
		$check     = new Sky_Sentinel_Page_Check( $this->sig, array( __CLASS__, 'fetch' ) );
		$done      = 0;
		while ( $queue && microtime( true ) < $deadline ) {
			$job = array_shift( $queue );
			$was = $baseline['inventory']['pages'][ $job['label'] ] ?? null;
			$r   = $check->check( $job['url'], $job['label'], $was['srcs'] ?? null, $was['inline'] ?? null, (int) $job['blog_id'] );
			if ( $r['fetched'] ) {
				$inventory[ $job['label'] ] = $r['inventory'];
			}
			$new = $this->findings->record( $r['findings'], $this->root );
			if ( $new ) {
				$this->alerts->send( $new );
			}
			$done++;
			update_site_option( self::PAGES_QUEUE, $queue );
		}
		update_site_option( self::PAGES_INVENTORY, $inventory );
		if ( ! $queue ) {
			update_site_option( self::PAGES_LAST, array( 'at' => gmdate( 'c' ), 'pages' => count( $inventory ) ) );
		}
		return $done;
	}

	/** wp_remote_get shaped for Sky_Sentinel_Page_Check. */
	public static function fetch( string $url, array $headers ): array {
		$r = wp_remote_get( $url, array(
			'timeout'     => 12,
			'redirection' => 3,
			'headers'     => $headers + array( 'User-Agent' => 'Sky-Sentinel/' . Sky_Sentinel::VERSION . ' (rendered-page check)' ),
			'sslverify'   => true,
		) );
		if ( is_wp_error( $r ) ) {
			return array( 'code' => 0, 'body' => '', 'headers' => array(), 'error' => $r->get_error_message() );
		}
		$h = wp_remote_retrieve_headers( $r );
		return array(
			'code'    => (int) wp_remote_retrieve_response_code( $r ),
			'body'    => (string) wp_remote_retrieve_body( $r ),
			'headers' => is_object( $h ) && method_exists( $h, 'getAll' ) ? $h->getAll() : (array) $h,
		);
	}

	// ---- L8: our own files --------------------------------------------------

	/** sha256 of every file under the plugin directory, relative paths. */
	public static function self_hashes(): array {
		$root = Sky_Sentinel::dir();
		$out  = array();
		$it   = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ) );
		foreach ( $it as $file ) {
			$rel = str_replace( '\\', '/', substr( $file->getPathname(), strlen( $root ) + 1 ) );
			if ( str_starts_with( $rel, 'vendor/' ) || str_starts_with( $rel, 'tests/' ) || str_starts_with( $rel, '.' ) ) {
				continue;
			}
			$out[ $rel ] = (string) hash_file( 'sha256', $file->getPathname() );
		}
		ksort( $out );
		return $out;
	}

	/**
	 * Every tick, once a baseline exists: are our own files what they were
	 * when signed? A changed detector is an attacker editing the tripwire; a
	 * missing file is worse. CRITICAL, and the webhook is the channel that
	 * matters here because it does not depend on anything under wp-content.
	 */
	public function self_check(): void {
		$baseline = $this->baseline();
		if ( null === $baseline || empty( $baseline['inventory']['self'] ) ) {
			return;
		}
		$was = (array) $baseline['inventory']['self'];
		$now = self::self_hashes();
		$found = array();
		foreach ( $was as $rel => $sha ) {
			if ( ! isset( $now[ $rel ] ) ) {
				$found[] = new Sky_Sentinel_Finding( 'L8', 'critical', "self:{$rel}", "Sentinel's own file is missing: {$rel}" );
			} elseif ( $now[ $rel ] !== $sha ) {
				$found[] = new Sky_Sentinel_Finding( 'L8', 'critical', "self:{$rel}", "Sentinel's own file changed since the baseline: {$rel}", array( 'was' => $sha ), $now[ $rel ] );
			}
		}
		foreach ( array_diff_key( $now, $was ) as $rel => $sha ) {
			$found[] = new Sky_Sentinel_Finding( 'L8', 'high', "self:{$rel}", "A file appeared inside Sentinel's directory: {$rel}", array(), $sha );
		}
		if ( $found ) {
			$new = $this->findings->record( $found, $this->root );
			if ( $new ) {
				$this->alerts->send( $new );
			}
		}
	}

	// ---- Networks and Tor -------------------------------------------------

	public function network(): Sky_Sentinel_Network {
		$cidrs = array_merge( $this->sig->allow_list( 'network_cidrs' ), (array) get_site_option( 'sky_sentinel_network_cidrs', array() ) );
		return new Sky_Sentinel_Network( $this->sig->attacker_ips(), $this->sig->tooling_user_agents(), array_values( array_unique( array_filter( $cidrs ) ) ), self::tor_exits( $this->data_dir ) );
	}

	/** Weekly: the Tor exit list, into the data directory. A fixed URL, never a user-supplied one. */
	public function refresh_tor_list(): bool {
		$r = wp_remote_get( 'https://check.torproject.org/torbulkexitlist', array( 'timeout' => 20 ) );
		if ( is_wp_error( $r ) || 200 !== (int) wp_remote_retrieve_response_code( $r ) ) {
			$this->findings->event( 'tor.refresh_failed', 0, null, null, array( 'error' => is_wp_error( $r ) ? $r->get_error_message() : wp_remote_retrieve_response_code( $r ) ) );
			return false;
		}
		$body = (string) wp_remote_retrieve_body( $r );
		$ips  = array_values( array_filter( array_map( 'trim', explode( "\n", $body ) ), fn( $l ) => filter_var( $l, FILTER_VALIDATE_IP ) ) );
		if ( count( $ips ) < 100 ) {
			// A list that short is a broken download, not the Tor network.
			return false;
		}
		@file_put_contents( $this->data_dir . '/tor-exits.txt', implode( "\n", $ips ) . "\n" );
		$this->findings->event( 'tor.refreshed', 0, null, null, array( 'count' => count( $ips ) ) );
		return true;
	}

	public static function tor_exits( string $data_dir ): array {
		$file = $data_dir . '/tor-exits.txt';
		if ( ! is_readable( $file ) ) {
			return array();
		}
		return array_values( array_filter( array_map( 'trim', (array) file( $file ) ) ) );
	}

	private function session_checks(): Sky_Sentinel_Session_Checks {
		global $wpdb;
		return new Sky_Sentinel_Session_Checks( $wpdb, $this->network() );
	}

	/** Every login that is an administrator somewhere or a super admin. */
	private function privileged_logins( Sky_Sentinel_DB_Checks $checks ): array {
		$inv = $checks->inventory();
		$all = (array) ( $inv['site_admins'] ?? array() );
		foreach ( (array) ( $inv['blogs'] ?? array() ) as $b ) {
			$all = array_merge( $all, (array) ( $b['admins'] ?? array() ) );
		}
		return array_values( array_unique( $all ) );
	}

	private function db_checks(): Sky_Sentinel_DB_Checks {
		global $wpdb;
		$blog_ids = is_multisite() ? array_map( 'intval', get_sites( array( 'fields' => 'ids', 'number' => 500 ) ) ) : array( 1 );
		return new Sky_Sentinel_DB_Checks(
			$wpdb,
			$this->sig,
			$blog_ids,
			function (): int {
				// count_users() is per-blog; on a network the users table is
				// shared, so ask the API the network-wide question it does answer.
				if ( is_multisite() ) {
					return (int) get_user_count();
				}
				$c = count_users();
				return (int) ( $c['total_users'] ?? 0 );
			},
			function (): array {
				if ( ! function_exists( 'get_plugins' ) ) {
					require_once ABSPATH . 'wp-admin/includes/plugin.php';
				}
				return array_keys( get_plugins() );
			},
			function (): array {
				// Straight off the disk, with the same rule get_plugins() uses to
				// decide what a plugin is: a top-level .php with a Plugin Name
				// header, or a directory holding one.
				$out = array();
				foreach ( (array) glob( WP_PLUGIN_DIR . '/*' ) as $entry ) {
					$base = basename( $entry );
					if ( is_file( $entry ) && str_ends_with( $entry, '.php' ) ) {
						if ( self::has_plugin_header( $entry ) ) {
							$out[] = $base;
						}
						continue;
					}
					if ( is_dir( $entry ) ) {
						foreach ( (array) glob( $entry . '/*.php' ) as $file ) {
							if ( self::has_plugin_header( $file ) ) {
								$out[] = $base . '/' . basename( $file );
							}
						}
					}
				}
				sort( $out );
				return $out;
			},
			is_multisite()
		);
	}

	private static function has_plugin_header( string $file ): bool {
		$head = (string) @file_get_contents( $file, false, null, 0, 8192 );
		return (bool) preg_match( '/^[ \t\/*#@]*Plugin Name:/mi', $head );
	}

	private function prune_manifests( int $keep ): void {
		$files = (array) glob( $this->data_dir . '/manifest-*.jsonl' );
		rsort( $files );
		foreach ( array_slice( $files, $keep ) as $old ) {
			@unlink( $old );
		}
	}
}
