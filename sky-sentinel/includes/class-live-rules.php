<?php
/**
 * What the live hooks decide, with WordPress removed.
 *
 * L1 to L7 are things that happen while an attacker is inside: a login, a
 * role change, a plugin upload, the theme editor, a file-manager call, user
 * enumeration, a password-guessing burst. Every one of them was in the
 * request logs of this incident. The hooks in class-live-hooks catch the
 * event; the methods here decide what it means, so the decision is a unit
 * test and not a production experiment.
 *
 * Every method returns a Sky_Sentinel_Finding or null.
 */
final class Sky_Sentinel_Live_Rules {

	public const BURST_THRESHOLD = 10;
	public const BURST_WINDOW    = 600;

	private Sky_Sentinel_Network $net;

	public function __construct( Sky_Sentinel_Network $net ) {
		$this->net = $net;
	}

	/**
	 * L1: an administrator logged in. Where from, and have they ever logged in
	 * from that network before?
	 *
	 * @param string[] $prior_prefixes /24s this user has logged in from, from Sentinel's own event log.
	 */
	public function login( string $login, bool $privileged, string $ip, string $ua, array $prior_prefixes, bool $tooling_sequence, int $blog_id = 0 ): ?Sky_Sentinel_Finding {
		if ( ! $privileged ) {
			return null;
		}
		$subject = "login:{$login}@" . Sky_Sentinel_Network::prefix_of( $ip );
		$detail  = array( 'ip' => $ip, 'ua' => $ua );
		switch ( $this->net->classify( $ip, $ua ) ) {
			case Sky_Sentinel_Network::ATTACKER_IP:
				return new Sky_Sentinel_Finding( 'L1', 'critical', $subject, "Administrator {$login} logged in from a known attacker address {$ip}", $detail, null, $blog_id );
			case Sky_Sentinel_Network::TOOLING_UA:
				return new Sky_Sentinel_Finding( 'L1', 'critical', $subject, "Administrator {$login} logged in with the campaign's tooling user-agent", $detail, null, $blog_id );
			case Sky_Sentinel_Network::TOR_EXIT:
				return new Sky_Sentinel_Finding( 'L1', 'high', $subject, "Administrator {$login} logged in from a Tor exit {$ip}", $detail, null, $blog_id );
			case Sky_Sentinel_Network::OUTSIDE_ALLOWED:
				return new Sky_Sentinel_Finding( 'L1', 'high', $subject, "Administrator {$login} logged in from {$ip}, outside the allow-listed networks", $detail, null, $blog_id );
		}
		// L7 second clause: the attacker's login sequence opened with
		// GET /wp-login.php?wp_lang=en_US every time. A human's browser does
		// not add that.
		if ( $tooling_sequence ) {
			return new Sky_Sentinel_Finding( 'L7', 'high', $subject, "Administrator {$login} logged in via the wp_lang=en_US tooling sequence from {$ip}", $detail, null, $blog_id );
		}
		if ( ! in_array( Sky_Sentinel_Network::prefix_of( $ip ), $prior_prefixes, true ) ) {
			// First login from this block. MEDIUM: a real person on a new
			// ISP once; the digest will show it; the second one is silent.
			return new Sky_Sentinel_Finding( 'L1', 'medium', $subject, "Administrator {$login} logged in from a network not seen before ({$ip})", $detail, null, $blog_id );
		}
		return null;
	}

	/** L2: somebody became an administrator. Always CRITICAL: nobody does that by accident. */
	public function promoted( string $login, string $how, string $by, int $blog_id = 0 ): Sky_Sentinel_Finding {
		return new Sky_Sentinel_Finding( 'L2', 'critical', "user:{$login}", "{$login} was made an administrator ({$how}) by {$by}", array( 'how' => $how, 'by' => $by ), null, $blog_id );
	}

	/** L2: a signup or new user carrying the administrator role. */
	public function admin_signup( string $login, string $email, string $by ): Sky_Sentinel_Finding {
		return new Sky_Sentinel_Finding( 'L2', 'critical', "signup:{$login}", "A signup for administrator {$login} <{$email}> was created by {$by}", array( 'by' => $by ) );
	}

	/**
	 * L3: a package landed or changed state. Install and activate alert;
	 * an update from wordpress.org is a log line.
	 */
	public function package( string $action, string $type, string $slug, string $by, bool $from_upload ): Sky_Sentinel_Finding {
		$subject = "{$type}:{$slug}";
		switch ( $action ) {
			case 'install':
				$sev = 'high';
				$what = $from_upload ? "A {$type} was UPLOADED and installed: {$slug}" : "A {$type} was installed: {$slug}";
				break;
			case 'activate':
			case 'switch_theme':
				$sev  = 'high';
				$what = "A {$type} was activated: {$slug}";
				break;
			case 'deactivate':
				$sev  = 'medium';
				$what = "A {$type} was deactivated: {$slug}";
				break;
			default:
				$sev  = 'info';
				$what = "A {$type} was updated: {$slug}";
		}
		return new Sky_Sentinel_Finding( 'L3', $sev, $subject, $what . " by {$by}", array( 'action' => $action, 'by' => $by, 'upload' => $from_upload ) );
	}

	/** L4: the theme or plugin editor was used. Should be impossible with DISALLOW_FILE_EDIT. */
	public function editor_used( string $file, string $by ): Sky_Sentinel_Finding {
		return new Sky_Sentinel_Finding( 'L4', 'critical', "editor:{$file}", "The built-in file editor wrote {$file} (by {$by}). DISALLOW_FILE_EDIT should make this impossible.", array( 'by' => $by ) );
	}

	/** L5: an admin-ajax action belonging to a file manager. */
	public static function is_file_manager_action( string $action ): bool {
		return (bool) preg_match( '/mk_file_folder_manager|elfinder|wp_file_manager|filester|^fm_|file_manager/i', $action );
	}

	public function file_manager( string $action, string $by, string $ip ): Sky_Sentinel_Finding {
		return new Sky_Sentinel_Finding( 'L5', 'critical', "ajax:{$action}", "A file-manager connector was called ({$action}) by {$by} from {$ip}", array( 'by' => $by, 'ip' => $ip ) );
	}

	/**
	 * L6: is this user lookup enumeration by the client? Only when the request
	 * itself is a REST request ($rest_request: WordPress's REST_REQUEST, set
	 * only for /wp-json/ and ?rest_route=), from nobody logged in, reading
	 * /wp/v2/users.
	 *
	 * A plugin or block that looks users up with rest_do_request() while
	 * building an ordinary page fires the same filter, and before 0.4.4 L6
	 * counted it against whoever loaded the page. On one multisite that was
	 * Sentinel's own hourly page check: ~1,000 a day against the server's own
	 * address, 94% of every L6 hit, which read like a neighbour on the same
	 * host enumerating users. An embedded author on an anonymous
	 * /wp-json/wp/v2/posts?_embed still counts: that IS a REST request reading
	 * user data, and ?_embed is a known way to harvest author names.
	 */
	public static function is_enumeration( bool $logged_in, string $method, string $route, bool $rest_request ): bool {
		return $rest_request && ! $logged_in && 'GET' === strtoupper( $method ) && (bool) preg_match( '#^/wp/v2/users(?:/|$)#', $route );
	}

	/** L6: unauthenticated user enumeration over REST. One finding per IP per day, by subject. */
	public function user_enumeration( string $ip, string $day ): Sky_Sentinel_Finding {
		return new Sky_Sentinel_Finding( 'L6', 'medium', "enum:{$ip}:{$day}", "Unauthenticated GET /wp-json/wp/v2/users from {$ip}", array( 'ip' => $ip ) );
	}

	/**
	 * L7: failed logins in a window. The caller keeps the per-IP timestamps;
	 * this says whether the latest one tipped it.
	 *
	 * @param int[] $timestamps Failed-login times for this IP, oldest first.
	 */
	public static function is_burst( array $timestamps, int $now ): bool {
		$recent = array_filter( $timestamps, fn( $t ) => $t > $now - self::BURST_WINDOW );
		return count( $recent ) >= self::BURST_THRESHOLD;
	}

	public function burst( string $ip, int $count, string $day ): Sky_Sentinel_Finding {
		return new Sky_Sentinel_Finding( 'L7', 'high', "burst:{$ip}:{$day}", "{$count} failed logins from {$ip} inside ten minutes", array( 'ip' => $ip, 'count' => $count ) );
	}

	/**
	 * L2: an administrator's password was set outside the lost-password flow.
	 * The Wordfence-reported mu-plugin takes over an existing administrator
	 * with wp_set_password() instead of creating one, so the user count never
	 * moves and no role hook fires. From cron or an anonymous request it is
	 * CRITICAL: no human changed that password.
	 *
	 * @param bool $reset_flow The request is wp-login.php?action=rp|resetpass, where the owner resets their own.
	 */
	public function password_set( string $login, bool $privileged, string $by, bool $reset_flow, string $when, int $blog_id = 0 ): ?Sky_Sentinel_Finding {
		if ( ! $privileged || $reset_flow ) {
			return null;
		}
		$sev = in_array( $by, array( 'anonymous', 'wp-cron' ), true ) ? 'critical' : 'high';
		return new Sky_Sentinel_Finding( 'L2', $sev, "password:{$login}:{$when}", "Administrator {$login}'s password was set by {$by}, outside the lost-password flow", array( 'by' => $by ), null, $blog_id );
	}

	/**
	 * L11: WordPress was asked to make an outbound request that is an
	 * on-chain lookup. The mu-plugin in the Wordfence write-up finds its
	 * command servers by eth_call to a smart contract through public RPC
	 * gateways, and tries wp_remote_post before cURL, so the request passes
	 * through pre_http_request where this can see it. The source can be as
	 * obfuscated as it likes; the request body cannot be.
	 *
	 * Matched on JSON-RPC STRUCTURE ("method":"eth_..."), not the bare word,
	 * because Sentinel's own webhook can carry the word eth_call in a
	 * finding's summary.
	 *
	 * @param string   $body      The request body, JSON-encoded if it was an array.
	 * @param string[] $rpc_hosts The campaign's gateway list (iocs.json).
	 * @param string   $caller    The file that called the HTTP API, relative, or ''.
	 */
	public function outbound_request( string $url, string $body, array $rpc_hosts, string $caller ): ?Sky_Sentinel_Finding {
		$host   = strtolower( (string) parse_url( $url, PHP_URL_HOST ) );
		$method = preg_match( '/"method"\s*:\s*"(eth_[A-Za-z]+)"/', $body, $m ) ? $m[1] : null;
		$known  = false;
		$hostpath = $host . (string) parse_url( $url, PHP_URL_PATH );
		foreach ( $rpc_hosts as $h ) {
			if ( '' !== $h && str_starts_with( $hostpath, strtolower( (string) $h ) ) ) {
				$known = true;
			}
		}
		if ( null === $method && ! $known ) {
			return null;
		}
		$detail = array( 'url' => $url, 'caller' => $caller );
		if ( null !== $method ) {
			$detail['method'] = $method;
			if ( preg_match( '/"data"\s*:\s*"(0x[0-9a-fA-F]{8})/', $body, $s ) ) {
				$detail['selector'] = $s[1];
			}
			if ( preg_match( '/"to"\s*:\s*"(0x[0-9a-fA-F]{40})"/', $body, $t ) ) {
				$detail['contract'] = $t[1];
			}
		}
		$what = null !== $method ? "an on-chain {$method} call" : 'a request to a campaign RPC gateway';
		$from = '' !== $caller ? " from {$caller}" : '';
		return new Sky_Sentinel_Finding( 'L11', 'critical', "outbound:{$host}:" . ( $caller ?: '?' ), "WordPress made {$what} to {$host}{$from}: an EtherHiding command-server lookup", $detail );
	}

	/**
	 * L11: which file asked for the request. The first frame outside
	 * wp-includes/ is the caller: WP_Http and wp_remote_post live there.
	 *
	 * @param array  $trace debug_backtrace() frames
	 * @param string $root  absolute path to make the file relative to
	 */
	public static function caller_from_trace( array $trace, string $root ): string {
		$root = rtrim( str_replace( '\\', '/', $root ), '/' ) . '/';
		foreach ( $trace as $frame ) {
			$file = str_replace( '\\', '/', (string) ( $frame['file'] ?? '' ) );
			if ( '' === $file ) {
				continue;
			}
			$rel = str_starts_with( $file, $root ) ? substr( $file, strlen( $root ) ) : $file;
			if ( str_starts_with( $rel, 'wp-includes/' ) || str_contains( $rel, '/sky-sentinel/includes/class-live-hooks.php' ) ) {
				continue;
			}
			return $rel;
		}
		return '';
	}

	/** Roles that count as privileged on a network like this one. */
	public static function is_privileged( array $roles, bool $super_admin ): bool {
		return $super_admin || (bool) array_intersect( $roles, array( 'administrator' ) );
	}
}
