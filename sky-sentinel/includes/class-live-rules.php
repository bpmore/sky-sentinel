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

	/** Roles that count as privileged on a network like this one. */
	public static function is_privileged( array $roles, bool $super_admin ): bool {
		return $super_admin || (bool) array_intersect( $roles, array( 'administrator' ) );
	}
}
