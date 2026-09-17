<?php
/**
 * D8 and D9: who is logged in right now, and from where.
 *
 * WordPress keeps every live session in usermeta `session_tokens`: a
 * serialized map of token hash => {expiration, ip, ua, login}. The dump from
 * this incident held 38 sessions for the compromised super admin, every one
 * carrying the same Safari 18.0 tooling user-agent. That table is where a
 * stolen credential shows up first, before any file changes.
 *
 * Read with a regex, never unserialize(): the values are attacker-written.
 */
final class Sky_Sentinel_Session_Checks {

	/** @var object with base_prefix, get_results() */
	private $db;
	private Sky_Sentinel_Network $net;

	public function __construct( $db, Sky_Sentinel_Network $net ) {
		$this->db  = $db;
		$this->net = $net;
	}

	/**
	 * Sessions of every user who is an administrator anywhere or a super
	 * admin, classified.
	 *
	 * @param string[] $privileged_logins
	 * @return Sky_Sentinel_Finding[]
	 */
	public function run( array $privileged_logins, int $now ): array {
		if ( ! $privileged_logins ) {
			return array();
		}
		$in   = implode( ',', array_map( fn( $l ) => "'" . str_replace( "'", "''", $l ) . "'", $privileged_logins ) );
		$rows = (array) $this->db->get_results( "SELECT u.user_login, m.meta_value FROM {$this->db->base_prefix}users u INNER JOIN {$this->db->base_prefix}usermeta m ON m.user_id = u.ID AND m.meta_key = 'session_tokens' WHERE u.user_login IN ({$in})" );
		$out  = array();
		foreach ( $rows as $row ) {
			foreach ( self::parse_sessions( (string) $row->meta_value ) as $s ) {
				if ( $s['expiration'] > 0 && $s['expiration'] < $now ) {
					continue;
				}
				$f = $this->classify( (string) $row->user_login, $s );
				if ( $f ) {
					$out[] = $f;
				}
			}
		}
		return $out;
	}

	private function classify( string $login, array $s ): ?Sky_Sentinel_Finding {
		// By /24, like L1: three Private Relay addresses in one afternoon are
		// one fact about one person, not three findings.
		$subject = "session:{$login}@" . Sky_Sentinel_Network::prefix_of( $s['ip'] );
		$detail  = array( 'ip' => $s['ip'], 'ua' => $s['ua'], 'login_at' => $s['login'] ? gmdate( 'Y-m-d H:i:s', $s['login'] ) : null );
		switch ( $this->net->classify( $s['ip'], $s['ua'] ) ) {
			case Sky_Sentinel_Network::ATTACKER_IP:
				return new Sky_Sentinel_Finding( 'D9', 'critical', $subject, "Live session for {$login} from a known attacker address {$s['ip']}", $detail );
			case Sky_Sentinel_Network::TOOLING_UA:
				return new Sky_Sentinel_Finding( 'D9', 'critical', $subject, "Live session for {$login} with the campaign's tooling user-agent", $detail );
			case Sky_Sentinel_Network::TOR_EXIT:
				return new Sky_Sentinel_Finding( 'D8', 'high', $subject, "Live session for {$login} from a Tor exit {$s['ip']}", $detail );
			case Sky_Sentinel_Network::OUTSIDE_ALLOWED:
				return new Sky_Sentinel_Finding( 'D8', 'high', $subject, "Live session for {$login} from {$s['ip']}, outside the allow-listed networks", $detail );
		}
		return null;
	}

	/**
	 * Pull {expiration, ip, ua, login} out of the serialized map without
	 * unserializing it. The shape WordPress writes is stable:
	 *   a:N:{s:64:"<hash>";a:4:{s:10:"expiration";i:...;s:2:"ip";s:L:"...";s:2:"ua";s:L:"...";s:5:"login";i:...;}...}
	 *
	 * Strings are read by their LENGTH prefix, never by looking for the closing
	 * quote: a user-agent is attacker-chosen and a quote inside it would end a
	 * quote-delimited match early and hide the rest.
	 *
	 * @return array<int, array{expiration:int, ip:string, ua:string, login:int}>
	 */
	public static function parse_sessions( string $raw ): array {
		$out = array();
		$pos = 0;
		while ( false !== ( $at = strpos( $raw, 's:10:"expiration";', $pos ) ) ) {
			// Start AT the label, so the expiration field is read from this
			// session and not the next one's. The first draft skipped past it
			// and every session read as never expiring.
			$pos = $at;
			$s   = array( 'expiration' => 0, 'ip' => '', 'ua' => '', 'login' => 0 );
			foreach ( array( 'expiration' => 'i', 'ip' => 's', 'ua' => 's', 'login' => 'i' ) as $key => $type ) {
				$label = 's:' . strlen( $key ) . ':"' . $key . '";';
				$k     = strpos( $raw, $label, $pos );
				if ( false === $k || $k - $pos > 64 ) {
					// Fields are adjacent; a label far away belongs to the next session.
					continue;
				}
				$p = $k + strlen( $label );
				if ( 'i' === $type ) {
					if ( preg_match( '/\Gi:(\d+);/', $raw, $m, 0, $p ) ) {
						$s[ $key ] = (int) $m[1];
						$pos       = $p + strlen( $m[0] );
					}
				} elseif ( preg_match( '/\Gs:(\d+):"/', $raw, $m, 0, $p ) ) {
					$len       = (int) $m[1];
					$from      = $p + strlen( $m[0] );
					$s[ $key ] = substr( $raw, $from, $len );
					$pos       = $from + $len + 2; // closing quote and semicolon
				}
			}
			if ( '' !== $s['ip'] || '' !== $s['ua'] ) {
				$out[] = $s;
			}
		}
		return $out;
	}
}
