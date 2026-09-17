<?php
/**
 * Where a request came from, and whether that is a place an administrator
 * of this site logs in from.
 *
 * Pure. The lists are injected: the campaign's IPs and user-agents from
 * iocs.json, the networks administrators are expected on (an office range,
 * a few home blocks) from the allow-list, and the Tor exit list fetched
 * weekly into the data directory.
 *
 * This campaign rotates through a handful of addresses on Tor, consumer VPNs
 * and hosting providers, with a small fixed set of tooling user-agents. Any
 * one of those, on an administrator login, is the intrusion starting.
 */
final class Sky_Sentinel_Network {

	public const ATTACKER_IP     = 'attacker_ip';
	public const TOOLING_UA      = 'tooling_ua';
	public const TOR_EXIT        = 'tor_exit';
	public const OUTSIDE_ALLOWED = 'outside_allowed';
	public const OK              = 'ok';

	/** @var string[] */
	private array $attacker_ips;
	/** @var string[] */
	private array $tooling_uas;
	/** @var string[] CIDRs */
	private array $allowed;
	/** @var array<string,true> */
	private array $tor;

	public function __construct( array $attacker_ips, array $tooling_uas, array $allowed_cidrs, array $tor_exits = array() ) {
		$this->attacker_ips = array_map( 'trim', $attacker_ips );
		$this->tooling_uas  = array_map( 'trim', $tooling_uas );
		$this->allowed      = array_map( 'trim', $allowed_cidrs );
		$this->tor          = array_fill_keys( array_map( 'trim', $tor_exits ), true );
	}

	/**
	 * The worst thing true about this origin, in order of certainty. Returns
	 * OK only when nothing matched AND (there is no allow-list, or the IP is
	 * inside it). An allow-list that exists and does not contain the IP is
	 * OUTSIDE_ALLOWED, which is HIGH rather than CRITICAL: a new home ISP is
	 * a one-time notice, not an incident.
	 */
	public function classify( string $ip, string $ua ): string {
		$ip = trim( $ip );
		$ua = trim( $ua );
		if ( in_array( $ip, $this->attacker_ips, true ) ) {
			return self::ATTACKER_IP;
		}
		if ( '' !== $ua && in_array( $ua, $this->tooling_uas, true ) ) {
			return self::TOOLING_UA;
		}
		if ( isset( $this->tor[ $ip ] ) ) {
			return self::TOR_EXIT;
		}
		if ( $this->allowed && '' !== $ip && ! $this->allowed( $ip ) ) {
			return self::OUTSIDE_ALLOWED;
		}
		return self::OK;
	}

	public function allowed( string $ip ): bool {
		foreach ( $this->allowed as $cidr ) {
			if ( self::in_cidr( $ip, $cidr ) ) {
				return true;
			}
		}
		return false;
	}

	/** IPv4 and IPv6, "a.b.c.d" alone meaning /32. */
	public static function in_cidr( string $ip, string $cidr ): bool {
		$ip = trim( $ip );
		if ( ! str_contains( $cidr, '/' ) ) {
			return $ip === trim( $cidr );
		}
		list( $net, $bits ) = explode( '/', trim( $cidr ), 2 );
		$bits = (int) $bits;
		$a    = @inet_pton( $ip );
		$b    = @inet_pton( $net );
		if ( false === $a || false === $b || strlen( $a ) !== strlen( $b ) ) {
			return false;
		}
		$max = strlen( $a ) * 8;
		if ( $bits < 0 || $bits > $max ) {
			return false;
		}
		$full = intdiv( $bits, 8 );
		$rest = $bits % 8;
		if ( $full > 0 && substr( $a, 0, $full ) !== substr( $b, 0, $full ) ) {
			return false;
		}
		if ( 0 === $rest ) {
			return true;
		}
		$mask = ( 0xFF << ( 8 - $rest ) ) & 0xFF;
		return ( ord( $a[ $full ] ) & $mask ) === ( ord( $b[ $full ] ) & $mask );
	}

	/** The /24 (or /64) a login came from: what "a network they have used before" means. */
	public static function prefix_of( string $ip ): string {
		$ip = trim( $ip );
		$p  = @inet_pton( $ip );
		if ( false === $p ) {
			return $ip;
		}
		if ( 4 === strlen( $p ) ) {
			return implode( '.', array_slice( explode( '.', $ip ), 0, 3 ) ) . '.0/24';
		}
		return inet_ntop( substr( $p, 0, 8 ) . str_repeat( "\0", 8 ) ) . '/64';
	}

	/**
	 * The client IP behind a proxy. Managed hosts commonly front with nginx
	 * and Cloudflare; REMOTE_ADDR is then the proxy. CF-Connecting-IP is set
	 * by Cloudflare and cannot be forged past it; X-Forwarded-For is trusted
	 * only as a fallback and only its first hop.
	 */
	public static function client_ip( array $server ): string {
		foreach ( array( 'HTTP_CF_CONNECTING_IP', 'HTTP_X_REAL_IP' ) as $h ) {
			if ( ! empty( $server[ $h ] ) && filter_var( $server[ $h ], FILTER_VALIDATE_IP ) ) {
				return (string) $server[ $h ];
			}
		}
		if ( ! empty( $server['HTTP_X_FORWARDED_FOR'] ) ) {
			$first = trim( explode( ',', (string) $server['HTTP_X_FORWARDED_FOR'] )[0] );
			if ( filter_var( $first, FILTER_VALIDATE_IP ) ) {
				return $first;
			}
		}
		return (string) ( $server['REMOTE_ADDR'] ?? '' );
	}
}
