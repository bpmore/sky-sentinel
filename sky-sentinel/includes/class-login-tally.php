<?php
/**
 * L13: a daily count of failed logins, so that silence can be read.
 *
 * L7 only speaks when one address fails ten times in ten minutes. A night
 * with no L7 could mean nobody tried, that something upstream (a WAF, a
 * login limiter) now stops them before WordPress, or that Sentinel stopped
 * hearing them. The first quiet night after an upgrade looks exactly like
 * all three. Counting every failure, by day and
 * by address, tells them apart: a total that falls from hundreds to zero
 * overnight is a change worth a line in the digest.
 *
 * Pure. Every method takes the tally array and returns a new one or a
 * reading of it; the caller stores it (one site option) and supplies time().
 *
 * Shape:
 *   since => 'Y-m-d'  the first day counted, so a new install does not read as a quiet week
 *   days  => [ 'Y-m-d' => [ total, ips => [ip => n], capped ] ]   today and yesterday
 *            [ 'Y-m-d' => [ total, distinct, capped, top_ip, top_count, repeat => [ip => n] ] ]  older, compacted
 *
 * `repeat` keeps, for older days, every address that failed more than once
 * that day (0.4.13), so the block list can look back KEEP_DAYS. A single
 * failure from an address is not kept past yesterday.
 */
final class Sky_Sentinel_Login_Tally {

	/** Where the tally is stored (one site option). */
	public const OPTION = 'sky_sentinel_login_tally';

	/** Days of history kept. */
	public const KEEP_DAYS = 14;

	/** Distinct addresses counted per day before the rest go into a total only. Bounds the option's size under a spray. */
	public const MAX_IPS = 300;

	/** L13 wants the week before a quiet day to have averaged at least this many failures a day. */
	public const QUIET_FLOOR = 10;

	/** The block list: an address (or a /24) with at least this many failures in KEEP_DAYS. */
	public const BLOCK_MIN = 5;

	/** Count one failed login. */
	public static function record( array $tally, string $ip, int $now ): array {
		$today = gmdate( 'Y-m-d', $now );
		$tally['since'] ??= $today;
		$tally['days']  ??= array();
		$day = $tally['days'][ $today ] ?? array( 'total' => 0, 'ips' => array(), 'capped' => false );
		$day['total']++;
		if ( '' !== $ip ) {
			if ( isset( $day['ips'][ $ip ] ) ) {
				$day['ips'][ $ip ]++;
			} elseif ( count( $day['ips'] ) < self::MAX_IPS ) {
				$day['ips'][ $ip ] = 1;
			} else {
				$day['capped'] = true;
			}
		}
		$tally['days'][ $today ] = $day;
		return self::compact( $tally, $now );
	}

	/**
	 * Keep per-address maps for today and yesterday only; reduce older days to
	 * their numbers; drop anything past KEEP_DAYS.
	 */
	public static function compact( array $tally, int $now ): array {
		$keep_detail = array( gmdate( 'Y-m-d', $now ), gmdate( 'Y-m-d', $now - 86400 ) );
		$oldest      = gmdate( 'Y-m-d', $now - ( self::KEEP_DAYS - 1 ) * 86400 );
		foreach ( (array) ( $tally['days'] ?? array() ) as $date => $day ) {
			if ( $date < $oldest ) {
				unset( $tally['days'][ $date ] );
			} elseif ( ! in_array( $date, $keep_detail, true ) && isset( $day['ips'] ) ) {
				$repeat = array_filter( (array) $day['ips'], fn( $n ) => $n > 1 );
				arsort( $repeat );
				$tally['days'][ $date ] = self::summary_of( $day ) + array( 'repeat' => $repeat );
			}
		}
		if ( isset( $tally['days'] ) ) {
			krsort( $tally['days'] );
		}
		return $tally;
	}

	/**
	 * One day as numbers, whichever shape it is stored in. A day with no
	 * failures has no entry, and reads as zeros.
	 *
	 * @return array{total:int,distinct:int,capped:bool,top_ip:string,top_count:int}
	 */
	public static function day( array $tally, string $date ): array {
		$day = $tally['days'][ $date ] ?? null;
		if ( null === $day ) {
			return array( 'total' => 0, 'distinct' => 0, 'capped' => false, 'top_ip' => '', 'top_count' => 0 );
		}
		return isset( $day['ips'] ) ? self::summary_of( $day ) : array_diff_key( $day, array( 'repeat' => true ) );
	}

	/**
	 * Failures by address over the last $days days: every address for today
	 * and yesterday, the repeat offenders for older days.
	 *
	 * @return array<string,int> ip => failures, most first
	 */
	public static function addresses( array $tally, int $now, int $days = self::KEEP_DAYS ): array {
		$oldest = gmdate( 'Y-m-d', $now - ( $days - 1 ) * 86400 );
		$out    = array();
		foreach ( (array) ( $tally['days'] ?? array() ) as $date => $day ) {
			if ( $date < $oldest ) {
				continue;
			}
			foreach ( (array) ( $day['ips'] ?? $day['repeat'] ?? array() ) as $ip => $n ) {
				$out[ (string) $ip ] = ( $out[ (string) $ip ] ?? 0 ) + (int) $n;
			}
		}
		arsort( $out );
		return $out;
	}

	/**
	 * What to paste into a host's block list: addresses, or their /24s (/64
	 * for IPv6), with at least $min failures. Held back, and never in the
	 * list: anything inside an allow-listed network, and any address or
	 * /24 an administrator has logged in from. A /24 is shared with
	 * strangers; blocking one an administrator uses locks them out.
	 *
	 * @param array<string,int> $counts        ip => failures (addresses()).
	 * @param string[]          $allowed_cidrs The network allow-list.
	 * @param string[]          $admin_prefixes /24s (or /64s) administrators logged in from.
	 * @return array{block: array<string,array{total:int,addresses:int}>, held: array<string,array{total:int,addresses:int,why:string}>}
	 */
	public static function block_list( array $counts, array $allowed_cidrs, array $admin_prefixes, bool $subnets, int $min = self::BLOCK_MIN ): array {
		$groups = array();
		foreach ( $counts as $ip => $n ) {
			$ip = (string) $ip;
			if ( false === @inet_pton( $ip ) ) {
				continue;
			}
			$key = $subnets ? Sky_Sentinel_Network::prefix_of( $ip ) : $ip;
			$groups[ $key ]['total']   = ( $groups[ $key ]['total'] ?? 0 ) + (int) $n;
			$groups[ $key ]['members'][] = $ip;
		}
		$out = array( 'block' => array(), 'held' => array() );
		foreach ( $groups as $key => $g ) {
			if ( $g['total'] < $min ) {
				continue;
			}
			$row = array( 'total' => $g['total'], 'addresses' => count( $g['members'] ) );
			$why = self::protected_by( (string) $key, $g['members'], $allowed_cidrs, $admin_prefixes );
			if ( null !== $why ) {
				$out['held'][ $key ] = $row + array( 'why' => $why );
			} else {
				$out['block'][ $key ] = $row;
			}
		}
		foreach ( array( 'block', 'held' ) as $k ) {
			uasort( $out[ $k ], fn( $a, $b ) => $b['total'] <=> $a['total'] );
		}
		return $out;
	}

	/** Why an entry must not be blocked, or null. $key is an address or a prefix. */
	private static function protected_by( string $key, array $members, array $allowed_cidrs, array $admin_prefixes ): ?string {
		$is_prefix = str_contains( $key, '/' );
		foreach ( $allowed_cidrs as $cidr ) {
			$cidr = trim( (string) $cidr );
			if ( '' === $cidr ) {
				continue;
			}
			if ( $is_prefix ) {
				// Overlap either way: the /24 inside the allowed range, or the
				// allowed range (a /25, a single address) inside the /24.
				$base = strstr( $key, '/', true );
				$net  = str_contains( $cidr, '/' ) ? strstr( $cidr, '/', true ) : $cidr;
				if ( Sky_Sentinel_Network::in_cidr( $base, $cidr ) || Sky_Sentinel_Network::in_cidr( $net, $key ) ) {
					return "overlaps the allowed network {$cidr}";
				}
			} elseif ( Sky_Sentinel_Network::in_cidr( $key, $cidr ) ) {
				return "inside the allowed network {$cidr}";
			}
		}
		foreach ( $members as $ip ) {
			if ( in_array( Sky_Sentinel_Network::prefix_of( $ip ), $admin_prefixes, true ) ) {
				return 'an administrator has logged in from ' . Sky_Sentinel_Network::prefix_of( $ip );
			}
		}
		return null;
	}

	/**
	 * The last $days days, newest first, with zero rows for days that had no
	 * failures and nothing for days before counting began.
	 *
	 * @return array<string,array> date => day()
	 */
	public static function recent( array $tally, int $now, int $days = 7 ): array {
		$out   = array();
		$since = (string) ( $tally['since'] ?? gmdate( 'Y-m-d', $now ) );
		for ( $i = 0; $i < $days; $i++ ) {
			$date = gmdate( 'Y-m-d', $now - $i * 86400 );
			if ( $date < $since ) {
				break;
			}
			$out[ $date ] = self::day( $tally, $date );
		}
		return $out;
	}

	/**
	 * L13: yesterday had no failed logins at all, after a full week that
	 * averaged QUIET_FLOOR or more a day. MEDIUM: it is a change to explain,
	 * not an attack. The likely answers are an upstream block (good) or
	 * Sentinel no longer hearing failures (bad), and the summary says how to
	 * tell them apart.
	 */
	public static function went_quiet( array $tally, int $now ): ?Sky_Sentinel_Finding {
		$yesterday = gmdate( 'Y-m-d', $now - 86400 );
		$first     = gmdate( 'Y-m-d', $now - 8 * 86400 );
		if ( (string) ( $tally['since'] ?? $yesterday ) > $first ) {
			return null; // not counting for a full week before yesterday yet
		}
		if ( 0 !== self::day( $tally, $yesterday )['total'] ) {
			return null;
		}
		$sum = 0;
		for ( $i = 2; $i <= 8; $i++ ) {
			$sum += self::day( $tally, gmdate( 'Y-m-d', $now - $i * 86400 ) )['total'];
		}
		$avg = $sum / 7;
		if ( $avg < self::QUIET_FLOOR ) {
			return null;
		}
		return new Sky_Sentinel_Finding( 'L13', 'medium', "logins-quiet:{$yesterday}", sprintf( 'No failed logins on %s (UTC), after an average of %d a day the week before. Either something upstream now blocks attempts before WordPress, or Sentinel stopped hearing them: fail a login ten times with a made-up username and see whether L7 fires.', $yesterday, (int) round( $avg ) ), array( 'date' => $yesterday, 'week_average' => round( $avg, 1 ) ) );
	}

	/** One line per day for the digest. */
	public static function digest_lines( array $tally, int $now ): array {
		if ( empty( $tally['since'] ) ) {
			return array( 'Failed logins: none counted since this version was installed.' );
		}
		$rows = self::recent( $tally, $now, 7 );
		$lines = array( 'Failed logins by day (UTC; L7 fires at 10 from one address in 10 minutes):' );
		foreach ( $rows as $date => $d ) {
			$lines[] = sprintf( '  %s  %5d from %s address%s%s', $date, $d['total'], $d['distinct'] . ( $d['capped'] ? '+' : '' ), 1 === $d['distinct'] ? '' : 'es', $d['top_count'] ? sprintf( ', busiest %s (%d)', $d['top_ip'], $d['top_count'] ) : '' );
		}
		$lines[] = '  Counting since ' . $tally['since'] . '.';
		return $lines;
	}

	private static function summary_of( array $day ): array {
		$ips = (array) ( $day['ips'] ?? array() );
		arsort( $ips );
		$top = (string) ( array_key_first( $ips ) ?? '' );
		return array(
			'total'     => (int) ( $day['total'] ?? 0 ),
			'distinct'  => count( $ips ),
			'capped'    => (bool) ( $day['capped'] ?? false ),
			'top_ip'    => $top,
			'top_count' => '' === $top ? 0 : (int) $ips[ $top ],
		);
	}
}
