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
 *            [ 'Y-m-d' => [ total, distinct, capped, top_ip, top_count ] ]  older, compacted
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
				$tally['days'][ $date ] = self::summary_of( $day );
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
		return isset( $day['ips'] ) ? self::summary_of( $day ) : $day;
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
