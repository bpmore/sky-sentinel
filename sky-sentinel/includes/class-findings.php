<?php
/**
 * The findings store: what Sentinel has seen, when, and what a human did
 * about it.
 *
 * One row per fingerprint. Seeing the same thing twice bumps last_seen and
 * the count; it never re-alerts, because the second alert about the same
 * dropper teaches nobody anything and the fortieth trains people to delete
 * the emails. Acknowledged findings stay quiet until their hash changes, and
 * resolved ones are kept for the record.
 *
 * Evidence: a CRITICAL or HIGH file finding gets a copy of the file, with a
 * .quarantined suffix and no execute bit, in the evidence directory. The
 * original is not touched. Cleanup decisions stay with a human and the
 * runbook; Sentinel's job is to make sure the evidence still exists when
 * that human arrives.
 */
final class Sky_Sentinel_Findings {

	public const TABLE = 'sentinel_findings';
	public const EVENTS = 'sentinel_events';

	private wpdb $db;
	private string $table;
	private string $events;
	private string $evidence_dir;

	public function __construct( wpdb $db, string $evidence_dir ) {
		$this->db           = $db;
		$this->table        = $db->base_prefix . self::TABLE;
		$this->events       = $db->base_prefix . self::EVENTS;
		$this->evidence_dir = rtrim( $evidence_dir, '/' );
	}

	public function install(): void {
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		$charset = $this->db->get_charset_collate();
		dbDelta( "CREATE TABLE {$this->table} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			fingerprint char(64) NOT NULL,
			detector varchar(8) NOT NULL,
			severity varchar(10) NOT NULL,
			blog_id bigint(20) unsigned NOT NULL DEFAULT 0,
			subject varchar(1024) NOT NULL,
			summary text NOT NULL,
			detail longtext NULL,
			sha256 char(64) NULL,
			status varchar(12) NOT NULL DEFAULT 'open',
			seen_count int unsigned NOT NULL DEFAULT 1,
			first_seen datetime NOT NULL,
			last_seen datetime NOT NULL,
			alerted_at datetime NULL,
			acted_by bigint(20) unsigned NULL,
			acted_at datetime NULL,
			note text NULL,
			evidence varchar(1024) NULL,
			PRIMARY KEY  (id),
			UNIQUE KEY fingerprint (fingerprint),
			KEY status_severity (status, severity),
			KEY last_seen (last_seen)
		) {$charset};" );
		dbDelta( "CREATE TABLE {$this->events} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			at datetime NOT NULL,
			kind varchar(32) NOT NULL,
			blog_id bigint(20) unsigned NOT NULL DEFAULT 0,
			user_id bigint(20) unsigned NULL,
			ip varchar(45) NULL,
			detail longtext NULL,
			PRIMARY KEY  (id),
			KEY at (at),
			KEY kind (kind)
		) {$charset};" );
	}

	/**
	 * Record what a run found. Returns the findings that are NEW at HIGH or
	 * above, which is exactly the set that should alert now.
	 *
	 * @param Sky_Sentinel_Finding[] $findings
	 * @return Sky_Sentinel_Finding[]
	 */
	public function record( array $findings, string $scan_root ): array {
		$now      = current_time( 'mysql', true );
		$to_alert = array();
		foreach ( $findings as $f ) {
			$fp  = $f->fingerprint();
			$row = $this->db->get_row( $this->db->prepare( "SELECT id, status, severity FROM {$this->table} WHERE fingerprint = %s", $fp ) );
			if ( $row ) {
				// The severity and wording are the detector's CURRENT opinion.
				// A rule that is downgraded after deployment must downgrade the
				// rows it already produced, or the table keeps saying HIGH.
				$this->db->query( $this->db->prepare( "UPDATE {$this->table} SET last_seen = %s, seen_count = seen_count + 1, severity = %s, summary = %s WHERE id = %d", $now, $f->severity, $f->summary, $row->id ) );
				// A resolved finding that comes back is a new event: the
				// artifact was removed and re-planted. Reopen and alert.
				if ( 'resolved' === $row->status ) {
					$this->db->query( $this->db->prepare( "UPDATE {$this->table} SET status = 'open', alerted_at = NULL, note = CONCAT(COALESCE(note, ''), %s) WHERE id = %d", "\nReturned {$now} after being resolved.", $row->id ) );
					if ( $f->is_at_least( 'high' ) ) {
						$to_alert[] = $f;
					}
				}
				continue;
			}
			$evidence = null;
			if ( $f->is_at_least( 'high' ) && $this->looks_like_a_path( $f->subject ) ) {
				$evidence = $this->preserve( $scan_root . '/' . $f->subject, $fp );
			}
			$this->db->insert( $this->table, array(
				'fingerprint' => $fp,
				'detector'    => $f->detector,
				'severity'    => $f->severity,
				'blog_id'     => $f->blog_id,
				'subject'     => mb_substr( $f->subject, 0, 1024 ),
				'summary'     => $f->summary,
				'detail'      => wp_json_encode( $f->detail ),
				'sha256'      => $f->sha256,
				'status'      => 'open',
				'seen_count'  => 1,
				'first_seen'  => $now,
				'last_seen'   => $now,
				'evidence'    => $evidence,
			) );
			if ( $f->is_at_least( 'high' ) ) {
				$to_alert[] = $f;
			}
		}
		return $to_alert;
	}

	public function mark_alerted( array $findings ): void {
		$now = current_time( 'mysql', true );
		foreach ( $findings as $f ) {
			$this->db->query( $this->db->prepare( "UPDATE {$this->table} SET alerted_at = %s WHERE fingerprint = %s", $now, $f->fingerprint() ) );
		}
	}

	/** open | acknowledged | resolved | muted */
	public function set_status( int $id, string $status, int $user_id, string $note ): bool {
		if ( ! in_array( $status, array( 'open', 'acknowledged', 'resolved', 'muted' ), true ) ) {
			return false;
		}
		$ok = $this->db->update( $this->table, array(
			'status'   => $status,
			'acted_by' => $user_id,
			'acted_at' => current_time( 'mysql', true ),
			'note'     => $note,
		), array( 'id' => $id ) );
		$this->event( 'finding.' . $status, 0, $user_id, null, array( 'finding' => $id, 'note' => $note ) );
		return false !== $ok;
	}

	public function open_counts(): array {
		$rows = $this->db->get_results( "SELECT severity, COUNT(*) AS n FROM {$this->table} WHERE status = 'open' GROUP BY severity" );
		$out  = array( 'critical' => 0, 'high' => 0, 'medium' => 0, 'info' => 0 );
		foreach ( (array) $rows as $r ) {
			$out[ $r->severity ] = (int) $r->n;
		}
		return $out;
	}

	/**
	 * Columns the Findings table can be sorted by, each with the direction a
	 * first click should give (the one you usually want: critical first, most
	 * seen first, newest first, A to Z for text). Only these ever reach SQL.
	 */
	public const SORTS = array(
		'severity'   => 'desc',
		'detector'   => 'asc',
		'site'       => 'asc',
		'subject'    => 'asc',
		'status'     => 'asc',
		'first_seen' => 'desc',
		'last_seen'  => 'desc',
		'seen'       => 'desc',
	);

	/** A requested sort, made safe: an unknown column is severity, an unknown direction is that column's default. */
	public static function sort_of( string $sort, string $dir ): array {
		$sort = isset( self::SORTS[ $sort ] ) ? $sort : 'severity';
		$dir  = strtolower( $dir );
		return array( $sort, in_array( $dir, array( 'asc', 'desc' ), true ) ? $dir : self::SORTS[ $sort ] );
	}

	/**
	 * The ORDER BY for a sort. Built only from SORTS and two literal
	 * directions, never from the request. Detectors sort naturally (F2 before
	 * F10, D10 after D9); ties fall back to severity, then most recent, then
	 * id, so a page never shuffles between loads.
	 */
	public static function order_by( string $sort, string $dir ): string {
		list( $sort, $dir ) = self::sort_of( $sort, $dir );
		$d    = 'asc' === $dir ? 'ASC' : 'DESC';
		$cols = array(
			'severity'   => "FIELD(severity,'info','medium','high','critical') {$d}",
			'detector'   => "LEFT(detector,1) {$d}, CAST(SUBSTRING(detector,2) AS UNSIGNED) {$d}, detector {$d}",
			'site'       => "blog_id {$d}",
			'subject'    => "subject {$d}",
			'status'     => "FIELD(status,'open','acknowledged','muted','resolved') {$d}",
			'first_seen' => "first_seen {$d}",
			'last_seen'  => "last_seen {$d}",
			'seen'       => "seen_count {$d}",
		);
		return 'ORDER BY ' . $cols[ $sort ] . ", FIELD(severity,'critical','high','medium','info'), last_seen DESC, id DESC";
	}

	/**
	 * A detector id from the request, or '' for every detector. Ids are
	 * letters then digits (F18, L10, D5, P0, SCAN); anything else is ''.
	 */
	public static function detector_of( string $detector ): string {
		$detector = strtoupper( trim( $detector ) );
		return preg_match( '/^[A-Z]{1,6}[0-9]{0,3}$/', $detector ) ? $detector : '';
	}

	/**
	 * @param string $detector '' for all, else one detector id (see detector_of()).
	 */
	public function list( string $status = 'open', int $limit = 200, string $sort = 'severity', string $dir = '', string $detector = '' ): array {
		$where = array();
		$args  = array();
		if ( 'all' !== $status ) {
			$where[] = 'status = %s';
			$args[]  = $status;
		}
		$detector = self::detector_of( $detector );
		if ( '' !== $detector ) {
			$where[] = 'detector = %s';
			$args[]  = $detector;
		}
		$args[] = $limit;
		$sql    = "SELECT * FROM {$this->table}" . ( $where ? ' WHERE ' . implode( ' AND ', $where ) : '' ) . ' ' . self::order_by( $sort, $dir ) . ' LIMIT %d';
		return (array) $this->db->get_results( $this->db->prepare( $sql, ...$args ) );
	}

	/**
	 * How many findings each detector has in a status, detectors in natural
	 * order (F2 before F10), for the Findings tab's filter.
	 *
	 * @return array<string,int>
	 */
	public function detector_counts( string $status ): array {
		$where = 'all' === $status ? '' : $this->db->prepare( ' WHERE status = %s', $status );
		$rows  = (array) $this->db->get_results( "SELECT detector, COUNT(*) AS n FROM {$this->table}{$where} GROUP BY detector ORDER BY LEFT(detector,1), CAST(SUBSTRING(detector,2) AS UNSIGNED), detector" );
		$out   = array();
		foreach ( $rows as $r ) {
			$out[ (string) $r->detector ] = (int) $r->n;
		}
		return $out;
	}

	public function get( int $id ): ?object {
		return $this->db->get_row( $this->db->prepare( "SELECT * FROM {$this->table} WHERE id = %d", $id ) ) ?: null;
	}

	public function event( string $kind, int $blog_id = 0, ?int $user_id = null, ?string $ip = null, array $detail = array() ): void {
		$this->db->insert( $this->events, array(
			'at'      => current_time( 'mysql', true ),
			'kind'    => $kind,
			'blog_id' => $blog_id,
			'user_id' => $user_id,
			'ip'      => $ip,
			'detail'  => wp_json_encode( $detail ),
		) );
	}

	public function recent_events( int $limit = 50 ): array {
		return (array) $this->db->get_results( $this->db->prepare( "SELECT * FROM {$this->events} ORDER BY at DESC LIMIT %d", $limit ) );
	}

	/**
	 * Copy a flagged file into the evidence directory. Renamed with a suffix
	 * PHP will not execute, and chmod 0400, because an evidence directory full
	 * of live droppers is a second infection waiting for a misconfiguration.
	 */
	private function preserve( string $abs, string $fingerprint ): ?string {
		if ( ! is_file( $abs ) || ! is_readable( $abs ) || filesize( $abs ) > 8388608 ) {
			return null;
		}
		if ( ! is_dir( $this->evidence_dir ) && ! wp_mkdir_p( $this->evidence_dir ) ) {
			return null;
		}
		// The evidence directory refuses to serve or execute anything, twice.
		foreach ( array( '.htaccess' => "Require all denied\nDeny from all\n<FilesMatch \".*\">\n  SetHandler none\n  php_flag engine off\n</FilesMatch>\n", 'index.html' => '' ) as $name => $body ) {
			if ( ! file_exists( $this->evidence_dir . '/' . $name ) ) {
				@file_put_contents( $this->evidence_dir . '/' . $name, $body );
			}
		}
		$dest = $this->evidence_dir . '/' . substr( $fingerprint, 0, 16 ) . '-' . basename( $abs ) . '.quarantined';
		if ( ! @copy( $abs, $dest ) ) {
			return null;
		}
		@chmod( $dest, 0400 );
		return $dest;
	}

	private function looks_like_a_path( string $subject ): bool {
		return ! str_contains( $subject, ':' ) && ! str_contains( $subject, '#' ) && ! str_starts_with( $subject, 'wp_' ) && '' !== $subject;
	}
}
