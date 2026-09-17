<?php
/**
 * The daily digest: everything MEDIUM and INFO that opened in the last day,
 * plus the counts, in one email at 07:00. The things worth knowing that are
 * not worth a page.
 */
final class Sky_Sentinel_Digest {

	private Sky_Sentinel_Findings $findings;
	private Sky_Sentinel_Alerts $alerts;

	public function __construct( Sky_Sentinel_Findings $findings, Sky_Sentinel_Alerts $alerts ) {
		$this->findings = $findings;
		$this->alerts   = $alerts;
	}

	public function send(): bool {
		global $wpdb;
		$since = gmdate( 'Y-m-d H:i:s', time() - DAY_IN_SECONDS );
		$rows  = (array) $wpdb->get_results( $wpdb->prepare( "SELECT severity, detector, subject, summary, blog_id, first_seen FROM {$wpdb->base_prefix}sentinel_findings WHERE status = 'open' AND first_seen >= %s ORDER BY FIELD(severity,'critical','high','medium','info'), first_seen DESC LIMIT 300", $since ) );
		$counts = $this->findings->open_counts();
		$last   = get_site_option( Sky_Sentinel_Runner::LAST_RUN_OPTION );
		$pages  = get_site_option( Sky_Sentinel_Runner::PAGES_LAST );
		$lines  = array(
			'Sky Sentinel daily digest for ' . Sky_Sentinel::site_label(),
			'',
			sprintf( 'Open now: %d critical, %d high, %d medium, %d info.', $counts['critical'], $counts['high'], $counts['medium'], $counts['info'] ),
			is_array( $last ) ? sprintf( 'Last file scan: %s, %d files, %d findings.', $last['at'], $last['files'], $last['findings'] ) : 'Last file scan: none recorded.',
			is_array( $pages ) ? sprintf( 'Last rendered-page pass: %s, %d pages.', $pages['at'], $pages['pages'] ) : 'Last rendered-page pass: none yet.',
			'',
			$rows ? 'Opened in the last 24 hours:' : 'Nothing new opened in the last 24 hours.',
		);
		foreach ( $rows as $r ) {
			$lines[] = sprintf( '%-8s %-4s %s', strtoupper( $r->severity ), $r->detector, $r->subject );
			$lines[] = '  ' . $r->summary;
		}
		$lines[] = '';
		$lines[] = 'Sentinel: ' . Sky_Sentinel_Alerts::admin_url();
		$to = Sky_Sentinel_Alerts::recipients();
		if ( ! $to ) {
			return false;
		}
		$ok = (bool) wp_mail( $to, '[Sky Sentinel] Daily digest: ' . Sky_Sentinel::site_label(), implode( "\n", $lines ), array( 'Content-Type: text/plain; charset=UTF-8' ) );
		$this->findings->event( 'digest.sent', 0, null, null, array( 'rows' => count( $rows ), 'ok' => $ok ) );
		return $ok;
	}
}
