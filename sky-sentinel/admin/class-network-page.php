<?php
/**
 * Network Admin -> Sentinel.
 *
 * One page for the whole network, on purpose: findings carry a blog_id, and
 * a per-site menu would give eighteen sites eighteen places to not look.
 *
 * Every write goes through admin-post with a nonce and manage_network. The
 * baseline signature requires typing the site's hostname, because "re-sign
 * baseline" is the one button that can make a live dropper look like it
 * belongs, and a confirm() is not a decision.
 */
final class Sky_Sentinel_Network_Page {

	private Sky_Sentinel_Findings $findings;
	private Sky_Sentinel_Alerts $alerts;
	private Sky_Sentinel_Runner $runner;
	private Sky_Sentinel_Signatures $sig;

	public function __construct( Sky_Sentinel_Findings $findings, Sky_Sentinel_Alerts $alerts, Sky_Sentinel_Runner $runner, Sky_Sentinel_Signatures $sig ) {
		$this->findings = $findings;
		$this->alerts   = $alerts;
		$this->runner   = $runner;
		$this->sig      = $sig;

		// One page per install. On a network it is a Network Admin page; on a
		// single site the same page under the ordinary admin menu.
		add_action( is_multisite() ? 'network_admin_menu' : 'admin_menu', array( $this, 'menu' ) );
		add_action( is_multisite() ? 'network_admin_notices' : 'admin_notices', array( $this, 'notice' ) );
		add_action( 'admin_post_sky_sentinel_finding', array( $this, 'act_on_finding' ) );
		add_action( 'admin_post_sky_sentinel_settings', array( $this, 'save_settings' ) );
		add_action( 'admin_post_sky_sentinel_test_alert', array( $this, 'test_alert' ) );
		add_action( 'admin_post_sky_sentinel_sign', array( $this, 'sign_baseline' ) );
		add_action( 'wp_ajax_sky_sentinel_step', array( $this, 'ajax_step' ) );
		add_action( 'admin_post_sky_sentinel_export', array( $this, 'export' ) );
		add_action( 'admin_post_sky_sentinel_evidence', array( $this, 'evidence' ) );
		add_action( 'admin_post_sky_sentinel_signatures', array( $this, 'signatures' ) );
	}

	/** Replace one of the three signature files from a pasted JSON document, or reset it to the shipped one. */
	public function signatures(): void {
		$this->guard( 'sky_sentinel_signatures' );
		$key = sanitize_key( $_POST['which'] ?? '' );
		if ( ! isset( Sky_Sentinel_Signatures::FILES[ $key ] ) ) {
			$this->back( 'settings', 'Unknown signature file.' );
		}
		$stored = (array) get_site_option( 'sky_sentinel_signature_overrides', array() );
		if ( ! empty( $_POST['reset'] ) ) {
			unset( $stored[ $key ] );
			update_site_option( 'sky_sentinel_signature_overrides', $stored );
			$this->findings->event( 'signatures.reset', 0, get_current_user_id(), null, array( 'file' => $key ) );
			$this->back( 'settings', Sky_Sentinel_Signatures::FILES[ $key ] . ' reset to the shipped copy.' );
		}
		$json    = (string) wp_unslash( $_POST['json'] ?? '' );
		$decoded = json_decode( $json, true );
		$why     = Sky_Sentinel_Signatures::validate_override( $key, $decoded );
		if ( null !== $why ) {
			$this->back( 'settings', 'Not applied: ' . $why . '.' );
		}
		$stored[ $key ] = wp_json_encode( $decoded );
		update_site_option( 'sky_sentinel_signature_overrides', $stored );
		$this->findings->event( 'signatures.updated', 0, get_current_user_id(), null, array( 'file' => $key, 'version' => $decoded['version'] ) );
		$this->back( 'settings', Sky_Sentinel_Signatures::FILES[ $key ] . ' now at version ' . $decoded['version'] . '. Takes effect on the next scan.' );
	}

	/**
	 * Download one finding's evidence copy. The evidence directory is beside
	 * the webroot on purpose, which also puts it out of reach of an FTP
	 * account that lands in public/. This is the door. Served as a plain
	 * download with the .quarantined suffix kept, so nothing on the way
	 * mistakes it for an image or a script.
	 */
	public function evidence(): void {
		$this->guard( 'sky_sentinel_evidence' );
		$row = $this->findings->get( (int) ( $_GET['id'] ?? 0 ) );
		if ( ! $row || empty( $row->evidence ) || ! is_file( $row->evidence ) ) {
			wp_die( 'No evidence copy for that finding.' );
		}
		// Only ever a file Sentinel itself wrote, under its own evidence dir.
		$dir = realpath( Sky_Sentinel::data_dir() . '/evidence' );
		$abs = realpath( $row->evidence );
		if ( false === $dir || false === $abs || ! str_starts_with( $abs, $dir . DIRECTORY_SEPARATOR ) ) {
			wp_die( 'That path is not in the evidence directory.' );
		}
		$this->findings->event( 'evidence.downloaded', 0, get_current_user_id(), null, array( 'finding' => (int) $row->id, 'file' => basename( $abs ) ) );
		nocache_headers();
		header( 'Content-Type: application/octet-stream' );
		header( 'Content-Disposition: attachment; filename="' . basename( $abs ) . '"' );
		header( 'Content-Length: ' . (string) filesize( $abs ) );
		header( 'X-Content-Type-Options: nosniff' );
		readfile( $abs );
		exit;
	}

	/**
	 * Findings as a file. CSV for a spreadsheet, JSON for the next tool.
	 * Read-only, nonce-guarded, and it carries everything the table shows
	 * plus the detail and the evidence path, so the download IS the record.
	 */
	public function export(): void {
		$this->guard( 'sky_sentinel_export' );
		$status = sanitize_key( $_GET['status'] ?? 'all' );
		$format = 'json' === sanitize_key( $_GET['format'] ?? 'csv' ) ? 'json' : 'csv';
		$rows   = $this->findings->list( $status, 5000, sanitize_key( $_GET['sort'] ?? '' ), sanitize_key( $_GET['dir'] ?? '' ), sanitize_key( $_GET['detector'] ?? '' ) );
		$name   = sprintf( 'sentinel-%s-%s-%s.%s', sanitize_file_name( Sky_Sentinel::site_label() ), $status, gmdate( 'Ymd-His' ), $format );
		nocache_headers();
		header( 'Content-Disposition: attachment; filename="' . $name . '"' );
		if ( 'json' === $format ) {
			header( 'Content-Type: application/json; charset=utf-8' );
			$out = array();
			foreach ( $rows as $r ) {
				$r->detail = json_decode( (string) $r->detail, true );
				$out[]     = $r;
			}
			echo wp_json_encode( array(
				'site'       => Sky_Sentinel::site_label(),
				'exported'   => gmdate( 'c' ),
				'status'     => $status,
				'signatures' => $this->sig->version(),
				'last_run'   => get_site_option( Sky_Sentinel_Runner::LAST_RUN_OPTION ),
				'findings'   => $out,
			), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES );
			exit;
		}
		header( 'Content-Type: text/csv; charset=utf-8' );
		$h = fopen( 'php://output', 'w' );
		fputcsv( $h, array( 'severity', 'detector', 'status', 'blog_id', 'subject', 'summary', 'sha256', 'first_seen', 'last_seen', 'seen_count', 'alerted_at', 'note', 'evidence', 'detail' ) );
		foreach ( $rows as $r ) {
			fputcsv( $h, array( $r->severity, $r->detector, $r->status, $r->blog_id, $r->subject, $r->summary, $r->sha256, $r->first_seen, $r->last_seen, $r->seen_count, $r->alerted_at, $r->note, $r->evidence, $r->detail ) );
		}
		fclose( $h );
		exit;
	}

	public function menu(): void {
		$counts = $this->findings->open_counts();
		$badge  = $counts['critical'] + $counts['high'];
		$title  = 'Sentinel' . ( $badge ? sprintf( ' <span class="awaiting-mod">%d</span>', $badge ) : '' );
		add_menu_page( 'Sky Sentinel', $title, Sky_Sentinel::cap(), 'sky-sentinel', array( $this, 'render' ), 'dashicons-shield-alt', 3 );
	}

	/** While anything CRITICAL is open, every network-admin page says so. */
	public function notice(): void {
		if ( ! current_user_can( Sky_Sentinel::cap() ) ) {
			return;
		}
		$counts = $this->findings->open_counts();
		if ( $counts['critical'] > 0 ) {
			printf(
				'<div class="notice notice-error"><p><strong>Sky Sentinel:</strong> %d CRITICAL finding(s) are open. <a href="%s">Open Sentinel</a>. Do not delete anything before reading the runbook.</p></div>',
				(int) $counts['critical'],
				esc_url( Sky_Sentinel_Alerts::admin_url() )
			);
		}
		$baseline = $this->runner->baseline_status();
		if ( 'invalid' === $baseline['state'] ) {
			printf( '<div class="notice notice-error"><p><strong>Sky Sentinel:</strong> the stored baseline does not verify. Either SKY_SENTINEL_KEY changed or the baseline was altered. <a href="%s">Baseline</a></p></div>', esc_url( Sky_Sentinel_Alerts::admin_url() . '&tab=baseline' ) );
		}
	}

	public function render(): void {
		if ( ! current_user_can( Sky_Sentinel::cap() ) ) {
			wp_die( 'Not allowed.' );
		}
		$tab  = sanitize_key( $_GET['tab'] ?? 'dashboard' );
		$tabs = array( 'dashboard' => 'Dashboard', 'findings' => 'Findings', 'baseline' => 'Baseline', 'settings' => 'Alerts and settings', 'runbook' => 'Runbook' );
		if ( ! isset( $tabs[ $tab ] ) ) {
			$tab = 'dashboard';
		}
		$view = __DIR__ . "/views/{$tab}.php";
		$data = array(
			'tabs'     => $tabs,
			'tab'      => $tab,
			'counts'   => $this->findings->open_counts(),
			'last_run' => get_site_option( Sky_Sentinel_Runner::LAST_RUN_OPTION ),
			'baseline' => $this->runner->baseline_status(),
			'in_progress' => $this->runner->in_progress(),
			'state'    => $this->runner->state(),
			'notice'   => sanitize_text_field( wp_unslash( $_GET['sentinel_notice'] ?? '' ) ),
			'findings' => $this->findings,
			'alerts'   => $this->alerts,
			'runner'   => $this->runner,
			'sig'      => $this->sig,
			'site'     => Sky_Sentinel::site_label(),
		);
		require __DIR__ . '/views/shell.php';
	}

	public function act_on_finding(): void {
		$this->guard( 'sky_sentinel_finding' );
		// Back to the same tab and sort the button was pressed on, so
		// acknowledging a row does not throw away the view.
		list( $sort, $dir ) = Sky_Sentinel_Findings::sort_of( sanitize_key( $_POST['view_sort'] ?? '' ), sanitize_key( $_POST['view_dir'] ?? '' ) );
		$view_status = sanitize_key( $_POST['view_status'] ?? 'open' );
		$view = array(
			'status' => in_array( $view_status, array( 'open', 'acknowledged', 'muted', 'resolved', 'all' ), true ) ? $view_status : 'open',
			'sort'     => $sort,
			'dir'      => $dir,
			'detector' => Sky_Sentinel_Findings::detector_of( sanitize_key( $_POST['view_detector'] ?? '' ) ),
		);
		$status = sanitize_key( $_POST['status'] ?? '' );
		$note   = sanitize_textarea_field( wp_unslash( $_POST['note'] ?? '' ) );
		// One row, or the checked rows. A first scan of a large install produces
		// dozens of rows nobody should click through one at a time.
		$ids = isset( $_POST['ids'] ) ? array_map( 'intval', (array) $_POST['ids'] ) : array( (int) ( $_POST['id'] ?? 0 ) );
		$ids = array_values( array_filter( $ids ) );
		if ( ! $ids ) {
			$this->back( 'findings', 'Nothing selected.', $view );
		}
		if ( 'muted' === $status && '' === trim( $note ) ) {
			$this->back( 'findings', 'A mute needs a reason.', $view );
		}
		$n = 0;
		foreach ( $ids as $id ) {
			if ( $this->findings->set_status( $id, $status, get_current_user_id(), $note ) ) {
				$n++;
			}
		}
		$this->back( 'findings', "{$n} finding(s) marked {$status}.", $view );
	}

	public function save_settings(): void {
		$this->guard( 'sky_sentinel_settings' );
		$emails = array_filter( array_map( 'sanitize_email', preg_split( '/[\s,]+/', (string) wp_unslash( $_POST['recipients'] ?? '' ), -1, PREG_SPLIT_NO_EMPTY ) ) );
		update_site_option( 'sky_sentinel_recipients', array_values( $emails ) );
		if ( ! Sky_Sentinel_Alerts::locked( 'SKY_SENTINEL_WEBHOOK' ) ) {
			update_site_option( 'sky_sentinel_webhook', esc_url_raw( trim( (string) wp_unslash( $_POST['webhook'] ?? '' ) ) ) );
		}
		if ( ! Sky_Sentinel_Alerts::locked( 'SKY_SENTINEL_HEARTBEAT' ) ) {
			update_site_option( 'sky_sentinel_heartbeat', esc_url_raw( trim( (string) wp_unslash( $_POST['heartbeat'] ?? '' ) ) ) );
		}
		// Networks administrators are expected on. Validated as CIDRs; a bad
		// one is dropped rather than stored, because a stored typo would put
		// every staff login on the wrong side of the line.
		$cidrs = array();
		foreach ( preg_split( '/[\s,]+/', (string) wp_unslash( $_POST['cidrs'] ?? '' ), -1, PREG_SPLIT_NO_EMPTY ) as $c ) {
			if ( Sky_Sentinel_Network::in_cidr( explode( '/', $c )[0], $c ) ) {
				$cidrs[] = $c;
			}
		}
		update_site_option( 'sky_sentinel_network_cidrs', array_values( array_unique( $cidrs ) ) );
		update_site_option( 'sky_sentinel_block_user_enum', ! empty( $_POST['block_enum'] ) ? 1 : 0 );
		$this->findings->event( 'settings.saved', 0, get_current_user_id() );
		$this->back( 'settings', 'Saved.' );
	}

	public function test_alert(): void {
		$this->guard( 'sky_sentinel_test_alert' );
		$r = $this->alerts->test();
		$this->back( 'settings', sprintf( 'Test sent. Email: %s. Webhook: %s. Heartbeat: %s.', $r['email'] ? 'ok' : 'FAILED or unconfigured', $r['webhook'] ? 'ok' : 'FAILED or unconfigured', $r['heartbeat'] ? 'ok' : 'FAILED or unconfigured' ) );
	}

	public function sign_baseline(): void {
		$this->guard( 'sky_sentinel_sign' );
		$typed = trim( (string) wp_unslash( $_POST['confirm'] ?? '' ) );
		if ( $typed !== Sky_Sentinel::site_label() ) {
			$this->back( 'baseline', 'Type the site hostname exactly to sign.' );
		}
		$r = $this->runner->sign_baseline( get_current_user_id() );
		$this->back( 'baseline', $r['ok'] ? "Baseline signed over {$r['files']} files." : $r['why'] );
	}

	/**
	 * "Scan now": the browser calls this in a loop, each call does up to five
	 * seconds of walking and reports progress. The same runner the cron uses,
	 * so a manual scan and a scheduled one cannot disagree.
	 */
	public function ajax_step(): void {
		check_ajax_referer( 'sky_sentinel_step', 'nonce' );
		if ( ! current_user_can( Sky_Sentinel::cap() ) ) {
			wp_send_json_error( 'Not allowed.', 403 );
		}
		if ( ! $this->runner->in_progress() ) {
			if ( ! empty( $_POST['start'] ) ) {
				$this->runner->start( 'manual:' . wp_get_current_user()->user_login );
			} else {
				wp_send_json_success( array( 'done' => true, 'idle' => true ) );
			}
		}
		wp_send_json_success( $this->runner->step( 5 ) );
	}

	private function guard( string $action ): void {
		if ( ! current_user_can( Sky_Sentinel::cap() ) ) {
			wp_die( 'Not allowed.' );
		}
		check_admin_referer( $action );
	}

	private function back( string $tab, string $notice, array $view = array() ): never {
		wp_safe_redirect( add_query_arg( array( 'tab' => $tab, 'sentinel_notice' => rawurlencode( $notice ) ) + $view, Sky_Sentinel_Alerts::admin_url() ) );
		exit;
	}
}
