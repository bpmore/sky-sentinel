<?php
/**
 * How Sentinel reaches a person.
 *
 * Two channels, on purpose, and the second must not depend on WordPress mail
 * settings: an attacker holding wp-admin can read the SMTP credentials, so
 * an alert that only goes through wp_mail() is an alert the attacker can
 * silence. The webhook URL comes from a constant in wp-config.php and is
 * posted to with wp_remote_post, which does not touch the mail stack.
 *
 * The heartbeat is the third leg. It fires at the END of a completed run, so
 * a run that never completes never pings, and an external monitor that hears
 * nothing for two intervals raises the alarm itself. That is what covers
 * "the attacker deleted Sentinel", which no code inside Sentinel can.
 *
 * Every alert links the runbook. An alert with no next step is a worry, not a
 * tool.
 */
final class Sky_Sentinel_Alerts {

	private Sky_Sentinel_Findings $findings;
	private string $site_label;

	public function __construct( Sky_Sentinel_Findings $findings, string $site_label ) {
		$this->findings   = $findings;
		$this->site_label = $site_label;
	}

	/**
	 * A constant counts only when it holds something. The sample config file
	 * defines every constant as '' so the names are visible, and an empty
	 * define used to lock the settings field AND supply nothing: the first
	 * webhook URL pasted into wp-admin went nowhere with no error.
	 */
	public static function constant( string $name ): string {
		if ( ! defined( $name ) ) {
			return '';
		}
		$v = constant( $name );
		return is_string( $v ) ? trim( $v ) : '';
	}

	/** @return string[] */
	public static function recipients(): array {
		$list = array();
		if ( '' !== self::constant( 'SKY_SENTINEL_ALERT_TO' ) ) {
			$list = preg_split( '/[\s,]+/', self::constant( 'SKY_SENTINEL_ALERT_TO' ), -1, PREG_SPLIT_NO_EMPTY );
		}
		foreach ( (array) get_site_option( 'sky_sentinel_recipients', array() ) as $email ) {
			$list[] = $email;
		}
		return array_values( array_unique( array_filter( array_map( 'sanitize_email', $list ) ) ) );
	}

	public static function webhook_url(): string {
		$c = self::constant( 'SKY_SENTINEL_WEBHOOK' );
		return '' !== $c ? $c : trim( (string) get_site_option( 'sky_sentinel_webhook', '' ) );
	}

	public static function heartbeat_url(): string {
		$c = self::constant( 'SKY_SENTINEL_HEARTBEAT' );
		return '' !== $c ? $c : trim( (string) get_site_option( 'sky_sentinel_heartbeat', '' ) );
	}

	/** Whether the settings field is locked by a non-empty constant. */
	public static function locked( string $name ): bool {
		return '' !== self::constant( $name );
	}

	/**
	 * Alert on a batch of NEW findings at HIGH or above. Both channels, one
	 * message each, however many findings: forty emails about one scan is how
	 * a mailbox learns to filter Sentinel.
	 *
	 * @param Sky_Sentinel_Finding[] $findings
	 * @return array{email: bool, webhook: bool}
	 */
	public function send( array $findings ): array {
		if ( ! $findings ) {
			// Nothing to send is not "sent". The first dashboard read
			// "webhook ok" with no webhook configured because of this.
			return array( 'email' => 'nothing new', 'webhook' => 'nothing new' );
		}
		usort( $findings, fn( $a, $b ) => $b->rank() <=> $a->rank() );
		$top     = $findings[0];
		$subject = sprintf( '[Sky Sentinel] %s: %s - %s - %s', strtoupper( $top->severity ), $this->site_label, $top->detector, $this->short( $top->subject ) );
		if ( count( $findings ) > 1 ) {
			$subject .= sprintf( ' (+%d more)', count( $findings ) - 1 );
		}
		$body = $this->body( $findings );

		$email   = $this->email( $subject, $body );
		$webhook = $this->webhook( $subject, $findings );

		$this->findings->mark_alerted( $findings );
		$this->findings->event( 'alert.sent', 0, null, null, array( 'count' => count( $findings ), 'email' => $email, 'webhook' => $webhook ) );
		return array( 'email' => $email, 'webhook' => $webhook );
	}

	public function test(): array {
		$f = new Sky_Sentinel_Finding( 'TEST', 'high', 'sentinel/test', 'This is a test alert from the Sentinel settings page. Nothing was found.' );
		$subject = "[Sky Sentinel] TEST: {$this->site_label} - both channels";
		return array(
			'email'     => $this->email( $subject, $this->body( array( $f ) ) ),
			'webhook'   => $this->webhook( $subject, array( $f ) ),
			'heartbeat' => $this->heartbeat( 'test' ),
		);
	}

	private function email( string $subject, string $body ): bool {
		$to = self::recipients();
		if ( ! $to ) {
			return false;
		}
		return (bool) wp_mail( $to, $subject, $body, array( 'Content-Type: text/plain; charset=UTF-8' ) );
	}

	/**
	 * The webhook. Teams retired the Office 365 "Incoming Webhook" connector;
	 * the replacement is a Workflow ("Post to a channel when a webhook request
	 * is received"), whose URL lives on logic.azure.com and which accepts an
	 * Adaptive Card, not the old MessageCard. Slack's incoming webhooks read
	 * a plain "text" field. Both are built by payload(), which is pure and
	 * tested; this only posts it, with wp_remote_post, never the mail stack.
	 */
	private function webhook( string $subject, array $findings ): bool {
		$url = self::webhook_url();
		if ( '' === $url ) {
			return false;
		}
		if ( ! wp_http_validate_url( $url ) ) {
			$this->findings->event( 'webhook.failed', 0, null, null, array( 'error' => 'URL rejected by wp_http_validate_url: ' . substr( $url, 0, 60 ) . '...' ) );
			return false;
		}
		$r = wp_remote_post( $url, array(
			'timeout' => 10,
			'headers' => array( 'Content-Type' => 'application/json' ),
			'body'    => wp_json_encode( self::payload( $url, $subject, $findings, self::runbook_url(), self::admin_url() ) ),
		) );
		$ok = ! is_wp_error( $r ) && (int) wp_remote_retrieve_response_code( $r ) < 300;
		if ( ! $ok ) {
			$this->findings->event( 'webhook.failed', 0, null, null, array( 'error' => is_wp_error( $r ) ? $r->get_error_message() : wp_remote_retrieve_response_code( $r ) . ' ' . substr( (string) wp_remote_retrieve_body( $r ), 0, 200 ) ) );
		}
		return $ok;
	}

	/**
	 * Pure. Slack gets {text}; everything else gets a Teams Adaptive Card,
	 * which is what a Workflow webhook accepts.
	 *
	 * @param Sky_Sentinel_Finding[] $findings
	 */
	public static function payload( string $url, string $subject, array $findings, string $runbook, string $admin ): array {
		$host = strtolower( (string) parse_url( $url, PHP_URL_HOST ) );
		if ( str_contains( $host, 'slack.com' ) ) {
			$lines = array( "*{$subject}*" );
			foreach ( array_slice( $findings, 0, 10 ) as $f ) {
				$lines[] = strtoupper( $f->severity ) . " {$f->detector} `{$f->subject}`: {$f->summary}";
			}
			$lines[] = "Runbook: {$runbook}";
			return array( 'text' => implode( "\n", $lines ) );
		}
		$facts = array();
		foreach ( array_slice( $findings, 0, 10 ) as $f ) {
			$facts[] = array( 'title' => strtoupper( $f->severity ) . ' ' . $f->detector, 'value' => mb_substr( $f->subject, 0, 120 ) . ': ' . $f->summary );
		}
		$top = $findings[0] ?? null;
		return array(
			'type'        => 'message',
			'attachments' => array( array(
				'contentType' => 'application/vnd.microsoft.card.adaptive',
				'contentUrl'  => null,
				'content'     => array(
					'$schema' => 'http://adaptivecards.io/schemas/adaptive-card.json',
					'type'    => 'AdaptiveCard',
					'version' => '1.4',
					'msteams' => array( 'width' => 'Full' ),
					'body'    => array(
						array( 'type' => 'TextBlock', 'text' => $subject, 'weight' => 'Bolder', 'size' => 'Medium', 'wrap' => true, 'color' => $top && 'critical' === $top->severity ? 'Attention' : 'Warning' ),
						array( 'type' => 'TextBlock', 'text' => count( $findings ) . ' finding(s). Do not delete anything before reading the runbook.', 'wrap' => true ),
						array( 'type' => 'FactSet', 'facts' => $facts ),
					),
					'actions' => array(
						array( 'type' => 'Action.OpenUrl', 'title' => 'Open Sentinel', 'url' => $admin ),
						array( 'type' => 'Action.OpenUrl', 'title' => 'Runbook', 'url' => $runbook ),
					),
				),
			) ),
		);
	}

	/**
	 * Ping the external monitor. Called by the runner after a COMPLETE run and
	 * nowhere else. A failed ping is logged, not retried: the monitor's whole
	 * purpose is to notice silence.
	 */
	public function heartbeat( string $context = 'run' ): bool {
		$url = self::heartbeat_url();
		if ( '' === $url || ! wp_http_validate_url( $url ) ) {
			return false;
		}
		$counts = $this->findings->open_counts();
		$r = wp_remote_post( $url, array(
			'timeout' => 10,
			'headers' => array( 'Content-Type' => 'application/json' ),
			'body'    => wp_json_encode( array( 'site' => $this->site_label, 'context' => $context, 'open' => $counts, 'at' => gmdate( 'c' ) ) ),
		) );
		$ok = ! is_wp_error( $r ) && (int) wp_remote_retrieve_response_code( $r ) < 300;
		if ( ! $ok ) {
			$this->findings->event( 'heartbeat.failed', 0, null, null, array( 'error' => is_wp_error( $r ) ? $r->get_error_message() : wp_remote_retrieve_response_code( $r ) ) );
		}
		return $ok;
	}

	private function body( array $findings ): string {
		$lines = array(
			"Site: {$this->site_label}",
			'When: ' . gmdate( 'Y-m-d H:i:s' ) . ' UTC',
			'Findings: ' . count( $findings ),
			'',
			'DO NOT delete anything yet. Open the finding, download the evidence copy, then follow the runbook:',
			self::runbook_url(),
			'',
		);
		foreach ( $findings as $f ) {
			$lines[] = sprintf( '%s  %s  %s', str_pad( strtoupper( $f->severity ), 8 ), $f->detector, $f->subject );
			$lines[] = '  ' . $f->summary;
			if ( $f->sha256 ) {
				$lines[] = '  sha256 ' . $f->sha256;
			}
			foreach ( $f->detail as $k => $v ) {
				$lines[] = '  ' . $k . ': ' . ( is_scalar( $v ) ? $v : wp_json_encode( $v ) );
			}
			$lines[] = '';
		}
		$lines[] = 'Sentinel: ' . self::admin_url();
		return implode( "\n", $lines );
	}

	public static function admin_url(): string {
		return is_multisite() ? network_admin_url( 'admin.php?page=sky-sentinel' ) : admin_url( 'admin.php?page=sky-sentinel' );
	}

	public static function runbook_url(): string {
		return self::admin_url() . '&tab=runbook';
	}

	private function short( string $s, int $n = 60 ): string {
		return mb_strlen( $s ) > $n ? '...' . mb_substr( $s, -( $n - 3 ) ) : $s;
	}
}
