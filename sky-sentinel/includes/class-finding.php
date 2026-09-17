<?php
/**
 * One thing Sentinel noticed.
 *
 * Plain data, no WordPress. Every detector returns these and nothing else, so
 * the detectors can be run against a directory on a laptop with no WordPress
 * install at all, which is how the infected backup gets scanned in the tests.
 *
 * The fingerprint is what stops one artifact alerting forever: the same
 * detector on the same path with the same bytes is the same finding, however
 * many times the scanner walks past it.
 */
final class Sky_Sentinel_Finding {

	public const CRITICAL = 'critical';
	public const HIGH     = 'high';
	public const MEDIUM   = 'medium';
	public const INFO     = 'info';

	public const SEVERITY_RANK = array(
		self::CRITICAL => 4,
		self::HIGH     => 3,
		self::MEDIUM   => 2,
		self::INFO     => 1,
	);

	public string $detector;
	public string $severity;
	/** File path relative to the scan root, a user login, an option name: whatever the detector looked at. */
	public string $subject;
	public string $summary;
	/** Free-form evidence: byte offset, matched text, counts. Never the whole file. */
	public array $detail;
	public ?string $sha256;
	public int $blog_id;

	public function __construct(
		string $detector,
		string $severity,
		string $subject,
		string $summary,
		array $detail = array(),
		?string $sha256 = null,
		int $blog_id = 0
	) {
		if ( ! isset( self::SEVERITY_RANK[ $severity ] ) ) {
			throw new InvalidArgumentException( "Unknown severity: {$severity}" );
		}
		$this->detector = $detector;
		$this->severity = $severity;
		$this->subject  = $subject;
		$this->summary  = $summary;
		$this->detail   = $detail;
		$this->sha256   = $sha256;
		$this->blog_id  = $blog_id;
	}

	public function fingerprint(): string {
		return hash( 'sha256', $this->detector . '|' . $this->subject . '|' . ( $this->sha256 ?? '' ) );
	}

	public function rank(): int {
		return self::SEVERITY_RANK[ $this->severity ];
	}

	public function is_at_least( string $severity ): bool {
		return $this->rank() >= self::SEVERITY_RANK[ $severity ];
	}

	public function to_array(): array {
		return array(
			'detector'    => $this->detector,
			'severity'    => $this->severity,
			'subject'     => $this->subject,
			'summary'     => $this->summary,
			'detail'      => $this->detail,
			'sha256'      => $this->sha256,
			'blog_id'     => $this->blog_id,
			'fingerprint' => $this->fingerprint(),
		);
	}
}
