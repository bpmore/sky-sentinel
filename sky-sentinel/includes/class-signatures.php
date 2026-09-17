<?php
/**
 * Everything the detectors compare against, loaded from JSON so it can be
 * updated without a code deploy when a host or another scanner reports a new
 * variant.
 *
 * No WordPress. The three files under signatures/ are the defaults; a copy
 * uploaded through the settings page (stored in sitemeta) overrides each one
 * wholesale, and the version string on the settings page tells you which is
 * in force.
 */
final class Sky_Sentinel_Signatures {

	private array $hashes;
	private array $known_clean;
	private array $iocs;
	private array $allow;
	private string $hash_version;

	public function __construct( array $hashes, array $iocs, array $allow ) {
		$this->hash_version = (string) ( $hashes['version'] ?? '?' );
		$this->hashes      = array_change_key_case( $hashes['hashes'] ?? array(), CASE_LOWER );
		$this->known_clean = array_change_key_case( $hashes['known_clean'] ?? array(), CASE_LOWER );
		$this->iocs        = $iocs;
		$this->allow       = $allow;
	}

	public const FILES = array( 'hashes' => 'known-bad-hashes.json', 'iocs' => 'iocs.json', 'allowlist' => 'allowlist.json' );

	/**
	 * The shipped files, each replaced WHOLE by an override when one is
	 * given. Whole, not merged: a merge would let a stale shipped entry
	 * survive an update that meant to remove it, and the version string on
	 * the settings page would then describe neither file.
	 *
	 * @param array<string,array> $overrides  hashes|iocs|allowlist => decoded JSON
	 */
	public static function from_directory( string $dir, array $overrides = array() ): self {
		$load = fn( string $key ) => is_array( $overrides[ $key ] ?? null ) ? $overrides[ $key ] : self::read_json( $dir . '/' . self::FILES[ $key ] );
		return new self( $load( 'hashes' ), $load( 'iocs' ), $load( 'allowlist' ) );
	}

	/**
	 * Is this JSON an acceptable replacement for one of the three files?
	 * Returns null when it is, else the reason. Checked before anything is
	 * stored: a signature file that parses to the wrong shape makes every
	 * hash check pass.
	 */
	public static function validate_override( string $key, $decoded ): ?string {
		if ( ! is_array( $decoded ) ) {
			return 'not a JSON object';
		}
		if ( empty( $decoded['version'] ) || ! is_string( $decoded['version'] ) ) {
			return 'missing a "version" string';
		}
		switch ( $key ) {
			case 'hashes':
				if ( ! isset( $decoded['hashes'] ) || ! is_array( $decoded['hashes'] ) ) {
					return 'missing the "hashes" map';
				}
				foreach ( $decoded['hashes'] as $h => $name ) {
					if ( ! preg_match( '/^[0-9a-f]{64}$/i', (string) $h ) ) {
						return "not a sha256: {$h}";
					}
				}
				return null;
			case 'iocs':
				foreach ( array( 'strings', 'rpc_hosts', 'attacker_ips', 'tooling_user_agents' ) as $k ) {
					if ( ! isset( $decoded[ $k ] ) || ! is_array( $decoded[ $k ] ) ) {
						return "missing the \"{$k}\" list";
					}
				}
				foreach ( (array) ( $decoded['contract_regex'] ?? array() ) as $re ) {
					// The @ does not silence PCRE's compile warning under a test
					// harness that turns warnings into failures; a handler does.
					set_error_handler( fn() => true );
					$ok = preg_match( '/' . $re . '/', '' );
					restore_error_handler();
					if ( false === $ok ) {
						return "bad regex in contract_regex: {$re}";
					}
				}
				return null;
			case 'allowlist':
				foreach ( $decoded as $k => $v ) {
					if ( str_starts_with( (string) $k, '_' ) || 'version' === $k ) {
						continue;
					}
					if ( ! is_array( $v ) ) {
						return "\"{$k}\" is not a list";
					}
				}
				return null;
		}
		return "unknown signature file: {$key}";
	}

	/** Refuses silently-empty JSON: a signature file that fails to parse would make every hash check pass. */
	public static function read_json( string $file ): array {
		if ( ! is_readable( $file ) ) {
			throw new RuntimeException( "Signature file missing: {$file}" );
		}
		$data = json_decode( (string) file_get_contents( $file ), true );
		if ( ! is_array( $data ) ) {
			throw new RuntimeException( "Signature file is not valid JSON: {$file}" );
		}
		return $data;
	}

	public function version(): string {
		return sprintf(
			'hashes %s / iocs %s / allowlist %s',
			$this->hash_version,
			$this->iocs['version'] ?? '?',
			$this->allow['version'] ?? '?'
		);
	}

	public function known_bad( string $sha256 ): ?string {
		return $this->hashes[ strtolower( $sha256 ) ] ?? null;
	}

	public function known_clean( string $sha256 ): ?string {
		return $this->known_clean[ strtolower( $sha256 ) ] ?? null;
	}

	/** @return string[] */
	public function ioc_strings(): array {
		return array_values( array_filter( array_map( 'strval', $this->iocs['strings'] ?? array() ) ) );
	}

	/** @return string[] regex bodies, no delimiters */
	public function ioc_contract_patterns(): array {
		return $this->iocs['contract_regex'] ?? array();
	}

	/** @return string[] */
	public function rpc_hosts(): array {
		return $this->iocs['rpc_hosts'] ?? array();
	}

	/** @return string[] */
	public function attacker_ips(): array {
		return $this->iocs['attacker_ips'] ?? array();
	}

	/** @return string[] */
	public function tooling_user_agents(): array {
		return $this->iocs['tooling_user_agents'] ?? array();
	}

	/**
	 * Is this path excused from one detector?
	 *
	 * Fragments, not globs: "plugins/wordfence/" excuses everything under it and
	 * nothing else. The path is compared with forward slashes, case-folded,
	 * relative to wp-content, so a Windows-cased fixture and the live host agree.
	 */
	public function allowed( string $list, string $rel_path ): bool {
		$path = strtolower( str_replace( '\\', '/', $rel_path ) );
		foreach ( (array) ( $this->allow[ $list ] ?? array() ) as $fragment ) {
			$fragment = strtolower( (string) $fragment );
			if ( '' !== $fragment && str_contains( $path, $fragment ) ) {
				return true;
			}
		}
		return false;
	}

	/** @return string[] */
	public function allow_list( string $list ): array {
		return (array) ( $this->allow[ $list ] ?? array() );
	}
}
