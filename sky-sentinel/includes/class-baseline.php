<?php
/**
 * The signed record of what "clean" looked like.
 *
 * A baseline is a manifest (every file's sha256 plus the inventories that
 * matter: plugin and theme directories, administrators, active plugins, the
 * active theme) and an HMAC over it keyed by SKY_SENTINEL_KEY from
 * wp-config.php. The key is not in the database on purpose: this campaign
 * operates with valid administrator credentials, which means it has the
 * database, and a baseline it could re-sign is a baseline that says whatever
 * it wants.
 *
 * Pure. Storage is the caller's problem (the plugin writes it to the DB and,
 * when it can, to ../private/ off the webroot, because the site's own backup
 * zeroed file mtimes and lost a day of logs, and the record of what was clean
 * must not share that fate).
 */
final class Sky_Sentinel_Baseline {

	public const VERSION = 1;

	/**
	 * @param array<string,string> $files      rel_path => sha256
	 * @param string[]             $packages   plugin/theme directory names, e.g. plugins/akismet
	 * @param array                $inventory  admins, active_plugins, template, stylesheet, site_admins
	 */
	public static function build( array $files, array $packages, array $inventory, string $signed_by, int $signed_at ): array {
		ksort( $files );
		sort( $packages );
		ksort( $inventory );
		return array(
			'version'   => self::VERSION,
			'signed_at' => $signed_at,
			'signed_by' => $signed_by,
			'files'     => $files,
			'packages'  => array_values( $packages ),
			'inventory' => $inventory,
		);
	}

	/** Deterministic bytes to sign: sorted keys, no whitespace, slashes unescaped. */
	public static function canonical( array $manifest ): string {
		self::ksort_recursive( $manifest );
		return (string) json_encode( $manifest, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );
	}

	public static function sign( array $manifest, string $key ): string {
		if ( strlen( $key ) < 32 ) {
			throw new InvalidArgumentException( 'SKY_SENTINEL_KEY must be at least 32 characters' );
		}
		return hash_hmac( 'sha256', self::canonical( $manifest ), $key );
	}

	public static function verify( array $manifest, string $signature, string $key ): bool {
		if ( strlen( $key ) < 32 || ! preg_match( '/^[0-9a-f]{64}$/', $signature ) ) {
			return false;
		}
		return hash_equals( self::sign( $manifest, $key ), $signature );
	}

	private static function ksort_recursive( array &$a ): void {
		foreach ( $a as &$v ) {
			if ( is_array( $v ) ) {
				self::ksort_recursive( $v );
			}
		}
		unset( $v );
		// Lists stay lists; only maps are sorted. array_is_list keeps a
		// packages array from being turned into an object by json_encode.
		if ( ! array_is_list( $a ) ) {
			ksort( $a );
		}
	}
}
