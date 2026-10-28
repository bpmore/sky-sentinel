<?php
/**
 * Sentinel's data folder: can a scan use it?
 *
 * Every scan writes its manifest here before it walks a single file, and
 * evidence copies and the off-database baseline copy live here too. Until
 * 0.4.17 nothing checked the folder first, so a folder PHP could not write
 * to ended every scan in an uncaught exception: a white "critical error"
 * page from Scan now, and every scheduled scan dying silently. On one
 * install the folder had been created by root, mode 750, while PHP ran as
 * the site's own user.
 *
 * Pure apart from the filesystem: no WordPress. check() creates the folder
 * when it is missing, then proves it is writable by writing and removing a
 * probe file, because is_writable() can be wrong under ACLs and some
 * network filesystems. A failure is described in the terms a person fixes
 * it in: who owns the folder, its mode, and who PHP runs as.
 */
final class Sky_Sentinel_Data_Dir {

	/** What an under-the-web-root data folder gets so the web server refuses it. */
	public const DENY_FILES = array(
		'.htaccess'  => "Require all denied\nDeny from all\n",
		'index.html' => '',
	);

	/**
	 * @param string $dir     The data folder.
	 * @param bool   $protect True when the folder sits under the web root
	 *                        (the uploads fallback): write the deny files.
	 * @return array{ok: bool, path: string, problem: ?string}
	 */
	public static function check( string $dir, bool $protect = false ): array {
		$dir = rtrim( $dir, '/\\' );
		if ( ! is_dir( $dir ) && ! @mkdir( $dir, 0750, true ) && ! is_dir( $dir ) ) {
			return array( 'ok' => false, 'path' => $dir, 'problem' => 'it does not exist and could not be created (' . self::describe( dirname( $dir ) ) . ')' );
		}
		$probe = $dir . '/.sentinel-write-test-' . bin2hex( random_bytes( 4 ) );
		if ( false === @file_put_contents( $probe, '' ) ) {
			return array( 'ok' => false, 'path' => $dir, 'problem' => 'PHP cannot write to it (' . self::describe( $dir ) . ')' );
		}
		@unlink( $probe );
		if ( $protect ) {
			foreach ( self::DENY_FILES as $name => $body ) {
				if ( ! file_exists( "{$dir}/{$name}" ) ) {
					@file_put_contents( "{$dir}/{$name}", $body );
				}
			}
		}
		return array( 'ok' => true, 'path' => $dir, 'problem' => null );
	}

	/** "owned by root (uid 0), mode 0750; PHP runs as www-data (uid 33)", as far as the platform can say. */
	public static function describe( string $path ): string {
		$owner = @fileowner( $path );
		$perms = @fileperms( $path );
		$parts = array();
		if ( false !== $owner ) {
			$parts[] = 'owned by ' . self::user_name( $owner );
		}
		if ( false !== $perms ) {
			$parts[] = 'mode ' . sprintf( '%04o', $perms & 07777 );
		}
		if ( function_exists( 'posix_geteuid' ) ) {
			$parts[] = 'PHP runs as ' . self::user_name( posix_geteuid() );
		}
		return $parts ? implode( '; ', $parts ) : 'no ownership details available';
	}

	private static function user_name( int $uid ): string {
		$name = function_exists( 'posix_getpwuid' ) ? ( posix_getpwuid( $uid )['name'] ?? null ) : null;
		return null !== $name ? "{$name} (uid {$uid})" : "uid {$uid}";
	}
}
