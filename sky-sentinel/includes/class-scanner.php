<?php
/**
 * The file walk: chunked, resumable, and indifferent to whether WordPress is
 * loaded.
 *
 * Why chunked: the install is 205k files, 28 GB of which is uploads, and the
 * host runs wp-cron from system cron every minute with a sixty-second
 * ceiling. A walk that has to finish in one call either times out or is
 * never scheduled. So the walk keeps its place (a stack of directories still
 * to visit) in a small state array the caller persists, and step() does as
 * much as fits in the budget it is given, then hands the state back.
 *
 * Why the manifest is a file and not part of the state: 30k sha256 entries
 * do not belong in a sitemeta row rewritten every tick. They are appended as
 * JSON lines to a file the caller names, and read back once at the end for
 * the baseline diff.
 *
 * What is read: outside uploads/, every file's sha256 goes in the manifest,
 * and every file with a content extension gets the content detectors, a
 * file over MAX_BYTES in overlapping pieces. Inside uploads/, only the first 16 bytes are read (S3/S4), and
 * nothing is hashed: tens of gigabytes of pictures are not something to
 * sha256 every six hours, and what this campaign puts there is a disguised
 * zip, which four bytes finds.
 */
final class Sky_Sentinel_Scanner {

	/** Directories never entered. */
	public const SKIP_DIRS = array( '.git', '.svn', 'node_modules', '.quarantine' );

	/**
	 * Hashed for the baseline, never read for content. Sentinel's own source
	 * carries every indicator it looks for, in the signature file and in the
	 * detectors themselves, and a scanner that reads its own signature file
	 * reports itself. Its integrity is L8's job, by hash, not by pattern.
	 */
	public const NO_CONTENT_SCAN = array( 'wp-content/mu-plugins/sky-sentinel/', 'mu-plugins/sky-sentinel/' );

	private string $root;
	private Sky_Sentinel_Signatures $sig;
	private Sky_Sentinel_Content_Detectors $content;
	private Sky_Sentinel_FS_Checks $fs;

	public function __construct( string $root, Sky_Sentinel_Signatures $sig ) {
		$real = realpath( $root );
		if ( false === $real || ! is_dir( $real ) ) {
			throw new InvalidArgumentException( "Scan root is not a directory: {$root}" );
		}
		$this->root    = rtrim( str_replace( '\\', '/', $real ), '/' );
		$this->sig     = $sig;
		$this->content = new Sky_Sentinel_Content_Detectors( $sig );
		$this->fs      = new Sky_Sentinel_FS_Checks( $sig );
	}

	public function root(): string {
		return $this->root;
	}

	/** A fresh walk. $manifest_file receives one JSON line per hashed file. */
	public static function start( string $manifest_file ): array {
		if ( false === file_put_contents( $manifest_file, '' ) ) {
			throw new RuntimeException( "Cannot write manifest: {$manifest_file}" );
		}
		return array(
			'pending'       => array( '' ),
			'manifest_file' => $manifest_file,
			'files'         => 0,
			'hashed'        => 0,
			'content_read'  => 0,
			'bytes_read'    => 0,
			'packages'      => array(),
			'started_at'    => time(),
			'done'          => false,
		);
	}

	/**
	 * Walk until the budget is spent or there is nothing left.
	 *
	 * @return array{state: array, findings: Sky_Sentinel_Finding[]}
	 */
	public function step( array $state, float $budget_seconds ): array {
		$deadline = microtime( true ) + $budget_seconds;
		$findings = array();
		$manifest = fopen( $state['manifest_file'], 'ab' );
		if ( false === $manifest ) {
			throw new RuntimeException( "Cannot append to manifest: {$state['manifest_file']}" );
		}

		// At least one directory per call, whatever the budget: a step that can
		// do nothing is a walk that never ends.
		$first = true;
		while ( $state['pending'] && ( $first || microtime( true ) < $deadline ) ) {
			$first = false;
			$rel = array_pop( $state['pending'] );
			$abs = '' === $rel ? $this->root : $this->root . '/' . $rel;
			$entries = @scandir( $abs, SCANDIR_SORT_ASCENDING );
			if ( false === $entries ) {
				$findings[] = new Sky_Sentinel_Finding( 'SCAN', 'info', $rel, 'Directory could not be read' );
				continue;
			}
			$entries = array_values( array_diff( $entries, array( '.', '..' ) ) );

			// A plugin or theme directory is a package: S1/S2 on its name and
			// contents, and its name goes in the inventory for S7.
			if ( self::is_package_parent( $rel ) ) {
				foreach ( $entries as $name ) {
					if ( is_dir( $abs . '/' . $name ) ) {
						$pkg = $rel . '/' . $name;
						$state['packages'][] = $pkg;
						$inside = @scandir( $abs . '/' . $name ) ?: array();
						foreach ( $this->fs->check_package_dir( $pkg, $inside ) as $f ) {
							$findings[] = $f;
						}
					}
				}
			}

			foreach ( $entries as $name ) {
				$child_rel = '' === $rel ? $name : $rel . '/' . $name;
				$child_abs = $abs . '/' . $name;
				if ( is_link( $child_abs ) ) {
					continue;
				}
				if ( is_dir( $child_abs ) ) {
					if ( ! in_array( $name, self::SKIP_DIRS, true ) ) {
						$state['pending'][] = $child_rel;
					}
					continue;
				}
				if ( ! is_file( $child_abs ) ) {
					continue;
				}
				$state['files']++;
				$size = (int) @filesize( $child_abs );
				$in_uploads = Sky_Sentinel_Content_Detectors::under( $child_rel, 'uploads/' );
				$ext = strtolower( pathinfo( $name, PATHINFO_EXTENSION ) );

				$head = null;
				$bytes = null;
				$sha   = '';
				$wants_content = ! $in_uploads
					&& ! self::is_self( $child_rel )
					&& ( in_array( $ext, Sky_Sentinel_Content_Detectors::CONTENT_EXTENSIONS, true ) || '' === $ext || str_starts_with( $name, '.' ) );

				if ( $wants_content || ! $in_uploads ) {
					// Outside uploads everything is hashed, so read it once.
					if ( $size <= 8388608 ) {
						$bytes = @file_get_contents( $child_abs );
					}
					if ( is_string( $bytes ) ) {
						$head = substr( $bytes, 0, 256 );
						$sha  = hash( 'sha256', $bytes );
						$state['bytes_read'] += strlen( $bytes );
					} else {
						$sha = @hash_file( 'sha256', $child_abs ) ?: '';
						$head = self::head( $child_abs );
					}
					if ( '' !== $sha ) {
						fwrite( $manifest, json_encode( array( $child_rel, $sha, $size, (int) @filemtime( $child_abs ) ), JSON_UNESCAPED_SLASHES ) . "\n" );
						$state['hashed']++;
					}
				} else {
					$head = self::head( $child_abs );
				}

				$stat = $in_uploads ? false : @stat( $child_abs );
				foreach ( $this->fs->check_file( $child_rel, $size, $head, $stat ? (int) $stat['mode'] : null, $stat ? (int) $stat['mtime'] : null, $stat ? (int) $stat['ctime'] : null ) as $f ) {
					$findings[] = $f;
				}
				if ( $wants_content && $size > Sky_Sentinel_Content_Detectors::MAX_BYTES && '' !== $sha ) {
					// Too big to read at once: the whole file, a piece at a time.
					$h = is_string( $bytes ) ? null : @fopen( $child_abs, 'rb' );
					if ( is_string( $bytes ) || false !== $h ) {
						$read = is_string( $bytes )
							? fn( int $offset, int $length ) => substr( $bytes, $offset, $length )
							: fn( int $offset, int $length ) => 0 === fseek( $h, $offset ) ? (string) fread( $h, $length ) : '';
						$state['content_read']++;
						foreach ( $this->content->scan_chunked( $child_rel, $read, $size, $sha ) as $f ) {
							$findings[] = $f;
						}
						if ( $h ) {
							fclose( $h );
						}
					}
				} elseif ( $wants_content && is_string( $bytes ) ) {
					$state['content_read']++;
					foreach ( $this->content->scan( $child_rel, $bytes ) as $f ) {
						$findings[] = $f;
					}
				} elseif ( ! $in_uploads && '' !== $sha && null !== ( $known = $this->sig->known_bad( $sha ) ) ) {
					// F1 for what no content detector reads: a .zip, a binary.
					// The hash list has named site-helper's restore.zip since
					// 0.3.0 and, until 0.4.7, nothing ever compared it.
					$findings[] = new Sky_Sentinel_Finding( 'F1', 'critical', $child_rel, "SHA-256 matches a known artifact: {$known}", array( 'known_as' => $known ), $sha );
				}
			}
		}
		fclose( $manifest );
		$state['done'] = empty( $state['pending'] );
		if ( $state['done'] ) {
			sort( $state['packages'] );
			$state['packages'] = array_values( array_unique( $state['packages'] ) );
		}
		return array( 'state' => $state, 'findings' => $findings );
	}

	/** Convenience for CLI and tests: the whole walk in one call. */
	public function scan_all( string $manifest_file ): array {
		$state    = self::start( $manifest_file );
		$findings = array();
		while ( ! $state['done'] ) {
			$r = $this->step( $state, 3600 );
			$state = $r['state'];
			foreach ( $r['findings'] as $f ) {
				$findings[] = $f;
			}
		}
		return array( 'state' => $state, 'findings' => $findings );
	}

	/** Read a manifest file back as rel_path => sha256. */
	public static function read_manifest( string $manifest_file ): array {
		$out = array();
		$h   = @fopen( $manifest_file, 'rb' );
		if ( false === $h ) {
			return $out;
		}
		while ( false !== ( $line = fgets( $h ) ) ) {
			$row = json_decode( $line, true );
			if ( is_array( $row ) && isset( $row[0], $row[1] ) ) {
				$out[ $row[0] ] = $row[1];
			}
		}
		fclose( $h );
		return $out;
	}

	public static function is_self( string $rel ): bool {
		$r = strtolower( $rel );
		foreach ( self::NO_CONTENT_SCAN as $prefix ) {
			if ( str_starts_with( $r, $prefix ) ) {
				return true;
			}
		}
		return false;
	}

	private static function is_package_parent( string $rel ): bool {
		$r = strtolower( $rel );
		return in_array( $r, array( 'wp-content/plugins', 'wp-content/themes', 'wp-content/mu-plugins', 'plugins', 'themes', 'mu-plugins' ), true );
	}

	private static function head( string $abs ): ?string {
		$h = @fopen( $abs, 'rb' );
		if ( false === $h ) {
			return null;
		}
		// 256 rather than 16: S4 wants to read an error page's <title> to tell a
		// broken upload from a disguised payload, and 256 bytes of 181k
		// uploads is nothing.
		$head = fread( $h, 256 );
		fclose( $h );
		return is_string( $head ) ? $head : null;
	}
}
