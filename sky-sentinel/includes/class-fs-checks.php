<?php
/**
 * File-system detectors S1 to S7: WHERE a file is, what it is CALLED, and what
 * its first bytes say it is, as opposed to what its extension claims.
 *
 * Pure. Takes a relative path plus the few facts the walker already has
 * (size, first bytes, directory listing), never touches the disk itself, so
 * it runs against a list of paths in a test as readily as against wp-content.
 *
 * The naming detector (S1) exists because the attacker planted 31 droppers
 * and 24 decoy packages named <word>-<unixtime>, and the timestamp was the
 * plant time to the second. The magic-byte detector (S4) exists because the
 * self-healing plugin's restore archive was uploads/2026/08/cache-05193152.jpg.
 */
final class Sky_Sentinel_FS_Checks {

	/**
	 * S1: one or more words, a separator, a 10-digit epoch from 2020 onward,
	 * optional .php. More than one word: a scan of a real compromised install found nine decoy
	 * themes (author-template-, widget_area_, custom_file_3_, ...) that a
	 * single-word pattern walked straight past.
	 */
	public const NAMED_LIKE_A_PLANT = '/(?:^|\/)([A-Za-z][A-Za-z0-9]*(?:[-_.][A-Za-z0-9]+)*?[-_.]1[6-9]\d{8})(?:\.php)?\/?$/';

	/**
	 * S10: site-helper's naming, <word>-<12 hex>: site-helper-b0a4d4920f57 and
	 * site-helper-bdcd2b1a9ff2 in two builds seen on real installs. The
	 * hex must mix letters and digits, so a 12-digit date is not a match.
	 */
	public const NAMED_LIKE_SITE_HELPER = '/^[a-z][a-z0-9]*(?:-[a-z0-9]+)*?-((?=[0-9a-f]*[a-f])(?=[0-9a-f]*\d)[0-9a-f]{12})$/';

	/** S3: directories where PHP has no business being. */
	public const NO_PHP_HERE = array( 'uploads/', 'blogs.dir/', 'languages/', 'cache/', 'upgrade/', 'upgrade-temp-backup/' );

	/** S4: extensions that promise an image or a document. */
	public const MEDIA_EXTENSIONS = array( 'jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'bmp', 'ico', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'mp3', 'mp4', 'mov', 'zip' );

	/** S9: how far before its inode change a file's mtime must be to count as backdated. */
	public const BACKDATE_SECONDS = 30 * 86400;

	/** S5: what the droppers leave in a temp dir once they have fired. */
	public const DROPPER_DOTFILES = array( '.holder', '.mrk', '.property_set' );

	private Sky_Sentinel_Signatures $sig;

	public function __construct( Sky_Sentinel_Signatures $sig ) {
		$this->sig = $sig;
	}

	/**
	 * Checks that need only the path and the first bytes.
	 *
	 * @param string      $rel_path Relative to wp-content, forward slashes.
	 * @param int         $size     Bytes.
	 * @param string|null $head     First bytes (16 is enough; more lets S4 read an error page's title), or null if the walker did not read them.
	 * @param int|null    $mode     fileperms(), for S9. Null when the walker did not stat.
	 * @param int|null    $mtime    filemtime(), for S9.
	 * @param int|null    $ctime    filectime(), for S9.
	 * @return Sky_Sentinel_Finding[]
	 */
	public function check_file( string $rel_path, int $size, ?string $head, ?int $mode = null, ?int $mtime = null, ?int $ctime = null ): array {
		$rel_path = ltrim( str_replace( '\\', '/', $rel_path ), '/' );
		$out      = array();
		$base     = basename( $rel_path );
		$ext      = strtolower( pathinfo( $base, PATHINFO_EXTENSION ) );
		$f        = function ( string $id, string $sev, string $summary, array $detail = array() ) use ( &$out, $rel_path ) {
			$out[] = new Sky_Sentinel_Finding( $id, $sev, $rel_path, $summary, $detail );
		};

		// S1: named like a plant.
		if ( 'php' === $ext && preg_match( self::NAMED_LIKE_A_PLANT, $rel_path, $m ) ) {
			$f( 'S1', 'high', 'PHP file named <word>-<unix time>, the campaign plant naming', array( 'name' => $m[1], 'planted_at' => self::epoch_of( $m[1] ) ) );
		}

		// S3: PHP where there should be none. Matched directly under
		// wp-content (or at the root of a wp-content copy), not anywhere a
		// plugin happens to have a folder called cache/.
		$wc = preg_replace( '#^wp-content/#', '', $rel_path );
		if ( in_array( $ext, array( 'php', 'phtml', 'php5', 'php7', 'phar' ), true ) ) {
			foreach ( self::NO_PHP_HERE as $dir ) {
				if ( str_starts_with( strtolower( $wc ), $dir ) ) {
					if ( $this->sig->allowed( 's3_php_in_datastore', $rel_path ) || $this->sig->allowed( 's3_php_in_datastore', self::single_site_uploads( $rel_path ) ) ) {
						$f( 'S3', 'info', "PHP inside {$dir} (allow-listed datastore)" );
					} elseif ( 'index.php' === strtolower( $base ) && $size <= 64 ) {
						// "Silence is golden" guards. Not flagged at all: 205k of
						// them is noise nobody reads and then nobody reads the list.
					} elseif ( 0 === $size ) {
						// Empty: nothing to run. WP All Export leaves a 0-byte
						// functions.php in each site's uploads. Once anything is
						// written into it, the next walk sees a size and says so.
					} else {
						$f( 'S3', 'high', "PHP file inside {$dir}" );
					}
					break;
				}
			}
		}

		// S4: the extension says picture, the bytes say zip / PHP / HTML.
		if ( null !== $head && in_array( $ext, self::MEDIA_EXTENSIONS, true ) && 'zip' !== $ext ) {
			$kind = self::disguised_as( $head, $ext );
			if ( 'HTML' === $kind && self::is_server_error_page( $head ) ) {
				// A 502 page saved under an image's name: the uploader fetched
				// the picture, the server hiccupped, and the error body was
				// stored. Common inside e-learning packages with hundreds of
				// small images. Broken, not hostile.
				$f( 'S4', 'medium', "A .{$ext} that is a saved server error page (broken upload, re-upload the image)", array( 'magic' => bin2hex( substr( $head, 0, 4 ) ) ) );
			} elseif ( null !== $kind ) {
				$f( 'S4', 'critical', "A .{$ext} whose first bytes are {$kind}", array( 'magic' => bin2hex( substr( $head, 0, 4 ) ) ) );
			}
		}

		// S5: dropper side-effect files.
		if ( in_array( $base, self::DROPPER_DOTFILES, true ) ) {
			$f( 'S5', 'critical', "Dropper marker file {$base}" );
		}

		// F16 by name: site-helper kept restore.zip beside a .state.json. A
		// content detector never reads a .zip, so the name is checked here.
		if ( Sky_Sentinel_Content_Detectors::under( $rel_path, 'plugins/' ) && in_array( strtolower( $base ), array( '.state.json', 'restore.zip' ), true ) ) {
			$f( 'F16', 'high', "Self-heal artifact inside a plugin: {$base}" );
		}

		// S9: PHP locked read-only for everyone, and PHP whose modification
		// time is far older than its inode change time. The Wordfence-reported
		// mu-plugin does both to every copy it writes: chmod 0444 so a cleanup
		// script's overwrite fails, touch() into the past so a "sort by date"
		// never shows it. Deploys preserve mtimes too (rsync, some FTP
		// clients), so a backdate alone is not a finding; only a lock is, and
		// only on the load path, where there is no reason for it. In a plugin
		// or theme it takes both.
		if ( null !== $mode && 'php' === $ext ) {
			$locked    = 0 === ( $mode & 0222 );
			$backdated = null !== $mtime && null !== $ctime && $ctime - $mtime > self::BACKDATE_SECONDS;
			$load      = self::is_load_path( 'wp-content/' . $wc );
			$package   = str_starts_with( $wc, 'plugins/' ) || str_starts_with( $wc, 'themes/' ) || str_starts_with( $wc, 'mu-plugins/' );
			$detail    = array( 'mode' => sprintf( '%04o', $mode & 0777 ) ) + ( $backdated ? array( 'mtime' => gmdate( 'Y-m-d H:i:s', $mtime ) . ' UTC', 'ctime' => gmdate( 'Y-m-d H:i:s', $ctime ) . ' UTC' ) : array() );
			if ( $locked && $load ) {
				$f( 'S9', $backdated ? 'critical' : 'high', $backdated ? 'Load-path PHP locked read-only (0444) and backdated: mtime is long before ctime' : 'Load-path PHP locked read-only for everyone', $detail );
			} elseif ( $locked && $backdated && $package ) {
				$f( 'S9', 'high', 'PHP locked read-only (0444) and backdated: mtime is long before ctime', $detail );
			}
		}

		// F15 second clause lives here because it is a location, not a content,
		// question. One file is ours: the remediation worker placed during the
		// cleanup, named in the allow-list so it is known rather than tolerated.
		if ( 'js' === $ext && ! str_contains( $rel_path, '/' ) && ! in_array( strtolower( $base ), array_map( 'strtolower', $this->sig->allow_list( 'f15_webroot_js' ) ), true ) ) {
			$f( 'F15', 'high', 'A JavaScript file at the webroot' );
		}

		return $out;
	}

	/**
	 * Checks on a plugin or theme DIRECTORY: S1 for the directory name, S2 for
	 * a decoy package.
	 *
	 * @param string   $rel_dir  e.g. plugins/akismet-1723456789
	 * @param string[] $entries  Names directly inside it.
	 * @return Sky_Sentinel_Finding[]
	 */
	public function check_package_dir( string $rel_dir, array $entries ): array {
		$rel_dir = trim( str_replace( '\\', '/', $rel_dir ), '/' );
		$out     = array();
		// S8: a package DIRECTORY named like a PHP file. When the Wordfence-
		// reported mu-plugin cannot write into mu-plugins it falls back to
		// plugins/<its name>/<its name>, and its name is advanced-cache.php
		// or db.php. No real plugin directory ends in .php.
		if ( preg_match( '/\.(?:php\d?|phtml|phar)$/i', basename( $rel_dir ) ) ) {
			$twin = in_array( strtolower( basename( $rel_dir ) ), array_map( 'strtolower', $entries ), true );
			$out[] = new Sky_Sentinel_Finding( 'S8', 'critical', $rel_dir, $twin ? 'Package directory named like a PHP file, holding a file of the same name: the mu-plugin spreader\'s fallback' : 'Package directory named like a PHP file', array( 'twin' => $twin ) );
		}
		// S10: a package named like one of the campaign's plugins, by its
		// exact name from iocs.json or by site-helper's naming.
		$why = self::campaign_package_name( basename( $rel_dir ), $this->sig->plugin_dirs() );
		if ( null !== $why ) {
			$out[] = new Sky_Sentinel_Finding( 'S10', $why[0], $rel_dir, $why[1] );
		}
		if ( ! preg_match( self::NAMED_LIKE_A_PLANT, $rel_dir, $m ) ) {
			return $out;
		}
		$entries = array_map( 'strtolower', $entries );
		$decoy   = in_array( 'akismet.php', $entries, true )
			|| ( in_array( 'theme.php', $entries, true ) && in_array( 'style.css', $entries, true ) );
		if ( $decoy ) {
			$out[] = new Sky_Sentinel_Finding( 'S2', 'critical', $rel_dir, 'Decoy package: a plant-named directory holding a copy of a real plugin or theme', array( 'name' => $m[1] ) );
		} else {
			$out[] = new Sky_Sentinel_Finding( 'S1', 'high', $rel_dir, 'Directory named <word>-<unix time>, the campaign plant naming', array( 'name' => $m[1], 'planted_at' => self::epoch_of( $m[1] ) ) );
		}
		return $out;
	}

	/**
	 * A multisite upload path as the allow-list writes it: uploads/sites/6/
	 * and blogs.dir/6/files/ both become uploads/. The Sucuri datastore
	 * entry "uploads/sucuri/" matched only the main site's, and every other
	 * site's copy was a HIGH: eight of them on one real multisite.
	 */
	public static function single_site_uploads( string $rel_path ): string {
		return (string) preg_replace( '#(^|/)(?:uploads/sites/\d+|blogs\.dir/\d+/files)/#i', '$1uploads/', str_replace( '\\', '/', $rel_path ) );
	}

	/**
	 * Is this plugin or theme directory name one the campaign uses? Shared by
	 * S10 (the directory on disk) and D11 (the name in active_plugins).
	 *
	 * @param string[] $known Exact names from iocs.json plugin_dirs.
	 * @return array{0:string,1:string}|null Severity and reason.
	 */
	public static function campaign_package_name( string $dir, array $known ): ?array {
		$dir = strtolower( trim( $dir, '/' ) );
		if ( in_array( $dir, $known, true ) ) {
			return array( 'critical', 'Named like a known campaign plugin' );
		}
		if ( preg_match( self::NAMED_LIKE_SITE_HELPER, $dir ) ) {
			return array( 'high', 'Named <word>-<12 hex>, the site-helper plugin\'s naming' );
		}
		return null;
	}

	/**
	 * S6 and S7: what changed since the signed baseline.
	 *
	 * @param array<string,string> $baseline  rel_path => sha256
	 * @param array<string,string> $current   rel_path => sha256
	 * @param string[]             $baseline_packages  plugin/theme directory names
	 * @param string[]             $current_packages
	 * @return Sky_Sentinel_Finding[]
	 */
	public static function diff_against_baseline( array $baseline, array $current, array $baseline_packages, array $current_packages ): array {
		$out = array();
		foreach ( $current as $path => $sha ) {
			$ext = strtolower( pathinfo( $path, PATHINFO_EXTENSION ) );
			if ( ! isset( $baseline[ $path ] ) ) {
				$code = in_array( $ext, array( 'php', 'js', 'phtml', 'inc' ), true );
				$out[] = new Sky_Sentinel_Finding( 'S6', $code ? 'high' : 'medium', $path, 'New file since the baseline', array(), $sha );
			} elseif ( $baseline[ $path ] !== $sha ) {
				$out[] = new Sky_Sentinel_Finding( 'S6', 'medium', $path, 'File changed since the baseline', array( 'was' => $baseline[ $path ] ), $sha );
			}
		}
		foreach ( array_diff_key( $baseline, $current ) as $path => $sha ) {
			$out[] = new Sky_Sentinel_Finding( 'S6', 'info', $path, 'File deleted since the baseline', array( 'was' => $sha ) );
		}
		foreach ( array_diff( $current_packages, $baseline_packages ) as $pkg ) {
			$out[] = new Sky_Sentinel_Finding( 'S7', 'high', $pkg, 'Plugin or theme directory not in the baseline inventory' );
		}
		return $out;
	}

	/**
	 * The drop-ins WordPress loads from wp-content by name, whatever is in
	 * them (_get_dropins()). The Wordfence-reported mu-plugin family shipped
	 * most often AS advanced-cache.php or db.php, because those names look
	 * like they belong.
	 */
	public const DROPINS = array(
		'advanced-cache.php', 'db.php', 'db-error.php', 'install.php', 'maintenance.php',
		'object-cache.php', 'php-error.php', 'fatal-error-handler.php', 'sunrise.php',
		'blog-deleted.php', 'blog-inactive.php', 'blog-suspended.php',
	);

	/**
	 * Is this file on WordPress's automatic load path: a top-level .php in
	 * mu-plugins, or a drop-in at the top of wp-content? Those files run on
	 * every request without anyone activating them, so they get the strictest
	 * treatment Sentinel has (L9).
	 *
	 * @param string $rel_path    Relative to the scan root, forward slashes.
	 * @param string $content_rel wp-content relative to the scan root.
	 * @param string $mu_rel      mu-plugins relative to the scan root.
	 */
	public static function is_load_path( string $rel_path, string $content_rel = 'wp-content', string $mu_rel = 'wp-content/mu-plugins' ): bool {
		$rel_path = ltrim( str_replace( '\\', '/', $rel_path ), '/' );
		$dir      = dirname( $rel_path );
		$base     = basename( $rel_path );
		if ( trim( $mu_rel, '/' ) === $dir ) {
			return 'php' === strtolower( pathinfo( $base, PATHINFO_EXTENSION ) );
		}
		return trim( $content_rel, '/' ) === $dir && in_array( strtolower( $base ), self::DROPINS, true );
	}

	/**
	 * L9: the load path against the signed baseline. Checked every minute, not
	 * every six hours, because a file here is live on the next request. A new
	 * or changed file is CRITICAL: nothing lands in mu-plugins or becomes a
	 * drop-in without a deploy, and a deploy is followed by re-signing. The
	 * mu-plugin in the Wordfence write-up hid itself from the Must-Use screen,
	 * so "look at the list in wp-admin" is not a check.
	 *
	 * @param array<string,string> $baseline rel_path => sha256, load-path files only
	 * @param array<string,string> $current  rel_path => sha256, load-path files only
	 * @return Sky_Sentinel_Finding[]
	 */
	public static function diff_load_path( array $baseline, array $current ): array {
		$out = array();
		foreach ( $current as $path => $sha ) {
			if ( ! isset( $baseline[ $path ] ) ) {
				$out[] = new Sky_Sentinel_Finding( 'L9', 'critical', $path, 'New file on the load path (mu-plugins or a drop-in) since the baseline: it runs on every request', array(), $sha );
			} elseif ( $baseline[ $path ] !== $sha ) {
				$out[] = new Sky_Sentinel_Finding( 'L9', 'critical', $path, 'Load-path file (mu-plugins or a drop-in) changed since the baseline', array( 'was' => $baseline[ $path ] ), $sha );
			}
		}
		foreach ( array_diff_key( $baseline, $current ) as $path => $sha ) {
			$out[] = new Sky_Sentinel_Finding( 'L9', 'high', $path, 'Load-path file (mu-plugins or a drop-in) removed since the baseline', array( 'was' => $sha ) );
		}
		return $out;
	}

	/** What a media file's first bytes actually are, or null when they are plausibly media. */
	public static function disguised_as( string $head, string $ext ): ?string {
		if ( str_starts_with( $head, "PK\x03\x04" ) ) {
			// Office formats ARE zips. Only a picture claiming to be one is a lie.
			return in_array( $ext, array( 'docx', 'xlsx', 'pptx' ), true ) ? null : 'a ZIP archive';
		}
		if ( str_starts_with( $head, '<?php' ) || str_starts_with( $head, '<?=' ) ) {
			return 'PHP';
		}
		$trim = ltrim( $head );
		if ( 'svg' !== $ext && ( 0 === stripos( $trim, '<!DOCTYPE' ) || 0 === stripos( $trim, '<html' ) || 0 === stripos( $trim, '<script' ) ) ) {
			return 'HTML';
		}
		return null;
	}

	/**
	 * nginx and Apache error bodies: a title that opens with a 4xx/5xx code,
	 * and no script anywhere in the head we read. A lure dressed as an error
	 * page would carry one; a real error page never does.
	 */
	public static function is_server_error_page( string $head ): bool {
		return preg_match( '/<title>\s*(?:4\d\d|5\d\d)\s+[A-Za-z ]+<\/title>/i', $head )
			&& false === stripos( $head, '<script' );
	}

	private static function epoch_of( string $name ): ?string {
		if ( preg_match( '/(1[6-9]\d{8})$/', $name, $m ) ) {
			return gmdate( 'Y-m-d H:i:s', (int) $m[1] ) . ' UTC';
		}
		return null;
	}
}
