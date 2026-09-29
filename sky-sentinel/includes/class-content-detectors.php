<?php
/**
 * Content detectors F1 to F17: what a file SAYS.
 *
 * Pure functions over (relative path, bytes). No WordPress, no filesystem, no
 * database. That is deliberate: it means the same code runs on a laptop
 * against the infected backup, in PHPUnit against a fixture, and in wp-cron
 * against the live host, and the answer is the same in all three.
 *
 * Every detector here corresponds to something this campaign family is
 * documented doing to WordPress installs. The comments name which behaviour,
 * because a rule with no observed behaviour behind it is the first thing the
 * next person will delete.
 *
 * Signatures are on STRUCTURE where the campaign rotates names (F10: the
 * loader's shape, not its variable names), and on literals only where a
 * literal is the whole point (F2: the decoder alphabet the droppers share).
 */
final class Sky_Sentinel_Content_Detectors {

	/**
	 * The most of a file any detector sees at once. A bigger file is read
	 * whole, in pieces of this size that overlap by CHUNK_OVERLAP
	 * (scan_chunked()). Until 0.4.7 bigger files were skipped, and this
	 * campaign appends its loader to big library files: a 3.7 MB
	 * fontawesome-all.min.js in one real install, which no detector read.
	 * 0.4.7 read only the first and last MB.
	 */
	public const MAX_BYTES = 1048576;

	/**
	 * How much consecutive pieces share. The loader is ~10 KB and F10 looks
	 * 16 KB past its start, so anything this size or smaller lies whole in
	 * at least one piece, wherever it sits.
	 */
	public const CHUNK_OVERLAP = 65536;

	/** Extensions whose content is read outside uploads/. */
	public const CONTENT_EXTENSIONS = array( 'php', 'phtml', 'inc', 'js', 'html', 'htm', 'json', 'txt', 'svg', 'css' );

	private const TEMP_PROBE  = '/sys_get_temp_dir\s*\(|session_save_path\s*\(|upload_tmp_dir|\/dev\/shm/';
	private const INCLUDE_VAR = '/\b(?:include|include_once|require|require_once)\s*\(?\s*\$/';
	private const LURE_STRONG = array( 'mshta', 'powershell -', 'cmd /c', 'Win + R', 'Windows + R', 'Command + Space', 'Cmd + Space' );
	// Weak terms in CATEGORIES. A lure needs two different ideas: a fake
	// verification AND a clipboard write, or steps to perform AND a
	// verification. Two terms from one category is one idea. Counting terms
	// flags every "copy to clipboard" button ever written, including the one
	// in WordPress core's own block editor.
	private const LURE_WEAK   = array(
		'verify'    => array( 'Verify you are human', 'Human Verification', 'I am not a robot', 'challenge-platform', 'Press Enter to verify' ),
		'clipboard' => array( 'clipboard.writeText', "execCommand('copy')", 'execCommand("copy")' ),
		'steps'     => array( 'Perform the steps' ),
	);

	private Sky_Sentinel_Signatures $sig;

	public function __construct( Sky_Sentinel_Signatures $sig ) {
		$this->sig = $sig;
	}

	/**
	 * Run every content detector over one file.
	 *
	 * @param string $rel_path Path relative to wp-content (or the scan root), forward slashes.
	 * @param string $bytes    The file's contents, at most MAX_BYTES.
	 * @return Sky_Sentinel_Finding[]
	 */
	public function scan( string $rel_path, string $bytes ): array {
		$rel_path = str_replace( '\\', '/', $rel_path );
		$sha      = hash( 'sha256', $bytes );
		$ext      = strtolower( pathinfo( $rel_path, PATHINFO_EXTENSION ) );
		$in_uploads = self::under( $rel_path, 'uploads/' );
		$out      = array();

		$f = function ( string $id, string $sev, string $summary, array $detail = array() ) use ( &$out, $rel_path, $sha ) {
			$out[] = new Sky_Sentinel_Finding( $id, $sev, $rel_path, $summary, $detail, $sha );
		};

		// F1: the hash list. Exact, so CRITICAL with no further argument.
		if ( null !== ( $name = $this->sig->known_bad( $sha ) ) ) {
			$f( 'F1', 'critical', "SHA-256 matches a known artifact: {$name}", array( 'known_as' => $name ) );
		}

		// F2: the dropper decoder. All three droppers on the network carried the
		// same alphabet, exploded it, and XOR'd through it with a per-build key.
		if ( str_contains( $bytes, 'abcdefghijklmnopqrstuvwxyz0123456789' )
			&& preg_match( '/\bexplode\s*\(/', $bytes )
			&& preg_match( '/\^\s*\d+/', $bytes ) ) {
			$f( 'F2', 'critical', 'Dropper decoder: shared alphabet + explode + XOR against an integer key' );
		}

		// F3: the droppers open with an HTML comment tag and then <?php. Legit
		// PHP does not start with a comment aimed at a browser.
		if ( preg_match( '/\A<!--[A-Za-z0-9]{5,12}-->\s*<\?php/', $bytes, $m ) ) {
			$f( 'F3', 'high', 'File opens with an HTML comment tag immediately before <?php', array( 'tag' => $m[0] ) );
		}

		// F4: one request key + a temp-dir probe + include of a variable. The
		// dropper's whole job in three features. The key may be read from
		// $_POST, $_REQUEST or $_COOKIE, by literal or by variable:
		// a 2026-09 dropper build reads $_REQUEST[$value], which the
		// $_POST-literal rule never saw, so with the alphabet reordered and
		// the comment tag dropped it fell to F5 alone, MEDIUM, the digest.
		// Not $_GET: a page cache reads one ?page= and includes its template
		// from beside a temp-dir path, and a dropper's payload is too long
		// for a URL anyway.
		$keys    = self::request_keys( $bytes );
		$temp    = (bool) preg_match( self::TEMP_PROBE, $bytes );
		$inc_var = (bool) preg_match( self::INCLUDE_VAR, $bytes );
		if ( 1 === count( $keys ) && $temp && $inc_var ) {
			$f( 'F4', 'high', "Reads one request key ({$keys[0]}), probes a temp directory, and includes a variable", array( 'request_key' => $keys[0] ) );
		}

		// F5: write-then-include. Real software does this too (Wordfence's
		// waf bootstrap, elFinder, the AWS SDK), hence MEDIUM and an allow-list.
		if ( $temp && $inc_var && preg_match( '/\b(?:fopen|file_put_contents|fwrite)\s*\(/', $bytes )
			&& ! $this->sig->allowed( 'f5_write_then_include', $rel_path ) ) {
			$f( 'F5', 'medium', 'Writes to a temp directory and then includes a variable path' );
		}

		// F6: the marker files the droppers leave behind: a comment tag and nothing else.
		if ( strlen( $bytes ) <= 24 && preg_match( '/\A\s*<!--[A-Za-z0-9]{5,12}-->\s*\z/', $bytes ) ) {
			$f( 'F6', 'high', 'Marker file: only an HTML comment tag', array( 'bytes' => strlen( $bytes ) ) );
		}

		// F7: the admin-hider by its own option names, or by the trio of hooks
		// a generic one needs.
		if ( preg_match( '/_pre_user_id|wsh_tracked_admin_ids|WSH_HIDDEN_USERS/', $bytes, $m ) ) {
			$f( 'F7', 'critical', "Admin-hider option name present: {$m[0]}", array( 'matched' => $m[0] ) );
		} elseif ( str_contains( $bytes, 'pre_user_query' ) && str_contains( $bytes, 'views_users' )
			&& ( str_contains( $bytes, 'pre_count_users' ) || str_contains( $bytes, 'all_plugins' ) ) ) {
			$f( 'F7', 'high', 'Filters the user query, the user views, and the user count or plugin list together' );
		}

		// F8: a plugin that removes ITSELF from the plugin list.
		if ( preg_match( '/add_filter\s*\(\s*[\'"]all_plugins[\'"]/', $bytes )
			&& preg_match( '/unset\s*\(\s*\$\w+\s*\[\s*plugin_basename\s*\(\s*__FILE__\s*\)\s*\]/', $bytes ) ) {
			$f( 'F8', 'high', 'Filters all_plugins and unsets its own basename: a self-hiding plugin' );
		}

		// F9: the EtherHiding loader's decode-and-run shape, in ANY file type
		// outside uploads/. Same three calls in home-slider.js, main.js and the
		// inline script echoed from functions.php, always within ~8 KB of one
		// another. Anywhere in the file was the rule until 0.4.8; a bundle has
		// all three by chance: Formidable Pro's dropzone.min.js (dropzone
		// 5.9.3) holds them 80 KB apart, MailPoet's editor bundle 800 KB.
		$f9 = ! $in_uploads && self::f9_calls_near( $bytes, self::F9_SPAN )
			&& ! $this->sig->allowed( 'f9_loader_structure', $rel_path );

		// F10: the loader's structure. Variable names rotate between builds;
		// the numeric array, the XOR loop and the run-once flag do not.
		$f10 = self::loader_structure( $bytes );

		if ( $f10 ) {
			$f( 'F10', 'critical', $f10['appended'] ? 'Loader structure appended to a longer file' : 'Loader structure', $f10 );
		}
		if ( $f9 ) {
			$f( 'F9', $f10 ? 'critical' : 'high', 'atob + new Function + charCode decode-and-run in one file' );
		}

		// F11: the campaign's own plaintext indicators. Contracts, selector,
		// token, run-once flags, RPC hosts. Never contacted, only matched.
		$hits = array();
		foreach ( $this->sig->ioc_strings() as $needle ) {
			if ( str_contains( $bytes, $needle ) ) {
				$hits[] = $needle;
			}
		}
		foreach ( $this->sig->ioc_contract_patterns() as $pattern ) {
			if ( preg_match( '/' . $pattern . '/', $bytes, $m ) ) {
				$hits[] = $m[0];
			}
		}
		foreach ( $this->sig->rpc_hosts() as $host ) {
			if ( str_contains( $bytes, $host ) ) {
				$hits[] = $host;
			}
		}
		if ( $hits ) {
			$f( 'F11', 'critical', 'Campaign indicator present: ' . implode( ', ', array_slice( $hits, 0, 4 ) ), array( 'iocs' => $hits ) );
		}

		// F12: any on-chain resolver, not just this campaign's. A WordPress
		// theme has no business calling eth_call.
		if ( ! $in_uploads ) {
			if ( preg_match( '/\beth_call\b|ethers\.(?:JsonRpcProvider|Contract)\b/', $bytes, $m ) ) {
				$f( 'F12', 'high', "On-chain resolver call: {$m[0]}", array( 'matched' => $m[0] ) );
			} elseif ( null !== ( $near = self::address_near_rpc( $bytes ) ) ) {
				$f( 'F12', 'high', 'A contract address within 2 KB of an RPC hostname', $near );
			}
		}

		// F13: PHP echoing a loader from a footer/head hook. This is the
		// twentyseventeen/functions.php injection, and the one file-scanning
		// of .js alone would never have found.
		if ( in_array( $ext, array( 'php', 'phtml', 'inc' ), true )
			&& preg_match( '/add_action\s*\(\s*[\'"](?:wp_footer|wp_head|login_footer|login_head)[\'"]/', $bytes, $m )
			&& stripos( $bytes, '<script' ) !== false
			&& ( $f9 || $f10 ) ) {
			$f( 'F13', 'critical', "PHP echoes a loader script from {$m[0]}", array( 'hook' => $m[0] ) );
		}

		// F14: ClickFix lure text. One strong term (a command the lure tells
		// the victim to run) is enough; weak terms need two, because a real
		// captcha plugin legitimately says "I am not a robot".
		if ( ! $this->sig->allowed( 'f14_lure_text', $rel_path ) ) {
			$strong = array_values( array_filter( self::LURE_STRONG, fn( $t ) => str_contains( $bytes, $t ) ) );
			$weak   = array();
			$categories = 0;
			foreach ( self::LURE_WEAK as $terms ) {
				$hit = array_values( array_filter( $terms, fn( $t ) => false !== stripos( $bytes, $t ) ) );
				if ( $hit ) {
					$categories++;
					$weak = array_merge( $weak, $hit );
				}
			}
			if ( $strong || $categories >= 2 ) {
				$f( 'F14', 'high', 'ClickFix lure text: ' . implode( ', ', array_merge( $strong, $weak ) ), array( 'strong' => $strong, 'weak' => $weak ) );
			}
		}

		// F15: a service worker registration, unless it is a known one. The
		// attacker registered one in visitors' browsers to keep the lure alive
		// after the page was cleaned.
		// Allowed by script path OR by the file's own path: a plugin that
		// registers its worker from a variable (wp-mail-smtp-pro's push
		// notifications, wp-migrate-db-pro) cannot be excused by argument.
		if ( ! $in_uploads && ! $this->sig->allowed( 'f15_service_worker_paths', $rel_path )
			&& preg_match_all( '/serviceWorker\s*\.\s*register\s*\(\s*([^)]*)\)/', $bytes, $mm ) ) {
			foreach ( $mm[1] as $arg ) {
				if ( ! $this->script_allowed( $arg ) ) {
					$f( 'F15', 'high', 'Registers a service worker not on the allow-list', array( 'argument' => trim( $arg ) ) );
					break;
				}
			}
		}

		// F16: a plugin that can put itself back. site-helper kept restore.zip
		// beside a .state.json and re-extracted into WP_PLUGIN_DIR.
		if ( in_array( $ext, array( 'php', 'phtml', 'inc' ), true ) && ! $this->sig->allowed( 'f16_self_heal', $rel_path ) ) {
			if ( str_contains( $bytes, 'ZipArchive' ) && str_contains( $bytes, 'extractTo(' )
				&& ( str_contains( $bytes, 'WP_PLUGIN_DIR' ) || str_contains( $bytes, 'plugin_dir_path' ) ) ) {
				$f( 'F16', 'high', 'Extracts a zip into the plugin directory: a self-healing plugin' );
			} elseif ( str_contains( $bytes, 'register_activation_hook' ) && str_contains( $bytes, 'wp_upload_dir(' )
				&& preg_match( '/\b(?:copy|rename|file_put_contents)\s*\(/', $bytes ) ) {
				// Three things present anywhere in one file, which in a
				// 10,000-line plugin is Gravity Forms, LearnDash and Wordfence.
				// MEDIUM: worth a line in the digest, not a page.
				$f( 'F16', 'medium', 'Has an activation hook, reads the upload dir, and writes a file (somewhere in the file)' );
			}
		}
		// The by-NAME half of F16 (restore.zip, .state.json inside a plugin) is
		// in Sky_Sentinel_FS_Checks, because this class only ever sees files
		// with a content extension and a .zip is not one. The first walk of a
		// fake site found the plugin and missed its archive for exactly that
		// reason.
		$base = strtolower( basename( $rel_path ) );

		// F17: obfuscation in a theme's entry files. MEDIUM because some
		// commercial themes do this and are merely bad, not hostile.
		if ( self::under( $rel_path, 'themes/' ) && in_array( $base, array( 'functions.php', 'header.php', 'footer.php', 'index.php' ), true )
			&& preg_match( '/\b(eval|base64_decode|gzinflate|str_rot13)\s*\(/', $bytes, $m ) ) {
			$f( 'F17', 'medium', "Obfuscation call in a theme entry file: {$m[1]}(", array( 'call' => $m[1] ) );
		}

		// F24: PHP that includes a picture. Code hidden in a .gif or .jpg
		// passes any look at uploads/ that trusts the extension, then runs
		// through a one-line include somewhere else. One compromised install
		// still had a logo.php that was a short open tag and
		// include('/home/<user>/bin/start.gif') and nothing else.
		if ( in_array( $ext, array( 'php', 'phtml', 'inc' ), true )
			&& preg_match( '/\b(?:include|include_once|require|require_once)\s*\(?\s*[\'"]([^\'"\n]+\.(?:gif|jpe?g|png|webp|bmp|ico))[\'"]/i', $bytes, $m ) ) {
			$f( 'F24', 'high', "Includes an image file as PHP: {$m[1]}", array( 'included' => $m[1] ) );
		}

		// F18 to F23: the self-healing mu-plugin in Wordfence's September 2026
		// write-up. Its hook names, option keys and paths are cipher-encoded,
		// so these match what the cipher leaves in the clear: magic constants,
		// function names, integer modes, and the cipher itself.
		if ( in_array( $ext, array( 'php', 'phtml', 'inc' ), true ) ) {
			foreach ( $this->self_heal_family( $bytes ) as $args ) {
				$f( ...$args );
			}
		}

		return $out;
	}

	/**
	 * Any size of content already in memory: scan() when it fits, in pieces
	 * when it does not. The page check hands whole response bodies here; it
	 * used to keep the first MAX_BYTES and drop the rest.
	 *
	 * @return Sky_Sentinel_Finding[]
	 */
	public function scan_any( string $rel_path, string $bytes ): array {
		$size = strlen( $bytes );
		if ( $size <= self::MAX_BYTES ) {
			return $this->scan( $rel_path, $bytes );
		}
		return $this->scan_chunked( $rel_path, fn( int $offset, int $length ) => substr( $bytes, $offset, $length ), $size, hash( 'sha256', $bytes ) );
	}

	/**
	 * A file too big to read at once, read whole in pieces of MAX_BYTES that
	 * overlap by CHUNK_OVERLAP. Memory stays at one piece. Appending is how
	 * the loader gets into a library file, but a File Manager edit can put
	 * it anywhere, so every byte is read.
	 *
	 * Findings carry the whole file's sha256, so F1 matches the file and the
	 * fingerprint changes when the file does. A detector that fires in more
	 * than one piece is reported once, from the first. F10's offset is made
	 * absolute.
	 *
	 * What this cannot see: a match that needs two features more than
	 * MAX_BYTES - CHUNK_OVERLAP apart. None of the loader's do.
	 *
	 * @param callable(int,int):string $read   Bytes at an offset, at most a length.
	 * @param string                   $sha    sha256 of the whole file.
	 * @return Sky_Sentinel_Finding[]
	 */
	public function scan_chunked( string $rel_path, callable $read, int $size, string $sha ): array {
		$rel_path = str_replace( '\\', '/', $rel_path );
		$out      = array();
		$seen     = array();
		if ( null !== ( $name = $this->sig->known_bad( $sha ) ) ) {
			$out[] = new Sky_Sentinel_Finding( 'F1', 'critical', $rel_path, "SHA-256 matches a known artifact: {$name}", array( 'known_as' => $name ), $sha );
			$seen['F1'] = true;
		}
		$step = self::MAX_BYTES - self::CHUNK_OVERLAP;
		for ( $start = 0; $start < $size; $start += $step ) {
			$bytes = (string) $read( $start, self::MAX_BYTES );
			if ( '' === $bytes ) {
				break;
			}
			foreach ( $this->scan( $rel_path, $bytes ) as $f ) {
				if ( isset( $seen[ $f->detector ] ) ) {
					continue;
				}
				$seen[ $f->detector ] = true;
				$summary = $f->summary;
				$detail  = $f->detail + array( 'window' => 'bytes ' . $start . ' to ' . ( $start + strlen( $bytes ) ) . " of {$size}" );
				if ( 'F10' === $f->detector && isset( $detail['offset'] ) ) {
					$detail['offset']   = $start + (int) $detail['offset'];
					$detail['appended'] = $detail['offset'] > 256;
					$summary            = $detail['appended'] ? 'Loader structure appended to a longer file' : 'Loader structure';
				}
				$out[] = new Sky_Sentinel_Finding( $f->detector, $f->severity, $rel_path, $summary, $detail, $sha );
			}
			if ( $start + strlen( $bytes ) >= $size ) {
				break;
			}
		}
		return $out;
	}

	/** How close F9's three calls must be. The loader spans ~8 KB. */
	public const F9_SPAN = 32768;

	/** atob(, new Function( and fromCharCode/charCodeAt, all within $span bytes of one another. */
	public static function f9_calls_near( string $bytes, int $span ): bool {
		$at = array();
		foreach ( array( 'atob' => '/atob\(/', 'fn' => '/new Function\(/', 'cc' => '/fromCharCode|charCodeAt/' ) as $k => $re ) {
			if ( ! preg_match_all( $re, $bytes, $m, PREG_OFFSET_CAPTURE ) ) {
				return false;
			}
			$at[ $k ] = array_column( $m[0], 1 );
		}
		foreach ( $at['fn'] as $fn ) {
			$near = fn( array $list ) => (bool) array_filter( $list, fn( $o ) => abs( $o - $fn ) <= $span );
			if ( $near( $at['atob'] ) && $near( $at['cc'] ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Hex-escaped text that decodes to one of these is hiding a query or a
	 * call. SQL keywords are matched in capitals only, as the sample writes
	 * them: case-insensitive, "Please select an option" is a query.
	 */
	private const HIDDEN_WORDS = '/\b(?:UPDATE|SELECT|INSERT|DELETE|DROP|UNION|TRANSACTION)\b|(?i:active_plugins|_options\b|base64_decode|gzinflate|str_rot13|\beval\b|\bassert\b|create_function|shell_exec|passthru|\bsystem\b|proc_open|file_put_contents|add_filter|add_action|get_option|update_option)/';

	/** Web-server roots a spreader walks to find other installs. */
	private const SERVER_ROOTS = array( '/var/www/vhosts', '/var/www/html', '/var/www', '/srv/www', '/srv/users', '/usr/local/www', '/home' );

	/**
	 * F18 to F23. Returns argument lists for the scan()'s finding closure.
	 *
	 * @return array<int,array{0:string,1:string,2:string,3?:array}>
	 */
	private function self_heal_family( string $bytes ): array {
		$out = array();

		// F18: a file that rewrites itself, then backdates and locks the
		// result. The sample restores from an option into __FILE__, touch()es
		// it into the past and chmods it 0444. Writing to __FILE__ alone is
		// rare but not unheard of in self-updaters, so MEDIUM; with the
		// backdate or the lock it is the sample's restore routine.
		$writes_self = preg_match( '/\bfile_put_contents\s*\(\s*__FILE__\b/', $bytes )
			|| preg_match( '/\b(?:copy|rename)\s*\([^;]{0,200}?,\s*__FILE__\s*\)/', $bytes );
		$backdates   = (bool) preg_match( '/\btouch\s*\(\s*__FILE__\s*,/', $bytes );
		$locks       = (bool) preg_match( '/\bchmod\s*\(\s*__FILE__\s*,\s*0?444\s*\)/', $bytes );
		if ( $writes_self ) {
			if ( $backdates || $locks ) {
				$out[] = array( 'F18', 'critical', 'Rewrites its own file, then ' . implode( ' and ', array_filter( array( $backdates ? 'backdates it' : '', $locks ? 'locks it read-only (0444)' : '' ) ) ), array( 'backdates' => $backdates, 'locks' => $locks ) );
			} else {
				$out[] = array( 'F18', 'medium', 'Writes to its own file (__FILE__)' );
			}
		}

		// F19: the string cipher. A lookup loop (strpos of one character of
		// a string in an alphabet) beside an alphabet built from twenty or more
		// short fragments. The fragments exist so no grep finds the alphabet;
		// that is the tell.
		if ( preg_match( '/\bstrpos\s*\(\s*\$\w+\s*,\s*\$\w+\s*\[\s*\$\w+\s*\]\s*\)/', $bytes )
			&& preg_match( '/(?:(?:\'[^\'\n]{1,6}\'|"[^"\n]{1,6}")\s*\.\s*){20,}/', $bytes ) ) {
			$out[] = array( 'F19', 'high', 'Substitution-cipher string decoder: a per-character alphabet lookup over an alphabet assembled from 20+ fragments' );
		}

		// F20: hex-escaped words. "\x55P\x44\x41\x54\x45" is UPDATE. Decode
		// every double-quoted literal carrying two or more \x escapes and see
		// whether it spells a query or a sensitive call. Binary data decodes
		// to nothing readable and stays quiet.
		if ( preg_match_all( '/"((?:[^"\\\\\n]|\\\\.){0,200}?\\\\x[0-9A-Fa-f]{2}(?:[^"\\\\\n]|\\\\.){0,200}?)"/', $bytes, $mm ) ) {
			$decoded = array();
			foreach ( $mm[1] as $lit ) {
				if ( preg_match_all( '/\\\\x[0-9A-Fa-f]{2}/', $lit ) < 2 ) {
					continue;
				}
				$plain = stripcslashes( $lit );
				if ( preg_match( self::HIDDEN_WORDS, $plain ) ) {
					$decoded[] = substr( $plain, 0, 60 );
				}
			}
			if ( $decoded ) {
				$decoded = array_values( array_unique( $decoded ) );
				$out[] = array( 'F20', 'high', 'Hex-escaped strings that decode to a query or a sensitive call: ' . implode( ', ', array_slice( $decoded, 0, 3 ) ), array( 'decoded' => array_slice( $decoded, 0, 10 ) ) );
			}
		}

		// F21: a spreader. Three or more web-server roots in one file that also
		// names mu-plugins in a string (a comment does not count): it is
		// looking for other WordPress installs to copy itself into. On shared
		// hosting, one infection becomes all of them.
		$roots = array();
		foreach ( self::SERVER_ROOTS as $r ) {
			if ( preg_match( '#[\'"]' . preg_quote( $r, '#' ) . '/?[\'"]#', $bytes ) ) {
				$roots[] = $r;
			}
		}
		if ( count( $roots ) >= 3 && preg_match( '/[\'"][^\'"\n]*mu-plugins/', $bytes ) ) {
			$out[] = array( 'F21', 'high', 'Walks web-server roots (' . implode( ', ', $roots ) . ') looking for mu-plugins to write into', array( 'roots' => $roots ) );
		}

		// F22: a payment-credential harvester. Payment names (the gateway
		// constants or WooCommerce's gateway settings) together with reading
		// wp-config.php and/or .env / .git/config. A payment plugin names the
		// gateway and never reads wp-config.php as text; a backup plugin
		// reads wp-config.php and never cares which gateway you use.
		$payment = (bool) preg_match( '/\(\?:[A-Z|]*(?:STRIPE|BRAINTREE|AUTHNET)[A-Z|]*\)|woocommerce_(?:stripe|braintree|authorize_net\w*)_settings/', $bytes );
		$config  = (bool) preg_match( '/[\'"][^\'"]*wp-config\.php[\'"]/', $bytes ) && (bool) preg_match( '/\bfile_get_contents\s*\(|\bfile\s*\(|\bfopen\s*\(/', $bytes );
		$secrets = (bool) preg_match( '/[\'"][^\'"]*(?:\/\.env|\.git\/config)[\'"]|[\'"]\.env[\'"]/', $bytes );
		if ( $payment && ( $config || $secrets ) ) {
			$out[] = array( 'F22', $config && $secrets ? 'critical' : 'high', 'Collects payment credentials: gateway names with ' . implode( ' and ', array_filter( array( $config ? 'wp-config.php read as text' : '', $secrets ? '.env / .git/config' : '' ) ) ), array( 'config' => $config, 'secrets' => $secrets ) );
		}

		// F23: active_plugins written with raw SQL. WordPress's own path is
		// update_option(); going around it (with a row lock, in the sample)
		// is how a plugin reactivates itself without firing activated_plugin.
		// SQL shape, in capitals: UPDATE <table> SET ... active_plugins, or a
		// row lock on it. Case-insensitive, a scan of a real compromised install showed it firing on
		// "Update plugin loading order" comments and update_option(
		// 'active_plugins' ) in Akismet, Freemius and Gravity Perks.
		if ( preg_match( '/\bUPDATE\s+\S+\s+SET\b[^;]{0,300}?active_plugins|active_plugins[^;]{0,300}?\bFOR\s+UPDATE\b/s', $bytes ) ) {
			$out[] = array( 'F23', 'high', 'Writes active_plugins with raw SQL, bypassing activation' );
		}

		return $out;
	}

	/**
	 * Distinct request keys, as written: $_POST['elem'], $_REQUEST[$value].
	 * A key held in a variable counts as one key per variable name.
	 */
	private static function request_keys( string $bytes ): array {
		if ( ! preg_match_all( '/\$_(POST|REQUEST|COOKIE)\s*\[\s*(?:[\'"]([^\'"]+)[\'"]|(\$\w+))\s*\]/', $bytes, $m, PREG_SET_ORDER ) ) {
			return array();
		}
		$keys = array();
		foreach ( $m as $k ) {
			$keys[] = '$_' . $k[1] . '[' . ( '' !== ( $k[3] ?? '' ) ? $k[3] : "'{$k[2]}'" ) . ']';
		}
		return array_values( array_unique( $keys ) );
	}

	/**
	 * F10. Two shapes seen on the network:
	 *   (function(){var k=NN; ... =[n,n,n,...]; ... ^ ...    (decoder IIFE)
	 *   window['_0123456789ab']                             (run-once flag)
	 * Reports the byte offset, and whether it sits after real content, because
	 * "appended to home-slider.js" and "is the whole of main.js" are different
	 * cleanup steps.
	 */
	public static function loader_structure( string $bytes ): ?array {
		$offset = null;
		$shape  = null;
		// The numeric array starts within the first 1 KB of the IIFE; the XOR
		// comes after the array, however long it is. The real loader's array
		// runs ~7.8 KB and its XOR sits ~8.1 KB in: a scan of a real compromised install found a
		// 4 KB window and a required closing bracket missing both builds.
		if ( preg_match( '/\(function\s*\(\)\s*\{\s*var\s+[A-Za-z_$][\w$]*\s*=\s*\d+\s*;/', $bytes, $m, PREG_OFFSET_CAPTURE ) ) {
			$start  = $m[0][1];
			$head   = substr( $bytes, $start, 1024 );
			$window = substr( $bytes, $start, 16384 );
			if ( preg_match( '/=\s*\[\s*\d+\s*(?:,\s*\d+\s*){7,}/', $head ) && preg_match( '/\^/', $window ) ) {
				$offset = $start;
				$shape  = 'decoder-iife';
			}
		}
		if ( null === $offset && preg_match( '/window\s*\[\s*[\'"]_[0-9a-f]{10}[\'"]\s*\]/', $bytes, $m, PREG_OFFSET_CAPTURE ) ) {
			$offset = $m[0][1];
			$shape  = 'run-once-flag';
		}
		if ( null === $offset ) {
			return null;
		}
		$before = trim( substr( $bytes, 0, $offset ) );
		return array(
			'shape'    => $shape,
			'offset'   => $offset,
			'appended' => strlen( $before ) > 256,
		);
	}

	/** F12 second clause: an EVM address within 2 KB of any RPC-looking host. */
	private static function address_near_rpc( string $bytes ): ?array {
		if ( ! preg_match_all( '/0x[0-9a-fA-F]{40}\b/', $bytes, $addrs, PREG_OFFSET_CAPTURE ) ) {
			return null;
		}
		if ( ! preg_match_all( '/[a-z0-9.-]*(?:rpc|publicnode|ankr\.com|drpc\.org|blastapi|quiknode|tenderly|nodies|mainnet\.base\.org|cloudflare-eth|merkle\.io|infura\.io|alchemy\.com)[a-z0-9.\/-]*/i', $bytes, $hosts, PREG_OFFSET_CAPTURE ) ) {
			return null;
		}
		foreach ( $addrs[0] as $a ) {
			foreach ( $hosts[0] as $h ) {
				if ( abs( $a[1] - $h[1] ) <= 2048 ) {
					return array( 'address' => $a[0], 'host' => $h[0], 'distance' => abs( $a[1] - $h[1] ) );
				}
			}
		}
		return null;
	}

	private function script_allowed( string $arg ): bool {
		$arg = strtolower( trim( $arg, " \t\n\r\0\x0B'\"" ) );
		foreach ( $this->sig->allow_list( 'f15_service_worker_scripts' ) as $ok ) {
			if ( '' !== $ok && str_contains( $arg, strtolower( $ok ) ) ) {
				return true;
			}
		}
		return false;
	}

	public static function under( string $rel_path, string $prefix ): bool {
		$p = strtolower( ltrim( str_replace( '\\', '/', $rel_path ), '/' ) );
		return str_starts_with( $p, $prefix ) || str_contains( $p, '/' . $prefix );
	}
}
