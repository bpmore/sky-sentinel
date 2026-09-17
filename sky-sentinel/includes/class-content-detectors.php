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

	/** Files bigger than this are never read for content; S3/S4 still see them. */
	public const MAX_BYTES = 1048576;

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

		// F4: one POST key + a temp-dir probe + include of a variable. The
		// dropper's whole job in three features.
		$post_keys = self::post_keys( $bytes );
		$temp      = (bool) preg_match( self::TEMP_PROBE, $bytes );
		$inc_var   = (bool) preg_match( self::INCLUDE_VAR, $bytes );
		if ( 1 === count( $post_keys ) && $temp && $inc_var ) {
			$f( 'F4', 'high', 'Reads one $_POST key, probes a temp directory, and includes a variable', array( 'post_key' => $post_keys[0] ) );
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
		// inline script echoed from functions.php.
		$f9 = false;
		if ( ! $in_uploads && str_contains( $bytes, 'atob(' ) && str_contains( $bytes, 'new Function(' )
			&& ( str_contains( $bytes, 'fromCharCode' ) || str_contains( $bytes, 'charCodeAt' ) )
			&& ! $this->sig->allowed( 'f9_loader_structure', $rel_path ) ) {
			$f9 = true;
		}

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

		return $out;
	}

	/** Distinct $_POST keys read by string literal. */
	private static function post_keys( string $bytes ): array {
		if ( ! preg_match_all( '/\$_POST\s*\[\s*[\'"]([^\'"]+)[\'"]\s*\]/', $bytes, $m ) ) {
			return array();
		}
		return array_values( array_unique( $m[1] ) );
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
		if ( preg_match( '/\(function\s*\(\)\s*\{\s*var\s+[A-Za-z_$][\w$]*\s*=\s*\d+\s*;/', $bytes, $m, PREG_OFFSET_CAPTURE ) ) {
			$start  = $m[0][1];
			$window = substr( $bytes, $start, 4096 );
			if ( preg_match( '/=\s*\[\s*\d+\s*(?:,\s*\d+\s*){7,}\]/', $window ) && preg_match( '/\^/', $window ) ) {
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
		if ( ! preg_match_all( '/[a-z0-9.-]*(?:rpc|publicnode|ankr\.com|drpc\.org|blastapi|quiknode|tenderly|nodies|mainnet\.base\.org)[a-z0-9.\/-]*/i', $bytes, $hosts, PREG_OFFSET_CAPTURE ) ) {
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
