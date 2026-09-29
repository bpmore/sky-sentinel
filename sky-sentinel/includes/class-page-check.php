<?php
/**
 * The rendered-page check (plan 3.5): what a visitor's browser actually
 * receives.
 *
 * This is the one check that is indifferent to WHERE an injection lives.
 * File, database, widget, object cache, page cache, CDN, a plugin assembling
 * it at runtime: the browser gets HTML, and the loader is in the HTML or it
 * is not. The twentyseventeen/functions.php injection was invisible to a scan
 * of .js files and would have been caught here on the first fetch.
 *
 * analyze() is pure: HTML in, findings out, plus the script inventory (every
 * external src and the hash of every inline block) so the baseline can say
 * "this is what the page loaded when it was last declared clean" and the next
 * run can report additions. fetch() is injected so a test can hand it a
 * string and production can hand it wp_remote_get.
 */
final class Sky_Sentinel_Page_Check {

	public const MAX_SCRIPTS = 25;

	private Sky_Sentinel_Content_Detectors $content;
	private Sky_Sentinel_Signatures $sig;
	/** @var callable(string $url, array $headers): array{code:int, body:string, headers:array<string,string>}|null */
	private $fetch;

	/**
	 * Why a network site is left out of the page check, or null if it is
	 * checked. Archived, deactivated ("deleted") and spam sites show visitors
	 * WordPress's suspended notice, not their pages. Networks often archive a
	 * site as a holding step before deleting it, and a retired site's domain
	 * may lapse and be re-registered by a stranger: then Sentinel fetches
	 * someone else's domain every hour, and waits out a ten-second timeout on
	 * each attempt the live sites needed the time for. Only this
	 * check skips them: their files, options, content and administrators are
	 * still scanned, because a holding site's data is exactly what is kept.
	 *
	 * @param object $site a WP_Site, or anything with archived / deleted / spam
	 */
	public static function skip_reason( object $site ): ?string {
		foreach ( array( 'archived', 'deleted' => 'deactivated', 'spam' ) as $flag => $word ) {
			$flag = is_int( $flag ) ? $word : $flag;
			if ( ! empty( $site->{$flag} ) && '0' !== (string) $site->{$flag} ) {
				return $word;
			}
		}
		return null;
	}

	public function __construct( Sky_Sentinel_Signatures $sig, callable $fetch ) {
		$this->sig     = $sig;
		$this->content = new Sky_Sentinel_Content_Detectors( $sig );
		$this->fetch   = $fetch;
	}

	/**
	 * One URL as a visitor: no cache, then (optionally) through the cache
	 * without the buster, because the cache can be serving something the
	 * origin no longer has.
	 *
	 * @param string[] $baseline_srcs   external script srcs recorded when last clean (null: no baseline)
	 * @param string[] $baseline_inline sha256 of inline scripts when last clean
	 * @return array{findings: Sky_Sentinel_Finding[], inventory: array{srcs: string[], inline: string[]}, fetched: bool}
	 */
	public function check( string $url, string $label, ?array $baseline_srcs, ?array $baseline_inline, int $blog_id = 0 ): array {
		$findings  = array();
		$inventory = array( 'srcs' => array(), 'inline' => array() );

		$raw   = ( $this->fetch )( self::bust( $url ), array( 'Cache-Control' => 'no-cache', 'Pragma' => 'no-cache' ) );
		$fresh = $this->accept( $raw );
		if ( null === $fresh ) {
			$code = (int) ( $raw['code'] ?? 0 );
			$why  = 0 === $code ? (string) ( $raw['error'] ?? 'no response' ) : "HTTP {$code}";
			// A login page that answers 401 or 403 to a stranger is protected,
			// which is a hardening step, not a problem. Recorded, not raised.
			$refused = in_array( $code, array( 401, 403 ), true ) && str_ends_with( $label, ':login' );
			// 410 is a site saying "gone, on purpose". A retired subsite is a
			// fact to record, not a page to worry about.
			$retired = 410 === $code;
			$sev     = $refused || $retired ? 'info' : 'medium';
			$what    = $refused ? "Login page refuses visitors ({$why})" : ( $retired ? "Site answers 410 Gone: retired ({$url})" : "Could not fetch {$url} as a visitor ({$why})" );
			$findings[] = new Sky_Sentinel_Finding( 'P0', $sev, "page:{$label}", $what, array( 'url' => $url, 'code' => $code, 'error' => (string) ( $raw['error'] ?? '' ) ), null, $blog_id );
			return array( 'findings' => $findings, 'inventory' => $inventory, 'fetched' => false );
		}
		$r = $this->analyze( $fresh['body'], $url, $label, $baseline_srcs, $baseline_inline, $blog_id );
		$findings  = $r['findings'];
		$inventory = $r['inventory'];

		// The same URL through the cache. If the two differ in what scripts
		// they load, the cache is serving a page the origin no longer makes.
		$cached = $this->get( $url, array() );
		if ( null !== $cached && $cached['body'] !== $fresh['body'] ) {
			$c = self::script_inventory( $cached['body'], $url );
			$extra = array_diff( $c['srcs'], $inventory['srcs'] );
			if ( $extra ) {
				$findings[] = new Sky_Sentinel_Finding( 'P4', 'high', "page:{$label}", 'The cached copy loads scripts the fresh page does not: ' . implode( ', ', array_slice( $extra, 0, 5 ) ), array( 'cached_only' => array_values( $extra ) ), null, $blog_id );
			}
			foreach ( $this->content->scan_any( "page/{$label}/cached.html", $cached['body'] ) as $f ) {
				if ( in_array( $f->detector, array( 'F9', 'F10', 'F11', 'F12', 'F14', 'F15' ), true ) ) {
					$findings[] = new Sky_Sentinel_Finding( 'P1', $f->severity, "page:{$label}:cached", "Cached page: {$f->summary}", $f->detail, $f->sha256, $blog_id );
				}
			}
		}

		// Every same-origin script the page references, scanned too. Cross-
		// origin ones are named in the inventory but never fetched: Sentinel
		// does not contact hosts it does not own.
		$origin = self::origin( $url );
		$n = 0;
		foreach ( $inventory['srcs'] as $src ) {
			if ( $n >= self::MAX_SCRIPTS ) {
				break;
			}
			if ( self::origin( $src ) !== $origin ) {
				continue;
			}
			$n++;
			$js = $this->get( self::bust( $src ), array( 'Cache-Control' => 'no-cache' ) );
			if ( null === $js ) {
				continue;
			}
			$path = (string) parse_url( $src, PHP_URL_PATH );
			foreach ( $this->content->scan_any( 'served' . $path, $js['body'] ) as $f ) {
				if ( in_array( $f->detector, array( 'F9', 'F10', 'F11', 'F12', 'F14', 'F15' ), true ) ) {
					$findings[] = new Sky_Sentinel_Finding( 'P2', $f->severity, "script:{$path}", "Served script: {$f->summary}", $f->detail, $f->sha256, $blog_id );
				}
			}
			// A .js allowed to control the whole origin as a service worker.
			foreach ( $js['headers'] as $h => $v ) {
				if ( 'service-worker-allowed' === strtolower( $h ) ) {
					$findings[] = new Sky_Sentinel_Finding( 'P3', 'high', "script:{$path}", "Served with Service-Worker-Allowed: {$v}", array( 'header' => $v ), null, $blog_id );
				}
			}
		}

		return array( 'findings' => $findings, 'inventory' => $inventory, 'fetched' => true );
	}

	/**
	 * Pure. The HTML of one page against the detectors and the baseline.
	 */
	public function analyze( string $html, string $url, string $label, ?array $baseline_srcs, ?array $baseline_inline, int $blog_id = 0 ): array {
		$findings  = array();
		$inventory = self::script_inventory( $html, $url );

		foreach ( $this->content->scan_any( "page/{$label}.html", $html ) as $f ) {
			if ( in_array( $f->detector, array( 'F9', 'F10', 'F11', 'F12', 'F14', 'F15' ), true ) ) {
				$findings[] = new Sky_Sentinel_Finding( 'P1', $f->severity, "page:{$label}", "Rendered page: {$f->summary}", $f->detail, $f->sha256, $blog_id );
			}
		}

		if ( null !== $baseline_srcs ) {
			foreach ( array_diff( $inventory['srcs'], $baseline_srcs ) as $src ) {
				$host = strtolower( (string) parse_url( $src, PHP_URL_HOST ) );
				$same = self::origin( $src ) === self::origin( $url );
				$sev  = $same || $this->sig->allowed( 'd2_script_hosts', $host ) ? 'medium' : 'high';
				$findings[] = new Sky_Sentinel_Finding( 'P4', $sev, "page:{$label}", "Loads a script that was not there when last clean: {$src}", array( 'src' => $src ), null, $blog_id );
			}
		}
		if ( null !== $baseline_inline ) {
			$new = array_diff( $inventory['inline'], $baseline_inline );
			if ( $new ) {
				$findings[] = new Sky_Sentinel_Finding( 'P4', 'medium', "page:{$label}:inline", count( $new ) . ' inline script block(s) not present when last clean', array( 'hashes' => array_values( $new ) ), null, $blog_id );
			}
		}
		return array( 'findings' => $findings, 'inventory' => $inventory );
	}

	/** Every <script src> resolved to absolute, and sha256 of every inline <script> body. */
	public static function script_inventory( string $html, string $base_url ): array {
		$srcs   = array();
		$inline = array();
		if ( preg_match_all( '/<script\b([^>]*)>(.*?)<\/script\s*>/is', $html, $m, PREG_SET_ORDER ) ) {
			foreach ( $m as $s ) {
				if ( preg_match( '/\bsrc\s*=\s*["\']?([^"\'\s>]+)/i', $s[1], $src ) ) {
					$srcs[] = self::absolutize( html_entity_decode( $src[1] ), $base_url );
				} else {
					$body = trim( $s[2] );
					if ( '' !== $body && ! preg_match( '/type\s*=\s*["\'](?:application\/(?:ld\+)?json|text\/template)/i', $s[1] ) ) {
						$inline[] = hash( 'sha256', $body );
					}
				}
			}
		}
		$srcs = array_values( array_unique( $srcs ) );
		sort( $srcs );
		$inline = array_values( array_unique( $inline ) );
		sort( $inline );
		return array( 'srcs' => $srcs, 'inline' => $inline );
	}

	public static function absolutize( string $src, string $base ): string {
		if ( preg_match( '#^https?://#i', $src ) ) {
			return $src;
		}
		$b = parse_url( $base );
		$scheme = $b['scheme'] ?? 'https';
		$host   = $b['host'] ?? '';
		if ( str_starts_with( $src, '//' ) ) {
			return $scheme . ':' . $src;
		}
		if ( str_starts_with( $src, '/' ) ) {
			return "{$scheme}://{$host}{$src}";
		}
		$dir = rtrim( dirname( $b['path'] ?? '/' ), '/' );
		return "{$scheme}://{$host}{$dir}/{$src}";
	}

	public static function origin( string $url ): string {
		$u = parse_url( $url );
		return strtolower( ( $u['scheme'] ?? 'https' ) . '://' . ( $u['host'] ?? '' ) );
	}

	public static function bust( string $url ): string {
		return $url . ( str_contains( $url, '?' ) ? '&' : '?' ) . 'sentinel=' . time();
	}

	private function get( string $url, array $headers ): ?array {
		return $this->accept( ( $this->fetch )( $url, $headers ) );
	}

	private function accept( $r ): ?array {
		if ( ! is_array( $r ) || ( $r['code'] ?? 0 ) < 200 || ( $r['code'] ?? 0 ) >= 400 || ! is_string( $r['body'] ?? null ) ) {
			return null;
		}
		// The whole body: scan_any() reads a big one as its first and last
		// MB. Until 0.4.7 this kept the first MB only, and the loader is
		// appended at the end.
		$r['headers'] = (array) ( $r['headers'] ?? array() );
		return $r;
	}
}
