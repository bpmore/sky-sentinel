<?php
/**
 * L10: who is listening on the hooks a hider or a password thief needs.
 *
 * The mu-plugin in Wordfence's September 2026 write-up hides every hook name,
 * option key and path behind a substitution cipher, so no text signature
 * finds add_filter('authenticate', ...) in its source. But once it has run,
 * the callback is sitting in $wp_filter like any other, and Reflection says
 * which file it came from. This class reads that answer: every callback on a
 * short list of hooks, resolved to a file, and classified by where the file
 * lives. The source can be as obfuscated as it likes; the registration
 * cannot be.
 *
 * Pure. collect() takes a $wp_filter-shaped array (WP_Hook objects or
 * anything with a public `callbacks` property); classify() takes the rows
 * collect() produced. Neither calls WordPress.
 */
final class Sky_Sentinel_Hook_Census {

	/**
	 * Hooks that remove things from what an administrator sees. Each one is
	 * something a documented admin-hider in this family or the Wordfence write-up used.
	 */
	public const HIDING_HOOKS = array(
		'pre_user_query',        // appends user_login != '...' to the Users query
		'rest_user_query',       // login__not_in on /wp/v2/users
		'views_users',           // subtracts one from the All / Administrator counts
		'pre_count_users',       // the family's classic admin-hider
		'show_advanced_plugins', // unsets itself from the Must-Use list
		'all_plugins',           // unsets itself from the Plugins list
	);

	/**
	 * Hooks that are handed the plaintext password, and how many accepted
	 * arguments a callback needs to receive it. The Wordfence sample sat on
	 * authenticate at priority 999 with three arguments and wrote every
	 * administrator's password into an option.
	 */
	public const PASSWORD_HOOKS = array(
		'authenticate'         => 3,
		'wp_authenticate_user' => 2,
		'wp_authenticate'      => 2,
	);

	private string $content_rel;
	private string $mu_rel;
	private string $self_rel;
	/** @var string[] path fragments that are excused, as allowlist.json hook_census_files */
	private array $allowed;

	/**
	 * @param string   $content_rel wp-content relative to the root, e.g. "wp-content"
	 * @param string   $mu_rel      mu-plugins relative to the root
	 * @param string   $self_rel    Sentinel's own directory relative to the root
	 * @param string[] $allowed     path fragments whose callbacks are known and excused
	 */
	public function __construct( string $content_rel, string $mu_rel, string $self_rel, array $allowed = array() ) {
		$this->content_rel = trim( $content_rel, '/' );
		$this->mu_rel      = trim( $mu_rel, '/' );
		$this->self_rel    = trim( $self_rel, '/' );
		$this->allowed     = array_values( array_filter( array_map( fn( $a ) => strtolower( (string) $a ), $allowed ) ) );
	}

	/** Every hook this census reads. */
	public static function hooks(): array {
		return array_merge( self::HIDING_HOOKS, array_keys( self::PASSWORD_HOOKS ) );
	}

	/**
	 * Flatten the watched hooks into rows, each callback resolved to a file.
	 *
	 * @param array  $wp_filter hook => WP_Hook (or an object with `callbacks`, or the callbacks array itself)
	 * @param string $root      Absolute path the returned files are made relative to.
	 * @return array<int,array{hook:string,priority:int,accepted_args:int,callback:string,file:?string}>
	 */
	public static function collect( array $wp_filter, string $root ): array {
		$root = rtrim( str_replace( '\\', '/', $root ), '/' ) . '/';
		$rows = array();
		foreach ( self::hooks() as $hook ) {
			if ( ! isset( $wp_filter[ $hook ] ) ) {
				continue;
			}
			$h         = $wp_filter[ $hook ];
			$callbacks = is_object( $h ) ? (array) ( $h->callbacks ?? array() ) : (array) $h;
			foreach ( $callbacks as $priority => $list ) {
				foreach ( (array) $list as $entry ) {
					if ( ! is_array( $entry ) || ! array_key_exists( 'function', $entry ) ) {
						continue;
					}
					list( $name, $file ) = self::describe( $entry['function'] );
					if ( null !== $file ) {
						$file = str_replace( '\\', '/', $file );
						$file = str_starts_with( $file, $root ) ? substr( $file, strlen( $root ) ) : $file;
					}
					$rows[] = array(
						'hook'          => $hook,
						'priority'      => (int) $priority,
						'accepted_args' => (int) ( $entry['accepted_args'] ?? 1 ),
						'callback'      => $name,
						'file'          => $file,
					);
				}
			}
		}
		return $rows;
	}

	/**
	 * A callable's printable name and the file it was defined in. The file is
	 * null for PHP's own functions (nothing to judge) and for anything
	 * Reflection cannot place, which classify() treats as suspect.
	 *
	 * @return array{0:string,1:?string}
	 */
	public static function describe( $callback ): array {
		try {
			if ( is_string( $callback ) && str_contains( $callback, '::' ) ) {
				$callback = explode( '::', $callback, 2 );
			}
			if ( is_array( $callback ) && 2 === count( $callback ) ) {
				$class = is_object( $callback[0] ) ? get_class( $callback[0] ) : (string) $callback[0];
				$ref   = new ReflectionMethod( $class, (string) $callback[1] );
				return array( $class . '::' . $callback[1], $ref->isInternal() ? null : (string) $ref->getFileName() );
			}
			if ( $callback instanceof Closure || is_string( $callback ) ) {
				$ref  = new ReflectionFunction( $callback );
				$name = $callback instanceof Closure ? '{closure}' : $callback;
				return array( $name, $ref->isInternal() ? null : (string) $ref->getFileName() );
			}
			if ( is_object( $callback ) && method_exists( $callback, '__invoke' ) ) {
				$ref = new ReflectionMethod( $callback, '__invoke' );
				return array( get_class( $callback ) . '::__invoke', (string) $ref->getFileName() );
			}
		} catch ( ReflectionException $e ) {
			return array( is_string( $callback ) ? $callback : 'unresolvable', '?' );
		}
		return array( 'unresolvable', '?' );
	}

	/**
	 * Where a file lives, in the words classify() decides by.
	 *
	 * @return string core|self|mu|dropin|plugin|theme|other|unknown
	 */
	public function location( ?string $file ): string {
		if ( null === $file ) {
			return 'core'; // PHP's own function
		}
		if ( '?' === $file || '' === $file ) {
			return 'unknown';
		}
		$file = ltrim( str_replace( '\\', '/', $file ), '/' );
		if ( str_starts_with( $file, 'wp-includes/' ) || str_starts_with( $file, 'wp-admin/' ) ) {
			return 'core';
		}
		if ( '' !== $this->self_rel && str_starts_with( $file, $this->self_rel . '/' ) ) {
			return 'self';
		}
		if ( '' !== $this->mu_rel && str_starts_with( $file, $this->mu_rel . '/' ) ) {
			return 'mu';
		}
		if ( Sky_Sentinel_FS_Checks::is_load_path( $file, $this->content_rel, $this->mu_rel ) ) {
			return 'dropin';
		}
		if ( str_starts_with( $file, $this->content_rel . '/plugins/' ) ) {
			return 'plugin';
		}
		if ( str_starts_with( $file, $this->content_rel . '/themes/' ) ) {
			return 'theme';
		}
		return 'other';
	}

	/**
	 * Decide. One finding per (hook, file): the question a human answers is
	 * "should this file be on this hook", and the same file on the same hook
	 * at two priorities is one answer.
	 *
	 * Severity by where the file lives, because that is what separates the
	 * incident from the inventory. A plugin on pre_user_query is often a
	 * role editor (MEDIUM: the digest); the same hook from mu-plugins, a
	 * drop-in, uploads or a file Reflection cannot place is CRITICAL. And
	 * one file on a password hook AND a hiding hook, or on two hiding hooks,
	 * is CRITICAL wherever it lives: that pairing is the whole of the
	 * Wordfence sample and of the family's classic admin-hider, and no ordinary
	 * plugin both reads passwords and hides users.
	 *
	 * @param array $rows as returned by collect()
	 * @return Sky_Sentinel_Finding[]
	 */
	public function classify( array $rows ): array {
		$by_file = array();
		foreach ( $rows as $r ) {
			$file = $r['file'];
			$loc  = $this->location( $file );
			if ( in_array( $loc, array( 'core', 'self' ), true ) || ( null !== $file && $this->is_allowed( $file ) ) ) {
				continue;
			}
			$reads_password = isset( self::PASSWORD_HOOKS[ $r['hook'] ] ) && $r['accepted_args'] >= self::PASSWORD_HOOKS[ $r['hook'] ];
			$hides          = in_array( $r['hook'], self::HIDING_HOOKS, true );
			if ( ! $reads_password && ! $hides ) {
				continue; // a password hook that never asks for the password
			}
			$key = (string) $file;
			$by_file[ $key ]['loc']                     = $loc;
			$by_file[ $key ]['hooks'][ $r['hook'] ][]   = $r;
			$by_file[ $key ]['password']                = ( $by_file[ $key ]['password'] ?? false ) || $reads_password;
			$by_file[ $key ]['hiding'][ $r['hook'] ]    = $hides || ( $by_file[ $key ]['hiding'][ $r['hook'] ] ?? false );
		}

		$out = array();
		foreach ( $by_file as $file => $info ) {
			$hiding_hooks = array_keys( array_filter( $info['hiding'] ) );
			$combination  = count( $hiding_hooks ) >= 2 || ( $info['password'] && $hiding_hooks );
			$severity     = $combination ? 'critical' : self::severity_for( $info['loc'] );
			foreach ( $info['hooks'] as $hook => $regs ) {
				$first = $regs[0];
				$what  = isset( self::PASSWORD_HOOKS[ $hook ] ) ? 'receives the plaintext password on' : 'can hide things from administrators on';
				$summary = "{$first['callback']} in {$file} {$what} {$hook}";
				if ( $combination ) {
					$summary .= ' (and the same file is on ' . implode( ', ', array_diff( array_keys( $info['hooks'] ), array( $hook ) ) ) . ')';
				}
				$out[] = new Sky_Sentinel_Finding( 'L10', $severity, "hook:{$hook}:{$file}", $summary, array(
					'hook'       => $hook,
					'file'       => $file,
					'location'   => $info['loc'],
					'callback'   => $first['callback'],
					'priorities' => array_values( array_unique( array_map( fn( $x ) => $x['priority'], $regs ) ) ),
					'args'       => $first['accepted_args'],
					'also_on'    => array_values( array_diff( array_keys( $info['hooks'] ), array( $hook ) ) ),
				) );
			}
		}
		return $out;
	}

	private static function severity_for( string $loc ): string {
		switch ( $loc ) {
			case 'plugin':
				return 'medium';
			case 'theme':
				return 'high';
			default: // mu, dropin, other, unknown
				return 'critical';
		}
	}

	private function is_allowed( string $file ): bool {
		$path = strtolower( ltrim( str_replace( '\\', '/', $file ), '/' ) );
		foreach ( $this->allowed as $fragment ) {
			if ( str_contains( $path, $fragment ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * L12: cron schedules registered since the baseline. The sample runs its
	 * restore, spread and check-in on its own schedule with a random name
	 * (jf_7xc5bj9trbgji in the write-up). A plugin update can add a schedule
	 * too, hence HIGH rather than CRITICAL, and the name is the finding so
	 * one acknowledgement covers it for good.
	 *
	 * @param string[]                         $was schedule names at signing
	 * @param array<string,array{interval?:int,display?:string}> $now wp_get_schedules()
	 * @return Sky_Sentinel_Finding[]
	 */
	public static function diff_schedules( array $was, array $now ): array {
		$out = array();
		foreach ( array_diff( array_keys( $now ), $was ) as $name ) {
			$s     = (array) $now[ $name ];
			$out[] = new Sky_Sentinel_Finding( 'L12', 'high', "cron_schedule:{$name}", "Cron schedule {$name} was not registered when the baseline was signed", array(
				'interval' => (int) ( $s['interval'] ?? 0 ),
				'display'  => (string) ( $s['display'] ?? '' ),
			) );
		}
		return $out;
	}
}
