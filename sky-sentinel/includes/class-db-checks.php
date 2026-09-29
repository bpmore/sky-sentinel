<?php
/**
 * Database detectors D1 to D7: what is in the tables, compared with what
 * WordPress says is there.
 *
 * The hiding detectors (D5, D6) are the point of this file. The admin-hider on
 * the network filtered pre_user_query, views_users and all_plugins so that
 * wp-admin showed one fewer user and one fewer plugin than the database held.
 * The only defence against a lie told through the API is to ask the table
 * directly and compare. So every check here reads with raw SQL first and asks
 * the WordPress API second, and a mismatch IS the finding.
 *
 * Takes a $wpdb-shaped object and two callables for the API side, so the
 * whole file runs against a fake in tests and against the real thing in
 * production with no branch between them.
 */
final class Sky_Sentinel_DB_Checks {

	/** @var object with prefix, base_prefix, get_var(), get_col(), get_results() */
	private $db;
	private Sky_Sentinel_Content_Detectors $content;
	private Sky_Sentinel_Signatures $sig;
	/** @var callable(): int  what count_users() reports for the network */
	private $api_user_count;
	/**
	 * @var callable|null  (): int, what a WP_User_Query counts. count_users()
	 * and get_user_count() are raw SQL and never fire pre_user_query, which
	 * is the filter the Wordfence-reported mu-plugin uses to hide its admin.
	 * Only a real user query walks through that filter.
	 */
	private $api_query_count;
	/** @var callable(): string[]  plugin basenames get_plugins() reports */
	private $api_plugin_list;
	/** @var callable(): string[]  plugin basenames actually on disk */
	private $disk_plugin_list;
	/** @var int[] */
	private array $blog_ids;
	/**
	 * A single-site install has no sitemeta and no signups table. Queries
	 * against them would log a database error every run and find nothing;
	 * D3 and the network half of D1/D4/D7 simply do not apply there.
	 */
	private bool $multisite;

	public function __construct( $db, Sky_Sentinel_Signatures $sig, array $blog_ids, callable $api_user_count, callable $api_plugin_list, callable $disk_plugin_list, bool $multisite = true, ?callable $api_query_count = null ) {
		$this->db               = $db;
		$this->api_query_count  = $api_query_count;
		$this->multisite        = $multisite;
		$this->sig              = $sig;
		$this->content          = new Sky_Sentinel_Content_Detectors( $sig );
		$this->blog_ids         = $blog_ids ?: array( 1 );
		$this->api_user_count   = $api_user_count;
		$this->api_plugin_list  = $api_plugin_list;
		$this->disk_plugin_list = $disk_plugin_list;
	}

	/**
	 * @param array|null $baseline_inventory  admins, site_admins, active_plugins, active_sitewide_plugins, template, stylesheet (per blog)
	 * @return Sky_Sentinel_Finding[]
	 */
	public function run( ?array $baseline_inventory ): array {
		$out = array();
		foreach ( $this->d1_options() as $f ) {
			$out[] = $f;
		}
		foreach ( $this->d2_content() as $f ) {
			$out[] = $f;
		}
		if ( $this->multisite ) {
			foreach ( $this->d3_signups() as $f ) {
				$out[] = $f;
			}
		}
		foreach ( $this->d5_hidden_users() as $f ) {
			$out[] = $f;
		}
		foreach ( $this->d6_hidden_plugins() as $f ) {
			$out[] = $f;
		}
		foreach ( $this->d10_rogue_logins() as $f ) {
			$out[] = $f;
		}
		foreach ( $this->d11_campaign_plugins_active() as $f ) {
			$out[] = $f;
		}
		if ( null !== $baseline_inventory ) {
			foreach ( $this->d4_admin_set( $baseline_inventory ) as $f ) {
				$out[] = $f;
			}
			foreach ( $this->d7_active_set( $baseline_inventory ) as $f ) {
				$out[] = $f;
			}
		}
		return $out;
	}

	/** The inventory a baseline records, so D4/D7 have something to compare with next time. */
	public function inventory(): array {
		$inv = array(
			'site_admins' => $this->site_admins(),
			'blogs'       => array(),
		);
		foreach ( $this->blog_ids as $blog_id ) {
			$p = $this->prefix_for( $blog_id );
			$admins = $this->db->get_col( "SELECT u.user_login FROM {$this->db->base_prefix}users u INNER JOIN {$this->db->base_prefix}usermeta m ON m.user_id = u.ID WHERE m.meta_key = '{$p}capabilities' AND m.meta_value LIKE '%administrator%' ORDER BY u.user_login" );
			$inv['blogs'][ (string) $blog_id ] = array(
				'admins'         => array_values( (array) $admins ),
				'active_plugins' => $this->unserialize_list( $this->option( $p, 'active_plugins' ) ),
				'template'       => (string) $this->option( $p, 'template' ),
				'stylesheet'     => (string) $this->option( $p, 'stylesheet' ),
			);
		}
		$inv['active_sitewide_plugins'] = $this->multisite ? array_keys( $this->unserialize_map( $this->sitemeta( 'active_sitewide_plugins' ) ) ) : array();
		sort( $inv['active_sitewide_plugins'] );
		return $inv;
	}

	/**
	 * D1: option names the Wordfence-reported mu-plugin writes. The two sc_
	 * transients throttle its self-restore and its spreader; the payload
	 * option caches the command server's last answer.
	 */
	public const MU_FAMILY_OPTIONS = array(
		'sc_payload_persistent',
		'_transient_sc_recover_check', '_transient_timeout_sc_recover_check',
		'_transient_sc_spread_interval', '_transient_timeout_sc_spread_interval',
	);

	/**
	 * D1: its short names: src (its own source, for self-restore), bu and bp
	 * (the rogue administrator's login and password), ic (every
	 * administrator's plaintext password, captured at login). One of these
	 * alone could be anybody's; two together on one blog are the sample.
	 */
	public const MU_FAMILY_SHORT = array( 'src', 'bu', 'bp', 'ic' );

	/** D10: the rogue administrator's login, a fixed prefix and six random characters. */
	public const ROGUE_ADMIN_LOGIN = '/^(?:admin|adm|administrator|backup)_[A-Za-z0-9]{6}$/';

	// D1: options. The admin-hider's own names, the mu-plugin family's names,
	// PHP source stored as an option value, plus any option value that
	// carries a loader, a lure or an IOC. Widgets, custom HTML blocks, theme
	// mods and code-snippet plugins all store executable content here.
	private function d1_options(): array {
		$out   = array();
		$names = "'" . implode( "','", array_merge( array( '_pre_user_id' ), self::MU_FAMILY_OPTIONS, self::MU_FAMILY_SHORT ) ) . "'";
		foreach ( $this->blog_ids as $blog_id ) {
			$p    = $this->prefix_for( $blog_id );
			$rows = (array) $this->db->get_results( "SELECT option_name, option_value FROM {$p}options WHERE option_name IN ({$names}) OR option_name LIKE 'wsh\\_%' OR LENGTH(option_value) > 40 AND (option_value LIKE '<?php%' OR option_value LIKE 's:%:\"<?php%' OR option_value LIKE '%atob(%' OR option_value LIKE '%new Function(%' OR option_value LIKE '%serviceWorker%' OR option_value LIKE '%<script%' OR option_value LIKE '%eth_call%' OR option_value LIKE '%0x%')" );
			$short = array_values( array_intersect( self::MU_FAMILY_SHORT, array_map( fn( $r ) => (string) $r->option_name, $rows ) ) );
			foreach ( $rows as $row ) {
				$name    = (string) $row->option_name;
				$value   = (string) $row->option_value;
				$subject = "{$p}options.{$name}";
				if ( '_pre_user_id' === $name || str_starts_with( $name, 'wsh_' ) ) {
					$out[] = new Sky_Sentinel_Finding( 'D1', 'critical', $subject, 'Admin-hider option present', array(), null, $blog_id );
					continue;
				}
				if ( self::stores_php( $value ) ) {
					// Nothing legitimate keeps a PHP file in wp_options. The
					// sample keeps its whole source here and writes it back to
					// disk when the file is deleted: remove this BEFORE the file.
					$out[] = new Sky_Sentinel_Finding( 'D1', 'critical', $subject, 'Option stores PHP source: a self-restore copy', array( 'bytes' => strlen( $value ) ), hash( 'sha256', $value ), $blog_id );
					continue;
				}
				if ( in_array( $name, self::MU_FAMILY_OPTIONS, true ) ) {
					$out[] = new Sky_Sentinel_Finding( 'D1', 'critical', $subject, 'Option written by the self-healing mu-plugin family (Wordfence, 2026-09)', array(), null, $blog_id );
					continue;
				}
				if ( in_array( $name, self::MU_FAMILY_SHORT, true ) ) {
					$pair  = count( $short ) >= 2;
					$out[] = new Sky_Sentinel_Finding( 'D1', $pair ? 'critical' : 'medium', $subject, $pair ? 'Options ' . implode( ', ', $short ) . ' together: the mu-plugin family\'s source, rogue-admin and captured-password store' : "Option named {$name}, one of the mu-plugin family's names (alone, it may be innocent)", array( 'together' => $short ), null, $blog_id );
					continue;
				}
				foreach ( $this->content->scan( "options/{$name}.html", $value ) as $f ) {
					if ( in_array( $f->detector, array( 'F9', 'F10', 'F11', 'F12', 'F14', 'F15' ), true ) ) {
						$out[] = new Sky_Sentinel_Finding( 'D1', $f->severity, $subject, "Option value: {$f->summary}", $f->detail, $f->sha256, $blog_id );
					}
				}
			}
		}
		$rows = $this->multisite ? (array) $this->db->get_results( "SELECT meta_key, meta_value FROM {$this->db->base_prefix}sitemeta WHERE LENGTH(meta_value) > 40 AND (meta_value LIKE '<?php%' OR meta_value LIKE 's:%:\"<?php%' OR meta_value LIKE '%atob(%' OR meta_value LIKE '%new Function(%' OR meta_value LIKE '%<script%')" ) : array();
		foreach ( $rows as $row ) {
			if ( self::stores_php( (string) $row->meta_value ) ) {
				$out[] = new Sky_Sentinel_Finding( 'D1', 'critical', "sitemeta.{$row->meta_key}", 'Site meta stores PHP source: a self-restore copy', array( 'bytes' => strlen( (string) $row->meta_value ) ), hash( 'sha256', (string) $row->meta_value ) );
				continue;
			}
			foreach ( $this->content->scan( "sitemeta/{$row->meta_key}.html", (string) $row->meta_value ) as $f ) {
				if ( in_array( $f->detector, array( 'F9', 'F10', 'F11', 'F14', 'F15' ), true ) ) {
					$out[] = new Sky_Sentinel_Finding( 'D1', $f->severity, "sitemeta.{$row->meta_key}", "Site meta value: {$f->summary}", $f->detail, $f->sha256 );
				}
			}
		}
		return $out;
	}

	/** A value that is a PHP file, raw or as a serialized string. */
	public static function stores_php( string $value ): bool {
		return (bool) preg_match( '/\A(?:s:\d+:")?\s*<\?php\b/', $value );
	}

	// D10: an administrator whose login has the rogue account's shape. No
	// baseline needed. HIGH, not CRITICAL: backup_ plus six characters is
	// also what a person might pick. The sample hides the account from the
	// Users screen and from REST, so this reads the table.
	private function d10_rogue_logins(): array {
		$inv = $this->inventory();
		$out = array();
		$seen = array();
		foreach ( $inv['site_admins'] as $login ) {
			$seen[ $login ] = 0;
		}
		foreach ( $inv['blogs'] as $blog_id => $b ) {
			foreach ( $b['admins'] as $login ) {
				$seen[ $login ] ??= (int) $blog_id;
			}
		}
		foreach ( $seen as $login => $blog_id ) {
			if ( preg_match( self::ROGUE_ADMIN_LOGIN, (string) $login ) ) {
				$out[] = new Sky_Sentinel_Finding( 'D10', 'high', "user:{$login}", "Administrator {$login} has the rogue account's login shape (admin_ / adm_ / administrator_ / backup_ + 6 characters)", array(), null, $blog_id );
			}
		}
		return $out;
	}

	// D2: posts, postmeta and comments carrying a loader or a script from a
	// host nobody allow-listed.
	private function d2_content(): array {
		$out = array();
		foreach ( $this->blog_ids as $blog_id ) {
			$p    = $this->prefix_for( $blog_id );
			$rows = (array) $this->db->get_results( "SELECT ID AS id, post_content AS body, 'post' AS kind FROM {$p}posts WHERE post_content LIKE '%<script%' OR post_content LIKE '%atob(%' OR post_content LIKE '%serviceWorker%' UNION ALL SELECT meta_id, meta_value, 'postmeta' FROM {$p}postmeta WHERE meta_value LIKE '%<script%' OR meta_value LIKE '%atob(%' UNION ALL SELECT comment_ID, comment_content, 'comment' FROM {$p}comments WHERE comment_content LIKE '%<script%' OR comment_content LIKE '%atob(%'" );
			foreach ( $rows as $row ) {
				$subject = "{$p}{$row->kind}#{$row->id}";
				$body    = (string) $row->body;
				foreach ( $this->content->scan( "content/{$row->kind}-{$row->id}.html", $body ) as $f ) {
					if ( in_array( $f->detector, array( 'F9', 'F10', 'F11', 'F12', 'F14', 'F15' ), true ) ) {
						$out[] = new Sky_Sentinel_Finding( 'D2', $f->severity, $subject, "{$row->kind} content: {$f->summary}", $f->detail, $f->sha256, $blog_id );
					}
				}
				if ( preg_match_all( '/<script[^>]+src\s*=\s*[\'"]([^\'"]+)/i', $body, $m ) ) {
					foreach ( $m[1] as $src ) {
						$host = strtolower( (string) parse_url( $src, PHP_URL_HOST ) );
						if ( '' === $host || $this->sig->allowed( 'd2_script_hosts', $host ) ) {
							continue;
						}
						// A host on the campaign's RPC list is the campaign. Any
						// other stranger is an inventory line: a site's embeds
						// produce dozens of these, and dozens of HIGHs about a
						// calendar widget is how a mailbox learns to filter
						// Sentinel.
						$rpc = false;
						foreach ( $this->sig->rpc_hosts() as $known ) {
							if ( str_contains( $known, $host ) ) {
								$rpc = true;
							}
						}
						$out[] = new Sky_Sentinel_Finding( 'D2', $rpc ? 'critical' : 'medium', $subject, "{$row->kind} loads a script from {$host}", array( 'src' => $src ), null, $blog_id );
					}
				}
			}
		}
		return $out;
	}

	// D3: a pending signup for an administrator, and any signup that has sat
	// unactivated for a day. The attacker left row 522 behind.
	private function d3_signups(): array {
		$out  = array();
		$rows = (array) $this->db->get_results( "SELECT signup_id, user_login, user_email, registered, meta FROM {$this->db->base_prefix}signups WHERE active = 0" );
		foreach ( $rows as $row ) {
			$meta   = (string) $row->meta;
			$age_h  = ( time() - strtotime( (string) $row->registered ) ) / 3600;
			$is_adm = str_contains( $meta, 'administrator' );
			if ( $is_adm ) {
				$out[] = new Sky_Sentinel_Finding( 'D3', 'high', "signups#{$row->signup_id}", "Pending signup for an administrator: {$row->user_login} <{$row->user_email}>", array( 'registered' => $row->registered ) );
			} elseif ( $age_h > 24 ) {
				$out[] = new Sky_Sentinel_Finding( 'D3', 'medium', "signups#{$row->signup_id}", "Signup inactive for " . round( $age_h ) . "h: {$row->user_login}", array( 'registered' => $row->registered ) );
			}
		}
		return $out;
	}

	// D4: the administrator set moved since the baseline.
	private function d4_admin_set( array $baseline ): array {
		$out = array();
		$now = $this->inventory();
		$was = (array) ( $baseline['site_admins'] ?? array() );
		foreach ( array_diff( $now['site_admins'], $was ) as $login ) {
			$out[] = new Sky_Sentinel_Finding( 'D4', 'critical', "user:{$login}", 'Super admin not in the baseline' );
		}
		foreach ( array_diff( $was, $now['site_admins'] ) as $login ) {
			$out[] = new Sky_Sentinel_Finding( 'D4', 'high', "user:{$login}", 'Super admin removed since the baseline' );
		}
		foreach ( $now['blogs'] as $blog_id => $b ) {
			$was_admins = (array) ( $baseline['blogs'][ $blog_id ]['admins'] ?? array() );
			foreach ( array_diff( $b['admins'], $was_admins ) as $login ) {
				$out[] = new Sky_Sentinel_Finding( 'D4', 'critical', "user:{$login}", "Administrator on blog {$blog_id} not in the baseline", array(), null, (int) $blog_id );
			}
		}
		return $out;
	}

	// D5: hidden users. The table count against what WordPress admits to, by
	// two routes. count_users() catches a hider on pre_count_users (the
	// family's classic one); a WP_User_Query catches a hider on pre_user_query,
	// which leaves count_users() alone and fixes the Users-screen totals
	// through views_users instead (Wordfence, September 2026). One finding
	// per route that disagrees, so the summary says which filter is lying.
	private function d5_hidden_users(): array {
		$raw = (int) $this->db->get_var( "SELECT COUNT(*) FROM {$this->db->base_prefix}users" );
		$out = array();
		$api = (int) ( $this->api_user_count )();
		if ( $raw !== $api ) {
			$out[] = new Sky_Sentinel_Finding( 'D5', 'critical', 'users', "Database holds {$raw} users, WordPress reports {$api}: something is filtering the user query", array( 'db' => $raw, 'api' => $api ) );
		}
		if ( null !== $this->api_query_count ) {
			$query = (int) ( $this->api_query_count )();
			if ( $raw !== $query ) {
				$out[] = new Sky_Sentinel_Finding( 'D5', 'critical', 'users:query', "Database holds {$raw} users, a WP_User_Query returns {$query}: something on pre_user_query is hiding users", array( 'db' => $raw, 'query' => $query ) );
			}
		}
		return $out;
	}

	// D6: hidden plugins. Directories on disk against get_plugins().
	private function d6_hidden_plugins(): array {
		$disk = ( $this->disk_plugin_list )();
		$api  = ( $this->api_plugin_list )();
		$out  = array();
		foreach ( array_diff( $disk, $api ) as $basename ) {
			$out[] = new Sky_Sentinel_Finding( 'D6', 'critical', "plugin:{$basename}", 'Plugin exists on disk but is missing from get_plugins(): something is filtering all_plugins' );
		}
		return $out;
	}

	// D11: a campaign plugin, by name, in any blog's active_plugins or in
	// active_sitewide_plugins. Needs no baseline. D7 only reports what was
	// activated since one, and a baseline signed after the break-in would
	// hold these as normal: on one compromised multisite the main site had
	// both site-helper-bdcd2b1a9ff2 and wp-security-helper active.
	private function d11_campaign_plugins_active(): array {
		$out   = array();
		$known = $this->sig->plugin_dirs();
		$check = function ( string $plugin, string $where, int $blog_id ) use ( &$out, $known ) {
			$dir = str_contains( $plugin, '/' ) ? strstr( $plugin, '/', true ) : preg_replace( '/\.php$/i', '', $plugin );
			$why = Sky_Sentinel_FS_Checks::campaign_package_name( (string) $dir, $known );
			if ( null !== $why ) {
				$out[] = new Sky_Sentinel_Finding( 'D11', $why[0], "plugin:{$plugin}", "Active {$where}: {$why[1]}", array( 'plugin' => $plugin ), null, $blog_id );
			}
		};
		if ( $this->multisite ) {
			foreach ( array_keys( $this->unserialize_map( $this->sitemeta( 'active_sitewide_plugins' ) ) ) as $pl ) {
				$check( (string) $pl, 'network-wide', 0 );
			}
		}
		foreach ( $this->blog_ids as $blog_id ) {
			foreach ( $this->unserialize_list( $this->option( $this->prefix_for( $blog_id ), 'active_plugins' ) ) as $pl ) {
				$check( (string) $pl, "on blog {$blog_id}", (int) $blog_id );
			}
		}
		return $out;
	}

	// D7: what is active, and which theme, moved since the baseline.
	private function d7_active_set( array $baseline ): array {
		$out = array();
		$now = $this->inventory();
		foreach ( array_diff( $now['active_sitewide_plugins'], (array) ( $baseline['active_sitewide_plugins'] ?? array() ) ) as $pl ) {
			$out[] = new Sky_Sentinel_Finding( 'D7', 'high', "plugin:{$pl}", 'Network-activated since the baseline' );
		}
		foreach ( $now['blogs'] as $blog_id => $b ) {
			$was = (array) ( $baseline['blogs'][ $blog_id ] ?? array() );
			foreach ( array_diff( $b['active_plugins'], (array) ( $was['active_plugins'] ?? array() ) ) as $pl ) {
				$out[] = new Sky_Sentinel_Finding( 'D7', 'high', "plugin:{$pl}", "Activated on blog {$blog_id} since the baseline", array(), null, (int) $blog_id );
			}
			foreach ( array( 'template', 'stylesheet' ) as $k ) {
				if ( isset( $was[ $k ] ) && $was[ $k ] !== $b[ $k ] ) {
					$out[] = new Sky_Sentinel_Finding( 'D7', 'high', "{$k}:{$b[$k]}", "Theme {$k} changed on blog {$blog_id} (was {$was[$k]})", array(), null, (int) $blog_id );
				}
			}
		}
		return $out;
	}

	private function site_admins(): array {
		if ( ! $this->multisite ) {
			return array();
		}
		$list = $this->unserialize_list( $this->sitemeta( 'site_admins' ) );
		sort( $list );
		return $list;
	}

	private function prefix_for( int $blog_id ): string {
		return 1 === $blog_id ? $this->db->base_prefix : $this->db->base_prefix . $blog_id . '_';
	}

	private function option( string $prefix, string $name ) {
		return $this->db->get_var( "SELECT option_value FROM {$prefix}options WHERE option_name = '{$name}' LIMIT 1" );
	}

	private function sitemeta( string $key ) {
		return $this->db->get_var( "SELECT meta_value FROM {$this->db->base_prefix}sitemeta WHERE meta_key = '{$key}' LIMIT 1" );
	}

	/** A serialized list, read WITHOUT unserialize(): the data came from a database the attacker wrote. */
	public static function unserialize_list( $raw ): array {
		$raw = (string) $raw;
		if ( ! preg_match_all( '/s:\d+:"([^"]*)";/', $raw, $m ) ) {
			return array();
		}
		$list = array_values( array_unique( $m[1] ) );
		sort( $list );
		return $list;
	}

	/** A serialized string-keyed map: keys only, same reason. */
	public static function unserialize_map( $raw ): array {
		$raw = (string) $raw;
		$out = array();
		if ( preg_match_all( '/s:\d+:"([^"]*)";(?:i|s|b|d):/', $raw, $m ) ) {
			foreach ( $m[1] as $k ) {
				$out[ $k ] = true;
			}
		}
		return $out;
	}
}
