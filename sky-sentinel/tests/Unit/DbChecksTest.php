<?php
/**
 * D1 to D7 against a fake $wpdb. The fake answers each query from a map of
 * regexes, which is enough to prove that the SQL asks the right question and
 * that the comparison with the API answer is the finding.
 */

final class Sentinel_Fake_DB {
    public string $prefix = 'wp_';
    public string $base_prefix = 'wp_';
    public array $answers = array();
    public array $queries = array();

    private function answer(string $sql) {
        $this->queries[] = $sql;
        foreach ($this->answers as $pattern => $value) {
            if (preg_match($pattern, $sql)) {
                return $value;
            }
        }
        return null;
    }
    public function get_var(string $sql) { return $this->answer($sql); }
    public function get_col(string $sql): array { return (array) ($this->answer($sql) ?? array()); }
    public function get_results(string $sql): array {
        return array_map(fn($r) => (object) $r, (array) ($this->answer($sql) ?? array()));
    }
}

function sentinel_db_checks(Sentinel_Fake_DB $db, int $api_users = 3, array $api_plugins = array('akismet/akismet.php'), array $disk_plugins = array('akismet/akismet.php')): Sky_Sentinel_DB_Checks {
    return new Sky_Sentinel_DB_Checks($db, sentinel_signatures(), array(1), fn() => $api_users, fn() => $api_plugins, fn() => $disk_plugins);
}

function sentinel_clean_db(): Sentinel_Fake_DB {
    $db = new Sentinel_Fake_DB();
    $db->answers = array(
        '/COUNT\(\*\) FROM wp_users/' => 3,
        '/meta_key = \'site_admins\'/' => 'a:1:{i:0;s:5:"alice";}',
        '/option_name = \'active_plugins\'/' => 'a:1:{i:0;s:19:"akismet/akismet.php";}',
        '/option_name = \'template\'/' => 'example',
        '/option_name = \'stylesheet\'/' => 'example',
        '/meta_key = \'active_sitewide_plugins\'/' => 'a:1:{s:19:"akismet/akismet.php";i:1;}',
        '/LIKE \'%administrator%\'/' => array('alice', 'bob'),
    );
    return $db;
}

test('a clean database produces nothing', function () {
    $db = sentinel_clean_db();
    $checks = sentinel_db_checks($db);
    expect($checks->run($checks->inventory()))->toBe(array());
});

test('D1: the admin-hider option is CRITICAL, and a widget carrying a loader is caught by the content detectors', function () {
    $db = sentinel_clean_db();
    $db->answers = array('/FROM wp_options WHERE option_name IN/' => array(
        array('option_name' => '_pre_user_id', 'option_value' => '7'),
        array('option_name' => 'widget_custom_html', 'option_value' => sentinel_fixture('bad/loader-wholefile.js.txt')),
        array('option_name' => 'widget_text', 'option_value' => '<script>console.log(1)</script>'),
    )) + $db->answers;
    $f = sentinel_db_checks($db)->run(null);
    $by = array();
    foreach ($f as $x) { $by[$x->subject][] = $x->severity; }
    expect($by)->toHaveKey('wp_options._pre_user_id')->toHaveKey('wp_options.widget_custom_html')
        ->not->toHaveKey('wp_options.widget_text')
        ->and($by['wp_options._pre_user_id'])->toBe(array('critical'));
});

test('D2: a post loading a script from a stranger host, and one from an allow-listed host', function () {
    $db = sentinel_clean_db();
    $db->answers = array('/FROM wp_posts WHERE/' => array(
        array('id' => 5, 'body' => '<p>hi</p><script src="https://evil.example/x.js"></script>', 'kind' => 'post'),
        array('id' => 6, 'body' => '<script src="https://www.youtube.com/iframe_api"></script>', 'kind' => 'post'),
    )) + $db->answers;
    $f = sentinel_db_checks($db)->run(null);
    $subjects = array_map(fn($x) => $x->subject, $f);
    expect($subjects)->toBe(array('wp_post#5'))
        ->and($f[0]->summary)->toContain('evil.example');
});

test('D3: a pending administrator signup is HIGH; a stale ordinary one is MEDIUM', function () {
    $db = sentinel_clean_db();
    $db->answers = array('/FROM wp_signups WHERE active = 0/' => array(
        array('signup_id' => 522, 'user_login' => 'sysadmin2', 'user_email' => 'x@y.z', 'registered' => gmdate('Y-m-d H:i:s'), 'meta' => 'a:1:{s:8:"new_role";s:13:"administrator";}'),
        array('signup_id' => 523, 'user_login' => 'reader', 'user_email' => 'r@y.z', 'registered' => gmdate('Y-m-d H:i:s', time() - 90000), 'meta' => 'a:0:{}'),
        array('signup_id' => 524, 'user_login' => 'fresh', 'user_email' => 'f@y.z', 'registered' => gmdate('Y-m-d H:i:s'), 'meta' => 'a:0:{}'),
    )) + $db->answers;
    $f = sentinel_db_checks($db)->run(null);
    $by = array();
    foreach ($f as $x) { $by[$x->subject] = $x->severity; }
    expect($by)->toBe(array('signups#522' => 'high', 'signups#523' => 'medium'));
});

test('D4: an administrator who is not in the baseline is CRITICAL', function () {
    $db = sentinel_clean_db();
    $checks = sentinel_db_checks($db);
    $baseline = $checks->inventory();
    $db->answers['/LIKE \'%administrator%\'/'] = array('alice', 'bob', 'sysadmin2');
    $db->answers['/meta_key = \'site_admins\'/'] = 'a:2:{i:0;s:5:"alice";i:1;s:9:"sysadmin2";}';
    $f = $checks->run($baseline);
    $keys = array_map(fn($x) => $x->detector . ' ' . $x->subject . ' ' . $x->severity, $f);
    sort($keys);
    expect($keys)->toBe(array('D4 user:sysadmin2 critical', 'D4 user:sysadmin2 critical'));
});

test('D5: the table holds more users than count_users() admits', function () {
    $db = sentinel_clean_db();
    $f = sentinel_db_checks($db, api_users: 2)->run(null);
    expect($f)->toHaveCount(1)->and($f[0]->detector)->toBe('D5')->and($f[0]->severity)->toBe('critical')
        ->and($f[0]->detail)->toBe(array('db' => 3, 'api' => 2));
});

test('D6: a plugin on disk that get_plugins() does not list', function () {
    $db = sentinel_clean_db();
    $f = sentinel_db_checks($db, disk_plugins: array('akismet/akismet.php', 'wp-security-helper/wp-security-helper.php'))->run(null);
    expect($f)->toHaveCount(1)->and($f[0]->detector)->toBe('D6')->and($f[0]->subject)->toBe('plugin:wp-security-helper/wp-security-helper.php');
});

test('D7: a plugin activated, and a theme switched, since the baseline', function () {
    $db = sentinel_clean_db();
    $checks = sentinel_db_checks($db);
    $baseline = $checks->inventory();
    $db->answers['/option_name = \'active_plugins\'/'] = 'a:2:{i:0;s:19:"akismet/akismet.php";i:1;s:26:"site-helper/site-helper.php";}';
    $db->answers['/option_name = \'stylesheet\'/'] = 'twentyseventeen';
    $f = $checks->run($baseline);
    $keys = array_map(fn($x) => $x->detector . ' ' . $x->subject, $f);
    sort($keys);
    expect($keys)->toBe(array('D7 plugin:site-helper/site-helper.php', 'D7 stylesheet:twentyseventeen'));
});

test('serialized lists are read without unserialize(), and a hostile payload is inert', function () {
    // The database is attacker-written. unserialize() on it is an object
    // injection waiting to happen, so the reader is a regex.
    $hostile = 'O:8:"stdClass":1:{s:3:"pwn";s:1:"x";}a:1:{i:0;s:5:"alice";}';
    expect(Sky_Sentinel_DB_Checks::unserialize_list($hostile))->toBe(array('alice', 'pwn', 'x'));
    expect(Sky_Sentinel_DB_Checks::unserialize_map('a:2:{s:19:"akismet/akismet.php";i:1;s:5:"x/y.php";i:1;}'))->toBe(array('akismet/akismet.php' => true, 'x/y.php' => true));
});

test('D2: a stranger script host is MEDIUM; a campaign RPC host is CRITICAL', function () {
    // A site's embeds produce dozens of these. An inventory of embed hosts
    // belongs in the digest.
    $db = sentinel_clean_db();
    $db->answers = array('/FROM wp_posts WHERE/' => array(
        array('id' => 7, 'body' => '<script src="https://widgets.example-newsletter.com/w.js"></script>', 'kind' => 'post'),
        array('id' => 8, 'body' => '<script src="https://polygon-bor-rpc.publicnode.com/x.js"></script>', 'kind' => 'post'),
        array('id' => 9, 'body' => '<script src="https://connect.facebook.net/en_US/sdk.js"></script>', 'kind' => 'post'),
    )) + $db->answers;
    $f = sentinel_db_checks($db)->run(null);
    $by = array();
    foreach ($f as $x) { $by[$x->subject] = $x->severity; }
    expect($by)->toBe(array('wp_post#7' => 'medium', 'wp_post#8' => 'critical'));
});

test('on a single site, no query ever names sitemeta or signups', function () {
    // Those tables do not exist there. A query against them logs a database
    // error every six hours and finds nothing.
    $db = sentinel_clean_db();
    $checks = new Sky_Sentinel_DB_Checks($db, sentinel_signatures(), array(1), fn() => 3, fn() => array('akismet/akismet.php'), fn() => array('akismet/akismet.php'), false);
    $checks->run($checks->inventory());
    $bad = array_values(array_filter($db->queries, fn($q) => str_contains($q, 'sitemeta') || str_contains($q, 'signups')));
    expect($bad)->toBe(array());
    // ...and the blog-level checks still run.
    expect(array_filter($db->queries, fn($q) => str_contains($q, 'wp_options')))->not->toBe(array());
});

test('on a network, the same checks do ask sitemeta and signups', function () {
    $db = sentinel_clean_db();
    $checks = sentinel_db_checks($db);
    $checks->run($checks->inventory());
    expect(array_filter($db->queries, fn($q) => str_contains($q, 'sitemeta')))->not->toBe(array())
        ->and(array_filter($db->queries, fn($q) => str_contains($q, 'signups')))->not->toBe(array());
});

test('D5: a hider on pre_user_query leaves count_users() alone; the WP_User_Query count is what catches it', function () {
    // The Wordfence-reported mu-plugin appends user_login != '...' on
    // pre_user_query and fixes the Users-screen totals through views_users.
    // count_users() is raw SQL and never sees the filter, so it agrees with
    // the table. Only a real user query disagrees.
    $db = sentinel_clean_db();
    $checks = new Sky_Sentinel_DB_Checks($db, sentinel_signatures(), array(1), fn() => 3, fn() => array('akismet/akismet.php'), fn() => array('akismet/akismet.php'), true, fn() => 2);
    $f = $checks->run(null);
    expect($f)->toHaveCount(1)
        ->and($f[0]->detector)->toBe('D5')
        ->and($f[0]->subject)->toBe('users:query')
        ->and($f[0]->severity)->toBe('critical')
        ->and($f[0]->summary)->toContain('pre_user_query')
        ->and($f[0]->detail)->toBe(array('db' => 3, 'query' => 2));
});

test('D5: when both routes agree with the table, nothing; when both disagree, two findings that name the route', function () {
    $db = sentinel_clean_db();
    $ok = new Sky_Sentinel_DB_Checks($db, sentinel_signatures(), array(1), fn() => 3, fn() => array(), fn() => array(), true, fn() => 3);
    expect($ok->run(null))->toBe(array());
    $both = new Sky_Sentinel_DB_Checks($db, sentinel_signatures(), array(1), fn() => 2, fn() => array(), fn() => array(), true, fn() => 2);
    expect(array_map(fn($x) => $x->subject, $both->run(null)))->toBe(array('users', 'users:query'));
});

// ---- The self-healing mu-plugin family (Wordfence, 2026-09) ---------------

function sentinel_d1(array $rows): array {
    $db = sentinel_clean_db();
    $db->answers = array('/FROM wp_options WHERE option_name IN/' => $rows) + $db->answers;
    $by = array();
    foreach (sentinel_db_checks($db)->run(null) as $x) {
        if ($x->detector === 'D1') { $by[$x->subject] = $x->severity; }
    }
    ksort($by);
    return $by;
}

test('D1: the query asks for the family\'s names and for option values that are PHP', function () {
    $db = sentinel_clean_db();
    sentinel_db_checks($db)->run(null);
    $sql = implode("\n", array_filter($db->queries, fn($q) => str_contains($q, 'FROM wp_options WHERE option_name IN')));
    expect($sql)->toContain("'src'")->toContain("'ic'")->toContain("'sc_payload_persistent'")
        ->toContain("'_transient_sc_recover_check'")->toContain("LIKE '<?php%'");
});

test('D1: an option that stores a PHP file is CRITICAL whatever it is called, raw or serialized', function () {
    $src = "<?php\n/* Plugin Name: Site Health Reporter */\n" . str_repeat('// x', 20);
    expect(sentinel_d1(array(
        array('option_name' => 'src', 'option_value' => $src),
        array('option_name' => 'health_cache', 'option_value' => 's:' . strlen($src) . ':"' . $src . '";'),
        array('option_name' => 'widget_text', 'option_value' => 'a:1:{s:4:"text";s:40:"Use <?php echo 1; ?> in the template...";}'),
    )))->toBe(array('wp_options.health_cache' => 'critical', 'wp_options.src' => 'critical'));
});

test('D1: the sc_ throttles and the payload cache are CRITICAL by name', function () {
    expect(sentinel_d1(array(
        array('option_name' => '_transient_sc_recover_check', 'option_value' => '1'),
        array('option_name' => '_transient_timeout_sc_spread_interval', 'option_value' => '1790000000'),
        array('option_name' => 'sc_payload_persistent', 'option_value' => 'a:0:{}'),
    )))->toBe(array(
        'wp_options._transient_sc_recover_check'           => 'critical',
        'wp_options._transient_timeout_sc_spread_interval' => 'critical',
        'wp_options.sc_payload_persistent'                 => 'critical',
    ));
});

test('D1: one short name alone is MEDIUM; two together are the sample and CRITICAL', function () {
    expect(sentinel_d1(array(array('option_name' => 'ic', 'option_value' => 'a:0:{}'))))->toBe(array('wp_options.ic' => 'medium'));
    expect(sentinel_d1(array(
        array('option_name' => 'bu', 'option_value' => 'backup_k3x9qz'),
        array('option_name' => 'bp', 'option_value' => 'hunter2hunter2'),
    )))->toBe(array('wp_options.bp' => 'critical', 'wp_options.bu' => 'critical'));
});

test('D1: site meta that stores PHP is CRITICAL too', function () {
    $db = sentinel_clean_db();
    $db->answers = array('/FROM wp_sitemeta WHERE LENGTH/' => array(array('meta_key' => 'net_cache', 'meta_value' => "<?php\n" . str_repeat('// x', 20)))) + $db->answers;
    $f = array_values(array_filter(sentinel_db_checks($db)->run(null), fn($x) => $x->subject === 'sitemeta.net_cache'));
    expect($f)->toHaveCount(1)->and($f[0]->severity)->toBe('critical');
});

test('D10: an administrator named like the rogue account is HIGH, with no baseline; ordinary logins are not', function () {
    $db = sentinel_clean_db();
    $db->answers['/LIKE \'%administrator%\'/'] = array('alice', 'bob', 'backup_k3x9qz', 'admin_7Qp2Lm', 'admin_team', 'administrator', 'adm_12345');
    $f = array_values(array_filter(sentinel_db_checks($db)->run(null), fn($x) => $x->detector === 'D10'));
    $subjects = array_map(fn($x) => $x->subject . ' ' . $x->severity, $f);
    sort($subjects);
    expect($subjects)->toBe(array('user:admin_7Qp2Lm high', 'user:backup_k3x9qz high'));
});

test('stores_php() wants PHP at the very start, not a mention of it', function () {
    expect(Sky_Sentinel_DB_Checks::stores_php('<?php echo 1;'))->toBeTrue()
        ->and(Sky_Sentinel_DB_Checks::stores_php("  \n<?php echo 1;"))->toBeTrue()
        ->and(Sky_Sentinel_DB_Checks::stores_php('s:13:"<?php echo 1;";'))->toBeTrue()
        ->and(Sky_Sentinel_DB_Checks::stores_php('Put <?php at the top'))->toBeFalse()
        ->and(Sky_Sentinel_DB_Checks::stores_php('<?phpx'))->toBeFalse();
});
