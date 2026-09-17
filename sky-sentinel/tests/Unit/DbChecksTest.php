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
