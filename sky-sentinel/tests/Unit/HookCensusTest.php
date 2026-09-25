<?php
/**
 * L10: who is on the hiding and password hooks, decided by where the
 * callback's FILE lives. The source of the Wordfence-reported mu-plugin is
 * cipher-obfuscated, so these tests never look at source text: they register
 * callables, the way WordPress would hold them, and ask the census.
 */

function sentinel_census(array $allowed = array()): Sky_Sentinel_Hook_Census {
    return new Sky_Sentinel_Hook_Census('wp-content', 'wp-content/mu-plugins', 'wp-content/mu-plugins/sky-sentinel', $allowed);
}

function sentinel_census_root(): string {
    return realpath(__DIR__ . '/../fixtures/census');
}

/** Load a census fixture once; the files declare functions, so a second require would be fatal. */
function sentinel_census_load(string $rel) {
    static $loaded = array();
    return $loaded[$rel] ??= require sentinel_census_root() . '/' . $rel;
}

/** A WP_Hook-shaped object: the only thing collect() reads is ->callbacks. */
function sentinel_hook(array $by_priority): object {
    $h = new stdClass();
    $h->callbacks = array();
    foreach ($by_priority as $priority => $list) {
        foreach ($list as $i => $pair) {
            $h->callbacks[$priority]["cb{$i}"] = array('function' => $pair[0], 'accepted_args' => $pair[1]);
        }
    }
    return $h;
}

function sentinel_row(string $hook, string $file, int $args = 1, int $priority = 10, string $cb = 'cb'): array {
    return array('hook' => $hook, 'priority' => $priority, 'accepted_args' => $args, 'callback' => $cb, 'file' => $file);
}

function sentinel_census_severities(array $findings): array {
    $out = array();
    foreach ($findings as $f) { $out[$f->subject] = $f->severity; }
    ksort($out);
    return $out;
}

test('collect() resolves functions, methods, static strings and closures to files relative to the root', function () {
    $root = sentinel_census_root();
    $mu   = sentinel_census_load('wp-content/mu-plugins/site-health-reporter.php');
    $core = sentinel_census_load('wp-includes/user.php');
    $wp_filter = array(
        'authenticate'          => sentinel_hook(array(20 => array(array($core, 3)), 999 => array(array($mu['harvest'], 3)))),
        'pre_user_query'        => sentinel_hook(array(10 => array(array($mu['query'], 1)))),
        'views_users'           => sentinel_hook(array(10 => array(array($mu['views'], 1)))),
        'show_advanced_plugins' => sentinel_hook(array(10 => array(array($mu['mustuse'], 2)))),
        'rest_user_query'       => sentinel_hook(array(10 => array(array($mu['rest'], 2)))),
        'the_content'           => sentinel_hook(array(10 => array(array($mu['query'], 1)))), // not watched
        'all_plugins'           => sentinel_hook(array(10 => array(array('strtolower', 1)))), // PHP's own
    );
    $rows = Sky_Sentinel_Hook_Census::collect($wp_filter, $root);
    $seen = array_map(fn($r) => "{$r['hook']} {$r['priority']} {$r['callback']} " . ($r['file'] ?? 'internal'), $rows);
    sort($seen);
    expect($seen)->toBe(array(
        'all_plugins 10 strtolower internal',
        'authenticate 20 sentinel_fixture_census_core_auth wp-includes/user.php',
        'authenticate 999 sentinel_fixture_census_harvest wp-content/mu-plugins/site-health-reporter.php',
        'pre_user_query 10 sentinel_fixture_census_hide_query wp-content/mu-plugins/site-health-reporter.php',
        'rest_user_query 10 {closure} wp-content/mu-plugins/site-health-reporter.php',
        'show_advanced_plugins 10 Sentinel_Fixture_Census_Hider::mustuse wp-content/mu-plugins/site-health-reporter.php',
        'views_users 10 Sentinel_Fixture_Census_Hider::views wp-content/mu-plugins/site-health-reporter.php',
    ));
});

test('the Wordfence mu-plugin shape, end to end: every hook it sits on is CRITICAL, and core is silent', function () {
    $root = sentinel_census_root();
    $mu   = sentinel_census_load('wp-content/mu-plugins/site-health-reporter.php');
    $core = sentinel_census_load('wp-includes/user.php');
    $wp_filter = array(
        'authenticate'          => sentinel_hook(array(20 => array(array($core, 3)), 999 => array(array($mu['harvest'], 3)))),
        'pre_user_query'        => sentinel_hook(array(10 => array(array($mu['query'], 1)))),
        'views_users'           => sentinel_hook(array(10 => array(array($mu['views'], 1)))),
        'show_advanced_plugins' => sentinel_hook(array(10 => array(array($mu['mustuse'], 2)))),
        'rest_user_query'       => sentinel_hook(array(10 => array(array($mu['rest'], 2)))),
    );
    $f = sentinel_census()->classify(Sky_Sentinel_Hook_Census::collect($wp_filter, $root));
    $file = 'wp-content/mu-plugins/site-health-reporter.php';
    expect(sentinel_census_severities($f))->toBe(array(
        "hook:authenticate:{$file}"          => 'critical',
        "hook:pre_user_query:{$file}"        => 'critical',
        "hook:rest_user_query:{$file}"       => 'critical',
        "hook:show_advanced_plugins:{$file}" => 'critical',
        "hook:views_users:{$file}"           => 'critical',
    ));
    $auth = array_values(array_filter($f, fn($x) => $x->detail['hook'] === 'authenticate'))[0];
    expect($auth->detector)->toBe('L10')
        ->and($auth->summary)->toContain('plaintext password')
        ->and($auth->detail['priorities'])->toBe(array(999))
        ->and($auth->detail['also_on'])->toContain('pre_user_query');
});

test('a lone plugin on pre_user_query is MEDIUM: a role editor is inventory, not an incident', function () {
    $root = sentinel_census_root();
    $cb   = sentinel_census_load('wp-content/plugins/members/members.php');
    $rows = Sky_Sentinel_Hook_Census::collect(array('pre_user_query' => sentinel_hook(array(10 => array(array($cb, 1))))), $root);
    $f    = sentinel_census()->classify($rows);
    expect($f)->toHaveCount(1)->and($f[0]->severity)->toBe('medium')->and($f[0]->detail['location'])->toBe('plugin');
});

test('severity follows where the file lives', function () {
    $c = sentinel_census();
    $f = $c->classify(array(
        sentinel_row('all_plugins', 'wp-content/plugins/hide-my-plugins/hide.php'),
        sentinel_row('all_plugins', 'wp-content/themes/flashy/functions.php'),
        sentinel_row('all_plugins', 'wp-content/advanced-cache.php'),
        sentinel_row('all_plugins', 'wp-content/uploads/2026/09/x.php'),
        sentinel_row('all_plugins', '?', 1, 10, 'unresolvable'),
    ));
    expect(sentinel_census_severities($f))->toBe(array(
        'hook:all_plugins:?'                                        => 'critical',
        'hook:all_plugins:wp-content/advanced-cache.php'            => 'critical',
        'hook:all_plugins:wp-content/plugins/hide-my-plugins/hide.php' => 'medium',
        'hook:all_plugins:wp-content/themes/flashy/functions.php'   => 'high',
        'hook:all_plugins:wp-content/uploads/2026/09/x.php'         => 'critical',
    ));
});

test('a plugin that reads passwords AND hides users is CRITICAL even as a plugin', function () {
    $f = sentinel_census()->classify(array(
        sentinel_row('authenticate', 'wp-content/plugins/perf-helper/perf-helper.php', 3, 999),
        sentinel_row('views_users', 'wp-content/plugins/perf-helper/perf-helper.php'),
    ));
    expect(array_unique(array_map(fn($x) => $x->severity, $f)))->toBe(array('critical'));
});

test('a plugin on two hiding hooks is CRITICAL; the classic admin-hider is pre_count_users + all_plugins', function () {
    $f = sentinel_census()->classify(array(
        sentinel_row('pre_count_users', 'wp-content/plugins/wp-security-helper/wp-security-helper.php'),
        sentinel_row('all_plugins', 'wp-content/plugins/wp-security-helper/wp-security-helper.php'),
    ));
    expect($f)->toHaveCount(2)->and(array_unique(array_map(fn($x) => $x->severity, $f)))->toBe(array('critical'));
});

test('authenticate without the password argument is not a finding; with it, from a plugin, it is MEDIUM', function () {
    // Two-factor and LDAP plugins sit on authenticate and do need the
    // password; the allow-list names them. A callback that never asks for
    // the third argument cannot read it.
    $f = sentinel_census()->classify(array(
        sentinel_row('authenticate', 'wp-content/plugins/limit-logins/l.php', 2, 30),
        sentinel_row('authenticate', 'wp-content/plugins/ldap-login/ldap.php', 3, 20),
        sentinel_row('wp_authenticate_user', 'wp-content/plugins/captcha/c.php', 1),
    ));
    expect(sentinel_census_severities($f))->toBe(array('hook:authenticate:wp-content/plugins/ldap-login/ldap.php' => 'medium'));
});

test('core, Sentinel itself, PHP internals and allow-listed files are never findings', function () {
    $f = sentinel_census(array('plugins/wordfence/'))->classify(array(
        sentinel_row('authenticate', 'wp-includes/user.php', 3, 20),
        sentinel_row('views_users', 'wp-admin/includes/class-wp-users-list-table.php'),
        sentinel_row('all_plugins', 'wp-content/mu-plugins/sky-sentinel/includes/x.php'),
        array('hook' => 'all_plugins', 'priority' => 10, 'accepted_args' => 1, 'callback' => 'strtolower', 'file' => null),
        sentinel_row('authenticate', 'wp-content/plugins/wordfence/lib/wordfenceClass.php', 3, 1),
        sentinel_row('pre_user_query', 'wp-content/plugins/wordfence/lib/wordfenceClass.php'),
    ));
    expect($f)->toBe(array());
});

test('one file on one hook at two priorities is one finding', function () {
    $f = sentinel_census()->classify(array(
        sentinel_row('views_users', 'wp-content/mu-plugins/x.php', 1, 10),
        sentinel_row('views_users', 'wp-content/mu-plugins/x.php', 1, 999),
    ));
    expect($f)->toHaveCount(1)->and($f[0]->detail['priorities'])->toBe(array(10, 999));
});

test('the shipped allow-list has a hook_census_files list for each install to fill', function () {
    expect(sentinel_signatures()->allow_list('hook_census_files'))->toBeArray();
});

test('L12: a cron schedule that was not there at signing is HIGH, named, with its interval', function () {
    $f = Sky_Sentinel_Hook_Census::diff_schedules(
        array('hourly', 'twicedaily', 'daily', 'weekly', 'sky_sentinel_minute'),
        array(
            'hourly' => array('interval' => 3600, 'display' => 'Once Hourly'),
            'daily' => array('interval' => 86400, 'display' => 'Once Daily'),
            'jf_7xc5bj9trbgji' => array('interval' => 3600, 'display' => 'jf_7xc5bj9trbgji'),
        )
    );
    expect($f)->toHaveCount(1)->and($f[0]->detector)->toBe('L12')->and($f[0]->severity)->toBe('high')
        ->and($f[0]->subject)->toBe('cron_schedule:jf_7xc5bj9trbgji')
        ->and($f[0]->detail)->toBe(array('interval' => 3600, 'display' => 'jf_7xc5bj9trbgji'));
});

test('L12: a schedule that went away is not a finding', function () {
    expect(Sky_Sentinel_Hook_Census::diff_schedules(array('hourly', 'old_plugin_5min'), array('hourly' => array())))->toBe(array());
});

test('Gravity Forms widening the user picker on its own settings screen is allow-listed, by that one file only', function () {
    // GF 2.10.5 hooks rest_user_query to UNSET has_published_posts when the
    // referer is its form-settings screen: it shows more users, not fewer.
    // Found by L10 on a live multisite, 2026-09-24. The rest of Gravity Forms is not excused.
    $c = new Sky_Sentinel_Hook_Census('wp-content', 'wp-content/mu-plugins', 'wp-content/mu-plugins/sky-sentinel', sentinel_signatures()->allow_list('hook_census_files'));
    expect($c->classify(array(sentinel_row('rest_user_query', 'wp-content/plugins/gravityforms/includes/settings/class-gf-settings-service-provider.php', 2))))->toBe(array())
        ->and($c->classify(array(sentinel_row('rest_user_query', 'wp-content/plugins/gravityforms/includes/other.php', 2))))->toHaveCount(1);
});
