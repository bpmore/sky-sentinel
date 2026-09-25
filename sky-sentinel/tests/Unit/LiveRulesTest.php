<?php
/**
 * L1 to L7 decided without WordPress.
 */

function sentinel_rules(array $allowed = array('10.30.0.0/16')): Sky_Sentinel_Live_Rules {
    return new Sky_Sentinel_Live_Rules(sentinel_net($allowed));
}

test('L1: a non-privileged login is nothing, whatever it looks like', function () {
    expect(sentinel_rules()->login('reader', false, '194.165.17.13', 'x', array(), true))->toBeNull();
});

test('L1: an administrator from an attacker address is CRITICAL', function () {
    $f = sentinel_rules()->login('alice', true, '194.165.17.13', 'Mozilla', array('10.30.0.0/24'), false);
    expect($f->detector)->toBe('L1')->and($f->severity)->toBe('critical')->and($f->summary)->toContain('known attacker');
});

test('L1: an administrator with the tooling user-agent is CRITICAL even from the office range', function () {
    $ua = sentinel_signatures()->tooling_user_agents()[1];
    $f = sentinel_rules()->login('alice', true, '10.30.1.1', $ua, array('10.30.1.0/24'), false);
    expect($f->severity)->toBe('critical')->and($f->summary)->toContain('tooling user-agent');
});

test('L1: outside the allow-list is HIGH; a first-seen network inside it is MEDIUM; a known network is silent', function () {
    $r = sentinel_rules();
    expect($r->login('alice', true, '8.8.8.8', 'Mozilla', array('10.30.1.0/24'), false)->severity)->toBe('high');
    expect($r->login('alice', true, '10.30.7.7', 'Mozilla', array('10.30.1.0/24'), false)->severity)->toBe('medium');
    expect($r->login('alice', true, '10.30.1.9', 'Mozilla', array('10.30.1.0/24'), false))->toBeNull();
});

test('L7: the wp_lang=en_US sequence on an otherwise clean login is HIGH', function () {
    // Every one of the attacker's logins opened with GET /wp-login.php?wp_lang=en_US.
    $f = sentinel_rules()->login('alice', true, '10.30.1.9', 'Mozilla', array('10.30.1.0/24'), true);
    expect($f->detector)->toBe('L7')->and($f->severity)->toBe('high');
});

test('L1 subject is login plus network, so one person on one network is one finding', function () {
    $a = sentinel_rules()->login('alice', true, '8.8.8.8', 'Mozilla', array(), false);
    $b = sentinel_rules()->login('alice', true, '8.8.8.9', 'Mozilla', array(), false);
    expect($a->fingerprint())->toBe($b->fingerprint());
});

test('L2: promotion and admin signup are always CRITICAL', function () {
    $r = sentinel_rules();
    expect($r->promoted('sysadmin2', 'set_user_role', 'alice')->severity)->toBe('critical')
        ->and($r->admin_signup('newadmin9', 'x@example.com', 'alice')->severity)->toBe('critical');
});

test('L3: install and activate are HIGH, deactivate MEDIUM, update INFO', function () {
    $r = sentinel_rules();
    expect($r->package('install', 'plugin', 'site-helper', 'alice', true)->severity)->toBe('high')
        ->and($r->package('install', 'plugin', 'site-helper', 'alice', true)->summary)->toContain('UPLOADED')
        ->and($r->package('activate', 'plugin', 'site-helper', 'alice', false)->severity)->toBe('high')
        ->and($r->package('switch_theme', 'theme', 'twentyseventeen', 'alice', false)->severity)->toBe('high')
        ->and($r->package('deactivate', 'plugin', 'wordfence', 'alice', false)->severity)->toBe('medium')
        ->and($r->package('update', 'plugin', 'akismet', 'wp-cron', false)->severity)->toBe('info');
});

test('L4 and L5: the editor and a file manager are CRITICAL, and the action regex knows the four managers', function () {
    $r = sentinel_rules();
    expect($r->editor_used('themes/example/functions.php', 'alice')->severity)->toBe('critical')
        ->and($r->file_manager('mk_file_folder_manager', 'alice', '1.2.3.4')->severity)->toBe('critical');
    foreach (array('mk_file_folder_manager', 'elfinder_connector', 'wp_file_manager_ajax', 'filester_run', 'fm_upload') as $a) {
        expect(Sky_Sentinel_Live_Rules::is_file_manager_action($a))->toBeTrue($a);
    }
    foreach (array('heartbeat', 'save-post', 'gf_submit', 'edit-theme-plugin-file') as $a) {
        expect(Sky_Sentinel_Live_Rules::is_file_manager_action($a))->toBeFalse($a);
    }
});

test('L7: ten failures in ten minutes is a burst; nine, or ten spread over an hour, is not', function () {
    $now = 1_000_000;
    expect(Sky_Sentinel_Live_Rules::is_burst(range($now - 500, $now, 50), $now))->toBeTrue()
        ->and(Sky_Sentinel_Live_Rules::is_burst(range($now - 400, $now, 50), $now))->toBeFalse()
        ->and(Sky_Sentinel_Live_Rules::is_burst(range($now - 3600, $now, 360), $now))->toBeFalse();
});

test('privileged means administrator anywhere or super admin', function () {
    expect(Sky_Sentinel_Live_Rules::is_privileged(array('editor'), false))->toBeFalse()
        ->and(Sky_Sentinel_Live_Rules::is_privileged(array('administrator'), false))->toBeTrue()
        ->and(Sky_Sentinel_Live_Rules::is_privileged(array(), true))->toBeTrue();
});

// ---- The self-healing mu-plugin family (Wordfence, 2026-09) ---------------

test('L2: an administrator\'s password set from cron or an anonymous request is CRITICAL', function () {
    $r = sentinel_rules();
    $cron = $r->password_set('alice', true, 'wp-cron', false, '2026-09-24T03:12');
    expect($cron->detector)->toBe('L2')->and($cron->severity)->toBe('critical')->and($cron->subject)->toBe('password:alice:2026-09-24T03:12')
        ->and($r->password_set('alice', true, 'anonymous', false, 'x')->severity)->toBe('critical');
});

test('L2: set by another logged-in user or WP-CLI is HIGH; the lost-password flow and non-administrators are silent', function () {
    $r = sentinel_rules();
    expect($r->password_set('alice', true, 'bob', false, 'x')->severity)->toBe('high')
        ->and($r->password_set('alice', true, 'wp-cli', false, 'x')->severity)->toBe('high')
        ->and($r->password_set('alice', true, 'anonymous', true, 'x'))->toBeNull()
        ->and($r->password_set('reader', false, 'wp-cron', false, 'x'))->toBeNull();
});

test('L11: a JSON-RPC eth_call leaving WordPress is CRITICAL, with the contract, selector and caller', function () {
    $body = '{"jsonrpc":"2.0","id":3,"method":"eth_call","params":[{"data":"0x3bc5de30","to":"0x' . str_repeat('ab', 20) . '"},"latest"]}';
    $f = sentinel_rules()->outbound_request('https://eth.llamarpc.com/', $body, array(), 'wp-content/mu-plugins/site-health-reporter.php');
    expect($f->detector)->toBe('L11')->and($f->severity)->toBe('critical')
        ->and($f->subject)->toBe('outbound:eth.llamarpc.com:wp-content/mu-plugins/site-health-reporter.php')
        ->and($f->detail['method'])->toBe('eth_call')
        ->and($f->detail['selector'])->toBe('0x3bc5de30')
        ->and($f->detail['contract'])->toBe('0x' . str_repeat('ab', 20))
        ->and($f->summary)->toContain('site-health-reporter.php');
});

test('L11: any request to a campaign gateway is CRITICAL even without a JSON-RPC body', function () {
    $f = sentinel_rules()->outbound_request('https://polygon-bor-rpc.publicnode.com/', 'x=1', sentinel_signatures()->rpc_hosts(), 'wp-content/themes/x/functions.php');
    expect($f->severity)->toBe('critical')->and($f->summary)->toContain('campaign RPC gateway');
    // A path-qualified gateway matches on its path, not just the host.
    expect(sentinel_rules()->outbound_request('https://rpc.ankr.com/polygon', '', array('rpc.ankr.com/polygon'), ''))->not->toBeNull()
        ->and(sentinel_rules()->outbound_request('https://rpc.ankr.com/eth', '', array('rpc.ankr.com/polygon'), ''))->toBeNull();
});

test('L11: the word eth_call in a webhook payload is not a JSON-RPC call; ordinary requests are silent', function () {
    // Sentinel's own Teams card for an F12 finding says "eth_call" in prose.
    $card = '{"type":"message","text":"F12 On-chain resolver call: eth_call in wp-content/themes/x/app.js"}';
    $r = sentinel_rules();
    expect($r->outbound_request('https://outlook.office.com/webhook/x', $card, sentinel_signatures()->rpc_hosts(), ''))->toBeNull()
        ->and($r->outbound_request('https://api.wordpress.org/plugins/update-check/1.1/', 'plugins=%7B%7D', sentinel_signatures()->rpc_hosts(), 'wp-includes/update.php'))->toBeNull();
});

test('L11: the caller is the first frame outside wp-includes and Sentinel\'s own hook class', function () {
    $root = '/srv/site';
    $trace = array(
        array('file' => '/srv/site/wp-content/mu-plugins/sky-sentinel/includes/class-live-hooks.php'),
        array('file' => '/srv/site/wp-includes/class-wp-hook.php'),
        array('file' => '/srv/site/wp-includes/plugin.php'),
        array('file' => '/srv/site/wp-includes/class-wp-http.php'),
        array('file' => '/srv/site/wp-includes/http.php'),
        array(),
        array('file' => '/srv/site/wp-content/mu-plugins/site-health-reporter.php'),
        array('file' => '/srv/site/wp-settings.php'),
    );
    expect(Sky_Sentinel_Live_Rules::caller_from_trace($trace, $root))->toBe('wp-content/mu-plugins/site-health-reporter.php')
        ->and(Sky_Sentinel_Live_Rules::caller_from_trace(array(array('file' => '/srv/site/wp-includes/http.php')), $root))->toBe('');
});

// ---- L6: only a real REST request is enumeration (0.4.4) ----------------
// On one multisite, 94% of L6 hits were internal user lookups made while
// Sentinel's own hourly page check rendered pages, counted against the
// server's own address.

test('L6: an anonymous GET of /wp/v2/users over REST is enumeration, a list or a single user', function () {
    expect(Sky_Sentinel_Live_Rules::is_enumeration(false, 'GET', '/wp/v2/users', true))->toBeTrue()
        ->and(Sky_Sentinel_Live_Rules::is_enumeration(false, 'GET', '/wp/v2/users/1', true))->toBeTrue()
        ->and(Sky_Sentinel_Live_Rules::is_enumeration(false, 'get', '/wp/v2/users', true))->toBeTrue();
});

test('L6: the same lookup made internally while rendering a page is not enumeration', function () {
    // No REST_REQUEST: a plugin or block called rest_do_request() during an
    // ordinary page load. The visitor asked for a page, not for users.
    expect(Sky_Sentinel_Live_Rules::is_enumeration(false, 'GET', '/wp/v2/users', false))->toBeFalse()
        ->and(Sky_Sentinel_Live_Rules::is_enumeration(false, 'GET', '/wp/v2/users/7', false))->toBeFalse();
});

test('L6: an author embedded in an anonymous REST request still counts, because it is a REST request reading users', function () {
    // /wp-json/wp/v2/posts?_embed dispatches /wp/v2/users/<id> inside a REST request.
    expect(Sky_Sentinel_Live_Rules::is_enumeration(false, 'GET', '/wp/v2/users/1', true))->toBeTrue();
});

test('L6: a logged-in user, a write, and other routes are never enumeration', function () {
    expect(Sky_Sentinel_Live_Rules::is_enumeration(true, 'GET', '/wp/v2/users', true))->toBeFalse()
        ->and(Sky_Sentinel_Live_Rules::is_enumeration(false, 'POST', '/wp/v2/users', true))->toBeFalse()
        ->and(Sky_Sentinel_Live_Rules::is_enumeration(false, 'GET', '/wp/v2/posts', true))->toBeFalse()
        ->and(Sky_Sentinel_Live_Rules::is_enumeration(false, 'GET', '/wp/v2/usersettings', true))->toBeFalse()
        ->and(Sky_Sentinel_Live_Rules::is_enumeration(false, 'GET', '/myplugin/v1/wp/v2/users', true))->toBeFalse();
});
