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
