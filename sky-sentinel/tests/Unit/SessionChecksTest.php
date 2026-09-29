<?php
/**
 * D8 and D9 from the session_tokens usermeta, read without unserialize().
 */

function sentinel_session_blob(array $sessions): string {
    // Builds the exact shape WordPress writes, so the regex is tested against it.
    $parts = array();
    foreach ($sessions as $i => $s) {
        $inner = sprintf('a:4:{s:10:"expiration";i:%d;s:2:"ip";s:%d:"%s";s:2:"ua";s:%d:"%s";s:5:"login";i:%d;}',
            $s['expiration'], strlen($s['ip']), $s['ip'], strlen($s['ua']), $s['ua'], $s['login']);
        $parts[] = sprintf('s:64:"%s";%s', str_repeat(dechex($i), 64), $inner);
    }
    return 'a:' . count($sessions) . ':{' . implode('', $parts) . '}';
}

test('sessions are parsed out of the serialized map', function () {
    $blob = sentinel_session_blob(array(
        array('expiration' => 2_000_000_000, 'ip' => '10.30.1.1', 'ua' => 'Mozilla/5.0 (X11) Firefox', 'login' => 1_700_000_000),
        array('expiration' => 2_000_000_001, 'ip' => '2001:db8::1', 'ua' => 'UA "with" quotes', 'login' => 1_700_000_001),
    ));
    $s = Sky_Sentinel_Session_Checks::parse_sessions($blob);
    expect($s)->toHaveCount(2)
        ->and($s[0]['ip'])->toBe('10.30.1.1')
        ->and($s[1]['ip'])->toBe('2001:db8::1')
        ->and($s[0]['login'])->toBe(1_700_000_000);
});

test('a hostile blob with an object in it yields nothing dangerous and no crash', function () {
    $s = Sky_Sentinel_Session_Checks::parse_sessions('O:8:"stdClass":1:{s:3:"pwn";s:1:"x";}');
    expect($s)->toBe(array());
});

test('D9: a live session with the tooling user-agent is CRITICAL; an expired one is ignored', function () {
    $ua = sentinel_signatures()->tooling_user_agents()[0];
    $db = new Sentinel_Fake_DB();
    $db->answers = array('/session_tokens/' => array(
        array('user_login' => 'alice', 'meta_value' => sentinel_session_blob(array(
            array('expiration' => 2_000_000_000, 'ip' => '10.30.1.1', 'ua' => $ua, 'login' => 1_700_000_000),
            array('expiration' => 1_000, 'ip' => '194.165.17.13', 'ua' => 'x', 'login' => 900),
            array('expiration' => 2_000_000_000, 'ip' => '10.30.1.1', 'ua' => 'Mozilla/5.0 (X11) Firefox', 'login' => 1_700_000_000),
        ))),
    ));
    $f = (new Sky_Sentinel_Session_Checks($db, sentinel_net()))->run(array('alice'), 1_800_000_000);
    expect($f)->toHaveCount(1)->and($f[0]->detector)->toBe('D9')->and($f[0]->severity)->toBe('critical');
});

test('D8: a live session from outside the allow-list is HIGH, and the query is scoped to the privileged logins', function () {
    $db = new Sentinel_Fake_DB();
    $db->answers = array('/session_tokens/' => array(
        array('user_login' => 'bob', 'meta_value' => sentinel_session_blob(array(
            array('expiration' => 2_000_000_000, 'ip' => '8.8.8.8', 'ua' => 'Mozilla', 'login' => 1_700_000_000),
        ))),
    ));
    $f = (new Sky_Sentinel_Session_Checks($db, sentinel_net()))->run(array('bob', "o'brien"), 1_800_000_000);
    expect($f)->toHaveCount(1)->and($f[0]->detector)->toBe('D8')->and($f[0]->severity)->toBe('high');
    expect($db->queries[0])->toContain("'bob','o''brien'");
});

test('no privileged users means no query at all', function () {
    $db = new Sentinel_Fake_DB();
    expect((new Sky_Sentinel_Session_Checks($db, sentinel_net()))->run(array(), time()))->toBe(array())
        ->and($db->queries)->toBe(array());
});

test('D8 subject is the /24, so three Private Relay addresses are one finding', function () {
    $db = new Sentinel_Fake_DB();
    $db->answers = array('/session_tokens/' => array(
        array('user_login' => 'alice', 'meta_value' => sentinel_session_blob(array(
            array('expiration' => 2_000_000_000, 'ip' => '198.51.100.173', 'ua' => 'Safari', 'login' => 1),
            array('expiration' => 2_000_000_000, 'ip' => '198.51.100.174', 'ua' => 'Safari', 'login' => 2),
            array('expiration' => 2_000_000_000, 'ip' => '198.51.100.175', 'ua' => 'Safari', 'login' => 3),
        ))),
    ));
    $f = (new Sky_Sentinel_Session_Checks($db, sentinel_net()))->run(array('alice'), 1_800_000_000);
    $fps = array_unique(array_map(fn($x) => $x->fingerprint(), $f));
    expect($f)->toHaveCount(3)->and($fps)->toHaveCount(1);
});


test('D8: a live session from the same network as an attacker address is HIGH', function () {
    $db = new Sentinel_Fake_DB();
    $db->answers = array('/session_tokens/' => array(
        array('user_login' => 'alice', 'meta_value' => sentinel_session_blob(array(
            array('expiration' => 2_000_000_000, 'ip' => '194.165.17.0', 'ua' => 'Mozilla/5.0', 'login' => 1_700_000_000),
        ))),
    ));
    $f = (new Sky_Sentinel_Session_Checks($db, sentinel_net(array())))->run(array('alice'), 1_800_000_000);
    expect($f)->toHaveCount(1)->and($f[0]->detector)->toBe('D8')->and($f[0]->severity)->toBe('high');
});
