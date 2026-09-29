<?php
/**
 * Signature files pasted into the settings page replace the shipped ones,
 * whole, after validation. A bad file must be refused, because a signature
 * file that parses to the wrong shape makes every hash check pass.
 */

test('an override replaces the shipped file whole', function () {
    $dir = dirname(__DIR__, 2) . '/signatures';
    $sig = Sky_Sentinel_Signatures::from_directory($dir, array(
        'hashes' => array('version' => '2026-10-01', 'hashes' => array(str_repeat('a', 64) => 'new variant')),
    ));
    expect($sig->known_bad(str_repeat('a', 64)))->toBe('new variant')
        // The shipped dropper A hash is GONE, not merged in: the override is the whole file.
        ->and($sig->known_bad('61fb226317c9c0065c76a0ead1ee72cd2375b0e2c1d16717255b51178d1dcabf'))->toBeNull()
        ->and($sig->version())->toContain('hashes 2026-10-01')
        // The other two files are still the shipped ones.
        ->and($sig->rpc_hosts())->toContain('1rpc.io/matic');
});

test('validation refuses the shapes that would blind a detector', function () {
    $v = fn($k, $d) => Sky_Sentinel_Signatures::validate_override($k, $d);
    expect($v('hashes', 'not json'))->toBe('not a JSON object')
        ->and($v('hashes', array('hashes' => array())))->toContain('version')
        ->and($v('hashes', array('version' => 'x')))->toContain('hashes')
        ->and($v('hashes', array('version' => 'x', 'hashes' => array('deadbeef' => 'short'))))->toContain('not a sha256')
        ->and($v('hashes', array('version' => 'x', 'hashes' => array(str_repeat('A', 64) => 'ok'))))->toBeNull()
        ->and($v('iocs', array('version' => 'x', 'strings' => array())))->toContain('rpc_hosts')
        ->and($v('iocs', array('version' => 'x', 'strings' => array(), 'rpc_hosts' => array(), 'attacker_ips' => array(), 'tooling_user_agents' => array(), 'contract_regex' => array('['))))->toContain('bad regex')
        ->and($v('iocs', array('version' => 'x', 'strings' => array(), 'rpc_hosts' => array(), 'attacker_ips' => array(), 'tooling_user_agents' => array())))->toBeNull()
        ->and($v('allowlist', array('version' => 'x', 'f5_write_then_include' => 'not a list')))->toContain('not a list')
        ->and($v('allowlist', array('version' => 'x', 'f5_write_then_include' => array(), '_notes' => 'free text')))->toBeNull()
        ->and($v('bogus', array('version' => 'x')))->toContain('unknown');
});

test('the shipped files pass their own validation', function () {
    $dir = dirname(__DIR__, 2) . '/signatures';
    foreach (Sky_Sentinel_Signatures::FILES as $key => $file) {
        expect(Sky_Sentinel_Signatures::validate_override($key, Sky_Sentinel_Signatures::read_json($dir . '/' . $file)))->toBeNull($file);
    }
});

test('plugin_dirs is optional in iocs, and must be a list when present', function () {
    $base = array('version' => 'x', 'strings' => array(), 'rpc_hosts' => array(), 'attacker_ips' => array(), 'tooling_user_agents' => array());
    expect(Sky_Sentinel_Signatures::validate_override('iocs', $base + array('plugin_dirs' => 'wp-security-helper')))->toContain('plugin_dirs')
        ->and(Sky_Sentinel_Signatures::validate_override('iocs', $base + array('plugin_dirs' => array('wp-security-helper'))))->toBeNull()
        ->and(sentinel_signatures()->plugin_dirs())->toContain('site-helper-bdcd2b1a9ff2');
});
