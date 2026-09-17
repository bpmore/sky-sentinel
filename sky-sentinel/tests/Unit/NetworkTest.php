<?php
/**
 * Where a request came from. The lists are the campaign's published
 * indicators plus a test office range.
 */

function sentinel_net(array $allowed = array('10.30.0.0/16'), array $tor = array('185.220.101.5')): Sky_Sentinel_Network {
    $sig = sentinel_signatures();
    return new Sky_Sentinel_Network($sig->attacker_ips(), $sig->tooling_user_agents(), $allowed, $tor);
}

test('CIDR matching, v4 and v6, with the edge bits', function () {
    expect(Sky_Sentinel_Network::in_cidr('10.30.12.7', '10.30.0.0/16'))->toBeTrue()
        ->and(Sky_Sentinel_Network::in_cidr('10.31.0.1', '10.30.0.0/16'))->toBeFalse()
        ->and(Sky_Sentinel_Network::in_cidr('10.0.0.129', '10.0.0.128/25'))->toBeTrue()
        ->and(Sky_Sentinel_Network::in_cidr('10.0.0.127', '10.0.0.128/25'))->toBeFalse()
        ->and(Sky_Sentinel_Network::in_cidr('10.0.0.5', '10.0.0.5'))->toBeTrue()
        ->and(Sky_Sentinel_Network::in_cidr('2001:db8::1', '2001:db8::/32'))->toBeTrue()
        ->and(Sky_Sentinel_Network::in_cidr('2001:db9::1', '2001:db8::/32'))->toBeFalse()
        ->and(Sky_Sentinel_Network::in_cidr('not-an-ip', '10.0.0.0/8'))->toBeFalse()
        ->and(Sky_Sentinel_Network::in_cidr('10.0.0.1', '10.0.0.0/40'))->toBeFalse();
});

test('classification, worst thing first', function () {
    $sig = sentinel_signatures();
    $net = sentinel_net();
    $tooling = $sig->tooling_user_agents()[0];
    expect($net->classify('194.165.17.13', 'Mozilla/5.0 ordinary'))->toBe('attacker_ip')
        ->and($net->classify('10.30.1.1', $tooling))->toBe('tooling_ua')
        ->and($net->classify('185.220.101.5', 'Mozilla/5.0 ordinary'))->toBe('tor_exit')
        // 192.42.116.49 is on BOTH lists; the attacker list wins because it is the surer claim.
        ->and($net->classify('192.42.116.49', 'Mozilla/5.0 ordinary'))->toBe('attacker_ip')
        ->and($net->classify('8.8.8.8', 'Mozilla/5.0 ordinary'))->toBe('outside_allowed')
        ->and($net->classify('10.30.1.1', 'Mozilla/5.0 ordinary'))->toBe('ok');
    // The attacker's own IP with the tooling UA is attacker_ip: certainty wins.
    expect($net->classify('194.165.17.13', $tooling))->toBe('attacker_ip');
});

test('with no allow-list, an unknown address is ok, not outside', function () {
    // The allow-list may stay empty for a while on a new install. Empty must
    // mean "not configured", never "nobody is allowed".
    expect(sentinel_net(array())->classify('8.8.8.8', 'x'))->toBe('ok');
});

test('the network prefix a login is remembered by', function () {
    expect(Sky_Sentinel_Network::prefix_of('10.30.12.7'))->toBe('10.30.12.0/24')
        ->and(Sky_Sentinel_Network::prefix_of('2001:db8:1:2:3:4:5:6'))->toBe('2001:db8:1:2::/64')
        ->and(Sky_Sentinel_Network::prefix_of('garbage'))->toBe('garbage');
});

test('the client IP behind Cloudflare and nginx', function () {
    expect(Sky_Sentinel_Network::client_ip(array('REMOTE_ADDR' => '10.0.0.1', 'HTTP_CF_CONNECTING_IP' => '203.0.113.9', 'HTTP_X_FORWARDED_FOR' => '198.51.100.1, 10.0.0.1')))->toBe('203.0.113.9')
        ->and(Sky_Sentinel_Network::client_ip(array('REMOTE_ADDR' => '10.0.0.1', 'HTTP_X_FORWARDED_FOR' => '198.51.100.1, 10.0.0.1')))->toBe('198.51.100.1')
        ->and(Sky_Sentinel_Network::client_ip(array('REMOTE_ADDR' => '10.0.0.1', 'HTTP_CF_CONNECTING_IP' => 'not an ip')))->toBe('10.0.0.1')
        ->and(Sky_Sentinel_Network::client_ip(array()))->toBe('');
});
