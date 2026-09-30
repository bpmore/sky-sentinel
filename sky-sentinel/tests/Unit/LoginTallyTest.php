<?php
/**
 * L13: the daily failed-login count. Written after a quiet night on
 * a live site that could not be told apart from Sentinel going deaf.
 */

const SENTINEL_T0 = 1790294400; // 2026-09-25 00:00:00 UTC

function sentinel_tally_fail(array $tally, string $ip, int $times, int $at): array {
    for ($i = 0; $i < $times; $i++) {
        $tally = Sky_Sentinel_Login_Tally::record($tally, $ip, $at + $i);
    }
    return $tally;
}

/** $per_day[k] failures on day T0 - k days, from one address each. */
function sentinel_tally_history(array $per_day, int $now): array {
    $tally = array();
    krsort($per_day);
    foreach ($per_day as $days_ago => $n) {
        $tally = sentinel_tally_fail($tally, '203.0.113.' . $days_ago, $n, $now - $days_ago * 86400 + 3600);
    }
    return $tally;
}

test('counts every failure by day, with distinct addresses and the busiest one', function () {
    $t = sentinel_tally_fail(array(), '198.51.100.7', 12, SENTINEL_T0 + 100);
    $t = sentinel_tally_fail($t, '198.51.100.8', 3, SENTINEL_T0 + 200);
    expect(Sky_Sentinel_Login_Tally::day($t, '2026-09-25'))->toBe(array(
        'total' => 15, 'distinct' => 2, 'capped' => false, 'top_ip' => '198.51.100.7', 'top_count' => 12,
    ))->and($t['since'])->toBe('2026-09-25');
});

test('a day with no failures reads as zeros, and days before counting began do not appear', function () {
    $t = sentinel_tally_fail(array(), '198.51.100.7', 1, SENTINEL_T0 - 86400 + 5);
    $recent = Sky_Sentinel_Login_Tally::recent($t, SENTINEL_T0 + 3600, 7);
    expect(array_keys($recent))->toBe(array('2026-09-25', '2026-09-24'))
        ->and($recent['2026-09-25']['total'])->toBe(0)
        ->and($recent['2026-09-24']['total'])->toBe(1);
});

test('a spray from many addresses stops growing the map at MAX_IPS but keeps the total', function () {
    $t = array();
    for ($i = 0; $i < Sky_Sentinel_Login_Tally::MAX_IPS + 50; $i++) {
        $t = Sky_Sentinel_Login_Tally::record($t, '10.0.' . intdiv($i, 250) . '.' . ($i % 250), SENTINEL_T0 + $i);
    }
    $d = Sky_Sentinel_Login_Tally::day($t, '2026-09-25');
    expect($d['total'])->toBe(Sky_Sentinel_Login_Tally::MAX_IPS + 50)
        ->and($d['distinct'])->toBe(Sky_Sentinel_Login_Tally::MAX_IPS)
        ->and($d['capped'])->toBeTrue();
});

test('only today and yesterday keep per-address maps; older days shrink to numbers; past KEEP_DAYS they go', function () {
    $t = array();
    foreach (array(20, 5, 1, 0) as $ago) {
        $t = sentinel_tally_fail($t, '198.51.100.' . $ago, 2, SENTINEL_T0 - $ago * 86400 + 60);
    }
    $t = Sky_Sentinel_Login_Tally::compact($t, SENTINEL_T0 + 60);
    expect(array_keys($t['days']))->toBe(array('2026-09-25', '2026-09-24', '2026-09-20'))
        ->and($t['days']['2026-09-25'])->toHaveKey('ips')
        ->and($t['days']['2026-09-24'])->toHaveKey('ips')
        ->and($t['days']['2026-09-20'])->not->toHaveKey('ips')
        ->and(Sky_Sentinel_Login_Tally::day($t, '2026-09-20'))->toBe(array('total' => 2, 'distinct' => 1, 'capped' => false, 'top_ip' => '198.51.100.5', 'top_count' => 2));
});

test('L13: zero failures yesterday after a week averaging QUIET_FLOOR or more is MEDIUM', function () {
    $now = SENTINEL_T0 + 7 * 3600; // digest time
    $t = sentinel_tally_history(array(8 => 40, 7 => 35, 6 => 50, 5 => 20, 4 => 30, 3 => 45, 2 => 25), $now);
    $f = Sky_Sentinel_Login_Tally::went_quiet($t, $now);
    expect($f->detector)->toBe('L13')->and($f->severity)->toBe('medium')
        ->and($f->subject)->toBe('logins-quiet:2026-09-24')
        ->and($f->detail)->toBe(array('date' => '2026-09-24', 'week_average' => 35.0))
        ->and($f->summary)->toContain('made-up username');
});

test('L13 is silent when yesterday had any failure, when the week was quiet anyway, and before a full week of counting', function () {
    $now = SENTINEL_T0 + 7 * 3600;
    $busy = array(8 => 40, 7 => 35, 6 => 50, 5 => 20, 4 => 30, 3 => 45, 2 => 25);
    expect(Sky_Sentinel_Login_Tally::went_quiet(sentinel_tally_history($busy + array(1 => 1), $now), $now))->toBeNull();
    expect(Sky_Sentinel_Login_Tally::went_quiet(sentinel_tally_history(array(8 => 9, 7 => 9, 6 => 9, 5 => 9, 4 => 9, 3 => 9, 2 => 9), $now), $now))->toBeNull();
    // Counting only began six days ago: no full week to compare with.
    expect(Sky_Sentinel_Login_Tally::went_quiet(sentinel_tally_history(array(6 => 400, 5 => 400, 4 => 400, 3 => 400, 2 => 400), $now), $now))->toBeNull();
});

test('the digest lines say the day, count, addresses and busiest address, and read sensibly before anything is counted', function () {
    $t = sentinel_tally_fail(array(), '198.51.100.7', 12, SENTINEL_T0 + 100);
    $t = sentinel_tally_fail($t, '198.51.100.8', 1, SENTINEL_T0 + 200);
    $lines = implode("\n", Sky_Sentinel_Login_Tally::digest_lines($t, SENTINEL_T0 + 7 * 3600));
    expect($lines)->toContain('2026-09-25     13 from 2 addresses, busiest 198.51.100.7 (12)')
        ->toContain('Counting since 2026-09-25.');
    expect(Sky_Sentinel_Login_Tally::digest_lines(array(), SENTINEL_T0))->toBe(array('Failed logins: none counted since this version was installed.'));
});

// ---- 0.4.13: the block list -------------------------------------------------

test('older days keep every address that failed more than once, and drop the one-off ones', function () {
    $t = sentinel_tally_fail(array(), '192.0.2.188', 40, SENTINEL_T0 + 100);
    $t = sentinel_tally_fail($t, '203.0.113.9', 2, SENTINEL_T0 + 200);
    $t = sentinel_tally_fail($t, '198.51.100.1', 1, SENTINEL_T0 + 300);
    // Three days later the 25th is compacted.
    $t = Sky_Sentinel_Login_Tally::compact($t, SENTINEL_T0 + 3 * 86400);
    expect($t['days']['2026-09-25']['repeat'])->toBe(array('192.0.2.188' => 40, '203.0.113.9' => 2))
        // day() reads the same as before for everything else.
        ->and(Sky_Sentinel_Login_Tally::day($t, '2026-09-25'))->toBe(array('total' => 43, 'distinct' => 3, 'capped' => false, 'top_ip' => '192.0.2.188', 'top_count' => 40));
});

test('addresses() adds up every day in the window and nothing older', function () {
    $t = sentinel_tally_fail(array(), '192.0.2.188', 6, SENTINEL_T0 - 20 * 86400); // outside 14 days
    $t = sentinel_tally_fail($t, '192.0.2.188', 3, SENTINEL_T0 - 5 * 86400);
    $t = sentinel_tally_fail($t, '192.0.2.188', 4, SENTINEL_T0 + 100);
    $t = sentinel_tally_fail($t, '203.0.113.9', 1, SENTINEL_T0 + 200);
    expect(Sky_Sentinel_Login_Tally::addresses($t, SENTINEL_T0 + 3600))->toBe(array('192.0.2.188' => 7, '203.0.113.9' => 1))
        // A shorter window leaves out the day five days back.
        ->and(Sky_Sentinel_Login_Tally::addresses($t, SENTINEL_T0 + 3600, 3))->toBe(array('192.0.2.188' => 4, '203.0.113.9' => 1));
});

test('the block list: addresses at five or more, most first; /24s add their addresses up', function () {
    $counts = array('192.0.2.188' => 2359, '192.0.2.7' => 3, '198.18.106.188' => 1238, '203.0.113.171' => 4, '198.51.100.1' => 1, 'garbage' => 50);
    $ip  = Sky_Sentinel_Login_Tally::block_list($counts, array(), array(), false);
    $net = Sky_Sentinel_Login_Tally::block_list($counts, array(), array(), true);
    expect(array_keys($ip['block']))->toBe(array('192.0.2.188', '198.18.106.188'))
        ->and(array_keys($net['block']))->toBe(array('192.0.2.0/24', '198.18.106.0/24'))
        ->and($net['block']['192.0.2.0/24'])->toBe(array('total' => 2362, 'addresses' => 2))
        ->and($ip['held'])->toBe(array());
    // Most first, whatever order they arrive in.
    $asc = Sky_Sentinel_Login_Tally::block_list(array('192.0.2.1' => 5, '192.0.2.2' => 9, '198.51.100.3' => 7), array(), array(), false);
    expect(array_keys($asc['block']))->toBe(array('192.0.2.2', '198.51.100.3', '192.0.2.1'));
    // IPv6 groups by /64.
    $v6 = Sky_Sentinel_Login_Tally::block_list(array('2001:db8:1:2::5' => 3, '2001:db8:1:2::9' => 3), array(), array(), true);
    expect(array_keys($v6['block']))->toBe(array('2001:db8:1:2::/64'));
});

test('the block list never offers an allowed network or a range an administrator logged in from', function () {
    $counts = array('10.30.5.9' => 50, '10.0.0.200' => 50, '10.0.0.20' => 50, '100.64.199.172' => 50, '192.0.2.188' => 50);
    $allowed = array('10.30.0.0/16', '10.0.0.128/25');
    $admins  = array('100.64.199.0/24');
    $ip  = Sky_Sentinel_Login_Tally::block_list($counts, $allowed, $admins, false);
    $net = Sky_Sentinel_Login_Tally::block_list($counts, $allowed, $admins, true);
    // Addresses: 10.0.0.20 is outside the /25, so it may be blocked alone.
    expect(array_keys($ip['block']))->toBe(array('10.0.0.20', '192.0.2.188'))
        ->and($ip['held']['10.30.5.9']['why'])->toContain('10.30.0.0/16')
        ->and($ip['held']['10.0.0.200']['why'])->toContain('10.0.0.128/25')
        ->and($ip['held']['100.64.199.172']['why'])->toContain('administrator');
    // Ranges: 10.0.0.0/24 overlaps the allowed /25, so the whole range is held.
    expect(array_keys($net['block']))->toBe(array('192.0.2.0/24'))
        ->and(array_keys($net['held']))->toContain('10.30.5.0/24')->toContain('10.0.0.0/24')->toContain('100.64.199.0/24');
});
