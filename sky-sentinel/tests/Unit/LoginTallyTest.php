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
