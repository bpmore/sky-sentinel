<?php
/**
 * Sorting the Findings table. The ORDER BY is built only from a whitelist,
 * because the column and direction arrive in the query string.
 */

test('every sortable column has a default direction, and a first click uses it', function () {
    expect(Sky_Sentinel_Findings::sort_of('seen', ''))->toBe(array('seen', 'desc'))
        ->and(Sky_Sentinel_Findings::sort_of('detector', ''))->toBe(array('detector', 'asc'))
        ->and(Sky_Sentinel_Findings::sort_of('severity', ''))->toBe(array('severity', 'desc'))
        ->and(Sky_Sentinel_Findings::sort_of('last_seen', 'ASC'))->toBe(array('last_seen', 'asc'));
});

test('an unknown column falls back to severity, an unknown direction to the column default', function () {
    expect(Sky_Sentinel_Findings::sort_of('password', 'desc'))->toBe(array('severity', 'desc'))
        ->and(Sky_Sentinel_Findings::sort_of('seen', 'sideways'))->toBe(array('seen', 'desc'));
});

test('nothing from the request reaches the SQL but whitelisted text', function () {
    $evil = Sky_Sentinel_Findings::order_by("seen_count; DROP TABLE wp_users; --", "desc; DELETE FROM wp_options");
    expect($evil)->not->toContain('DROP')->not->toContain('DELETE')->not->toContain(';')
        ->and($evil)->toBe(Sky_Sentinel_Findings::order_by('severity', 'desc'));
    foreach (array_keys(Sky_Sentinel_Findings::SORTS) as $col) {
        foreach (array('asc', 'desc') as $dir) {
            expect(Sky_Sentinel_Findings::order_by($col, $dir))->toMatch("/^ORDER BY [A-Za-z_(),' 0-9]+$/");
        }
    }
});

test('each column sorts on the right expression, with the same tie-breakers', function () {
    $tail = ", FIELD(severity,'critical','high','medium','info'), last_seen DESC, id DESC";
    expect(Sky_Sentinel_Findings::order_by('seen', 'desc'))->toBe('ORDER BY seen_count DESC' . $tail)
        ->and(Sky_Sentinel_Findings::order_by('site', 'asc'))->toBe('ORDER BY blog_id ASC' . $tail)
        ->and(Sky_Sentinel_Findings::order_by('severity', 'desc'))->toBe("ORDER BY FIELD(severity,'info','medium','high','critical') DESC" . $tail)
        ->and(Sky_Sentinel_Findings::order_by('detector', 'asc'))->toBe('ORDER BY LEFT(detector,1) ASC, CAST(SUBSTRING(detector,2) AS UNSIGNED) ASC, detector ASC' . $tail);
});

test('detector filter: real detector ids pass, uppercased; anything else means all detectors', function () {
    foreach (array('L6' => 'L6', 'l6' => 'L6', 'F18' => 'F18', 'P0' => 'P0', 'SCAN' => 'SCAN', 'd10' => 'D10') as $in => $out) {
        expect(Sky_Sentinel_Findings::detector_of($in))->toBe($out);
    }
    foreach (array('', "L6' OR 1=1 --", 'L6;DROP', '6L', 'L1234', 'TOOLONGID1', 'L 6') as $bad) {
        expect(Sky_Sentinel_Findings::detector_of($bad))->toBe('', $bad);
    }
});
