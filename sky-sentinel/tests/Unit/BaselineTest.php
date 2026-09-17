<?php
/**
 * The baseline is only worth anything if it cannot be re-signed by somebody
 * who has the database. The key lives in wp-config.php; these prove the HMAC
 * does what a signature must.
 */
const SENTINEL_TEST_KEY = 'a-test-key-that-is-at-least-32-characters-long-ok';

test('a manifest signs and verifies', function () {
    $m = Sky_Sentinel_Baseline::build(array('b.php' => 'x', 'a.php' => 'y'), array('plugins/z', 'plugins/a'), array('site_admins' => array('alice')), 'alice', 1700000000);
    $sig = Sky_Sentinel_Baseline::sign($m, SENTINEL_TEST_KEY);
    expect(Sky_Sentinel_Baseline::verify($m, $sig, SENTINEL_TEST_KEY))->toBeTrue();
});

test('one changed hash breaks the signature', function () {
    $m = Sky_Sentinel_Baseline::build(array('a.php' => 'y'), array(), array(), 'alice', 1700000000);
    $sig = Sky_Sentinel_Baseline::sign($m, SENTINEL_TEST_KEY);
    $m['files']['a.php'] = 'z';
    expect(Sky_Sentinel_Baseline::verify($m, $sig, SENTINEL_TEST_KEY))->toBeFalse();
});

test('the wrong key does not verify, and a short key is refused outright', function () {
    $m = Sky_Sentinel_Baseline::build(array('a.php' => 'y'), array(), array(), 'alice', 1700000000);
    $sig = Sky_Sentinel_Baseline::sign($m, SENTINEL_TEST_KEY);
    expect(Sky_Sentinel_Baseline::verify($m, $sig, str_repeat('b', 40)))->toBeFalse();
    expect(fn() => Sky_Sentinel_Baseline::sign($m, 'short'))->toThrow(InvalidArgumentException::class);
    expect(Sky_Sentinel_Baseline::verify($m, $sig, 'short'))->toBeFalse();
});

test('key order does not change the signature, so a round trip through the database is safe', function () {
    $a = array('version' => 1, 'files' => array('b' => '1', 'a' => '2'), 'packages' => array('p', 'q'));
    $b = array('packages' => array('p', 'q'), 'files' => array('a' => '2', 'b' => '1'), 'version' => 1);
    expect(Sky_Sentinel_Baseline::sign($a, SENTINEL_TEST_KEY))->toBe(Sky_Sentinel_Baseline::sign($b, SENTINEL_TEST_KEY));
    // ...but list ORDER is meaning, and stays.
    $c = array('packages' => array('q', 'p'), 'files' => array('a' => '2', 'b' => '1'), 'version' => 1);
    expect(Sky_Sentinel_Baseline::sign($c, SENTINEL_TEST_KEY))->not->toBe(Sky_Sentinel_Baseline::sign($a, SENTINEL_TEST_KEY));
});
