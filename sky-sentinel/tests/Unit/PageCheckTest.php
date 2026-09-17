<?php
/**
 * The rendered-page check with a fake fetcher.
 */

function sentinel_pages(array $responses): Sky_Sentinel_Page_Check {
    // $responses: url-prefix => [code, body, headers]. Cache-busted URLs match by prefix.
    return new Sky_Sentinel_Page_Check(sentinel_signatures(), function (string $url, array $headers) use ($responses) {
        foreach ($responses as $prefix => $r) {
            if (str_starts_with($url, $prefix)) {
                return array('code' => $r[0], 'body' => $r[1], 'headers' => $r[2] ?? array());
            }
        }
        return array('code' => 404, 'body' => '', 'headers' => array());
    });
}

test('the script inventory: absolute srcs, inline hashes, JSON blocks ignored', function () {
    $html = '<script src="/wp-includes/js/jquery.js"></script><script src="//cdn.example.com/x.js"></script>'
        . '<script src="js/rel.js"></script><script>console.log(1)</script>'
        . '<script type="application/ld+json">{"a":1}</script><script type="text/javascript">console.log(1)</script>';
    $inv = Sky_Sentinel_Page_Check::script_inventory($html, 'https://example.test/dir/page');
    expect($inv['srcs'])->toBe(array('https://cdn.example.com/x.js', 'https://example.test/dir/js/rel.js', 'https://example.test/wp-includes/js/jquery.js'))
        ->and($inv['inline'])->toHaveCount(1); // two identical inline blocks, one JSON, one hash
});

test('the inline loader echoed from functions.php is caught in the rendered HTML', function () {
    $html = '<html><body><p>hi</p>' . substr(sentinel_fixture('bad/functions-inline.php.txt'), strpos(sentinel_fixture('bad/functions-inline.php.txt'), '<script')) . '</body></html>';
    $html = preg_replace("/';\s*\}\);\s*$/", '', $html);
    $r = sentinel_pages(array('https://site.test/' => array(200, $html)))->check('https://site.test/', 'site:home', null, null);
    $ids = sentinel_ids($r['findings']);
    expect($ids)->toBe(array('P1'))
        ->and($r['findings'][0]->severity)->toBe('critical')
        ->and($r['fetched'])->toBeTrue();
});

test('a script added since last clean: HIGH from a stranger host, MEDIUM from an allow-listed one, MEDIUM same-origin', function () {
    $html = '<script src="https://site.test/a.js"></script><script src="https://evil.example/x.js"></script><script src="https://connect.facebook.net/sdk.js"></script>';
    $pc = sentinel_pages(array('https://site.test/' => array(200, $html), 'https://site.test/a.js' => array(200, 'var a=1;')));
    $r = $pc->check('https://site.test/', 'site:home', array(), array());
    $by = array();
    foreach ($r['findings'] as $f) { $by[$f->detail['src'] ?? 'inline'] = $f->severity; }
    ksort($by);
    expect($by)->toBe(array('https://connect.facebook.net/sdk.js' => 'medium', 'https://evil.example/x.js' => 'high', 'https://site.test/a.js' => 'medium'));
});

test('with the baseline matching, a clean page is silent', function () {
    $html = '<script src="https://site.test/a.js"></script><script>var x=1;</script>';
    $pc = sentinel_pages(array('https://site.test/' => array(200, $html), 'https://site.test/a.js' => array(200, 'var a=1;')));
    $first = $pc->check('https://site.test/', 'site:home', null, null);
    $second = $pc->check('https://site.test/', 'site:home', $first['inventory']['srcs'], $first['inventory']['inline']);
    expect($second['findings'])->toBe(array());
});

test('a same-origin script is fetched and scanned; a cross-origin one is never fetched', function () {
    $fetched = array();
    $pc = new Sky_Sentinel_Page_Check(sentinel_signatures(), function (string $url) use (&$fetched) {
        $fetched[] = preg_replace('/[?&]sentinel=\d+/', '', $url);
        if (str_starts_with($url, 'https://site.test/js/main.js')) {
            return array('code' => 200, 'body' => sentinel_fixture('bad/loader-wholefile.js.txt'), 'headers' => array('Service-Worker-Allowed' => '/'));
        }
        return array('code' => 200, 'body' => '<script src="/js/main.js"></script><script src="https://cdn.other.example/lib.js"></script>', 'headers' => array());
    });
    $r = $pc->check('https://site.test/', 'site:home', null, null);
    $ids = sentinel_ids($r['findings']);
    expect($ids)->toContain('P2')->toContain('P3')
        ->and($fetched)->not->toContain('https://cdn.other.example/lib.js');
});

test('the cached copy loading a script the fresh page does not is HIGH', function () {
    $pc = new Sky_Sentinel_Page_Check(sentinel_signatures(), function (string $url) {
        $fresh = str_contains($url, 'sentinel=');
        return array('code' => 200, 'body' => $fresh ? '<p>clean</p>' : '<p>clean</p><script src="https://evil.example/x.js"></script>', 'headers' => array());
    });
    $r = $pc->check('https://site.test/', 'site:home', array(), array());
    $p4 = array_values(array_filter($r['findings'], fn($f) => 'P4' === $f->detector));
    expect($p4)->toHaveCount(1)->and($p4[0]->severity)->toBe('high')->and($p4[0]->summary)->toContain('cached copy');
});

test('an unreachable page is a MEDIUM, not a crash and not silence', function () {
    $r = sentinel_pages(array())->check('https://site.test/', 'site:home', null, null);
    expect(sentinel_ids($r['findings']))->toBe(array('P0'))->and($r['fetched'])->toBeFalse();
});

test('P0 says why: the HTTP code, or the transport error', function () {
    // The first phase 2 run produced sixteen "could not fetch" rows with no
    // code on them, which is a list of questions rather than answers.
    $pc = new Sky_Sentinel_Page_Check(sentinel_signatures(), fn() => array('code' => 0, 'body' => '', 'headers' => array(), 'error' => 'cURL error 6: Could not resolve host'));
    $r = $pc->check('https://sub.example.test/', 'sub.example.test:home', null, null);
    expect($r['findings'][0]->severity)->toBe('medium')
        ->and($r['findings'][0]->summary)->toContain('Could not resolve host')
        ->and($r['findings'][0]->detail['code'])->toBe(0);
});

test('P0: a login page that answers 403 to a visitor is protected, which is INFO not MEDIUM', function () {
    $pc = sentinel_pages(array('https://clinic.example.test/wp-login.php' => array(403, 'Forbidden')));
    $r = $pc->check('https://clinic.example.test/wp-login.php', 'clinic.example.test:login', null, null);
    expect($r['findings'][0]->severity)->toBe('info')->and($r['findings'][0]->summary)->toContain('HTTP 403');
    // The same 403 on a HOME page is still a problem.
    $pc = sentinel_pages(array('https://clinic.example.test/' => array(403, 'Forbidden')));
    $r = $pc->check('https://clinic.example.test/', 'clinic.example.test:home', null, null);
    expect($r['findings'][0]->severity)->toBe('medium');
});

test('P0: a site answering 410 Gone is retired, INFO not MEDIUM', function () {
    $pc = sentinel_pages(array('https://network.example.test/digitalsign/' => array(410, 'Gone')));
    $r = $pc->check('https://network.example.test/digitalsign/', 'network.example.test:home', null, null);
    expect($r['findings'][0]->severity)->toBe('info')->and($r['findings'][0]->summary)->toContain('retired');
    // 404 on a home page is still MEDIUM: a live site whose front door is missing.
    $pc = sentinel_pages(array('https://dead.example.test/' => array(404, 'Not found')));
    expect($pc->check('https://dead.example.test/', 'dead.example.test:home', null, null)['findings'][0]->severity)->toBe('medium');
});
