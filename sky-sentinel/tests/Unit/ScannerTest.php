<?php
/**
 * The walk, against a throwaway wp-content built in a temp dir from the
 * fixtures. Proves the chunking resumes without losing or double-counting,
 * that uploads/ is not hashed, and that the package inventory is collected.
 */

function sentinel_fake_site(): string {
    $root = sys_get_temp_dir() . '/sentinel-' . bin2hex(random_bytes(4));
    $put = function (string $rel, string $bytes) use ($root) {
        $abs = $root . '/' . $rel;
        if (!is_dir(dirname($abs))) { mkdir(dirname($abs), 0777, true); }
        file_put_contents($abs, $bytes);
    };
    $put('index.php', "<?php require 'wp-blog-header.php';");
    $put('sw.js', 'self.addEventListener("fetch", () => {});');
    $put('wp-content/plugins/akismet/akismet.php', "<?php /* Plugin Name: Akismet */");
    $put('wp-content/plugins/akismet-1723456789/akismet.php', "<?php /* decoy */");
    $put('wp-content/plugins/site-helper/site-helper.php', sentinel_fixture('bad/self-heal.php.txt'));
    $put('wp-content/plugins/site-helper/restore.zip', "PK\x03\x04");
    $put('wp-content/themes/example/functions.php', sentinel_fixture('bad/functions-inline.php.txt'));
    $put('wp-content/themes/example/js/home-slider.js', sentinel_fixture('bad/loader-appended.js.txt'));
    $put('wp-content/cache/elem-1723456789.php', sentinel_fixture('bad/dropper-a.php.txt'));
    $put('wp-content/.holder', '');
    $put('wp-content/uploads/2026/08/cache-05193152.jpg', sentinel_fixture('bad/disguised.jpg.txt'));
    $put('wp-content/uploads/2026/08/real.jpg', sentinel_fixture('clean/real.jpg.txt'));
    $put('wp-content/uploads/2026/08/big.bin', str_repeat('x', 100));
    $put('wp-content/plugins/wordfence/waf/bootstrap.php', sentinel_fixture('clean/wordfence-like.php.txt'));
    return $root;
}

function sentinel_rm(string $dir): void {
    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST) as $f) {
        $f->isDir() ? rmdir($f->getPathname()) : unlink($f->getPathname());
    }
    rmdir($dir);
}

test('a full walk finds every planted artifact once, and nothing in the clean files', function () {
    $root = sentinel_fake_site();
    $manifest = $root . '.manifest';
    try {
        $r = (new Sky_Sentinel_Scanner($root, sentinel_signatures()))->scan_all($manifest);
        $keys = array();
        foreach ($r['findings'] as $f) {
            $keys[] = $f->detector . ' ' . $f->subject;
        }
        sort($keys);
        expect($keys)->toContain('S2 wp-content/plugins/akismet-1723456789')
            ->toContain('F16 wp-content/plugins/site-helper/site-helper.php')
            ->toContain('F16 wp-content/plugins/site-helper/restore.zip')
            ->toContain('F13 wp-content/themes/example/functions.php')
            ->toContain('F10 wp-content/themes/example/js/home-slider.js')
            ->toContain('S1 wp-content/cache/elem-1723456789.php')
            ->toContain('S3 wp-content/cache/elem-1723456789.php')
            ->toContain('F2 wp-content/cache/elem-1723456789.php')
            ->toContain('S5 wp-content/.holder')
            ->toContain('S4 wp-content/uploads/2026/08/cache-05193152.jpg')
            ->toContain('F15 sw.js');
        // Each once.
        expect(count($keys))->toBe(count(array_unique($keys)));
        // Nothing about the real jpeg or Wordfence at HIGH.
        foreach ($r['findings'] as $f) {
            if (str_contains($f->subject, 'real.jpg') || str_contains($f->subject, 'wordfence')) {
                expect($f->is_at_least('high'))->toBeFalse("{$f->detector} fired on {$f->subject}");
            }
        }
        // The inventory.
        expect($r['state']['packages'])->toContain('wp-content/plugins/akismet')->toContain('wp-content/themes/example');
        // uploads/ is never hashed; everything else is.
        $m = Sky_Sentinel_Scanner::read_manifest($manifest);
        expect($m)->toHaveKey('wp-content/themes/example/functions.php')->toHaveKey('index.php')
            ->not->toHaveKey('wp-content/uploads/2026/08/real.jpg')->not->toHaveKey('wp-content/uploads/2026/08/big.bin');
        expect($r['state']['files'])->toBe(14)->and($r['state']['done'])->toBeTrue();
    } finally {
        sentinel_rm($root);
        @unlink($manifest);
    }
});

test('a chunked walk with a tiny budget reaches the same answer as one call', function () {
    $root = sentinel_fake_site();
    $m1 = $root . '.m1';
    $m2 = $root . '.m2';
    try {
        $scanner = new Sky_Sentinel_Scanner($root, sentinel_signatures());
        $whole = $scanner->scan_all($m1);

        $state = Sky_Sentinel_Scanner::start($m2);
        $found = array();
        $steps = 0;
        while (!$state['done']) {
            // A budget of zero processes exactly one directory per step.
            $r = $scanner->step($state, 0.0);
            $state = $r['state'];
            foreach ($r['findings'] as $f) { $found[] = $f->detector . ' ' . $f->subject; }
            $steps++;
        }
        $expected = array_map(fn($f) => $f->detector . ' ' . $f->subject, $whole['findings']);
        sort($found); sort($expected);
        expect($found)->toBe($expected)
            ->and($steps)->toBeGreaterThan(3)
            ->and(Sky_Sentinel_Scanner::read_manifest($m2))->toBe(Sky_Sentinel_Scanner::read_manifest($m1));
    } finally {
        sentinel_rm($root);
        @unlink($m1); @unlink($m2);
    }
});

test('Sentinel never content-scans its own source, but still hashes it', function () {
    // A scanner that reads its own signature file reports itself: the IOC
    // list, the option names in its detectors.
    $root = sys_get_temp_dir() . '/sentinel-self-' . bin2hex(random_bytes(4));
    $dir = $root . '/wp-content/mu-plugins/sky-sentinel/signatures';
    mkdir($dir, 0777, true);
    copy(dirname(__DIR__, 2) . '/signatures/iocs.json', $dir . '/iocs.json');
    mkdir($root . '/wp-content/themes/x', 0777, true);
    file_put_contents($root . '/wp-content/themes/x/main.js', sentinel_fixture('bad/loader-wholefile.js.txt'));
    $manifest = $root . '.manifest';
    try {
        $r = (new Sky_Sentinel_Scanner($root, sentinel_signatures()))->scan_all($manifest);
        $subjects = array_map(fn($f) => $f->subject, $r['findings']);
        expect($subjects)->not->toContain('wp-content/mu-plugins/sky-sentinel/signatures/iocs.json')
            ->toContain('wp-content/themes/x/main.js');
        expect(Sky_Sentinel_Scanner::read_manifest($manifest))->toHaveKey('wp-content/mu-plugins/sky-sentinel/signatures/iocs.json');
    } finally {
        sentinel_rm($root);
        @unlink($manifest);
    }
});

test('the walk hands S9 real modes and times, and S8 real directory names', function () {
    // The Wordfence sample's spreader fallback, as it lands on disk:
    // plugins/<name>/<name>, backdated and locked.
    $root = sys_get_temp_dir() . '/sentinel-' . bin2hex(random_bytes(4));
    $manifest = $root . '.manifest';
    mkdir($root . '/wp-content/mu-plugins', 0777, true);
    mkdir($root . '/wp-content/plugins/advanced-cache.php', 0777, true);
    $mu  = $root . '/wp-content/mu-plugins/site-health-reporter.php';
    $twin = $root . '/wp-content/plugins/advanced-cache.php/advanced-cache.php';
    file_put_contents($mu, "<?php // inert\n");
    file_put_contents($twin, "<?php // inert\n");
    foreach (array($mu, $twin) as $file) {
        touch($file, time() - 400 * 86400);
        chmod($file, 0444);
    }
    try {
        $r = (new Sky_Sentinel_Scanner($root, sentinel_signatures()))->scan_all($manifest);
        $by = array();
        foreach ($r['findings'] as $f) { $by[$f->detector . ' ' . $f->subject] = $f->severity; }
        expect($by)->toMatchArray(array(
            'S9 wp-content/mu-plugins/site-health-reporter.php'              => 'critical',
            'S9 wp-content/plugins/advanced-cache.php/advanced-cache.php'    => 'high',
            'S8 wp-content/plugins/advanced-cache.php'                        => 'critical',
        ));
    } finally {
        foreach (array($mu, $twin) as $file) { @chmod($file, 0644); }
        sentinel_rm($root);
        @unlink($manifest);
    }
});

test('the walk reads big files whole, in memory and past the 8 MB read, and hashes a .zip against the list', function () {
    $root = sys_get_temp_dir() . '/sentinel-' . bin2hex(random_bytes(4));
    $manifest = $root . '.manifest';
    $loader = sentinel_fixture('bad/loader-wholefile.js.txt');
    $pad = str_repeat("function f(a){return a+1};\n", 1000);
    $zip = "PK\x03\x04 a restore.zip of some later build";
    $files = array(
        'wp-content/themes/example/js/fontawesome-all.min.js' => str_repeat($pad, 140) . $loader,   // ~3.7 MB, read into memory
        'wp-content/themes/example/js/huge.min.js'            => str_repeat($pad, 340) . $loader,   // ~9 MB, read by seeking
        'wp-content/themes/example/js/huge-middle.min.js'     => str_repeat($pad, 170) . $loader . str_repeat($pad, 170),
        'wp-content/themes/example/js/clean-big.min.js'       => str_repeat($pad, 60),
        'wp-content/plugins/perf-assist/backup/archive.zip'     => $zip,
    );
    foreach ($files as $rel => $bytes) {
        if (!is_dir(dirname("{$root}/{$rel}"))) { mkdir(dirname("{$root}/{$rel}"), 0777, true); }
        file_put_contents("{$root}/{$rel}", $bytes);
    }
    $dir = dirname(__DIR__, 2) . '/signatures';
    $sig = new Sky_Sentinel_Signatures(array('hashes' => array(hash('sha256', $zip) => 'restore.zip, later build')), Sky_Sentinel_Signatures::read_json("{$dir}/iocs.json"), Sky_Sentinel_Signatures::read_json("{$dir}/allowlist.json"));
    try {
        $r = (new Sky_Sentinel_Scanner($root, $sig))->scan_all($manifest);
        $keys = array_map(fn($f) => $f->detector . ' ' . $f->subject, $r['findings']);
        expect($keys)->toContain('F10 wp-content/themes/example/js/fontawesome-all.min.js')
            ->toContain('F10 wp-content/themes/example/js/huge.min.js')
            ->toContain('F10 wp-content/themes/example/js/huge-middle.min.js')
            ->toContain('F1 wp-content/plugins/perf-assist/backup/archive.zip');
        foreach ($r['findings'] as $f) {
            expect($f->subject)->not->toContain('clean-big');
        }
    } finally {
        sentinel_rm($root);
        @unlink($manifest);
    }
});
