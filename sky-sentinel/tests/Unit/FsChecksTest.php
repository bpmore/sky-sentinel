<?php
/**
 * S1 to S7: where a file is, what it is called, what its first bytes say.
 */

function sentinel_fs(): Sky_Sentinel_FS_Checks {
    return new Sky_Sentinel_FS_Checks(sentinel_signatures());
}

test('S1: a PHP file named word-unixtime, and the plant time is decoded', function () {
    $f = sentinel_fs()->check_file('wp-content/cache/elem-1723456789.php', 900, '<?php');
    $s1 = array_values(array_filter($f, fn($x) => 'S1' === $x->detector));
    expect($s1)->toHaveCount(1)
        ->and($s1[0]->detail['planted_at'])->toStartWith('2024-08-12');
});

test('S1 needs a ten-digit epoch from 2020 on: a version-numbered file is not a plant', function () {
    $ids = sentinel_ids(sentinel_fs()->check_file('wp-content/plugins/x/lib-20240101.php', 900, '<?php'));
    expect($ids)->not->toContain('S1');
    $ids = sentinel_ids(sentinel_fs()->check_file('wp-content/plugins/x/cache-1234567890.php', 900, '<?php'));
    expect($ids)->not->toContain('S1');
});

test('S1 and S2 on a package directory: plant-named is HIGH, plant-named with akismet.php inside is a CRITICAL decoy', function () {
    $fs = sentinel_fs();
    $plain = $fs->check_package_dir('wp-content/plugins/helper-1723456789', array('helper.php', 'readme.txt'));
    $decoy = $fs->check_package_dir('wp-content/plugins/akismet-1723456789', array('akismet.php', 'class.akismet.php'));
    $theme = $fs->check_package_dir('wp-content/themes/hello-1723456789', array('theme.php', 'style.css'));
    $ok    = $fs->check_package_dir('wp-content/plugins/akismet', array('akismet.php'));

    expect(sentinel_ids($plain))->toBe(array('S1'))
        ->and(sentinel_ids($decoy))->toBe(array('S2'))
        ->and($decoy[0]->severity)->toBe('critical')
        ->and(sentinel_ids($theme))->toBe(array('S2'))
        ->and($ok)->toBe(array());
});

test('S3: PHP under uploads/ is HIGH, an index.php guard is nothing, a datastore is INFO', function () {
    $fs = sentinel_fs();
    expect(sentinel_ids($fs->check_file('wp-content/uploads/2026/08/x.php', 500, '<?php')))->toContain('S3')
        ->and(sentinel_ids($fs->check_file('wp-content/uploads/2026/08/index.php', 28, '<?php')))->toBe(array())
        ->and(sentinel_ids($fs->check_file('wp-content/uploads/index.php', 5000, '<?php')))->toContain('S3');
    $ds = $fs->check_file('wp-content/uploads/learndash/x.php', 500, '<?php');
    expect($ds[0]->severity)->toBe('info');
});

test('S3 covers cache/, languages/, blogs.dir/, upgrade-temp-backup/ directly under wp-content only', function () {
    $fs = sentinel_fs();
    foreach (array('cache', 'languages', 'blogs.dir', 'upgrade', 'upgrade-temp-backup') as $dir) {
        expect(sentinel_ids($fs->check_file("wp-content/{$dir}/x.php", 500, '<?php')))->toContain('S3');
    }
    // A plugin's own cache/ folder is not wp-content/cache/.
    expect(sentinel_ids($fs->check_file('wp-content/plugins/x/cache/x.php', 500, '<?php')))->not->toContain('S3');
});

test('S4: a .jpg whose bytes are a zip, PHP or HTML is CRITICAL; a real jpeg and a docx are not', function () {
    $fs = sentinel_fs();
    $zip = $fs->check_file('wp-content/uploads/2026/08/cache-05193152.jpg', 40000, sentinel_fixture('bad/disguised.jpg.txt'));
    expect(sentinel_ids($zip))->toContain('S4')->and($zip[0]->severity)->toBe('critical');
    expect(sentinel_ids($fs->check_file('wp-content/uploads/a.png', 100, '<?php echo 1;')))->toContain('S4');
    expect(sentinel_ids($fs->check_file('wp-content/uploads/a.gif', 100, "<!DOCTYPE html>")))->toContain('S4');
    expect(sentinel_ids($fs->check_file('wp-content/uploads/real.jpg', 100, sentinel_fixture('clean/real.jpg.txt'))))->toBe(array());
    expect(sentinel_ids($fs->check_file('wp-content/uploads/report.docx', 100, "PK\x03\x04\x14\x00")))->toBe(array());
    // An SVG is allowed to be text.
    expect(sentinel_ids($fs->check_file('wp-content/uploads/logo.svg', 100, '<svg xmlns=')))->toBe(array());
});

test('S4: a saved server error page under an image name is MEDIUM, not CRITICAL', function () {
    // Seen inside an e-learning package: an nginx 502 body stored under an
    // image's name. Broken upload, not a payload.
    $fs = sentinel_fs();
    $nginx = "<html>\n<head><title>502 Bad Gateway</title></head>\n<body>\n<center><h1>502 Bad Gateway</h1></center>\n</body>\n</html>\n";
    $f = $fs->check_file('wp-content/uploads/sites/95/x/pathway.jpg', strlen($nginx), $nginx);
    expect(sentinel_ids($f))->toBe(array('S4'))->and($f[0]->severity)->toBe('medium');
    // A page that merely LOOKS like an error page but carries a script is
    // still the CRITICAL shape. The content detectors never read uploads, so
    // this is the only place that script would be noticed.
    $lure = "<html><head><title>502 Bad Gateway</title></head><body><script>x()</script></body></html>";
    $f = $fs->check_file('wp-content/uploads/sites/95/x/pathway.jpg', strlen($lure), $lure);
    expect($f[0]->severity)->toBe('critical');
    // ...and ordinary HTML under an image name stays CRITICAL.
    $f = $fs->check_file('wp-content/uploads/a.gif', 100, "<!DOCTYPE html><title>Verify</title>");
    expect($f[0]->severity)->toBe('critical');
});

test('S5: the dropper dotfiles', function () {
    $fs = sentinel_fs();
    foreach (array('.holder', '.mrk', '.property_set') as $name) {
        $f = $fs->check_file("wp-content/{$name}", 0, '');
        expect(sentinel_ids($f))->toContain('S5')->and($f[0]->severity)->toBe('critical');
    }
    expect(sentinel_ids($fs->check_file('wp-content/.htaccess', 10, '#')))->toBe(array());
});

test('F16 by name: restore.zip or .state.json inside a plugin, whatever the bytes', function () {
    $fs = sentinel_fs();
    expect(sentinel_ids($fs->check_file('wp-content/plugins/site-helper/restore.zip', 4, 'PK')))->toContain('F16')
        ->and(sentinel_ids($fs->check_file('wp-content/plugins/site-helper/.state.json', 2, '{}')))->toContain('F16')
        ->and(sentinel_ids($fs->check_file('wp-content/uploads/restore.zip', 4, 'PK')))->not->toContain('F16');
});

test('F15 by location: a .js at the webroot, except one named in the allow-list', function () {
    $fs = sentinel_fs();
    expect(sentinel_ids($fs->check_file('sw.js', 10, 'x')))->toContain('F15')
        ->and(sentinel_ids($fs->check_file('wp-includes/js/x.js', 10, 'x')))->not->toContain('F15');
    // A remediation worker you placed yourself, named in the allow-list. A
    // second file with a different name at the webroot is still the finding.
    $dir = dirname(__DIR__, 2) . '/signatures';
    $allow = Sky_Sentinel_Signatures::read_json($dir . '/allowlist.json');
    $allow['f15_webroot_js'] = array('my-cleanup-sw.js');
    $named = new Sky_Sentinel_FS_Checks(new Sky_Sentinel_Signatures(
        Sky_Sentinel_Signatures::read_json($dir . '/known-bad-hashes.json'),
        Sky_Sentinel_Signatures::read_json($dir . '/iocs.json'),
        $allow
    ));
    expect(sentinel_ids($named->check_file('my-cleanup-sw.js', 10, 'x')))->not->toContain('F15')
        ->and(sentinel_ids($named->check_file('my-cleanup-sw2.js', 10, 'x')))->toContain('F15');
});

test('S6 and S7: the baseline diff', function () {
    $baseline = array('a.php' => 'aaa', 'b.js' => 'bbb', 'c.txt' => 'ccc', 'gone.php' => 'ggg');
    $current  = array('a.php' => 'aaa', 'b.js' => 'BBB', 'c.txt' => 'ccc', 'new.php' => 'nnn', 'new.png' => 'ppp');
    $f = Sky_Sentinel_FS_Checks::diff_against_baseline($baseline, $current, array('plugins/akismet'), array('plugins/akismet', 'plugins/site-helper'));
    $by = array();
    foreach ($f as $x) { $by[$x->detector . ':' . $x->subject] = $x->severity; }
    expect($by)->toBe(array(
        'S6:b.js'    => 'medium',
        'S6:new.php' => 'high',
        'S6:new.png' => 'medium',
        'S6:gone.php' => 'info',
        'S7:plugins/site-helper' => 'high',
    ));
});
