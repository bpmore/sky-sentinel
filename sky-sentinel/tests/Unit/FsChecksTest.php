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

test('L9: the load path is top-level mu-plugins PHP and the named drop-ins, nothing else', function () {
    $yes = array('wp-content/mu-plugins/site-health-reporter.php', 'wp-content/advanced-cache.php', 'wp-content/db.php', 'wp-content/object-cache.php', 'wp-content/sunrise.php', 'wp-content/DB.PHP');
    $no  = array('wp-content/mu-plugins/sky-sentinel/sentinel.php', 'wp-content/mu-plugins/readme.txt', 'wp-content/functions.php', 'wp-content/plugins/db.php', 'wp-content/themes/x/advanced-cache.php', 'db.php');
    foreach ($yes as $p) { expect(Sky_Sentinel_FS_Checks::is_load_path($p))->toBeTrue(); }
    foreach ($no as $p) { expect(Sky_Sentinel_FS_Checks::is_load_path($p))->toBeFalse(); }
    // A relocated content dir is honoured.
    expect(Sky_Sentinel_FS_Checks::is_load_path('app/mu/x.php', 'app', 'app/mu'))->toBeTrue()
        ->and(Sky_Sentinel_FS_Checks::is_load_path('app/db.php', 'app', 'app/mu'))->toBeTrue();
});

test('L9: a new mu-plugin or a changed drop-in is CRITICAL; a removed one is HIGH; unchanged is silent', function () {
    $was = array(
        'wp-content/mu-plugins/sky-sentinel-loader.php' => str_repeat('a', 64),
        'wp-content/object-cache.php'                    => str_repeat('b', 64),
        'wp-content/mu-plugins/host-helper.php'          => str_repeat('c', 64),
    );
    $now = array(
        'wp-content/mu-plugins/sky-sentinel-loader.php' => str_repeat('a', 64),
        'wp-content/object-cache.php'                    => str_repeat('d', 64),
        'wp-content/advanced-cache.php'                  => str_repeat('e', 64),
    );
    $f = Sky_Sentinel_FS_Checks::diff_load_path($was, $now);
    $by = array();
    foreach ($f as $x) { $by[$x->subject] = $x->detector . ' ' . $x->severity; }
    ksort($by);
    expect($by)->toBe(array(
        'wp-content/advanced-cache.php'         => 'L9 critical',
        'wp-content/mu-plugins/host-helper.php' => 'L9 high',
        'wp-content/object-cache.php'           => 'L9 critical',
    ));
});

test('S8: a package directory named like a PHP file is CRITICAL, and says so when it holds its twin', function () {
    $fs = new Sky_Sentinel_FS_Checks(sentinel_signatures());
    $twin = $fs->check_package_dir('wp-content/plugins/advanced-cache.php', array('advanced-cache.php'));
    $bare = $fs->check_package_dir('wp-content/plugins/db.php', array('readme.txt'));
    expect($twin)->toHaveCount(1)->and($twin[0]->detector)->toBe('S8')->and($twin[0]->severity)->toBe('critical')
        ->and($twin[0]->detail)->toBe(array('twin' => true))
        ->and($bare[0]->detail)->toBe(array('twin' => false))
        ->and($fs->check_package_dir('wp-content/plugins/akismet', array('akismet.php')))->toBe(array())
        ->and($fs->check_package_dir('wp-content/plugins/php-compatibility-checker', array('x.php')))->toBe(array());
});

function sentinel_s9(string $path, int $mode, int $mtime, int $ctime): array {
    $f = (new Sky_Sentinel_FS_Checks(sentinel_signatures()))->check_file($path, 9000, '<?php', $mode, $mtime, $ctime);
    $out = array();
    foreach ($f as $x) { if ($x->detector === 'S9') { $out[] = $x->severity; } }
    return $out;
}

test('S9: load-path PHP locked 0444 is HIGH, and CRITICAL when also backdated', function () {
    $now = 1790000000;
    $old = $now - 400 * 86400;
    expect(sentinel_s9('wp-content/mu-plugins/health.php', 0100444, $now, $now))->toBe(array('high'))
        ->and(sentinel_s9('wp-content/mu-plugins/health.php', 0100444, $old, $now))->toBe(array('critical'))
        ->and(sentinel_s9('wp-content/advanced-cache.php', 0100444, $old, $now))->toBe(array('critical'));
});

test('S9: in a plugin or theme it takes the lock AND the backdate; either alone is a deploy habit', function () {
    $now = 1790000000;
    $old = $now - 400 * 86400;
    expect(sentinel_s9('wp-content/plugins/db.php/db.php', 0100444, $old, $now))->toBe(array('high'))
        ->and(sentinel_s9('wp-content/plugins/akismet/akismet.php', 0100444, $now, $now))->toBe(array())
        ->and(sentinel_s9('wp-content/plugins/akismet/akismet.php', 0100644, $old, $now))->toBe(array())
        ->and(sentinel_s9('wp-content/themes/x/functions.php', 0100444, $old, $now))->toBe(array('high'));
});

test('S9: a writable load-path file, a read-only wp-config.php, a locked .js, and no stat at all are silent', function () {
    $now = 1790000000;
    $old = $now - 400 * 86400;
    expect(sentinel_s9('wp-content/mu-plugins/health.php', 0100644, $old, $now))->toBe(array())
        ->and(sentinel_s9('wp-config.php', 0100400, $old, $now))->toBe(array())
        ->and(sentinel_s9('wp-content/mu-plugins/app.js', 0100444, $old, $now))->toBe(array());
    $f = (new Sky_Sentinel_FS_Checks(sentinel_signatures()))->check_file('wp-content/mu-plugins/health.php', 9000, '<?php');
    expect(array_filter($f, fn($x) => $x->detector === 'S9'))->toBe(array());
});

test('S9: a mode with only the owner write bit set is not locked', function () {
    expect(sentinel_s9('wp-content/mu-plugins/health.php', 0100644 & ~0022, 1, 1))->toBe(array())
        ->and(sentinel_s9('wp-content/mu-plugins/health.php', 0100200, 1, 1))->toBe(array());
});

test('S1 and S2: plant names with more than one word, which a real-install scan found nine decoys hiding behind', function () {
    $fs = new Sky_Sentinel_FS_Checks(sentinel_signatures());
    foreach (array('author-template-1788356646', 'widget_area_1788998285', 'custom_file_3_1788356570', 'comment-section-1788998789', 'category_template_1788356405') as $dir) {
        $f = $fs->check_package_dir("wp-content/themes/{$dir}", array('theme.php', 'style.css', 'index.php'));
        expect($f)->toHaveCount(1)->and($f[0]->detector)->toBe('S2', $dir)->and($f[0]->severity)->toBe('critical');
    }
    foreach (array('custom-file-2-1788379040.php', 'front.page.template.1788356238.php', 'custom_file_3_1788356443.php') as $name) {
        $ids = array_map(fn($x) => $x->detector, $fs->check_file("wp-content/languages/{$name}", 900, '<?php'));
        expect($ids)->toContain('S1');
    }
});

test('S1: version numbers, dates and hashes are not plant names', function () {
    $fs = new Sky_Sentinel_FS_Checks(sentinel_signatures());
    foreach (array('jquery-3.7.1.php', 'report-2026-09-24.php', 'plugin-v2-1788356646x.php', 'cache-abc1788356646.php', 'build-1500000000.php', 'x-17883566460.php') as $name) {
        $ids = array_map(fn($x) => $x->detector, $fs->check_file("wp-content/plugins/p/{$name}", 900, '<?php'));
        expect($ids)->not->toContain('S1', $name);
    }
    expect($fs->check_package_dir('wp-content/plugins/woocommerce-gateway-stripe', array('woocommerce-gateway-stripe.php')))->toBe(array());
});

test('S3: a datastore allow-listed as uploads/sucuri/ is INFO on every network site too', function () {
    // One real multisite: eight HIGHs, one per Sucuri file on site 6, under
    // both multisite layouts.
    $fs = sentinel_fs();
    foreach (array('wp-content/uploads/sucuri/sucuri-lastlogins.php', 'wp-content/uploads/sites/6/sucuri/sucuri-lastlogins.php', 'wp-content/blogs.dir/6/files/sucuri/sucuri-lastlogins.php') as $p) {
        $f = $fs->check_file($p, 500, '<?php exit(0); ?>');
        expect($f)->toHaveCount(1)->and($f[0]->severity)->toBe('info');
    }
    // Only the multisite prefix is folded: an unlisted folder on site 6 is still HIGH.
    expect($fs->check_file('wp-content/uploads/sites/6/other/x.php', 500, '<?php')[0]->severity)->toBe('high');
});

test('S10: a package named like the campaign plugins, by exact name or by site-helper naming', function () {
    $fs = sentinel_fs();
    $by = function (string $dir) use ($fs) {
        $f = array_values(array_filter($fs->check_package_dir($dir, array('x.php')), fn($x) => 'S10' === $x->detector));
        return $f ? $f[0]->severity : null;
    };
    expect($by('wp-content/plugins/wp-security-helper'))->toBe('critical')
        ->and($by('wp-content/plugins/site-helper-bdcd2b1a9ff2'))->toBe('critical')
        ->and($by('wp-content/plugins/perf-assist-9c1e77a0b2d4'))->toBe('high')
        // Twelve digits is a date, twelve letters is a word: both needed.
        ->and($by('wp-content/plugins/backup-202609281234'))->toBeNull()
        ->and($by('wp-content/plugins/tools-deadbeefcafe'))->toBeNull()
        ->and($by('wp-content/plugins/akismet'))->toBeNull()
        ->and($by('wp-content/themes/twentytwentyfive'))->toBeNull();
});

test('S3: an empty PHP file has nothing to run and is not flagged; one byte more is HIGH', function () {
    // WP All Export's 0-byte functions.php in blogs.dir/25/files/wpallexport/.
    $fs = sentinel_fs();
    expect($fs->check_file('wp-content/blogs.dir/25/files/wpallexport/functions.php', 0, ''))->toBe(array())
        ->and($fs->check_file('wp-content/blogs.dir/25/files/wpallexport/functions.php', 30, '<?php eval($_POST["x"]);')[0]->severity)->toBe('high');
});

test('S3: a translation file that only returns strings is not flagged; one line of code in it is HIGH', function () {
    // WordPress 6.5+ writes languages/**/*.l10n.php. Thirty HIGHs on one
    // real site, one per translated plugin.
    $fs = sentinel_fs();
    $data = sentinel_fixture('clean/translations.l10n.php.txt');
    $bad  = str_replace("']];", "']]; eval(\$_POST['x']);", $data);
    $p = 'wp-content/languages/plugins/gravityforms-es_ES.l10n.php';
    expect($fs->check_file($p, strlen($data), substr($data, 0, 256), null, null, null, $data))->toBe(array())
        ->and($fs->check_file($p, strlen($bad), substr($bad, 0, 256), null, null, null, $bad)[0]->severity)->toBe('high')
        // No bytes, no proof: HIGH.
        ->and($fs->check_file($p, strlen($data), substr($data, 0, 256))[0]->severity)->toBe('high')
        // Data, but not named like a translation file, or not in languages/: HIGH.
        ->and($fs->check_file('wp-content/languages/plugins/helper.php', strlen($data), substr($data, 0, 256), null, null, null, $data)[0]->severity)->toBe('high')
        ->and($fs->check_file('wp-content/cache/x.l10n.php', strlen($data), substr($data, 0, 256), null, null, null, $data)[0]->severity)->toBe('high');
});

test('what counts as a file that only returns a literal array', function () {
    $yes = fn(string $s) => Sky_Sentinel_FS_Checks::returns_literal_array($s);
    expect($yes("<?php\nreturn ['a'=>['b'=>1, 2=>3.5, 'c'=>null, 'd'=>TRUE], 'e'=>'x' . \"\\0\" . 'y'];\n"))->toBeTrue()
        ->and($yes("<?php return ['a'=>1]; ?>\n"))->toBeTrue()
        ->and($yes("<?php /* generated */ return [];"))->toBeTrue()
        ->and($yes('<?php return ["a"=>"$x"];'))->toBeFalse()          // interpolation
        ->and($yes("<?php return ['a'=>system('id')];"))->toBeFalse()   // a call
        ->and($yes("<?php return ['a'=>PHP_OS];"))->toBeFalse()         // a constant
        ->and($yes("<?php return ['a'=>1]; eval(\$_POST['x']);"))->toBeFalse() // a second statement
        ->and($yes("<?php return ['a'=><<<X\nhi\nX\n];"))->toBeFalse()  // heredoc
        ->and($yes("<?php \$a = 1; return [];"))->toBeFalse()           // anything before return
        ->and($yes("<?php ['a'=>1];"))->toBeFalse()                      // no return at all
        ->and($yes("x<?php return [];"))->toBeFalse()                    // text before the tag
        ->and($yes("<?php return ['a'=>1]; ?>\n<?php eval(\$_POST['x']);"))->toBeFalse()
        ->and($yes("<?php return ['a'=>1]"))->toBeFalse();              // never finished
});

test('S3: MailPoet\'s compiled Twig cache is not flagged; the same file anywhere else, or named otherwise, is HIGH', function () {
    // 724 HIGHs on one real site.
    $fs = sentinel_fs();
    $twig = sentinel_fixture('clean/twig-cache.php.txt');
    $head = substr($twig, 0, 256);
    $name = '61/6145c290daa80e197668fc6f1a3bd812ec00d62e4429afdefecea0ca9619e132.php';
    foreach (array("wp-content/uploads/mailpoet/cache/{$name}", "wp-content/uploads/mailpoet-premium/cache/{$name}", "wp-content/uploads/sites/4/mailpoet/cache/{$name}", "wp-content/blogs.dir/4/files/mailpoet/cache/{$name}") as $p) {
        expect($fs->check_file($p, strlen($twig), $head))->toBe(array());
    }
    // Older MailPoet builds: no use block, the class straight after the name.
    $old = substr(sentinel_fixture('clean/twig-cache-old.php.txt'), 0, 256);
    expect($fs->check_file("wp-content/uploads/mailpoet-premium/cache/{$name}", 900, $old))->toBe(array())
        ->and($fs->check_file("wp-content/uploads/mailpoet-premium/cache/{$name}", 900, str_replace('extends Twig_Template', 'extends Anything', $old))[0]->severity)->toBe('high');
    foreach (array(
        array("wp-content/uploads/mailpoet/cache/{$name}", '<?php eval($_POST["x"]);'),   // right place, wrong content
        array('wp-content/uploads/mailpoet/cache/61/shell.php', $head),                   // wrong name
        array('wp-content/uploads/mailpoet/cache/6145c290daa80e197668fc6f1a3bd812ec00d62e4429afdefecea0ca9619e132.php', $head), // no hash folder
        array("wp-content/uploads/other/cache/{$name}", $head),                           // wrong plugin
    ) as list($p, $h)) {
        expect($fs->check_file($p, 500, $h)[0]->severity)->toBe('high');
    }
});

test('S4: a web page under a picture\'s name is MEDIUM when it carries nothing, CRITICAL when it carries a lure or the loader', function () {
    // Sixteen CRITICALs on one real site: old 404 pages and saved pages
    // stored where a picture or PDF should have been.
    $fs = sentinel_fs();
    $page = sentinel_fixture('clean/saved-404-page.jpg.txt');
    $f = $fs->check_file('wp-content/uploads/2002/10/portrait.jpg', strlen($page), substr($page, 0, 256), null, null, null, $page);
    expect(sentinel_ids($f))->toBe(array('S4'))->and($f[0]->severity)->toBe('medium');
    $pdf = $fs->check_file('wp-content/uploads/2018/09/screening.pdf', strlen($page), substr($page, 0, 256), null, null, null, $page);
    expect($pdf[0]->severity)->toBe('medium');

    $lure = '<!DOCTYPE html><html><body>' . sentinel_fixture('bad/clickfix-lure.html.txt') . '</body></html>';
    $f = $fs->check_file('wp-content/uploads/2026/09/verify.jpg', strlen($lure), substr($lure, 0, 256), null, null, null, $lure);
    expect($f[0]->severity)->toBe('critical')->and($f[0]->detail['carries'])->toContain('F14');

    $loader = '<!DOCTYPE html><html><body><script>' . sentinel_fixture('bad/loader-wholefile.js.txt') . '</script></body></html>';
    $f = $fs->check_file('wp-content/uploads/2026/09/banner.png', strlen($loader), substr($loader, 0, 256), null, null, null, $loader);
    expect($f[0]->severity)->toBe('critical')->and($f[0]->detail['carries'])->toContain('F10');

    // Not read: no way to vouch for it, so still CRITICAL.
    expect($fs->check_file('wp-content/uploads/2002/10/portrait.jpg', strlen($page), substr($page, 0, 256))[0]->severity)->toBe('critical');
    // PHP under a picture's name is CRITICAL whatever it says.
    expect($fs->check_file('wp-content/uploads/a.jpg', 20, '<?php echo 1;', null, null, null, '<?php echo 1;')[0]->severity)->toBe('critical');
});

test('S4: markup that starts with any tag is a web page, so a <div> lure under a picture\'s name is CRITICAL', function () {
    // Until 0.4.11 only <!DOCTYPE, <html and <script counted; a lure
    // fragment opening with <div> was not an S4 at all.
    $fs = sentinel_fs();
    $lure = sentinel_fixture('bad/clickfix-lure.html.txt');
    expect(str_starts_with($lure, '<div'))->toBeTrue();
    $f = $fs->check_file('wp-content/uploads/2026/09/verify.jpg', strlen($lure), substr($lure, 0, 256), null, null, null, $lure);
    expect($f)->toHaveCount(1)->and($f[0]->severity)->toBe('critical')->and($f[0]->detail['carries'])->toContain('F14');
    // With a byte-order mark and blank lines first, too.
    $bom = "\xEF\xBB\xBF\n\n" . $lure;
    expect($fs->check_file('wp-content/uploads/2026/09/verify.png', strlen($bom), substr($bom, 0, 256), null, null, null, $bom)[0]->severity)->toBe('critical');
    // An HTML table saved as .xls carries nothing: MEDIUM.
    $xls = "<table><tr><td>Name</td><td>Dept</td></tr></table>";
    expect($fs->check_file('wp-content/uploads/2019/01/roster.xls', strlen($xls), $xls, null, null, null, $xls)[0]->severity)->toBe('medium');
    // Real formats never start with "<": nothing.
    foreach (array("\xFF\xD8\xFF\xE0", "\x89PNG\r\n", 'GIF89a', '%PDF-1.7', "RIFF\x00\x00WEBP", "\xD0\xCF\x11\xE0") as $magic) {
        expect($fs->check_file('wp-content/uploads/x.jpg', 100, $magic . str_repeat('x', 50)))->toBe(array());
    }
    // A text file that merely mentions a tag is not markup.
    expect($fs->check_file('wp-content/uploads/x.pdf', 100, 'notes: use <div> here'))->toBe(array())
        // "< " and "<3" are not tags.
        ->and($fs->check_file('wp-content/uploads/x.doc', 100, '< 5 items'))->toBe(array());
});
