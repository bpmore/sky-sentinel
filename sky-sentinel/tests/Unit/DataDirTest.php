<?php
/**
 * Sentinel's data folder. Until 0.4.17 an unwritable one ended every scan in
 * an uncaught exception: a white "critical error" page from Scan now, and
 * every scheduled scan dying silently. Real temporary folders, because the
 * point is what the filesystem actually allows.
 */

function sentinel_tmp_dir(): string {
    $d = sys_get_temp_dir() . '/sentinel-datadir-' . bin2hex(random_bytes(4));
    mkdir($d, 0700);
    return $d;
}

function sentinel_tmp_rm(string $dir): void {
    if (!is_dir($dir)) { return; }
    @chmod($dir, 0700);
    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST) as $f) {
        @chmod($f->getPathname(), 0700);
        $f->isDir() ? rmdir($f->getPathname()) : unlink($f->getPathname());
    }
    rmdir($dir);
}

/**
 * Run $fn with PHP warnings swallowed: under the test harness "@" does not
 * silence the expected "Permission denied", and an error handler does.
 */
function sentinel_quietly(callable $fn) {
    set_error_handler(fn() => true);
    try { return $fn(); } finally { restore_error_handler(); }
}

/**
 * Make $dir refuse writes, or skip: as root, permissions refuse nothing, and a
 * test that "passes" there would prove nothing about the refusal path.
 */
function sentinel_make_unwritable(string $dir): void {
    chmod($dir, 0550);
    clearstatcache();
    if (false !== sentinel_quietly(fn() => file_put_contents($dir . '/.probe-check', ''))) {
        @unlink($dir . '/.probe-check');
        test()->markTestSkipped('This process can write to a mode 0550 folder (running as root?), so the refusal path cannot be exercised here.');
    }
}

test('a writable folder is ok, and the write probe leaves nothing behind', function () {
    $d = sentinel_tmp_dir();
    try {
        expect(Sky_Sentinel_Data_Dir::check($d))->toBe(array('ok' => true, 'path' => $d, 'problem' => null))
            ->and(glob($d . '/{,.}*', GLOB_BRACE) ?: array())->toBe(array_values(array_filter(glob($d . '/{,.}*', GLOB_BRACE) ?: array(), fn($p) => in_array(basename($p), array('.', '..'), true))));
    } finally { sentinel_tmp_rm($d); }
});

test('a missing folder is created (it used to be made only on install)', function () {
    $parent = sentinel_tmp_dir();
    $d = $parent . '/private/sky-sentinel';
    try {
        expect(is_dir($d))->toBeFalse();
        expect(Sky_Sentinel_Data_Dir::check($d)['ok'])->toBeTrue()->and(is_dir($d))->toBeTrue();
    } finally { sentinel_tmp_rm($parent); }
});

test('the deny files are written only when the folder sits under the web root', function () {
    $a = sentinel_tmp_dir(); $b = sentinel_tmp_dir();
    try {
        Sky_Sentinel_Data_Dir::check($a, true);
        Sky_Sentinel_Data_Dir::check($b, false);
        expect(file_get_contents($a . '/.htaccess'))->toContain('Require all denied')
            ->and(file_exists($a . '/index.html'))->toBeTrue()
            ->and(file_exists($b . '/.htaccess'))->toBeFalse();
    } finally { sentinel_tmp_rm($a); sentinel_tmp_rm($b); }
});

test('a folder PHP cannot write to is reported with its owner, its mode and who PHP runs as', function () {
    $d = sentinel_tmp_dir();
    try {
        sentinel_make_unwritable($d);
        $r = sentinel_quietly(fn() => Sky_Sentinel_Data_Dir::check($d));
        expect($r['ok'])->toBeFalse()
            ->and($r['problem'])->toContain('PHP cannot write to it')->toContain('mode 0550')->toContain('owned by');
        if (function_exists('posix_geteuid')) {
            expect($r['problem'])->toContain('PHP runs as')->toContain('uid ' . posix_geteuid());
        }
    } finally { sentinel_tmp_rm($d); }
});

test('a folder that is missing and cannot be created says so, describing the parent', function () {
    $parent = sentinel_tmp_dir();
    try {
        sentinel_make_unwritable($parent);
        $r = sentinel_quietly(fn() => Sky_Sentinel_Data_Dir::check($parent . '/sky-sentinel'));
        expect($r['ok'])->toBeFalse()
            ->and($r['problem'])->toContain('does not exist and could not be created')->toContain('mode 0550');
    } finally { sentinel_tmp_rm($parent); }
});
