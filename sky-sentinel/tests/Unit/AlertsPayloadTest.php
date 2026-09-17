<?php
/**
 * The webhook body. Teams' replacement for the retired connector is a
 * Workflow that accepts an Adaptive Card; Slack reads "text".
 */

test('a Teams Workflow URL gets an Adaptive Card with the findings as facts', function () {
    $f = array(
        new Sky_Sentinel_Finding('L2', 'critical', 'user:sysadmin2', 'sysadmin2 was made an administrator'),
        new Sky_Sentinel_Finding('L3', 'high', 'plugin:site-helper', 'A plugin was UPLOADED'),
    );
    $p = Sky_Sentinel_Alerts::payload('https://prod-12.westus.logic.azure.com:443/workflows/abc/triggers/manual/paths/invoke?sig=x', '[Sky Sentinel] CRITICAL', $f, 'https://x/runbook', 'https://x/admin');
    expect($p['type'])->toBe('message')
        ->and($p['attachments'][0]['contentType'])->toBe('application/vnd.microsoft.card.adaptive')
        ->and($p['attachments'][0]['content']['type'])->toBe('AdaptiveCard')
        ->and($p['attachments'][0]['content']['body'][0]['color'])->toBe('Attention')
        ->and($p['attachments'][0]['content']['body'][2]['facts'])->toHaveCount(2)
        ->and($p['attachments'][0]['content']['body'][2]['facts'][1]['title'])->toBe('HIGH L3')
        ->and($p['attachments'][0]['content']['actions'][1]['url'])->toBe('https://x/runbook');
    // It must survive JSON without a schema key being mangled.
    expect(json_decode(json_encode($p), true)['attachments'][0]['content']['$schema'])->toContain('adaptivecards.io');
});

test('a Slack URL gets plain text', function () {
    $f = array(new Sky_Sentinel_Finding('L2', 'high', 'user:x', 'promoted'));
    $p = Sky_Sentinel_Alerts::payload('https://hooks.slack.com/services/T/B/x', 'subject', $f, 'https://x/runbook', 'https://x/admin');
    expect($p)->toHaveKey('text')->not->toHaveKey('attachments')
        ->and($p['text'])->toContain('HIGH L2')->toContain('runbook');
});

test('the card caps at ten facts, however many findings there are', function () {
    $f = array();
    for ($i = 0; $i < 40; $i++) { $f[] = new Sky_Sentinel_Finding('D2', 'medium', "post#$i", 'x'); }
    $p = Sky_Sentinel_Alerts::payload('https://prod-1.logic.azure.com/x', 's', $f, 'r', 'a');
    expect($p['attachments'][0]['content']['body'][2]['facts'])->toHaveCount(10)
        ->and($p['attachments'][0]['content']['body'][1]['text'])->toContain('40 finding(s)');
});

test('an empty constant is "not set", not "set to nothing"', function () {
    // The sample config defines every constant as ''. That must fall
    // through to the settings page, not lock it and supply nothing.
    define('SKY_SENTINEL_TEST_EMPTY', '');
    define('SKY_SENTINEL_TEST_SPACES', '   ');
    define('SKY_SENTINEL_TEST_SET', 'https://prod-1.logic.azure.com/x');
    expect(Sky_Sentinel_Alerts::constant('SKY_SENTINEL_TEST_EMPTY'))->toBe('')
        ->and(Sky_Sentinel_Alerts::constant('SKY_SENTINEL_TEST_SPACES'))->toBe('')
        ->and(Sky_Sentinel_Alerts::constant('SKY_SENTINEL_TEST_MISSING'))->toBe('')
        ->and(Sky_Sentinel_Alerts::constant('SKY_SENTINEL_TEST_SET'))->toBe('https://prod-1.logic.azure.com/x')
        ->and(Sky_Sentinel_Alerts::locked('SKY_SENTINEL_TEST_EMPTY'))->toBeFalse()
        ->and(Sky_Sentinel_Alerts::locked('SKY_SENTINEL_TEST_SET'))->toBeTrue();
});
