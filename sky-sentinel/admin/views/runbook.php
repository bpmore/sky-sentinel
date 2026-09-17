<?php if ( ! defined( 'ABSPATH' ) ) { exit; } ?>
<h2>When an alert fires</h2>
<ol style="max-width:800px;font-size:14px;line-height:1.7">
	<li><strong>Do not delete anything yet.</strong> Open the finding on the Findings tab. The evidence copy is in the data directory with a <code>.quarantined</code> suffix; download it before anything else. Deleting first destroys the only record of what was there.</li>
	<li><strong>CRITICAL file finding</strong> (F1, F2, F10, F11, F13, S2, S4, S5): take the site offline at the edge (host maintenance mode or a CDN rule). Find every copy of the loader: the file named, plus every <code>.js</code> and every theme <code>functions.php</code> that S6 reports changed. Remove the loaders first, then the droppers and decoy packages, then any plugin that can re-install them (F16). Purge every cache layer. Fetch the home page as a visitor and confirm the loader is gone from what the browser receives.</li>
	<li><strong>CRITICAL account or session finding</strong> (D4, D5, D6, D9, L1, L2): this campaign operates with valid administrator credentials. Reset the affected account's password, rotate the salts in <code>wp-config.php</code> so every session dies, delete every pending signup, and review each administrator's <code>session_tokens</code>. Then step 2, because a credential that was used was used for something.</li>
	<li><strong>HIGH plugin or package finding</strong> (L3, S7, F16): read the plugin's main file before deciding. A self-healing plugin keeps a zip of itself and a state file; remove all three together or it comes back.</li>
	<li><strong>Any finding</strong>: purge every cache and CDN, re-fetch the rendered pages, and run whatever browser-based sweep you trust in addition to Sentinel.</li>
	<li>Record what you did: mark the finding resolved with a note. When the install is clean again, re-sign the baseline. Do not re-sign before.</li>
</ol>
<h2>What the detector ids mean</h2>
<table class="widefat striped" style="max-width:900px"><tbody>
	<tr><th>F1</th><td>SHA-256 in the known-bad list</td></tr>
	<tr><th>F2, F3, F4, F6</th><td>The dropper family: shared decoder alphabet, HTML-comment prelude, one POST key + temp dir + include, marker file</td></tr>
	<tr><th>F5</th><td>Write-then-include (MEDIUM; some security plugins and libraries do this legitimately)</td></tr>
	<tr><th>F7, F8</th><td>Admin-hider and self-hiding plugins</td></tr>
	<tr><th>F9, F10, F11, F12, F13</th><td>The EtherHiding loader: decode-and-run shape, decoder structure, campaign indicators, on-chain resolver calls, inline echo from a theme hook</td></tr>
	<tr><th>F14</th><td>ClickFix lure text</td></tr>
	<tr><th>F15</th><td>Service worker registration, or a .js at the webroot</td></tr>
	<tr><th>F16</th><td>A plugin that can re-install itself</td></tr>
	<tr><th>F17</th><td>eval/base64 in a theme entry file (MEDIUM)</td></tr>
	<tr><th>S1, S2</th><td>Plant-naming (word-unixtime) and decoy packages</td></tr>
	<tr><th>S3, S4, S5</th><td>PHP in uploads/cache/languages; a media file whose bytes are a zip or PHP; dropper dotfiles</td></tr>
	<tr><th>S6, S7</th><td>Files and packages that differ from the signed baseline</td></tr>
	<tr><th>D1 to D7</th><td>Options, content, signups, administrator set, hidden users, hidden plugins, activation changes</td></tr>
	<tr><th>D8, D9</th><td>Live administrator sessions from a bad origin</td></tr>
	<tr><th>L1 to L7</th><td>Logins, promotions, packages, the editor, file managers, user enumeration, login bursts, as they happen</td></tr>
	<tr><th>L8</th><td>Sentinel's own files, or the baseline itself, do not verify</td></tr>
	<tr><th>P0 to P4</th><td>The rendered page: unreachable, carries the loader, serves a bad script, allows a service worker, loads something new since the baseline</td></tr>
</tbody></table>
