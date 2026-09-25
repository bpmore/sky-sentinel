<?php if ( ! defined( 'ABSPATH' ) ) { exit; } ?>
<h2>When an alert fires</h2>
<ol style="max-width:800px;font-size:14px;line-height:1.7">
	<li><strong>Do not delete anything yet.</strong> Open the finding on the Findings tab. The evidence copy is in the data directory with a <code>.quarantined</code> suffix; download it before anything else. Deleting first destroys the only record of what was there.</li>
	<li><strong>CRITICAL file finding</strong> (F1, F2, F10, F11, F13, S2, S4, S5): take the site offline at the edge (host maintenance mode or a CDN rule). Find every copy of the loader: the file named, plus every <code>.js</code> and every theme <code>functions.php</code> that S6 reports changed. Remove the loaders first, then the droppers and decoy packages, then any plugin that can re-install them (F16). Purge every cache layer. Fetch the home page as a visitor and confirm the loader is gone from what the browser receives.</li>
	<li><strong>CRITICAL account or session finding</strong> (D4, D5, D6, D9, L1, L2): this campaign operates with valid administrator credentials. Reset the affected account's password, rotate the salts in <code>wp-config.php</code> so every session dies, delete every pending signup, and review each administrator's <code>session_tokens</code>. Then step 2, because a credential that was used was used for something.</li>
	<li><strong>HIGH plugin or package finding</strong> (L3, S7, F16): read the plugin's main file before deciding. A self-healing plugin keeps a zip of itself and a state file; remove all three together or it comes back.</li>
	<li><strong>Any finding</strong>: purge every cache and CDN, re-fetch the rendered pages, and run whatever browser-based sweep you trust in addition to Sentinel.</li>
	<li><strong>The self-healing mu-plugin family</strong> (L9, L10, L11, S8, S9, F18 to F23, D1 <code>src</code>/<code>bu</code>/<code>bp</code>/<code>ic</code>/<code>sc_*</code>, D10). Order matters, because it restores itself from the database once an hour:
		<ol>
			<li>Delete the options first: <code>src</code>, <code>bu</code>, <code>bp</code>, <code>ic</code>, <code>sc_payload_persistent</code>, and the <code>sc_recover_check</code> / <code>sc_spread_interval</code> transients, on every blog.</li>
			<li>Then the files. They are chmod 0444 and backdated: expect the delete to need a chmod first, and do not trust modification dates when looking for copies. Check <code>mu-plugins/</code>, every drop-in (<code>advanced-cache.php</code>, <code>db.php</code>, <code>object-cache.php</code>), every theme's <code>functions.php</code>, and any <code>plugins/&lt;name&gt;.php/</code> directory.</li>
			<li>Find the hidden administrator in the <code>users</code> table directly (it is filtered out of the Users screen and REST); delete it. Look for <code>admin_</code>, <code>adm_</code>, <code>administrator_</code>, <code>backup_</code> plus six characters, and for an existing admin whose password changed with no one asking.</li>
			<li>Assume every administrator's password was captured in plaintext at login: reset them all, rotate the salts, destroy every session.</li>
			<li>Rotate every secret in <code>wp-config.php</code>, <code>.env</code> and <code>.git/config</code>, and the Stripe, Braintree, Authorize.Net and AWS keys, including WooCommerce gateway settings. The family exfiltrates them.</li>
			<li>It copies itself into every WordPress install the web server can write to: check sibling sites on the same host.</li>
			<li>Re-check plugins that were deactivated or edited: it can delete plugins and strip text from active plugins' main files on command.</li>
		</ol>
	</li>
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
	<tr><th>F18</th><td>A file that rewrites itself, then backdates and locks it read-only (CRITICAL; writing itself alone is MEDIUM)</td></tr>
	<tr><th>F19, F20</th><td>A substitution-cipher string decoder; hex-escaped strings that decode to SQL or a sensitive call</td></tr>
	<tr><th>F21</th><td>A spreader: walks server roots looking for other installs' mu-plugins</td></tr>
	<tr><th>F22</th><td>Collects payment credentials from wp-config.php, .env, .git/config or WooCommerce gateway settings</td></tr>
	<tr><th>F23</th><td>Writes active_plugins with raw SQL, bypassing activation</td></tr>
	<tr><th>S1, S2</th><td>Plant-naming (word-unixtime) and decoy packages</td></tr>
	<tr><th>S3, S4, S5</th><td>PHP in uploads/cache/languages; a media file whose bytes are a zip or PHP; dropper dotfiles</td></tr>
	<tr><th>S6, S7</th><td>Files and packages that differ from the signed baseline</td></tr>
	<tr><th>S8</th><td>A plugin or theme directory named like a PHP file (the spreader's fallback)</td></tr>
	<tr><th>S9</th><td>PHP locked read-only (0444), on the load path or backdated</td></tr>
	<tr><th>D1 to D7</th><td>Options (including PHP stored as an option), content, signups, administrator set, hidden users (by count_users() and by a real user query), hidden plugins, activation changes</td></tr>
	<tr><th>D10</th><td>An administrator named like the rogue account (admin_/adm_/administrator_/backup_ + 6)</td></tr>
	<tr><th>L2</th><td>Someone became an administrator, or an administrator's password was set outside the lost-password flow</td></tr>
	<tr><th>L8</th><td>The baseline itself does not verify, or Sentinel's own files changed</td></tr>
	<tr><th>L9</th><td>A mu-plugin or drop-in is new or changed since the baseline (checked every minute)</td></tr>
	<tr><th>L10</th><td>A callback on a user-hiding or password hook, judged by where its file lives</td></tr>
	<tr><th>L11</th><td>WordPress made an on-chain (eth_call) request or called a campaign RPC gateway</td></tr>
	<tr><th>L12</th><td>A cron schedule that was not there when the baseline was signed</td></tr>
	<tr><th>L13</th><td>No failed logins at all yesterday, after a week that averaged ten or more a day (MEDIUM, digest). Something upstream now blocks attempts, or Sentinel stopped hearing them: fail a login ten times with a made-up username and see whether L7 fires. The Dashboard's Failed logins table shows the week.</td></tr>
	<tr><th>L1 to L7</th><td>Logins, promotions, packages, the editor, file managers, user enumeration, login bursts, as they happen</td></tr>
	<tr><th>L8</th><td>Sentinel's own files, or the baseline itself, do not verify</td></tr>
	<tr><th>P0 to P4</th><td>The rendered page: unreachable, carries the loader, serves a bad script, allows a service worker, loads something new since the baseline</td></tr>
</tbody></table>
