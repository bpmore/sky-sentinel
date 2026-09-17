<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }
$recipients = implode( ', ', (array) get_site_option( 'sky_sentinel_recipients', array() ) );
$webhook_locked   = Sky_Sentinel_Alerts::locked( 'SKY_SENTINEL_WEBHOOK' );
$heartbeat_locked = Sky_Sentinel_Alerts::locked( 'SKY_SENTINEL_HEARTBEAT' );
?>
<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
	<?php wp_nonce_field( 'sky_sentinel_settings' ); ?>
	<input type="hidden" name="action" value="sky_sentinel_settings">
	<table class="form-table">
		<tr><th><label for="recipients">Alert email recipients</label></th>
			<td><input class="regular-text" id="recipients" name="recipients" value="<?php echo esc_attr( $recipients ); ?>" placeholder="you@example.org, colleague@example.org">
			<p class="description">Plus anything in <code>SKY_SENTINEL_ALERT_TO</code> in wp-config.php, which a database edit cannot remove. Effective list now: <?php echo esc_html( implode( ', ', Sky_Sentinel_Alerts::recipients() ) ?: 'nobody' ); ?></p></td></tr>
		<tr><th><label for="webhook">Teams or Slack webhook URL</label></th>
			<td><input class="regular-text" id="webhook" name="webhook" value="<?php echo esc_attr( Sky_Sentinel_Alerts::webhook_url() ); ?>" <?php disabled( $webhook_locked ); ?>>
			<p class="description"><?php echo $webhook_locked ? 'Set by <code>SKY_SENTINEL_WEBHOOK</code> in wp-config.php (recommended: the database is not where this belongs).' : 'Better: define <code>SKY_SENTINEL_WEBHOOK</code> in wp-config.php instead, so a database edit cannot silence it.'; ?></p></td></tr>
		<tr><th><label for="heartbeat">Heartbeat URL</label></th>
			<td><input class="regular-text" id="heartbeat" name="heartbeat" value="<?php echo esc_attr( Sky_Sentinel_Alerts::heartbeat_url() ); ?>" <?php disabled( $heartbeat_locked ); ?>>
			<p class="description">Healthchecks.io or UptimeRobot heartbeat. Pinged only when a run COMPLETES. Set the monitor's period to 6 hours and its grace to 6 hours: two missed runs is the alarm.</p></td></tr>
		<tr><th><label for="cidrs">Networks administrators log in from</label></th>
			<td><input class="regular-text" id="cidrs" name="cidrs" value="<?php echo esc_attr( implode( ', ', (array) get_site_option( 'sky_sentinel_network_cidrs', array() ) ) ); ?>" placeholder="203.0.113.0/24, 198.51.100.7">
			<p class="description">CIDRs, comma-separated. <strong>Empty means not configured</strong>: only the attacker list, the tooling user-agents and Tor exits are checked. Once it has entries, an administrator login or live session from anywhere else is HIGH (L1, D8). Start with your organisation's range and each administrator's home /24, taken from the first L1 or D8 finding each of them produces. iCloud Private Relay, carrier networks and VPNs come out of shared address space that cannot be pinned to a person; either log in from a listed network or accept a HIGH the first time each new /24 appears. Never allow-list a CDN, a carrier or a whole ISP.</p></td></tr>
		<tr><th>REST user enumeration</th>
			<td><label><input type="checkbox" name="block_enum" value="1" <?php checked( get_site_option( 'sky_sentinel_block_user_enum' ) ); ?>> Refuse unauthenticated <code>GET /wp-json/wp/v2/users</code></label>
			<p class="description">Off: logged as MEDIUM once per IP per day (L6). On: also answered 401. The attacker enumerated users this way before the first login.</p></td></tr>
	</table>
	<p><button class="button button-primary">Save</button></p>
</form>

<h2>Tor exit list</h2>
<p><?php $tor = Sky_Sentinel_Runner::tor_exits( Sky_Sentinel::data_dir() ); echo $tor ? count( $tor ) . ' addresses on file, refreshed weekly.' : 'Not downloaded yet; the weekly job fetches it. Until then Tor exits are not recognised.'; ?></p>

<h2>Test both channels</h2>
<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
	<?php wp_nonce_field( 'sky_sentinel_test_alert' ); ?>
	<input type="hidden" name="action" value="sky_sentinel_test_alert">
	<p><button class="button">Send test alert</button> <span class="description">Sends an email, posts to the webhook, and pings the heartbeat. Check all three arrived.</span></p>
</form>

<h2>Signatures in force</h2>
<p><code><?php echo esc_html( $data['sig']->version() ); ?></code>. Shipped copies live in <code><?php echo esc_html( Sky_Sentinel::dir() . '/signatures/' ); ?></code>; a file pasted below replaces the shipped one whole, is validated before it is stored, and takes effect on the next scan. When a new variant is reported, paste the updated JSON here on every site rather than FTP-ing it to each.</p>
<?php $overrides = (array) get_site_option( 'sky_sentinel_signature_overrides', array() ); ?>
<?php foreach ( Sky_Sentinel_Signatures::FILES as $key => $file ) : ?>
	<details style="max-width:900px;margin-bottom:.5em">
		<summary><code><?php echo esc_html( $file ); ?></code>: <?php echo isset( $overrides[ $key ] ) ? 'uploaded copy in force' : 'shipped copy in force'; ?></summary>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<?php wp_nonce_field( 'sky_sentinel_signatures' ); ?>
			<input type="hidden" name="action" value="sky_sentinel_signatures">
			<input type="hidden" name="which" value="<?php echo esc_attr( $key ); ?>">
			<p><textarea name="json" rows="8" style="width:100%;font-family:monospace;font-size:12px" placeholder="Paste the whole JSON file, including its &quot;version&quot;."></textarea></p>
			<p><button class="button button-primary">Apply</button>
			<?php if ( isset( $overrides[ $key ] ) ) : ?><button class="button" name="reset" value="1">Reset to shipped</button><?php endif; ?></p>
		</form>
	</details>
<?php endforeach; ?>

<h2>Storage</h2>
<p>Manifests, evidence copies and the off-database baseline copy: <code><?php echo esc_html( Sky_Sentinel::data_dir() ); ?></code></p>

<h2>Recent events</h2>
<table class="widefat striped" style="max-width:1000px"><thead><tr><th>When (UTC)</th><th>Event</th><th>User</th><th>Detail</th></tr></thead><tbody>
<?php foreach ( $data['findings']->recent_events( 40 ) as $e ) : ?>
	<tr><td><?php echo esc_html( $e->at ); ?></td><td><?php echo esc_html( $e->kind ); ?></td><td><?php echo $e->user_id ? '#' . (int) $e->user_id : '-'; ?></td><td><code style="font-size:11px;word-break:break-all"><?php echo esc_html( mb_substr( (string) $e->detail, 0, 300 ) ); ?></code></td></tr>
<?php endforeach; ?>
</tbody></table>
