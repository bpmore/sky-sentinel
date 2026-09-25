<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }
$b = $data['baseline']; $c = $data['counts'];
?>
<h2>What the baseline is</h2>
<p>A signed record of every file's hash outside <code>uploads/</code>, the plugin and theme directories, the administrators, and what is active. Once signed, every run reports what is new, changed, or gone (S6, S7), and any administrator or activation that was not there when you signed (D4, D7).</p>
<p>The signature uses <code>SKY_SENTINEL_KEY</code> from this site's <code>sky-sentinel-config.php</code> (or <code>wp-config.php</code>, which wins where it is set), so the database alone cannot re-sign it. <?php echo null === Sky_Sentinel_Runner::key() ? '<strong style="color:#b00020">That constant is not set, or is shorter than 32 characters. Signing is disabled.</strong>' : 'The key is set.'; ?></p>

<h2>Current baseline</h2>
<p>
	<?php if ( 'ok' === $b['state'] ) : ?>
		Signed <?php echo esc_html( gmdate( 'Y-m-d H:i', (int) $b['signed_at'] ) ); ?> UTC by user #<?php echo (int) $b['signed_by']; ?> over <?php echo (int) $b['files']; ?> files.
	<?php elseif ( 'invalid' === $b['state'] ) : ?>
		<strong style="color:#b00020">Stored, but does not verify.</strong> Either the key changed or the stored manifest was altered. Re-sign only after confirming which.
	<?php else : ?>
		None yet.
	<?php endif; ?>
</p>

<h2>Sign the current state as clean</h2>
<p><strong>Only after the install has been verified clean</strong>: browser sweep v2 shows nothing above MEDIUM, and Sentinel has no open CRITICAL findings (<?php echo (int) $c['critical']; ?> open now). A baseline signed over a live dropper says the dropper belongs there.</p>
<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
	<?php wp_nonce_field( 'sky_sentinel_sign' ); ?>
	<input type="hidden" name="action" value="sky_sentinel_sign">
	<p><label>Type <code><?php echo esc_html( $data['site'] ); ?></code> to confirm: <input type="text" name="confirm" autocomplete="off" required></label></p>
	<p><button class="button button-primary" <?php disabled( $c['critical'] > 0 || null === Sky_Sentinel_Runner::key() ); ?>>Sign baseline</button></p>
</form>
