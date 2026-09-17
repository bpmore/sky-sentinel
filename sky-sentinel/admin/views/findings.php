<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }
$status = sanitize_key( $_GET['status'] ?? 'open' );
$rows   = $data['findings']->list( $status, 500 );
$base   = Sky_Sentinel_Alerts::admin_url() . '&tab=findings&status=';
?>
<p>
	<?php foreach ( array( 'open', 'acknowledged', 'muted', 'resolved', 'all' ) as $s ) : ?>
		<a class="button <?php echo $s === $status ? 'button-primary' : ''; ?>" href="<?php echo esc_url( $base . $s ); ?>"><?php echo esc_html( ucfirst( $s ) ); ?></a>
	<?php endforeach; ?>
</p>
<p>
	Download <?php echo esc_html( $status ); ?>:
	<a class="button" href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=sky_sentinel_export&format=csv&status=' . $status ), 'sky_sentinel_export' ) ); ?>">CSV</a>
	<a class="button" href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=sky_sentinel_export&format=json&status=' . $status ), 'sky_sentinel_export' ) ); ?>">JSON</a>
	<span class="description">JSON includes the last run's numbers; paste it wherever the findings need reading.</span>
</p>
<?php if ( ! $rows ) : ?>
	<p>Nothing <?php echo esc_html( $status ); ?>.</p>
<?php else : ?>
<p class="description" style="max-width:900px">
	<strong>Resolved</strong> means it is gone; if the same thing is seen again it reopens and alerts, because an artifact that returns was re-planted.
	<strong>Acknowledged</strong> means it is known and still there; it stays quiet until its content changes. Use this for a plugin's odd habits, a stale signup you have decided to keep, a broken upload.
	<strong>Muted</strong> is acknowledged with a written reason.
	Marking a persistent benign row resolved brings it straight back on the next scan.
</p>
<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" id="sky-sentinel-bulk">
	<?php wp_nonce_field( 'sky_sentinel_finding' ); ?>
	<input type="hidden" name="action" value="sky_sentinel_finding">
	<p>
		<label><input type="checkbox" id="sky-sentinel-all"> All</label>
		<select name="status">
			<?php foreach ( array( 'acknowledged', 'resolved', 'muted', 'open' ) as $s ) : ?><option value="<?php echo $s; ?>"><?php echo esc_html( $s ); ?></option><?php endforeach; ?>
		</select>
		<input type="text" name="note" placeholder="note (required to mute)" style="width:260px">
		<button class="button">Apply to checked</button>
	</p>
<table class="widefat striped">
	<thead><tr><th></th><th>Severity</th><th>Detector</th><th>Site</th><th>Subject</th><th>What</th><th>First seen</th><th>Last seen</th><th>Seen</th><th>Evidence</th><th>Action</th></tr></thead>
	<tbody>
	<?php foreach ( $rows as $r ) : $detail = json_decode( (string) $r->detail, true ); ?>
		<tr>
			<td><input type="checkbox" name="ids[]" value="<?php echo (int) $r->id; ?>" form="sky-sentinel-bulk"></td>
			<td><strong style="color:<?php echo 'critical' === $r->severity ? '#b00020' : ( 'high' === $r->severity ? '#e65100' : '#555' ); ?>"><?php echo esc_html( strtoupper( $r->severity ) ); ?></strong></td>
			<td><?php echo esc_html( $r->detector ); ?></td>
			<td><?php echo (int) $r->blog_id ?: 'network'; ?></td>
			<td><code style="word-break:break-all"><?php echo esc_html( $r->subject ); ?></code><?php if ( $r->sha256 ) : ?><br><small>sha256 <?php echo esc_html( substr( $r->sha256, 0, 16 ) ); ?>...</small><?php endif; ?></td>
			<td><?php echo esc_html( $r->summary ); ?>
				<?php if ( is_array( $detail ) && $detail ) : ?><details><summary>detail</summary><pre style="white-space:pre-wrap;font-size:11px"><?php echo esc_html( wp_json_encode( $detail, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) ); ?></pre></details><?php endif; ?>
				<?php if ( $r->note ) : ?><p><em><?php echo esc_html( $r->note ); ?></em></p><?php endif; ?>
			</td>
			<td><?php echo esc_html( $r->first_seen ); ?></td>
			<td><?php echo esc_html( $r->last_seen ); ?></td>
			<td><?php echo (int) $r->seen_count; ?></td>
			<td><?php if ( $r->evidence ) : ?>
				<a class="button button-small" href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=sky_sentinel_evidence&id=' . (int) $r->id ), 'sky_sentinel_evidence' ) ); ?>">Download</a>
				<br><code style="font-size:10px"><?php echo esc_html( basename( $r->evidence ) ); ?></code>
			<?php else : ?>-<?php endif; ?></td>
			<td>
				<?php $fid = 'sky-sentinel-row-' . (int) $r->id; ?>
				<select name="status" form="<?php echo $fid; ?>">
					<?php foreach ( array( 'open', 'acknowledged', 'resolved', 'muted' ) as $s ) : ?>
						<option value="<?php echo $s; ?>" <?php selected( $s, $r->status ); ?>><?php echo esc_html( $s ); ?></option>
					<?php endforeach; ?>
				</select>
				<input type="text" name="note" form="<?php echo $fid; ?>" placeholder="note (required to mute)" style="width:140px">
				<button class="button" form="<?php echo $fid; ?>">Save</button>
			</td>
		</tr>
	<?php endforeach; ?>
	</tbody>
</table>
</form>
<?php foreach ( $rows as $r ) : ?>
	<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" id="sky-sentinel-row-<?php echo (int) $r->id; ?>">
		<?php wp_nonce_field( 'sky_sentinel_finding' ); ?>
		<input type="hidden" name="action" value="sky_sentinel_finding">
		<input type="hidden" name="id" value="<?php echo (int) $r->id; ?>">
	</form>
<?php endforeach; ?>
<script>document.getElementById('sky-sentinel-all').addEventListener('change',function(e){document.querySelectorAll('input[name="ids[]"]').forEach(function(c){c.checked=e.target.checked;});});</script>
<?php endif; ?>
