<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }
$status = sanitize_key( $_GET['status'] ?? 'open' );
list( $sort, $dir ) = Sky_Sentinel_Findings::sort_of( sanitize_key( $_GET['sort'] ?? '' ), sanitize_key( $_GET['dir'] ?? '' ) );
$detector = Sky_Sentinel_Findings::detector_of( sanitize_key( $_GET['detector'] ?? '' ) );
$limit    = 500;
$rows     = $data['findings']->list( $status, $limit, $sort, $dir, $detector );
$counts   = $data['findings']->detector_counts( $status );
$view     = fn( array $args ) => add_query_arg( $args + array( 'tab' => 'findings', 'status' => $status, 'sort' => $sort, 'dir' => $dir, 'detector' => $detector ), Sky_Sentinel_Alerts::admin_url() );
// A sortable header: a first click takes the column's usual direction, a
// second click on the same column reverses it.
$th = function ( string $key, string $label ) use ( $sort, $dir, $view ) {
	$next  = $key === $sort ? ( 'asc' === $dir ? 'desc' : 'asc' ) : Sky_Sentinel_Findings::SORTS[ $key ];
	$arrow = $key === $sort ? ( 'asc' === $dir ? ' &#9650;' : ' &#9660;' ) : '';
	printf( '<th%s><a href="%s" style="text-decoration:none">%s%s</a></th>', $key === $sort ? ' aria-sort="' . ( 'asc' === $dir ? 'ascending' : 'descending' ) . '"' : '', esc_url( $view( array( 'sort' => $key, 'dir' => $next ) ) ), esc_html( $label ), $arrow );
};
$keep = function () use ( $status, $sort, $dir, $detector ) {
	foreach ( array( 'view_status' => $status, 'view_sort' => $sort, 'view_dir' => $dir, 'view_detector' => $detector ) as $k => $v ) {
		printf( '<input type="hidden" name="%s" value="%s">', esc_attr( $k ), esc_attr( $v ) );
	}
};
?>
<p>
	<?php foreach ( array( 'open', 'acknowledged', 'muted', 'resolved', 'all' ) as $s ) : ?>
		<a class="button <?php echo $s === $status ? 'button-primary' : ''; ?>" href="<?php echo esc_url( $view( array( 'status' => $s, 'detector' => '' ) ) ); ?>"><?php echo esc_html( ucfirst( $s ) ); ?></a>
	<?php endforeach; ?>
</p>
<?php if ( count( $counts ) > 1 || '' !== $detector ) : ?>
<p>
	<?php // Filter by detector, so "select all" can mean "all L6" rather than everything. ?>
	Detector:
	<a class="button button-small <?php echo '' === $detector ? 'button-primary' : ''; ?>" href="<?php echo esc_url( $view( array( 'detector' => '' ) ) ); ?>">All (<?php echo (int) array_sum( $counts ); ?>)</a>
	<?php foreach ( $counts as $d => $n ) : ?>
		<a class="button button-small <?php echo $d === $detector ? 'button-primary' : ''; ?>" href="<?php echo esc_url( $view( array( 'detector' => $d ) ) ); ?>"><?php echo esc_html( $d ); ?> (<?php echo (int) $n; ?>)</a>
	<?php endforeach; ?>
</p>
<?php endif; ?>
<p>
	Download <?php echo esc_html( $status ); ?>:
	<a class="button" href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=sky_sentinel_export&format=csv&status=' . $status . '&sort=' . $sort . '&dir=' . $dir . '&detector=' . $detector ), 'sky_sentinel_export' ) ); ?>">CSV</a>
	<a class="button" href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=sky_sentinel_export&format=json&status=' . $status . '&sort=' . $sort . '&dir=' . $dir . '&detector=' . $detector ), 'sky_sentinel_export' ) ); ?>">JSON</a>
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
	<?php $keep(); ?>
	<p>
		<strong id="sky-sentinel-count">0 selected</strong>
		<span class="description">(tick the box in the table header for every row shown, shift-click for a range, or click anywhere on a row)</span>
		<br>
		Mark selected as
		<select name="status">
			<?php foreach ( array( 'acknowledged', 'resolved', 'muted', 'open' ) as $s ) : ?><option value="<?php echo $s; ?>"><?php echo esc_html( $s ); ?></option><?php endforeach; ?>
		</select>
		<input type="text" name="note" placeholder="note (required to mute)" style="width:260px">
		<button class="button">Apply to checked</button>
	</p>
	<?php $shown = '' === $detector ? array_sum( $counts ) : ( $counts[ $detector ] ?? 0 ); if ( $shown > $limit ) : ?>
		<p class="description">Showing the first <?php echo (int) $limit; ?> of <?php echo (int) $shown; ?>. Apply to these, and the rest move up.</p>
	<?php endif; ?>
<table class="widefat striped" id="sky-sentinel-table">
	<thead><tr><th style="width:2em"><input type="checkbox" id="sky-sentinel-all" title="Select every row shown" aria-label="Select every row shown"></th><?php $th( 'severity', 'Severity' ); $th( 'detector', 'Detector' ); $th( 'site', 'Site' ); $th( 'subject', 'Subject' ); ?><th>What</th><?php $th( 'first_seen', 'First seen' ); $th( 'last_seen', 'Last seen' ); $th( 'seen', 'Seen' ); ?><th>Evidence</th><?php $th( 'status', 'Status' ); ?></tr></thead>
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
		<?php $keep(); ?>
	</form>
<?php endforeach; ?>
<script>
(function(){
	var boxes = [].slice.call(document.querySelectorAll('#sky-sentinel-table tbody input[name="ids[]"]'));
	var all = document.getElementById('sky-sentinel-all'), count = document.getElementById('sky-sentinel-count'), last = null;
	function update(){
		var n = boxes.filter(function(b){ return b.checked; }).length;
		count.textContent = n + ' selected';
		all.checked = n > 0 && n === boxes.length;
		all.indeterminate = n > 0 && n < boxes.length;
		boxes.forEach(function(b){ b.closest('tr').style.background = b.checked ? '#f0f6fc' : ''; });
	}
	// Set one row, or with Shift every row between it and the last one touched.
	function set(i, on, shift){
		var a = shift && last !== null ? Math.min(last, i) : i, z = shift && last !== null ? Math.max(last, i) : i;
		for (var k = a; k <= z; k++) { boxes[k].checked = on; }
		last = i;
		update();
	}
	all.addEventListener('change', function(){ boxes.forEach(function(b){ b.checked = all.checked; }); last = null; update(); });
	boxes.forEach(function(b, i){
		b.addEventListener('click', function(e){ set(i, b.checked, e.shiftKey); });
		b.closest('tr').addEventListener('click', function(e){
			// Links, buttons, the per-row form and the detail toggle keep their own clicks.
			if (e.target.closest('a,button,input,select,textarea,label,summary,pre')) { return; }
			set(i, !b.checked, e.shiftKey);
		});
		b.closest('tr').style.cursor = 'pointer';
	});
	update();
})();
</script>
<?php endif; ?>
