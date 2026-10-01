<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }
$c = $data['counts']; $last = $data['last_run']; $b = $data['baseline'];
$nonce = wp_create_nonce( 'sky_sentinel_step' );
?>
<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;max-width:900px">
	<?php foreach ( array( 'critical' => '#b00020', 'high' => '#e65100', 'medium' => '#8a6d00', 'info' => '#555' ) as $sev => $color ) : ?>
		<div style="border:1px solid #ccd0d4;border-left:5px solid <?php echo $color; ?>;padding:12px;background:#fff">
			<div style="font-size:28px;font-weight:600"><?php echo (int) $c[ $sev ]; ?></div>
			<div style="text-transform:uppercase;color:#555"><?php echo esc_html( $sev ); ?> open</div>
		</div>
	<?php endforeach; ?>
</div>

<h2>Last run</h2>
<?php if ( is_array( $last ) ) : ?>
	<table class="widefat striped" style="max-width:900px"><tbody>
		<tr><th>Finished</th><td><?php echo esc_html( $last['at'] ); ?> (<?php echo esc_html( $last['trigger'] ); ?>)</td></tr>
		<tr><th>Files walked</th><td><?php echo (int) $last['files']; ?> (<?php echo (int) $last['hashed']; ?> hashed, <?php echo (int) $last['content']; ?> read for content, <?php echo size_format( (int) $last['bytes'] ); ?>)</td></tr>
		<tr><th>Took</th><td><?php echo (int) $last['seconds']; ?> s across cron ticks</td></tr>
		<tr><th>Findings this run</th><td><?php echo (int) $last['findings']; ?> seen, <?php echo (int) $last['new_alerts']; ?> new at HIGH or above</td></tr>
		<tr><th>Alert delivery</th><td><?php
			$say = fn( $v ) => is_string( $v ) ? $v : ( $v ? 'ok' : 'FAILED or unconfigured' );
			echo 'email ' . esc_html( $say( $last['alert']['email'] ?? false ) ) . ', webhook ' . esc_html( $say( $last['alert']['webhook'] ?? false ) ) . ', heartbeat ' . ( ! empty( $last['heartbeat'] ) ? 'ok' : 'NOT SENT (unconfigured, or the run did not complete)' );
		?></td></tr>
		<tr><th>Compared with baseline</th><td><?php echo ! empty( $last['baseline'] ) ? 'yes' : 'no baseline'; ?></td></tr>
	</tbody></table>
<?php else : ?>
	<p>No completed run yet.</p>
<?php endif; ?>

<h2>Rendered pages</h2>
<p><?php $pl = get_site_option( Sky_Sentinel_Runner::PAGES_LAST ); echo is_array( $pl ) ? 'Last full pass ' . esc_html( $pl['at'] ) . ' over ' . (int) $pl['pages'] . ' pages (home and login of every site), hourly.' : 'No full pass yet. The hourly job queues every site; the minute tick fetches them.'; ?></p>
<?php $skipped = (array) get_site_option( Sky_Sentinel_Runner::PAGES_SKIPPED, array() ); if ( $skipped ) : ?>
	<p><?php echo (int) count( $skipped ); ?> archived, deactivated or spam site<?php echo 1 === count( $skipped ) ? ' is' : 's are'; ?> not page-checked (their files, content and administrators still are):
	<?php echo esc_html( implode( ', ', array_map( fn( $s ) => '#' . (int) $s['blog_id'] . ' ' . $s['host'] . ' (' . $s['why'] . ')', $skipped ) ) ); ?>.</p>
<?php endif; ?>

<h2>Failed logins</h2>
<?php
$tally = (array) get_site_option( Sky_Sentinel_Login_Tally::OPTION, array() );
if ( empty( $tally['since'] ) ) :
	?>
	<p>None counted since this version was installed. Every failed login is counted here by day; a burst of 10 from one address in 10 minutes also raises L7.</p>
<?php else : ?>
	<p>By day, UTC. L7 fires on 10 from one address in 10 minutes; a day of zero after a busy week raises L13 in the digest. Counting since <?php echo esc_html( $tally['since'] ); ?>.</p>
	<table class="widefat striped" style="max-width:900px">
		<thead><tr><th>Day</th><th>Failed logins</th><th>Addresses</th><th>Busiest address</th></tr></thead>
		<tbody>
		<?php foreach ( Sky_Sentinel_Login_Tally::recent( Sky_Sentinel_Login_Tally::compact( $tally, time() ), time(), 7 ) as $date => $d ) : ?>
			<tr>
				<td><?php echo esc_html( $date ); ?></td>
				<td><?php echo (int) $d['total']; ?></td>
				<td><?php echo (int) $d['distinct'] . ( $d['capped'] ? '+' : '' ); ?></td>
				<td><?php echo $d['top_count'] ? esc_html( $d['top_ip'] ) . ' (' . (int) $d['top_count'] . ')' : '&mdash;'; ?></td>
			</tr>
		<?php endforeach; ?>
		</tbody>
	</table>
<?php endif; ?>

<h2>Logins</h2>
<?php
$lg_days  = $data['findings']->login_days( 14 );
$lg_total = $data['findings']->login_totals( 14 );
$lg_site  = function ( int $blog_id ): string {
	if ( is_multisite() && $blog_id > 0 && ( $s = get_site( $blog_id ) ) ) {
		return $s->domain . untrailingslashit( $s->path );
	}
	return $blog_id > 0 ? "site {$blog_id}" : 'network';
};
?>
<p style="max-width:900px">Every successful login, by anyone, as Sentinel's event log records it: never an alert. Only administrators' logins are judged (L1). Last 14 days, UTC: <strong><?php echo (int) $lg_total['logins']; ?></strong> logins by <strong><?php echo (int) $lg_total['people']; ?></strong> people, <?php echo (int) $lg_total['admins']; ?> of them administrators.</p>
<?php if ( $lg_total['logins'] ) : ?>
	<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:16px;max-width:900px">
		<table class="widefat striped">
			<thead><tr><th>Day</th><th>Logins</th><th>People</th><th>Admin logins</th></tr></thead>
			<tbody>
			<?php foreach ( $lg_days as $day => $d ) : ?>
				<tr><td><?php echo esc_html( $day ); ?></td><td><?php echo (int) $d['logins']; ?></td><td><?php echo (int) $d['people']; ?></td><td><?php echo (int) $d['admins']; ?></td></tr>
			<?php endforeach; ?>
			</tbody>
		</table>
		<table class="widefat striped">
			<thead><tr><th>Busiest sites</th><th>Logins</th><th>People</th></tr></thead>
			<tbody>
			<?php foreach ( $lg_total['sites'] as $s ) : ?>
				<tr><td><?php echo esc_html( $lg_site( $s['blog_id'] ) ); ?></td><td><?php echo (int) $s['logins']; ?></td><td><?php echo (int) $s['people']; ?></td></tr>
			<?php endforeach; ?>
			</tbody>
		</table>
	</div>
	<?php
	$lg_users = $data['findings']->login_users( 14 );
	if ( function_exists( 'cache_users' ) ) {
		cache_users( array_column( $lg_users, 'user_id' ) ); // one query for every name below
	}
	?>
	<h3>Who logged in (<?php echo (int) count( $lg_users ); ?>)</h3>
	<div style="max-width:900px;max-height:420px;overflow:auto;border:1px solid #ccd0d4">
		<table class="widefat striped" style="border:0">
			<thead><tr><th>User</th><th>Name</th><th>Logins</th><th>Sites</th><th>Last login (UTC)</th></tr></thead>
			<tbody>
			<?php foreach ( $lg_users as $u ) : $wp_user = get_userdata( $u['user_id'] ); ?>
				<tr>
					<td><?php echo $wp_user ? esc_html( $wp_user->user_login ) : '<em>deleted user #' . (int) $u['user_id'] . '</em>'; ?><?php echo $u['admin'] ? ' <strong>(admin)</strong>' : ''; ?></td>
					<td><?php echo $wp_user ? esc_html( $wp_user->display_name ) : '&mdash;'; ?></td>
					<td><?php echo (int) $u['logins']; ?></td>
					<td><?php echo (int) $u['sites']; ?></td>
					<td><?php echo esc_html( substr( $u['last_at'], 0, 16 ) ); ?></td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>
	</div>
<?php endif; ?>

<h2>Block list</h2>
<?php
$bl_ip  = $data['runner']->block_list( false );
$bl_net = $data['runner']->block_list( true );
$bl_url = fn( string $mode ) => wp_nonce_url( admin_url( 'admin-post.php?action=sky_sentinel_blocklist&mode=' . $mode ), 'sky_sentinel_blocklist' );
?>
<p style="max-width:900px">Addresses with <?php echo (int) Sky_Sentinel_Login_Tally::BLOCK_MIN; ?> or more failed logins in the last <?php echo (int) Sky_Sentinel_Login_Tally::KEEP_DAYS; ?> days, and any L7 burst in that time, ready to paste into the host's block list, one per line. <strong>/24</strong> blocks the whole range an address sits in (<code>192.0.2.188</code> becomes <code>192.0.2.0/24</code>); a range is shared with strangers, so it is never offered when it overlaps the allowed networks or an administrator has logged in from it.</p>
<p>
	<label><input type="radio" name="sentinel_bl_mode" value="ip" checked> Addresses (<?php echo (int) count( $bl_ip['block'] ); ?>)</label>
	&nbsp; <label><input type="radio" name="sentinel_bl_mode" value="subnet"> /24 ranges (<?php echo (int) count( $bl_net['block'] ); ?>)</label>
</p>
<?php foreach ( array( 'ip' => $bl_ip, 'subnet' => $bl_net ) as $mode => $bl ) : ?>
	<div class="sentinel-bl" data-mode="<?php echo esc_attr( $mode ); ?>"<?php echo 'ip' === $mode ? '' : ' hidden'; ?> style="max-width:900px">
		<?php if ( $bl['block'] ) : ?>
			<textarea readonly rows="<?php echo (int) min( 12, max( 3, count( $bl['block'] ) ) ); ?>" style="width:100%;font-family:monospace" onclick="this.select()"><?php echo esc_textarea( implode( "\n", array_keys( $bl['block'] ) ) ); ?></textarea>
			<p>
				<button type="button" class="button sentinel-bl-copy">Copy</button>
				<a class="button" href="<?php echo esc_url( $bl_url( $mode ) ); ?>">Download .txt</a>
			</p>
			<table class="widefat striped"><thead><tr><th><?php echo 'ip' === $mode ? 'Address' : 'Range'; ?></th><th>Failed logins</th><?php if ( 'subnet' === $mode ) : ?><th>Addresses</th><?php endif; ?></tr></thead><tbody>
			<?php foreach ( $bl['block'] as $entry => $row ) : ?>
				<tr><td><code><?php echo esc_html( $entry ); ?></code></td><td><?php echo (int) $row['total']; ?></td><?php if ( 'subnet' === $mode ) : ?><td><?php echo (int) $row['addresses']; ?></td><?php endif; ?></tr>
			<?php endforeach; ?>
			</tbody></table>
		<?php else : ?>
			<p>Nothing at <?php echo (int) Sky_Sentinel_Login_Tally::BLOCK_MIN; ?> or more failed logins in the last <?php echo (int) Sky_Sentinel_Login_Tally::KEEP_DAYS; ?> days.</p>
		<?php endif; ?>
		<?php if ( $bl['held'] ) : ?>
			<p><strong>Held back</strong> (not in the list above; block by hand only if you are sure):</p>
			<ul style="list-style:disc;margin-left:20px">
			<?php foreach ( $bl['held'] as $entry => $row ) : ?>
				<li><code><?php echo esc_html( $entry ); ?></code>, <?php echo (int) $row['total']; ?> failed logins: <?php echo esc_html( $row['why'] ); ?></li>
			<?php endforeach; ?>
			</ul>
		<?php endif; ?>
	</div>
<?php endforeach; ?>
<script>
(function(){
	document.querySelectorAll('input[name="sentinel_bl_mode"]').forEach(function(r){
		r.addEventListener('change', function(){
			document.querySelectorAll('.sentinel-bl').forEach(function(d){ d.hidden = d.getAttribute('data-mode') !== r.value; });
		});
	});
	document.querySelectorAll('.sentinel-bl-copy').forEach(function(b){
		b.addEventListener('click', function(){
			var t = b.closest('.sentinel-bl').querySelector('textarea');
			t.select();
			var done = function(){ b.textContent = 'Copied'; setTimeout(function(){ b.textContent = 'Copy'; }, 1500); };
			if (navigator.clipboard) { navigator.clipboard.writeText(t.value).then(done, function(){ document.execCommand('copy'); done(); }); } else { document.execCommand('copy'); done(); }
		});
	});
})();
</script>

<h2>Baseline</h2>
<p>
	<?php if ( 'ok' === $b['state'] ) : ?>
		Signed <?php echo esc_html( gmdate( 'Y-m-d H:i', (int) $b['signed_at'] ) ); ?> UTC by user #<?php echo (int) $b['signed_by']; ?> over <?php echo (int) $b['files']; ?> files.
	<?php elseif ( 'invalid' === $b['state'] ) : ?>
		<strong style="color:#b00020">Stored baseline does not verify.</strong>
	<?php else : ?>
		None. S6/S7 (new and changed files, new packages) and D4/D7 (admin and activation changes) are inactive until one is signed.
	<?php endif; ?>
</p>

<h2>Scan now</h2>
<p>Runs the same walk the schedule does, in five-second pieces from this browser tab. Leave the tab open.</p>
<p>
	<button class="button button-primary" id="sky-sentinel-scan" <?php disabled( $data['in_progress'] ); ?>>Scan now</button>
	<span id="sky-sentinel-progress" style="margin-left:1em"><?php echo $data['in_progress'] ? 'A scan is in progress (cron will finish it, or click to continue here).' : ''; ?></span>
</p>
<script>
(function(){
	var btn=document.getElementById('sky-sentinel-scan'), out=document.getElementById('sky-sentinel-progress');
	function step(start){
		var body=new URLSearchParams({action:'sky_sentinel_step',nonce:<?php echo wp_json_encode( $nonce ); ?>,start:start?'1':''});
		fetch(ajaxurl,{method:'POST',credentials:'same-origin',body:body}).then(function(r){return r.json();}).then(function(j){
			if(!j.success){ out.textContent='Failed: '+(j.data||'unknown'); btn.disabled=false; return; }
			var d=j.data;
			if(d.done){
				out.textContent=d.idle?'Nothing was running.':('Done. '+d.files+' files, '+d.findings+' findings, '+d.new_alerts+' new alerts. Reloading.');
				if(!d.idle) setTimeout(function(){location.reload();},1500); else btn.disabled=false;
				return;
			}
			out.textContent='Walking: '+d.files+' files so far, '+d.pending+' directories queued.';
			step(false);
		}).catch(function(e){ out.textContent='Request failed: '+e; btn.disabled=false; });
	}
	btn.addEventListener('click',function(){ btn.disabled=true; out.textContent='Starting.'; step(true); });
	<?php if ( $data['in_progress'] ) : ?>btn.disabled=false; btn.textContent='Continue scan here';<?php endif; ?>
})();
</script>
