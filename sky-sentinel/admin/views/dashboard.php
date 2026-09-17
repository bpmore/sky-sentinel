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
