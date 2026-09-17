<?php
/** @var array $data */
if ( ! defined( 'ABSPATH' ) ) { exit; }
$tabs = $data['tabs']; $tab = $data['tab']; $base = Sky_Sentinel_Alerts::admin_url();
?>
<div class="wrap">
	<h1>Sky Sentinel <small style="font-weight:normal;color:#666">v<?php echo esc_html( Sky_Sentinel::VERSION ); ?> on <?php echo esc_html( $data['site'] ); ?></small></h1>
	<?php if ( '' !== $data['notice'] ) : ?>
		<div class="notice notice-info is-dismissible"><p><?php echo esc_html( $data['notice'] ); ?></p></div>
	<?php endif; ?>
	<nav class="nav-tab-wrapper">
		<?php foreach ( $tabs as $key => $label ) : ?>
			<a class="nav-tab <?php echo $key === $tab ? 'nav-tab-active' : ''; ?>" href="<?php echo esc_url( $base . '&tab=' . $key ); ?>"><?php echo esc_html( $label ); ?></a>
		<?php endforeach; ?>
	</nav>
	<div style="margin-top:1em">
		<?php require $view; ?>
	</div>
</div>
