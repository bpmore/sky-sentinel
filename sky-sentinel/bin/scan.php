#!/usr/bin/env php
<?php
/**
 * Scan a directory with no WordPress at all.
 *
 *   php bin/scan.php /path/to/public            walk everything, print findings
 *   php bin/scan.php /path/to/public --json     one JSON document instead
 *   php bin/scan.php /path/to/public --min=high only HIGH and CRITICAL
 *
 * This is how to test the detectors against a real infected backup with no
 * WordPress: point it at the extracted webroot, compare the "By detector"
 * line with what you know is there, and read every file it names. Then point
 * it at the cleaned copy and expect nothing at HIGH or above.
 *
 * Content detectors, file-system checks and the package inventory run here.
 * Database checks (D1 to D7) and the baseline diff need WordPress and do not.
 */
// Ships inside mu-plugins, so it is reachable by URL. It is a command-line tool only.
if ( 'cli' !== PHP_SAPI ) {
	http_response_code( 404 );
	exit;
}
$root = $argv[1] ?? '';
$json = in_array( '--json', $argv, true );
$min  = 'info';
foreach ( $argv as $a ) {
	if ( str_starts_with( $a, '--min=' ) ) {
		$min = substr( $a, 6 );
	}
}
if ( '' === $root || ! is_dir( $root ) ) {
	fwrite( STDERR, "Usage: php bin/scan.php <directory> [--json] [--min=high]\n" );
	exit( 2 );
}
foreach ( array( 'finding', 'signatures', 'content-detectors', 'fs-checks', 'baseline', 'scanner' ) as $c ) {
	require_once dirname( __DIR__ ) . "/includes/class-{$c}.php";
}
$sig      = Sky_Sentinel_Signatures::from_directory( dirname( __DIR__ ) . '/signatures' );
$manifest = tempnam( sys_get_temp_dir(), 'sentinel-manifest-' );
$t0       = microtime( true );
$r        = ( new Sky_Sentinel_Scanner( $root, $sig ) )->scan_all( $manifest );
$secs     = round( microtime( true ) - $t0, 1 );
$findings = array_values( array_filter( $r['findings'], fn( $f ) => $f->is_at_least( $min ) ) );
usort( $findings, fn( $a, $b ) => $b->rank() <=> $a->rank() ?: strcmp( $a->detector, $b->detector ) ?: strcmp( $a->subject, $b->subject ) );

$by_sev = array( 'critical' => 0, 'high' => 0, 'medium' => 0, 'info' => 0 );
$by_det = array();
foreach ( $findings as $f ) {
	$by_sev[ $f->severity ]++;
	$by_det[ $f->detector ] = ( $by_det[ $f->detector ] ?? 0 ) + 1;
}
ksort( $by_det );

if ( $json ) {
	echo json_encode( array(
		'root'     => $r['state'] ? realpath( $root ) : $root,
		'seconds'  => $secs,
		'files'    => $r['state']['files'],
		'hashed'   => $r['state']['hashed'],
		'packages' => $r['state']['packages'],
		'by_severity' => $by_sev,
		'by_detector' => $by_det,
		'findings' => array_map( fn( $f ) => $f->to_array(), $findings ),
		'signatures' => $sig->version(),
	), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ), "\n";
} else {
	printf( "Scanned %d files (%d hashed) under %s in %ss. Signatures: %s\n\n", $r['state']['files'], $r['state']['hashed'], realpath( $root ), $secs, $sig->version() );
	foreach ( $findings as $f ) {
		printf( "%-8s %-4s %s\n         %s\n", strtoupper( $f->severity ), $f->detector, $f->subject, $f->summary );
		if ( $f->sha256 ) {
			printf( "         sha256 %s\n", $f->sha256 );
		}
	}
	printf( "\nBy severity: critical %d, high %d, medium %d, info %d\n", $by_sev['critical'], $by_sev['high'], $by_sev['medium'], $by_sev['info'] );
	echo 'By detector: ';
	foreach ( $by_det as $d => $n ) {
		echo "{$d}={$n} ";
	}
	echo "\n";
}
@unlink( $manifest );
exit( $by_sev['critical'] + $by_sev['high'] > 0 ? 1 : 0 );
