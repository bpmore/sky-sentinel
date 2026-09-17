<?php
/**
 * No WordPress here, on purpose. Everything under tests/Unit exercises the
 * pure classes: detectors, checks, baseline signing, the walker. If a test in
 * this directory ever needs a WordPress function, the class it is testing has
 * grown a dependency it should not have.
 */
foreach ( array( 'finding', 'signatures', 'content-detectors', 'fs-checks', 'baseline', 'scanner', 'db-checks', 'network', 'live-rules', 'session-checks', 'page-check' ) as $c ) {

	require_once dirname( __DIR__ ) . "/includes/class-{$c}.php";
}

function sentinel_signatures(): Sky_Sentinel_Signatures {
	static $sig = null;
	return $sig ??= Sky_Sentinel_Signatures::from_directory( dirname( __DIR__ ) . '/signatures' );
}

function sentinel_fixture( string $rel ): string {
	$path = __DIR__ . '/fixtures/' . $rel;
	if ( ! is_file( $path ) ) {
		throw new RuntimeException( "No fixture: {$rel}" );
	}
	return (string) file_get_contents( $path );
}

/** Scan one fixture under the path the real file would have had. */
function sentinel_scan( string $fixture, string $as_path ): array {
	return ( new Sky_Sentinel_Content_Detectors( sentinel_signatures() ) )->scan( $as_path, sentinel_fixture( $fixture ) );
}

/** The detector ids a scan produced, for one-line assertions. */
function sentinel_ids( array $findings ): array {
	$ids = array_map( fn( Sky_Sentinel_Finding $f ) => $f->detector, $findings );
	sort( $ids );
	return array_values( array_unique( $ids ) );
}
// class-alerts needs WordPress to SEND. Its payload() is pure, and that is
// the only method the tests call. Nothing is stubbed; a test that reached a
// WordPress function here would fail loudly, which is the point.
require_once dirname( __DIR__ ) . '/includes/class-alerts.php';
