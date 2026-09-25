<?php
// L10 fixture: the SHAPE of the Wordfence-reported mu-plugin's registrations,
// with inert bodies. Every callback returns its first argument untouched.
function sentinel_fixture_census_harvest( $user, $username = '', $password = '' ) { return $user; }
function sentinel_fixture_census_hide_query( $query ) { return $query; }
final class Sentinel_Fixture_Census_Hider {
	public function views( $views ) { return $views; }
	public static function mustuse( $show, $type ) { return $show; }
}
return array(
	'harvest' => 'sentinel_fixture_census_harvest',
	'query'   => 'sentinel_fixture_census_hide_query',
	'views'   => array( new Sentinel_Fixture_Census_Hider(), 'views' ),
	'mustuse' => 'Sentinel_Fixture_Census_Hider::mustuse',
	'rest'    => function ( $args, $request ) { return $args; },
);
