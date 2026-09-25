<?php
// L10 fixture: stands in for core's own authenticate callback.
function sentinel_fixture_census_core_auth( $user, $username, $password ) { return $user; }
return 'sentinel_fixture_census_core_auth';
