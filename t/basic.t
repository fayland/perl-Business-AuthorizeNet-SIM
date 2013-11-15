use strict;
use Test::More;
use Business::AuthorizeNet::SIM;

my $sim = Business::AuthorizeNet::SIM->new(
	amount => '4.12',
	transaction_id => '123',
	api_login_id => '528udYYwz',
	md5_settings => 'test',
);
is($sim->generateHash(), '8FC33C32ABB3EDD8BBC4BE3E904CB47E');

$sim = Business::AuthorizeNet::SIM->new(
	amount => '4.12',
	transaction_id => '123',
	api_login_id => '528udYYwz',
	md5_settings => 'test',
	md5_hash => '8FC33C32ABB3EDD8BBC4BE3E904CB47E',
);
ok($sim->isAuthorizeNet());

$sim = Business::AuthorizeNet::SIM->new(
	amount => '4.12',
	transaction_id => '123',
	api_login_id => '528udYYwz',
	md5_settings => 'test',
	md5_hash => '8FC33C32BB3EDD8BBC4BE3E904CB47E',
);
ok(! $sim->isAuthorizeNet());

is( $sim->getFingerprint("123","123","123","123","123"), 'db88bbebb8f699acdbe70daad897a68a' );

done_testing;
