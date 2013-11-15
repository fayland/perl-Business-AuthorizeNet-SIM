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
    x_trans_id => '123',
    api_login_id => '528udYYwz',
    md5_settings => 'test',
    x_MD5_Hash => '8FC33C32ABB3EDD8BBC4BE3E904CB47E',
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

$sim = Business::AuthorizeNet::SIM->new(
    amount => '4.12',
    x_response_code => '3',
    x_ship_to_state => 'CA',
    api_login_id => '528udYYwz',
    md5_settings => 'test',
);
is($sim->{response_code}, 3);
ok($sim->is_error());
ok(! $sim->is_approved());
is($sim->{ship_to_state}, 'CA');

is( $sim->getFingerprint("123","123","123","123","123"), 'db88bbebb8f699acdbe70daad897a68a' );

done_testing;
