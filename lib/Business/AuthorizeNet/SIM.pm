package Business::AuthorizeNet::SIM;

use strict;
use 5.008_005;
our $VERSION = '0.01';
use Carp 'croak';
use Digest::MD5  qw(md5 md5_hex);
use Digest::HMAC qw(hmac);

sub new {
	my $class = shift;
	my %args = (@_ % 2) ? %{$_[0]} : @_;

	$args{api_login_id} or croak "api_login_id is required.";

	return bless \%args, $class;
}

sub isAuthorizeNet {
	my ($self) = @_;

	return ($self->{md5_hash} && ($self->generateHash() eq $self->{md5_hash}));
}

sub generateHash {
	my ($self) = @_;

	my $amount = $self->{amount} ? $self->{amount} : '0.00';
	return uc(md5_hex($self->{md5_settings}, $self->{api_login_id}, $self->{transaction_id} . $self->{amount}));
}

sub getFingerprint {
	my ($self, $api_login_id, $transaction_key, $amount, $fp_sequence, $fp_timestamp) = @_;

	return hmac_md5_hex($api_login_id . "^" . $fp_sequence . "^" . $fp_timestamp . "^" . $amount . "^", $transaction_key);
}

sub hmac_md5_hex {
    unpack("H*", hmac($_[0], $_[1], \&md5, 64))
}

1;
__END__

=encoding utf-8

=head1 NAME

Business::AuthorizeNet::SIM - AUthorize.Net SIM

=head1 SYNOPSIS

  use Business::AuthorizeNet::SIM;

=head1 DESCRIPTION

Business::AuthorizeNet::SIM is

=head1 AUTHOR

Fayland Lam E<lt>fayland@gmail.comE<gt>

=head1 COPYRIGHT

Copyright 2013- Fayland Lam

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=head1 SEE ALSO

=cut
