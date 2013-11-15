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

	foreach my $key (keys %args) {
		if ($key =~ /^x_/) {
			my $nk = substr($key, 2);
			$args{$nk} = $args{$key};
		}
	}

	# Set some human readable fields
    my %map = (
        'avs_response' => 'x_avs_code',
        'authorization_code' => 'x_auth_code',
        'transaction_id' => 'x_trans_id',
        'customer_id' => 'x_cust_id',
        'md5_hash' => 'x_MD5_Hash',
        'card_code_response' => 'x_cvv2_resp_code',
        'cavv_response' => 'x_cavv_response',
    );
    foreach my $key (keys %map) {
    	$args{$key} = $args{ $map{$key} } if exists $args{ $map{$key} }; # alias
    }

	return bless \%args, $class;
}

sub is_approved {
	my $self = shift;
	return ($self->{response_code} and $self->{response_code} == 1);
}
sub is_declined {
	my $self = shift;
	return ($self->{response_code} and $self->{response_code} == 2);
}
sub is_error {
	my $self = shift;
	return ($self->{response_code} and $self->{response_code} == 3);
}
sub is_held {
	my $self = shift;
	return ($self->{response_code} and $self->{response_code} == 4);
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
