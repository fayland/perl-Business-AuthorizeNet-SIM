# NAME

Business::AuthorizeNet::SIM - AUthorize.Net SIM

# SYNOPSIS

    use Business::AuthorizeNet::SIM;

    ### STEP 1. create <form> hidden values
    my $api_login_id = 'blabla';
    my $api_trans_key = 'zzzz';
    my $subtotal = 100;
    my $fp_sequence = rand();
    my %submit_data = (
        'x_login' => $api_login_id,
        'x_amount' => $subtotal,
        'x_version' => '3.1',
        'x_method' => 'CC',
        'x_type' => 'AUTH_CAPTURE',
        'x_cust_ID' => '...',
        'x_email_customer' => 'TRUE',
        'x_first_name' => '...',
        'x_last_name' => '...',
        'x_address' => '...',
        'x_city' => '...',
        'x_state' => '...',
        'x_zip' => '...',
        'x_country' => '...',
        'x_phone' => '...',
        'x_fax' => '...',
        'x_email' => '...',

        'x_relay_response' => 'FALSE',
        # or TRUE with 'x_repay_url'

        'x_invoice_num' => '',
        'x_duplicate_window' => '120',
        'x_allow_partial_Auth' => 'FALSE',
        'x_description' => 'Purchase GOODS',

        'x_fp_sequence' => $fp_sequence,
        'x_show_form' => 'PAYMENT_FORM',
        'x_receipt_link_method' => 'POST',
        'x_receipt_link_text' => 'Click here to complete your order.',
        'x_receipt_link_url'  => 'https://www.example.com/sim/redirect_back',
    );

    my $sim = Business::AuthorizeNet::SIM->new(api_login_id => $api_login_id);
    my $fp_timestamp = time();
    my $fingerprint = $sim->getFingerprint($api_login_id, $api_trans_key, $subtotal, $fp_sequence, $fp_timestamp);
    $submit_data{x_fp_timestamp} = $fp_timestamp;
    $submit_data{x_fp_hash} = $fingerprint;

    # print qq~<form action='https://secure.authorize.net/gateway/transact.dll' method='POST'>~;
    # foreach my $k (keys %submit_data) {
    #     my $v = $submit_data{$k};
    #     $v =~ s/\"/\&quot;/g;
    #     print qq~<input type="hidden" name="$k" value="$v" />\n~;
    # }
    # print "<input type='submit' /></form>";

    #####
    ## STEP 2, when redirect back
    ## ON /sim/redirect_back
    #####

    my %params = params(); # contains x_* from Authorize.NET
    my $sim = Business::AuthorizeNet::SIM->new(api_login_id => 'blabla', %params);
    unless ($sim->isAuthorizeNet()) {
        die "Invalid call.\n";
    }
    unless ($sim->is_approved()) {
        die "The bank has rejected this transaction.\n";
        return;
    }
    # do real transaction
    print "Thank you!\n";

# DESCRIPTION

Business::AuthorizeNet::SIM is sample code for AUthorize.Net SIM.

# AUTHOR

Fayland Lam <fayland@gmail.com>

# COPYRIGHT

Copyright 2013- Fayland Lam

# LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

# SEE ALSO
