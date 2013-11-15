requires 'perl', '5.008005';

requires 'Digest::MD5';
requires 'Digest::HMAC';

on test => sub {
    requires 'Test::More', '0.88';
};
