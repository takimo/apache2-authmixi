use strict;
use warnings;
use Test::More tests => 2;
use t::AuthMixi;

my %config;
Apache2::AuthMixi::MixiAuthType(\%config, undef, community => 145643);
Apache2::AuthMixi::MixiAuthTrustRoot(\%config, undef, 'http://example.com/user/path/');
Apache2::AuthMixi::MixiAuthReturnTo(\%config, undef, 'http://example.com/user/return/to');
Apache2::AuthMixi::MixiAuthSecret(\%config, undef, '1ji3fnwlr8dhl36s9');

my $handler = t::AuthMixi->new(\%config);

my %headers_out;
my $req = t::AuthMixi::create_request(\%headers_out);

is(
    $handler->authen_handler($req),
    Apache2::Const::REDIRECT,
    'status code'
);
is_deeply(
    \%headers_out,
    { Location => 'https://mixi.jp/openid_server.pl?openid.e2.required=nickname&openid.e1.claimed_id=https%3A%2F%2Fid.mixi.jp%2Fcommunity%2F145643&openid.ns.e1=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.mode=checkid_immediate&openid.return_to=http%3A%2F%2Fexample.com%2Fuser%2Freturn%2Fto&openid.ns.e2=http%3A%2F%2Fopenid.net%2Fextensions%2Fsreg%2F1.1' },
    'response header'
);
