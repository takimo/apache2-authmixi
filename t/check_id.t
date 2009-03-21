use strict;
use warnings;
use Test::More tests => 6;
use t::AuthMixi;
use Apache2::AuthMixi;

my %config;
Apache2::AuthMixi::MixiAuthReturnTo(\%config, undef, 'http://example.com/user/return/to');

my %headers;
my $req;

$req = t::AuthMixi::create_request(\%headers);
is(
    Apache2::AuthMixi::check_id($req, \%config),
    Apache2::Const::REDIRECT,
    'status code'
);
is_deeply(
    \%headers,
    { Location => 'https://mixi.jp/openid_server.pl?openid.ns.e1=http%3A%2F%2Fopenid.net%2Fextensions%2Fsreg%2F1.1&openid.mode=checkid_immediate&openid.e1.required=nickname&openid.return_to=http%3A%2F%2Fexample.com%2Fuser%2Freturn%2Fto' },
    'location'
);

Apache2::AuthMixi::MixiAuthType(\%config, undef, community => 145643);
$req = t::AuthMixi::create_request(\%headers);
is(
    Apache2::AuthMixi::check_id($req, \%config),
    Apache2::Const::REDIRECT,
    'community: status code'
);
is_deeply(
    \%headers,
    { Location => 'https://mixi.jp/openid_server.pl?openid.e2.required=nickname&openid.e1.claimed_id=https%3A%2F%2Fid.mixi.jp%2Fcommunity%2F145643&openid.ns.e1=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.mode=checkid_immediate&openid.return_to=http%3A%2F%2Fexample.com%2Fuser%2Freturn%2Fto&openid.ns.e2=http%3A%2F%2Fopenid.net%2Fextensions%2Fsreg%2F1.1' },
    'community: location'
);

Apache2::AuthMixi::MixiAuthType(\%config, undef, user => 1);
$req = t::AuthMixi::create_request(\%headers);
is(
    Apache2::AuthMixi::check_id($req, \%config),
    Apache2::Const::REDIRECT,
    'user: status code'
);
is_deeply(
    \%headers,
    { Location => 'https://mixi.jp/openid_server.pl?openid.e2.required=nickname&openid.e1.claimed_id=https%3A%2F%2Fid.mixi.jp%2F1%2Ffriends&openid.ns.e1=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.mode=checkid_immediate&openid.return_to=http%3A%2F%2Fexample.com%2Fuser%2Freturn%2Fto&openid.ns.e2=http%3A%2F%2Fopenid.net%2Fextensions%2Fsreg%2F1.1' },
    'user: location'
);
