use strict;
use warnings;
use Test::More tests => 2;
use Test::MockObject;

my %Configuration;
my %Parameters;
my %Cookie;

{
    package AuthMixi;
    use base qw(Apache2::AuthMixi);

    sub configuration_of {
        \%Configuration;
    }

    sub cookie_of {
        %Cookie;
    }

    sub parameters_of {
        %Parameters;
    }
}

sub create_request {
    my ($headers_out_ref) = @_;

    my $result = Test::MockObject->new;
    $result->mock(
        headers_out => sub {
            Test::MockObject->new->mock(
                set => sub {
                    my ($self, $key, $value) = @_;
                    $headers_out_ref->{$key} = $value;
                }
            );
        }
    );
    return $result;
}

my $handler = AuthMixi->new;
Apache2::AuthMixi::MixiAuthType(\%Configuration, undef, community => 145643);
Apache2::AuthMixi::MixiAuthTrustRoot(\%Configuration, undef, 'http://example.com/user/path/');
Apache2::AuthMixi::MixiAuthReturnTo(\%Configuration, undef, 'http://example.com/user/return/to');
Apache2::AuthMixi::MixiAuthSecret(\%Configuration, undef, '1ji3fnwlr8dhl36s9');

my %headers_out;

is(
    $handler->authen_handler(create_request(\%headers_out)),
    Apache2::Const::REDIRECT,
    'status code'
);
is_deeply(
    \%headers_out,
    { Location => 'https://mixi.jp/openid_server.pl?openid.ns.e1=http%3A%2F%2Fopenid.net%2Fextensions%2Fsreg%2F1.1&openid.mode=checkid_immediate&openid.e1.required=nickname&openid.return_to=http%3A%2F%2Fexample.com%2Fuser%2Freturn%2Fto' },
    'response header'
);
