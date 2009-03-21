package t::TestAuthMixi;
use strict;
use warnings;
use Test::MockObject;

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

1;
