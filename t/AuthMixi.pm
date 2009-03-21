package t::AuthMixi;
use strict;
use warnings;
use base qw(Apache2::AuthMixi);
use Test::MockObject;

sub new {
    my ($class, $config_ref, $cookie_ref, $params_ref) = @_;

    my $self = $class->SUPER::new;
    $self->{configuration} = $config_ref;
    $self->{cookie}        = $cookie_ref || {};
    $self->{parameters}    = $params_ref || {};

    return $self;
}

sub configuration_of {
    my ($self, $req) = @_;
    return $self->{configuration};
}

sub cookie_of {
    my ($self, $req) = @_;
    return %{ $self->{cookie} };
}

sub parameters_of {
    my ($self, $req) = @_;
    return %{ $self->{parameters} };
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

1;
