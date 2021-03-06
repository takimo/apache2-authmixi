package Apache2::AuthMixi;
use strict;
use warnings;
use 5.00800;
our $VERSION = '0.02';

use Apache2::Access;
use Apache2::Cookie;
use Apache2::Const -compile => qw(
    OK DECLINED FORBIDDEN REDIRECT NOT_FOUND OR_AUTHCFG TAKE1 TAKE2
);
use Apache2::CmdParms;
use Apache2::Module;
use Apache2::Request;
use Apache2::RequestRec;
use Apache2::ServerRec;
use Apache2::ServerUtil;
use HTTP::Date;
use Digest::SHA1;
use LWP::UserAgent;
use Net::OpenID::Consumer::Lite;

use constant {
    # auth limit time
    TIMEOUT     => 3600,
    # relation type
    USER        => 'user',
    COMMUNITY   => 'community',
    # openid server & namespace
    MIXI_OP     => 'https://mixi.jp/openid_server.pl',
    SELECT_ID   => 'http://specs.openid.net/auth/2.0/identifier_select',
    CADIR       => '/etc/ssl/certs',
};

my $extensions = {
    'http://openid.net/extensions/sreg/1.1' => {
        'required' => 'nickname',
    }
};

my @directives = (
    {
        name            => 'MixiAuthReturnTo',
        req_override    => Apache2::Const::OR_AUTHCFG,
        args_how        => Apache2::Const::TAKE1,
        errmsg          => 'MixiAuthReturnTo http://sample.com/trust_root/callback',
    },
    {
        name            => 'MixiAuthTrustRoot',
        req_override    => Apache2::Const::OR_AUTHCFG,
        args_how        => Apache2::Const::TAKE1,
        errmsg          => 'MixiAuthTrustRoot http://sample.com/trust_root/',
    },
    {
        name            => 'MixiAuthSecret',
        req_override    => Apache2::Const::OR_AUTHCFG,
        args_how        => Apache2::Const::TAKE1,
        errmsg          => 'MixiAuthSecret "Your consumer secret goes here"',
    },
    {
        name            => 'MixiAuthType',
        req_override    => Apache2::Const::OR_AUTHCFG,
        args_how        => Apache2::Const::TAKE2,
        errmsg          => 'MixiAuthType community [community_id]',
    },
);

eval {
    Apache2::Module::add(__PACKAGE__, \@directives);
    Apache2::ServerUtil->server->push_handlers(
        PerlAccessHandler => \&_authen_handler
    );
};

sub MixiAuthReturnTo {
    my ($self, $params, $arg) = @_;
    $self->{'return_to'} = $arg;
}

sub MixiAuthTrustRoot {
    my ($self, $params, $arg) = @_;
    $self->{'trust_root'} = $arg;
}

sub MixiAuthSecret {
    my ($self, $params, $arg) = @_;
    $self->{'mixi_auth_secret'} = $arg;
}

sub MixiAuthType {
    my ($self, $params, %arg) = @_;
    ($self->{'type'}, $self->{'id'}) = each %arg;
}

sub authen_handler {
    my ($self, $request) = @_;
    my $config = $self->configuration_of($request);

    my $server = $request->server;
    if(!$config->{'mixi_auth_secret'})
    {
        return Apache2::Const::OK;
    }

    my %cookie = $self->cookie_of($request);
    unless(%cookie && $cookie{"Apache2-AuthMixi"}){
        return $self->process_authen($request);
    }
    # check cookie by token
    my ($identity, $nickname, $token, $time) = $cookie{"Apache2-AuthMixi"}->value;
    if (Digest::SHA1::sha1_hex($identity.$nickname.$config->{'mixi_auth_secret'}.$time) ne $token){
        return $self->process_authen($request);
    }
    return Apache2::Const::DECLINED;
}

sub process_authen {
    # handle response of OP
    my ($self, $request) = @_;
    my $config = $self->configuration_of($request);
    my $param = { $self->parameters_of($request) };
    my $cadir = $ENV{HTTPS_CA_DIR};
    local $ENV{HTTPS_CA_DIR};
    if ($cadir) {
        $ENV{HTTPS_CA_DIR} = $cadir;
    } elsif (-d CADIR) {
        $ENV{HTTPS_CA_DIR} = CADIR;
    }
    Net::OpenID::Consumer::Lite->handle_server_response($param,
        not_openid => sub {
            return &check_id($request, $config);
        },
        setup_required => sub {
            my $url = shift;
            return &redirect_setup($request, $url);
        },
        cancelled => sub {
            return &process_forbidden();
        },
        verified => sub {
            my $verified_identity = shift;
            return &success_authz($request, $config, $verified_identity);
       },
        error => sub {
            return &process_forbidden();
        },
   );
}

sub success_authz {
    my ($r, $cf, $vident) = @_;
    my $return_url = $cf->{'return_to'};
    my $mixi_auth_secret = $cf->{'mixi_auth_secret'};
    my $identity = $vident->{'identity'};
    my $nickname = $vident->{'sreg.nickname'} || "";
    my $time = time() + TIMEOUT;
    my $expires = time2str($time);
    my $token = Digest::SHA1::sha1_hex($identity.$nickname.$mixi_auth_secret.$time);
    my $cookie = Apache2::Cookie->new($r,
        -name => "Apache2-AuthMixi",
        -value => [ $identity, $nickname, $token, $time ],
        -expires => $expires,
    );
    $r->err_headers_out->add('Set-Cookie' => $cookie->as_string);
    $r->headers_out->set('Location' => $return_url);
    return Apache2::Const::REDIRECT;
}

sub check_id {
    my ($r, $cf) = @_;
    my $return_url = $cf->{'return_to'};
    my $type = $cf->{'type'};
    my $id = $cf->{'id'};
    if($type eq USER && $id){
        $extensions->{SELECT_ID()} = {
            'claimed_id' => "https://id.mixi.jp/$id/friends",
        };
    }
    if($type eq COMMUNITY && $id){
        $extensions->{SELECT_ID()} = {
            'claimed_id' => "https://id.mixi.jp/community/$id",
        };
    }
    my $check_url = Net::OpenID::Consumer::Lite->check_url(
        MIXI_OP,
        $return_url,
        $extensions,
    );
    $r->headers_out->set('Location' => $check_url);
    return Apache2::Const::REDIRECT;
};

sub redirect_setup {
    my ($r, $setup_url) = @_;
    $r->err_headers_out->set('Location' => $setup_url);
    return Apache2::Const::REDIRECT;
}

sub process_forbidden {
    return Apache2::Const::FORBIDDEN;
}

sub new {
    my ($class) = @_;
    return bless {}, $class;
}

sub _authen_handler {
    my $request = shift;

    my $self = __PACKAGE__->new;
    $self->authen_handler($request);
}

sub cookie_of {
    my ($self, $request) = @_;

    my %cookie = Apache2::Cookie->fetch($request);
    return %cookie;
}

sub configuration_of {
    my ($self, $request) = @_;

    return Apache2::Module::get_config(
        __PACKAGE__,
        $request->server,
        $request->per_dir_config
    );
}

sub parameters_of {
    my ($self, $request) = @_;

    my $apr = Apache2::Request->new($request);
    return %{ $apr->param || {} };
}

1;
__END__

=head1 NAME

Apache2::AuthMixi - Authentication library using mixi OpenID 

=head1 SYNOPSIS

    # admin setting apache config
    LoadModule perl_module modules/mod_perl.so
    PerlModule Apache2::AuthMixi
    PerlSetEnv HTTPS_CA_DIR /etc/ssl/certs

    # user setting .htaccess 
    MixiAuthType        community 145643
    MixiAuthTrustRoot   http://example.com/user/path/
    MixiAuthReturnTo    http://exmaple.com/user/return/to
    MixiAuthSecret      1ji3fnwlr8dhl36s9

=head1 DESCRIPTION

This mod_perl module allows you to implement "my mixi authentication" and "community authentication" with mixi OpenID.

"my mixi" is a term which means a friend of a mixi user.

This module depend to L<Net::OpenID::Consumer::Lite>.

=head1 LIMITATION

    this module supports mixi OpenID only.
    
=head1 AUTHOR

Shinya Takimoto E<lt>subtakimo@gmail.comE<gt>

=head1 SEE ALSO

mixi website: http://mixi.jp
mixi OpenID website: http://developer.mixi.co.jp/openid
OpenID website: http://openid.net/

L<Net::OpenID::Consumer>
L<Net::OpenID::Consumer::Lite>

=head1 REPOSITORY

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
