package Apache2::AuthMixi;
use strict;
use warnings;
use 5.00800;
our $VERSION = '0.01';
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
use Digest::MD5;
#use Digest::SHA1;
use LWP::UserAgent;
use Net::OpenID::Consumer::Lite;

use constant {
    # auth limit time
    TIMEOUT => 3600,
    # relation type
    USER => 'user',
    COMMUNITY => 'community',
    # openid server & namespace
    MIXI_OP => 'https://mixi.jp/openid_server.pl',
    SELECT_ID => 'http://specs.openid.net/auth/2.0/identifier_select',
};

my $extensions = {
    'http://openid.net/extensions/sreg/1.1' => {
        'required' => 'nickname',
    }
};

$ENV{HTTPS_CA_DIR} = '/etc/ssl/certs';

my @directives = (
    {
        name            => 'ReturnTo',
        req_override    => Apache2::Const::OR_AUTHCFG,
        args_how        => Apache2::Const::TAKE1,
        errmsg          => 'ReturnTo http://sample.com/trust_root/callback',
    },
    {
        name            => 'TrustRoot',
        req_override    => Apache2::Const::OR_AUTHCFG,
        args_how        => Apache2::Const::TAKE1,
        errmsg          => 'TrustRoot http://sample.com/trust_root/',
    },
    {
        name            => 'ConsumerSecret',
        req_override    => Apache2::Const::OR_AUTHCFG,
        args_how        => Apache2::Const::TAKE1,
        errmsg          => 'ConsumerSecret "Your consumer secret goes here"',
    },
    {
        name            => 'RequireRelation',
        req_override    => Apache2::Const::OR_AUTHCFG,
        args_how        => Apache2::Const::TAKE2,
        errmsg          => 'RequireRelation community [community_id]',
    },
);

eval {
    Apache2::Module::add(__PACKAGE__, \@directives);
    Apache2::ServerUtil->server->push_handlers(
        PerlAccessHandler => \&authen_handler
    );
};

sub ReturnTo {
    my ($self, $params, $arg) = @_;
    $self->{'return_to'} = $arg;
}

sub TrustRoot {
    my ($self, $params, $arg) = @_;
    $self->{'trust_root'} = $arg;
}

sub ConsumerSecret {
    my ($self, $params, $arg) = @_;
    $self->{'consumer_secret'} = $arg;
}

sub RequireRelation {
    my ($self, $params, %arg) = @_;
    ($self->{'type'}, $self->{'id'}) = each %arg;
}

sub authen_handler {
    my $request = shift;
    my $config = Apache2::Module::get_config(__PACKAGE__, $request->server, $request->per_dir_config);
    my %cookie = Apache2::Cookie->fetch($request);
    unless(%cookie && $cookie{"Apache2-AuthMixi"}){
        return &process_authen($request);
    }
    # check cookie by token
    my ($identity, $nickname, $token, $time) = $cookie{"Apache2-AuthMixi"}->value;
    if (Digest::MD5::md5_hex($identity.$nickname.$config->{'consumer_secret'}.$time) ne $token){
        return &process_authen($request);
    }
    return Apache2::Const::DECLINED;
}

sub process_authen {
    # handle response of OP
    my $request = shift;
    my $config = Apache2::Module::get_config(__PACKAGE__, $request->server, $request->per_dir_config);
    my $apr = Apache2::Request->new($request);
    my $param = { %{ $apr->param || {} } };
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
    my $consumer_secret = $cf->{'consumer_secret'};
    my $identity = $vident->{'identity'};
    my $nickname = $vident->{'sreg.nickname'} || "";
    my $time = time() + TIMEOUT;
    my $expires = time2str($time);
    my $token = Digest::MD5::md5_hex($identity.$nickname.$consumer_secret.$time);
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

1;
__END__

=encoding utf8

=head1 NAME

Apache2::AuthMixi - Authentication library uses Mixi OpenID 

=head1 SYNOPSIS

    # admin setting apache config
    PerlModule Apache2::AuthMixi

    # user setting .htaccess 
    AuthTyep        Mixi
    TrustRoot       http://example.com/user/path/
    ReturnTo        http://exmaple.com/user/return/to
    ConsumerSecret  1ji3fnwlr8dhl36s9
    RequireRelation communiry 145643

=head1 LIMITATION

    this module supports Mixi OpenID only.

=head1 DESCRIPTION

Apache2::AuthMixi is Authentication library that use Mixi OpenID.

This module depend to L<Net::OpenID::Consumer::Lite>.

=head1 AUTHOR

Shinya Takimoto E<lt>subtakimo@gmail.comE<gt>

=head1 SEE ALSO

OpenID website: http://openid.net/
Mixi OpenID website: http://developer.mixi.co.jp/

L<Net::OpenID::Consumer>
L<Net::OpenID::Consumer::Lite>

=head1 REPOSITORY

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut