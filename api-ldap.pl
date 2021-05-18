#!/usr/bin/env perl
#
# vim: set foldmethod=marker:
#
# Perl module to easily handle return values
# Copyright (c) 2014-2021 Jan Jaeger
# License: MIT License as found here: https://opensource.org/licenses/MIT
# The low down: You may copy this. You may use this as you see fit.
# You have to include this notice. I am not liable.
#


use strict;
use warnings;

# config section
#
my $app_title="LDAP API Gateway";
my $ldap_auth_realm="Active Directory login";
my $token_lib="/var/lib/api-ldap/tokens";

## Mail specific
#my $smtpserver = '';
#my $smtpport = 25;
#my $alert_spool="/tmp/alerttest/spool";
#my $done_alerts="/tmp/alerttest/done";

# the variables $authuser and $authpass can be used to 
# perform an LDAP bind with the web users credentials.
my $ldap_host   = 'my.dc.domain.local';
my $ldap_basedn = 'OU=group,OU=dept,DC=domain,DC=local';
my $ldap_binddn = '$authuser\@domain.local';
my $ldap_bindpw = '$authpass';
my $ldap_filter = '(&(objectClass=organizationalPerson)(cn=%s))';

# static bind user
my $ldap_binduser='mybinduser@domain.local';
my $ldap_bindpasswd='';
#
# end config


use POSIX;
use Proc::Simple;

use Mojolicious::Lite;
use Mojo::Log;
use Mojo::JSON;
use Mojo::JSON qw(decode_json encode_json from_json);
use Mojo::JSON::Pointer;
use Mojo::Util qw(url_unescape);
#use Mojolicious::Plugin::Authentication;
use Mojolicious::Plugin::BasicAuthPlus;
use Mojolicious::Command::routes;

## Mail specific
#use Email::Sender::Simple qw(sendmail);
#use Email::Sender::Transport::SMTP();
#use Email::Simple();
#use Email::Simple::Creator();

use Encode qw(decode encode);

use DateTime;

use Apache::Htpasswd;

use Net::LDAP;

# only used for debugging
use Data::Dumper::Simple;

plugin 'basic_auth_plus';


# {{{ functions
#
sub authenticate_user {
    my $c= shift;
    my $log = Mojo::Log->new;
    #warn Dumper($c->session);
    $log->info("attempting login.");

    if (not defined $c->req->url->to_abs->userinfo) {
        $log->info("no user info in request. sending auth header.");
        $c->res->headers->www_authenticate("Basic realm=\"$ldap_auth_realm\"");
        $c->render('text' => "Access denied.", status => '401');
        return undef;
    } else {
        $log->info("auth header found.");
        my $auth= $c->req->url->to_abs->userinfo;
        my ($authuser, $authpass) = split ':', $auth;
        $log->info("attempting LDAP auth with user: $authuser.");
        my $auth_ok = $c->basic_auth(
            $ldap_auth_realm => {
                host   => $ldap_host,
                basedn => $ldap_basedn,
                binddn => eval qq("$ldap_binddn"),
                bindpw => eval qq("$ldap_bindpw"),
                filter => $ldap_filter,
                tls_verify => 'none',
                logging => 1
            }
        );
        if (not $auth_ok) {
            $log->info("LDAP auth failed. sending auth header again.");
            $c->res->headers->www_authenticate("Basic realm=\"$ldap_auth_realm\"");
            $c->render('text' => "Access denied.", status => '401');
            return undef;
        } else {
            $log->info("LDAP auth succeeded.");
            return 1;
        }
    }
    $log->warn("execution should not reach here!");
    return undef;
}

sub authenticate_token { 
    my ($username, $token_name, $pass)= @_;
    #warn Dumper($token_name);
    my $password_file="$token_lib/$username.htpasswd";
    my $vault = new Apache::Htpasswd( { passwdFile => $password_file, ReadOnly   => 1 } );
    return $vault->htCheckPassword($token_name, $pass);
}

sub list_tokens {
    my ($username)= shift;
    my $password_file="$token_lib/$username.htpasswd";
    unless(-e $password_file) {
        open my $fc, ">", $password_file;
        close $fc;
    }
    open my $in, "<:encoding(utf8)", $password_file or die "$password_file: $!";
    my @usernames= map { (split /:/, $_, 2)[0];  } grep(!/^#/, <$in>);
    close $in;
    warn Dumper(@usernames);
    return \@usernames;
}

sub add_token {
    my ($username, $token_name, $pass)= @_;
    my $password_file="$token_lib/$username.htpasswd";
    my $vault = new Apache::Htpasswd( { passwdFile => $password_file, ReadOnly   => 0 } );
    # try to overwrite first
    my $result= $vault->htpasswd($token_name, $pass, {'overwrite' => 1});
    if (not $result) {
        warn Dumper($result);
        # just create the token
        return $vault->htpasswd($token_name, $pass);
    }
    return $result;
}

sub remove_token {
    my ($username, $token_name)= @_;
    my $password_file="$token_lib/$username.htpasswd";
    if (not -w $password_file) {
        return undef;
    }
    my $vault = new Apache::Htpasswd( { passwdFile => $password_file, ReadOnly   => 0 } );
    $vault->htDelete($token_name);
    return 1;
}

#sub trigger_myself {
#    while (1){
#        sleep(5);
#    }
#}


#sub remove_single_key {
#    my $var= shift;
#    if (count_elements($var) > 1) {
#        $var= remove_top_key($var);
#    } else {
#        for ($c=0; $c <= count_elements($var); ++$c) {
#            remove_single_key($var);
#        }
#    }
#}

sub remove_single_key {
    my $var= shift;
    if (ref($var) eq "HASH") {
        #warn (ref($var));
        if (keys(%$var) == 1) {
            ($var)= values(%$var);
            return remove_single_key($var);
        } else {
            while ((my $key, my $value)= each(%$var)) {
                $var->{$key}= remove_single_key($value);
            }
            return $var;
        }
    } elsif (ref($var) eq "ARRAY") {
        #warn (ref($var));
        if (scalar(@$var) == 1) {
            $var= @$var[0];
            return remove_single_key($var);
        } else {
            foreach my $value (@$var) {
                #warn Dumper($value);
                $value= remove_single_key($value);
            }
            return $var;
        }
    } else {
        return $var;
    }
}

sub get_all_routes {
    my @arr;
    my $root= shift;
    for my $route (@{$root->children}) {
        push @arr, route_full_path($route);
    }
    return @arr;
}

sub route_full_path {
    my $route= shift;
    my $path='';
    my @arr;
    my %elem;
    #warn Dumper($route_sub);
    #warn Dumper($route->over);
    #warn Dumper($route->inline);
    #warn Dumper($route->partial);
    if (! $route->inline) {
        $elem{'path'}= $route->pattern->unparsed // '/';
        $elem{'scheme'}= $route->via;
        $elem{'description'}= ${$route->pattern->defaults}{route_description};
        push @arr, \%elem;
    }
    for my $route_sub (@{$route->children}) {
        push @arr, route_full_path($route_sub);
    }
    return @arr;
}

# }}} end functions

app->secrets(['32byte random string here']);

# background process to periodically work queued alerts (and possibly other stuff)
#
#my $wakemeup= Proc::Simple->new();
#$wakemeup->start( \&trigger_myself );
#$wakemeup->kill_on_destroy(1);
#$wakemeup->signal_on_destroy("SIGKILL");


# {{{ mojolicious routes
#

get '/' => {    route_description   => 'redirects to /help',
                app_title           => $app_title
            } => sub {

    my $c = shift;
    $c->stash(  app_title => $app_title); 
    $c->redirect_to('/help');
};
    

get '/help' => {    route_description   => 'Help page (you are probably looking at it).',
                    template            => 'help', 
                    app_title           => $app_title
                } => sub {

    my $c = shift;
    my $base_url= $c->req->url->to_abs->scheme . "://" . $c->req->url->to_abs->host . ":" . $c->req->url->to_abs->port;
    my @arr= get_all_routes ($c->app->routes);
    
    $c->stash(  app_routes      => \@arr,
                app_base_url    => $base_url
            );
};

get '/login' => {   route_description   => 'Lets a (human) Active Directory user log in via HTTP Basic Authentication.',
                    app_title           => $app_title
                } => sub {

    my $c = shift;
    my $log = Mojo::Log->new;
    if (authenticate_user($c)) {
        my ($authuser, undef) = split ':', $c->req->url->to_abs->userinfo;
        $c->session->{username}= $authuser;
        my $previous_page= ( defined $c->session->{redirecting_page} and not $c->session->{redirecting_page} eq '/login' )
            ? $c->session->{redirecting_page}
            : '/';
        $log->info("redirecting to $previous_page");
        $c->redirect_to($previous_page);
        return 1;
    }
};

#{ template => 'login' };

get '/logout' => {  route_description   => 'Logs out a (human) Active Directory user.',
                    app_title           => $app_title
                } => sub {

    my $c= shift;
    # Expire and in turn clear session automatically
    $c->session(expires => 1);
    $c->redirect_to('/');
};

# authentication with a session.
# stateful; should only be used whith human interaction.
#
group {
    under sub {
        my $c= shift;
        my $log = Mojo::Log->new;

        $c->stash(  app_title => $app_title); 
        $c->stash(  app_base_url => $c->req->url->to_abs); 

        if (not defined $c->session->{username} or $c->session->{username} eq '') {
            $log->info("no session(yet).");
            $log->info("redirecting to /login");
            $c->session->{redirecting_page}= '/dashboard';
            $c->redirect_to('/login');
            #$c->render('text' => "Access denied.", status => '401');
            return undef;
        } else {
            my $username= $c->session->{username};
            $log->info("session user found: $username");
            warn Dumper($c->session->{username});
            return 1;
        }
    };

    get '/dashboard' => {   route_description   => 'Manage tokens (requires AD login)',
                            app_title           => $app_title
                        } => sub {

        my $c= shift;
        $c->stash('username' => $c->session->{username});
        my $username= $c->session->{username};

        my $tokens= list_tokens($username);
        $c->stash('tokens' => list_tokens($username));
        $c->render();

    };
};

# stateless authentication with real world user credentials
# usually only used to obtain tokens
#
group {
    under sub {
        my $c = shift;
        my $log = Mojo::Log->new;
        if (authenticate_user($c)) {
            my ($authuser, undef) = split ':', $c->req->url->to_abs->userinfo;
            $c->session->{username}= $authuser;
            return 1;
        } else {
            return undef;
        }
    };

    get '/tokens' => {  route_description   => 'List Tokens (requires AD login)',
                        app_title           => $app_title
                    } => sub {

        my $c= shift;
        my $username= $c->session->{username};

        my $tokens= list_tokens($username);
        $c->stash('tokens' => list_tokens($username));
        $c->render(json => {"tokens" => [@$tokens]});

    };

    put '/tokens/#username/#token' => { route_description   => 'Add token to username\'s authentication-namespace (requires AD login)',
                                        app_title           => $app_title
                                    } => sub {

        my $c= shift;
        my ($session_username, undef)= split /:/, $c->req->url->to_abs->userinfo;
        my $url_username= $c->param('username');
        if (not $session_username eq $url_username) {
            $c->render('text' => "Access denied.", status => '401');
            return;
        }
        my $url_token= $c->param('token');
        my $json= $c->req->json;
        warn Dumper($json);
        my $pass= $json->{'password'};
        warn Dumper($pass);
        if (not defined $pass or $pass eq '') {
            $c->render('json' => { "reason" => "data required." }, status => '403');
            return;
        }
        if (add_token($url_username, $url_token, $pass)) {
            $c->render('text' => '', status => '204');
            return 1;
        } else {
            $c->render(text => "It's not you, it's us.", status => '500');
            return;
        }
    };

    del '/tokens/#username/#token' => { route_description   => 'Remove token from username\'s authentication-namespace (requires AD login)',
                                        app_title           => $app_title
                                    } => sub {

        my $c= shift;
        my ($session_username, undef)= split /:/, $c->req->url->to_abs->userinfo;
        my $url_username= $c->param('username');
        if (not $session_username eq $url_username) {
            $c->render('text' => "Access denied.", status => '401');
            return;
        }
        my $url_token= $c->param('token');

        if (remove_token($url_username, $url_token)) {
            $c->render('text' => '', status => '204');
            return 1;
        } else {
            $c->render(text => "It's not you, it's us.", status => '500');
            return;
        }
    };
};

# API PAYLOAD: token authenticated api endpoint.
# not wrapped in a group because there is just one route.
#
any ['GET', 'POST'] => '/ldap' => { route_description   => 'REST API endpoint. Accepts POST and GET requests with JSON data. Requires token authentication.',
                                    app_title           => $app_title
                                } => sub {

    # Log to STDERR
    my $log = Mojo::Log->new;

    my $c = shift;

    my $json;
    if ($c->req->method eq 'GET') {
        $json= decode_json(url_unescape($c->req->query_params->to_string));
    } else {
        $json= $c->req->json;
    }

    my $username= $c->req->headers->header('x-auth-namespace');

    # authentication / atuhorization
    #
    my $auth_ok;
    my $token_name;

    # allow from localhost
    my $client_ip= $c->tx->remote_address;
    my $my_ip= $c->tx->local_address;
    if ($client_ip eq $my_ip) {
        $token_name="localhost";
        $auth_ok= 1;
    } else {
        $auth_ok= $c->basic_auth('token authentication' => sub { 
                &authenticate_token($username, @_) 
            }
        );
        if ($auth_ok) {
            ($token_name)= split /:/, $c->req->url->to_abs->userinfo;
        }
    }

    my $json_str;
    if ($auth_ok) {
        $log->info("logged in as $username/$token_name");

        my $ldap = Net::LDAP->new( $ldap_host, debug => 0 ) or die "$@";

        my $mesg;
        $mesg = $ldap->bind( $ldap_binduser, password => $ldap_bindpasswd);

        my $output_format= delete $json->{'format'} // "short";
        $mesg= $ldap->search(%$json);
        
        my $count= $mesg->count();
        my $struct= $mesg->as_struct();

        if ($output_format !~ m/ldap/i) {
            $struct= remove_single_key($struct);
        }
        $json_str=encode_json($struct);

        $mesg= $ldap->unbind;

    } else {
        $c->render('text' => "Access denied.", status => '401');
        return 0;
    }
    # auth end

    ## trigger background thread
    #my $bg_alive= $wakemeup->poll();


    # decode twice and downgrade? wtf?
    my $answer= decode('UTF-8', $json_str, Encode::FB_CROAK);
    $answer= decode('UTF-8', $answer, Encode::FB_CROAK);
    my $utf8_success = utf8::downgrade($answer);

    my $success= 1;

    if ($success) {
        $c->render(text => $answer);
    } else
    {
        $c->render(text => $answer, status => '500');
    }
};

# }}} end mojolicious routes

app->start;

# wrong place; see: https://stackoverflow.com/questions/22871601/how-do-i-properly-shut-down-a-mojoliciouslite-server?rq=1
#$wakemeup->kill('SIGKILL');

__DATA__

@@ layouts/mylayout.html.ep
<!DOCTYPE html>
<html>
<head><title><%= $app_title %></title></head>
<body>
<script src="vue.js"></script>
<%= content %>
</body>
</html>

@@ index.html.ep
% layout 'mylayout';
<h1><%= $app_title %></h1>

@@ help.html.ep
% layout 'mylayout';
<h1><%= $app_title %></h1>
<h2>URLs</h2>

<table>
<th>Scheme</th><th>URL</th><th>Route Description</th>
<% foreach my $el (@$app_routes) { %>
    <tr>
      <td><%= join(', ', @{$el->{'scheme'}}) %></td>
      <td><code><%= $app_base_url %><%= $el->{'path'} %></code></td>
      <td><%= $el->{'description'} %></td>
    <tr>
<% } %>
</table>

<h2>
CURL example
</h2>
Set the HTTP header X-AUTH-NAMESPACE to the AD username whose token you are authenticating with.
<p />
Suppose I have created a token with a password and I want to find out which email address I have:<sup>*</sup>
<p />
<code>
curl -u "foo:xxx" -H "X-AUTH-NAMESPACE: myldapuser" -X POST -d '{"base":"DC=domain,DC=local","filter":"(sAMAccountname=myldapuser)","attrs":["mail"]}' "https://serviceurl.domain.local:3444/ldap"
</code>
<p />
(*) "mail" is the attribute that holds a users email address in AD (cf. <a href="https://docs.microsoft.com/en-us/windows/desktop/adschema/a-mail">E-mail-Addresses attribute | Microsoft Docs</a>).
</div>

@@ dashboard.html.ep
% layout 'mylayout';
<h1><%= $app_title %></h1>

<!--
<ul>
% foreach my $token (@$tokens) {
<li><%= $token %></li>
% }
</ul>
-->

<div id='gateway-app'></div>

%= javascript begin
var app= new Vue({
        el: '#gateway-app',
        data : {
            message: 'hello Vue',
            tokens: [],
            addingToken: false,
            newtoken: {
                name: '',
                password: ''
            },
            token: {
                name: '',
                password: ''
            },
            input_password: [],
            editing_password: []
        },
        methods: {
            getTokens() {
                tokens= []
                fetch("/tokens")
                .then(response => response.json())
                .then((data) => {
                    this.tokens= data.tokens.reduce( function(result, token) {
                            result.push({ "name" : token, "password" : '' })
                            return result
                    }, [])
                })
            },
            deleteToken(token) {
                fetch("/tokens/<%= $username %>/" + token.name, {method: "DELETE"})
                .then(() => {
                    this.getTokens()
                    console.log("deleted.")
                })
            },
            saveToken(token) {
                if (token.name==='' || token.password==='') {
                    console.log('neither token.name nor token.password may be empty')
                }
                fetch("/tokens/<%= $username %>/" + token.name, {
                    method: "PUT",
                    headers: {
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify((({ password}) => ({ password }))(token)),
                })
                .then(() => {
                    this.getTokens()
                    this.addingToken= false
                    console.log("saved.")
                })

                console.log("saved: " + token.name + " with pass: " + token.password)
                console.log(JSON.stringify((({ password}) => ({ password }))(token)))
                token.name=''
                token.password=''
            },
            addToken() {
                this.addingToken= true
            },
            showAddTokenButton(token) {
                if ((token.name === '') && (token.password === '')) {
                    this.addingToken= false
                }
            },
            editPassword(token, i) {
                if (token.password !== '') {
                    this.editing_password[i]=true
                } else {
                    this.editing_password[i]=false
                }
                console.log(i)
            },
            savePassword(token, i) {
                this.saveToken(token)
                this.editPassword(token, i)
                console.log('saving password: ' + i)
            }
        },
        directives: {
            focus: {
                // directive definition
                inserted: function (el) {
                    el.focus()
                }
            }
        },
        mounted() {
            this.getTokens()
        },
        template: `
        <div>
        <h2>Tokens for <%= $username %></h2>
        <table>
            <th>token</th><th>password</th><th></th>
            <tr v-for="token, i in tokens">
                <td style="min-width:12em">{{ token.name }}</td>
                <td style="min-width:12em"><input v-model="token.password" v-on:input="editPassword(token, i)" type='password' placeholder='*********'></td>
                <td v-if="editing_password[i]!==true"><button v-on:click="deleteToken(token)">x</button></td>
                <td v-else><button v-on:click="savePassword(token, i)">save</button></td>
            </tr>
            <tr v-if="addingToken===false"><td><button v-on:click="addToken()">+</button></td></tr>
            <tr v-else>
                <td><input style="min-width:12em" v-model="newtoken.name" v-focus v-on:blur="showAddTokenButton(newtoken)" v-on:focus="addToken()" placeholder='token name'></td>
                <td><input style="min-width:12em" v-model="newtoken.password" v-on:blur="showAddTokenButton(newtoken)" v-on:focus="addToken()" type='password' placeholder='password'></td>
                <td><button v-on:click="saveToken(newtoken)" v-on:blur="showAddTokenButton(newtoken)">save</button></td>
            </tr>
        </table>
        </ul>
        </div>
        `
    }
)
% end
