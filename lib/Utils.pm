package lib::Utils;
use strict;
use warnings;

use Exporter 'import';


use DBI;
use DBD::Pg qw(:pg_types);
use LWP;

use LWP::UserAgent;
use MIME::Base64;
use JSON::MaybeXS;
use Data::Dumper;
use Data::Printer;
use MIME::Base64;
use DateTime;
use Log::Log4perl;
use Sys::Hostname;

use Readonly;
use Crypt::Mode::CBC;
#use Crypt::PBKDF2;
use Crypt::KeyDerivation qw(pbkdf2);

use DateTime::Infinite;
use DateTime::Span;
use DateTime::Format::Pg;
use List::NSect qw(spart);
use List::Util qw(uniq uniqstr any all sum0);

#use DateTime::Span;
#use DateTime::Format::ISO8601;

our @EXPORT = qw( write_dumper_to_file
                    _db_connect
                    _db_disconnect _log_init
                    _get_response_token
                    cbc_decrypt_key
                    cbc_decrypt_array
                    self_cbc_decrypt_key
                    dlr_cbc_decrypt_md
                    dlr_decrypt_data_cbc
                    rsa_decrypt
                    dlr_decrypt_data_rsa
                    _dlr_request
                    _oauth_request
                    cbc_decrypt_md
                    get_krids
                    get_keyrings
                    %GLOBAL_ALLOWED_DATA_TYPES
                    prep_copy copy_data finish_copy
                    newjson
);


use constant DEALER_BUN => 'mdflush';
use constant DEALER_UUN => 'mdflush';
use constant DEALER_BPW => 'Zeet1oshain6ouha';
use constant DEALER_UPW => 'undfagemokep';
use constant OAUTH_URL => 'http://dealer.md.api.exetel.com.au:8093/oauth/access_token';
use constant OAUTH_KEY => 'metadata';
use constant OAUTH_SECRET => 'VkHTqtGHQ6QdCMcU1rGf';
use constant DEALER_DERSA_URL => 'http://dealer.md.api.exetel.com.au:8093/decrypt_data_rsa';
use constant DEALER_DECBC_URL => 'http://dealer.md.api.exetel.com.au:8093/decrypt_data_cbc';


#Readonly our %global_allowed_data_types => (
Readonly our %GLOBAL_ALLOWED_DATA_TYPES => (
		'cdr'		=> {'*'	=> 1},
		'execonf'	=> {'*'	=> 1},
		'sipsacc'	=> {'*'	=> 1},
		'fax'		=> {'*'	=> 1},
		'radius'	=> {'auth'	=> 1, 'reply'	=> 1, 'accounting'	=> 1},
		'maild'		=> {'*'	=> 1},
		'mailp'		=> {'*'	=> 1},
		'mailw'		=> {'*'	=> 1},
		'invoice'	=> {'*'	=> 1},
		'payment'	=> {'*'	=> 1},
        'smslog'	=> {'*' => 1},
		#'smslog'	=> {
		#	'sms2email'		=> 1,	'sms2emailpickup'	=> 1,
		#	'sms2apiin'		=> 1,	'sms2apipickup'		=> 1,
		#	'email2smsin'	=> 1,	'custapi2sms'		=> 1,
		#	'outgoingsms'	=> 1,	'email2smsout'		=> 1,
		#},
		'faxlog'			=> {'*'	=> 1},
		'datalinkusage'		=> {'*'	=> 1},
		'broadbandusage'	=> {'*'	=> 1},
		'broadbandlog'		=> {'*'	=> 1},
	);


sub write_dumper_to_file {

    my ( $filename, $ds_dumper_name ) = @_;
    #my $filename = 'report.txt';
    open(my $fh, '>', $filename) or die "Could not open file '$filename' $!";
    $Data::Dumper::Sortkeys = 1;
    print $fh Dumper( $ds_dumper_name );
    close $fh;
}

sub newjson {
	return JSON::MaybeXS::JSON->new->pretty(1)->canonical(1)->utf8(1)->allow_blessed(1)->convert_blessed(1);
}

sub _get_response_token {

    my $ua = LWP::UserAgent->new();
    my $log = Log::Log4perl->get_logger();
    my $json = newjson();

    my $resp = $ua->post(
            'http://dealer.md.api.exetel.com.au:8093/auth_user',
            Authorization => sprintf('Basic %s', MIME::Base64::encode(sprintf('%s:%s', DEALER_BUN, DEALER_BPW), '')),
            Content => $json->encode({ username => DEALER_UUN, password => DEALER_UPW }),
    );

    print "response ". Dumper($resp);
    #debug 'dealer response: %s', slnp($resp);

    my $resp_content = $json->decode($resp->content);

    print "Data ". Dumper($resp_content);
    #debug 'dealer data: %s', slnp($resp_content);

    my $user_jwt = $resp_content->{jwt};

    my $oauth_data = _oauth_request(
            OAUTH_URL,
            sprintf('Basic-X-JWT %s', MIME::Base64::encode(sprintf('%s:%s:%s', OAUTH_KEY, OAUTH_SECRET, $user_jwt), '')),
            {
                grant_type => 'password',
                scope => [qw/md.crypto.create-jwt md.crypto.get-claims md.crypto.decrypt-data md.enquiry.start md.enquiry.update/],
            },
    );

    print "\n\noauth_data ==>> ". Dumper($oauth_data);
    $log->info("oauth_data ==>> ". Dumper($oauth_data));

    return ( $oauth_data, $resp_content  );
}


sub _oauth_request {
        my ($uri, $auth_header, $data) = @_;

        my $resp_obj = {};

        my $cnt = 10;
        my $ua = LWP::UserAgent->new();
        my $json = newjson();

        for ( my $i = 0; $i < $cnt; $i++ ) {
                my $resp = $ua->post(
                        $uri,
                        Authorization => $auth_header,
                        Content       => $data,
                );
                printf( "_oauth_request-Received a %s response for %s: %s", $resp->code, $uri, substr( $resp->content, 0, 2048 ) );

                $resp_obj = $json->decode($resp->content);

                if ( $resp->code == 200 ) {
                        # got response, nothing else to do

#               } elsif ( $resp->code == 401 ) {
#               } elsif ( $resp->code == 500 ) { # read timeout??
                } else {
                        printf("_oauth_request-tx->error: ERROR - Response Code %s for request %s\n%s\n", $resp->code, $uri, substr( $resp->content, 0, 2048 ) );
                        sleep 4;
                }
                ## break out of loop and return
                return $resp_obj if %$resp_obj;
        } ## end for ( my $i = 0; $i < $cnt; $i++ )

        printf( "_oauth_request-tx->error: ERROR - Exceeded retry count of %s for request %s", $cnt, $uri );
        printf( 'Exceeded retry count for request %s', $uri);
        die;
}



sub _dlr_request {
        my ($uri, $oauth_data, $data, $method, $is_refresh) = @_;
        $method ||= 'post';
        $is_refresh ||= 0;

        if ( !$oauth_data->{access_token} ) {
                printf ('Invalid OAuth access token url: %s', $uri);
                die;
        }

        my $resp_obj = {};

        my $cnt = 10;
        my $last_error;
        my $last_resp;
        my $ua = LWP::UserAgent->new();
        my $json = JSON->new;

        for ( my $i = 0; $i < $cnt; $i++ ) {
                my $resp = $ua->$method(
                        $uri,
                        Authorization => sprintf( 'Bearer %s', $oauth_data->{access_token} ),
                        Content => $json->encode($data),
                );
                #debug( "_dlr_request-Received a %s response for $uri: %s", $resp->code, substr( $resp->content, 0, 2048 ) );

                $resp_obj = $json->decode($resp->content);
                if ( $resp->code == 200 && ( !defined $resp_obj->{status} || $resp_obj->{status} eq 'ok' ) ) {
                    print "_dlr_request SUCCESS - SUCCESS URI " . $uri . " status " . $resp->code ;
                } elsif ( $resp->code == 401 && !$is_refresh ) {
                        $oauth_data = get_oauth_refresh_token( $oauth_data->{refresh_token} );
                        printf( "refreshed oauth_data-from _dlr_request try-again: %s", np($oauth_data) );
                        # try again with refreshed oauth data
                        ( $oauth_data, $resp_obj ) = _dlr_request( $uri, $oauth_data, $data, $method, 1 ); ## is_refresh
                } elsif ( $resp->code == 403
                        && exists $resp_obj->{status}
                        && $resp_obj->{status} eq 'error'
                        && $resp_obj->{data}->{message} =~ m/JWT has expired/ ) {

                        printf( "_dlr_request-tx->error: ERROR - JWT has expired for request %s", $uri );
                } else {
                        $last_error = sprintf( "_dlr_request ERROR - Response Code %s for request %d at %s\n%s\n", $resp->code, $i, $uri, ( %$resp_obj ? Dumper($resp_obj) : substr( $resp->content, 0, 2048 ) ) );
                        $last_resp = $resp_obj;
                        printf( "_dlr_request-tx->error (sleeping for 4s): %s", $last_error );
                        $resp_obj = {};
                        sleep 4;
                }
                return ( $oauth_data, $resp_obj ) if %$resp_obj;
        }; ## end for ( my $i = 0; $i < $cnt; $i++ )

        printf( "_dlr_request-tx->error: ERROR - Exceeded retry count of %s for request %s with %s", $cnt, $uri, $last_error );
        die;
}




sub dlr_decrypt_data_rsa {
        my ($oauth_data, $resp_content, $data, $loop_callback) = @_;

        my $user_jwt = $resp_content->{jwt};

        $loop_callback //= sub {
                my $stats = shift;
                if ($stats->{loop_stage} eq 'start') {
#                       printf('dlr_decrypt_data_rsa for %s: datas count: %d, broken into %d partitions',
#				$app_class, $stats->{rec_total}, $stats->{loop_total}
#                       );
                } elsif ($stats->{loop_stage} eq 'end') {
                        printf('dlr_decrypt_data_rsa: decrypted datas count: %d, ',
                                $stats->{rec_cnt}
                        );
                }
        };

        print "dlr_decrypt_data_rsa-user_jwt: " . Dumper($user_jwt);
        #debug "dlr_decrypt_data_rsa-data: %s", np($data);

        my $plaintext_data = {};

        my $processed_datas = 0;
        my $total_datas     = scalar keys %{$data};

        my $max = 500; ## max number of stashes to decrypt with each request
        my @data_lists = spart($max, keys %{$data});

        my $partition_idx = 0;
        foreach my $data_list (@data_lists) {
                $loop_callback->( {
                                loop_stage => 'start',
                                loop_cnt   => $partition_idx + 1,
                                loop_total => scalar @data_lists,
                                rec_cnt    => $processed_datas,
                                rec_total  => $total_datas,
                        }
                );

                my $unpacked_data = { map { $_ => { mk_uuid => $data->{$_}->{mk_uuid}, data => unpack( "H*", $data->{$_}->{data} ) } } @$data_list };

                my $resp_obj;
                ( $oauth_data, $resp_obj ) = _dlr_request(
                        DEALER_DERSA_URL,
                        $oauth_data,
                        { user_jwt => $user_jwt, crypted => $unpacked_data }
                );

                #debug "dlr_decrypt_data_rsa resp_obj: '%s'", slnp($resp_obj);
                foreach my $k (keys %{$resp_obj->{plaintext}}) {
                        $plaintext_data->{$k} = $resp_obj->{plaintext}->{$k};
                }

                $processed_datas += scalar @$data_list;
                $loop_callback->( {
                                loop_stage => 'end',
                                loop_cnt   => $partition_idx + 1,
                                loop_total => scalar @data_lists,
                                rec_cnt    => $processed_datas,
                                rec_total  => $total_datas,
                        }
                );
                $partition_idx++;
        }

        print ( "BEFORE RETURN dlr_decrypt_data_rsa: oauth_data " . Dumper($oauth_data) . " plaintext_data " .  Dumper($plaintext_data) );
        return ( $oauth_data, $plaintext_data );
}

sub rsa_decrypt {
        my ($oauth_data, $resp_content, $data) = @_;

        my $user_jwt = $resp_content->{jwt};

        my $decrypted_data;
        ( $oauth_data, $decrypted_data ) = dlr_decrypt_data_rsa(
                $oauth_data,
                $resp_content,
                $data,
                sub {
                        my $stats = shift;
                        return unless $stats->{loop_stage} eq 'start';
#	                $self->update_log( {
#	                                stage         => 'rsa_decrypt',
#	                                loop_cnt      => $stats->{loop_cnt},
#	                                loop_total    => $stats->{loop_total},
#	                                rec_cnt       => $stats->{rec_cnt},
#	                                rec_total     => $stats->{rec_total},
#	                                partition_idx => $stats->{loop_cnt}-1,
#	                        }
#	                );
                }
        );

        return $decrypted_data;
}


sub dlr_decrypt_data_cbc {
        my ($oauth_data, $resp_content, $data, $loop_callback) = @_;

        my $user_jwt = $resp_content->{jwt};

        $loop_callback //= sub {
                my $stats = shift;
                if ($stats->{loop_stage} eq 'start') {
#                       $app_class->logger->info(
#                               sprintf(
#                                       'dlr_decrypt_data_cbc for %s: datas count: %d, broken into %d partitions',
#                                       $app_class, $stats->{rec_total}, $stats->{loop_total}
#                               )
#                       );
                } elsif ($stats->{loop_stage} eq 'end') {
                        info('dlr_decrypt_data_cbc: decrypted datas count: %d, ', $stats->{rec_cnt});
                }
        };

        my $plaintext_data = {};

        my $processed_datas = 0;
        my $total_datas     = scalar keys %$data;

        my $max = 500; ## max number of stashes to decrypt with each request
        my @data_lists = spart($max, keys %$data);

        my $partition_idx = 0;
        foreach my $data_list (@data_lists) {
                $loop_callback->( {
                                loop_stage => 'start',
                                loop_cnt   => $partition_idx + 1,
                                loop_total => scalar @data_lists,
                                rec_cnt    => $processed_datas,
                                rec_total  => $total_datas,
                        }
                );

                my $unpacked_data = {
                        map {
                                $_ => {
                                        data => unpack( "H*", $data->{$_}->{'data'} ),
                                        key  => unpack( "H*", $data->{$_}->{'key'} ),
                                        iv   => unpack( "H*", $data->{$_}->{'iv'} ),
                                };
#                       } keys %$data
                        } @$data_list
                };

#               $app_class->logger->debug( "dlr_decrypt_data_cbc-unpacked_data: " . np($unpacked_data) );
                my @unpacked_data_keys = keys %$unpacked_data;
#               $app_class->logger->debug( "dlr_decrypt_data_cbc-unpacked_data_keys: " . np(@unpacked_data_keys) );

                my $resp_obj;
                ( $oauth_data, $resp_obj ) = _dlr_request(
                        DEALER_DECBC_URL,
                        $oauth_data,
                        { user_jwt => $user_jwt, crypted => $unpacked_data }
                );
#               $app_class->logger->debug( "dlr_decrypt_data_cbc-plaintext: " . np( $resp_obj->{plaintext} ) );

                foreach my $k (keys %{$resp_obj->{plaintext}}) {
                        $plaintext_data->{$k} = $resp_obj->{plaintext}->{$k};
                }

                $processed_datas += scalar @$data_list;
                $loop_callback->( {
                                loop_stage => 'end',
                                loop_cnt   => $partition_idx + 1,
                                loop_total => scalar @data_lists,
                                rec_cnt    => $processed_datas,
                                rec_total  => $total_datas,
                        }
                );
                $partition_idx++;
        }

#       return ( $oauth_data, $resp_obj->{plaintext} );
        return ( $oauth_data, $plaintext_data );
}

sub dlr_cbc_decrypt_md {
        my ( $oauth_data, $resp_content, $data ) = @_;
        my $json = newjson();
        my $user_jwt = $resp_content->{jwt};

        my $packed_data = {
                map {
                        my $md = $json->decode( $data->{$_}->{metadata} );
                        $_ => {
                                data => $data->{$_}->{data},
                                key  => pack( "H*", $md->{'key'} ),
                                iv   => pack( "H*", $md->{'iv'} ),
                        };
                } keys %$data
        };

        my $decrypted_data;
        ( $oauth_data, $decrypted_data ) =
                dlr_decrypt_data_cbc(
                        $oauth_data,
                        $resp_content,
                        $packed_data,
                        sub {
                                my $stats = shift;
                                return unless $stats->{loop_stage} eq 'start';
#                                $self->update_log( {
#                                                stage         => 'cbc_decrypt_md',
#                                                loop_cnt      => $stats->{loop_cnt},
#                                                loop_total    => $stats->{loop_total},
#                                                rec_cnt       => $stats->{rec_cnt},
#                                                rec_total     => $stats->{rec_total},
#                                                partition_idx => $stats->{loop_cnt}-1,
#                                        }
#                                );
                        }
                );

        return { map { $_ => $json->decode( $decrypted_data->{$_} ) } keys %$decrypted_data };
};

sub cbc_decrypt_md {
        my ($oauth_data, $resp_content, $data) = @_;

        return dlr_cbc_decrypt_md($oauth_data, $resp_content, $data); # self_cbc_decrypt_md($data);
};

=begin comment

sub dlr_cbc_decrypt_key {
        my ($data) = @_;

        my $packed_data = {
                map {
                        my ( $iv, $val ) = ( $data->{$_}->{data} =~ m/^(.{16})(.+)$/s );    # strip off first 16 bytes to use as `iv`
                        $_ => {
                                data => $val,
                                key  => pack( "H*", $data->{$_}->{key} ),
                                iv   => $iv,
                        };
                } keys %$data
        };

        #my $decrypted_data;
        my ( $oauth_data, $decrypted_data ) =
                dlr_decrypt_data_cbc(
                        $oauth_data,
                        $user_jwt,
                        $packed_data,
                        sub {
                                my $stats = shift;
                                return unless $stats->{loop_stage} eq 'start';
                                printf ( "searchkeys: decrypted %s/%s items of data", $stats->{rec_cnt}, $stats->{rec_total} ) unless scalar($stats->{rec_cnt})%10_000;
#                                $self->update_log( {
#                                                stage         => 'cbc_decrypt_key',
#                                                loop_cnt      => $stats->{loop_cnt},
#                                                loop_total    => $stats->{loop_total},
#                                                rec_cnt       => $stats->{rec_cnt},
#                                                rec_total     => $stats->{rec_total},
#                                                partition_idx => $stats->{loop_cnt}-1,
#                                        }
#                                );
                        }
                );

        return $decrypted_data;
} ## end sub dlr_cbc_decrypt_key

=end comment

=cut

sub self_cbc_decrypt_key {
        my ($data) = @_;
        CORE::state $cbc_dec //= Crypt::Mode::CBC->new('AES');

        my $decrypted_data = +{
                map {
                        my ( $iv, $val ) = ( $data->{$_}->{data} =~ m/^(.{16})(.+)$/s );    # strip off first 16 bytes to use as `iv`
                        $_ => $cbc_dec->decrypt(
                                $val,
                                pack( "H*", $data->{$_}->{key} ),
                                $iv
                        )
                } keys %$data
        };

        return $decrypted_data;
}

sub cbc_decrypt_array {
	my ($data, $retref) = @_;
	CORE::state $cbc_dec //= Crypt::Mode::CBC->new('AES');

	my $decrypted_data = [
		map {
			my ($iv, $val) = ($_->{data_enc} =~ m/^(.{16})(.+)$/s);    # strip off first 16 bytes to use as `iv`
			my $data_dec = $cbc_dec->decrypt(
				$val,
				pack("H*", $_->{key}),
				$iv
			);
			{
				data_enc => $_->{data_enc},
				data_dec => $data_dec,
				extra => $_->{extra}//{},
			}
		} @$data
	];

	return $decrypted_data;
}

sub cbc_decrypt_key {
        my ($data) = @_;

        #return dlr_cbc_decrypt_key($data);
        return self_cbc_decrypt_key($data);
};



################### Database subs

sub _db_connect {

    my $driver  = "Pg";
    my $database = "mdstash";
    my $host = hostname;

    my $dsn;
    my $userid;
    my $password;

    #my $dsn = "DBI:$driver:dbname = $database;host = 127.0.0.1;port = 5432";
    if ( $host =~  /dev/ ) {
        $dsn = "DBI:$driver:dbname = $database;port = 5432";
        $userid = "postgres";
        $password = "";
    } elsif ( $host =~  /flush/ ) {
        $dsn = "DBI:$driver:dbname = $database;host=10.3.34.1;port = 5432;sslmode=allow";
        #$userid = "mdstash";
        #$password = "mdstash123";
        $userid   = "mdflush";
        $password = "test";        
        #$userid   = "mdmull";
        #$password = "j5Hwp5AhMIIlHNsfCWLK";
    }

    my $log = Log::Log4perl->get_logger();
    #my $dbh = DBI->connect($dsn, $userid, $password,  {AutoCommit => 1, PrintError => 1, RaiseError => 1})
    my $dbh = DBI->connect($dsn, $userid, $password,  { AutoCommit => 1, RaiseError => 1 } )
    or die $DBI::errstr;

    print "Opened database successfully\n";

    $log->info("Opened database successfully");
    $log->info("HOSTNAME $host");
    print "HOSTNAME $host\n";

    return $dbh;

}

sub _db_disconnect {

    my ( $dbh ) = @_;
    my $log = Log::Log4perl->get_logger();

    print "DB Operation done successfully\n";
    $log->info("DB Operation done successfully");

    $dbh->disconnect();

}

sub _log_init {

    # Initialize Logger
    my $log_conf = "/home/vikram/log4perl.conf";
    Log::Log4perl::init($log_conf);
    my $log = Log::Log4perl->get_logger();
    # sample logging statement
    $log->info("Initialised logger");

}


sub get_krids {
    my ($dbh, $lower_tstz_range, $upper_tstz_range, $oauth_data, $resp_content) = @_;

    my $json = newjson();   ### TODO:::  Enclose dsotm fetch in a sub and get rid of this....
    my $log = Log::Log4perl->get_logger();

    $log->info("lower_tstz_range ==>> ". $lower_tstz_range);
    $log->info("upper_tstz_range ==>> ". $upper_tstz_range);

    #print "tsr_start " . Dumper($tsr_start);
    #print "tsr_end "   . Dumper ($tsr_end);
    #print "timerange " . Dumper ($input_timerange_span);
    

    my $stmt = "SELECT
                    moon,
                    tsr,
                    yutu,
                    lower(tsr) AS tsr_start,
                    upper(tsr) AS tsr_end
                FROM
                    dsotm
                WHERE
                    tsr && tstzrange( ?, ?, '[]') order by tsr desc";

    my $sth = $dbh->prepare( $stmt );
    my $rv = $sth->execute( $lower_tstz_range, $upper_tstz_range ) or die $DBI::errstr;

    #print $DBI::errstr if($rv < 0);

    my $slices = $sth->fetchall_arrayref({});

    my $mds = @$slices
            ? rsa_decrypt( $oauth_data,
                           $resp_content,                           
                           { map { unpack( "H*", $_->{moon} ) => { mk_uuid => $_->{yutu}, data => $_->{moon} } } @$slices } )
            : {};

    printf ( "mds: %s", Dumper($mds) );

    my %krids;
    foreach my $slice (@$slices) {

            printf ( "moon before json_decode : %s", Dumper( $slice->{moon} ) );
            my $moon_data = $json->decode( $mds->{unpack( "H*", $slice->{moon} )});
            printf ( "moon_data after json_decode : %s", Dumper($moon_data) );

            #my $tsr_range = $json->decode($tsr);
            my $tsr_start = DateTime::Format::Pg->parse_datetime( $slice->{tsr_start} );
            my $tsr_end   = DateTime::Format::Pg->parse_datetime( $slice->{tsr_end} );
            $krids{ $moon_data->{krid} } = {
                    krid      => $moon_data->{krid},
                    timerange => DateTime::Span->from_datetimes( start => $tsr_start, end => $tsr_end ),
                    mk_uuid   => $slice->{yutu},
            };
            printf ( "krids mk_uuid: %s", Dumper( $krids{ $moon_data->{krid} }->{'mk_uuid'} ) );
            printf ( "krids krid: %s", Dumper( $krids{ $moon_data->{krid} }->{'krid'} ) );

            printf ( "moon_data: %s", Dumper($moon_data) );
    } ## end foreach my $slice (@$slices)

    $sth->finish;

    #my $krids = $krids;

    return \%krids;
}

sub get_keyrings {
	my ( $dbh, $krids, $oauth_data, $resp_content, $input_timerange_span ) = @_;
    #my ( $dbh, $krids, $oauth_data, $resp_content, $input_timerange_span ) = @_;

	my %salty_kids;
    my $log = Log::Log4perl->get_logger();

	my $max = 4096; ## max number of parameters for DBD::pg
	foreach my $krids_list ( spart( $max, keys %$krids ) ) {
		my $sql = sprintf(q{
			SELECT krid, metadata, keys
			FROM keyring
			WHERE krid IN (%s)
		;}, join(', ', ('?') x scalar(@$krids_list)));

		my $sth = $dbh->prepare($sql);
		$sth->execute(@$krids_list);

		my $rtkeyrings = $sth->fetchall_arrayref;

		# $mds in old code
		my $keyring_metadata_secrets = @$rtkeyrings
			? rsa_decrypt(
				$oauth_data,
				$resp_content,
				{
					map {    #print "\n DECRYPT mk_uuid for keyring table ==>> " . $krids->{$_->[0]}->{mk_uuid} ."\n";
						$_->[0] => { mk_uuid => $krids->{$_->[0]}->{mk_uuid}, data => $_->[1] }
					} @$rtkeyrings
				}
			)
			: {}; ## ( $krid, $key, $metadata, $tsr ) -> { $krid => $metadata }

		my $keyring_keys_secrets = @$rtkeyrings
			? cbc_decrypt_md(
				$oauth_data,
				$resp_content,
				{
					map {
						$_->[0] => {
							data     => $_->[2],
							metadata => $keyring_metadata_secrets->{$_->[0]}
						}
					} @$rtkeyrings
				}
			)
			: {};

		foreach my $keyring (@$rtkeyrings) {
			my ($krid) = @$keyring;
			my $skeyring = $keyring_keys_secrets->{$krid};

			if ($skeyring->{version} eq '8') {
				my $sess_secrets = $skeyring->{secrets};
				$sess_secrets->{mk_uuid} = $krids->{$krid}->{mk_uuid};

				my $salty_all_kid = pbkdf2(
					$sess_secrets->{kid},
					pack( 'H*', $sess_secrets->{salt}->{search_kid} ),
					$sess_secrets->{pdkargs}->{iters},
					$sess_secrets->{pdkargs}->{hash},
					$sess_secrets->{pdkargs}->{dklen}
				);

				my (@dt_kids, @dt_hkids, @dt_data_types, @dt_timeranges);
				printf("keyring:%s all timerange: %s", $krid, Dumper($sess_secrets->{logts_range}) );

				my $strp = DateTime::Format::Strptime->new(
					pattern   => '%FT%T%z',
				);

				foreach my $dtype_info (@{$skeyring->{info}}) {

                    my $start_dt = $strp->parse_datetime( $dtype_info->{logts_range}->{start} );
                    my $end_dt   = $strp->parse_datetime( $dtype_info->{logts_range}->{end} );

                    unless ( $input_timerange_span->contains( $end_dt ) &&
                            $input_timerange_span->contains( $start_dt ) && 
                            $GLOBAL_ALLOWED_DATA_TYPES{$dtype_info->{data_type}} ) {

                        $log->info( "keyring: $krid keep data: " . Dumper($dtype_info) );
                        next;
                    }
					printf("keyring:%s nuke data: %s", $krid, Dumper($dtype_info) );

					my $salty_kid = pbkdf2(
						$dtype_info->{kid},
						pack('H*', $sess_secrets->{salt}->{search_kid}),
						$sess_secrets->{pdkargs}->{iters},
						$sess_secrets->{pdkargs}->{hash},
						$sess_secrets->{pdkargs}->{dklen}
					);

					# AP: 20190611: we do this here so that we don't have to count kids later and decide then.
					$salty_kids{$krid}{mk_uuid} = $krids->{$krid}->{mk_uuid};
					# salty_kids{keyring_id}{"kids"}{all_kid}{dtype_kid}{...}
					$salty_kids{$krid}{kids}{$salty_all_kid}{$salty_kid}{'search_id'} = $sess_secrets->{skeys}->{search_id};
					$salty_kids{$krid}{kids}{$salty_all_kid}{$salty_kid}{'dt_info'}   = $dtype_info;
					#$salty_kids{$krid}{kids}{$salty_all_kid}{$salty_kid}{'dt_info'}->{logts_range}->{start_dt} = $logts_start_dt;
					#$salty_kids{$krid}{kids}{$salty_all_kid}{$salty_kid}{'dt_info'}->{logts_range}->{end_dt} = $logts_end_dt;
					$salty_kids{$krid}{kids}{$salty_all_kid}{$salty_kid}{'secrets'}   = $sess_secrets;
				}
			} else {
				print "Keyring key/metadata unsupported version\n";
				die;
			}
		} ## end foreach my $keyring (@$rtkeyrings)
		$sth->finish;
	};

	write_dumper_to_file( "salty_kids.txt", \%salty_kids);

	return \%salty_kids;

}


1;
