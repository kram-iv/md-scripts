#!/usr/bin/perl

use strict;
use warnings;
use v5.20;

use DBI;
use LWP;
use JSON;

use LWP::UserAgent;
use MIME::Base64;
#use JSON::MaybeXS;
use JSON;
use Data::Dumper;
use Data::Printer;
use MIME::Base64;
use DateTime;

use Crypt::Mode::CBC;
use Crypt::KeyDerivation qw(pbkdf2);

use DateTime::Infinite;
use DateTime::Span;
use DateTime::Format::Pg;
use List::NSect qw(spart);
use List::Util qw(uniq uniqstr any all sum0);


my $driver  = "Pg"; 
my $database = "mdstash";
#my $dsn = "DBI:$driver:dbname = $database;host = 127.0.0.1;port = 5432";
my $dsn = "DBI:$driver:dbname = $database;port = 5432";
my $userid = "postgres";
my $password = "";
my $dbh = DBI->connect($dsn, $userid, $password, { RaiseError => 1 }) 
   or die $DBI::errstr;

print "Opened database successfully\n";


my $ua = LWP::UserAgent->new();
#my $json = JSON::MaybeXS::JSON->new->pretty(1)->canonical(1)->utf8(1)->allow_blessed(1)->convert_blessed(1);
my $json = JSON->new;

#my $ser = Sereal::Encoder->new({compress => 1, no_shared_hashkeys => 1, dedupe_strings => 0});
#my $sdr = Sereal::Decoder->new();

my $dealer_bun = 'mdflush';
my $dealer_uun = 'mdflush';
my $dealer_bpw = 'Zeet1oshain6ouha';
my $dealer_upw = 'undfagemokep';
my $oauth_url = 'http://dealer.md.api.exetel.com.au:8093/oauth/access_token';
my $oauth_key = 'metadata';
my $oauth_secret = 'VkHTqtGHQ6QdCMcU1rGf';
my $dealer_dersa_url = 'http://dealer.md.api.exetel.com.au:8093/decrypt_data_rsa';
my $dealer_decbc_url = 'http://dealer.md.api.exetel.com.au:8093/decrypt_data_cbc';

my %keyrings;
my $keyring_metadata_secrets = {};
my $keyring_keys_secrets = {};
my $keyring_hkid_mapping = {};
my $keyring_krid_mapping = {};
my $keyring_metadata = {};

my $resp = $ua->post(
	'http://dealer.md.api.exetel.com.au:8093/auth_user',
	Authorization => sprintf('Basic %s', MIME::Base64::encode(sprintf('%s:%s', $dealer_bun, $dealer_bpw), '')),
	Content => $json->encode({ username => $dealer_uun, password => $dealer_upw }),
);

print "response ". Dumper($resp);
#debug 'dealer response: %s', slnp($resp);

my $data = $json->decode($resp->content);

print "Data ". Dumper($data);
#debug 'dealer data: %s', slnp($data);

my $user_jwt = $data->{jwt};

my $oauth_data = _oauth_request(
	$oauth_url,
	sprintf('Basic-X-JWT %s', MIME::Base64::encode(sprintf('%s:%s:%s', $oauth_key, $oauth_secret, $user_jwt), '')), 
	{
		grant_type => 'password',
		scope => [qw/md.crypto.create-jwt md.crypto.get-claims md.crypto.decrypt-data md.enquiry.start md.enquiry.update/],
	},
);

print "\n\noauth_data ==>> ". Dumper($oauth_data);



#my $stash_stmt = qq(SELECT tsr, encode(moon,'hex') as moon, yutu from dsotm limit 1;);
my $stash_stmt = qq(SELECT id, kid, datum from search limit 1;);
my $stash_sth = $dbh->prepare( $stash_stmt );
my $stash_rv = $stash_sth->execute() or die $DBI::errstr;
#if($stash_rv < 0) {
print $DBI::errstr if($stash_rv < 0);
#}
#while (my $row = $stash_sth->fetchrow_hashref) {
#      print "$row->{tsr} $row->{moon}, $row->{yutu}\n";
#}

	my $stash_slices = $stash_sth->fetchall_arrayref;



    my $srchks = @$stash_slices
        ? cbc_decrypt_key( {
            map {
                my ( $id, $hkid, $datum ) = @$_;
                my $skeyring = $keyring_metadata->{$keyring_hkid_mapping->{$hkid} };
                #$secretcount++;
                #unless ($secretcount%100_000) {
                #    plogmem("searchkeys: metaed %s searchables", $secretcount);
                #};
                unpack( "H*", $id ) => {
                    data => $id,
                    key  => $skeyring->{skeys}->{search_id}
                    }
            } @$stash_slices
        }
        )
        : {};

    print "DUMPING search keys " . Dumper($srchks);

=begin
      #while (my $row = $stash_sth->fetchrow_hashref) {
    foreach (@$stash_slices) {
        print "id: " . $_->[0] ."\n" .  "kid:" . $_->[1] ."\n". "datum:" . $_->[2] ."\n";
        print "UNPACKED id: " . unpack( "H*", $_->[0] ) ."\n";
        #print "Decrypting metadata: " . rsa_decrypt( $_->[1] );

        $keyring_metadata_secrets =
            @$stash_slices
            ? cbc_decrypt_key( { map { unpack( "H*", $_->[0] ) => { mk_uuid => unpack( "H*", $_->[0] ) , data => $_->[2] } } @$stash_slices } )
            : {}; ## ( $krid, $key, $metadata, $tsr ) -> { $krid => $metadata }

        printf ( "keyring_metadata_secrets DUMPER: %s", Dumper($keyring_metadata_secrets) );
        #print "Decrypting data: " . cbc_decrypt_key( $row->{data}  );
    }
=cut


=begin
	my $stash_mds = @$stash_slices
	          ? rsa_decrypt( { map { unpack( "H*", $_->[0] ) => { mk_uuid => $_->[2], data => $_->[0] } } @$stash_slices } )
	          : {};

	printf ( "stash_mds: %s", Dumper($stash_mds) );

	my $darksides = {};
	foreach my $slice (@$stash_slices) {
	        my ( $moon, $tsr, $mk_uuid ) = @$slice;
            printf ( "moon before json_decode : %s", Dumper($moon) );
	        my $moon_data = $json->decode( $stash_mds->{unpack( "H*", $moon)});
            printf ( "moon_data after json_decode : %s", Dumper($moon_data) );
	        my $tsr_range = $json->decode($tsr);
	        my $tsr_start = DateTime::Format::Pg->parse_datetime( $tsr_range->[0] );
	        my $tsr_end   = DateTime::Format::Pg->parse_datetime( $tsr_range->[1] );
	        $darksides->{ $moon_data->{krid} } = {
	                krid      => $moon_data->{krid},
	                timerange => DateTime::Span->from_datetimes( start => $tsr_start, end => $tsr_end ),
	                mk_uuid   => $mk_uuid,
	        };
            printf ( "darksides mk_uuid: %s", Dumper( $darksides->{ $moon_data->{krid} }->{'mk_uuid'} ) );
            printf ( "darksides krid: %s", Dumper( $darksides->{ $moon_data->{krid} }->{'krid'} ) );

            printf ( "moon_data: %s", Dumper($moon_data) );
	} ## end foreach my $slice (@$slices)

	#printf ( "darksides: %s", Dumper($darksides) );
=cut
	$stash_sth->finish;





print "Operation done successfully\n";

$dbh->disconnect();


sub _oauth_request {
	my ($uri, $auth_header, $data) = @_;

	my $resp_obj = {};

        my $cnt = 10;
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
        for ( my $i = 0; $i < $cnt; $i++ ) {
		my $resp = $ua->$method(
			$uri,
			Authorization => sprintf( 'Bearer %s', $oauth_data->{access_token} ),
			Content => $json->encode($data),
		);
                #debug( "_dlr_request-Received a %s response for $uri: %s", $resp->code, substr( $resp->content, 0, 2048 ) );

		$resp_obj = $json->decode($resp->content);
                if ( $resp->code == 200 && ( !defined $resp_obj->{status} || $resp_obj->{status} eq 'ok' ) ) {
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
                        $last_error = sprintf( "ERROR - Response Code %s for request %d at %s\n%s\n", $resp->code, $i, $uri, ( %$resp_obj ? Dumper($resp_obj) : substr( $resp->content, 0, 2048 ) ) );
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
	my ($oauth_data, $user_jwt, $data, $loop_callback) = @_;

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

                my $unpacked_data = { map { $_ => { mk_uuid => $data->{$_}->{mk_uuid}, data => unpack( "H*", $data->{$_}->{data} ) } } @$data_list };
                print "dlr_decrypt_data_rsa-unpacked_data: " . Dumper($unpacked_data);
                my $resp_obj;

                ( $oauth_data, $resp_obj ) = _dlr_request(
                        $dealer_dersa_url,
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
	my ($data) = @_;

	my ($oauth_data, $decrypted_data) = dlr_decrypt_data_rsa(
	        $oauth_data,
	        $user_jwt,
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
	my ($oauth_data, $user_jwt, $data, $loop_callback) = @_;
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
                        $dealer_decbc_url,
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
	my ($data) = @_;

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

        my ( $oauth_data, $decrypted_data ) = 
                dlr_decrypt_data_cbc(
                        $oauth_data,
                        $user_jwt,
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
	my ($data) = @_;

	return dlr_cbc_decrypt_md($data); # self_cbc_decrypt_md($data);
};

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

	my $decrypted_data;
        ( $oauth_data, $decrypted_data ) = 
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

sub self_cbc_decrypt_key {
	my ($data) = @_;
	state $cbc_dec //= Crypt::Mode::CBC->new('AES');

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

sub cbc_decrypt_key {
	my ($data) = @_;

	#return dlr_cbc_decrypt_key($data);
	return self_cbc_decrypt_key($data);
};





