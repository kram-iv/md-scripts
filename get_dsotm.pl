#!/usr/bin/perl

use strict;
use warnings;
#use v5.20;

use DBI;
use DBD::Pg qw(:pg_types);
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
#use Crypt::PBKDF2;
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

my %bundles = (
        default => {
                id       => 'default',
                krid     => [],          # is this deprecated
#		metadata => {},          # is this deprecated
                payload  => {
                        tables => {
                                search => 'search',
                                link   => 'link',
                                stash  => 'stash',
                                brick  => 'brick',
                        },
                        schemas => {
                                search => 'public',
                                link   => 'public',
                                stash  => 'public',
                                brick  => 'public',
                        }
                }
        },
);
my $bundle_metadata_secrets = {};
my $bundle_payloads_secrets = {};
my $stash_linkrefs = {};
my $bndl_links_dtype = {};

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
my %hkid_hex_hash;

#foreach my $ts_range_type (qw(query custserv selves)) {
#my $stmt = qq(SELECT tsr, encode(moon,'hex') as moon, yutu from dsotm limit 1;);
#my $stmt = "SELECT moon, tsr, yutu from dsotm limit 5";
#my $stmt = "SELECT moon, tsr, yutu from dsotm order by tsr desc limit 5";

my $stmt = "SELECT 
                moon, tsr, yutu
            FROM 
                dsotm
            WHERE 
                lower(tsr) > '2019-05-10 05:00:00' AND
                upper(tsr) <= '2019-05-20 05:59:58'";

#my $stmt = "SELECT moon, tsr, yutu from dsotm";
my $sth = $dbh->prepare( $stmt );
my $rv = $sth->execute() or die $DBI::errstr;
#if($rv < 0) {
print $DBI::errstr if($rv < 0);
#}
#while (my $row = $sth->fetchrow_hashref) {
#      print "$row->{tsr} $row->{moon}, $row->{yutu}\n";
#}

        my $slices = $sth->fetchall_arrayref;

        my $mds = @$slices
                  ? rsa_decrypt( { map { unpack( "H*", $_->[0] ) => { mk_uuid => $_->[2], data => $_->[0] } } @$slices } )
                  : {};

        printf ( "mds: %s", Dumper($mds) );

        my $darksides = {};
        foreach my $slice (@$slices) {
                my ( $moon, $tsr, $mk_uuid ) = @$slice;
            printf ( "moon before json_decode : %s", Dumper($moon) );
                my $moon_data = $json->decode( $mds->{unpack( "H*", $moon)});
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

        $sth->finish;

        my $krids = $darksides;

        my $keyring_keys = [];

        my $max = 65535; ## max number of parameters for DBD::pg


    #printf ( "darksides or krids: %s", Dumper($darksides) );

        foreach my $krids_list ( spart( $max, uniqstr keys %$krids ) ) {

                my $sql = sprintf(q{
                        SELECT krid, metadata, keys
                        FROM keyring
                        WHERE krid IN (%s)
                ;}, join(', ', ('?') x scalar(@$krids_list)));

                my $sth = $dbh->prepare($sql) or die;
                    $sth->execute(@$krids_list);

                my $rtkeyrings = $sth->fetchall_arrayref;

                print("decrypting metadata for %d keyring records\n", scalar @$rtkeyrings);
                #debug('encrypted metadata: %s',np($rtkeyrings));

                # $mds in old code
                $keyring_metadata_secrets =
                    @$rtkeyrings
                  ? rsa_decrypt( { map { $_->[0] => { mk_uuid => $krids->{$_->[0]}->{mk_uuid}, data => $_->[1] } } @$rtkeyrings } )
                  : {}; ## ( $krid, $key, $metadata, $tsr ) -> { $krid => $metadata }

                printf("decrypted metadata for %d keyring records\n", scalar keys %$keyring_metadata_secrets);
                #debug('decrepted metadata: %s', np($keyring_metadata_secret));

                print("decrypted keys for keyring records DUMPER " . Dumper($keyring_metadata_secrets) );
                # $skrs in old code
                $keyring_keys_secrets = @$rtkeyrings
                  ? cbc_decrypt_md( {
                                map {
                                        $_->[0] => {
                                                data     => $_->[2],
                                                metadata => $keyring_metadata_secrets->{$_->[0]}
                                          }
                                } @$rtkeyrings
                        }
                  )
                  : {};

                printf("decrypted keys for %d keyring records\n", scalar keys %$keyring_keys_secrets);
                #debug('decrypted keys: %s', np($keyring_keys_secret));
                printf("decrypted keys: %s\n", Dumper($keyring_keys_secrets) );
        #        $self->set_keyring_keys_secret(%$skrs) if %$skrs;    # can't set keys with empty hash
                print( "rtkeyrings DUMPER \n", Dumper(@$rtkeyrings) );

                foreach my $keyring (@$rtkeyrings) {
                        my ( $krid, $metadata, $key ) = @$keyring;
                        my $skeyring = $keyring_keys_secrets->{$krid};

                        print( "skeyring DUMPER \n", Dumper($skeyring) );

                        if ($skeyring->{version} eq '8') {
                                printf( "INSIDE IF version %d CONFIRMED \n", $skeyring->{version} );
                                my $sess_secrets = $skeyring->{secrets};
                                $sess_secrets->{mk_uuid} = $krids->{$krid}->{mk_uuid};

                                my $hkid = pbkdf2(
                                        $sess_secrets->{kid},
                                        pack( 'H*', $sess_secrets->{salt}->{search_kid} ),
                                         $sess_secrets->{pdkargs}->{iters},
                                         $sess_secrets->{pdkargs}->{hash},
                                         $sess_secrets->{pdkargs}->{dklen}
                                );
                                $sess_secrets->{hkid} = $hkid;
                                $keyring_hkid_mapping->{$hkid} = $sess_secrets->{kid};
                                foreach my $dtype_info (@{$skeyring->{info}}) {

                                        print "dtype_info INFO " . Dumper($dtype_info);
                                        print "dtype_info kid " . Dumper( $dtype_info->{kid} );

                                        my $dtype_hkid = pbkdf2(
                                                $dtype_info->{kid},
                                                pack( 'H*', $sess_secrets->{salt}->{search_kid} ), $sess_secrets->{pdkargs}->{iters}, $sess_secrets->{pdkargs}->{hash}, $sess_secrets->{pdkargs}->{dklen}
                                        );

                                    my $dtype_hkid_hex =  unpack("H*",$dtype_hkid);  # output dtype_hkid as hexadecimal
                                    $hkid_hex_hash{ $dtype_hkid_hex }{'searchId'} = $sess_secrets->{skeys}->{search_id};
                                    $hkid_hex_hash{ $dtype_hkid_hex }{'secrets'}  = $sess_secrets;

                                        $dtype_info->{hkid} = $dtype_hkid;
                                        $keyring_hkid_mapping->{$dtype_hkid} = $sess_secrets->{kid};

                                        print "HASHED KID from INFO ";
                                        print "HASHED KID from INFO " . Dumper($dtype_hkid);
                                        print "HASHED KID HEX from INFO " . Dumper($dtype_hkid_hex);
                                }
                                $keyring_krid_mapping->{$krid} =$sess_secrets->{kid};
                                $keyring_metadata->{$sess_secrets->{kid}} = $sess_secrets;
                            print "keyring_metadata " . Dumper($keyring_metadata);

                            my $ts_range_type = "selves";

                                push @$keyring_keys, {
                                        v             => 8,
                                        krid          => $krid,                                                # krid of keyring record `keyring.krid`
                                        kid           => $sess_secrets->{kid},                                 # all-sessionid, id for skeys/salts/pdkargs
                                        kids          => [map { $_->{kid} } @{ $skeyring->{info} }],           # datatype-sessionid, ids for all data_types in `info`
                                        hkid          => $hkid,                                                # hashed kid, same as kid of searchables - `search.kid`
                                        hkids         => [map { $_->{hkid} } @{ $skeyring->{info} }],          # hashed kid(s), hkid for all data_types in `info`
                                        data_type     => 'all', ## $sess_secrets->{data_type},
                                        data_types    => [map { $_->{data_type} } @{ $skeyring->{info} }],
                                        salt          => $sess_secrets->{salt},
                                        pdkargs       => $sess_secrets->{pdkargs},
                                        skeys         => $sess_secrets->{skeys},
                                        mk_uuid       => $sess_secrets->{mk_uuid},
                                        timerange     => $sess_secrets->{logts_range},                         # { start => ..., end => ... } ## can be deprecated, doesn't appear to be used
                                        timeranges    => [map { $_->{logts_range} } @{ $skeyring->{info} }],
                                        ts_range_type => $ts_range_type,
                                        needle_type   => 'keyring', # 'all' ## really should be (cust|serv|log)
                                };

                        } else {
                                print("Keyring key/metadata unsupported version");
                                die;
                        }
                ######################## ### DEBUG UNCOMMENT print "keyring_keys " . Dumper(@$keyring_keys);
                } ## end foreach my $keyring (@$rtkeyrings)
                $sth->finish;
        };
    #$keyrings{$ts_range_type} = $keyring_keys;
#print "keyring_hkid_mapping DUMPER " . Dumper($keyring_hkid_mapping);
#}

######################## ### DEBUG UNCOMMENT print "keyring_keys: " . Dumper(\%keyrings);



#############################################################################################
#############################################################################################
#############################################################################################

=begin
my $bndl_lrefs;
# START: get_bundled_linkrefs()
# START: get_bundled_searchkeys_for_keyring_keys()
# START: get_bundled_searchkeys()
my $search_sources = [ map {
        my $keyring = $_;
        (
                +{%$keyring},
                map { +{ %$keyring, hkid => $_ } } @{ $keyring->{hkids} }
        )
} @{ $keyrings{'query'} } ];
#debug('search sources: %s', np($search_sources));
my $source_key_lookup = 'hkid';
my $source_key_meta = '';
my $query_column = 'kid';

my $total_sources = scalar @$search_sources;

my @source_lists = spart( $max, uniqstr map { $_->{$source_key_lookup} } @{ $search_sources } );
my $source_meta = { map { $_->{$source_key_lookup} => $source_key_meta ? $_->{$source_key_meta} : $_ } @{$search_sources} };

=cut

=begin
my $search_stmt = 'SELECT
                        encode(id,\'hex\')    as hex_id,
                        encode(kid,\'hex\')   as kid_hex,
                        encode(datum,\'hex\') as datum_hex
                    FROM
                        search
                    WHERE
                        encode(kid,\'hex\') = ? limit 10';
=cut

my $search_stmt = 'SELECT id, kid, datum FROM search WHERE encode(kid,\'hex\') = ?';
#my $search_stmt = 'SELECT id, kid, datum FROM search WHERE encode(kid,\'hex\') = ?';

my $search_sth = $dbh->prepare( $search_stmt );
#my $search_array_refs =[];

print "hkid_hex_hash " . Dumper(\%hkid_hex_hash);

foreach my $hkid_hex (keys %hkid_hex_hash)
{
#for my $hkid_hex ( @hkid_hex_array ) {
    my $search_id = $hkid_hex_hash{$hkid_hex}{'searchId'};
    print( "hkid_hex $hkid_hex \n");
    my $search_rv = $search_sth->execute($hkid_hex); #or die $DBI::errstr;
    print $DBI::errstr if( $search_rv < 0 );

    #while (my $row = $search_sth->fetchrow_hashref) {
    my $search_array_refs = $search_sth->fetchall_arrayref;


        #print "id: $row->{hex_id}  kid: $row->{kid_hex} datum: $row->{datum_hex} search $search_id\n";
        #print "id: $row[0]  kid: $row[1] datum: $row[2] search $search_id\n";

        my $search_refs = @$search_array_refs ?
                        cbc_decrypt_key({
                                                map {
                                                        my ( $id, $hkid, $datum ) = @$_;
                                                        #my $skeyring = $keyring_metadata->{$keyring_hkid_mapping->{$hkid} };

                                                        unpack( "H*", $id ) => {
                                                                data => $id,
                                                                key  => $search_id
                                                        }
                                                } @$search_array_refs
                                        }) : {};

        print "search_refs ". Dumper($search_refs);

        print "DUMPING secrets salt links  ". $hkid_hex_hash{$hkid_hex}{'secrets'}{'salt'}{'link'} . "\n";

        foreach my $hkid_hex_01 (keys %$search_refs)
        {
            my $uuid      = %$search_refs{$hkid_hex_01};
            my $salt_link = $hkid_hex_hash{$hkid_hex}{'secrets'}{'salt'}{'link'};
            my $link_ids  = $hkid_hex_hash{$hkid_hex}{'secrets'}{'skeys'}{'link_ids'};

            print "plaintext uuid ". $uuid . "\n";
            print "hkid_hex_hash link table salt " . $salt_link . "\n";
            print "hkid_hex_hash linkids " . $link_ids . "\n";

            my $datum_id = pbkdf2(
                $uuid,
                pack( 'H*', $salt_link ),
                $hkid_hex_hash{$hkid_hex}{'secrets'}->{'pdkargs'}->{'iters'},
                $hkid_hex_hash{$hkid_hex}{'secrets'}->{'pdkargs'}->{'hash'},
                $hkid_hex_hash{$hkid_hex}{'secrets'}->{'pdkargs'}->{'dklen'}
            );
            print "pbkdf2 hashed uuid ". $datum_id . "\n";

            my $hashed_uuid =  unpack("H*",$datum_id);  # output hashed datum_id as hexadecimal

            print "hashed uuid as hexadecimal ==> ". $hashed_uuid . "\n";
=begin
            my $sql = "SELECT
                        encode(datum_id,'hex') as datum_id,
                        encode(ids,'hex') as ids
                       FROM
                        link
                       limit 10";
=cut
#I want to use the $datum_id got above (pbkdf2 of uuid )in the query below.
            my $sql = "SELECT
                        datum_id,
                        ids
                       FROM
                        link
                       WHERE
                        datum_id = ?";

                my $sth = $dbh->prepare($sql) or die;

                $sth->bind_param( 1, $datum_id, { 'pg_type' => PG_BYTEA } );

                $sth->execute();

                my $link_array_refs = $sth->fetchall_arrayref;
                #print "link_array_refs ". Dumper($link_array_refs);   ### link_array_refs in binary


                my $lkrfs = @$link_array_refs
                  ? cbc_decrypt_key( {
                                map {
                                        unpack( "H*", $_->[1] ) => {
                                                data => $_->[1],
                                                #key  => $sdata->{meta}->{keyring}->{skeys}->{link_ids},
                                                key  => $link_ids,
                                        }
                                } @$link_array_refs
                        }
                  )
                  : {};
                print "linkrefs: DECRYPTED ==>>>  " . Dumper( $lkrfs);
                search_stash( $lkrfs, $hkid_hex_hash{$hkid_hex});

        }

}



print "DB Operation done successfully\n";

$dbh->disconnect();

sub search_stash {
    my ( $lkrfs, $hkid_hex_hash_ref ) = @_;

    print "hkid_hex_hash_ref secrets PRINT " . Dumper($hkid_hex_hash_ref);
    #print "hkid_hex_hash_ref pdkargs PRINT " . Dumper($hkid_hex_hash_ref->{pdkargs});

    foreach my $key (keys %$lkrfs) {
        my $data = %$lkrfs{$key};
        print "data PRINT " . Dumper($data);
        my $link_data = JSON->new->utf8->decode($data);
        #print "link data PRINT " . Dumper($link_data);
        foreach my $link_key (keys %$link_data) {
            #print "LINK KEY $link_key \n";
            if ( $link_key eq 'stash_id' ) {
                print "stash_id PRINT " . %$link_data{$link_key} . "\n";

                my $stash_id_enc = pbkdf2(
                    $link_data->{stash_id},
                    pack( 'H*', $hkid_hex_hash_ref->{secrets}->{salt}->{stash} ),
                    $hkid_hex_hash_ref->{secrets}->{pdkargs}->{iters},
                    $hkid_hex_hash_ref->{secrets}->{pdkargs}->{hash},
                    $hkid_hex_hash_ref->{secrets}->{pdkargs}->{dklen}
                );

                #print "stash_id_enc $stash_id_enc\n";

                my $hexed_stash_id =  unpack("H*",$stash_id_enc);

                print "hexed stash_id as hexadecimal ==> ". $hexed_stash_id . "\n";

            }
        }
    }

}

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

sub cbc_decrypt_key {
        my ($data) = @_;

        #return dlr_cbc_decrypt_key($data);
        return self_cbc_decrypt_key($data);
};





