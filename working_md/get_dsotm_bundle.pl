#!/usr/bin/perl

use strict;
use warnings;

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
use Log::Log4perl;

use Crypt::Mode::CBC;
#use Crypt::PBKDF2;
use Crypt::KeyDerivation qw(pbkdf2);

use DateTime::Infinite;
use DateTime::Span;
use DateTime::Format::Pg;
use DateTime::Format::Strptime;
use List::NSect qw(spart);
use List::Util qw(uniq uniqstr any all sum0);

use Getopt::Long qw(GetOptions);
use Pod::Usage qw(pod2usage);
use Readonly;

use lib './';
use lib::Utils;
################################################################################################
#my( $lower_tstz_range, $upper_tstz_range,$help );


GetOptions(
    'lower|l=s'  => \my $lower_tstz_range,
    'upper|u=s'  => \my $upper_tstz_range,
    'help'       => \my $help,
) or pod2usage( "Try '$0 --help' for more information." );

print "SELECTED option help\n" if $help;
pod2usage( -verbose => 1 ) if $help;


# die unless we got the mandatory argument
#if ($lower_tstz_range ) {
pod2usage(1) unless ($upper_tstz_range && $lower_tstz_range);


################################################################################################

_log_init();

################################################################################################


my $dbh = _db_connect();
#################################################################################


my $stash_linkrefs = {};
my $bndl_links_dtype = {};

my ( $oauth_data, $resp_content  ) = _get_response_token();
my $user_jwt = $resp_content->{jwt};

my $tsr_start = DateTime::Format::Pg->parse_timestamp_with_time_zone( $lower_tstz_range  );
my $tsr_end   = DateTime::Format::Pg->parse_timestamp_with_time_zone( $upper_tstz_range );

my $input_timerange_span = DateTime::Span->from_datetimes( start => $tsr_start, end => $tsr_end );

my $krids = get_krids ( $dbh, $lower_tstz_range, $upper_tstz_range, $oauth_data, $resp_content );   #get krids from dsotm

#   my $user_jwt = $resp_content->{jwt};

#my $keyrings = get_keyrings ( $dbh, $krids, $oauth_data, $resp_content );
my ( $keyrings, $hkid_hex_hash,
     $keyring_krid_mapping,
     $keyring_metadata ) = get_keyrings ( $dbh, $krids, $oauth_data, $resp_content, $input_timerange_span ); #get krid from keyring

my $bundle_payloads_secrets = get_bundle_payload ( $dbh, $keyrings,$hkid_hex_hash,$keyring_krid_mapping,
                                                         $keyring_metadata, $oauth_data, $resp_content );



########################################################################
########################################################################
########################################################################

# START: add_bundles_for_keyrings()
# START: get_bundles_for_keyrings()
#my $max = 5000; ## max number of parameters for DBD::pg
sub get_bundle_payload {

    my ( $dbh, $keyrings,$hkid_hex_hash, $keyring_krid_mapping,
                $keyring_metadata, $oauth_data, $resp_content ) = @_;

    my $bundle_metadata_secrets={};
    my $bundle_payloads_secrets={};

    #my %keyring_krid_map = %{$keyring_krid_mapping};
    #my %keyring_md       = %{$keyring_metadata};


#write_dumper_to_file( "keyring_krid_mapping.txt", \%keyring_krid_map);

#write_dumper_to_file( "keyring_metadata.txt", \%keyring_md);

    my $max = 65535;
    foreach my $keyring_keys_list (
            spart(
                    $max,
                    #uniqstr map { $_->{krid} } ( @{$keyrings->{selves}} )
                    map { $_->{krid} } ( @{$keyrings->{selves}} )
            )
    ) {

        print "keyring_keys_list " . Dumper(@$keyring_keys_list);

        my $sql = sprintf(q{
            SELECT krid, metadata, payload
            FROM bundle
            WHERE krid IN (%s)
        ;}, join(', ', ('?') x scalar(@$keyring_keys_list)));

        my $sth = $dbh->prepare($sql) or die;
        $sth->execute(@$keyring_keys_list);
        #$sth->execute();

        my $bundles = $sth->fetchall_hashref('krid');

        #print "DUMPING BUNDLES " . Dumper($bundles) . "\n SQL ". $sql . " JOIN " . join(', ', ('?') x scalar(@$keyring_keys_list)) . "\n";

        $bundle_metadata_secrets = %$bundles
                    ? rsa_decrypt( $oauth_data,
                                   $resp_content,
                                    {
                                        map {
                                                $_ => {
                                                    #mk_uuid => $keyring_md{$var}{'mk_uuid'},
                                                    mk_uuid => $keyring_metadata->{$keyring_krid_mapping->{$_}}->{mk_uuid},
                                                    data    => %$bundles{$_}->{"metadata"}
                                                }
                                        } keys %$bundles
                            }
                    )
                    : {};
        #print "bundle_metadata_secrets " . Dumper($bundle_metadata_secrets) . "\n";
        #write_dumper_to_file( "bundle_metadata_secrets.txt", $bundle_metadata_secrets);

        $bundle_payloads_secrets = %$bundles
                    ? cbc_decrypt_md($oauth_data,
                                    $resp_content,
                                        {
                                            map {
                                                    $_ => {
                                                            data     => %$bundles{$_}->{"payload"},
                                                            metadata => $bundle_metadata_secrets->{$_}
                                                        }
                                            } keys %$bundles
                                        }
                                ) : {};

        #print "bundle_payloads_secrets " . Dumper($bundle_payloads_secrets) . "\n";
        #write_dumper_to_file( "bundle_payloads_secrets.txt", $bundle_payloads_secrets);

        #return $bundle_payloads_secrets

    }



	foreach my $krid ( keys %$bundle_payloads_secrets) {

        my %bundle_tables;
        my $kid;

        foreach my $keyring ( @{ $keyrings->{'selves'} } ) {
            if ( $keyring->{'krid'} eq $krid ) {

                $bundle_tables{"search"} = %$bundle_payloads_secrets{$krid}->{"tables"}->{"search"};
                $bundle_tables{"link"}   = %$bundle_payloads_secrets{$krid}->{"tables"}->{"link"};
                $bundle_tables{"stash"}  = %$bundle_payloads_secrets{$krid}->{"tables"}->{"stash"};
                $bundle_tables{"brick"}  = %$bundle_payloads_secrets{$krid}->{"tables"}->{"brick"};

                #
                print "krid in bundle_payload_secrets $krid\n";
                print "bundle search table bundle_search.".$bundle_tables{"search"}."\n";
                print "bundle link   table bundle_link.".$bundle_tables{"link"}."\n";
                print "bundle stash  table bundle_stash.".$bundle_tables{"stash"}."\n";
                print "bundle brick  table bundle_brick.".$bundle_tables{"brick"}."\n";
                #
                #print "keyring krid:           $keyring->{'krid'}\n";
                #print "keyring plaintext kid:  $keyring->{'kid'}\n";
                #print "keyring hkid:           $keyring->{'hkid'}\n";

                $kid = $keyring->{'kid'};
            }
        }
        search_bundle_search( $hkid_hex_hash, $kid, \%bundle_tables );

	} ## end foreach my $bundle (@$bundles)
    #print "DUMPING BUNDLES ". Dumper (@$bundles) . "\n";

}

#print "hkid_hex_hash " . Dumper(\%hkid_hex_hash);

sub search_bundle_search {
    my ( $hkid_hex_hash, $kid, $bundle_tables ) = @_;
    #my $log = Log::Log4perl->get_logger("My::MegaPackage");
    my $log = Log::Log4perl->get_logger();

    my @hkid_hex = grep { $hkid_hex_hash->{$_}->{"secrets"}->{"kid"} eq $kid } keys %{$hkid_hex_hash};
    #my $var = $hkid_hex[0];

    $log->info( "Array hkid_hex is  =>>>  " . Dumper( \@hkid_hex ) );
    #$log->info( "hkid_hex[0] is ==>>>  " . $var );

    my $search_id = $hkid_hex_hash->{$hkid_hex[0]}->{'searchId'};
    #print "hkid_hex ". Dumper( \@hkid_hex ) ."\n";
    #print "hkid_hex ZERO ". $hkid_hex[0] ."\n";

    my $bundle_search = %$bundle_tables{"search"};
    my $bundle_search_table = $dbh->quote_identifier( undef, "bundle_search", $bundle_search );
    #print "bundle_search_table is $bundle_search_table";
    #my $search_stmt = "SELECT id, kid, datum FROM $bundle_search_table WHERE encode(kid,\'hex\') = ?";

    my $search_stmt =  "SELECT
                            id,
                            kid,
                            datum
                        FROM
                            $bundle_search_table
                        WHERE
                            kid = ?";

    my $sth;
    $dbh->begin_work or die $dbh->errstr;
    $sth = $dbh->prepare("DECLARE bundle_search_cursor NO SCROLL CURSOR WITHOUT HOLD FOR $search_stmt") or die;
    $sth->bind_param( 1, $hkid_hex[0] , { 'pg_type' => PG_BYTEA } );
    $sth->execute;


    while (1) {
        $sth = $dbh->prepare("FETCH 10000 FROM bundle_search_cursor");
        $sth->execute;


        last if $sth->rows == 0;
        my $search_hash_refs = $sth->fetchall_hashref( 'id' );
        print "Rows fetched for kid $kid COUNT " . $sth->rows ."\n";
        $log->info("Rows fetched for kid $kid COUNT " . $sth->rows);
        #print "search_hash_refs ". Dumper($search_hash_refs);   ### search_hash_refs in binary

        my $search_refs = %$search_hash_refs ?
                        cbc_decrypt_key({
                                            map {
                                                    my $id = %$search_hash_refs{$_}->{"id"};

                                                    unpack( "H*", $id ) => {
                                                            data => $id,
                                                            key  => $search_id
                                                    }
                                            } keys %$search_hash_refs
                                        }) : {};

        #print "search_refs ". Dumper($search_refs);

        #write_dumper_to_file( "bundle_search.txt", $search_refs);

        #print "DUMPING secrets salt links  ". $hkid_hex_hash{$hkid_hex[0]}{'secrets'}{'salt'}{'link'} . "\n";

        foreach my $hkid_hex_01 (keys %$search_refs)
        {
            my $uuid = %$search_refs{$hkid_hex_01};
            search_bundle_link( $hkid_hex_hash, $uuid, $hkid_hex[0], $bundle_tables );
        }

    }
    $dbh->do("CLOSE bundle_search_cursor");
    print("CLOSE bundle_search_cursor\n");
    $log->info("CLOSE bundle_search_cursor");
    #$dbh->rollback or die $dbh->errstr;   #OR #$dbh->commit;
    $dbh->commit or die $dbh->errstr;   #OR #$dbh->commit;
    $log->info("ROLLBACK postgres transaction");
}

sub search_bundle_link {
        my ( $hkid_hex_hash, $uuid, $hkid_hex, $bundle_tables ) = @_;
        my $log = Log::Log4perl->get_logger();

        my $salt_link = $hkid_hex_hash->{$hkid_hex}->{'secrets'}->{'salt'}->{'link'};
        my $link_ids  = $hkid_hex_hash->{$hkid_hex}->{'secrets'}->{'skeys'}->{'link_ids'};

        ###################print "plaintext uuid ". $uuid . "\n";
        ###################print "hkid_hex_hash link table salt " . $salt_link . "\n";
        ###################print "hkid_hex_hash linkids " . $link_ids . "\n";

        my $datum_id = pbkdf2(
            $uuid,
            pack( 'H*', $salt_link ),
            $hkid_hex_hash->{$hkid_hex}->{'secrets'}->{'pdkargs'}->{'iters'},
            $hkid_hex_hash->{$hkid_hex}->{'secrets'}->{'pdkargs'}->{'hash'},
            $hkid_hex_hash->{$hkid_hex}->{'secrets'}->{'pdkargs'}->{'dklen'}
        );
        ###################print "pbkdf2 hashed uuid ". $datum_id . "\n";

        my $hashed_uuid =  unpack("H*",$datum_id);  # output hashed datum_id as hexadecimal

        ###################print "hashed uuid as hexadecimal ==> ". $hashed_uuid . "\n";

        my $bundle_link = %$bundle_tables{"link"};
        my $bundle_link_table = $dbh->quote_identifier( undef, "bundle_link", $bundle_link );

        my $sql = "SELECT
                        datum_id,
                        ids
                   FROM
                        $bundle_link_table
                   WHERE
                        datum_id = ?";

        #$dbh->begin_work or die $dbh->errstr;
        my $sth = $dbh->prepare("DECLARE bundle_link_cursor NO SCROLL CURSOR WITHOUT HOLD FOR $sql") or die;
        $sth->bind_param( 1, $datum_id, { 'pg_type' => PG_BYTEA } );
        $sth->execute;



        #my $sth = $dbh->prepare($sql) or die;

        while (1) {
            $sth = $dbh->prepare("FETCH 10000 FROM bundle_link_cursor");
            $sth->execute;


            last if $sth->rows == 0;
            my $link_hash_refs = $sth->fetchall_hashref( 'datum_id' );
            #print "Rows fetched from $bundle_link_table for datum_id $hashed_uuid COUNT " . $sth->rows ."\n";
            $log->info("Rows fetched from $bundle_link_table for datum_id $hashed_uuid COUNT " . $sth->rows);
            #print "search_hash_refs ". Dumper($search_hash_refs);   ### search_hash_refs in binary

            my $link_refs = %$link_hash_refs
                    ? cbc_decrypt_key( {
                            map {
                                    my $ids = %$link_hash_refs{$_}->{'ids'};
                                    unpack( "H*", $ids ) => {
                                            data => $ids,
                                            key  => $link_ids,
                                    }
                            } keys %$link_hash_refs
                    }) : {};

            #print "search_refs ". Dumper($search_refs);

            #write_dumper_to_file( "bundle_search.txt", $search_refs);
            $log->info("$bundle_link_table LINK REFS " . Dumper($link_refs) );

            #print "DUMPING secrets salt links  ". $hkid_hex_hash{$hkid_hex[0]}{'secrets'}{'salt'}{'link'} . "\n";

            foreach my $hkid_hex_01 (keys %$link_refs)
            {
                my $uuid = %$link_refs{$hkid_hex_01};

                #print "plaintext uuid ". $uuid . "\n";
                #print "hkid_hex_hash link table salt " . $salt_link . "\n";

                search_stash_brick( $datum_id, $link_refs, $hkid_hex_hash->{$hkid_hex}, $input_timerange_span, $bundle_tables );  #Is searching in search_stash needed????

                #search_brick( $link_refs, $hkid_hex_hash->{$hkid_hex}, $input_timerange_span, $bundle_tables );  #Is searching in search_stash needed????

            }

        }
        $dbh->do("CLOSE bundle_link_cursor");
        #$dbh->rollback or die $dbh->errstr;  #OR #$dbh->commit;
        #$dbh->commit or die $dbh->errstr;  #OR #$dbh->rollback;


}
#############################################################################################
#############################################################################################
#############################################################################################

_db_disconnect($dbh);

sub search_stash_brick {
    my ( $datum_id, $lkrfs, $hkid_hex_hash_ref, $input_timerange_span, $bundle_tables ) = @_;

    my $log = Log::Log4perl->get_logger();
    #print "hkid_hex_hash_ref secrets PRINT " . Dumper($hkid_hex_hash_ref);
    #print "hkid_hex_hash_ref pdkargs PRINT " . Dumper($hkid_hex_hash_ref->{pdkargs});

    foreach my $key (keys %$lkrfs) {

        #print "GLOBAL_ALLOWED_DATATYPES " . Dumper \%GLOBAL_ALLOWED_DATA_TYPES;
        my $GLOBAL_ALLOWED_DATA_TYPES = \%GLOBAL_ALLOWED_DATA_TYPES;

        my $data = %$lkrfs{$key};
        #print "data PRINT " . Dumper($data);
        my $link_data = JSON->new->utf8->decode($data);
        $log->info( "link data PRINT " . Dumper($link_data) );

        $log->info( "link data ts start " .  $link_data->{ts}->{start} );
        $log->info( "link data ts end " .    $link_data->{ts}->{end} );
        $log->info( "link data data-type " . $link_data->{dt} );

        my $strp = DateTime::Format::Strptime->new(
                pattern   => '%FT%T%z',
            );

        my $start_dt = $strp->parse_datetime( $link_data->{ts}->{start} );
        my $end_dt   = $strp->parse_datetime( $link_data->{ts}->{end} );

        #my $timerange_span = DateTime::Span->from_datetimes( start => $start_dt, end => $end_dt );
        #$log->info("DATATYPE " . $link_data->{dt} . " EXISTS. link table contains " . Dumper $GLOBAL_ALLOWED_DATA_TYPES{ $link_data->{dt} } );


        my $bundle_stash = %$bundle_tables{"stash"};
        my $bundle_brick = %$bundle_tables{"brick"};
        my $bundle_stash_table = $dbh->quote_identifier( undef, "bundle_stash", $bundle_stash );
        my $stash_id_enc;

        if ( $input_timerange_span->contains( $end_dt ) &&
             exists ( $GLOBAL_ALLOWED_DATA_TYPES{ $link_data->{dt} } ) ) {
            $log->info("TIMERANGE CONSTRAINT satisfied DATATYPE CONSTRAINT satisfied " . $link_data->{dt} . " ==>> GOOD TO GO");
            $log->info("DATATYPE " . $link_data->{dt} . " EXISTS. link table contains " . Dumper $GLOBAL_ALLOWED_DATA_TYPES{ $link_data->{dt} } );


            #print "link data PRINT " . Dumper($link_data);

            if ( exists $link_data->{'stash_id'} ) {
                #print "stash_id PRINT " . %$link_data{$link_key} . "\n";

                $stash_id_enc = pbkdf2(
                    $link_data->{stash_id},
                    pack( 'H*', $hkid_hex_hash_ref->{secrets}->{salt}->{stash} ),
                    $hkid_hex_hash_ref->{secrets}->{pdkargs}->{iters},
                    $hkid_hex_hash_ref->{secrets}->{pdkargs}->{hash},
                    $hkid_hex_hash_ref->{secrets}->{pdkargs}->{dklen}
                );

                #print "stash_id_enc $stash_id_enc\n";

                my $hexed_stash_id =  unpack("H*",$stash_id_enc);                

                #print "hexed stash_id as hexadecimal ==> ". $hexed_stash_id . "\n";
                $log->info("hexed stash_id as hexadecimal ==> $hexed_stash_id $bundle_stash_table");

                $log->info("TESTING query ==>>>  select * from bundle_stash.$bundle_stash where encode(id,'hex') = '$hexed_stash_id'; ");

                my $sth = $dbh->prepare("INSERT INTO flush_datum_id(datum_id,table_name) VALUES (?,?)") or warn $DBI::errstr;
                $sth->bind_param( 1, $stash_id_enc, { 'pg_type' => PG_BYTEA } );
                $sth->bind_param( 2, $bundle_stash_table );
                $sth->execute();
                $sth->finish();

            }
        }
        if ( !exists ( $GLOBAL_ALLOWED_DATA_TYPES{ $link_data->{dt} } ) ) {
            $log->info("DATATYPE " . $link_data->{dt} . " ==>> DONT DELETE");
            $log->info("EXCLUDE DATATYPE " . $link_data->{dt} . " NOT IN GLOBAL_ALLOWED_DATA_TYPES");
                #my $sth = $dbh->prepare("INSERT INTO flush_datum_id(datum_id) VALUES (?)");                
                #$sth->bind_param( 1, $datum_id, { 'pg_type' => PG_BYTEA } );
                #$sth->execute();
                my $sth = $dbh->prepare("INSERT INTO retain_datum_id(datum_id,table_name) VALUES (?,?)") or warn $DBI::errstr;
                $sth->bind_param( 1, $stash_id_enc, { 'pg_type' => PG_BYTEA } );
                $sth->bind_param( 2, $bundle_stash_table );
                $sth->execute();
                $sth->finish();
        }


        if ( $input_timerange_span->contains( $end_dt ) &&
             exists ( $GLOBAL_ALLOWED_DATA_TYPES{ $link_data->{dt} } ) ) {
            $log->info("TIMERANGE CONSTRAINT satisfied DATATYPE CONSTRAINT satisfied " . $link_data->{dt} . " ==>> GOOD TO GO");
            $log->info("DATATYPE " . $link_data->{dt} . " EXISTS. link table contains " . Dumper $GLOBAL_ALLOWED_DATA_TYPES{ $link_data->{dt} } );

            if ( exists $link_data->{'brick_ids'} ) {
                #print "stash_id PRINT " . %$link_data{$link_key} . "\n";
                #print "brick ids PRINT " . Dumper( %$link_data{$link_key} ) . "\n";

                foreach my $brick_id ( @{ %$link_data{'brick_ids'} } ) {
                    #print "brick id $brick_id \n";

                    my $brick_id_enc = pbkdf2(
                        $link_data->{stash_id}."/".$brick_id,
                        pack( 'H*', $hkid_hex_hash_ref->{secrets}->{salt}->{brick} ),
                        $hkid_hex_hash_ref->{secrets}->{pdkargs}->{iters},
                        $hkid_hex_hash_ref->{secrets}->{pdkargs}->{hash},
                        $hkid_hex_hash_ref->{secrets}->{pdkargs}->{dklen}
                    );

                    #print "brick_id_enc $brick_id_enc\n";

                    my $hexed_brick_id =  unpack("H*",$brick_id_enc);

                    my $bundle_brick_table = $dbh->quote_identifier( undef, "bundle_brick", $bundle_brick );

                    #print "hexed stash_id as hexadecimal ==> ". $hexed_brick_id . "\n";
                    $log->info("hexed_brick_id as hexadecimal ==> $hexed_brick_id $bundle_brick_table");

                    $log->info("TESTING query ==>>>  select id from bundle_brick.$bundle_brick where encode(id,'hex') = '$hexed_brick_id'; ");

                }
            }
        }

    }

}


=head1 NAME

MD::Flush - Delete records from mdstash.stash.

=head1 SYNOPSIS


  --lower,-l    Fetch JSON record based on keyword
  --upper,-u    Create JSON record as per input.
  --help,-h     Print this help

  Example run:

  ./get_dsotm_bundle.pl --lower '2019-05-09 05:00:00+10' --upper '2019-05-09 07:59:58+10'

  ./get_dsotm_bundle.pl --help

=head1 OPTIONS

=over 4

=item B<-help>

Print a brief help message and exits.

=item B<-man>

Prints the manual page and exits.

=back

=head1 DESCRIPTION

B<This program> will read the given input parameters/dates and do something
useful with the contents thereof.

=cut