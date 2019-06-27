#!/usr/bin/perl

use strict;
use warnings;

use DBI;
use DBD::Pg qw(:pg_types);
use LWP;
use JSON;

use LWP::UserAgent;
use MIME::Base64;
use JSON::MaybeXS;
#use JSON;
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

my %pg_special_query_columns = (
	'id'	=> PG_BYTEA,
	'kid'	=> PG_BYTEA,
	'datum'	=> PG_BYTEA,
	'datum_id'	=> PG_BYTEA,
);
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
#my ( $keyrings, $hkid_hex_hash,
#     $keyring_krid_mapping,
#     $keyring_metadata ) = get_keyrings ( $dbh, $krids, $oauth_data, $resp_content, $input_timerange_span ); #get krid from keyring

#my $salty_kids = get_keyrings($dbh, $krids, $oauth_data, $resp_content, $tsr_start, $tsr_end);
my $salty_kids = get_keyrings($dbh, $krids, $oauth_data, $resp_content, $input_timerange_span );

#get_bundle_payload ( $dbh, $keyrings,$hkid_hex_hash,$keyring_krid_mapping,
#                                                         $keyring_metadata, $oauth_data, $resp_content );

get_bundle_payload ($dbh, $salty_kids, $oauth_data, $resp_content);

########################################################################
########################################################################
########################################################################

# START: add_bundles_for_keyrings()
# START: get_bundles_for_keyrings()
#my $max = 5000; ## max number of parameters for DBD::pg



# START: add_bundles_for_keyrings()
# START: get_bundles_for_keyrings()
#my $max = 5000; ## max number of parameters for DBD::pg
sub get_bundle_payload {

    my ($dbh, $salty_kids, $oauth_data, $resp_content) = @_;

    my $bundle_metadata_secrets={};
    my $bundle_payloads_secrets={};

    my $log = Log::Log4perl->get_logger();

    #my %keyring_krid_map = %{$keyring_krid_mapping};
    #my %keyring_md       = %{$keyring_metadata};


#write_dumper_to_file( "keyring_krid_mapping.txt", \%keyring_krid_map);

#write_dumper_to_file( "keyring_metadata.txt", \%keyring_md);

    my $max = 4096;
    #my $krids;
	foreach my $krids (spart($max, keys(%$salty_kids))) {

        print "keyring_keys_list " . Dumper( $krids);

        #print "krids type " . ref($krids) . "\n";
        

        my $sql = sprintf(q{
            SELECT krid, metadata, payload
            FROM bundle
            WHERE krid IN (%s)
        ;}, join(', ', ('?') x scalar(@$krids)));

        my $sth = $dbh->prepare($sql) or die;
        $sth->execute(@$krids);
        #$sth->execute();

        my $bundles = $sth->fetchall_hashref('krid');

        #print "DUMPING BUNDLES " . Dumper($bundles) . "\n SQL ". $sql . " JOIN " . join(', ', ('?') x scalar(@$krids)) . "\n";

        $bundle_metadata_secrets = %$bundles
                    ? rsa_decrypt( $oauth_data,
                                   $resp_content,
                                    {
                                        map {
                                                $_ => {
                                                    #mk_uuid => $keyring_md{$var}{'mk_uuid'},
                                                    mk_uuid => $salty_kids->{$_}{mk_uuid},
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

        $log->info("salty_kids are: " . Dumper($salty_kids) );
        #print "salty_kids are: " . Dumper($salty_kids);



        foreach my $krid ( @$krids ) {

            my %bundle_tables;
            my $kid;

            print "krid " . Dumper( $krid );
            my $bundle_tables = $bundle_payloads_secrets->{$krid}->{"tables"};
            print "bundle_metadata_tables " . Dumper($bundle_tables) . "\n";

=begin
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
=cut
            #search_bundle_search( $hkid_hex_hash, $kid, \%bundle_tables );
            search_bundle_search($salty_kids, $krid, $bundle_tables);

        } ## end foreach my $bundle (@$bundles)



    }

    #print "DUMPING BUNDLES ". Dumper (@$bundles) . "\n";

}

#print "hkid_hex_hash " . Dumper(\%hkid_hex_hash);

sub search_bundle_search {
	my ( $salty_kids, $krid, $bundle_tables ) = @_;

    my $log = Log::Log4perl->get_logger();

    my $bundle_search = %$bundle_tables{"search"};
    my $bundle_search_table = $dbh->quote_identifier( undef, "bundle_search", $bundle_search );

    my $search_stmt =  "SELECT
                            id,
                            kid,
                            datum
                        FROM
                            $bundle_search_table
                        WHERE
                            kid = ?";
    $dbh->begin_work or die $dbh->errstr;
	my $declare_sth = $dbh->prepare("DECLARE bundle_search_cursor NO SCROLL CURSOR WITHOUT HOLD FOR $search_stmt");
	foreach my $the_all_kid (keys(%{$salty_kids->{$krid}{kids}})) {
		$log->info("search: allkid: krid: $krid all_kid: " . Dumper($the_all_kid) . " dt kids: " . Dumper($salty_kids->{$krid}{kids}{$the_all_kid}) );
		foreach my $the_dt_kid (keys(%{$salty_kids->{$krid}{kids}{$the_all_kid}})) {
			$declare_sth->bind_param(1, $the_dt_kid, { 'pg_type' => PG_BYTEA } );
			$declare_sth->execute;

			my $sth = $dbh->prepare("FETCH 10000 FROM bundle_search_cursor");
            print("OPEN bundle_search_cursor\n");
			while (1) {
				$sth->execute();
				$log->info("search: dtkid:  krid: $krid" . " rows: " .  $sth->rows);
                print("\nsearch: dtkid:  krid: $krid " . " rows: " .  $sth->rows);

				last if $sth->rows == 0;
				my $search_hash_refs = $sth->fetchall_hashref('id');
				#print "search_hash_refs ". Dumper($search_hash_refs);   ### search_hash_refs in binary

				my $secretcount=0;
				my $search_refs = %$search_hash_refs ?
					cbc_decrypt_key({
						map {
							my $id = $search_hash_refs->{$_}->{"id"};

							#unless (++$secretcount%($sqlfetch/10)) {
								#$log->info("searchkeys: metaed $secretcount searchables");
							#};
							$id => {
								data => $id,
								key  => $salty_kids->{$krid}{kids}{$the_all_kid}{$the_dt_kid}->{'search_id'},
								#flip_hash_keyval => 1, # AP: 20190611: we use this in place of data elsewhere
							}; # encrypted search.id => decrypted search.id
						} keys %$search_hash_refs
					}) : {};

				#print "search_refs ". Dumper($search_refs);

				write_dumper_to_file( "bundle_search.txt", $search_refs);

				#search_bundle_link($salty_kids, $search_refs, $krid, $the_all_kid, $the_dt_kid, $bundle_tables, $nuke_search_rows, $keep_search_rows);
				search_bundle_link($salty_kids, $search_refs, $krid, $the_all_kid, $the_dt_kid, $bundle_tables);
				# XXX: debug
				#$sth->finish; last;
				#if ($bailonnukecount && $nukecount > $nukemax) { last; }
			}
			$dbh->do("CLOSE bundle_search_cursor");
            print("CLOSE bundle_search_cursor\n");
            $dbh->rollback or die $dbh->errstr;  #OR #$dbh->commit;
			#if ($bailonnukecount && $nukecount > $nukemax) { last; }
		}
	}
	#my @nukeables = grep { !exists $keep_search_rows->{$_} } keys(%$nuke_search_rows);
	#pdebug("counts: keep_search_rows, nuke_search_rows, nukeables: %d %d %d", scalar(keys(%$keep_search_rows)), scalar(keys(%$nuke_search_rows)), scalar(@nukeables));
	#pdebug("nukeables: ", mlnp(@nukeables)_);
	#print("CLOSE bundle_search_cursor_$$\n");
	#$log->info("CLOSE bundle_search_cursor_$$");
}



sub search_bundle_link {
        #my ( $hkid_hex_hash, $uuid, $hkid_hex, $bundle_tables ) = @_;
        my ($salty_kids, $search_refs, $krid, $the_all_kid, $the_dt_kid, $bundle_tables) = @_;
        my $log = Log::Log4perl->get_logger();

        my $the_salty_kid = $salty_kids->{$krid}{kids}{$the_all_kid}{$the_dt_kid};
        my $salt_link = $the_salty_kid->{'secrets'}->{'salt'}->{'link'};
        my $link_ids  = $the_salty_kid->{'secrets'}->{'skeys'}->{'link_ids'};
	    my $salt_link_bin = pack('H*', $salt_link);
        ###################print "plaintext uuid ". $uuid . "\n";
        ###################print "hkid_hex_hash link table salt " . $salt_link . "\n";
        ###################print "hkid_hex_hash linkids " . $link_ids . "\n";
        my $max = 4096;
        foreach my $searchids_enc (spart($max, keys %$search_refs)) { #
            my %datumids;
            foreach my $searchid_enc (@$searchids_enc) {
                my $datumid = pbkdf2(
                    $search_refs->{$searchid_enc},
                    $salt_link_bin,
                    $the_salty_kid->{'secrets'}->{'pdkargs'}->{'iters'},
                    $the_salty_kid->{'secrets'}->{'pdkargs'}->{'hash'},
                    $the_salty_kid->{'secrets'}->{'pdkargs'}->{'dklen'}
                );
                #$datumids{$datumid} = $search_refs->{$searchid}; # AP: 20160911: this gives us the db value of search.id
                $datumids{$datumid} = $searchid_enc; # link salted search.id => search salted search.id
            };

            my $bundle_link = %$bundle_tables{"link"};
            my $bundle_link_table = $dbh->quote_identifier( undef, "bundle_link", $bundle_link );

            my $query_column = 'datum_id';
            my $sql = sprintf(q{
                SELECT datum_id, ids
                FROM %s
                WHERE %s IN (%s)
            ;},
                $bundle_link_table,
                $query_column,
                join(',', ('?') x keys(%datumids))
            );

            my $sth = $dbh->prepare("DECLARE bundle_link_cursor NO SCROLL CURSOR WITHOUT HOLD FOR $sql");
            print("OPEN bundle_link_cursor\n");
            my $cnt = 1;
            foreach my $data (keys(%datumids)) {
                if ($pg_special_query_columns{$query_column}) {
                    $sth->bind_param($cnt++, $data, { 'pg_type' => $pg_special_query_columns{$query_column} });
                } else {
                    $sth->bind_param($cnt++, $data);
                }
            };
            $sth->execute;
            $sth = $dbh->prepare("FETCH 10000 FROM bundle_link_cursor;");

            my $fetchcnt = 0;
            while (1) {
                $sth->execute;

                $log->info("link: krid: $krid " . " rows:" . $sth->rows);
                #########################print("    link: krid: $krid " . " rows:" . $sth->rows ."\n");

                # XXX: debug 
                #$sth->finish; last
                last if ($sth->rows == 0);
                my $fetched = $sth->rows;
                $fetchcnt += $fetched;
                #$log->info("link: fetched " . $fetchcnt . " links");
                #printf("    link: fetched %s links", $fetchcnt);

                #my $links_enc = $sth->fetchall_hashref( 'datum_id' );
                my $links_enc = $sth->fetchall_arrayref({});
                #pdebug("link: links_enc: %s", mlnp($links_enc));

                my $secretcount=0;
                #my $links_dec = %$links_enc
                my $links_dec = @$links_enc
                    ? cbc_decrypt_array( [
                        map {
                            #my $ids = $links_enc->{$_}->{'ids'};
                            my $ids = $_->{'ids'};
                            #unless (++$secretcount%($sqlfetch/10)) {
                            #    $log->info("linkkeys: metaed %s links", $secretcount);
                            #};
                            {
                                data_enc => $ids,
                                key      => $link_ids,
                                extra    => { datum_id => $_->{'datum_id'} },
                            }
                        #} keys %$links_enc
                        } @$links_enc
                    ]) : [];
                ################print("link: links_dec: ". Dumper($links_dec));

                my $stashcnt = 0;
                write_dumper_to_file( "salty_kid.txt", $the_salty_kid);
                #filter_links_and_nuke_prep($the_salty_kid, $the_dt_kid, $links_dec, $search_refs, \%datumids, $bundle_tables, $nuke_search_rows, $keep_search_rows);
                #filter_links_and_nuke_prep($the_salty_kid, $the_dt_kid, $links_dec, \%datumids, $bundle_tables, $fetched);
                search_stash_brick( $the_salty_kid, $the_dt_kid, $links_dec, $input_timerange_span, $bundle_tables );
                #if ($bailonnukecount && $nukecount > $nukemax) { last; }
            }
            $dbh->do("CLOSE bundle_link_cursor");
            print "CLOSE bundle_link_cursor\n";
            #if ($bailonnukecount && $nukecount > $nukemax) { last; }
        }
}

=begin comment




=end comment

=cut

#############################################################################################
#############################################################################################
#############################################################################################

_db_disconnect($dbh);

sub search_stash_brick {
    #my ( $datum_id, $lkrfs, $hkid_hex_hash_ref, $input_timerange_span, $bundle_tables ) = @_;

    my ( $the_salty_kid, $the_dt_kid, $links_dec, $input_timerange_span, $bundle_tables ) = @_;

    my $log = Log::Log4perl->get_logger();
    #print "hkid_hex_hash_ref secrets PRINT " . Dumper($hkid_hex_hash_ref);
    #print "hkid_hex_hash_ref pdkargs PRINT " . Dumper($hkid_hex_hash_ref->{pdkargs});

    #foreach my $key (keys %$links_dec) {
    foreach my $link_dec (@$links_dec) {

        #print "GLOBAL_ALLOWED_DATATYPES " . Dumper \%GLOBAL_ALLOWED_DATA_TYPES;
        my $GLOBAL_ALLOWED_DATA_TYPES = \%GLOBAL_ALLOWED_DATA_TYPES;

        my $data = %$link_dec{'data_dec'};
        #################print "data PRINT " . Dumper($data);
        #my $link_data = JSON->new->utf8->decode($data);
        my $link_data = newjson()->decode($data);
        #################print "data PRINT " . Dumper($link_data);


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

        my $stash_id_enc;
        my $bundle_stash = %$bundle_tables{"stash"};
        my $bundle_brick = %$bundle_tables{"brick"};

        if ( exists $link_data->{'stash_id'} ) {
            #print "stash_id PRINT " . %$link_data{$link_key} . "\n";

            $stash_id_enc = pbkdf2(
                $link_data->{stash_id},
                pack( 'H*', $the_salty_kid->{'secrets'}->{'salt'}->{'stash'} ),
                $the_salty_kid->{'secrets'}->{'pdkargs'}->{'iters'},
                $the_salty_kid->{'secrets'}->{'pdkargs'}->{'hash'},
                $the_salty_kid->{'secrets'}->{'pdkargs'}->{'dklen'}                    
            );
        }

        if ( $input_timerange_span->contains( $end_dt ) &&
             #$input_timerange_span->contains( $start_dt ) &&
             exists ( $GLOBAL_ALLOWED_DATA_TYPES{ $link_data->{dt} } ) ) {

            $log->info("TIMERANGE CONSTRAINT satisfied DATATYPE CONSTRAINT satisfied " . $link_data->{dt} . " ==>> GOOD TO GO");
            $log->info("DATATYPE " . $link_data->{dt} . " EXISTS. link table contains " . Dumper $GLOBAL_ALLOWED_DATA_TYPES{ $link_data->{dt} } );

            #print "link data PRINT " . Dumper($link_data);
            

            if ( exists $link_data->{'stash_id'} ) {
                #print "stash_id PRINT " . %$link_data{$link_key} . "\n";

                #print "stash_id_enc $stash_id_enc\n";

                my $hexed_stash_id =  unpack("H*",$stash_id_enc);

                my $bundle_stash_table = $dbh->quote_identifier( undef, "bundle_stash", $bundle_stash );

                #print "hexed stash_id as hexadecimal ==> ". $hexed_stash_id . "\n";
                $log->info("hexed stash_id as hexadecimal ==> $hexed_stash_id $bundle_stash_table");

                $log->info("TESTING query ==>>>  select * from bundle_stash.$bundle_stash where encode(id,'hex') = '$hexed_stash_id'; ");

                my $sth = $dbh->prepare("INSERT INTO flush_datum_id(datum_id) VALUES (?)") or warn $DBI::errstr;
                $sth->bind_param( 1, $stash_id_enc, { 'pg_type' => PG_BYTEA } );
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
                my $sth = $dbh->prepare("INSERT INTO retain_datum_id(datum_id) VALUES (?)") or warn $DBI::errstr;
                $sth->bind_param( 1, $stash_id_enc, { 'pg_type' => PG_BYTEA } );
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
                        pack( 'H*', $the_salty_kid->{secrets}->{salt}->{brick} ),
                        $the_salty_kid->{secrets}->{pdkargs}->{iters},
                        $the_salty_kid->{secrets}->{pdkargs}->{hash},
                        $the_salty_kid->{secrets}->{pdkargs}->{dklen}
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
