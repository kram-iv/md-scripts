#!/usr/bin/perl

use v5.28;
use strict;
use warnings FATAL => qw(uninitialized);

use DBI;
use DBD::Pg qw(:pg_types);
#use LWP;

#use LWP::UserAgent;
#use MIME::Base64;
#use Data::Dumper;
use Data::Printer;
#use MIME::Base64;
use DateTime;
#use Log::Log4perl;

#use Crypt::Mode::CBC;
#use Crypt::PBKDF2;
use Crypt::KeyDerivation qw(pbkdf2);

use DateTime::Infinite;
#use DateTime::Span;
use DateTime::Format::Pg;
use DateTime::Format::Strptime;
use List::NSect qw(spart);
use List::Util qw(uniq uniqstr any all sum0);

use Getopt::Long qw(GetOptions);
use Pod::Usage qw(pod2usage);
use Readonly;

use lib './';
use lib::Utils;

my $bailonnukecount = 0;
my $nukecount = 0;
my $nukemax = 50;

################################################################################################
#my( $lower_tstz_range, $upper_tstz_range,$help );


GetOptions(
	'lower|l=s'  => \my $opt_lower_tstz_range,
	'upper|u=s'  => \my $opt_upper_tstz_range,
	'parallelkl|p'  => \my $opt_parallelkridlist,
	'krid|k=s'  => \my $opt_kridsd,
	'help'       => \my $help,
) or pod2usage( "Try '$0 --help' for more information." );

print "SELECTED option help\n" if $help;
pod2usage( -verbose => 1 ) if $help;


# die unless we got the mandatory argument
#if ($lower_tstz_range ) {
perror "upper ts range required" unless $opt_upper_tstz_range;
perror "lower ts range required" unless $opt_lower_tstz_range; # XXX: AP: 20160918: for testing anyway
perror "can't specify a krid with a request for krids" if $opt_kridsd && $opt_parallelkridlist;
pod2usage(1) unless ($opt_upper_tstz_range && $opt_lower_tstz_range);


################################################################################################

#_log_init();

################################################################################################

my $dbh = _db_connect();

#################################################################################

my $json = newjson();

my %pg_special_query_columns = (
	'id'	=> PG_BYTEA,
	'kid'	=> PG_BYTEA,
	'datum'	=> PG_BYTEA,
	'datum_id'	=> PG_BYTEA,
);
my $sqlfetch = 1_000;

my $tsr_start_dt = DateTime::Format::Pg->parse_timestamp_with_time_zone( $opt_lower_tstz_range  );
my $tsr_end_dt   = DateTime::Format::Pg->parse_timestamp_with_time_zone( $opt_upper_tstz_range );

# evil kludge - strip out the timezone for string matching in link table
#my $tsr_start = DateTime::Format::Strptime->format_datetime("%F %T", $tsr_start_dt);
#my $tsr_end   = DateTime::Format::Strptime->format_datetime("%F %T", $tsr_end_dt);
my $tsr_fmt = DateTime::Format::Strptime->new(pattern => '%FT%T'); # RFC3339 less TZ
my $tsr_start = $tsr_fmt->format_datetime($tsr_start_dt);
my $tsr_end   = $tsr_fmt->format_datetime($tsr_end_dt);
pdebug("start/lower dt:        $opt_lower_tstz_range -> $tsr_start");
pdebug("end/upper dt:          $opt_upper_tstz_range -> $tsr_end");
pdebug("krid list requested:   ".($opt_parallelkridlist//'unset'));
pdebug("krid to s&d:           ".($opt_kridsd//'unset'));

my ($oauth_data, $resp_content) = _get_response_token();
#my $user_jwt = $resp_content->{jwt};

# returns hash with key krid and values: krid, timerange and mk_uuid
my $krids = get_krids($dbh, $tsr_start_dt, $tsr_end_dt, $oauth_data, $resp_content);   #get krids from dsotm

#   my $user_jwt = $resp_content->{jwt};

my $salty_kids = get_keyrings($dbh, $krids, $oauth_data, $resp_content, $tsr_start_dt, $tsr_end_dt);

get_bundle_payload($dbh, $salty_kids, $oauth_data, $resp_content);

_db_disconnect($dbh);

########################################################################
########################################################################
########################################################################

# START: add_bundles_for_keyrings()
# START: get_bundles_for_keyrings()
#my $max = 5000; ## max number of parameters for DBD::pg
sub get_bundle_payload {
	my ($dbh, $salty_kids, $oauth_data, $resp_content) = @_;

	my $bundle_metadata_secrets = {};
	my $bundle_payloads_secrets = {};

	my $kridcount = 0;
	my $max = 4096;
	foreach my $krids (spart($max, keys(%$salty_kids))) {
		print "keyring_keys_list " . mlnp(@$krids);

		my $sql = sprintf(q{
			SELECT krid, metadata, payload
			FROM bundle
			WHERE krid IN (%s)
		;}, join(', ', ('?') x scalar(@$krids)));

		my $sth = $dbh->prepare($sql);
		$sth->execute(@$krids);

		my $bundles = $sth->fetchall_hashref('krid');

		$bundle_metadata_secrets = %$bundles
			? rsa_decrypt(
				$oauth_data,
				$resp_content,
				{
					map {
						$_ => {
							#mk_uuid => $keyring_md{$var}{'mk_uuid'},
							#mk_uuid => $keyring_metadata->{$keyring_krid_mapping->{$_}}->{mk_uuid},
							mk_uuid => $salty_kids->{$_}{mk_uuid},
							data    => $bundles->{$_}->{"metadata"}
						}
					} keys %$bundles
				}
			) : {};
		#write_dumper_to_file( "bundle_metadata_secrets.txt", $bundle_metadata_secrets);

		$bundle_payloads_secrets = %$bundles
			? cbc_decrypt_md(
				$oauth_data,
				$resp_content,
				{
					map {
						$_ => {
							data     => $bundles->{$_}->{"payload"},
							metadata => $bundle_metadata_secrets->{$_}
						}
					} keys %$bundles
				}
			) : {};
		#write_dumper_to_file( "bundle_payloads_secrets.txt", $bundle_payloads_secrets);

		pdebug("salty kids are: %s", mlnp($salty_kids));

		foreach my $krid (@{$krids}) {
			if ($opt_parallelkridlist) {
				print "--krid $krid\0\0";
				next;
			}
			# XXX: AP: 20160914: debug: remove the krid check
			#next if $krid ne 'eca53775-f6d3-42f7-815f-c4168ab5c472';
			next if $opt_kridsd && $krid ne $opt_kridsd;
			my $bundle_tables = $bundle_payloads_secrets->{$krid}->{"tables"};
			$kridcount++;

			pdebug("krid in bundle_payload_secrets $krid");
			foreach my $table (qw(search link stash brick)) {
				if ($bundle_tables->{$table}) {
					if ($table eq 'search' or $table eq 'link') {
						$bundle_tables->{"q_filter_keep_$table"} = $dbh->quote_identifier(undef, undef, "fk_${table}_${kridcount}_$$\_".$bundle_tables->{$table});
						$bundle_tables->{"q_filter_nuke_$table"} = $dbh->quote_identifier(undef, undef, "fn_${table}_${kridcount}_$$\_".$bundle_tables->{$table});
					}
					$bundle_tables->{"q_nuke_$table"} = $dbh->quote_identifier(undef, undef, "n_${table}_${kridcount}_$$\_".$bundle_tables->{$table});
					$bundle_tables->{"q_read_$table"} = $dbh->quote_identifier(undef, "bundle_$table", $bundle_tables->{$table});
				} else {
					perror("data purging from the default (live-for-insert) bundle is not supported for performance reasons.");
				}
				foreach my $tmptable (grep { /^q_(?:nuke|filter_.+?)_$table$/ } keys %$bundle_tables) {
					my $sql = sprintf(q{CREATE UNLOGGED TABLE IF NOT EXISTS %s (LIKE %s INCLUDING STATISTICS);},
					#my $sql = sprintf(q{CREATE TEMPORARY TABLE %s (LIKE %s INCLUDING STATISTICS) ON COMMIT DROP;},
						$bundle_tables->{$tmptable},
						$bundle_tables->{"q_read_$table"},
					);
					pdebug("bundle: tmp table sql: %s", $sql);
					$dbh->do($sql);
					if ($table eq 'link') { # no need to add weight to tables that aren't kludgy
						$sql = sprintf(q{ALTER TABLE %s ADD COLUMN rownum BIGINT GENERATED ALWAYS AS IDENTITY;}, $bundle_tables->{$tmptable});
						$dbh->do($sql);
					};
					pdebug("bundle: bundle %s table %s, nuke table %s", $table, $bundle_tables->{"q_read_$table"}, $bundle_tables->{$tmptable});
				};
			}

			#print "keyring krid:           $keyring->{'krid'}\n";
			#print "keyring plaintext kid:  $keyring->{'kid'}\n";

			$dbh->begin_work; # XXX: AP: 20190619: move this to beefore the table loop
			search_bundle_search($salty_kids, $krid, $bundle_tables);
			# XXX: AP: 20190612: here we decide what to nuke from the search table - woo
			# XXX: AP: 20190612: nuke here in general. end-of-krid means safety
			# XXX: debug - remove before prod XXX
			$dbh->commit; $dbh->begin_work;
			pdebug("bundle: tables : %s", mlnp($bundle_tables));
			nuke_links3($krid, $bundle_tables);
			nuke_searches($krid, $bundle_tables);
			nuke_stashbricks($krid, $bundle_tables, 'brick');
			nuke_stashbricks($krid, $bundle_tables, 'stash');
			# XXX: debug - remove before prod XXX
			$dbh->rollback; #die;
			#foreach my $table (qw(search link stash brick)) {
			#	$sql = sprintf(q{DROP TABLE %s;}, join(', ', grep { /^q_(?:nuke|filter_.+?)_$table$/ } keys %$bundle_tables));
			#	$dbh->do($sql);
			#};
		}
		#print "DUMPING BUNDLES ". Dumper (@$bundles) . "\n";
	}
	unless ($opt_parallelkridlist) {
		# XXX: DEBUG! REMOVE REMOVE REMOVE XXX
		#$dbh->commit;   #OR #$dbh->commit;
		#$dbh->rollback;   #OR #$dbh->commit;
		pdebug("ROLLBACK postgres transaction");
	}
}

sub search_bundle_search {
	my ( $salty_kids, $krid, $bundle_tables ) = @_;

	my $search_stmt = sprintf(q{
		SELECT id, kid
		FROM %s
		WHERE kid = ?
	;}, $bundle_tables->{"q_read_search"});

	my $declare_sth = $dbh->prepare("DECLARE bundle_search_cursor_$$ NO SCROLL CURSOR WITHOUT HOLD FOR $search_stmt");
	foreach my $the_all_kid (keys(%{$salty_kids->{$krid}{kids}})) {
		pdebug("search: allkid: krid: %s, all_kid: %s, dt kids: %s", $krid, slnp($the_all_kid), mlnp($salty_kids->{$krid}{kids}{$the_all_kid}));
		foreach my $the_dt_kid (keys(%{$salty_kids->{$krid}{kids}{$the_all_kid}})) {
			$declare_sth->bind_param(1, $the_dt_kid, { 'pg_type' => PG_BYTEA } );
			$declare_sth->execute;

			my $sth = $dbh->prepare("FETCH $sqlfetch FROM bundle_search_cursor_$$");
			while (1) {
				$sth->execute();
				pdebug("search: dtkid:  krid: %s, all_kid: %s, dt_kid: %s, rows: %s", $krid, slnp($the_all_kid), slnp($the_dt_kid), $sth->rows);

				last if $sth->rows == 0;
				my $search_hash_refs = $sth->fetchall_hashref('id');
				#print "search_hash_refs ". Dumper($search_hash_refs);   ### search_hash_refs in binary

				my $secretcount=0;
				my $search_refs = %$search_hash_refs ?
					cbc_decrypt_key({
						map {
							my $id = $search_hash_refs->{$_}->{"id"};

							unless (++$secretcount%($sqlfetch/10)) {
								pdebug("searchkeys: metaed %s searchables", $secretcount);
							};
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
				if ($bailonnukecount && $nukecount > $nukemax) { last; }
			}
			$dbh->do("CLOSE bundle_search_cursor_$$");
			if ($bailonnukecount && $nukecount > $nukemax) { last; }
		}
	}
	#my @nukeables = grep { !exists $keep_search_rows->{$_} } keys(%$nuke_search_rows);
	#pdebug("counts: keep_search_rows, nuke_search_rows, nukeables: %d %d %d", scalar(keys(%$keep_search_rows)), scalar(keys(%$nuke_search_rows)), scalar(@nukeables));
	#pdebug("nukeables: ", mlnp(@nukeables)_);
	#print("CLOSE bundle_search_cursor_$$\n");
	#$log->info("CLOSE bundle_search_cursor_$$");
}

sub search_bundle_link {
	#my ($salty_kids, $search_refs, $krid, $the_all_kid, $the_dt_kid, $bundle_tables, $nuke_search_rows, $keep_search_rows) = @_;
	my ($salty_kids, $search_refs, $krid, $the_all_kid, $the_dt_kid, $bundle_tables) = @_;
	#my $log = Log::Log4perl->get_logger();
	my $datum_id;

	pdebug("bundle tables: %s", slnp($bundle_tables));

	my $the_salty_kid = $salty_kids->{$krid}{kids}{$the_all_kid}{$the_dt_kid};
	my $salt_link = $the_salty_kid->{'secrets'}->{'salt'}->{'link'};
	my $link_ids  = $the_salty_kid->{'secrets'}->{'skeys'}->{'link_ids'};
	my $salt_link_bin = pack('H*', $salt_link);

	my $max = 4096;
	foreach my $searchids_enc (spart($max, keys %$search_refs)) { # AP: 20190611: the key is the decrypted data
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
		my $query_column = 'datum_id';
		my $sql = sprintf(q{
			SELECT datum_id, ids
			FROM %s
			WHERE %s IN (%s)
		;},
			$bundle_tables->{q_read_link},
			$query_column,
			join(',', ('?') x keys(%datumids))
		);

		my $sth = $dbh->prepare("DECLARE bundle_link_cursor_$$ NO SCROLL CURSOR WITHOUT HOLD FOR $sql");
		my $cnt = 1;
		foreach my $data (keys(%datumids)) {
			if ($pg_special_query_columns{$query_column}) {
				$sth->bind_param($cnt++, $data, { 'pg_type' => $pg_special_query_columns{$query_column} });
			} else {
				$sth->bind_param($cnt++, $data);
			}
		};
		$sth->execute;
		$sth = $dbh->prepare("FETCH $sqlfetch FROM bundle_link_cursor_$$;");

		my $fetchcnt = 0;
		while (1) {
			$sth->execute;
			pdebug("link: krid: %s, all_kid: %s, dt_kid: %s, rows: %s", $krid, slnp($the_all_kid), slnp($the_dt_kid), $sth->rows);
			# XXX: debug 
			#$sth->finish; last
			last if ($sth->rows == 0);
			my $fetched = $sth->rows;
			$fetchcnt += $fetched;
			pdebug("link: fetched %s links", $fetchcnt);

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
						unless (++$secretcount%($sqlfetch/10)) {
							pdebug("linkkeys: metaed %s links", $secretcount);
						};
						{
							data_enc => $ids,
							key  => $link_ids,
							extra => { datum_id => $_->{'datum_id'} },
						}
					#} keys %$links_enc
					} @$links_enc
				]) : [];
			#pdebug("link: links_dec: %s", mlnp($links_dec));

			my $stashcnt = 0;
			#filter_links_and_nuke_prep($the_salty_kid, $the_dt_kid, $links_dec, $search_refs, \%datumids, $bundle_tables, $nuke_search_rows, $keep_search_rows);
			filter_links_and_nuke_prep($the_salty_kid, $the_dt_kid, $links_dec, \%datumids, $bundle_tables, $fetched);
			if ($bailonnukecount && $nukecount > $nukemax) { last; }
		}
		$dbh->do("CLOSE bundle_link_cursor_$$");
		if ($bailonnukecount && $nukecount > $nukemax) { last; }
	}
}

sub filter_links_and_nuke_prep {
	#my ($the_salty_kid, $the_dt_kid, $links_dec, $search_refs, $datumids, $bundle_tables, $nuke_search_rows, $keep_search_rows) = @_;
	my ($the_salty_kid, $the_dt_kid, $links_dec, $datumids, $bundle_tables, $fetched) = @_;
	#my ($nuke_stashes, $nuke_bricks, $nuke_links, $keep_search_rows, $nuke_search_rows) = ([], [], [], {}, {});
	my ($nuke_stashes, $nuke_bricks, $keep_nuke_rows, $nuke_links, $keep_search_rows, $nuke_search_rows) = ([], [], [], [], [], []);

	foreach my $link_dec (@$links_dec) {

		#pdebug("filter_links_and_nuke_prep: \$link_dec: %s", mlnp($link_dec));
		my $link_ids_enc = $link_dec->{data_enc};
		my $link_ids_dec = $link_dec->{data_dec};
		my $link_data = $json->decode($link_ids_dec);
		my $datum_id = $link_dec->{extra}->{datum_id};

		unless ($GLOBAL_ALLOWED_DATA_TYPES{$link_data->{dt}}) {
			pdebug("link: datum_id:%8.8s keep data(%s/%s): %s %s %s : dt:%s", unpack('H*', $datum_id), $nukecount, $nukemax, $link_data->{dt}, $link_data->{ts}->{start}, $link_data->{ts}->{end}, $link_data->{dt});
			#$keep_search_rows->{$datum_id} = $datumids->{$datum_id}; # encrypted search_id
			push(@$keep_search_rows, $datumids->{$datum_id}); # encrypted search_id
			push(@$keep_nuke_rows, { datum_id_salted => $datum_id, ids_enc => $link_ids_enc }); # encrypted search_id
			next;
		}
		# XXX: AP: 20190611: what of start being -ve infinity (ie not specified)?
		unless (($link_data->{ts}->{start} ge $tsr_start && $link_data->{ts}->{start} lt $tsr_end) || ($link_data->{ts}->{end} lt $tsr_end && $link_data->{ts}->{end} ge $tsr_start)) {
			pdebug("link: datum_id:%8.8s keep data(%s/%s): %s %s %s : tr:%s %s", unpack('H*', $datum_id), $nukecount, $nukemax, $link_data->{dt}, $link_data->{ts}->{start}, $link_data->{ts}->{end}, $tsr_start, $tsr_end);
			#$keep_search_rows->{$datum_id} = $datumids->{$datum_id}; # encrypted search_id
			push(@$keep_search_rows, $datumids->{$datum_id}); # encrypted search_id
			push(@$keep_nuke_rows, { datum_id_salted => $datum_id, ids_enc => $link_ids_enc }); # encrypted search_id
			next;
		}
		pdebug("link: datum_id:%8.8s nuke data(%s/%s): %s %s %s : tr:%s %s", unpack('H*', $datum_id), $nukecount, $nukemax, $link_data->{dt}, $link_data->{ts}->{start}, $link_data->{ts}->{end}, $tsr_start, $tsr_end);
		#$nuke_search_rows->{$datum_id} = $datumids->{$datum_id}; # encrypted search_id
		push(@$nuke_search_rows, $datumids->{$datum_id}); # encrypted search_id
		push(@$nuke_links, { datum_id_salted => $datum_id, ids_enc => $link_ids_enc });
		push(@$nuke_stashes, $link_data->{stash_id});
		push(@$nuke_bricks, @{$link_data->{brick_ids}}) if ($link_data->{brick_ids} && @{$link_data->{brick_ids}});

		#my $bundle_stash = $bundle_tables->{"stash"};

		#pdebug("link:%8.8s stash id:  %s", $key, $link_data->{stash_id});
		#pdebug("link:%8.8s brick ids: %s", $key, join(', ', [$link_data->{brick_ids}])) if $link_data->{brick_ids};
	}

	pdebug("link: fetched: %s - now preparing...", $fetched);
	prep_nuke_stashbricks($bundle_tables, 'brick', $nuke_bricks, $the_salty_kid);
	prep_nuke_stashbricks($bundle_tables, 'stash', $nuke_stashes, $the_salty_kid);
	prep_nuke_links($bundle_tables, $nuke_links);
	prep_nuke_links2($bundle_tables, $nuke_links, $keep_nuke_rows);
	prep_nuke_searches($bundle_tables, $nuke_search_rows, $keep_search_rows, $the_dt_kid);
	$nukecount++ if (@$nuke_bricks or @$nuke_stashes or @$nuke_links);
}

sub prep_nuke_stashbricks {
	my ($bundle_tables, $table, $nukeables, $the_salty_kid) = @_;

	return unless @$nukeables;

	my $salt_bin = pack('H*', $the_salty_kid->{'secrets'}->{'salt'}->{$table});

	#pdebug("prep_nuke_stashbricks: \$bundle_tables: %s", mlnp($bundle_tables));
	#pdebug("prep_nuke_stashbricks: \$table: %s", mlnp($table));
	#pdebug("prep_nuke_stashbricks: \$nukeables: %s", mlnp($nukeables));
	#pdebug("prep_nuke_stashbricks: \$the_salty_kid: %s", mlnp($the_salty_kid));
	pdebug("preparing %s: count: %s", $table, scalar(keys @$nukeables));
	prep_copy($dbh, $bundle_tables->{"q_nuke_$table"}.' (id, metadata, data)');
	foreach my $id (uniq(@$nukeables)) {
		my $salty_id = pbkdf2(
			$id,
			$salt_bin,
			$the_salty_kid->{'secrets'}->{'pdkargs'}->{'iters'},
			$the_salty_kid->{'secrets'}->{'pdkargs'}->{'hash'},
			$the_salty_kid->{'secrets'}->{'pdkargs'}->{'dklen'}
		);
		my %row = (
			'id'	=> $salty_id,
			'metadata'	=> '',
			'data'	=> '',
		);
		#pdebug("prep_nuke_stashbricks: row: %s", mlnp(%row));
		copy_data($dbh, \%row, qw(id metadata data));
	}
	finish_copy($dbh);
}

sub nuke_stashbricks {
	my ($krid, $bundle_tables, $table) = @_;

	my $sql = sprintf(q{
		DELETE
		FROM %s AS sd
		WHERE EXISTS (
			SELECT 1
			FROM %s AS nd
			WHERE sd.id = nd.id
		)
	;},
		$bundle_tables->{"q_read_$table"},
		$bundle_tables->{"q_nuke_$table"}
	);
	my $count = $dbh->do($sql);

#	my $sql = sprintf(q{
#		SELECT count(*)
#		FROM %s AS sd
#		WHERE EXISTS (
#			SELECT 1
#			FROM %s AS nd
#			WHERE sd.id = nd.id
#		)
#	;},
#		$bundle_tables->{"q_read_$table"},
#		$bundle_tables->{"q_nuke_$table"}
#	);
#	my $count = $dbh->selectcol_arrayref($sql);

	pdebug("krid: %s - deleted from %s: %s rows", $krid//'', $table, slnp($count));
}

sub prep_nuke_links {
	my ($bundle_tables, $nukeables) = @_;

	return unless @$nukeables;

	#pdebug("prep_nuke_links: \$bundle_tables: %s", mlnp($bundle_tables));
	#pdebug("prep_nuke_links: \$nukeables: %s", mlnp($nukeables));
	prep_copy($dbh, $bundle_tables->{"q_nuke_link"}.' (datum_id, ids)');
	pdebug("preparing links: count: %s", scalar(@$nukeables));
	foreach my $link (@$nukeables) {
		my %row = (
			'datum_id'	=> $link->{datum_id_salted},
			'ids'		=> $link->{ids_enc},
		);
		#pdebug("prep_nuke_links: row: %s", mlnp(%row));
		copy_data($dbh, \%row, qw(datum_id ids));
	}
	finish_copy($dbh);
}

sub prep_nuke_links2 {
	my ($bundle_tables, $nukeables, $keepables) = @_;

	#return unless %$nukeables or %$keepables;
	return unless @$nukeables or @$keepables;

	my %nukekeep = (
		'nuke'	=> $nukeables//[],
		'keep'	=> $keepables//[],
	);
	#pdebug("prep_nuke_links2: \$bundle_tables: %s", mlnp($bundle_tables));
	#pdebug("prep_nuke_links2: \$nukeables: %s", mlnp($nukeables));
	#pdebug("prep_nuke_links2: \$table: %s", mlnp($keepables));
	#pdebug("prep_nuke_searches: \$the_salty_kid: %s", mlnp($the_dt_kid));
	foreach my $nukekeep (keys %nukekeep) {
		#pdebug("preparing %s links content: %s", $nukekeep, mlnp($nukekeep{$nukekeep}));
		#pdebug("preparing %s links count: %s", $nukekeep, scalar(keys %{$nukekeep{$nukekeep}}));
		pdebug("preparing %s links: count: %s", $nukekeep, scalar(@{$nukekeep{$nukekeep}}));
		prep_copy($dbh, $bundle_tables->{"q_filter_${nukekeep}_link"}.' (datum_id, ids)');
		foreach my $link (@{$nukekeep{$nukekeep}}) {
			my %row = (
				'datum_id'	=> $link->{datum_id_salted},
				'ids'		=> $link->{ids_enc},
			);
			#pdebug("prep_nuke_links2($nukekeep): row: %s", mlnp(%row));
			#pdebug("%s row: %s", $nukekeep, slnp(%row));
			copy_data($dbh, \%row, qw(datum_id ids));
		}
		finish_copy($dbh);
	}
}

#sub nuke_links2 {
#	my ($krid, $bundle_tables) = @_;
#	my $table = 'link';
#
##	my $sql = sprintf(q{
##		DELETE FROM %s AS sd
##		WHERE EXISTS (
##			SELECT * FROM (
##				SELECT DISTINCT id, kid
##				FROM %s AS fn
##				WHERE NOT EXISTS (
##					SELECT 1
##					FROM %s AS fk
##					WHERE fn.id = fk.id
##						AND fn.kid = fk.kid
##				)
##			) AS nd
##			WHERE sd.id = nd.id
##				AND sd.kid = nd.kid
##		)
##	;},
##		$bundle_tables->{"q_read_$table"},
##		$bundle_tables->{"q_filter_nuke_$table"},
##		$bundle_tables->{"q_filter_keep_$table"}
##	);
##	my $count = $dbh->do($sql);
#
#	# nuke rows based on datum_id which have no ids that require keeping
#	my $sql = sprintf(q{
#		DELETE
#		FROM %s AS sd
#		WHERE EXISTS (
#			SELECT * FROM (
#				SELECT DISTINCT datum_id
#				FROM %s AS fn
#				WHERE NOT EXISTS (
#					SELECT 1
#					FROM %s AS fk
#					WHERE fn.datum_id = fk.datum_id
#				)
#			) AS nd
#			WHERE sd.datum_id = nd.datum_id
#		)
#	;},
#		$bundle_tables->{"q_read_$table"},
#		$bundle_tables->{"q_filter_nuke_$table"},
#		$bundle_tables->{"q_filter_keep_$table"}
#	);
#	my $count = $dbh->selectcol_arrayref($sql);
#
#	pdebug("krid: %s - deleted from %s by datum_id: %s rows", $krid//'', $table, slnp($count));
#
#	# nuke rows based on datum_id and ids as there are datum_id and ids combos which require keeping
#	my $search_stmt = sprintf(q{
#		SELECT * FROM (
#			SELECT datum_id, ids
#			FROM %s AS fn
#			WHERE EXISTS (
#				SELECT 1
#				FROM %s AS fk
#				WHERE fn.datum_id = fk.datum_id)
#		) AS nd
#	;},
#		$bundle_tables->{"q_filter_nuke_$table"},
#		$bundle_tables->{"q_filter_keep_$table"},
#	);
#
#	my $declare_sth = $dbh->prepare("DECLARE nuke_${table}_$$ NO SCROLL CURSOR WITHOUT HOLD FOR $search_stmt");
#	while (1) {
#		my $sql = sprintf(q{
#			DELETE
#			FROM %s AS sd
#			WHERE EXISTS (
#				SELECT * FROM (
#					SELECT datum_id, ids
#					FROM %s AS fn
#					WHERE EXISTS (
#						SELECT 1
#						FROM %s AS fk
#						WHERE fn.datum_id = fk.datum_id
#					)
#				) AS nd
#				WHERE sd.datum_id = nd.datum_id
#					AND sd.ids = nd.ids
#			)
#		;},
#			$bundle_tables->{"q_read_$table"},
#			$bundle_tables->{"q_filter_nuke_$table"},
#			$bundle_tables->{"q_filter_keep_$table"}
#		);
#		my $count = $dbh->selectcol_arrayref($sql);
#	};
#
#	pdebug("krid: %s - deleted from %s by datum_id+ids: %s rows", $krid//'', $table, slnp($count));
#}

sub nuke_links3 {
	my ($krid, $bundle_tables) = @_;
	my $table = 'link';

	my $sql = sprintf(q{
		DELETE FROM %s AS sd
		WHERE EXISTS (
			SELECT 1
			FROM %s AS nd
			WHERE nd.rownum/%s AND 
				sd.datum_id = nd.datum_id
				AND sd.ids = nd.ids
		)
	;},
		$bundle_tables->{"q_read_$table"},
		$bundle_tables->{"q_nuke_$table"},
		10_000_000_000_000_000,	# XXX: AP: 20190619: dodgy af but if we're nuking more rows than this I'll be dead
	);
	my $count = $dbh->do($sql);

#	my $sql = sprintf(q{
#		SELECT count(*)
#		FROM (
#			SELECT *
#			FROM %s AS sd
#			WHERE EXISTS (
#				SELECT 1
#				FROM %s AS nd
#				WHERE sd.datum_id = nd.datum_id
#			)
#		) AS sd2
#		WHERE EXISTS (
#			SELECT 1
#			FROM %s AS nd
#			WHERE sd2.datum_id = nd.datum_id
#				AND sd2.ids = nd.ids
#		)
#	;},
#		$bundle_tables->{"q_read_$table"},
#		$bundle_tables->{"q_nuke_$table"},
#		$bundle_tables->{"q_nuke_$table"}
#	);
#	my $count = $dbh->selectcol_arrayref($sql);

	pdebug("krid: %s - deleted from %s: %s rows", $krid//'', $table, slnp($count));
}

sub nuke_links {
	my ($krid, $bundle_tables) = @_;
	my $table = 'link';

	my $sql = sprintf(q{
		DELETE FROM %s AS sd
		WHERE EXISTS (
			SELECT 1
			FROM %s AS nd
			WHERE sd.datum_id = nd.datum_id
				AND sd.ids = nd.ids
		)
	;},
		$bundle_tables->{"q_read_$table"},
		$bundle_tables->{"q_nuke_$table"}
	);
	my $count = $dbh->do($sql);

#	my $sql = sprintf(q{
#		SELECT count(*)
#		FROM (
#			SELECT *
#			FROM %s AS sd
#			WHERE EXISTS (
#				SELECT 1
#				FROM %s AS nd
#				WHERE sd.datum_id = nd.datum_id
#			)
#		) AS sd2
#		WHERE EXISTS (
#			SELECT 1
#			FROM %s AS nd
#			WHERE sd2.datum_id = nd.datum_id
#				AND sd2.ids = nd.ids
#		)
#	;},
#		$bundle_tables->{"q_read_$table"},
#		$bundle_tables->{"q_nuke_$table"},
#		$bundle_tables->{"q_nuke_$table"}
#	);
#	my $count = $dbh->selectcol_arrayref($sql);

	pdebug("krid: %s - deleted from %s: %s rows", $krid//'', $table, slnp($count));
}

sub prep_nuke_searches {
	my ($bundle_tables, $nukeables, $keepables, $the_dt_kid) = @_;

	#return unless %$nukeables or %$keepables;
	return unless @$nukeables or @$keepables;

	my %nukekeep = (
		#'nuke'	=> $nukeables//{},
		#'keep'	=> $keepables//{},
		'nuke'	=> $nukeables//[],
		'keep'	=> $keepables//[],
	);
	#pdebug("prep_nuke_searches: \$bundle_tables: %s", mlnp($bundle_tables));
	#pdebug("prep_nuke_searches: \$nukeables: %s", mlnp($nukeables));
	#pdebug("prep_nuke_searches: \$table: %s", mlnp($keepables));
	#pdebug("prep_nuke_searches: \$the_salty_kid: %s", mlnp($the_dt_kid));
	foreach my $nukekeep (keys %nukekeep) {
		#pdebug("preparing %s searchables: content: %s", $nukekeep, mlnp($nukekeep{$nukekeep}));
		#pdebug("preparing %s searchables: count: %s", $nukekeep, scalar(keys %{$nukekeep{$nukekeep}}));
		pdebug("preparing %s searchables: count: %s", $nukekeep, scalar(@{$nukekeep{$nukekeep}}));
		prep_copy($dbh, $bundle_tables->{"q_filter_${nukekeep}_search"}.' (id, kid, datum)');
		foreach my $datum_id (@{$nukekeep{$nukekeep}}) {
			my %row = (
				'id'		=> $datum_id,
				'kid'		=> $the_dt_kid,
				'datum'		=> '',
			);
			#pdebug("prep_nuke_searches($nukekeep): row: %s", mlnp(%row));
			#pdebug("%s row: %s", $nukekeep, slnp(%row));
			copy_data($dbh, \%row, qw(id kid datum));
		}
		finish_copy($dbh);
	}
}

sub nuke_searches {
	my ($krid, $bundle_tables) = @_;
	my $table = 'search';

	my $sql = sprintf(q{
		DELETE FROM %s AS sd
		WHERE EXISTS (
			SELECT * FROM (
				SELECT DISTINCT id, kid
				FROM %s AS fn
				WHERE NOT EXISTS (
					SELECT 1
					FROM %s AS fk
					WHERE fn.id = fk.id
						AND fn.kid = fk.kid
				)
			) AS nd
			WHERE sd.id = nd.id
				AND sd.kid = nd.kid
		)
	;},
		$bundle_tables->{"q_read_$table"},
		$bundle_tables->{"q_filter_nuke_$table"},
		$bundle_tables->{"q_filter_keep_$table"}
	);
	my $count = $dbh->do($sql);

#	my $sql = sprintf(q{
#		SELECT count(*)
#		FROM %s AS sd
#		WHERE EXISTS (
#			SELECT * FROM (
#				SELECT DISTINCT id, kid
#				FROM %s AS fn
#				WHERE NOT EXISTS (
#					SELECT 1
#					FROM %s AS fk
#					WHERE fn.id = fk.id
#						AND fn.kid = fk.kid
#				)
#			) AS nd
#			WHERE sd.id = nd.id
#				AND sd.kid = nd.kid
#		)
#	;},
#		$bundle_tables->{"q_read_$table"},
#		$bundle_tables->{"q_filter_nuke_$table"},
#		$bundle_tables->{"q_filter_keep_$table"}
#	);
#	my $count = $dbh->selectcol_arrayref($sql);

	pdebug("krid: %s - deleted from %s: %s rows", $krid//'', $table, slnp($count));
}

=head1 NAME

MD::Flush - Delete records from mdstash.stash.

=head1 SYNOPSIS


  --lower,-l <ts>   Fetch JSON record based on keyword
  --upper,-u <ts>   Create JSON record as per input.
  --parallelkl,-p   List KRIDs in timerange for feeding to parallel
  --krid,-k <krid>  Limit search and destroy to this KRID only

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

# vim:ts=4:
