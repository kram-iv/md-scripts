#!/usr/bin/perl

use v5.28;
use strict;
use warnings FATAL => qw(uninitialized);

# AP: 20190624: these must be defined before MetaData::Flush is used.
use constant DEBUG => 1;
use constant DEBUG_KR_DUMP       => DEBUG && 1;
use constant DEBUG_FILEDUMP      => DEBUG && 0;
use constant DEBUG_DEALER_CONVO  => DEBUG && 0;
use constant DEBUG_MOON          => DEBUG && 1;
use constant DEBUG_MOON_V        => DEBUG && 0;
use constant DEBUG_KEYRING       => DEBUG && 1;
use constant DEBUG_SQL           => DEBUG && 1;
use constant DEBUG_SQL_V         => DEBUG_SQL && 1;
use constant DEBUG_SQL_ROLLBACK  => DEBUG_SQL && 1;
use constant DEBUG_SQL_UNLOGGED  => DEBUG_SQL && 1;
use constant DEBUG_BUNDLE        => DEBUG && 1;
use constant DEBUG_SEARCH        => DEBUG && 1;
use constant DEBUG_LINK          => DEBUG && 1;
use constant DEBUG_LINK_V        => DEBUG_LINK && 0;
use constant DEBUG_NUKEBAIL      => DEBUG && 1;
use constant DEBUG_PREP_NUKE     => DEBUG && 1;
use constant DEBUG_PREP_NUKE_V   => DEBUG_PREP_NUKE && 0;
use constant DEBUG_NUKE	         => DEBUG && 1;

use DBI;
use DBD::Pg qw(:pg_types);

use Data::Printer;

use Crypt::KeyDerivation qw(pbkdf2);

use Date::Manip;
use DateTime;
use DateTime::Infinite;
use DateTime::Format::ISO8601;
use List::NSect qw(spart);
use List::Util qw(uniq max);

use Sys::Hostname;

use Getopt::Long qw(GetOptions);
use Pod::Usage qw(pod2usage);
use Readonly;

use FindBin;
use lib "$FindBin::Bin/../lib";

use MetaData::Flush;

my $bailonnukecount = 0;
my $nukecount = 0;
my $nukemax = 50;

################################################################################################

GetOptions(
	'from|start|f=s'	=> \my $opt_from_tstz_range,
	'until|end|u=s'		=> \my $opt_until_tstz_range,
	'kridlist|l'	=> \my $opt_kridlist,
	'parallelkl|p'	=> \my $opt_parallelkridlist,
	'krid|k=s'		=> \my $opt_kridsd,
	'help|h'		=> \my $opt_help,
) or pod2usage("Try '$0 --help' for more information.");

pod2usage() if $opt_help;

$opt_kridlist = 1 if $opt_parallelkridlist;

perror "need to know when to stop deleting (until range required)" unless $opt_until_tstz_range;
perror "can't specify a krid with a request for krids" if $opt_kridsd && $opt_parallelkridlist;

###############################################################################################

#################################################################################

my $json = newjson();

my %pg_special_query_columns = (
	'id'	=> PG_BYTEA,
	'kid'	=> PG_BYTEA,
	'datum'	=> PG_BYTEA,
	'datum_id'	=> PG_BYTEA,
);
my $sqlfetch = 100_000;
my $sqlfetch_search = $sqlfetch;
my $sqlfetch_link   = max($sqlfetch / 100, 1_000);

my $host = hostname;
my $host4sql = ($host =~ s/^([^\d]{1,5}).*?(\d*)$/$1$2/r);

perror("cannot get my hostname: %s", $host//'<undef>') unless $host;

# oh woe!
my $tsr_start_dt = $opt_from_tstz_range ? DateTime::Format::ISO8601->parse_datetime(UnixDate(ParseDate($opt_from_tstz_range), '%Y%m%dT%H%M%S%z')) : DateTime::Infinite::Past->new();
my $tsr_end_dt   = DateTime::Format::ISO8601->parse_datetime(UnixDate(ParseDate($opt_until_tstz_range), '%Y%m%dT%H%M%S%z'));
my $now_dt		 = DateTime->now(time_zone => 'local');

# evil kludge - strip out the timezone for string matching in link table for speed
my $tsr_start = $opt_from_tstz_range ? $tsr_start_dt->strftime('%FT%T') : '';
my $tsr_end   = $tsr_end_dt->strftime('%FT%T');
my $tsr_start_tz = $opt_from_tstz_range ? $tsr_start_dt->strftime('%Y%m%dT%H%M%S%z') : '';
my $tsr_end_tz   = $tsr_end_dt->strftime('%Y%m%dT%H%M%S%z');
pdebug("now:                   ".$now_dt) if DEBUG;
pdebug("end + 2 years:         ".$tsr_end_dt->clone->add(years => 2)) if DEBUG;
pdebug("start/from dt:         ".($opt_from_tstz_range//'**unspecified**')." -> $tsr_start") if DEBUG;
pdebug("end/until dt:          $opt_until_tstz_range -> $tsr_end") if DEBUG;
pdebug("krid list requested:   ".($opt_parallelkridlist//'unset')) if DEBUG;
pdebug("krid to s&d:           ".($opt_kridsd//'unset')) if DEBUG;
pdebug("pid, host4sql, host:   $$, $host4sql, $host") if DEBUG;
pdebug("sqlfetch, srch, link:  $sqlfetch, $sqlfetch_search, $sqlfetch_link") if DEBUG;

if ($tsr_end_dt > $now_dt->clone->subtract(years => 2)) {
	perror("until timestamp later than 2 years ago: %s (%s)", $opt_until_tstz_range, $tsr_end_dt->strftime('%a, %d %b %Y %H:%M:%S %z'));
}
my $max_params = 4096; ## max number of parameters for DBD::pg

my $dbh = _db_connect();

my ($oauth_data, $resp_content) = _get_response_token();

# returns hash with key krid and values: krid, timerange and mk_uuid
my $krids = get_krids($dbh, $tsr_start_dt, $tsr_end_dt, $oauth_data, $resp_content);   #get krids from dsotm

my $salty_kids = get_keyrings($dbh, $tsr_start_dt, $tsr_end_dt, $krids, $oauth_data, $resp_content);

get_bundle_payload($dbh, $tsr_start_tz, $tsr_end_tz, $salty_kids, $oauth_data, $resp_content);

_db_disconnect($dbh);

########################################################################
########################################################################
########################################################################

sub get_bundle_payload {
	my ($dbh, $tsr_start_tz, $tsr_end_tz, $salty_kids, $oauth_data, $resp_content) = @_;

	my $bundle_metadata_secrets = {};
	my $bundle_payloads_secrets = {};

	my $kridcount = 0;
	$max_params = 65535; # this is not a big table but lets keep it under some control
	foreach my $krids (spart($max_params, keys(%$salty_kids))) {
		pdebug("krids: %s", mlnp(@$krids)) if DEBUG_KEYRING;

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

		pdebug("salty kids are: %s", mlnp($salty_kids)) if DEBUG_KEYRING || DEBUG_BUNDLE;

		# AP: 20160921: go through all the krids in in bundle order so as to try to maximise
		# the chance of the tables being in the filesystem cache
		foreach my $krid (sort {$bundle_payloads_secrets->{$a}->{tables}{stash} <=> $bundle_payloads_secrets->{$b}->{tables}{stash}} @{$krids}) {
			if ($opt_kridlist) {
				if ($opt_parallelkridlist) {
					print "--krid\0$krid\0".($tsr_start_tz//'' ? "--from\0$tsr_start_tz\0" : "")."--until\0$tsr_end_tz\0\0";
				} else {
					print "$krid\n";
				}
				next;
			}
			next if $opt_kridsd && $krid ne $opt_kridsd;

			my $bundle_tables = $bundle_payloads_secrets->{$krid}->{"tables"};
			$kridcount++;

			pdebug("processing krid: $krid") if DEBUG;

			$dbh->begin_work; # XXX: AP: 20190619: move this to beefore the table loop
			foreach my $table (qw(search link stash brick)) {
				if ($bundle_tables->{$table}) {
					if ($table eq 'search' or $table eq 'link') {
						$bundle_tables->{"q_filter_keep_$table"} = $dbh->quote_identifier(undef, undef, "fk_${table}_${kridcount}_${host4sql}_$$\_".$bundle_tables->{$table});
						$bundle_tables->{"q_filter_nuke_$table"} = $dbh->quote_identifier(undef, undef, "fn_${table}_${kridcount}_${host4sql}_$$\_".$bundle_tables->{$table});
					}
					$bundle_tables->{"q_nuke_$table"} = $dbh->quote_identifier(undef, undef, "n_${table}_${kridcount}_${host4sql}_$$\_".$bundle_tables->{$table});
					$bundle_tables->{"q_read_$table"} = $dbh->quote_identifier(undef, "bundle_$table", $bundle_tables->{$table});
				} else {
					perror("data purging from the default (live-for-insert) bundle is not supported for performance reasons.");
				}
				foreach my $tmptable (grep { /^q_(?:nuke|filter_.+?)_$table$/ } keys %$bundle_tables) {
					my $sql = sprintf(q{CREATE TEMPORARY TABLE %s (LIKE %s INCLUDING STATISTICS) ON COMMIT DROP;},
						$bundle_tables->{$tmptable},
						$bundle_tables->{"q_read_$table"},
					);
					if (DEBUG_SQL_UNLOGGED) {
						$sql = sprintf(q{CREATE UNLOGGED TABLE %s (LIKE %s INCLUDING STATISTICS);},
							$bundle_tables->{$tmptable},
							$bundle_tables->{"q_read_$table"},
						);
					};
					pdebug("bundle: tmp table sql: %s", $sql) if DEBUG_SQL;
					$dbh->do($sql);
					pdebug("bundle: bundle %s table %s, nuke table %s", $table, $bundle_tables->{"q_read_$table"}, $bundle_tables->{$tmptable}) if DEBUG;
				};
			}

			search_bundle_search($salty_kids, $krid, $bundle_tables);
			# XXX: AP: 20190612: nuke here in general. end-of-krid means safety
			pdebug("bundle: tables : %s", mlnp($bundle_tables)) if DEBUG_BUNDLE;
			if (DEBUG_SQL_UNLOGGED) {
				pdebug("committing temp tables...") if DEBUG_SQL_V;
				$dbh->commit; $dbh->begin_work;
				pdebug("preparing to nuke...") if DEBUG_SQL_V;
			};
			nuke_links($krid, $bundle_tables); # AP: 20160921: biggest table, last touched, may still be in fs cache so do first
			nuke_searches($krid, $bundle_tables);
			nuke_stashbricks($krid, $bundle_tables, 'brick');
			nuke_stashbricks($krid, $bundle_tables, 'stash');
			if (DEBUG_SQL_ROLLBACK) {
				$dbh->rollback;
			} else {
				$dbh->commit;
			}
		}
	}
	unless ($opt_kridlist) {
		if (DEBUG_SQL_ROLLBACK) {
			$dbh->rollback;
			pdebug("ROLLBACK postgres transaction") if DEBUG_SQL_V;
		} else {
			#$dbh->commit;   #OR #$dbh->commit;
		}
	}
}

sub search_bundle_search {
	my ( $salty_kids, $krid, $bundle_tables ) = @_;

	my $search_stmt = sprintf(q{
		SELECT id, kid
		FROM %s
		WHERE kid = ?
	;}, $bundle_tables->{"q_read_search"});

	my $declare_sth = $dbh->prepare("DECLARE bundle_search_cursor_${host4sql}_$$ NO SCROLL CURSOR WITHOUT HOLD FOR $search_stmt");
	foreach my $the_all_kid (keys(%{$salty_kids->{$krid}{kids}})) {
		pdebug("search: allkid: krid: %s, all_kid: %s, dt kids: %s", $krid, slnp($the_all_kid), mlnp($salty_kids->{$krid}{kids}{$the_all_kid})) if DEBUG_SEARCH;
		foreach my $the_dt_kid (keys(%{$salty_kids->{$krid}{kids}{$the_all_kid}})) {
			$declare_sth->bind_param(1, $the_dt_kid, { 'pg_type' => PG_BYTEA } );
			$declare_sth->execute;

			my $sth = $dbh->prepare("FETCH $sqlfetch_search FROM bundle_search_cursor_${host4sql}_$$");
			while (1) {
				$sth->execute();
				pdebug("search: dtkid:  krid: %s, all_kid: %s, dt_kid: %s, rows: %s", $krid, slnp($the_all_kid), slnp($the_dt_kid), $sth->rows) if DEBUG_SEARCH;

				last if $sth->rows == 0;
				my $search_hash_refs = $sth->fetchall_hashref('id');

				my $secretcount=0;
				my $search_refs = %$search_hash_refs ?
					cbc_decrypt_key({
						map {
							my $id = $search_hash_refs->{$_}->{"id"};

							unless (++$secretcount%($sqlfetch_search/10)) {
								pdebug("searchkeys: metaed %s searchables", $secretcount) if DEBUG_SEARCH;
							};
							$id => {
								data => $id,
								key  => $salty_kids->{$krid}{kids}{$the_all_kid}{$the_dt_kid}->{'search_id'},
							}; # encrypted search.id => decrypted search.id
						} keys %$search_hash_refs
					}) : {};

				write_dumper_to_file( "bundle_search.txt", $search_refs);

				search_bundle_link($salty_kids, $search_refs, $krid, $the_all_kid, $the_dt_kid, $bundle_tables);
				# XXX: debug
				#$sth->finish; last;
				if (DEBUG_NUKEBAIL && $bailonnukecount && $nukecount > $nukemax) { last; }
			}
			$dbh->do("CLOSE bundle_search_cursor_${host4sql}_$$");
			if (DEBUG_NUKEBAIL && $bailonnukecount && $nukecount > $nukemax) { last; }
		}
	}
}

sub search_bundle_link {
	my ($salty_kids, $search_refs, $krid, $the_all_kid, $the_dt_kid, $bundle_tables) = @_;
	my $datum_id;

	pdebug("bundle tables: %s", slnp($bundle_tables)) if DEBUG_LINK;

	my $the_salty_kid = $salty_kids->{$krid}{kids}{$the_all_kid}{$the_dt_kid};
	my $salt_link = $the_salty_kid->{'secrets'}->{'salt'}->{'link'};
	my $link_ids  = $the_salty_kid->{'secrets'}->{'skeys'}->{'link_ids'};
	my $salt_link_bin = pack('H*', $salt_link);

	foreach my $searchids_enc (spart($max_params, keys %$search_refs)) {
		my %datumids;
		foreach my $searchid_enc (@$searchids_enc) {
			my $datumid = pbkdf2(
				$search_refs->{$searchid_enc},
				$salt_link_bin,
				$the_salty_kid->{'secrets'}->{'pdkargs'}->{'iters'},
				$the_salty_kid->{'secrets'}->{'pdkargs'}->{'hash'},
				$the_salty_kid->{'secrets'}->{'pdkargs'}->{'dklen'}
			);
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
			join(',', ('?') x keys(%datumids)),
		);

		my $sth = $dbh->prepare("DECLARE bundle_link_cursor_${host4sql}_$$ NO SCROLL CURSOR WITHOUT HOLD FOR $sql");
		my $cnt = 1;
		foreach my $data (keys(%datumids)) {
			if ($pg_special_query_columns{$query_column}) {
				$sth->bind_param($cnt++, $data, { 'pg_type' => $pg_special_query_columns{$query_column} });
			} else {
				$sth->bind_param($cnt++, $data);
			}
		};
		$sth->execute;
		$sth = $dbh->prepare("FETCH $sqlfetch_link FROM bundle_link_cursor_${host4sql}_$$;");

		my $fetchcnt = 0;
		while (1) {
			$sth->execute;
			pdebug("link: krid: %s, all_kid: %s, dt_kid: %s, rows: %s", $krid, slnp($the_all_kid), slnp($the_dt_kid), $sth->rows) if DEBUG_LINK;
			# XXX: debug 
			#$sth->finish; last
			last if ($sth->rows == 0);
			my $fetched = $sth->rows;
			$fetchcnt += $fetched;
			pdebug("link: fetched %s links", $fetchcnt) if DEBUG_LINK;

			my $links_enc = $sth->fetchall_arrayref({});

			my $secretcount=0;
			my $links_dec = @$links_enc
				? cbc_decrypt_array( [
					map {
						my $ids = $_->{'ids'};
						unless (++$secretcount%($sqlfetch_link/10)) {
							pdebug("linkkeys: metaed %s links", $secretcount) if DEBUG_LINK;
						};
						{
							data_enc => $ids,
							key  => $link_ids,
							extra => { datum_id => $_->{'datum_id'} },
						}
					} @$links_enc
				]) : [];

			filter_links_and_nuke_prep($the_salty_kid, $the_dt_kid, $links_dec, \%datumids, $bundle_tables, $fetched);
			if (DEBUG_NUKEBAIL && $bailonnukecount && $nukecount > $nukemax) { last; }
		}
		$dbh->do("CLOSE bundle_link_cursor_${host4sql}_$$");
		if (DEBUG_NUKEBAIL && $bailonnukecount && $nukecount > $nukemax) { last; }
	}
}

sub filter_links_and_nuke_prep {
	my ($the_salty_kid, $the_dt_kid, $links_dec, $datumids, $bundle_tables, $fetched) = @_;
	my ($nuke_stashes, $nuke_bricks, $keep_nuke_rows, $nuke_link_rows, $keep_search_rows, $nuke_search_rows) = ([], [], [], [], [], []);

	foreach my $link_dec (@$links_dec) {
		my $link_ids_enc = $link_dec->{data_enc};
		my $link_ids_dec = $link_dec->{data_dec};
		my $link_data = $json->decode($link_ids_dec);
		my $datum_id = $link_dec->{extra}->{datum_id};

		unless ($GLOBAL_ALLOWED_DATA_TYPES{$link_data->{dt}}) {
			pdebug("link: datum_id:%8.8s keep data(%s/%s): %s %s %s : dt:%s", unpack('H*', $datum_id), $nukecount, $nukemax, $link_data->{dt}, $link_data->{ts}->{start}, $link_data->{ts}->{end}, $link_data->{dt}) if DEBUG_LINK_V;
			push(@$keep_search_rows, $datumids->{$datum_id}); # encrypted search_id
			push(@$keep_nuke_rows, { datum_id_salted => $datum_id, ids_enc => $link_ids_enc }); # encrypted search_id
			next;
		}
		# XXX: AP: 20190611: what of start being -ve infinity (ie not specified)?
		unless (($link_data->{ts}->{start} ge $tsr_start && $link_data->{ts}->{start} lt $tsr_end) || ($link_data->{ts}->{end} lt $tsr_end && $link_data->{ts}->{end} ge $tsr_start)) {
			pdebug("link: datum_id:%8.8s keep data(%s/%s): %s %s %s : tr:%s %s", unpack('H*', $datum_id), $nukecount, $nukemax, $link_data->{dt}, $link_data->{ts}->{start}, $link_data->{ts}->{end}, $tsr_start, $tsr_end) if DEBUG_LINK_V;
			push(@$keep_search_rows, $datumids->{$datum_id}); # encrypted search_id
			push(@$keep_nuke_rows, { datum_id_salted => $datum_id, ids_enc => $link_ids_enc }); # encrypted search_id
			next;
		}
		pdebug("link: datum_id:%8.8s nuke data(%s/%s): %s %s %s : tr:%s %s", unpack('H*', $datum_id), $nukecount, $nukemax, $link_data->{dt}, $link_data->{ts}->{start}, $link_data->{ts}->{end}, $tsr_start, $tsr_end) if DEBUG_LINK_V;
		push(@$nuke_search_rows, $datumids->{$datum_id}); # encrypted search_id
		push(@$nuke_link_rows, { datum_id_salted => $datum_id, ids_enc => $link_ids_enc });
		push(@$nuke_stashes, $link_data->{stash_id});
		push(@$nuke_bricks, map {$link_data->{stash_id}."/".$_} @{$link_data->{brick_ids}}) if ($link_data->{brick_ids} && @{$link_data->{brick_ids}});
	}

	pdebug("link: fetched: %s - now preparing...", $fetched) if DEBUG_LINK;
	prep_nuke_stashbricks($bundle_tables, 'brick', $nuke_bricks, $the_salty_kid);
	prep_nuke_stashbricks($bundle_tables, 'stash', $nuke_stashes, $the_salty_kid);
	prep_nuke_searches($bundle_tables, $nuke_search_rows, $keep_search_rows, $the_dt_kid);
	prep_nuke_links($bundle_tables, $nuke_link_rows, $keep_nuke_rows);
	$nukecount++ if (DEBUG_NUKEBAIL && (@$nuke_bricks or @$nuke_stashes or @$nuke_link_rows));
}

sub prep_nuke_stashbricks {
	my ($bundle_tables, $table, $nukeables, $the_salty_kid) = @_;

	return unless @$nukeables;

	my $salt_bin = pack('H*', $the_salty_kid->{'secrets'}->{'salt'}->{$table});

	pdebug("prep_nuke_stashbricks: \$bundle_tables: %s", mlnp($bundle_tables)) if DEBUG_PREP_NUKE_V;
	pdebug("prep_nuke_stashbricks: \$table: %s", mlnp($table)) if DEBUG_PREP_NUKE_V;
	pdebug("prep_nuke_stashbricks: \$nukeables: %s", mlnp($nukeables)) if DEBUG_PREP_NUKE_V;
	pdebug("prep_nuke_stashbricks: \$the_salty_kid: %s", mlnp($the_salty_kid)) if DEBUG_PREP_NUKE_V;
	pdebug("preparing %s: count: %s", $table, scalar(keys @$nukeables)) if DEBUG_PREP_NUKE;
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
		pdebug("prep_nuke_stashbricks: row: %s", mlnp(%row)) if DEBUG_PREP_NUKE_V;
		copy_data($dbh, \%row, qw(id metadata data));
	}
	finish_copy($dbh);
}

sub nuke_stashbricks {
	my ($krid, $bundle_tables, $table) = @_;

	pdebug("going to nuke from $table table...") if DEBUG_NUKE;

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

	pdebug("krid: %s - deleted from %s: %s rows", $krid//'', $table, slnp($count)) if DEBUG_NUKE;
}

sub prep_nuke_links {
	my ($bundle_tables, $nukeables, $keepables) = @_;

	#return unless %$nukeables or %$keepables;
	return unless @$nukeables or @$keepables;

	my %nukekeep = (
		'nuke'	=> $nukeables // [],
		'keep'	=> $keepables // [],
	);
	pdebug("prep_nuke_links: \$bundle_tables: %s", mlnp($bundle_tables)) if DEBUG_PREP_NUKE_V;
	pdebug("prep_nuke_links: \$nukeables: %s", mlnp($nukeables)) if DEBUG_PREP_NUKE_V;
	pdebug("prep_nuke_links: \$table: %s", mlnp($keepables)) if DEBUG_PREP_NUKE_V;
	foreach my $nukekeep (keys %nukekeep) {
		if (DEBUG_PREP_NUKE) {
			pdebug("preparing %s links content: %s", $nukekeep, mlnp($nukekeep{$nukekeep})) if DEBUG_PREP_NUKE_V;
			pdebug("preparing %s links: count: %s", $nukekeep, scalar(@{$nukekeep{$nukekeep}})) if DEBUG_PREP_NUKE;
		}
		prep_copy($dbh, $bundle_tables->{"q_filter_${nukekeep}_link"}.' (datum_id, ids)');
		foreach my $link (@{$nukekeep{$nukekeep}}) {
			my %row = (
				'datum_id'	=> $link->{datum_id_salted},
				'ids'		=> $link->{ids_enc},
			);
			pdebug("prep_nuke_links($nukekeep): row: %s", mlnp(%row)) if DEBUG_PREP_NUKE_V;
			pdebug("%s row: %s", $nukekeep, slnp(%row)) if DEBUG_PREP_NUKE_V;
			copy_data($dbh, \%row, qw(datum_id ids));
		}
		finish_copy($dbh);
	}
}

sub nuke_links {
	my ($krid, $bundle_tables) = @_;
	my $table = 'link';

	pdebug("going to nuke from $table table...") if DEBUG_NUKE;
	# nuke rows based on datum_id which have no ids that require keeping
	my $sql = sprintf(q{
		DELETE
		FROM %s AS sd
		WHERE EXISTS (
			SELECT * FROM (
				SELECT DISTINCT datum_id
				FROM %s AS fn
				WHERE NOT EXISTS (
					SELECT 1
					FROM %s AS fk
					WHERE fn.datum_id = fk.datum_id
				)
			) AS nd
			WHERE sd.datum_id = nd.datum_id
		)
	;},
		$bundle_tables->{"q_read_$table"},
		$bundle_tables->{"q_filter_nuke_$table"},
		$bundle_tables->{"q_filter_keep_$table"}
	);
	my $count = $dbh->do($sql);

	pdebug("krid: %s - deleted from %s by datum_id: %s rows", $krid//'', $table, slnp($count)) if DEBUG_NUKE;

	# 20190621: AP: this will grind but it only gets really run for a small case
	# at the edge of (typically) just the upper bound as a lower bound will typically
	# be -infinity.
	my $sql = sprintf(q{
		DELETE
		FROM %s AS sd
		WHERE EXISTS (
			SELECT * FROM (
				SELECT datum_id, ids
				FROM %s AS fn
				WHERE EXISTS (
					SELECT 1
					FROM %s AS fk
					WHERE fn.datum_id = fk.datum_id
				)
			) AS nd
			WHERE sd.datum_id = nd.datum_id
				AND sd.ids = nd.ids
		)
	;},
		$bundle_tables->{"q_read_$table"},
		$bundle_tables->{"q_filter_nuke_$table"},
		$bundle_tables->{"q_filter_keep_$table"}
	);
	my $count = $dbh->do($sql);

	pdebug("krid: %s - deleted from %s by datum_id+ids: %s rows", $krid//'', $table, slnp($count)) if DEBUG_NUKE;
}

sub prep_nuke_searches {
	my ($bundle_tables, $nukeables, $keepables, $the_dt_kid) = @_;

	return unless @$nukeables or @$keepables;

	my %nukekeep = (
		'nuke'	=> $nukeables // [],
		'keep'	=> $keepables // [],
	);
	pdebug("prep_nuke_searches: \$bundle_tables: %s", mlnp($bundle_tables)) if DEBUG_PREP_NUKE_V;
	pdebug("prep_nuke_searches: \$nukeables: %s", mlnp($nukeables)) if DEBUG_PREP_NUKE_V;
	pdebug("prep_nuke_searches: \$table: %s", mlnp($keepables)) if DEBUG_PREP_NUKE_V;
	pdebug("prep_nuke_searches: \$the_salty_kid: %s", mlnp($the_dt_kid)) if DEBUG_PREP_NUKE_V;
	foreach my $nukekeep (keys %nukekeep) {
		pdebug("preparing %s searchables: content: %s", $nukekeep, mlnp($nukekeep{$nukekeep})) if DEBUG_PREP_NUKE_V;
		pdebug("preparing %s searchables: count: %s", $nukekeep, scalar(@{$nukekeep{$nukekeep}})) if DEBUG_PREP_NUKE;
		prep_copy($dbh, $bundle_tables->{"q_filter_${nukekeep}_search"}.' (id, kid, datum)');
		foreach my $datum_id (@{$nukekeep{$nukekeep}}) {
			my %row = (
				'id'		=> $datum_id,
				'kid'		=> $the_dt_kid,
				'datum'		=> '',
			);
			pdebug("prep_nuke_searches($nukekeep): row: %s", mlnp(%row)) if DEBUG_PREP_NUKE_V;
			pdebug("%s row: %s", $nukekeep, slnp(%row)) if DEBUG_PREP_NUKE_V;
			copy_data($dbh, \%row, qw(id kid datum));
		}
		finish_copy($dbh);
	}
}

sub nuke_searches {
	my ($krid, $bundle_tables) = @_;
	my $table = 'search';

	pdebug("going to nuke from $table table...") if DEBUG_NUKE;

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

	pdebug("krid: %s - deleted from %s: %s rows", $krid // '', $table, slnp($count)) if DEBUG_NUKE;
}

=head1 NAME

MD::Flush - Delete records from mdstash.stash.

=head1 SYNOPSIS

  --from,-f <ts>    Delete records from this timestamp
  --until,-u <ts>   Delete records until this timestamp
  --kridlist,-l     List KRIDs in timerange, one per line
  --parallelkl,-p   List KRIDs in timerange for feeding to parallel
  --krid,-k <krid>  Limit search and destroy to this KRID only

  --help,-h         Print this help

  Example run:

  ./get_dsotm_bundle.pl --from '2019-05-09 05:00:00+10' --until '2019-05-09 07:59:58+10'
  ./get_dsotm_bundle.pl --until '2 years ago'

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
