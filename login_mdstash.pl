#!/usr/bin/perl

use DBI;
use strict;
use warnings;

my $driver  = "Pg"; 
my $database = "mdstash";
#my $dsn = "DBI:$driver:dbname = $database;host = 127.0.0.1;port = 5432";
my $dsn = "DBI:$driver:dbname = $database;port = 5432";
my $userid = "postgres";
my $password = "";
my $dbh = DBI->connect($dsn, $userid, $password, { RaiseError => 1 }) 
   or die $DBI::errstr;

print "Opened database successfully\n";


my $stmt = qq(SELECT count(*)  from stash;);
my $sth = $dbh->prepare( $stmt );
my $rv = $sth->execute() or die $DBI::errstr;
#if($rv < 0) {
print $DBI::errstr if($rv < 0);
#}
while(my @row = $sth->fetchrow_array()) {
      print "TOTAL COUNT = ". $row[0] . "\n";
}
print "Operation done successfully\n";
$dbh->disconnect();

