package MD::Flush::Utils;
use strict;
use warnings;
 
use Exporter qw(import);
 
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


our @EXPORT = qw( write_dumper_to_file );
 
sub write_dumper_to_file {

    my ( $filename, $ds_dumper_name ) = @_;
    #my $filename = 'report.txt';
    open(my $fh, '>', $filename) or die "Could not open file '$filename' $!";
    print $fh Dumper( $ds_dumper_name ) . "\n";
    close $fh;
}

