use strict;
use warnings;
BEGIN { $ENV{PERL_DL_NONLAZY} = 0; }
use Test::More tests => 1;

BEGIN { use_ok 'Apache2::AuthMixi' }
