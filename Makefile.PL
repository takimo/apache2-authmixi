use inc::Module::Install;
name 'Apache2-AuthMixi';
all_from 'lib/Apache2/AuthMixi.pm';

requires $_ for (qw/ Net::OpenID::Consumer::Lite Apache2::Cookie /);

build_requires 'Test::More';
use_test_base;
auto_include;
WriteAll;
