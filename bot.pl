#!/usr/bin/perl

use strict;
use warnings;
use POE qw(Component::IRC Component::IRC::Plugin::DCC);
use Config::INI::Simple;
use DBI;
use DBD::mysql;
use Getopt::Long;

my $debug;
GetOptions ('debug' => \$debug);

if (!-e "sql.conf" || !-e "bot.conf") {
        die("Error:  Please make sure you have both \'sql.conf\' and \'bot.conf\' in this directory\n.");
}

my $sqlConfig = new Config::INI::Simple;
$sqlConfig->read( 'sql.conf' );

my $botConfig = new Config::INI::Simple;
$botConfig->read( 'bot.conf' );
my $nickname = $botConfig->{default}->{nickname};
my $server = $botConfig->{default}->{server};
my $port = $botConfig->{default}->{port};
my @channels = $botConfig->{default}->{channel};
my $nataddr = $botConfig->{default}->{nataddr};

my $dsn = "dbi:mysql:". $sqlConfig->{default}->{db} .":localhost:3306";
my $sql = DBI->connect($dsn, $sqlConfig->{default}->{user}, $sqlConfig->{default}->{passwd}) or die "Unable to connect: $DBI::errstr\n";

my %net;
my %dcc;

my $irc = POE::Component::IRC->spawn( 
   nick => $nickname,
   ircname => "NetWars IRC Bot",
   username => $nickname,
   server => $server,
   nataddr => $nataddr,
) or die "Oh noooo! $!";

POE::Session->create(
    package_states => [
        main => [ qw(_start irc_001 irc_public irc_msg irc_dcc_request irc_dcc_chat irc_dcc_start irc_dcc_done irc_dcc_error) ],
    ],
    heap => { irc => $irc },
);

$poe_kernel->run();

sub _start {
    my $heap = $_[HEAP];
    my $irc = $heap->{irc};
    $irc->yield( register => 'all' );
    $irc->yield( connect => { } );
    return;
 }

sub irc_001 {
    my $sender = $_[SENDER];
    my $irc = $sender->get_heap();
    print "Connected to ", $irc->server_name(), "\n" if defined($debug);
    $irc->yield( join => $_ ) for @channels;
    return;
}

sub irc_public {
        my ($sender, $who, $where, $what) = @_[SENDER, ARG0 .. ARG2];
        my $nick = ( split /!/, $who )[0];
        my $channel = $where->[0];
        if ($what =~ /$nickname: chat$/i) {
                $irc->yield(dcc => $nick => "CHAT");
        }
}

sub irc_msg {
        my ($who, $msg) = @_[ARG0, ARG2];
        my $nick = (split /!/,$who)[0];
        print "$nick> $msg\n" if defined($debug);
}

sub irc_dcc_request {
        my ($who, $type, $cookie) = @_[ARG0, ARG1, ARG3];
        my $nick = (split /!/,$who)[0];
        print "Received DCC $type from $nick\n" if defined($debug);
        if (!defined($dcc{$nick}) || $dcc{$nick}{on} != 1) {
                $irc->yield(dcc_accept => $cookie);
                $dcc{$nick}{on} = 1;
        }else{
                print "DCC Chat already exists from $nick\n" if defined($debug);
        }
}
sub irc_dcc_chat {
        my ($cookie, $nick, $msg) = @_[ARG0, ARG1, ARG3];
        my ($query, $username, $passwd);
        print "=$nick> $msg\n" if defined($debug);
        if ($msg =~ /^login (.+) (.+)$/) {
                if (!chk_loggedin($nick)) {
                        $username = $1;
                        $passwd =  $2;
                        $query = $sql->prepare("SELECT * FROM users WHERE `username`=? AND `password`=?");
                        $query->execute($username, $passwd);
                        if ($query->rows == 0) {
                                $irc->yield(dcc_chat => $cookie => "[\002Error\002] Your login credentials are invalid, please try again.");
                        }elsif ($query->rows == 1) {
                                my @data = $query->fetchrow_array();
                                $irc->yield(dcc_chat => $cookie => "[\002Logon\002] Welcome back $username, your last login was on \002$data[3]\002.");
                                $net{$nick}{loggedon} = 1;
                                $net{$nick}{username} = $username;
                                $net{$nick}{ip} = $data[2];
                        }
                }else{
                        $irc->yield(dcc_chat => $cookie => "[\002Error\002] You are already logged in.");
                }
        }
        if ($msg =~ /^register (.+) (.+)$/) {
                if (!chk_loggedin($nick)) {
                        $username = $1;
                        $passwd = $2;
                        $query = $sql->prepare("SELECT * FROM users WHERE `username`=?");
                        $query->execute($username);
                        if ($query->rows == 0) {
                                my $randip = gen_randip();
                                $query = $sql->prepare("INSERT INTO users (ip, username, password) VALUES(?, ?, ?)");
                                $query->execute($randip, $username, $passwd);
                                $query = $sql->prepare("INSERT INTO ips (ip, owner, vulns) VALUES(?, ?, ?)");
                                $query->execute($randip, $username, "PNP ASN WKS LSASS");
                                $net{$nick}{loggedon} = 1;
                                $net{$nick}{username} = $username;
                                $net{$nick}{ip} = $randip;
                                $irc->yield(dcc_chat => $cookie => "[\002Logon\002] Registration complete!  Please remember your password.  To get started, type \002help\002.");
                        }else{
                                $irc->yield(dcc_chat => $cookie => "[\002Error\002] The username you have chosen is taken.");
                        }
                }else{
                        $irc->yield(dcc_chat => $cookie => "[\002Error\002] You are already logged in.");
                }
        }
        if ($msg =~ /^scan (.+)$/) {
                if (chk_loggedin($nick)) {
                        my $ip = (split /\s/,$msg)[1];
                        if (is_valid_ip($ip)) {
                                 chk_vulns($ip,$nick,$cookie);
                                 chk_easter_egg($ip,$nick,$cookie);
                        }else{
                                $irc->yield(dcc_chat => $cookie => "[\002Error\002] The address you have entered is either invalid or inactive.");
                        }
                }else{
                        $irc->yield(dcc_chat => $cookie => "[\002Error\002] You are not logged in.");
                }
        }
        if ($msg =~ /^help$/) {
                $irc->yield(dcc_chat => $cookie => "[\002Help\002] If this is your first time, please type \002help firsttime\002.");
                $irc->yield(dcc_chat => $cookie => "[\002Help\002] Here are a list of areas for help:");
        }
        if ($msg =~ /^help (.+)$/) {
                if ($1 eq "firsttime") {
                        $irc->yield(dcc_chat => $cookie => "[\002Help\002] Initializing tutorial program...");
                        $irc->yield(dcc_chat => $cookie => "[\002Tutorial\002] To begin, you need some money to purchase stuff later on.  You'll receive money for unlocking achievements and when you successfully complete missions.");
                        $irc->yield(dcc_chat => $cookie => "[\002Tutorial\002] Your first assignment is simply downloading a tool to exploit vulnerabilities.");
                        $irc->yield(dcc_chat => $cookie => "[\002Tutorial\002] For details on this assignment, type \002assignments\002.")
                }
        }
        if ($msg =~ /^assignments$/) {
                if (chk_loggedin($nick)) {
                        print "checking for assignments... " if defined($debug);
                        $query = $sql->prepare("SELECT (assignments) FROM `users` WHERE `username`=?");
                        print "username = $net{$nick}{username}... " if defined($debug);
                        $query->execute($net{$nick}{username});
                        my @id=$query->fetchrow_array();
                        printf("found %d ids\n",$#id+1) if defined($debug);
                        $query = $sql->prepare("SELECT * FROM assignments WHERE `id`=?");
                        $query->execute($id[0]);
                        my @data = $query->fetchrow_array();
                        $irc->yield(dcc_chat => $cookie => "[\002Assignment\002] ID: $data[0] - Description: $data[1]");
                }
        }
}
sub irc_dcc_error {
        my ($nick) = ARG2;
        $dcc{$nick}{on} = 0;
}
sub irc_dcc_done {
        my ($cookie, $nick, $type) = @_[ARG0 .. ARG2];
        $dcc{$nick}{on} = 0;
}
sub irc_dcc_start {
        my ($cookie, $nick) = @_[ARG0, ARG1];
        $irc->yield(dcc_chat => $cookie => "[\002Start\002] To login, type \002login username password\002.  If this is your first time, please type \002register username password\002");
}

sub is_valid_ip {
        my $ip = $_[0];
        print "is_valid_ip -> $ip\n" if defined($debug);
        if ($ip =~ /^\d\d?\d?\.\d\d?\d?.\d\d?\d?.\d\d?\d?$/) {
                my $query = $sql->prepare("SELECT * FROM ips WHERE `ip`=?");
                $query->execute($ip);
                if ($query->rows == 1) {
                        return 1;
                }else{
                        return 0;
                }
        }else{
                return 0;
        }
}
sub chk_easter_egg($$$) {
        my ($ip,$nick,$cookie) = @_;
        my $query = $sql->prepare("SELECT easteregg, eegginfo, eeggid FROM ips WHERE `ip`=?");
        $query->execute($ip);
        my @info = $query->fetchrow_array();
        if (defined($info[0])) {
                my ($easteregg, $eegginfo, $eeggid) = @info;
                $query = $sql->prepare("SELECT eeggids FROM users WHERE `username`=?");
                $query->execute($net{$nick}{username});
                if ($query->rows == 0) {
                        $irc->yield(dcc_chat => $cookie => "[\002Info\002] You've gained an achievement!");
                        if ($eegginfo eq "money") {
                                $irc->yield(dcc_chat => $cookie => "[\002Gift\002] Scanning \002$ip\002 has given you an extra \002\$$easteregg in money!\002");
                        }
                        if ($eegginfo eq "conn") {
                                $irc->yield(dcc_chat => $cookie => "[\002Gift\002] Scanning \002$ip\002 has given you a new type \002$easteregg connection setup\002!");
                        }
                }else{
                        my @row = $query->fetchrow_array();
                        if ($row[0] !~ /\s?$info[2]\s?/) {
                                $irc->yield(dcc_chat => $cookie => "[\002Info\002] You've gained an achievement!");
                                if ($eegginfo eq "money") {
                                        $irc->yield(dcc_chat => $cookie => "[\002Gift\002] Scanning \002$ip\002 has given you an extra \002\$$easteregg in money!\002");
                                }
                                if ($eegginfo eq "conn") {
                                        $irc->yield(dcc_chat => $cookie => "[\002Gift\002] Scanning \002$ip\002 has given you a new type \002$easteregg connection setup\002!");
                                }
                        }
                }

        }
}
sub chk_vulns($$$) {
        my ($ip,$nick,$cookie) = @_;
        my $query = $sql->prepare("SELECT (vulns) FROM ips WHERE `ip`=?");
        $query->execute($ip);
        my @vulns = $query->fetchrow_array();
        $irc->yield(dcc_chat => $cookie => "[\002Vulns\002] $vulns[0]");
}
sub chk_loggedin {
        my $nick = $_[0];
        print "chk_loggedin() -> $nick = " if defined($debug);
        if (!defined($net{$nick}{loggedon}) || (defined($net{$nick}{loggedon}) && $net{$nick}{loggedon} != 1)) {
                print "false\n" if defined($debug);
                return 0;
        }else{
                print "true\n" if defined($debug);
                return 1;
        }
}
sub gen_randip {
        my ($a, $b, $c, $d) = "0";
        $a = int(rand(255));
        $b = int(rand(255));
        $c = int(rand(255));
        $d = int(rand(255));
        my $ip = "$a.$b.$c.$d";
        print "$ip" if defined($debug);
        my $query = $sql->prepare("SELECT * FROM ips WHERE `ip`=?");
        $query->execute($ip);
        if ($query->rows == 0) {
                print " - not taken\n" if defined($debug);
                return $ip;
        }else{
                print " - taken, trying again...\n" if defined($debug);
                gen_randip();
        }
}
