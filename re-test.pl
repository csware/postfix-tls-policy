#!/usr/bin/perl

if ($ARGV[0] eq '-v') { $verbose = 1; }

test('tls_policy', 0);
print "------\nDANE:";
test('tls_policy-dane', 1);
exit;

sub test() {
  ($filename,$dane) = @_;
  open(LIST, "<$filename");
  while(<LIST>) {
    $line = $_;
    next if ($line =~ /^#/);
    if ($line =~ /^\.?([a-zA-Z0-9-.]+)\s+(.*)/) {
      $dom = $1;
      $match = $2;
    } else { next; }

    print "$dom: ";
    testdomain($dom, $match, $dane);
    print "\n";
  }
  close(LIST);
}

sub testdomain() {
($srv,$match,$dane) = @_;
if ($dane) {
  open(DEF,'posttls-finger -P /etc/ssl/certs '.$srv.' |');
} else {
  open(DEF,'posttls-finger -l secure -P /etc/ssl/certs '.$srv.' |');
}
$cnt = 0;
$ssl = 0;
$certnames = ();
while(<DEF>) {
  $line = $_;
  #print STDERR $line;
  if ($cnt == 0 && $line =~ /^posttls-finger: using DANE RR:/) {
    print ' using DANE!! ' if ($verbose);
    $ssl = 2;
    if ($match ne 'dane-only') { print ' --NOW WITH DANE!-- '; }
  }
  if ($ssl == 0 && $line =~ /^posttls-finger: > STARTTLS$/) {
    $ssl = 1;
    print ' using STARTTLS ' if ($verbose);
    if ($match eq 'may' || $match eq 'dane') {
      print ' --NOW WITH STARTTLS!-- ';
    }
  }
  if ($ssl && $line =~ /^posttls-finger: Untrusted TLS connection established/) {
    if ($ssl == 2 || $match =~ /^secure /) {
      print ' -- ATTENTION: UNTRUSTED!!! -- ';
    }
  }
  if ($ssl == 1 && $match eq 'encrypt' && $line =~ /^posttls-finger: Verified TLS connection established/) {
    print ' -- NOW CERT VERIFICABLE! -- ';
  }
  if ($ssl != 2 && $line =~ /^posttls-finger: [a-zA-Z0-9-.]+\[[0-9.:]+\]:25 (?:Matched )?(?:subjectAltName:|CommonName) ([a-zA-Z0-9.*-]+)/) {
    push(@certnames, $1);
  }
  if ($line =~ /posttls-finger: server certificate verification failed/) {
    print " -- ATTENTION: $line --";
  }
  ++$cnt;
}
if ($ssl != 2 && $match eq 'dane-only') {
  print ' -- ATTENTION: LOST DANE!!! --';
} elsif (!$ssl && ($match eq 'encrypt' || $match eq 'dane' || $match =~ /^secure /)) {
  print ' -- ATTENTION: LOST SSL!!! --';
} elsif ($ssl = 1 && $match =~ /^secure match=(.*)/) {
  $found = 0;
  foreach $requiredmatch (split(/:/, $1)) {
    foreach $cert (@certnames) {
#      print "\nchecking $requiredmatch mit $cert\n";
      if (($requiredmatch =~ /^\./ && $cert =~ /$requiredmatch$/) || $requiredmatch eq $cert) {
        $found = 1;
        last;
      }
    }
    last if ($found);
  }
  if (!$found) {
    print ' -- REQUIRED TRUST CHANGED! -- ';
  }
}
close(DEF);
}
