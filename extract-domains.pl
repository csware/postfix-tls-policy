#!/usr/bin/perl
if ($ARGV[0] =~ /\.gz$/) {
  open(LOG, "gunzip < $ARGV[0] |");
} else {
  open(LOG, "<$ARGV[0]");
}
while(<LOG>) {
  $line = $_;
  #Sep 15 22:22:32 srv1 postfix/smtp[26806]: 49C05220A5C: to=<test@md-textil.de>,
  if ($line =~ /^\S+ \d+ \d+:\d+:\d+ \S+ postfix\/smtp\[\d+\]: [^:]+: to=<[^@]+@([^>]+)>, .*, status=sent/) {
      #print lc($1)."\n";
      ++$seen{lc($1)};
  }
}

foreach $domain (sort keys %seen) {
  print "$domain: $seen{$domain}\n";
}
