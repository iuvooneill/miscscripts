#!/usr/bin/perl

use Net::DNS;
use YAML::Tiny;
use Array::Compare;
use Data::Dumper;

my $yaml = YAML::Tiny->read( 'records.yaml' );

my $domains = $yaml->[0];

my $comp = Array::Compare->new;

my $totalrecords = 0;
my $errors = 0;

foreach my $domain (sort keys %$domains) {
    print "\nDOMAIN $domain:\n";
    my $dnssrv1 = $domains->{$domain}->{'dnsservers'}[0];
    my $resolver1 = Net::DNS::Resolver->new;
    $resolver1->tcp_timeout(5);
    $resolver1->nameservers($dnssrv1);
    my $dnssrv2 = $domains->{$domain}->{'dnsservers'}[1];
    my $resolver2 = Net::DNS::Resolver->new;
    $resolver2->tcp_timeout(5);
    $resolver2->nameservers($dnssrv2);
    
    
    print "DNS1: $dnssrv1\tDNS2: $dnssrv2\n\n";
    my $records = $domains->{$domain}->{'records'};
    foreach my $recordname (@$records) {
        # print "Checking record: $recordname\n";
        my $queryname = "$recordname.$domain";
        if ($recordname eq '@') {
            $queryname = $domain;
        }
        my $result1 = $resolver1->query($queryname,'ANY');
        if (! $result1) {
            print "Record: $recordname: not found or resolver error from $dnssrv1\n";
            $errors++;
            next;
        }
        my $result2 = $resolver2->query($queryname,'ANY');
        if (! $result2) {
            print "Record: $recordname: not found or resolver error from $dnssrv2\n";
            $errors++;
            next;
        }
        # print Dumper $result1;

        # Take each answer record, and place it in an array
        my @addr1;
        my @addr2;

        foreach my $rr ( $result1->answer ) {
            # Don't need SOA records, or NS records for the apex as we expect them to be different
            # unless we are checking currently active servers
            next if ((($queryname eq $domain) && ($rr->type eq 'NS')) or $rr->type eq 'SOA');
            # If the primary result is a CNAME, ignore all the possible additional records
            if ($rr->type eq 'CNAME') {
                # Empty the existing array, push the record, then skip the rest
                @addr1 = ( $rr->plain );
                last;
            } else {
                push @addr1, $rr->plain;
            }
            # print $rr->type." ";
            # print $rr->plain."\n";
        }
        foreach my $rr ( $result2->answer ) {
            # Don't need SOA records, or NS records for the apex as we expect them to be different
            # unless we are checking currently active servers
            next if ((($queryname eq $domain) && ($rr->type eq 'NS')) or $rr->type eq 'SOA');
            # If the primary result is a CNAME, ignore all the possible additional records
            if ($rr->type eq 'CNAME') {
                # Empty the existing array, push the record, then skip the rest
                @addr2 = ( $rr->plain );
                # print $rr->type." ";
                # print $rr->plain."\n";
                last;
            } else {
                push @addr2, $rr->plain;
            }
        }

        # print "Expected records:\n".join("\n",sort @addr1)."\n";
        if ($comp->perm(\@addr1, \@addr2)) {
            # print "Records are OK\n";
            $totalrecords++;
        } else {
            print "\nRecord: $recordname: MISMATCH: Records are not the same!\n";
            print "DNS1:\n".join("\n",sort @addr1)."\n";
            print "DNS2:\n".join("\n",sort @addr2)."\n\n";
            $errors++;
        }
        # print "\n";
        
    }
}

print "\nTotal records checked : $totalrecords\n";
print "Records with errors   : $errors\n";

if ($errors > 0) {
    print "\nTHERE WERE ERRORS\n";
}
