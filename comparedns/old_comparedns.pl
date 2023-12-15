#!/usr/bin/perl

use Net::DNS;
use YAML::Tiny;
use Array::Compare;
use Data::Dumper;

my $yaml = YAML::Tiny->read( 'records.yaml' );

my $domains = $yaml->[0];

my $comp = Array::Compare->new;

foreach my $domain (sort keys %$domains) {
    print "$domain:\n";
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
    foreach my $recordname (sort keys %$records) {
        print "Checking record: $recordname\n";
        my $queryname = "$recordname.$domain";
        if ($recordname eq '@') {
            $queryname = $domain;
        }
        foreach my $recordtype ( @{$records->{$recordname}}) {
            # We need to investigate each record type differently
            if ($recordtype eq 'A') {
                my $result1 = $resolver1->query($queryname,$recordtype);
                if (! $result1) {
                    print("Query to $dnssrv1 failed for record type $recordtype\n");
                    next;
                }
                my $result2 = $resolver2->query($queryname,$recordtype);
                if (! $result2) {
                    print("Query to $dnssrv2 failed for record type $recordtype\n");
                    next;
                }

                my @addr1;
                foreach my $rr ( $result1->answer ) {
                    # print $rr->address."\n";
                    push @addr1, $rr->address;
                    # print Dumper $rr->{'address'};
                }
                # my @sortaddr1 = sort @addr1;
                my @addr2;
                foreach my $rr ( $result2->answer ) {
                    # print $rr->address."\n";
                    push @addr2, $rr->address;
                    # print Dumper $rr->{'address'};
                }
                # my @sortaddr2 = sort @addr2;

                if ($comp->perm(\@addr1, \@addr2)) {
                    # print "Records are OK\n";
                } else {
                    print "MISMATCH: $recordtype Records are not the same!\n";
                    print "DNS1:\n".join("\n",@addr1)."\n";
                    print "DNS2:\n".join("\n",@addr2)."\n";
                }

                # print "Expected A records: ".join(', ',@sortaddr1)."\n";
                # if (@sortaddr1 != @sortaddr2) {
                #     print "MISMATCH: A Records are not the same!\n";
                #     print "DNS1: ".join(', ',@sortaddr1)."\n";
                #     print "DNS2: ".join(', ',@sortaddr2)."\n";
                # } else {
                #     print "Records OK!\n";
                # }
            } elsif ($recordtype eq 'CNAME') {
                my $result1 = $resolver1->query($queryname,$recordtype);
                if (! $result1) {
                    print("Query to $dnssrv1 failed for record type $recordtype\n");
                    next;
                }
                my $result2 = $resolver2->query($queryname,$recordtype);
                if (! $result2) {
                    print("Query to $dnssrv2 failed for record type $recordtype\n");
                    next;
                }
                my @addr1;
                foreach my $rr ( $result1->answer ) {
                    # The CNAME target's result MAY be returned in the same
                    # result set, so we need to skip if the "owner" is not the record we are querying.
                    # print Dumper $rr;
                    # print "Origin: ".$rr->owner."\n";
                    next if ($rr->owner ne $queryname);
                    push @addr1, $rr->cname;
                }
                my @addr2;
                foreach my $rr ( $result2->answer ) {
                    # The CNAME target's result MAY be returned in the same
                    # result set, so we need to skip if the "owner" is not the record we are querying.
                    # print Dumper $rr;
                    # print "Origin: ".$rr->owner."\n";
                    next if ($rr->owner ne $queryname);
                    push @addr2, $rr->cname;
                }

                # print "Expected $recordtype records: ".join(', ',@addr1)."\n";
                if ($comp->perm(\@addr1, \@addr2)) {
                    # print "Records are OK\n";
                } else {
                    print "MISMATCH: $recordtype Records are not the same!\n";
                    print "DNS1:\n".join("\n",@addr1)."\n";
                    print "DNS2:\n".join("\n",@addr2)."\n";
                }

                

            } elsif ($recordtype eq 'TXT') {
                my $result1 = $resolver1->query($queryname,$recordtype);
                if (! $result1) {
                    print("Query to $dnssrv1 failed for record type $recordtype\n");
                    next;
                }
                my $result2 = $resolver2->query($queryname,$recordtype);
                if (! $result2) {
                    print("Query to $dnssrv2 failed for record type $recordtype\n");
                    next;
                }
                # print Dumper $result1->{'answer'};
                
                my @addr1;
                foreach my $rr ( $result1->answer ) {
                    # print $rr->address."\n";
                    push @addr1, $rr->txtdata;
                    # print Dumper $rr->{'address'};
                }
                my @addr2;
                foreach my $rr ( $result2->answer ) {
                    # print $rr->address."\n";
                    push @addr2, $rr->txtdata;
                    # print Dumper $rr->{'address'};
                }
                
                # print "Expected $recordtype records:\n";
                # print "DNS1:\n".join("\n",@addr1)."\n";

                if ($comp->perm(\@addr1, \@addr2)) {
                    # print "Records are OK\n";
                } else {
                    print "MISMATCH: $recordtype Records are not the same!\n";
                    print "DNS1:\n".join("\n",@addr1)."\n";
                    print "DNS2:\n".join("\n",@addr2)."\n";
                }
                
            } elsif ($recordtype eq 'MX') {
                my @result1 = mx($resolver1,$queryname);
                if (! @result1) {
                    print("Query to $dnssrv1 failed for record type $recordtype\n");
                    next;
                }
                my @result2 = mx($resolver2,$queryname);
                if (! @result2) {
                    print("Query to $dnssrv2 failed for record type $recordtype\n");
                    next;
                }
                # print Dumper @result1;
                # print Dumper @result2;
                # foreach my $rr (@result1) {
                #     print $rr->preference." ".$rr->exchange."\n";
                # }
                my @addr1;
                foreach my $rr ( @result1 ) {
                    # print $rr->address."\n";
                    push @addr1, $rr->preference." ".$rr->exchange;
                }
                # my @sortaddr1 = sort @addr1;
                my @addr2;
                foreach my $rr ( @result2 ) {
                    # print $rr->address."\n";
                    push @addr2, $rr->preference." ".$rr->exchange;
                }
                # my @sortaddr2 = sort @addr2;

                # print "Expected $recordtype records:\n";
                # print "DNS1:\n".join("\n",@addr1)."\n";

                if ($comp->perm(\@addr1, \@addr2)) {
                    # print "Records are OK\n";
                } else {
                    print "MISMATCH: $recordtype Records are not the same!\n";
                    print "DNS1:\n".join("\n",@addr1)."\n";
                    print "DNS2:\n".join("\n",@addr2)."\n"; 
                }

                # print "Expected MX records:\n".join("\n",@sortaddr1)."\n";
                # if (@sortaddr1 != @sortaddr2) {
                #     print "MISMATCH: MX Records are not the same!\n";
                #     print "DNS1:\n".join("\n",@sortaddr1)."\n";
                #     print "DNS2:\n".join("\n",@sortaddr2)."\n";
                # } else {
                #     print "Records OK!\n";
                # }
            } elsif ($recordtype eq 'SRV') {
                my $result1 = $resolver1->query($queryname,$recordtype);
                if (! $result1) {
                    print("Query to $dnssrv1 failed for record type $recordtype\n");
                    next;
                }
                my $result2 = $resolver2->query($queryname,$recordtype);
                if (! $result2) {
                    print("Query to $dnssrv2 failed for record type $recordtype\n");
                    next;
                }
                # print Dumper $result2->{'answer'};
                my @addr1;
                foreach my $rr ( $result1->answer ) {
                    # print $rr->target."\n";
                    # Make string out of record for easy comparision
                    push @addr1, sprintf("%d %d %d %s",$rr->priority,$rr->weight,$rr->port,$rr->target);
                    # print Dumper $rr->{'address'};
                }

                my @addr2;
                foreach my $rr ( $result2->answer ) {
                    # print $rr->priority." ".$rr->weight." ".$rr->port." ".$rr-target."\n";
                    push @addr2, sprintf("%d %d %d %s",$rr->priority,$rr->weight,$rr->port,$rr->target);
                    # print Dumper $rr->{'address'};
                }

                # print "Expected $recordtype records:\n";
                # print "DNS1:\n".join("\n",@addr1)."\n";

                if ($comp->perm(\@addr1, \@addr2)) {
                    # print "Records are OK\n";
                } else {
                    print "MISMATCH: $recordtype Records are not the same!\n";
                    print "DNS1:\n".join("\n",@addr1)."\n";
                    print "DNS2:\n".join("\n",@addr2)."\n";
                }
            } else {
                print "Record type $recordtype unimplemented at this time.\n";
            }
            # print "\n";
            # print "Record type: $recordtype\n";
            # print Dumper $recordtype;
        }
        print "\n";
    }
}
