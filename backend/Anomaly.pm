#!/usr/bin/env perl

# Name of the plugin
package Anomaly;

use strict;
use warnings;
use NfProfile;
use NfConf;
use Sys::Syslog;
use LWP::UserAgent;
use JSON;
use Digest::MD5 qw(md5_hex);

our %cmd_lookup = ('status' => \&status,);

our $VERSION = 100;

my $EODATA = ".\n";

my ($nfdump, $PROFILEDIR);

sub status {
    my $socket = shift;
    my $opts   = shift;

    syslog('info', "ANOMALY action:status result:init src:${$opts}{src}");

    # Prepare answer
    my %response;
    $response{status} = 'running...';
    $response{endpoint}
        = ${NfConf::PluginConf}{Anomaly}{reputation_api_endpoint};
    $response{ports_file} = ${NfConf::PluginConf}{Anomaly}{ports_file};
    $response{threshold}  = ${NfConf::PluginConf}{Anomaly}{threshold};

    syslog('info', "ANOMALY action:status result:finish src:${$opts}{src}");

    Nfcomm::socket_send_ok($socket, \%response);
    return;
}    # End of status

#
# Periodic data processing function
#	input:	hash reference including the items:
#			'profile'		profile name
#			'profilegroup'	profile group
#			'timeslot' 		time of slot to process: Format yyyymmddHHMM
#
sub run {
    my $argref       = shift;
    my $profile      = ${$argref}{profile};
    my $profilegroup = ${$argref}{profilegroup};
    my $timeslot     = ${$argref}{timeslot};

    syslog('debug', "ANOMALY action:run time:$timeslot result:init");

    my %profileinfo = NfProfile::ReadProfile($profile, $profilegroup);
    my $profilepath = NfProfile::ProfilePath($profile, $profilegroup);
    my $all_sources = join ':', keys %{$profileinfo{channel}};
    my $netflow_sources = "$PROFILEDIR/$profilepath/$all_sources";

    my $anomaly_ports = ${NfConf::PluginConf}{Anomaly}{ports_file};

    my %filters;
    $filters{syn}
        = "proto tcp and (src port > 1023 and dst port in [ \@include $anomaly_ports ]) and flags S and not flags RAFPU";
    $filters{udp}
        = "proto udp and (src port > 1023 and dst port in [ \@include $anomaly_ports ])";
    $filters{syn_closed}
        = "proto tcp and (dst port in [ \@include $anomaly_ports ]) and flags RA and not flags FPU";
    $filters{null}
        = "proto tcp and (dst port in [ \@include $anomaly_ports ]) and flags R and not flags PUSFA and packets = 1";

    my $hash = {};

    foreach my $type (keys %filters) {
        syslog('debug', "ANOMALY action:run.get_data filter:$type");
        $hash->{$type}
            = get_data($filters{$type}, $netflow_sources, $timeslot);
    }

    save_data($hash);

    syslog('debug', "ANOMALY action:run time:$timeslot result:finish");

    return;
}    # End of run

#
# The Init function is called when the plugin is loaded. It's purpose is to give
#   the plugin the possibility to initialize itself. The plugin should return 1
#   for success or 0 for failure. If the plugin fails to initialize, it's
#   disabled and not used. Therefore, if you want to temporarily disable your
#   plugin return 0 when Init is called.
#
sub Init {
    syslog('info', 'ANOMALY action:init');

    # Init some vars
    $nfdump     = "$NfConf::PREFIX/nfdump";
    $PROFILEDIR = "$NfConf::PROFILEDATADIR";

    return 1;
}

#
# The Cleanup function is called, when nfsend terminates. It's purpose is to
#   give the plugin the possibility to cleanup itself. It's return value is
#   discard.
#
sub Cleanup {
    syslog('info', 'ANOMALY action:cleanup');

    return;
}

#
# perl trim function - remove leading and trailing whitespace
#
sub trim {
    my $string = shift;

    $string =~ s/^\s+//xsm;
    $string =~ s/\s+$//xsm;

    return $string;
}

#
# The get_data function is called, when run fuction process data. It works by
#   receiving a filter, where it will be matched with NetFlow data and returns a
#   results array
#
sub get_data {
    my $filter          = shift;
    my $netflow_sources = shift;
    my $timeslot        = shift;

    my $result = [];

    my @output
        = `$NfConf::PREFIX/nfdump -q -M $netflow_sources -r nfcapd.$timeslot -o "fmt:\%sa:\%sp:\%dp:" "$filter"`;
    syslog('info', 'ANOMALY action:get_data result:init info:cmd');

    @output = sort @output;

    my $id         = 1;
    my $id_alerts  = 0;
    my %suspicious = (
        source_ip             => 0,
        last_source_port      => 0,
        source_port           => [],
        last_destination_port => 0,
        destination_port      => [],
        probes                => 1,
    );

    if ($#output < 1) {
        syslog('info', 'ANOMALY action:get_data result:finish info:0');
        return;
    }

    syslog('info', "ANOMALY action:get_data result:middle info:$#output");

    foreach my $line (@output) {

        # clear \n
        chomp $line;

        # Parsing lines
        my ($source_ip, $source_port, $destination_port) = split /:/smx, $line;

        # trim variables
        $source_ip        = trim($source_ip);
        $source_port      = trim($source_port);
        $destination_port = trim($destination_port);


        # Verifying that the line is identical to previous line
        if (   $suspicious{source_ip} eq $source_ip
            && $suspicious{last_source_port} eq $source_port
            && $suspicious{last_destination_port} eq $destination_port)
        {

            # increasing the number of probes
            ++$suspicious{probes};

            next;
        }

        # if ip address registry does not exist in the hash
        if ($suspicious{source_ip} ne $source_ip) {

            my $size = scalar $result;
            if ($size > 0) {

                # If there is no new IP address, the old IP address had another
                #   probe that was not counted
                ++$suspicious{probes};

                # Save the entry (previous ip address) in store array
                my %local = %suspicious;
                push $result, \%local;

                # Clear the probes information
                $suspicious{probes} = 1;
            }

            # Saves the previous content in the global hash
            %suspicious = (
                source_ip             => $source_ip,
                last_source_port      => $source_port,
                source_port           => [$source_port],
                last_destination_port => $destination_port,
                destination_port      => [$destination_port],
            );
            next;
        }

        # if the previous IP source port is the same, only the destination port
        #   may have changed
        if (   $suspicious{source_ip} eq $source_ip
            && $suspicious{last_source_port} eq $source_port)
        {

            # increasing the number of probes
            ++$suspicious{probes};

            # if the destination port does not exist, add it
            my $occurrences
                = grep {$destination_port} $suspicious{destination_port};
            if ($occurrences == 0) {
                push @{$suspicious{destination_port}}, $destination_port;
            }
            next;
        }

  #  The source port is different, we check if the destination port is the same
        if (   $suspicious{source_ip} eq $source_ip
            && $suspicious{last_source_port} ne $source_port)
        {

            # increasing the number of probes
            ++$suspicious{probes};

            # If the destination port is the same, only add the source port
            if ($suspicious{last_destination_port} eq $destination_port) {
                push @{$suspicious{source_port}}, $source_port;
                $suspicious{last_source_port} = $source_port;

            }

           # The source port is different and the destination port is different
            else {

                push @{$suspicious{source_port}}, $source_port;
                $suspicious{last_source_port} = $source_port;

                # if the destination port does not exist, add it
                my $occurrences
                    = grep {$destination_port} $suspicious{destination_port};
                if ($occurrences == 0) {
                    push @{$suspicious{destination_port}}, $destination_port;
                }

                $suspicious{last_destination_port} = $destination_port;
            }
            next;
        }

    }    # end of foreach

    # remove first element
    shift $result;

    syslog('info', "ANOMALY action:get_data result:finish info:$#{$result}");
    return $result;
}

#
# The save_data function is called, after get_data function. She run sending the
#   data received by the first parameter (which are above the threshold set by
#   the threshold config parameter) to reputation_api.
#
#
sub save_data {
    my $data = shift;

    my $count_objects = 0;
    syslog('info',
        'ANOMALY action:save_data result:init endpoint:'
            . ${NfConf::PluginConf}{Anomaly}{reputation_api_endpoint});

    # for all types
    foreach my $type (keys $data) {

        # for all events of this type
        foreach my $event (@{$data->{$type}}) {

            # checking threshold limits
            if ($event->{probes} >= ${NfConf::PluginConf}{Anomaly}{threshold})
            {

                # generating POST content
                my %content = (
                    timestamp => time,
                    item      => $event->{source_ip},
                    category  => uc 'NETFLOW.' . $type,
                    msg       => encode_json($event),
                    log_id    => md5_hex(to_json($event)),
                );

                # making the request
                my $ua = LWP::UserAgent->new;
                $ua->timeout(1);
                my $response = $ua->post(
                    ${NfConf::PluginConf}{Anomaly}{reputation_api_endpoint},
                    'Content-type' => 'application/json;charset=utf-8',
                    'Content'      => encode_json(\%content),
                );

                $count_objects++;
            }
        }
    }

    syslog('info',
        "ANOMALY action:save_data result:finish info:$count_objects");
    return;
}

1;
