# Copyright 2018 dormando. Same terms as mc-crusher
#
# Why is this so complicated? Well, mc-crusher, sample, latency sample,
# memcached, etc, should all be runnable on different machines. It should even
# allow multiple mc-crushers on multiple different machines, and samplers on
# different machines.
#
# This currently only all runs on a single machine.
package Memcached::McCrusher;

use warnings;
use strict;
use IO::Socket::INET;

use POSIX ":sys_wait_h";

# TODO: argument validation
sub new {
    my ($class, %args) = @_;
    $args{server_ip} = "127.0.0.1" unless defined $args{server_ip};
    $args{server_port} = 11211 unless defined $args{server_port};
    return bless \%args, $class;
}

# Start the memcached with the supplied arguments
# TODO: this assumes you're describing the server/port here.
# do some argument parsing and pull it out from there if necessary
sub start_memcached {
    my $self = shift;

    my $args = $self->{server_args};
    my $bin  = $self->{server_bin};

    # TODO: array of IPs?
    my $ip   = $self->{server_ip};
    my $port = $self->{server_port};

    # TODO: unix domain sockets
    $args .= " -l $ip -p $port";

    my $child = fork();

    if ($child) {
        print "$bin $args\n";
        $self->{server_pid} = $child;
        sleep 1;
        for (1 .. 10) {
            my $conn = IO::Socket::INET->new(PeerAddr => "$ip:$port");
            if ($conn) {
                $self->{server_conn} = $conn;
                return $conn;
            }
            sleep 1;
        }
    } else {
        # child
        exec "$bin $args";
    }
}

sub stop_memcached {
    my $self = shift;
    return unless $self->{server_pid};
    $self->_kill_pid($self->{server_pid});
}

# TODO: Also take a conn argument
# (and add function to get more sockets)
sub stats {
    my $self = shift;
    my $subcmd = shift;
    $subcmd = $subcmd ? " $subcmd" : "";
    die "No memcached running" unless $self->{server_conn};
    my $sock = $self->{server_conn};
    print $sock "stats$subcmd\r\n";
    my %stats = ();
    while (<$sock>) {
        last if /^END/;
        if ($_ =~ m/^STAT (\S+)\s+([^\r\n]+)/) {
            $stats{$1} = $2;
        }
    }
    return \%stats;
}

sub warm {
    my $self = shift;
    my $sock = $self->{server_conn};
    my %a = @_;

    my $s = $a{size};
    my $p = $a{prefix};
    my $e = $a{exptime} || 0;
    my $f = $a{flags} || 0;
    my $c = $a{count};
    my $data = 'x' x $s;

    for (1 .. $c) {
        print $sock "set $p${_} $f $e $s noreply\r\n", $data, "\r\n";
        print "warm: $_\n" if ($_ % int($c / 10) == 0);
    }
}

# mc-crusher can take a while to start up if it has to pre-generate and/or
# shuffle the key list. Wait until it's running so the samplers are accurate.
# FIXME: mc-crusher should really block all threads until everyone's
# started...
#
# TODO: optionally, take a crush config directly
sub start_crush {
    my $self = shift;

    my $bin = $self->{crush_bin};
    my $config = $self->{crush_config};

    my $odir = $self->{output_dir} or die "missing output_dir";
    my $cfile = "$odir/crush_config";
    open(my $cfh, "> $cfile") or die "couldn't open $cfile for writing";
    print $cfh $config;
    close($cfh);

    my $cout = "$odir/crush_output";
    my $ip = $self->{server_ip};
    my $port = $self->{server_port};

    my $child = fork();

    if ($child) {
        print "$bin $cfile $ip $port\n";
        $self->{crush_pid} = $child;
        # try to open output file in loop
        # watch for "done initializing\n"
        # TODO: non-block reads, check for process death
        sleep 1;
        for (1..999) {
            if (-e $cout) {
                open(my $r, "< $cout") or die "Couldn't re-open $cout from parent";
                while (my $l = <$r>) {
                    if ($l =~ m/^done initializing/) {
                        # Tests are fully running.
                        return;
                    }
                }
            }
            sleep 1;
        }
        die "mc-crusher failed to initialize!";
    } else {
        # Child, re-open STDERR/STDOUT
        # NOTE: If the child doesn't autoflush STDOUT, it can get lost :|
        open(STDOUT, ">", $cout) or die "STDOUT -> $cout: $!";
        open(STDERR, ">&STDOUT", ) or die "STDERR -> STDOUT: $!";
        exec $bin, $cfile, $ip, $port;
    }
}

sub stop_crush {
    my $self = shift;
    return unless $self->{crush_pid};
    $self->_kill_pid($self->{crush_pid});
}

# takes the mc-crusher config to run
# TODO: Take an array and flatten it
sub crush_config {
    my $self = shift;
    my $config = shift;
    $self->{crush_config} = $config;
}

# FIXME: Just keep an array
sub sample_args {
    my $self = shift;
    my %a = @_;
    $self->{sample_args} = $self->{server_ip} . ':' . $self->{server_port}
        . ' ' . join(' ', $a{runs}, $a{period}, @{$a{stats}});
}

sub start_sample {
    my $self = shift;

    die "please set sample_args" unless $self->{sample_args};
    my $bin = $self->{sample_bin};

    my $odir = $self->{output_dir};
    my $cout = "$odir/bench_sample";
    my $args = $self->{sample_args};

    my $child = fork();

    if ($child) {
        print "$bin $args\n";
        $self->{sample_pid} = $child;
        return;
    } else {
        # Child, reopen STDOUT/STDERR
        open(STDOUT, ">", $cout) or die "STDOUT -> $cout: $!";
        open(STDERR, ">&STDOUT", ) or die "STDERR -> STDOUT: $!";
        my @a = split(/\s+/, $args);
        exec $bin, @a;
    }
}

sub latency_args {
    my $self = shift;
    my %a = @_;
    my $args = "--server " . $self->{server_ip} .
               " --port " . $self->{server_port};
    for my $key (keys %a) {
        $args .= " --$key " . $a{$key};
        chop $args unless $a{$key};
    }
    $self->{latency_args} = $args;
}

sub start_latency {
    my $self = shift;

    die "please set latency_args" unless $self->{latency_args};
    my $bin = $self->{latency_bin};

    my $odir = $self->{output_dir};
    my $cout = "$odir/latency_sample";
    my $args = $self->{latency_args};

    my $child = fork();

    if ($child) {
        print "$bin $args\n";
        $self->{latency_pid} = $child;
        return;
    } else {
        # Child, reopen STDOUT/STDERR
        open(STDOUT, ">", $cout) or die "STDOUT -> $cout: $!";
        open(STDERR, ">&STDOUT", ) or die "STDERR -> STDOUT: $!";
        my @a = split(/\s+/, $args);
        exec $bin, @a;
    }
}

sub stop_latency {
    my $self = shift;
    return unless $self->{latency_pid};
    # give it a chance to print final dump
    $self->_kill_pid($self->{latency_pid}, 2);
}

# run a sampler set.
# primarily we're running bench-sample, but optionally latency-sampler
sub sample_run {
    my $self = shift;
    my %a = @_;

    $self->start_sample();
    $self->start_latency();

    # wait for bench sampler to exit
    waitpid($self->{sample_pid}, 0);
    # no forecfully kill the latency sampler, which should print its summary
    $self->stop_latency();
}

# Allow changing the output directory mid-run
sub output_dir {
    my $self = shift;
    $self->{output_dir} = shift;
}

# TODO: timeout and kill harder via WNOHANG
sub _kill_pid {
    my $self = shift;
    my $pid = shift;
    my $sig = shift || 15;
    kill $sig, $pid;
    waitpid($pid, 0);
}

# Kill all processes we had running
sub DESTROY {
    my $self = shift;
    $self->stop_memcached();
    $self->stop_crush();
}

1;
