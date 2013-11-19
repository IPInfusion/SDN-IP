#! /usr/bin/perl
##
## CLI command extractor.
## Copyright (C) 2013 IP Infusion Inc.
##

$show_flag = 0;

$ignore{'"interface IFNAME"'} = "ignore";
$ignore{'"interface LINE"'} = "ignore";
$ignore{'"interface loopback"'} = "ignore";
$ignore{'"interface manage"'} = "ignore";

$ignore{'"show interface (IFNAME|)"'} = "ignore";

$ignore{'"hostname WORD"'} = "ignore";
$ignore{'"no hostname (WORD|)"'} = "ignore";
$ignore{'"service advanced-vty"'} = "ignore";
$ignore{'"no service advanced-vty"'} = "ignore";

$ignore{'"address-family ipv4 unicast"'} = "ignore";
$ignore{'"exit-address-family"'} = "ignore";
#ifndef HAVE_EXT_CAP_ASN
$ignore{'"router bgp <1-65535>"'} = "ignore";
$ignore{'"router bgp <1-65535> view WORD"'} = "ignore";
#else
$ignore{'"router bgp <1-4294967295>"'} = "ignore";
$ignore{'"router bgp <1-4294967295> view WORD"'} = "ignore";
#endif

$ignore{'"address-family ipv4"'} = "ignore";
$ignore{'"address-family ipv4 (unicast|multicast)"'} = "ignore";
$ignore{'"address-family ipv6 (unicast|)"'} = "ignore";
$ignore{'"exit-address-family"'} = "ignore";
$ignore{'"route-map WORD (deny|permit) <1-65535>"'} = "ignore";
$ignore{'"no route-map WORD ((deny|permit) <1-65535>|)"'} = "ignore";
$ignore{'"exit"'} = "ignore";
$ignore{'"end"'} = "ignore";
$ignore{'"show running-config"'} = "ignore";
$ignore{'"line console <0-0>"'} = "ignore";
$ignore{'"line aux <0-0>"'} = "ignore";
$ignore{'"line vty <0-871> (<0-871>|)"'} = "ignore";
$ignore{'"configure terminal"'} = "ignore";
$ignore{'"enable"'} = "ignore";
$ignore{'"disable"'} = "ignore";
$ignore{'"password (8|) LINE"'} = "ignore";
$ignore{'"no password"'} = "ignore";

$ignore{'"write (file|)"'} = "ignore";
$ignore{'"write memory"'} = "ignore";
$ignore{'"copy running-config startup-config"'} = "ignore";

$ignore{'"virtual-router WORD"'} = "ignore";
$ignore{'"virtual-router <1-512>"'} = "ignore";
$ignore{'"configure virtual-router WORD"'} = "ignore";
$ignore{'"configure virtual-router <1-512>"'} = "ignore";
$ignore{'"exit virtual-router"'} = "ignore";
$ignore{'"load bgp"'} = "ignore";
$ignore{'"no load bgp"'} = "ignore";
$ignore{'"enable-vr"'} = "ignore";
$ignore{'"disable-vr"'} = "ignore";

$BLD_NAME = shift @ARGV;

if ($ARGV[0] eq "-show") {
    $show_flag = 1;
    shift @ARGV;
}

print <<EOF;
#include "pal.h"
#include "lib.h"
#include "cli.h"

EOF

if ($show_flag) {
    print "int generic_show_func (struct cli *, int, char **);\n\n";
}

foreach (@ARGV) {
    $file = $_;

    open (FH, "$ENV{COMPILER_PREFIX}gcc -E -DHAVE_CONFIG_H -DEXTRACT_CLI -I. -I.. -I../pal/api -I../pal/$BLD_NAME -I../platform/$BLD_NAME -I../lib -I../bgpd -I/usr/include/ucd-snmp -I/usr/local/include/ucd-snmp $file |");

    local $/; undef $/;
    $line = <FH>;
    close (FH);

    @defun = ($line =~ /(?:CLI|ALI)\s*\((.+?)\);?\s?\s?\n/sg);
    @install = ($line =~ /cli_install\S*\s*\([^;]+?;/sg);

    # Protocol flag.
    $protocol = "PM_EMPTY";

  if ($file =~ /lib/) {
        if ($file =~ /line.c/) {
            $protocol = "PM_EMPTY";
        }
        if ($file =~ /routemap.c/) {
            $protocol = "PM_RMAP";
        }
        if ($file =~ /filter.c/) {
            $protocol = "PM_ACCESS";
        }
        if ($file =~ /plist.c/) {
            $protocol = "PM_PREFIX";
        }
        if ($file =~ /log.c/) {
            $protocol = "PM_LOG";
        }
        if ($file =~ /keychain.c/) {
            $protocol = "PM_KEYCHAIN";
        }
    } else {
        ($protocol) = ($file =~ /\/([a-z0-9]+)/);
        $protocol =~ s/d$//;
        $protocol = "PM_" . uc $protocol;
    }

    # DEFUN process
    foreach (@defun) {
        my (@defun_array);
        @defun_array = split (/,\s*\n/);

        $str = "$defun_array[2]";
        $str =~ s/^\s+//g;
        $str =~ s/\s+$//g;
        $str =~ s/\t//g;

        # When this command string in ignore list skip it.
        next if defined ($ignore{$str});

        # Add IMI string
        $defun_array[1] .= "_imi";

        # Replace _cli with _imish.
        $defun_array[1] =~ s/_cli/_imish/;

        # Show command
        if ($defun_array[2] =~ /^\s*\"show/
            || $defun_array[1] =~ /write_terminal/) {
            if ($show_flag) {
                $defun_array[0] = "generic_show_func";
            } else {
                next;
            }
        } else {
            $defun_array[0] = NULL;
        }

        $proto = $protocol;
        if ($defun_array[2] =~ /^\s*\"show/) {
          if ($file =~ /routemap.c/
              || ($file =~ /lib/
                  && $file =~ /filter.c/)
              || $file =~ /plist.c/) {
            $proto = "PM_EMPTY";
          }
        }

        $defun_body = join (",\n", @defun_array);

        $cli = $defun_array[1];
        $cli =~ s/^\s+//g;
        $cli =~ s/\s+$//g;
        $cli =~ s/\t//g;

        $cli2str{$cli} = $str;
        $cli2defun{$cli} = $defun_body;
        $cli2proto{$cli} = $proto;
    }

    # cli_install() process

    foreach (@install) {
        my (@install_array) = split (/,/);
        my $func = pop @install_array;
        my $flags = "0";
        my $priv;
        my $mode;

        if ($install_array[0] =~ /gen/) {
            $flags = $install_array[3];
            $priv = $install_array[2];
            $mode = $install_array[1];
        } elsif ($install_array[0] =~ /imi/) {
            $flags = $install_array[4];
            $priv = $install_array[3];
            $mode = $install_array[1];
        } else {
            if ($install_array[0] =~ /hidden/) {
                $flags = "CLI_FLAG_HIDDEN";
            }
            if ($install_array[1] =~ /EXEC_PRIV_MODE/
                || $install_array[1] =~ 78) {
                $mode = "EXEC_MODE";
                $priv = "PRIVILEGE_MAX";
            } else {
                $mode = $install_array[1];
                $priv = "PRIVILEGE_NORMAL";
            }
        }

        ($cli) = ($func =~ /&([^\)]+)/);
        $cli =~ s/^\s+//g;
        $cli =~ s/\s+$//g;
        $cli =~ s/_cli/_imish/;

        # Add IMI string
        $cli .= "_imi";

        $mode =~ s/^\s+//g;
        $mode =~ s/\s+$//g;

        if (defined ($cli2defun{$cli})) {
            my ($key) = $cli2str{$cli} . "," . $mode;

            $cli2install{$key} = [ $cli, $mode, $priv, $flags ];

            push (@{$cli2pm{$key}}, $cli2proto{$cli});
        }
    }
}

foreach (keys %cli2defun) {
    printf ("IMI_ALI (%s);\n\n", $cli2defun{$_});
}

printf ("\nvoid\nimi_extracted_cmd_init (struct cli_tree *ctree)\n{\n");
foreach (keys %cli2install) {
    my $proto_str;
    $count = 0;
    printf ("  SET_FLAG (%s.flags, CLI_FLAG_SHOW);\n",
            $cli2install{$_}[0]) if $_ =~ /write terminal/;

    next if $cli2mode{$_} eq "mode";

    {
      $count = $#{$cli2pm{$_}} ;
      $proto_str = join (", &", @{$cli2pm{$_}});
    }

    if ($count == 0) {
    printf ("  cli_install_imi (ctree, %s, %s, %s, %s, &%s);\n",
            $cli2install{$_}[1], $proto_str, $cli2install{$_}[2],
            $cli2install{$_}[3], $cli2install{$_}[0]);
    } else {
        printf ("  cli_install_imi (ctree, %s, modbmap_vor (%s, &%s), %s, %s, &%s);\n",
                $cli2install{$_}[1], ($count+1), $proto_str, $cli2install{$_}[2],
                $cli2install{$_}[3], $cli2install{$_}[0]);
    }
}
printf ("}\n");

