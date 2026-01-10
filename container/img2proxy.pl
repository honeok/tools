#!/usr/bin/env perl
# SPDX-License-Identifier: Apache-2.0
#
# Description: The script recursively rewrites Docker image references in text files to use a proxy registry.
# Copyright (c) 2026 honeok <i@honeok.com>

use strict;
use warnings;

my $registry_proxy = "docker.gh-proxy.org";

my @registry_repo = (
    "docker.io",
    "gcr.io",
    "ghcr.io",
    "k8s.gcr.io",
    "mcr.microsoft.com",
    "quay.io",
    "registry.k8s.io"
);

unless (@ARGV) {
    print "Usage: $0 <file_or_directory> [file_or_directory ...]\n";
    print "Example: $0 .\n";
    exit 1;
}

my @files;

sub scan_path {
    my ($cur_path) = @_;

    # 处理常规文件
    if (-f $cur_path) {
        my $fname = $cur_path;
        $fname =~ s|.*/||;

        # 忽略隐藏文件
        return if $fname =~ /^\./;

        if (-T $cur_path) {
            push @files, $cur_path;
        }
        return;
    }

    # 递归处理目录
    if (-d $cur_path) {
        my $dname = $cur_path;
        $dname =~ s|.*/||;

        # 忽略隐藏目录
        if ($dname =~ /^\./ && $cur_path ne '.' && $cur_path ne '..') {
            return;
        }

        opendir(my $dh, $cur_path) or do {
            warn "\033[91mWarning: Cannot open directory '$cur_path': $!\033[0m\n";
            return;
        };

        while (my $ent = readdir $dh) {
            next if $ent eq '.' || $ent eq '..';

            # 路径拼接
            my $ent_path;
            if ($cur_path eq '/') {
                $ent_path = "/$ent";
            } else {
                $ent_path = "$cur_path/$ent";
            }

            scan_path($ent_path);
        }
        closedir $dh;
    }
}

foreach my $arg (@ARGV) {
    $arg =~ s|/$|| unless $arg eq '/';
    scan_path($arg);
}

unless (@files) {
    print "\033[91mNo valid text files found.\033[0m\n";
    exit 0;
}

@ARGV = @files;
$^I = "";

my $registry_regex = join("|", map { quotemeta($_) } @registry_repo);

while (<>) {
    s{
        (^\s*(?:-\s+)?image:\s*|^\s*FROM\s+(?:--platform=\S+\s+)?|--from=)
        (["']?)
        ([^\s"']+)
        (["']?)
    }{
        $1 . $2 . rewrite_image($3) . $4
    }gxe;

    print;
}

sub rewrite_image {
    my ($img) = @_;
    my $out;

    # 只允许Docker Distribution Spec标准字符: [a-zA-Z0-9._:/-@]
    # 任何包含特殊符号 (如 {} [] () "" '' $ `) 的字符串均视为非法直接跳过
    unless ($img =~ m|^[a-zA-Z0-9\.\_\-\/\:\@]+$|) {
        return $img;
    }

    if ($img =~ /^\d+$/) {
        return $img;
    }

    return $img if $img =~ /^[A-Z0-9_]+$/;
    return $img if $img =~ /^\Q$registry_proxy\E/;

    # 域名处理
    if ($img =~ m{^([^/]+)/}) {
        my $domain = $1;
        if ($domain =~ /\.|localhost/) {
            if ($domain =~ /^($registry_regex)$/) {
                $out = "$registry_proxy/$img";
            } else {
                return $img;
            }
        }
    }

    # DockerHub处理
    unless ($out) {
        my $canon = $img;
        $canon = "library/$img" unless $img =~ m{/};
        $out = "$registry_proxy/docker.io/$canon";
    }

    # 变更一致性熔断
    if (!defined $out || $out eq $img) {
        return $img;
    }

    print STDERR "[$ARGV] \033[92m\xe2\x9c\x93\033[0m $img => $out\n";
    return $out;
}
