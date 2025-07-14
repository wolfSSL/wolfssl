#!/usr/bin/env perl

use strict;
use warnings;

use Time::Piece;

my %oid_sum_xors = ();

sub oid_sum {
    my @a =  @_;
    my $oid_sum = 0;

    for (my $i = 0; $i < 0+@a; $i++) {
        $oid_sum += $a[$i];
    }

   return $oid_sum;
}

sub oid_sum_xor {
    my @a =  @_;
    my $oid_val = 0;

    for (my $i = 0; $i < 0+@a; $i++) {
        $oid_val ^= (~$a[$i]) << (($i * 8) % 32);
    }

    return ($oid_val & 0x7fffffff);
}


sub dotted_to_array {
    my $dotted = $_[0];
    my @a = ();

    my $d = ($dotted->[0] * 40) + $dotted->[1];
    my $j = 0;
    for (my $i = 1; $i < 0+@$dotted; $i++) {
        if ($d > 0) {
            my $y = $j;
            my $mask = 0;
            while ($d > 0) {
                $a[$j] = ($d & 0x7f) | $mask;
                $j++;
                $d >>= 7;
                $mask |= 0x80;
            }
            my $z = $j - 1;
            while ($y< $z) {
                $mask = $a[$y];
                $a[$y] = $a[$z];
                $a[$z] = $mask;
                $y++;
                $z--;
            }
        }
        else {
            $a[$j] = 0x00;
            $j++;
        }

        if ($i < 0+@$dotted - 1) {
            $d = $dotted->[$i + 1];
        }
    }

    return @a;
}

sub oid_array_to_string {
    my @a = @_;
    my $str = "";

    for (my $i = 0; $i < 0+@a; $i++) {
        $str = $str . sprintf("0x%02x", $a[$i]);
        if ($i < 0+@a-1) {
            $str = $str . ",";
        }
    }
    return $str;
}

sub dotted_to_string {
    my $a = $_[0];
    my $str = "";

    for (my $i = 0; $i < 0+@$a; $i++) {
        $str = $str . sprintf("%d", $a->[$i]);
        if ($i < 0+@$a-1) {
            $str = $str . ".";
        }
    }
    return $str;
}

sub print_enum {
    my $name = $_[0];
    my $ext = $_[1];
    my $oids = $_[2];
    my $eq_col = $_[3];
    my $comment_col = $_[4];

    print "enum " . $name . " {\n";
    print "#ifdef WOLFSSL_OLD_OID_SUM\n";
    for (my $i = 0; $i < 0+@$oids; $i++) {
        my @a = dotted_to_array($oids->[$i]->{oid});
        my $sum = oid_sum(@a);
        if (exists $oids->[$i]->{oid_sum}) {
            $sum = $oids->[$i]->{oid_sum};
        }
        if (exists $oids->[$i]->{add_sum}) {
            $sum += $oids->[$i]->{add_sum};
        }

        print "    /* " . oid_array_to_string(@a) . "  */\n";
        if ($comment_col == 0) {
            print "    /* " . dotted_to_string($oids->[$i]->{oid}) . " */\n";
        }
        my $str = "    " . $oids->[$i]->{name} . $ext . " ";
        $str .= " " x ($eq_col - length($str));
        $str .= "= " . $sum;
        if ($i < 0+@$oids-1) {
            $str .= ",";
        }
        print $str;
        if ($comment_col > 0) {
            print " " x ($comment_col - length($str));
            print " /* " . dotted_to_string($oids->[$i]->{oid}) . " */\n";
        }
        else {
            print "\n";
        }
    }
    print "#else\n";
    for (my $i = 0; $i < 0+@$oids; $i++) {
        my @a = dotted_to_array($oids->[$i]->{oid});
        my $sum = oid_sum_xor(@a);

        if (not exists $oids->[$i]->{same} and exists $oid_sum_xors{$sum}) {
            print STDERR "Clash of " . $oids->[$i]->{name} . " with " . $oid_sum_xors{$sum} . "\n";
        } else {
            $oid_sum_xors{$sum} = $oids->[$i]->{name};
        }

        print "    /* " . oid_array_to_string(@a) . "  */\n";
        if ($comment_col == 0) {
            print "    /* " . dotted_to_string($oids->[$i]->{oid}) . " */\n";
        }
        my $str =  "    " . $oids->[$i]->{name} . $ext . " ";
        $str .= " " x ($eq_col - length($str));
        $str .= sprintf("= 0x%08x", $sum);
        if ($i < 0+@$oids-1) {
            $str .= ",";
        }
        print $str;
        if ($comment_col > 0) {
            print " " x ($comment_col - length($str));
            print " /* " . dotted_to_string($oids->[$i]->{oid}) . " */\n";
        }
        else {
            print "\n";
        }
    }
    print "#endif\n";
    print "};\n\n"
}

sub print_sum_enum {
    print_enum($_[0] . "_Sum", $_[1], $_[2], 32, 48);
}

sub print_header {
    my $t = Time::Piece->new();

    print "/* oid_sum.h
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/* Generated using (from wolfssl):
 *   ./scripts/asn1_oid_sum.pl > wolfssl/wolfcrypt/oid_sum.h
 */

#ifndef WOLF_CRYPT_OID_SUM_H
#define WOLF_CRYPT_OID_SUM_H

"
}

sub print_footer {
    print "#endif /* !WOLF_CRYPT_OID_SUM_H */\n"
}

print_header();

my @md2 = (1, 2, 840, 113549, 2, 2);
my @md4 = (1, 2, 840, 113549, 2, 4);
my @md5 = (1, 2, 840, 113549, 2, 5);
my @sha1 = (1, 3, 14, 3, 2, 26);
my @sha224 = (2, 16, 840, 1, 101, 3, 4, 2, 4);
my @sha256 = (2, 16, 840, 1, 101, 3, 4, 2, 1);
my @sha384 = (2, 16, 840, 1, 101, 3, 4, 2, 2);
my @sha512 = (2, 16, 840, 1, 101, 3, 4, 2, 3);
my @sha512_224 = (2, 16, 840, 1, 101, 3, 4, 2, 5);
my @sha512_256 = (2, 16, 840, 1, 101, 3, 4, 2, 6);
my @sha3_224 = (2, 16, 840, 1, 101, 3, 4, 2, 7);
my @sha3_256 = (2, 16, 840, 1, 101, 3, 4, 2, 8);
my @sha3_384 = (2, 16, 840, 1, 101, 3, 4, 2, 9);
my @sha3_512 = (2, 16, 840, 1, 101, 3, 4, 2, 10);
my @shake_128 = (2, 16, 840, 1, 101, 3, 4, 2, 11);
my @shake_256 = (2, 16, 840, 1, 101, 3, 4, 2, 12);
my @sm3 = (1, 2, 156, 10197, 1, 401);

my @hashes = (
    { name => "MD2",        oid => \@md2        },
    { name => "MD4",        oid => \@md4        },
    { name => "MD5",        oid => \@md5        },
    { name => "SHA",        oid => \@sha1       },
    { name => "SHA224",     oid => \@sha224     },
    { name => "SHA256",     oid => \@sha256     },
    { name => "SHA384",     oid => \@sha384     },
    { name => "SHA512",     oid => \@sha512     },
    { name => "SHA512_224", oid => \@sha512_224 },
    { name => "SHA512_256", oid => \@sha512_256 },
    { name => "SHA3_224",   oid => \@sha3_224   },
    { name => "SHA3_256",   oid => \@sha3_256   },
    { name => "SHA3_384",   oid => \@sha3_384   },
    { name => "SHA3_512",   oid => \@sha3_512   },
    { name => "SHAKE128",   oid => \@shake_128  },
    { name => "SHAKE256",   oid => \@shake_256  },
    { name => "SM3",        oid => \@sm3        },
);

print_sum_enum("Hash", "h", \@hashes);

my @aes_128_cbc = ( 2, 16, 840, 1, 101, 3, 4, 1, 2 );
my @aes_128_gcm = ( 2, 16, 840, 1, 101, 3, 4, 1, 6 );
my @aes_128_ccm = ( 2, 16, 840, 1, 101, 3, 4, 1, 7 );
my @aes_192_cbc = ( 2, 16, 840, 1, 101, 3, 4, 1, 22 );
my @aes_192_gcm = ( 2, 16, 840, 1, 101, 3, 4, 1, 26 );
my @aes_192_ccm = ( 2, 16, 840, 1, 101, 3, 4, 1, 27 );
my @aes_256_cbc = ( 2, 16, 840, 1, 101, 3, 4, 1, 42 );
my @aes_256_gcm = ( 2, 16, 840, 1, 101, 3, 4, 1, 46 );
my @aes_256_ccm = ( 2, 16, 840, 1, 101, 3, 4, 1, 47 );
my @des_cbc = ( 1, 3, 14, 3, 2, 7 );
my @des3_cbc = ( 1, 2, 840, 113549, 3, 7 );

my @blocks = (
    { name => "AES128CBC",        oid => \@aes_128_cbc },
    { name => "AES128GCM",        oid => \@aes_128_gcm },
    { name => "AES128CCM",        oid => \@aes_128_ccm },
    { name => "AES192CBC",        oid => \@aes_192_cbc },
    { name => "AES192GCM",        oid => \@aes_192_gcm },
    { name => "AES192CCM",        oid => \@aes_192_ccm },
    { name => "AES256CBC",        oid => \@aes_256_cbc },
    { name => "AES256GCM",        oid => \@aes_256_gcm },
    { name => "AES256CCM",        oid => \@aes_256_ccm },
    { name => "DES",              oid => \@des_cbc     },
    { name => "DES3",             oid => \@des3_cbc    },
);

print_sum_enum("Block", "b", \@blocks);

my @anon = ( 0, 0 );
my @dsa = ( 1, 2, 840, 10040, 4, 1 );
my @rsa = ( 1, 2, 840, 113549, 1, 1, 1 );
my @rsa_pss = ( 1, 2, 840, 113549, 1, 1, 10 );
my @rsa_oeap = ( 1, 2, 840, 113549, 1, 1, 7 );
my @ecdsa = ( 1, 2, 840, 10045, 2, 1 );
my @sm2 = ( 1, 2, 156, 10197, 1, 301 );
my @ed25519 = ( 1, 3, 101, 112 );
my @x25519 = ( 1, 3, 101, 110 );
my @ed448 = ( 1, 3, 101, 113 );
my @x448 = ( 1, 3, 101, 111 );
my @dh = ( 1, 2, 840, 113549, 1, 3, 1 );
my @falcon_1 = ( 1, 3, 9999, 3, 6 );
my @falcon_5 = ( 1, 3, 9999, 3, 9 );
my @dilithium_2 = ( 1, 3, 6, 1, 4, 1, 2, 267, 12, 4, 4 );
my @dilithium_3 = ( 1, 3, 6, 1, 4, 1, 2, 267, 12, 6, 5 );
my @dilithium_5 = ( 1, 3, 6, 1, 4, 1, 2, 267, 12, 8, 7 );
my @mldsa_2 = ( 2, 16, 840, 1, 101, 3, 4, 3, 17 );
my @mldsa_3 = ( 2, 16, 840, 1, 101, 3, 4, 3, 18 );
my @mldsa_5 = ( 2, 16, 840, 1, 101, 3, 4, 3, 19 );
my @sphincs_fast_1 = ( 1, 3, 9999, 6, 7, 4 );
my @sphincs_fast_3 = ( 1, 3, 9999, 6, 8, 3 );
my @sphincs_fast_5 = ( 1, 3, 9999, 6, 9, 3 );
my @sphincs_small_1 = ( 1, 3, 9999, 6, 7, 10 );
my @sphincs_small_3 = ( 1, 3, 9999, 6, 8, 7 );
my @sphincs_small_5 = ( 1, 3, 9999, 6, 9, 7 );

my @keys = (
    { name => "ANON",                 oid => \@anon            },
    { name => "DSA",                  oid => \@dsa             },
    { name => "RSA",                  oid => \@rsa             },
    { name => "RSAPSS",               oid => \@rsa_pss         },
    { name => "RSAESOAEP",            oid => \@rsa_oeap        },
    { name => "ECDSA",                oid => \@ecdsa           },
    { name => "SM2",                  oid => \@sm2             },
    { name => "ED25519",              oid => \@ed25519         },
    { name => "X25519",               oid => \@x25519          },
    { name => "ED448",                oid => \@ed448           },
    { name => "X448",                 oid => \@x448            },
    { name => "DH",                   oid => \@dh              },
    { name => "FALCON_LEVEL1",        oid => \@falcon_1        },
    { name => "FALCON_LEVEL5",        oid => \@falcon_5        },
    { name => "DILITHIUM_LEVEL2",     oid => \@dilithium_2     },
    { name => "DILITHIUM_LEVEL3",     oid => \@dilithium_3     },
    { name => "DILITHIUM_LEVEL5",     oid => \@dilithium_5     },
    { name => "ML_DSA_LEVEL2",        oid => \@mldsa_2         },
    { name => "ML_DSA_LEVEL3",        oid => \@mldsa_3         },
    { name => "ML_DSA_LEVEL5",        oid => \@mldsa_5         },
    { name => "SPHINCS_FAST_LEVEL1",  oid => \@sphincs_fast_1  },
    { name => "SPHINCS_FAST_LEVEL3",  oid => \@sphincs_fast_3,
                                      oid_sum => 283           },
    { name => "SPHINCS_FAST_LEVEL5",  oid => \@sphincs_fast_5  },
    { name => "SPHINCS_SMALL_LEVEL1", oid => \@sphincs_small_1 },
    { name => "SPHINCS_SMALL_LEVEL3", oid => \@sphincs_small_3 },
    { name => "SPHINCS_SMALL_LEVEL5", oid => \@sphincs_small_5 },
);

print_sum_enum("Key", "k", \@keys);


my @aes128_kw = ( 2, 16, 840, 1, 101, 3, 4, 1, 5 );
my @aes192_kw = ( 2, 16, 840, 1, 101, 3, 4, 1, 25 );
my @aes256_kw = ( 2, 16, 840, 1, 101, 3, 4, 1, 45 );
my @pwri_kek = ( 1, 2, 840, 113549, 1, 9, 16, 3, 9);

my @key_wraps = (
    { name => "AES128",     oid => \@aes128_kw },
    { name => "AES192",     oid => \@aes192_kw },
    { name => "AES256",     oid => \@aes256_kw },
    { name => "PWRI_KEK",   oid => \@pwri_kek  },
);

print_sum_enum("KeyWrap", "_WRAP", \@key_wraps);


my @dh_sha1 = ( 1, 3, 133, 16, 840, 63, 0, 2 );
my @dh_sha224 = ( 1, 3, 132, 1, 11, 0 );
my @dh_sha256 = ( 1, 3, 132, 1, 11, 1 );
my @dh_sha384 = ( 1, 3, 132, 1, 11, 2 );
my @dh_sha512 = ( 1, 3, 132, 1, 11, 3 );

my @key_agrees = (
    { name => "dhSinglePass_stdDH_sha1kdf",   oid => \@dh_sha1   },
    { name => "dhSinglePass_stdDH_sha224kdf", oid => \@dh_sha224 },
    { name => "dhSinglePass_stdDH_sha256kdf", oid => \@dh_sha256 },
    { name => "dhSinglePass_stdDH_sha384kdf", oid => \@dh_sha384 },
    { name => "dhSinglePass_stdDH_sha512kdf", oid => \@dh_sha512 },
);

print_enum("Key_Agree", "_scheme", \@key_agrees, 40, 0);


my @pbkdf2 = ( 1, 2, 840, 113549, 1, 5, 12 );
my @mgf1 = (1, 2, 840, 113549, 1, 1, 8 );

my @kdfs = (
    { name => "PBKDF2", oid => \@pbkdf2 },
    { name => "MGF1",   oid => \@mgf1   },
);

print_sum_enum("KDF", "_OID", \@kdfs);


my @hmac_sha224 = ( 1, 2, 840, 113549, 2, 8 );
my @hmac_sha256 = ( 1, 2, 840, 113549, 2, 9 );
my @hmac_sha384 = ( 1, 2, 840, 113549, 2, 10 );
my @hmac_sha512 = ( 1, 2, 840, 113549, 2, 11 );
my @hmac_sha3_224 = ( 2, 16, 840, 1, 101, 3, 4, 2, 13 );
my @hmac_sha3_256 = ( 2, 16, 840, 1, 101, 3, 4, 2, 14 );
my @hmac_sha3_384 = ( 2, 16, 840, 1, 101, 3, 4, 2, 15 );
my @hmac_sha3_512 = ( 2, 16, 840, 1, 101, 3, 4, 2, 16 );

my @hmacs = (
    { name => "HMAC_SHA224",   oid => \@hmac_sha224 },
    { name => "HMAC_SHA256",   oid => \@hmac_sha256 },
    { name => "HMAC_SHA384",   oid => \@hmac_sha384 },
    { name => "HMAC_SHA512",   oid => \@hmac_sha512 },
    { name => "HMAC_SHA3_224", oid => \@hmac_sha3_224 },
    { name => "HMAC_SHA3_256", oid => \@hmac_sha3_256 },
    { name => "HMAC_SHA3_384", oid => \@hmac_sha3_384 },
    { name => "HMAC_SHA3_512", oid => \@hmac_sha3_512 },
);

print_sum_enum("HMAC", "_OID", \@hmacs);


my @basic_ca = ( 2, 5, 29, 19 );
my @alt_names = ( 2, 5, 29, 17 );
my @crl_dist = ( 2, 5, 29, 31 );
my @auth_info = ( 1, 3, 6, 1, 5, 5, 7, 1, 1 );
my @auth_key = ( 2, 5, 29, 35 );
my @subj_key = ( 2, 5, 29, 14 );
my @cert_policy = ( 2, 5, 29, 32 );
my @crl_number = ( 2, 5, 29, 20 );
my @key_usage = ( 2, 5, 29, 15 );
my @inhibit_any = ( 2, 5, 29, 54 );
my @ext_key_usage = ( 2, 5, 29, 37 );
my @name_cons = ( 2, 5, 29, 30 );
my @priv_key_usage_period = ( 2, 5, 29, 16 );
my @subj_info_acc = ( 1, 3, 6, 1, 5, 5, 7, 1, 11 );
my @policy_map = ( 2, 5, 29, 33 );
my @policy_const = ( 2, 5, 29, 36 );
my @issue_alt_names = ( 2, 5, 29, 18 );
my @tls_feature = ( 1, 3, 6, 1, 5, 5, 7, 1, 24 );
my @dns_srv = ( 1, 3, 6, 1, 5, 5, 7, 8, 7 );
my @netscape_ct = ( 2, 16, 840, 1, 113730, 1, 1 );
my @ocsp_nocheck = ( 1, 3, 6, 1, 5, 5, 7, 48, 1, 5 );
my @subj_dir_attr = ( 2, 5, 29, 9 );
my @akey_package = ( 2, 16, 840, 1, 101, 2, 1, 2, 78, 5 );
my @fascn = ( 2, 16, 840, 1, 101, 3, 6, 6 );
my @upn = ( 1, 3, 6, 1, 4, 1, 311, 20, 2, 3 );
my @subj_alt_pub_key_info = ( 2, 5, 29, 72 );
my @alt_sig_alg = ( 2, 5, 29, 73 );
my @alt_sig_val = ( 2, 5, 29, 74 );

my @exts = (
    { name => "BASIC_CA",               oid => \@basic_ca               },
    { name => "ALT_NAMES",              oid => \@alt_names              },
    { name => "CRL_DIST",               oid => \@crl_dist               },
    { name => "AUTH_INFO",              oid => \@auth_info              },
    { name => "AUTH_KEY",               oid => \@auth_key               },
    { name => "SUBJ_KEY",               oid => \@subj_key               },
    { name => "CERT_POLICY",            oid => \@cert_policy            },
    { name => "CRL_NUMBER",             oid => \@crl_number             },
    { name => "KEY_USAGE",              oid => \@key_usage              },
    { name => "INHIBIT_ANY",            oid => \@inhibit_any            },
    { name => "EXT_KEY_USAGE",          oid => \@ext_key_usage          },
    { name => "NAME_CONS",              oid => \@name_cons              },
    { name => "PRIV_KEY_USAGE_PERIOD",  oid => \@priv_key_usage_period  },
    { name => "SUBJ_INFO_ACC",          oid => \@subj_info_acc          },
    { name => "POLICY_MAP",             oid => \@policy_map             },
    { name => "POLICY_CONST",           oid => \@policy_const           },
    { name => "ISSUE_ALT_NAMES",        oid => \@issue_alt_names        },
    { name => "TLS_FEATURE",            oid => \@tls_feature            },
    { name => "DNS_SRV",                oid => \@dns_srv                },
    { name => "NETSCAPE_CT",            oid => \@netscape_ct            },
    { name => "OCSP_NOCHECK",           oid => \@ocsp_nocheck           },
    { name => "SUBJ_DIR_ATTR",          oid => \@subj_dir_attr          },
    { name => "AKEY_PACKAGE",           oid => \@akey_package           },
    { name => "FASCN",                  oid => \@fascn                  },
    { name => "UPN",                    oid => \@upn                    },
    { name => "SUBJ_ALT_PUB_KEY_INFO",  oid => \@subj_alt_pub_key_info  },
    { name => "ALT_SIG_ALG",            oid => \@alt_sig_alg            },
    { name => "ALT_SIG_VAL",            oid => \@alt_sig_val            },
);

print_sum_enum("Extensions", "_OID", \@exts);


my @cp_any = ( 2, 5, 29, 32, 0 );
my @cp_isrg_domain_valid = ( 1, 3, 6, 1, 4, 1, 44947, 1, 1, 1 );
my @cp_fpki_high_assurance = ( 2, 16, 840, 1, 101, 3, 2, 1, 3, 4 );
my @cp_fpki_common_hw = ( 2, 16, 840, 1, 101, 3, 2, 1, 3, 7 );
my @cp_fpki_medium_hw = ( 2, 16, 840, 1, 101, 3, 2, 1, 3, 12 );
my @cp_fpki_common_auth = ( 2, 16, 840, 1, 101, 3, 2, 1, 3, 13 );
my @cp_fpki_common_high = ( 2, 16, 840, 1, 101, 3, 2, 1, 3, 16 );
my @cp_fpki_pivi_hw = ( 2, 16, 840, 1, 101, 3, 2, 1, 3, 18 );
my @cp_fpki_pivi_cs = ( 2, 16, 840, 1, 101, 3, 2, 1, 3, 20 );
my @cp_fpki_common_dev_hw = ( 2, 16, 840, 1, 101, 3, 2, 1, 3, 36 );
my @cp_fpki_medium_dev_hw = ( 2, 16, 840, 1, 101, 3, 2, 1, 3, 38 );
my @cp_fpki_common_piv_cs = ( 2, 16, 840, 1, 101, 3, 2, 1, 3, 39 );
my @cp_fpki_piv_auth = ( 2, 16, 840, 1, 101, 3, 2, 1, 3, 40 );
my @cp_fpki_piv_auth_hw = ( 2, 16, 840, 1, 101, 3, 2, 1, 3, 41 );
my @cp_fpki_pivi_auth = ( 2, 16, 840, 1, 101, 3, 2, 1, 3, 45 );
my @cp_fpki_common_pivi_cs = ( 2, 16, 840, 1, 101, 3, 2, 1, 3, 47 );

my @cp_fpki_auth_test = ( 2, 16, 840, 1, 101, 3, 2, 1, 48, 11 );
my @cp_fpki_cardauth_test = ( 2, 16, 840, 1, 101, 3, 2, 1, 48, 13 );
my @cp_fpki_piv_content_test = ( 2, 16, 840, 1, 101, 3, 2, 1, 48, 86 );
my @cp_fpki_piv_auth_der_test = ( 2, 16, 840, 1, 101, 3, 2, 1, 48, 109 );
my @cp_fpki_piv_auth_der_hw_test = ( 2, 16, 840, 1, 101, 3, 2, 1, 48, 110 );

my @cp_dod_medium = ( 2, 16, 840, 1, 101, 2, 1, 11, 5 );
my @cp_dod_medium_hw = ( 2, 16, 840, 1, 101, 2, 1, 11, 9 );
my @cp_dod_piv_auth = ( 2, 16, 840, 1, 101, 2, 1, 11, 10 );
my @cp_dod_medium_npe = ( 2, 16, 840, 1, 101, 2, 1, 11, 17 );
my @cp_dod_medium_2048 = ( 2, 16, 840, 1, 101, 2, 1, 11, 18 );
my @cp_dod_medium_hw_2048 = ( 2, 16, 840, 1, 101, 2, 1, 11, 19 );
my @cp_dod_piv_auth_2048 = ( 2, 16, 840, 1, 101, 2, 1, 11, 20 );
my @cp_dod_peer_interop = ( 2, 16, 840, 1, 101, 2, 1, 11, 31 );
my @cp_dod_medium_npe_112 = ( 2, 16, 840, 1, 101, 2, 1, 11, 36 );
my @cp_dod_medium_npe_128 = ( 2, 16, 840, 1, 101, 2, 1, 11, 37 );
my @cp_dod_medium_npe_192 = ( 2, 16, 840, 1, 101, 2, 1, 11, 38 );
my @cp_dod_medium_112 = ( 2, 16, 840, 1, 101, 2, 1, 11, 39 );
my @cp_dod_medium_128 = ( 2, 16, 840, 1, 101, 2, 1, 11, 40 );
my @cp_dod_medium_192 = ( 2, 16, 840, 1, 101, 2, 1, 11, 41 );
my @cp_dod_medium_hw_112 = ( 2, 16, 840, 1, 101, 2, 1, 11, 42 );
my @cp_dod_medium_hw_128 = ( 2, 16, 840, 1, 101, 2, 1, 11, 43 );
my @cp_dod_medium_hw_192 = ( 2, 16, 840, 1, 101, 2, 1, 11, 44 );
my @cp_dod_admin = ( 2, 16, 840, 1, 101, 2, 1, 11, 59 );
my @cp_dod_internal_npe_112 = ( 2, 16, 840, 1, 101, 2, 1, 11, 60 );
my @cp_dod_internal_npe_128 = ( 2, 16, 840, 1, 101, 2, 1, 11, 61 );
my @cp_dod_internal_npe_192 = ( 2, 16, 840, 1, 101, 2, 1, 11, 62 );

my @cp_eca_medium = ( 2, 16, 840, 1, 101, 3, 2, 1, 12, 1 );
my @cp_eca_medium_hw = ( 2, 16, 840, 1, 101, 3, 2, 1, 12, 2 );
my @cp_eca_medium_token = ( 2, 16, 840, 1, 101, 3, 2, 1, 12, 3);
my @cp_eca_medium_sha256 = ( 2, 16, 840, 1, 101, 3, 2, 1, 12, 4);
my @cp_eca_medium_token_sha256 = ( 2, 16, 840, 1, 101, 3, 2, 1, 12, 5);
my @cp_eca_medium_hw_pivi = ( 2, 16, 840, 1, 101, 3, 2, 1, 12, 6);
my @cp_eca_cs_pivi = ( 2, 16, 840, 1, 101, 3, 2, 1, 12, 8);
my @cp_eca_medium_dev_sha256 = ( 2, 16, 840, 1, 101, 3, 2, 1, 12, 9);
my @cp_eca_medium_hw_sha256 = ( 2, 16, 840, 1, 101, 3, 2, 1, 12, 10);

my @cp_state_basic = ( 2, 16, 840, 1, 101, 3, 2, 1, 6, 1 );
my @cp_state_low = ( 2, 16, 840, 1, 101, 3, 2, 1, 6, 2 );
my @cp_state_moderate = ( 2, 16, 840, 1, 101, 3, 2, 1, 6, 3 );
my @cp_state_high = ( 2, 16, 840, 1, 101, 3, 2, 1, 6, 4 );
my @cp_state_medhw = ( 2, 16, 840, 1, 101, 3, 2, 1, 6, 12 );
my @cp_state_meddevhw = ( 2, 16, 840, 1, 101, 3, 2, 1, 6, 38 );

my @cp_treas_mediumhw = ( 2, 16, 840, 1, 101, 3, 2, 1, 5, 4 );
my @cp_treas_high = ( 2, 16, 840, 1, 101, 3, 2, 1, 5, 5 );
my @cp_treas_pivi_hw = ( 2, 16, 840, 1, 101, 3, 2, 1, 5, 10 );
my @cp_treas_pivi_content = ( 2, 16, 840, 1, 101, 3, 2, 1, 5, 12 );

my @cp_boeing_medhw_sha256 = ( 1, 3, 6, 1, 4, 1, 73, 15, 3, 1, 12 );
my @cp_boeing_medhw_cont_sha256 = ( 1, 3, 6, 1, 4, 1, 73, 15, 3, 1, 17 );

my @cp_carillon_medhw_256 = ( 1, 3, 6, 1, 4, 1, 45606, 3, 1, 12 );
my @cp_carillon_aivhw = ( 1, 3, 6, 1, 4, 1, 45606, 3, 1, 20 );
my @cp_carillon_aivcontent = ( 1, 3, 6, 1, 4, 1, 45606, 3, 1, 22 );

my @cp_cis_medhw_256 = ( 1, 3, 6, 1, 4, 1, 25054, 3, 1, 12 );
my @cp_cis_meddevhw_256 = ( 1, 3, 6, 1, 4, 1, 25054, 3, 1, 14 );
my @cp_cis_icecap_hw = ( 1, 3, 6, 1, 4, 1, 25054, 3, 1, 20 );
my @cp_cis_icecap_cont_hw = ( 1, 3, 6, 1, 4, 1, 25054, 3, 1, 22 );

my @cp_certipath_medium = ( 1, 3, 6, 1, 4, 1, 24019, 1, 1, 1, 2 );
my @cp_certipath_highhw = ( 1, 3, 6, 1, 4, 1, 24019, 1, 1, 1, 3 );
my @cp_certipath_icecap_hw = ( 1, 3, 6, 1, 4, 1, 24019, 1, 1, 1, 7 );
my @cp_certipath_icecap_cont = ( 1, 3, 6, 1, 4, 1, 24019, 1, 1, 1, 9 );
my @cp_certipath_var_medhw = ( 1, 3, 6, 1, 4, 1, 24019, 1, 1, 1, 18 );
my @cp_certipath_var_highhw = ( 1, 3, 6, 1, 4, 1, 24019, 1, 1, 1, 19 );

my @cp_tscp_mediumhw = ( 1, 3, 6, 1, 4, 1, 38099, 1, 1, 1, 2 );
my @cp_tscp_pivi = ( 1, 3, 6, 1, 4, 1, 38099, 1, 1, 1, 5 );
my @cp_tscp_pivi_cont = ( 1, 3, 6, 1, 4, 1, 38099, 1, 1, 1, 7 );

my @cp_digicert_nfssp_medhw = ( 2, 16, 840, 1, 113733, 1, 7, 23, 3, 1, 7 );
my @cp_digicert_nfssp_auth = ( 2, 16, 840, 1, 113733, 1, 7, 23, 3, 1, 13 );
my @cp_digicert_nfssp_pivi_hw = ( 2, 16, 840, 1, 113733, 1, 7, 23, 3, 1, 18 );
my @cp_digicert_nfssp_pivi_cont = ( 2, 16, 840, 1, 113733, 1, 7, 23, 3, 1, 20 );
my @cp_digicert_nfssp_meddevhw = ( 2, 16, 840, 1, 113733, 1, 7, 23, 3, 1, 36 );

my @cp_entrust_mfssp_medhw = ( 2, 16, 840, 1, 114027, 200, 3, 10, 7, 2 );
my @cp_entrust_mfssp_medauth = ( 2, 16, 840, 1, 114027, 200, 3, 10, 7, 4 );
my @cp_entrust_mfssp_pivi_hw = ( 2, 16, 840, 1, 114027, 200, 3, 10, 7, 6 );
my @cp_entrust_mfssp_pivi_cont = ( 2, 16, 840, 1, 114027, 200, 3, 10, 7, 9 );
my @cp_entrust_mfssp_meddevhw = ( 2, 16, 840, 1, 114027, 200, 3, 10, 7, 16 );

my @cp_exostar_medhw_sha2 = ( 1, 3, 6, 1, 4, 1, 13948, 1, 1, 1, 6 );

my @cp_identrust_medhw_sign = ( 2, 16, 840, 1, 113839, 0, 100, 12, 1 );
my @cp_identrust_medhw_enc = ( 2, 16, 840, 1, 113839, 0, 100, 12, 2 );
my @cp_identrust_pivi_hw_id = ( 2, 16, 840, 1, 113839, 0, 100, 18, 0 );
my @cp_identrust_pivi_hw_sign = ( 2, 16, 840, 1, 113839, 0, 100, 18, 1 );
my @cp_identrust_pivi_hw_enc = ( 2, 16, 840, 1, 113839, 0, 100, 18, 2 );
my @cp_identrust_pivi_cont = ( 2, 16, 840, 1, 113839, 0, 100, 20, 1 );

my @cp_lockheed_medhw = ( 1, 3, 6, 1, 4, 1, 103, 100, 1, 1, 3, 3 );

my @cp_northrop_med_256_hw = ( 1, 3, 6, 1, 4, 1, 16334, 509, 2, 8 );
my @cp_northrop_pivi_256_hw = ( 1, 3, 6, 1, 4, 1, 16334, 509, 2, 9 );
my @cp_northrop_pivi_256_cont = ( 1, 3, 6, 1, 4, 1, 16334, 509, 2, 11 );
my @cp_northrop_med_384_hw = ( 1, 3, 6, 1, 4, 1, 16334, 509, 2, 14 );

my @cp_rayhtheon_medhw = ( 1, 3, 6, 1, 4, 1, 1569, 10, 1, 12 );
my @cp_rayhtheon_meddevhw = ( 1, 3, 6, 1, 4, 1, 1569, 10, 1, 18 );
my @cp_rayhtheon_sha2_medhw = ( 1, 3, 6, 1, 4, 1, 26769, 10, 1, 12 );
my @cp_rayhtheon_sha2_meddevhw = ( 1, 3, 6, 1, 4, 1, 26769, 10, 1, 18 );

my @cp_widepoint_medhw = ( 1, 3, 6, 1, 4, 1, 3922, 1, 1, 1, 12 );
my @cp_widepoint_pivi_hw = ( 1, 3, 6, 1, 4, 1, 3922, 1, 1, 1, 18 );
my @cp_widepoint_pivi_cont = ( 1, 3, 6, 1, 4, 1, 3922, 1, 1, 1, 20 );
my @cp_widepoint_meddevhw = ( 1, 3, 6, 1, 4, 1, 3922, 1, 1, 1, 38 );

my @cp_add_med = ( 1, 2, 36, 1, 334, 1, 2, 1, 2 );
my @cp_add_high = ( 1, 2, 36, 1, 334, 1, 2, 1, 3 );
my @cp_add_res_med = ( 1, 2, 36, 1, 334, 1, 2, 2, 2 );

my @cp_comodo = ( 1, 3, 6, 1, 4, 1, 6449, 1, 2, 1, 3, 4 );

my @cp_nl_mod_auth = ( 2, 16, 528, 1, 1003, 1, 2, 5, 1 );
my @cp_nl_mod_irrefut = ( 2, 16, 528, 1, 1003, 1, 2, 5, 2 );
my @cp_nl_mod_confid = ( 2, 16, 528, 1, 1003, 1, 2, 5, 3 );

my @cert_policies = (
    { name => "CP_ANY_OID",               oid => \@cp_any                     },
    { name => "CP_ISRG_DOMAIN_VALID",     oid => \@cp_isrg_domain_valid       },

    # Federal PKI
    { name => "CP_FPKI_HIGH_ASSURANCE_OID",
                                          oid => \@cp_fpki_high_assurance     },
    { name => "CP_FPKI_COMMON_HARDWARE_OID",
                                          oid => \@cp_fpki_common_hw          },
    { name => "CP_FPKI_MEDIUM_HARDWARE_OID",
                                          oid => \@cp_fpki_medium_hw          },
    { name => "CP_FPKI_COMMON_AUTH_OID",  oid => \@cp_fpki_common_auth        },
    { name => "CP_FPKI_COMMON_HIGH_OID",  oid => \@cp_fpki_common_high        },
    { name => "CP_FPKI_PIVI_HARDWARE_OID",
                                          oid => \@cp_fpki_pivi_hw            },
    { name => "CP_FPKI_PIVI_CONTENT_SIGNING_OID",
                                          oid => \@cp_fpki_pivi_cs            },
    { name => "CP_FPKI_COMMON_DEVICES_HARDWARE_OID",
                                          oid => \@cp_fpki_common_dev_hw      },
    { name => "CP_FPKI_MEDIUM_DEVICE_HARDWARE_OID",
                                          oid => \@cp_fpki_medium_dev_hw      },
    { name => "CP_FPKI_COMMON_PIV_CONTENT_SIGNING_OID",
                                          oid => \@cp_fpki_common_piv_cs      },
    { name => "CP_FPKI_PIV_AUTH_OID",     oid => \@cp_fpki_piv_auth           },
    { name => "CP_FPKI_PIV_AUTH_HW_OID",  oid => \@cp_fpki_piv_auth_hw        },
    { name => "CP_FPKI_PIVI_AUTH_OID",    oid => \@cp_fpki_pivi_auth          },
    { name => "CP_FPKI_COMMON_PIVI_CONTENT_SIGNING_OID",
                                          oid => \@cp_fpki_common_pivi_cs     },

    # Federal PKI Test
    { name => "CP_FPKI_AUTH_TEST_OID",    oid => \@cp_fpki_auth_test          },
    { name => "CP_FPKI_CARDAUTH_TEST_OID",
                                          oid => \@cp_fpki_cardauth_test      },
    { name => "CP_FPKI_PIV_CONTENT_TEST_OID",
                                          oid => \@cp_fpki_piv_content_test   },
    { name => "CP_FPKI_PIV_AUTH_DERIVED_TEST_OID",
                                          oid => \@cp_fpki_piv_auth_der_test  },
    { name => "CP_FPKI_PIV_AUTH_DERIVED_HW_TEST_OID",
                                        oid => \@cp_fpki_piv_auth_der_hw_test },

    # DOD PKI
    { name => "CP_DOD_MEDIUM_OID",        oid => \@cp_dod_medium              },
    { name => "CP_DOD_MEDIUM_HARDWARE_OID",
                                          oid => \@cp_dod_medium_hw           },
    { name => "CP_DOD_PIV_AUTH_OID",      oid => \@cp_dod_piv_auth            },
    { name => "CP_DOD_MEDIUM_NPE_OID",    oid => \@cp_dod_medium_npe          },
    { name => "CP_DOD_MEDIUM_2048_OID",   oid => \@cp_dod_medium_2048         },
    { name => "CP_DOD_MEDIUM_HARDWARE_2048_OID",
                                          oid => \@cp_dod_medium_hw_2048      },
    { name => "CP_DOD_PIV_AUTH_2048_OID", oid => \@cp_dod_piv_auth_2048       },
    { name => "CP_DOD_PEER_INTEROP_OID",  oid => \@cp_dod_peer_interop,
                                          add_sum => 100000                   },
    { name => "CP_DOD_MEDIUM_NPE_112_OID",
                                          oid => \@cp_dod_medium_npe_112,
                                          add_sum => 100000                   },
    { name => "CP_DOD_MEDIUM_NPE_128_OID",
                                          oid => \@cp_dod_medium_npe_128      },
    { name => "CP_DOD_MEDIUM_NPE_192_OID",
                                          oid => \@cp_dod_medium_npe_192      },
    { name => "CP_DOD_MEDIUM_112_OID",    oid => \@cp_dod_medium_112          },
    { name => "CP_DOD_MEDIUM_128_OID",    oid => \@cp_dod_medium_128,
                                          add_sum => 100000                   },
    { name => "CP_DOD_MEDIUM_192_OID",    oid => \@cp_dod_medium_192          },
    { name => "CP_DOD_MEDIUM_HARDWARE_112_OID",
                                          oid => \@cp_dod_medium_hw_112,
                                          add_sum => 100000                   },
    { name => "CP_DOD_MEDIUM_HARDWARE_128_OID",
                                          oid => \@cp_dod_medium_hw_128       },
    { name => "CP_DOD_MEDIUM_HARDWARE_192_OID",
                                          oid => \@cp_dod_medium_hw_192       },
    { name => "CP_DOD_ADMIN_OID",         oid => \@cp_dod_admin               },
    { name => "CP_DOD_INTERNAL_NPE_112_OID",
                                          oid => \@cp_dod_internal_npe_112    },
    { name => "CP_DOD_INTERNAL_NPE_128_OID",
                                          oid => \@cp_dod_internal_npe_128    },
    { name => "CP_DOD_INTERNAL_NPE_192_OID",
                                          oid => \@cp_dod_internal_npe_192    },

    # ECA PKI
    { name => "CP_ECA_MEDIUM_OID",        oid => \@cp_eca_medium,
                                          add_sum => 100000                   },
    { name => "CP_ECA_MEDIUM_HARDWARE_OID",
                                          oid => \@cp_eca_medium_hw           },
    { name => "CP_ECA_MEDIUM_TOKEN_OID",  oid => \@cp_eca_medium_token,
                                          add_sum => 100000                   },
    { name => "CP_ECA_MEDIUM_SHA256_OID", oid => \@cp_eca_medium_sha256,
                                          add_sum => 100000                   },
    { name => "CP_ECA_MEDIUM_TOKEN_SHA256_OID",
                                          oid => \@cp_eca_medium_token_sha256,
                                          add_sum => 100000                   },
    { name => "CP_ECA_MEDIUM_HARDWARE_PIVI_OID",
                                          oid => \@cp_eca_medium_hw_pivi,
                                          add_sum => 100000                   },
    { name => "CP_ECA_CONTENT_SIGNING_PIVI_OID",
                                          oid => \@cp_eca_cs_pivi,
                                          add_sum => 100000                   },
    { name => "CP_ECA_MEDIUM_DEVICE_SHA256_OID",
                                          oid => \@cp_eca_medium_dev_sha256   },
    { name => "CP_ECA_MEDIUM_HARDWARE_SHA256_OID",
                                          oid => \@cp_eca_medium_hw_sha256    },

    # Department of State PKI
    { name => "CP_STATE_BASIC_OID",       oid => \@cp_state_basic,
                                          add_sum => 100000                   },
    { name => "CP_STATE_LOW_OID",         oid => \@cp_state_low               },
    { name => "CP_STATE_MODERATE_OID",    oid => \@cp_state_moderate ,
                                          add_sum => 100000                   },
    { name => "CP_STATE_HIGH_OID",        oid => \@cp_state_high,
                                          add_sum => 100000                   },
    { name => "CP_STATE_MEDHW_OID",       oid => \@cp_state_medhw,
                                          add_sum => 101000                   },
    { name => "CP_STATE_MEDDEVHW_OID",    oid => \@cp_state_meddevhw,
                                          add_sum => 101000                   },

    # U.S. Treasury SSP PKI
    { name => "CP_TREAS_MEDIUMHW_OID",    oid => \@cp_treas_mediumhw          },
    { name => "CP_TREAS_HIGH_OID",        oid => \@cp_treas_high,
                                          add_sum => 101000                   },
    { name => "CP_TREAS_PIVI_HW_OID",     oid => \@cp_treas_pivi_hw,
                                          add_sum => 101000                   },
    { name => "CP_TREAS_PIVI_CONTENT_OID",
                                          oid => \@cp_treas_pivi_content,
                                          add_sum => 101000                   },

    # Boeing PKI
    { name => "CP_BOEING_MEDIUMHW_SHA256_OID",
                                          oid => \@cp_boeing_medhw_sha256     },
    { name => "CP_BOEING_MEDIUMHW_CONTENT_SHA256_OID",
                                          oid => \@cp_boeing_medhw_cont_sha256},

    # Carillon Federal Services
    { name => "CP_CARILLON_MEDIUMHW_256_OID",
                                          oid => \@cp_carillon_medhw_256      },
    { name => "CP_CARILLON_AIVHW_OID",    oid => \@cp_carillon_aivhw          },
    { name => "CP_CARILLON_AIVCONTENT_OID",
                                          oid => \@cp_carillon_aivcontent,
                                          add_sum => 100000                   },

    # Carillon Information Security
    { name => "CP_CIS_MEDIUMHW_256_OID",  oid => \@cp_cis_medhw_256           },
    { name => "CP_CIS_MEDDEVHW_256_OID",  oid => \@cp_cis_meddevhw_256        },
    { name => "CP_CIS_ICECAP_HW_OID",     oid => \@cp_cis_icecap_hw           },
    { name => "CP_CIS_ICECAP_CONTENT_OID", 
                                          oid => \@cp_cis_icecap_cont_hw      },

    # CertiPath Bridge
    { name => "CP_CERTIPATH_MEDIUMHW_OID",
                                          oid => \@cp_certipath_medium,
                                          add_sum => 100000                   },
    { name => "CP_CERTIPATH_HIGHHW_OID",  
                                          oid => \@cp_certipath_highhw,
                                          add_sum => 101000                   },
    { name => "CP_CERTIPATH_ICECAP_HW_OID",
                                          oid => \@cp_certipath_icecap_hw     },
    { name => "CP_CERTIPATH_ICECAP_CONTENT_OID",
                                          oid => \@cp_certipath_icecap_cont   },
    { name => "CP_CERTIPATH_VAR_MEDIUMHW_OID",
                                          oid => \@cp_certipath_var_medhw,
                                          add_sum => 100000                   },
    { name => "CP_CERTIPATH_VAR_HIGHHW_OID",
                                          oid => \@cp_certipath_var_highhw    },

    # TSCP Bridge
    { name => "CP_TSCP_MEDIUMHW_OID",     oid => \@cp_tscp_mediumhw           },
    { name => "CP_TSCP_PIVI_OID",         oid => \@cp_tscp_pivi               },
    { name => "CP_TSCP_PIVI_CONTENT_OID", oid => \@cp_tscp_pivi_cont          },

    # DigiCert NFI
    { name => "CP_DIGICERT_NFSSP_MEDIUMHW_OID",
                                          oid => \@cp_digicert_nfssp_medhw    },
    { name => "CP_DIGICERT_NFSSP_AUTH_OID",
                                          oid => \@cp_digicert_nfssp_auth     },
    { name => "CP_DIGICERT_NFSSP_PIVI_HW_OID",
                                          oid => \@cp_digicert_nfssp_pivi_hw  },
    { name => "CP_DIGICERT_NFSSP_PIVI_CONTENT_OID",
                                          oid => \@cp_digicert_nfssp_pivi_cont},
    { name => "CP_DIGICERT_NFSSP_MEDDEVHW_OID",
                                          oid => \@cp_digicert_nfssp_meddevhw },

    # Entrust Managed Services NFI
    { name => "CP_ENTRUST_NFSSP_MEDIUMHW_OID",
                                          oid => \@cp_entrust_mfssp_medhw     },
    { name => "CP_ENTRUST_NFSSP_MEDAUTH_OID",
                                          oid => \@cp_entrust_mfssp_medauth   },
    { name => "CP_ENTRUST_NFSSP_PIVI_HW_OID",
                                          oid => \@cp_entrust_mfssp_pivi_hw   },
    { name => "CP_ENTRUST_NFSSP_PIVI_CONTENT_OID",
                                          oid => \@cp_entrust_mfssp_pivi_cont },
    { name => "CP_ENTRUST_NFSSP_MEDDEVHW_OID",
                                          oid => \@cp_entrust_mfssp_meddevhw  },

    # Exostar LLC
    { name => "CP_EXOSTAR_MEDIUMHW_SHA2_OID",
                                          oid => \@cp_exostar_medhw_sha2,
                                          add_sum => 100000                   },

    # IdenTrust NFI
    { name => "CP_IDENTRUST_MEDIUMHW_SIGN_OID",
                                          oid => \@cp_identrust_medhw_sign    },
    { name => "CP_IDENTRUST_MEDIUMHW_ENC_OID",
                                          oid => \@cp_identrust_medhw_enc     },
    { name => "CP_IDENTRUST_PIVI_HW_ID_OID",
                                          oid => \@cp_identrust_pivi_hw_id    },
    { name => "CP_IDENTRUST_PIVI_HW_SIGN_OID",
                                          oid => \@cp_identrust_pivi_hw_sign  },
    { name => "CP_IDENTRUST_PIVI_HW_ENC_OID",
                                          oid => \@cp_identrust_pivi_hw_enc   },
    { name => "CP_IDENTRUST_PIVI_CONTENT_OID",
                                          oid => \@cp_identrust_pivi_cont     },

    # Lockheed Martin
    { name => "CP_LOCKHEED_MEDIUMHW_OID", oid => \@cp_lockheed_medhw          },

    # Northrop Grumman
    { name => "CP_NORTHROP_MEDIUM_256_HW_OID",
                                          oid => \@cp_northrop_med_256_hw     },
    { name => "CP_NORTHROP_PIVI_256_HW_OID",
                                          oid => \@cp_northrop_pivi_256_hw    },
    { name => "CP_NORTHROP_PIVI_256_CONTENT_OID",
                                          oid => \@cp_northrop_pivi_256_cont  },
    { name => "CP_NORTHROP_MEDIUM_384_HW_OID",
                                          oid => \@cp_northrop_med_384_hw     },

    # Raytheon PKI
    { name => "CP_RAYTHEON_MEDIUMHW_OID", oid => \@cp_rayhtheon_medhw         },
    { name => "CP_RAYTHEON_MEDDEVHW_OID", oid => \@cp_rayhtheon_meddevhw      },
    { name => "CP_RAYTHEON_SHA2_MEDIUMHW_OID",
                                          oid => \@cp_rayhtheon_sha2_medhw    },
    { name => "CP_RAYTHEON_SHA2_MEDDEVHW_OID",
                                          oid => \@cp_rayhtheon_sha2_meddevhw },

    # WidePoint NFI
    { name => "CP_WIDEPOINT_MEDIUMHW_OID",
                                          oid => \@cp_widepoint_medhw         },
    { name => "CP_WIDEPOINT_PIVI_HW_OID", oid => \@cp_widepoint_pivi_hw       },
    { name => "CP_WIDEPOINT_PIVI_CONTENT_OID",
                                          oid => \@cp_widepoint_pivi_cont     },
    { name => "CP_WIDEPOINT_MEDDEVHW_OID",
                                          oid => \@cp_widepoint_meddevhw      },

    # Australian Defence Organisation
    { name => "CP_ADO_MEDIUM_OID",        oid => \@cp_add_med                 },
    { name => "CP_ADO_HIGH_OID",          oid => \@cp_add_high                },
    { name => "CP_ADO_RESOURCE_MEDIUM_OID",
                                          oid => \@cp_add_res_med,
                                          add_sum => 100000                   },
    # Comodo Ltd PKI
    { name => "CP_COMODO_OID",            oid => \@cp_comodo,
                                          add_sum => 100000                   },

    # Netherlands Ministry of Defence
    { name => "CP_NL_MOD_AUTH_OID",       oid => \@cp_nl_mod_auth             },
    { name => "CP_NL_MOD_IRREFUT_OID",    oid => \@cp_nl_mod_irrefut,
                                          add_sum => 100000                   },
    { name => "CP_NL_MOD_CONFID_OID",     oid => \@cp_nl_mod_confid           },
);

print_enum("CertificatePolicy_Sum", "", \@cert_policies, 45, 0);


my @sep_hw_name = ( 1, 3, 6, 1, 5, 5, 7, 8, 4 );

my @seps = (
    { name => "HW_NAME",                oid => \@sep_hw_name          },
);

print_sum_enum("SepHardwareName", "_OID", \@seps);


my @aia_ocsp = ( 1, 3, 6, 1, 5, 5, 7, 48, 1 );
my @aia_ca_issuer = ( 1, 3, 6, 1, 5, 5, 7, 48, 2 );
my @aia_ca_repo = ( 1, 3, 6, 1, 5, 5, 7, 48, 5 );

my @aias = (
    { name => "AIA_OCSP",               oid => \@aia_ocsp             },
    { name => "AIA_CA_ISSUER",          oid => \@aia_ca_issuer        },
    { name => "AIA_CA_REPO",            oid => \@aia_ca_repo          },
);

print_sum_enum("AuthInfo", "_OID", \@aias);


my @eku_any = ( 2, 5, 29, 37, 0 );
my @eku_server_auth = ( 1, 3, 6, 1, 5, 5, 7, 3, 1 );
my @eku_client_auth = ( 1, 3, 6, 1, 5, 5, 7, 3, 2 );
my @eku_codesigning = ( 1, 3, 6, 1, 5, 5, 7, 3, 3 );
my @eku_emailprotect = ( 1, 3, 6, 1, 5, 5, 7, 3, 4 );
my @eku_timestamp = ( 1, 3, 6, 1, 5, 5, 7, 3, 8 );
my @eku_ocsp_sign = ( 1, 3, 6, 1, 5, 5, 7, 3, 9 );
my @eku_ssh_client_auth = ( 1, 3, 6, 1, 5, 5, 7, 3, 21 );
my @eku_ssh_mscl = ( 1, 3, 6, 1, 4, 1, 311, 20, 2, 2 );
my @eku_ssh_kp_client_auth = ( 1, 3, 6, 1, 5, 2, 3, 4 );

my @ekus = (
    { name => "EKU_ANY",                oid => \@eku_any                },
    { name => "EKU_SERVER_AUTH",        oid => \@eku_server_auth        },
    { name => "EKU_CLIENT_AUTH",        oid => \@eku_client_auth        },
    { name => "EKU_CODESIGNING",        oid => \@eku_codesigning        },
    { name => "EKU_EMAILPROTECT",       oid => \@eku_emailprotect       },
    { name => "EKU_TIMESTAMP",          oid => \@eku_timestamp          },
    { name => "EKU_OCSP_SIGN",          oid => \@eku_ocsp_sign          },
    { name => "EKU_SSH_CLIENT_AUTH",    oid => \@eku_ssh_client_auth    },
    { name => "EKU_SSH_MSCL",           oid => \@eku_ssh_mscl           },
    { name => "EKU_SSH_KP_CLIENT_AUTH", oid => \@eku_ssh_kp_client_auth },
);

print_sum_enum("ExtKeyUsage", "_OID", \@ekus);


my @sda_dob = ( 1, 3, 6, 1, 5, 5, 7, 9, 1 );
my @sda_pob = ( 1, 3, 6, 1, 5, 5, 7, 9, 2 );
my @sda_gender = ( 1, 3, 6, 1, 5, 5, 7, 9, 3 );
my @sda_coc = ( 1, 3, 6, 1, 5, 5, 7, 9, 4 );
my @sda_cor = ( 1, 3, 6, 1, 5, 5, 7, 9, 5 );

my @sdas = (
    { name => "SDA_DOB",                oid => \@sda_dob                },
    { name => "SDA_POB",                oid => \@sda_pob                },
    { name => "SDA_GENDER",             oid => \@sda_gender             },
    { name => "SDA_COC",                oid => \@sda_coc                },
    { name => "SDA_COR",                oid => \@sda_cor                },
);

print_sum_enum("SubjDirAttr", "_OID", \@sdas);


my @zlib = ( 1, 2, 840, 113549, 1, 9, 16, 3, 8 );

my @compressions = (
    { name => "ZLIB",                   oid => \@zlib                   },
);

print_sum_enum("CompressAlg", "c", \@compressions);


my @csr_unstructure_name = ( 1, 2, 840, 113549, 1, 9, 2 );
my @csr_pkcs9_content_type = ( 1, 2, 840, 113549, 1, 9, 3 );
my @csr_challenge_password = ( 1, 2, 840, 113549, 1, 9, 7 );
my @csr_serial_number = ( 2, 5, 4, 5 );
my @csr_ext_request = ( 1, 2, 840, 113549, 1, 9, 14 );
my @csr_user_id = ( 0, 9, 2342, 19200300, 100, 1, 1 );
my @csr_dnqualifier = ( 2, 5, 4, 46 );
my @csr_initials = ( 2, 5, 4, 43 );
my @csr_surname = ( 2, 5, 4, 4 );
my @csr_name = ( 2, 5, 4, 41 );
my @csr_given_name = ( 2, 5, 4, 42 );

my @csr_attr_types = (
    { name => "UNSTRUCTURED_NAME",      oid => \@csr_unstructure_name   },
    { name => "PKCS9_CONTENT_TYPE",     oid => \@csr_pkcs9_content_type },
    { name => "CHALLENGE_PASSWORD",     oid => \@csr_challenge_password },
    { name => "SERIAL_NUMBER",          oid => \@csr_serial_number      },
    { name => "EXTENSION_REQUEST",      oid => \@csr_ext_request        },
    { name => "USER_ID",                oid => \@csr_user_id            },
    { name => "DNQUALIFIER",            oid => \@csr_dnqualifier        },
    { name => "INITIALS",               oid => \@csr_initials           },
    { name => "SURNAME",                oid => \@csr_surname            },
    { name => "NAME",                   oid => \@csr_name               },
    { name => "GIVEN_NAME",             oid => \@csr_given_name         },
);

print_enum("CsrAttrType", "_OID", \@csr_attr_types, 32, 48);


my @ocsp_basic = (  1, 3, 6, 1, 5, 5, 7, 48, 1, 1 );
my @ocsp_nonce = (  1, 3, 6, 1, 5, 5, 7, 48, 1, 2 );

my @ocsp = (
    { name => "OCSP_BASIC",             oid => \@ocsp_basic             },
    { name => "OCSP_NONCE",             oid => \@ocsp_nonce             },
);

print_sum_enum("Ocsp", "_OID", \@ocsp);


my @ecc_secp112r1 = ( 1, 3, 132, 0, 6 );
my @ecc_secp112r2 = ( 1, 3, 132, 0, 7 );
my @ecc_secp128r1 = ( 1, 3, 132, 0, 28 );
my @ecc_secp128r2 = ( 1, 3, 132, 0, 29 );
my @ecc_secp160r1 = ( 1, 3, 132, 0, 8 );
my @ecc_secp160r2 = ( 1, 3, 132, 0, 30 );
my @ecc_secp160k1 = ( 1, 3, 132, 0, 9 );
my @ecc_brainpool160r1 = ( 1, 3, 36, 3, 3, 2, 8, 1, 1, 1 );
my @ecc_secp192r1 = ( 1, 2, 840, 10045, 3, 1, 1 );
my @ecc_prime192v2 = ( 1, 2, 840, 10045, 3, 1, 2 );
my @ecc_prime192v3 = ( 1, 2, 840, 10045, 3, 1, 3 );
my @ecc_secp192k1 = ( 1, 3, 132, 0, 31 );
my @ecc_brainpool192r1 = ( 1, 3, 36, 3, 3, 2, 8, 1, 1, 3 );
my @ecc_secp224r1 = ( 1, 3, 132, 0, 33 );
my @ecc_secp224k1 = ( 1, 3, 132, 0, 32 );
my @ecc_brainpool224r1 = ( 1, 3, 36, 3, 3, 2, 8, 1, 1, 5 );
my @ecc_prime239v1 = ( 1, 2, 840, 10045, 3, 1, 4 );
my @ecc_prime239v2 = ( 1, 2, 840, 10045, 3, 1, 5 );
my @ecc_prime239v3 = ( 1, 2, 840, 10045, 3, 1, 6 );
my @ecc_secp256r1 = ( 1, 2, 840, 10045, 3, 1, 7 );
my @ecc_secp256k1 = ( 1, 3, 132, 0, 10 );
my @ecc_brainpool256r1 = ( 1, 3, 36, 3, 3, 2, 8, 1, 1, 7 );
my @ecc_brainpool320r1 = ( 1, 3, 36, 3, 3, 2, 8, 1, 1, 9 );
my @ecc_secp384r1 = ( 1, 3, 132, 0, 34 );
my @ecc_brainpool384r1 = ( 1, 3, 36, 3, 3, 2, 8, 1, 1, 11 );
my @ecc_brainpool512r1 = ( 1, 3, 36, 3, 3, 2, 8, 1, 1, 13 );
my @ecc_secp521r1 = ( 1, 3, 132, 0, 35 );

my @eccs = (
    { name => "ECC_SECP112R1",          oid => \@ecc_secp112r1          },
    { name => "ECC_SECP112R2",          oid => \@ecc_secp112r2          },
    { name => "ECC_SECP128R1",          oid => \@ecc_secp128r1          },
    { name => "ECC_SECP128R2",          oid => \@ecc_secp128r2          },
    { name => "ECC_SECP160R1",          oid => \@ecc_secp160r1          },
    { name => "ECC_SECP160R2",          oid => \@ecc_secp160r2          },
    { name => "ECC_SECP160K1",          oid => \@ecc_secp160k1          },
    { name => "ECC_BRAINPOOLP160R1",    oid => \@ecc_brainpool160r1     },
    { name => "ECC_SECP192R1",          oid => \@ecc_secp192r1          },
    { name => "ECC_PRIME192V2",         oid => \@ecc_prime192v2         },
    { name => "ECC_PRIME192V3",         oid => \@ecc_prime192v3         },
    { name => "ECC_SECP192K1",          oid => \@ecc_secp192k1          },
    { name => "ECC_BRAINPOOLP192R1",    oid => \@ecc_brainpool192r1     },
    { name => "ECC_SECP224R1",          oid => \@ecc_secp224r1          },
    { name => "ECC_SECP224K1",          oid => \@ecc_secp224k1          },
    { name => "ECC_BRAINPOOLP224R1",    oid => \@ecc_brainpool224r1     },
    { name => "ECC_PRIME239V1",         oid => \@ecc_prime239v1         },
    { name => "ECC_PRIME239V2",         oid => \@ecc_prime239v2         },
    { name => "ECC_PRIME239V3",         oid => \@ecc_prime239v3         },
    { name => "ECC_SECP256R1",          oid => \@ecc_secp256r1          },
    { name => "ECC_SECP256K1",          oid => \@ecc_secp256k1          },
    { name => "ECC_BRAINPOOLP256R1",    oid => \@ecc_brainpool256r1     },
    { name => "ECC_SM2P256V1",          oid => \@sm2,
                                        same => 1                       },
    { name => "ECC_X25519",             oid => \@x25519,
                                        same => 1                       },
    { name => "ECC_ED25519",            oid => \@ed25519,
                                        same => 1                       },
    { name => "ECC_BRAINPOOLP320R1",    oid => \@ecc_brainpool320r1     },
    { name => "ECC_X448",               oid => \@x448,
                                        same => 1                       },
    { name => "ECC_ED448",              oid => \@ed448,
                                        same => 1                       },
    { name => "ECC_SECP384R1",          oid => \@ecc_secp384r1          },
    { name => "ECC_BRAINPOOLP384R1",    oid => \@ecc_brainpool384r1     },
    { name => "ECC_BRAINPOOLP512R1",    oid => \@ecc_brainpool512r1     },
    { name => "ECC_SECP521R1",          oid => \@ecc_secp521r1          },
);

print_sum_enum("Ecc", "_OID", \@eccs);


my @ctc_sha_dsa = ( 1, 2, 840, 10040, 4, 3 );
my @ctc_sha256_dsa = ( 2, 16, 840, 1, 101, 3, 4, 3, 2 );
my @ctc_md2_rsa = ( 1, 2, 840, 113549, 1, 1, 2 );
my @ctc_md5_rsa = ( 1, 2, 840, 113549, 1, 1, 4 );
my @ctc_sha1_rsa = ( 1, 2, 840, 113549, 1, 1, 5 );
my @ctc_sha1_ecdsa = ( 1, 2, 840, 10045, 4, 1 );
my @ctc_sha224_rsa = ( 1, 2, 840, 113549, 1, 1, 14 );
my @ctc_sha224_ecdsa = ( 1, 2, 840, 10045, 4, 3, 1 );
my @ctc_sha256_rsa = ( 1, 2, 840, 113549, 1, 1, 11 );
my @ctc_sha256_ecdsa = ( 1, 2, 840, 10045, 4, 3, 2 );
my @ctc_sha384_rsa = ( 1, 2, 840, 113549, 1, 1, 12 );
my @ctc_sha384_ecdsa = ( 1, 2, 840, 10045, 4, 3, 3 );
my @ctc_sha512_rsa = ( 1, 2, 840, 113549, 1, 1, 13 );
my @ctc_sha512_ecdsa = ( 1, 2, 840, 10045, 4, 3, 4 );
my @ctc_sha3_224_ecdsa = ( 2, 16, 840, 1, 101, 3, 4, 3, 9 );
my @ctc_sha3_256_ecdsa = ( 2, 16, 840, 1, 101, 3, 4, 3, 10 );
my @ctc_sha3_384_ecdsa = ( 2, 16, 840, 1, 101, 3, 4, 3, 11 );
my @ctc_sha3_512_ecdsa = ( 2, 16, 840, 1, 101, 3, 4, 3, 12 );
my @ctc_sha3_224_rsa = ( 2, 16, 840, 1, 101, 3, 4, 3, 13 );
my @ctc_sha3_256_rsa = ( 2, 16, 840, 1, 101, 3, 4, 3, 14 );
my @ctc_sha3_384_rsa = ( 2, 16, 840, 1, 101, 3, 4, 3, 15 );
my @ctc_sha3_512_rsa = ( 2, 16, 840, 1, 101, 3, 4, 3, 16 );
my @ctc_rsassapss = ( 1, 2, 840, 113549, 1, 1, 10 );
my @ctc_sm3_sm2 = ( 1, 2, 156, 10197, 1, 501 );

my @sig_types = (
    { name => "CTC_SHAwDSA",                oid => \@ctc_sha_dsa            },
    { name => "CTC_SHA256wDSA",             oid => \@ctc_sha256_dsa         },
    { name => "CTC_MD2wRSA",                oid => \@ctc_md2_rsa            },
    { name => "CTC_MD5wRSA",                oid => \@ctc_md5_rsa            },
    { name => "CTC_SHAwRSA",                oid => \@ctc_sha1_rsa           },
    { name => "CTC_SHAwECDSA",              oid => \@ctc_sha1_ecdsa         },
    { name => "CTC_SHA224wRSA",             oid => \@ctc_sha224_rsa         },
    { name => "CTC_SHA224wECDSA",           oid => \@ctc_sha224_ecdsa       },
    { name => "CTC_SHA256wRSA",             oid => \@ctc_sha256_rsa         },
    { name => "CTC_SHA256wECDSA",           oid => \@ctc_sha256_ecdsa       },
    { name => "CTC_SHA384wRSA",             oid => \@ctc_sha384_rsa         },
    { name => "CTC_SHA384wECDSA",           oid => \@ctc_sha384_ecdsa       },
    { name => "CTC_SHA512wRSA",             oid => \@ctc_sha512_rsa         },
    { name => "CTC_SHA512wECDSA",           oid => \@ctc_sha512_ecdsa       },
    { name => "CTC_SHA3_224wECDSA",         oid => \@ctc_sha3_224_ecdsa     },
    { name => "CTC_SHA3_256wECDSA",         oid => \@ctc_sha3_256_ecdsa     },
    { name => "CTC_SHA3_384wECDSA",         oid => \@ctc_sha3_384_ecdsa     },
    { name => "CTC_SHA3_512wECDSA",         oid => \@ctc_sha3_512_ecdsa     },
    { name => "CTC_SHA3_224wRSA",           oid => \@ctc_sha3_224_rsa       },
    { name => "CTC_SHA3_256wRSA",           oid => \@ctc_sha3_256_rsa       },
    { name => "CTC_SHA3_384wRSA",           oid => \@ctc_sha3_384_rsa       },
    { name => "CTC_SHA3_512wRSA",           oid => \@ctc_sha3_512_rsa       },
    { name => "CTC_RSASSAPSS",              oid => \@rsa_pss,
                                            same => 1                       },
    { name => "CTC_SM3wSM2",                oid => \@ctc_sm3_sm2            },
    { name => "CTC_ED25519",                oid => \@ed25519,
                                            same => 1                       },
    { name => "CTC_ED448",                  oid => \@ed448,
                                            same => 1                       },
    { name => "CTC_FALCON_LEVEL1",          oid => \@falcon_1,
                                            same => 1                       },
    { name => "CTC_FALCON_LEVEL5",          oid => \@falcon_5,
                                            same => 1                       },
    { name => "CTC_DILITHIUM_LEVEL2",       oid => \@dilithium_2,
                                            same => 1                       },
    { name => "CTC_DILITHIUM_LEVEL3",       oid => \@dilithium_3,
                                            same => 1                       },
    { name => "CTC_DILITHIUM_LEVEL5",       oid => \@dilithium_5,
                                            same => 1                       },
    { name => "CTC_ML_DSA_LEVEL2",          oid => \@mldsa_2,
                                            same => 1                       },
    { name => "CTC_ML_DSA_LEVEL3",          oid => \@mldsa_3,
                                            same => 1                       },
    { name => "CTC_ML_DSA_LEVEL5",          oid => \@mldsa_5,
                                            same => 1                       },
    { name => "CTC_SPHINCS_FAST_LEVEL1",    oid => \@sphincs_fast_1,
                                            same => 1                       },
    { name => "CTC_SPHINCS_FAST_LEVEL3",    oid => \@sphincs_fast_3,
                                            same => 1, oid_sum => 283       },
    { name => "CTC_SPHINCS_FAST_LEVEL5",    oid => \@sphincs_fast_5,
                                            same => 1                       },
    { name => "CTC_SPHINCS_SMALL_LEVEL1",   oid => \@sphincs_small_1,
                                            same => 1                       },
    { name => "CTC_SPHINCS_SMALL_LEVEL3",   oid => \@sphincs_small_3,
                                            same => 1                       },
    { name => "CTC_SPHINCS_SMALL_LEVEL5",   oid => \@sphincs_small_5,
                                            same => 1                       },
);

print_enum("Ctc_SigType", "", \@sig_types, 32, 48);


my @p7t_pkcs7_msg = ( 1, 2, 840, 113549, 1, 7 );
my @p7t_data = ( 1, 2, 840, 113549, 1, 7, 1 );
my @p7t_signed_data = ( 1, 2, 840, 113549, 1, 7, 2 );
my @p7t_env_data = ( 1, 2, 840, 113549, 1, 7, 3 );
my @p7t_sign_env_data = ( 1, 2, 840, 113549, 1, 7, 4 );
my @p7t_digested_data = ( 1, 2, 840, 113549, 1, 7, 5 );
my @p7t_encrypted_data = ( 1, 2, 840, 113549, 1, 7, 6 );
my @p7t_compressed_data = ( 1, 2, 840, 113549, 1, 9, 16, 1, 9 );
my @p7t_firmware_pkg_data = ( 1, 2, 840, 113549, 1, 9, 16, 1, 16 );
my @p7t_auth_env_data = ( 1, 2, 840, 113549, 1, 9, 16, 1, 23 );

my @pkcs7_types = (
    { name => "PKCS7_MSG",                  oid => \@p7t_pkcs7_msg          },
    { name => "DATA",                       oid => \@p7t_data               },
    { name => "SIGNED_DATA",                oid => \@p7t_signed_data        },
    { name => "ENVELOPED_DATA",             oid => \@p7t_env_data           },
    { name => "SIGNED_AND_ENVELOPED_DATA",  oid => \@p7t_sign_env_data      },
    { name => "DIGESTED_DATA",              oid => \@p7t_digested_data      },
    { name => "COMPRESSED_DATA",            oid => \@p7t_compressed_data    },
    { name => "ENCRYPTED_DATA",             oid => \@p7t_encrypted_data     },
    { name => "FIRMWARE_PKG_DATA",          oid => \@p7t_firmware_pkg_data  },
    { name => "AUTH_ENVELOPED_DATA",        oid => \@p7t_auth_env_data      },
);

print_enum("PKCS7_TYPES", "", \@pkcs7_types, 32, 46);


my @p12_key_bag = ( 1, 2, 840, 113549, 1, 12, 10, 1, 1 );
my @p12_shrouded_bag = ( 1, 2, 840, 113549, 1, 12, 10, 1, 2 );
my @p12_cert_bag = ( 1, 2, 840, 113549, 1, 12, 10, 1, 3 );
my @p12_cert_bag_type1 = ( 1, 2, 840, 113549, 1, 9, 22, 1 );
my @p12_crl_bag = ( 1, 2, 840, 113549, 1, 12, 10, 1, 4 );
my @p12_secret_bag = ( 1, 2, 840, 113549, 1, 12, 10, 1, 5 );
my @p12_safe_contents_bag = ( 1, 2, 840, 113549, 1, 12, 10, 1, 6 );

my @pkcs12_types = (
    { name => "WC_PKCS12_KeyBag",           oid => \@p12_key_bag            },
    { name => "WC_PKCS12_ShroudedKeyBag",   oid => \@p12_shrouded_bag       },
    { name => "WC_PKCS12_CertBag",          oid => \@p12_cert_bag           },
    { name => "WC_PKCS12_CertBag_Type1",    oid => \@p12_cert_bag_type1     },
    { name => "WC_PKCS12_CrlBag",           oid => \@p12_crl_bag            },
    { name => "WC_PKCS12_SecretBag",        oid => \@p12_secret_bag         },
    { name => "WC_PKCS12_SafeContentsBag",  oid => \@p12_safe_contents_bag  },
    { name => "WC_PKCS12_DATA",             oid => \@p7t_data,
                                            same => 1                       },
    { name => "WC_PKCS12_ENCRYPTED_DATA",   oid => \@p7t_encrypted_data,
                                            same => 1                       },
);

print_enum("PKCS12_TYPES", "", \@pkcs12_types, 32, 46);


my @name_common = ( 2, 5, 4, 3 );
my @name_serial_number = ( 2, 5, 4, 5 );
my @name_country = ( 2, 5, 4, 6 );
my @name_locality = ( 2, 5, 4, 7 );
my @name_state_prov = ( 2, 5, 4, 8 );
my @name_street = ( 2, 5, 4, 9 );
my @name_organization = ( 2, 5, 4, 10 );
my @name_org_unit = ( 2, 5, 4, 11 );
my @name_title = ( 2, 5, 4, 9, 12 );
my @name_description = ( 2, 5, 4, 13 );
my @name_business_cat = ( 2, 5, 4, 15 );
my @name_postal_code = ( 2, 5, 4, 17 );
my @name_pkcs9_email = ( 1, 2, 840, 113549, 1, 9, 1 );;
my @name_rfc822_mailbox = ( 0, 9, 2342, 19200300, 100, 1, 3 );
my @name_fav_drink = ( 0, 9, 2342, 19200300, 100, 1, 5 );
my @name_domain_component = ( 0, 9, 2342, 19200300, 100, 1, 25 );
my @name_juris_state_prov = ( 1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 2 );
my @name_juris_country = ( 1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 3 );

my @cert_names = (
    { name => "WC_NAME_COMMON_NAME",        oid => \@name_common              },
    { name => "WC_NAME_SURNAME",            oid => \@csr_surname,
                                            same => 1                         },
    { name => "WC_NAME_SERIAL_NUMBER",      oid => \@csr_serial_number,
                                            same => 1                         },
    { name => "WC_NAME_COUNTRY_NAME",       oid => \@name_country             },
    { name => "WC_NAME_LOCALITY_NAME",      oid => \@name_locality            },
    { name => "WC_NAME_STATE_NAME",         oid => \@name_state_prov          },
    { name => "WC_NAME_STREET_ADDRESS",     oid => \@name_street              },
    { name => "WC_NAME_ORGANIZATION_NAME",  oid => \@name_organization        },
    { name => "WC_NAME_ORGANIZATION_UNIT_NAME",
                                            oid => \@name_org_unit            },
    { name => "WC_NAME_TITLE",              oid => \@name_title               },
    { name => "WC_NAME_DESCRIPTION",        oid => \@name_description         },
    { name => "WC_NAME_BUSINESS_CATEGORY",  oid => \@name_business_cat        },
    { name => "WC_NAME_POSTAL_CODE",        oid => \@name_postal_code         },
    { name => "WC_NAME_NAME",               oid => \@csr_name,
                                            same => 1                         },
    { name => "WC_NAME_GIVEN_NAME",         oid => \@csr_given_name,
                                            same => 1                         },
    { name => "WC_NAME_INITIALIS",          oid => \@csr_initials,
                                            same => 1                         },
    { name => "WC_NAME_EMAIL_ADDRESS",      oid => \@name_pkcs9_email         },
    { name => "WC_NAME_USER_ID",            oid => \@csr_user_id,
                                            same => 1                         },
    { name => "WC_NAME_RFC822_MAILBOX",     oid => \@name_rfc822_mailbox      },
    { name => "WC_NAME_FAVOURITE_DRINK",    oid => \@name_fav_drink           },
    { name => "WC_NAME_DOMAIN_COMPONENT",   oid => \@name_domain_component    },
    { name => "WC_NAME_JURIS_STATE_PROV",   oid => \@name_juris_state_prov    },
    { name => "WC_NAME_JURIS_COUNTRY",      oid => \@name_juris_country       },
);

print_enum("CertName_Sum", "_OID", \@cert_names, 40, 0);

print_footer();

