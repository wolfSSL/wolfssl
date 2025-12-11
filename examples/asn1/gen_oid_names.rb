#!/usr/bin/ruby

class OidName
  def initialize(oid, name)
    @oid = oid
    @name = name
  end

  def der_to_str(d)
    s = "(byte*)\""
    d.each do |b|
      s += sprintf("\\x%02x", b)
    end
    s + "\""
  end

  def write()
    puts <<EOF
    { #{der_to_str(@oid)}, #{@oid.length},
      "#{@name.gsub(/\"/, '\\"')}" },
EOF
  end
end

class OidNames
  def initialize()
    @oid_name = []
  end

  def decode_dotted(oid)
     i = 0
     n = 0
     der = []
     oid.split(/ /).each do |s|
       t = s.to_i

       i += 1
       if i == 1
         n = t * 40
         next
       elsif i == 2
         n += t
       else
         n = t
       end

       if n == 0
         der << 0
       end

       tmp = []
       bit = 0;
       while n > 0
         tmp << ((n & 0x7f) | bit)
         n >>= 7
         bit = 0x80
       end
       der += tmp.reverse
     end

     der
  end

  def add(oid, name)
    @oid_name << OidName.new(decode_dotted(oid), name)
  end

  def write_struct()
    puts <<EOF
typedef struct asn1App_OidName {
    byte* oid;
    word32 len;
    const char* name;
} asn1App_OidName;

EOF
  end

  def write()
    puts <<EOF
/* oid_names.h
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
 *   cd examples/asn1
 *   ruby ./gen_oid_names.rb dumpasn1.cfg > oid_names.h
 */
EOF
    puts
    write_struct()
    puts
    puts "static asn1App_OidName asn1App_oid_name[#{@oid_name.length}] = {"
    @oid_name.each do |o|
      o.write()
    end
    puts "};"
    puts
    puts "int asn1App_oid_names_len = #{@oid_name.length};"
    puts
  end
end

oid = ""
oidNames = OidNames.new()
File.readlines(ARGV[0]).each do |l|
  next if l.length == 0
  next if l[0] == '#'

  var, value = l.split(/ = /)

  case var
  when /OID/
    oid = value
  when /Description/
    oidNames.add(oid, value.strip)
  end
end
oidNames.write()

