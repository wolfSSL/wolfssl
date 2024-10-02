#!/usr/bin/env python
#
#  gen_crt_bundle.py
#
#  Copyright (C) 2006-2024 wolfSSL Inc.
#
#  This file is part of wolfSSL.
#
#  wolfSSL is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  wolfSSL is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
#
# ESP32 x509 certificate bundle generation utility
#
# Converts PEM and DER certificates to a custom bundle format which stores just the
# subject name and public key to reduce space
#
# The bundle will have the format:
# number of certificates;
# crt 1 subject name length;
# crt 1 public key length;
# crt 1 subject name;
# crt 1 public key;
# crt 2...


from __future__ import with_statement

import argparse
import csv
import os
import re
import unicodedata
import struct
import sys
from io import open

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.x509.oid import NameOID

except ImportError:
    print('The cryptography package is not installed.'
          'Please refer to the Get Started section of the ESP-IDF Programming Guide for '
          'setting up the required packages.')
    raise

ca_bundle_bin_file = 'x509_crt_bundle_wolfssl'

quiet = False


def status(msg):
    """ Print status message to stderr """
    if not quiet:
        critical(msg)


def critical(msg):
    """ Print critical message to stderr """
    sys.stderr.write('gen_crt_bundle.py: ')
    sys.stderr.write(msg)
    sys.stderr.write('\n')


class CertificateBundle:
    def __init__(self):
        self.certificates = []
        self.compressed_crts = []

        if os.path.isfile(ca_bundle_bin_file):
            os.remove(ca_bundle_bin_file)

    def add_from_path(self, crts_path):

        found = False
        for file_path in os.listdir(crts_path):
            found |= self.add_from_file(os.path.join(crts_path, file_path))

        if found is False:
            raise InputError('No valid x509 certificates found in %s' % crts_path)

    def add_from_file(self, file_path):
        try:
            if file_path.endswith('.pem'):
                status('Parsing certificates from %s' % file_path)
                with open(file_path, 'r', encoding='utf-8') as f:
                    crt_str = f.read()
                    self.add_from_pem(crt_str)
                    return True

            elif file_path.endswith('.der'):
                status('Parsing certificates from %s' % file_path)
                with open(file_path, 'rb') as f:
                    crt_str = f.read()
                    self.add_from_der(crt_str)
                    return True

        except ValueError:
            critical('Invalid certificate in %s' % file_path)
            raise InputError('Invalid certificate')

        return False

    def add_from_pem(self, crt_str):
        """ A single PEM file may have multiple certificates """

        crt = ''
        count = 0
        start = False

        for strg in crt_str.splitlines(True):
            if strg == '-----BEGIN CERTIFICATE-----\n' and start is False:
                crt = ''
                start = True
            elif strg == '-----END CERTIFICATE-----\n' and start is True:
                crt += strg + '\n'
                start = False
                self.certificates.append(x509.load_pem_x509_certificate(crt.encode(), default_backend()))
                count += 1
            if start is True:
                crt += strg

        if count == 0:
            raise InputError('No certificate found')

        status('Successfully added %d certificates' % count)

    def add_from_der(self, crt_str):
        self.certificates.append(x509.load_der_x509_certificate(crt_str, default_backend()))
        status('Successfully added 1 certificate')

    def get_subject_text(self, cert):
        # Extract subject as a string in the desired format
        return ", ".join(
            f"/{attribute.oid._name}={attribute.value}"  # Adjust as necessary to format as "/C=US/O=..."
            for attribute in cert.subject
        )

    # We are currently sorting in AS FOUND order. wolfSSL does this in wolfSSL_X509_NAME_oneline()
    # But for reference, if desired:
    #
    # /C=TW/O=TAIWAN-CA/OU=Root CA/CN=TWCA Global Root CA
    # /C=US/ST=Illinois/L=Chicago/O=Trustwave Holdings, Inc./CN=Trustwave
    desired_dn_order = ["/C=", "/ST=", "/L=", "/O=", "/OU=", "/CN="]

    def extract_dn_components(self, cert):
        """
        Extract the DN components based on the desired order and return the assembled string.
        """
        #dn_dict = {"/C=": "/C=", "/ST=": "/ST=", "/L=": "/L=", "/O=": "/O=", "/OU=": "/OU=", "/CN=": "/CN="}
        dn_dict = {"/C=": "", "/ST=": "", "/L=": "", "/O=": "", "/OU=": "", "/CN=": ""}

        # Map the actual DN elements to the correct keys in the desired order
        for attribute in cert.subject:
            if attribute.oid == x509.NameOID.COUNTRY_NAME:
                dn_dict["/C="] = attribute.value
            elif attribute.oid == x509.NameOID.ORGANIZATIONAL_UNIT_NAME:
                dn_dict["/OU="] = attribute.value
            elif attribute.oid == x509.NameOID.ORGANIZATION_NAME:
                dn_dict["/O="] = attribute.value
            elif attribute.oid == x509.NameOID.COMMON_NAME:
                dn_dict["/CN="] = attribute.value
            elif attribute.oid == x509.NameOID.LOCALITY_NAME:
                dn_dict["/L="] = attribute.value
            elif attribute.oid == x509.NameOID.STATE_OR_PROVINCE_NAME:
                dn_dict["/ST="] = attribute.value

        #return ''.join([f"{key}{dn_dict[key]}" for key in self.desired_dn_order])
        return dn_dict

    def sorting_key(self, cert):
        """
        Create a tuple for sorting, where each component is sorted in the order defined by `desired_dn_order`.
        If a component is missing, it is replaced with a value that will ensure proper sorting (empty string).
        """
        dn_dict = self.extract_dn_components(cert)

        return ''.join([f"{key}{dn_dict[key]}" for key in self.desired_dn_order if dn_dict[key]])

    def sort_certificates_by_dn_order(self, certificates):
        """
        Sort the list of certificates based on the DN string assembled in the specified order.
        """
        return sorted(certificates, key=self.sorting_key)

    def extract_dn_components_as_is(self, cert):
        """
        Extract the DN components exactly as they appear in the certificate.
        """
        # dn_string = ', '.join([f"{attribute.oid._name}={attribute.value}" for attribute in cert.subject])
        dn_string = ""
        result_string = ""

        # Mapping of known OIDs to their short names
        oid_short_names = {
            'commonName': '/CN',
            'countryName': '/C',
            'stateOrProvinceName': '/ST',
            'localityName': '/L',
            'organizationName': '/O',
            'organizationalUnitName': '/OU'
        }

        with open("cert_bundle.log", "a") as file:
            # Write to the file
            file.write("\nNew cert\n\n")
            for attribute in cert.subject:
                # Use a predefined map for known OIDs, and fallback to the dotted string if not found
                oid_full_name  = attribute.oid._name if attribute.oid._name else attribute.oid.dotted_string

                # The common string uses "/CN" and not "commonName", so we need to swap out keywords such as commonName:
                oid_name = oid_short_names.get(oid_full_name, oid_full_name)
                file.write(f"oid_name={oid_name}\n")

                # Strip unicode
                normalized_string = unicodedata.normalize('NFKD', attribute.value)

                # Encode to ASCII bytes, ignoring any characters that can't be converted
                ascii_bytes = normalized_string.encode('ascii', 'ignore')

                # Decode back to ASCII string
                ascii_string = ascii_bytes.decode('ascii')
                file.write(f"attribute_value={ascii_string}\n")

                # assemble the dn string for this cert
                dn_string += f"/{oid_name}={ascii_string}"
                file.write(f"dn_string={dn_string}\n")

            # Remove any unprintable characters
            cleaned_string = re.sub(r'[^\x20-\x7E]', ' ', dn_string)
            file.write(f"cleaned_string={cleaned_string}\n")
            result_string = cleaned_string.replace("=", " ")
            file.write(f"result_string={result_string}\n")

        # Reminder this is a sort order only; cert NOT modified.
        return result_string

    def sorting_key_as_is(self, cert):
        """
        Use the DN string as found in the certificate as the sorting key.
        """
        dn_string = self.extract_dn_components_as_is(cert)
        return dn_string

    def sort_certificates_by_as_is(self, certificates):
        """
        Sort the list of certificates based on the DN string assembled in the specified order.
        """
        return sorted(certificates, key=self.sorting_key_as_is)

    def create_bundle(self):
        # Sort certificates in order to do binary search when looking up certificates
        # NOTE: When sorting, see `esp_crt_bundle.c`;
        #       Use `#define CERT_BUNDLE_UNSORTED` when not sorting.
        #
        with open("cert_bundle.log", "w") as file:
            # Write to the file
            file.write("init.\n")
        self.certificates = self.sort_certificates_by_as_is(self.certificates)


        bundle = struct.pack('>H', len(self.certificates))

        for crt in self.certificates:
            cert_der = crt.public_bytes(serialization.Encoding.DER)
            cert_der_len = len(cert_der)

            len_data = struct.pack('>H', cert_der_len)
            bundle += len_data
            bundle += cert_der

        return bundle

    def add_with_filter(self, crts_path, filter_path):

        filter_set = set()
        with open(filter_path, 'r', encoding='utf-8') as f:
            csv_reader = csv.reader(f, delimiter=',')

            # Skip header
            next(csv_reader)
            for row in csv_reader:
                filter_set.add(row[1])

        status('Parsing certificates from %s' % crts_path)
        crt_str = []
        with open(crts_path, 'r', encoding='utf-8') as f:
            crt_str = f.read()

            # Split all certs into a list of (name, certificate string) tuples
            pem_crts = re.findall(r'(^.+?)\n(=+\n[\s\S]+?END CERTIFICATE-----\n)', crt_str, re.MULTILINE)

            filtered_crts = ''
            for name, crt in pem_crts:
                if name in filter_set:
                    filtered_crts += crt

        self.add_from_pem(filtered_crts)


class InputError(RuntimeError):
    def __init__(self, e):
        super(InputError, self).__init__(e)


def main():
    global quiet

    parser = argparse.ArgumentParser(description='ESP-IDF x509 certificate bundle utility')

    parser.add_argument('--quiet', '-q', help="Don't print non-critical status messages to stderr", action='store_true')
    parser.add_argument('--input', '-i', nargs='+', required=True,
                        help='Paths to the custom certificate folders or files to parse, parses all .pem or .der files')
    parser.add_argument('--filter', '-f', help='Path to CSV-file where the second columns contains the name of the certificates \
                        that should be included from cacrt_all.pem')

    args = parser.parse_args()

    quiet = args.quiet

    bundle = CertificateBundle()

    for path in args.input:
        if os.path.isfile(path):
            if os.path.basename(path) == 'cacrt_all.pem' and args.filter:
                bundle.add_with_filter(path, args.filter)
            else:
                bundle.add_from_file(path)
        elif os.path.isdir(path):
            bundle.add_from_path(path)
        else:
            raise InputError('Invalid --input=%s, is neither file nor folder' % args.input)

    status('Successfully added %d certificates in total' % len(bundle.certificates))

    crt_bundle = bundle.create_bundle()

    with open(ca_bundle_bin_file, 'wb') as f:
        f.write(crt_bundle)


if __name__ == '__main__':
    try:
        main()
    except InputError as e:
        print(e)
        sys.exit(2)
