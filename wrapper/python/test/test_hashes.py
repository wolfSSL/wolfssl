# test_hashes.py
#
# Copyright (C) 2006-2016 wolfSSL Inc.
#
# This file is part of wolfSSL. (formerly known as CyaSSL)
#
# wolfSSL is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# wolfSSL is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
import unittest
from wolfcrypt.hashes import *


class TestSha(unittest.TestCase):
    digest = "1b6182d68ae91ce0853bd9c6b6edfedd4b6a510d"


    def setUp(self):
        self.hash = Sha.new()


    def test_new(self):
        # invalid construction
        self.assertRaises(ValueError, Sha)

        # update inside constructor
        assert Sha.new("wolfcrypt").hexdigest() == self.digest


    def test_hash_update_001(self):
        self.hash.update("wolfcrypt")

        assert self.hash.hexdigest() == self.digest
        assert self.hash.digest() == self.digest.decode("hex")


    def test_hash_update_002(self):
        self.hash.update("wolf")
        self.hash.update("crypt")

        assert self.hash.hexdigest() == self.digest
        assert self.hash.digest() == self.digest.decode("hex")


    def test_hash_copy(self):
        copy = self.hash.copy()

        assert self.hash.hexdigest() == copy.hexdigest()

        self.hash.update("wolfcrypt")

        assert self.hash.hexdigest() != copy.hexdigest()

        copy.update("wolfcrypt")

        assert self.hash.hexdigest() == copy.hexdigest() == self.digest


class TestSha256(unittest.TestCase):
    digest = "96e02e7b1cbcd6f104fe1fdb4652027a5505b68652b70095c6318f9dce0d1844"


    def setUp(self):
        self.hash = Sha256.new()


    def test_new(self):
        # invalid construction
        self.assertRaises(ValueError, Sha256)

        # update inside constructor
        assert Sha256.new("wolfcrypt").hexdigest() == self.digest


    def test_hash_update_001(self):
        self.hash.update("wolfcrypt")

        assert self.hash.hexdigest() == self.digest
        assert self.hash.digest() == self.digest.decode("hex")


    def test_hash_update_002(self):
        self.hash.update("wolf")
        self.hash.update("crypt")

        assert self.hash.hexdigest() == self.digest
        assert self.hash.digest() == self.digest.decode("hex")


    def test_hash_copy(self):
        copy = self.hash.copy()

        assert self.hash.hexdigest() == copy.hexdigest()

        self.hash.update("wolfcrypt")

        assert self.hash.hexdigest() != copy.hexdigest()

        copy.update("wolfcrypt")

        assert self.hash.hexdigest() == copy.hexdigest() == self.digest


class TestSha384(unittest.TestCase):
    digest = "4c79d80531203a16f91bee325f18c6aada47f9382fe44fc1" \
           + "1f92917837e9b7902f5dccb7d3656f667a1dce3460bc884b"


    def setUp(self):
        self.hash = Sha384.new()


    def test_new(self):
        # invalid construction
        self.assertRaises(ValueError, Sha384)

        # update inside constructor
        assert Sha384.new("wolfcrypt").hexdigest() == self.digest


    def test_hash_update_001(self):
        self.hash.update("wolfcrypt")

        assert self.hash.hexdigest() == self.digest
        assert self.hash.digest() == self.digest.decode("hex")


    def test_hash_update_002(self):
        self.hash.update("wolf")
        self.hash.update("crypt")

        assert self.hash.hexdigest() == self.digest
        assert self.hash.digest() == self.digest.decode("hex")


    def test_hash_copy(self):
        copy = self.hash.copy()

        assert self.hash.hexdigest() == copy.hexdigest()

        self.hash.update("wolfcrypt")

        assert self.hash.hexdigest() != copy.hexdigest()

        copy.update("wolfcrypt")

        assert self.hash.hexdigest() == copy.hexdigest() == self.digest


class TestSha512(unittest.TestCase):
    digest = "88fcf67ffd8558d713f9cedcd852db479e6573f0bd9955610a993f609637553c"\
           + "e8fff55e644ee8a106aae19c07f91b3f2a2a6d40dfa7302c0fa6a1a9a5bfa03f"


    def setUp(self):
        self.hash = Sha512.new()


    def test_new(self):
        # invalid construction
        self.assertRaises(ValueError, Sha512)

        # update inside constructor
        assert Sha512.new("wolfcrypt").hexdigest() == self.digest


    def test_hash_update_001(self):
        self.hash.update("wolfcrypt")

        assert self.hash.hexdigest() == self.digest
        assert self.hash.digest() == self.digest.decode("hex")


    def test_hash_update_002(self):
        self.hash.update("wolf")
        self.hash.update("crypt")

        assert self.hash.hexdigest() == self.digest
        assert self.hash.digest() == self.digest.decode("hex")


    def test_hash_copy(self):
        copy = self.hash.copy()

        assert self.hash.hexdigest() == copy.hexdigest()

        self.hash.update("wolfcrypt")

        assert self.hash.hexdigest() != copy.hexdigest()

        copy.update("wolfcrypt")

        assert self.hash.hexdigest() == copy.hexdigest() == self.digest


_HMAC_KEY = "python"


class TestHmacSha(unittest.TestCase):
    digest = "5dfabcfb3a25540824867cd21f065f52f73491e0"


    def setUp(self):
        self.hash = HmacSha.new(_HMAC_KEY)


    def test_new(self):
        # invalid construction
        self.assertRaises(ValueError, HmacSha)

        # update inside constructor
        assert HmacSha.new(_HMAC_KEY, "wolfcrypt").hexdigest() == self.digest


    def test_hash_update_001(self):
        self.hash.update("wolfcrypt")

        assert self.hash.hexdigest() == self.digest
        assert self.hash.digest() == self.digest.decode("hex")


    def test_hash_update_002(self):
        self.hash.update("wolf")
        self.hash.update("crypt")

        assert self.hash.hexdigest() == self.digest
        assert self.hash.digest() == self.digest.decode("hex")


    def test_hash_copy(self):
        copy = self.hash.copy()

        assert self.hash.hexdigest() == copy.hexdigest()

        self.hash.update("wolfcrypt")

        assert self.hash.hexdigest() != copy.hexdigest()

        copy.update("wolfcrypt")

        assert self.hash.hexdigest() == copy.hexdigest() == self.digest


class TestHmacSha256(unittest.TestCase):
    digest = "4b641d721493d80f019d9447830ebfee89234a7d594378b89f8bb73873576bf6"


    def setUp(self):
        self.hash = HmacSha256.new(_HMAC_KEY)


    def test_new(self):
        # invalid construction
        self.assertRaises(ValueError, HmacSha256)

        # update inside constructor
        assert HmacSha256.new(_HMAC_KEY, "wolfcrypt").hexdigest() == self.digest


    def test_hash_update_001(self):
        self.hash.update("wolfcrypt")

        assert self.hash.hexdigest() == self.digest
        assert self.hash.digest() == self.digest.decode("hex")


    def test_hash_update_002(self):
        self.hash.update("wolf")
        self.hash.update("crypt")

        assert self.hash.hexdigest() == self.digest
        assert self.hash.digest() == self.digest.decode("hex")


    def test_hash_copy(self):
        copy = self.hash.copy()

        assert self.hash.hexdigest() == copy.hexdigest()

        self.hash.update("wolfcrypt")

        assert self.hash.hexdigest() != copy.hexdigest()

        copy.update("wolfcrypt")

        assert self.hash.hexdigest() == copy.hexdigest() == self.digest


class TestHmacSha384(unittest.TestCase):
    digest = "e72c72070c9c5c78e3286593068a510c1740cdf9dc34b512" \
           + "ccec97320295db1fe673216b46fe72e81f399a9ec04780ab"


    def setUp(self):
        self.hash = HmacSha384.new(_HMAC_KEY)


    def test_new(self):
        # invalid construction
        self.assertRaises(ValueError, HmacSha384)

        # update inside constructor
        assert HmacSha384.new(_HMAC_KEY, "wolfcrypt").hexdigest() == self.digest


    def test_hash_update_001(self):
        self.hash.update("wolfcrypt")

        assert self.hash.hexdigest() == self.digest
        assert self.hash.digest() == self.digest.decode("hex")


    def test_hash_update_002(self):
        self.hash.update("wolf")
        self.hash.update("crypt")

        assert self.hash.hexdigest() == self.digest
        assert self.hash.digest() == self.digest.decode("hex")


    def test_hash_copy(self):
        copy = self.hash.copy()

        assert self.hash.hexdigest() == copy.hexdigest()

        self.hash.update("wolfcrypt")

        assert self.hash.hexdigest() != copy.hexdigest()

        copy.update("wolfcrypt")

        assert self.hash.hexdigest() == copy.hexdigest() == self.digest


class TestHmacSha512(unittest.TestCase):
    digest = "c7f48db79314fc2b5be9a93fd58601a1bf42f397ec7f66dba034d44503890e6b"\
           + "5708242dcd71a248a78162d815c685f6038a4ac8cb34b8bf18986dbd300c9b41"


    def setUp(self):
        self.hash = HmacSha512.new(_HMAC_KEY)


    def test_new(self):
        # invalid construction
        self.assertRaises(ValueError, HmacSha512)

        # update inside constructor
        assert HmacSha512.new(_HMAC_KEY, "wolfcrypt").hexdigest() == self.digest


    def test_hash_update_001(self):
        self.hash.update("wolfcrypt")

        assert self.hash.hexdigest() == self.digest
        assert self.hash.digest() == self.digest.decode("hex")


    def test_hash_update_002(self):
        self.hash.update("wolf")
        self.hash.update("crypt")

        assert self.hash.hexdigest() == self.digest
        assert self.hash.digest() == self.digest.decode("hex")


    def test_hash_copy(self):
        copy = self.hash.copy()

        assert self.hash.hexdigest() == copy.hexdigest()

        self.hash.update("wolfcrypt")

        assert self.hash.hexdigest() != copy.hexdigest()

        copy.update("wolfcrypt")

        assert self.hash.hexdigest() == copy.hexdigest() == self.digest
