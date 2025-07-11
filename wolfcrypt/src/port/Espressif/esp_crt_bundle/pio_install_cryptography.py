#!/usr/bin/env python
#
#  pio_install_cryptography.py
#
# Copyright (C) 2006-2025 wolfSSL Inc.
#
# This file is part of wolfSSL.
#
# wolfSSL is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# wolfSSL is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
#
# Import("env")
import subprocess
import sys

# Function to install a package
def install(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

try:
    # Check if cryptography is installed
    import cryptography
except ImportError:
    # If not installed, install it
    print("cryptography package not found. Installing...")
    install("cryptography")
