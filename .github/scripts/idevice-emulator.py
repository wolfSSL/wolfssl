#!/usr/bin/env python3
# Emulated iOS device for the libimobiledevice CI job.
#
# libimobiledevice never speaks USB: it talks to usbmuxd over a Unix socket,
# and libusbmuxd 2.x uses the one named by USBMUXD_SOCKET_ADDRESS=UNIX:<path>.
# This serves that socket plus the lockdownd service usbmuxd tunnels to, so
# the unmodified tools run a real pair / session exchange with no hardware.
#
# Two protocols, both plists on a socket:
#
#   usbmuxd   16-byte little-endian header (length including the header,
#             version, message type, tag) followed by an XML plist.
#             See usbmuxd/src/usbmuxd-proto.h and src/client.c.
#   lockdownd 4-byte big-endian length followed by an XML plist, on the
#             connection usbmuxd tunnels to port 62078.
#             See libimobiledevice/src/lockdown.c.
#
# The device RSA key is generated at startup. The host reads its public half
# through GetValue DevicePublicKey, issues the pair record certificates from
# it, and sends them in the Pair request; this checks those certificates and
# then serves the session TLS with the DeviceCertificate it was handed,
# requiring the host to present the RootCertificate as its client
# certificate - which is what libimobiledevice sends (src/idevice.c).

import argparse
import asyncio
import contextlib
import datetime
import errno
import os
import plistlib
import shutil
import signal
import socket
import ssl
import struct
import sys
import tempfile
import uuid
import warnings

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# usbmuxd framing and constants (usbmuxd/src/usbmuxd-proto.h).
USBMUX_HEADER = struct.Struct('<IIII')
USBMUX_VERSION_PLIST = 1
USBMUX_MESSAGE_PLIST = 8
RESULT_OK = 0
RESULT_BADCOMMAND = 1
RESULT_BADDEV = 2
RESULT_CONNREFUSED = 3

# usbmuxd reports a missing pair record as ENOENT, and libimobiledevice maps
# exactly that value to USERPREF_E_NOENT (common/userpref.c).
RESULT_NOENT = errno.ENOENT

# lockdownd framing and the port usbmuxd tunnels it on.
LOCKDOWN_HEADER = struct.Struct('>I')
LOCKDOWN_PORT = 62078
LOCKDOWN_TYPE = 'com.apple.mobile.lockdown'

# pair_record_generate_keys_and_certs() dates the certificates ten years out.
MIN_DEVICE_CERT_LIFETIME = datetime.timedelta(days=9 * 365)


class Log:
    """One line per event, for the CI job to assert on."""

    def __init__(self, path):
        self._file = open(path, 'w', buffering=1, encoding='utf-8')

    def __call__(self, message):
        stamp = datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]
        self._file.write('%s %s\n' % (stamp, message))

    def close(self):
        self._file.close()


def not_valid_after(cert):
    """cryptography 42 deprecated the naive not_valid_after."""
    value = getattr(cert, 'not_valid_after_utc', None)
    if value is None:
        value = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
    return value


def subject_text(cert):
    """The tools' certificates carry an empty subject DN."""
    return cert.subject.rfc4514_string() or '<empty>'


class Device:
    """Everything the emulated device knows about itself."""

    def __init__(self, args):
        self.udid = args.udid
        self.device_id = 1
        self.buid = str(uuid.uuid4()).upper()
        self.key = rsa.generate_private_key(public_exponent=65537,
                                            key_size=2048)
        # lockdownd hands out the device public key in PKCS#1 form; that is
        # what pair_record_generate_keys_and_certs() reads back with
        # PEM_read_bio_RSAPublicKey().
        self.public_key_pem = self.key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.PKCS1)
        self.values = {
            None: {
                'BuildVersion': '22G86',
                'CPUArchitecture': 'arm64e',
                'DeviceClass': 'iPhone',
                'DeviceColor': '1',
                'DeviceName': args.device_name,
                'DevicePublicKey': self.public_key_pem,
                'HardwareModel': 'D73AP',
                'HardwarePlatform': 't8110',
                'ProductName': 'iPhone OS',
                'ProductType': args.product_type,
                'ProductVersion': args.product_version,
                'ProtocolVersion': '2',
                'SerialNumber': 'F2LX90ABCDEF',
                'TimeIntervalSince1970': 0,
                'TimeZone': 'Etc/UTC',
                'UniqueDeviceID': self.udid,
                'WiFiAddress': args.wifi_address,
            },
        }
        # The pair record the device itself keeps, as set by Pair and dropped
        # by Unpair. Separate from the host-side records usbmuxd stores.
        self.pair_record = None


class Emulator:
    def __init__(self, args, log):
        self.log = log
        self.device = Device(args)
        # The host-side pair record store usbmuxd keeps, keyed by UDID.
        self.records = {}
        self._tmpdir = tempfile.mkdtemp(prefix='idevice-emulator-')

    def close(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    # ---- usbmuxd -----------------------------------------------------------

    def _attached(self):
        return {
            'MessageType': 'Attached',
            'DeviceID': self.device.device_id,
            'Properties': {
                'ConnectionSpeed': 480000000,
                'ConnectionType': 'USB',
                'DeviceID': self.device.device_id,
                'LocationID': 0,
                'ProductID': 0x12a8,
                'SerialNumber': self.device.udid,
            },
        }

    @staticmethod
    def _send_usbmux(writer, tag, payload):
        body = plistlib.dumps(payload)
        writer.write(USBMUX_HEADER.pack(USBMUX_HEADER.size + len(body),
                                        USBMUX_VERSION_PLIST,
                                        USBMUX_MESSAGE_PLIST, tag) + body)

    def _send_result(self, writer, tag, number):
        self._send_usbmux(writer, tag, {'MessageType': 'Result',
                                        'Number': number})

    async def handle_usbmux(self, reader, writer):
        try:
            while True:
                header = await reader.readexactly(USBMUX_HEADER.size)
                length, _, message, tag = USBMUX_HEADER.unpack(header)
                payload = await reader.readexactly(
                    max(0, length - USBMUX_HEADER.size))
                if message != USBMUX_MESSAGE_PLIST or not payload:
                    self.log('usbmux: message type %d -> BadCommand' % message)
                    self._send_result(writer, tag, RESULT_BADCOMMAND)
                    continue
                if await self._usbmux_request(reader, writer, tag,
                                              plistlib.loads(payload)):
                    return
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionResetError,
                BrokenPipeError):
            pass
        finally:
            with contextlib.suppress(OSError):
                writer.close()

    async def _usbmux_request(self, reader, writer, tag, request):
        """Answer one usbmuxd request; True means the connection was taken
        over by the tunnelled lockdownd session."""
        message = request.get('MessageType')
        record_id = request.get('PairRecordID')

        if message == 'ListDevices':
            self._send_usbmux(writer, tag, {'DeviceList': [self._attached()]})
            self.log('usbmux: ListDevices -> 1 device %s' % self.device.udid)
        elif message == 'Listen':
            self._send_result(writer, tag, RESULT_OK)
            self._send_usbmux(writer, 0, self._attached())
            self.log('usbmux: Listen -> Attached DeviceID=%d'
                     % self.device.device_id)
        elif message == 'ReadBUID':
            self._send_usbmux(writer, tag, {'BUID': self.device.buid})
            self.log('usbmux: ReadBUID -> %s' % self.device.buid)
        elif message == 'ReadPairRecord':
            data = self.records.get(record_id)
            if data is None:
                self._send_result(writer, tag, RESULT_NOENT)
                self.log('usbmux: ReadPairRecord %s -> not found (ENOENT)'
                         % record_id)
            else:
                self._send_usbmux(writer, tag, {'PairRecordData': data})
                self.log('usbmux: ReadPairRecord %s -> %d bytes'
                         % (record_id, len(data)))
        elif message == 'SavePairRecord':
            data = request['PairRecordData']
            try:
                detail = self._check_saved_record(data)
            except (ValueError, KeyError, TypeError) as exc:
                self._send_result(writer, tag, RESULT_BADCOMMAND)
                self.log('pair: stored pair record REJECTED: %s' % exc)
                return False
            self.records[record_id] = data
            self._send_result(writer, tag, RESULT_OK)
            self.log('usbmux: SavePairRecord %s -> stored %d bytes, %s'
                     % (record_id, len(data), detail))
        elif message == 'DeletePairRecord':
            existed = self.records.pop(record_id, None) is not None
            self._send_result(writer, tag, RESULT_OK)
            self.log('usbmux: DeletePairRecord %s -> %s' % (
                record_id, 'deleted' if existed else 'no such record'))
        elif message == 'Connect':
            return await self._usbmux_connect(reader, writer, tag, request)
        else:
            self._send_result(writer, tag, RESULT_BADCOMMAND)
            self.log('usbmux: %s -> BadCommand' % message)
        return False

    async def _usbmux_connect(self, reader, writer, tag, request):
        # PortNumber travels in network byte order.
        port = socket.ntohs(request.get('PortNumber', 0) & 0xffff)
        device_id = request.get('DeviceID')
        if device_id != self.device.device_id:
            self._send_result(writer, tag, RESULT_BADDEV)
            self.log('usbmux: Connect DeviceID=%s -> BadDevice' % device_id)
            return False
        if port != LOCKDOWN_PORT:
            self._send_result(writer, tag, RESULT_CONNREFUSED)
            self.log('usbmux: Connect port=%d -> ConnectionRefused' % port)
            return False
        self._send_result(writer, tag, RESULT_OK)
        await writer.drain()
        self.log('usbmux: Connect DeviceID=%d port=%d -> lockdownd'
                 % (device_id, port))
        # From here the socket carries the device stream verbatim, so the
        # lockdownd handler takes it over for the rest of the connection.
        await self.serve_lockdown(reader, writer)
        return True

    # ---- lockdownd ---------------------------------------------------------

    @staticmethod
    async def _send_lockdown(writer, reply):
        body = plistlib.dumps(reply)
        writer.write(LOCKDOWN_HEADER.pack(len(body)) + body)
        await writer.drain()

    async def serve_lockdown(self, reader, writer):
        session_id = None
        try:
            while True:
                header = await reader.readexactly(LOCKDOWN_HEADER.size)
                (length,) = LOCKDOWN_HEADER.unpack(header)
                request = plistlib.loads(await reader.readexactly(length))
                name = request.get('Request')
                tail = ' [session %s]' % session_id if session_id else ''

                if name == 'QueryType':
                    reply = {'Request': name, 'Type': LOCKDOWN_TYPE}
                    self.log('lockdown: QueryType -> %s%s'
                             % (LOCKDOWN_TYPE, tail))
                elif name == 'GetValue':
                    reply = self._get_value(request, tail)
                elif name in ('Pair', 'ValidatePair', 'Unpair'):
                    reply = self._pairing(name, request)
                elif name == 'StartSession':
                    reply = self._start_session(request)
                elif name == 'StopSession':
                    reply = {'Request': name, 'Result': 'Success'}
                    self.log('lockdown: StopSession%s -> Success' % tail)
                    session_id = None
                elif name == 'StartService':
                    # No services are emulated.
                    reply = {'Request': name, 'Error': 'InvalidService'}
                    self.log('lockdown: StartService %s -> InvalidService%s'
                             % (request.get('Service'), tail))
                elif name == 'Goodbye':
                    reply = {'Request': name, 'Result': 'Success'}
                    self.log('lockdown: Goodbye -> Success%s' % tail)
                    await self._send_lockdown(writer, reply)
                    return
                else:
                    reply = {'Request': name, 'Error': 'InvalidRequest'}
                    self.log('lockdown: %s -> InvalidRequest%s' % (name, tail))

                await self._send_lockdown(writer, reply)

                if reply.get('EnableSessionSSL'):
                    session_id = reply['SessionID']
                    reader, writer = await self._enable_ssl(reader, writer)
        except (asyncio.IncompleteReadError, ConnectionResetError,
                BrokenPipeError, ssl.SSLError):
            pass

    def _get_value(self, request, tail):
        domain = request.get('Domain')
        key = request.get('Key')
        values = self.device.values.get(domain, {})
        reply = {'Request': 'GetValue'}
        if domain is not None:
            reply['Domain'] = domain
        if key is not None:
            reply['Key'] = key
        if key is None:
            reply['Value'] = values
            shown = '%d values' % len(values)
        elif key in values:
            reply['Value'] = values[key]
            shown = repr(values[key])[:60]
        else:
            reply['Error'] = 'MissingValue'
            shown = 'MissingValue'
        self.log('lockdown: GetValue domain=%s key=%s -> %s%s'
                 % (domain or '-', key or '-', shown, tail))
        return reply

    def _pairing(self, name, request):
        record = request.get('PairRecord') or {}
        host_id = record.get('HostID')
        if name == 'Unpair':
            self.device.pair_record = None
            self.log('lockdown: Unpair HostID=%s -> Success, device pair '
                     'record dropped' % host_id)
            return {'Request': name, 'Result': 'Success'}
        if name == 'ValidatePair':
            known = self.device.pair_record
            if not known or known.get('HostID') != host_id:
                self.log('lockdown: ValidatePair HostID=%s -> InvalidHostID'
                         % host_id)
                return {'Request': name, 'Error': 'InvalidHostID'}
            self.log('lockdown: ValidatePair HostID=%s -> Success' % host_id)
            return {'Request': name, 'Result': 'Success'}

        self.log('lockdown: Pair HostID=%s SystemBUID=%s'
                 % (host_id, record.get('SystemBUID')))
        try:
            self.log('pair: pair record verified: %s' % self._check_record(
                record))
        except (ValueError, KeyError, TypeError,
                x509.ExtensionNotFound) as exc:
            self.log('pair: pair record REJECTED: %s' % exc)
            return {'Request': name, 'Error': 'InvalidPairRecord'}
        self.device.pair_record = record
        # A real device answers a successful pairing with an escrow bag.
        return {'Request': name, 'Result': 'Success',
                'EscrowBag': os.urandom(64)}

    def _check_record(self, record):
        """Check the certificates the host generated for this device."""
        root = x509.load_pem_x509_certificate(record['RootCertificate'])
        host = x509.load_pem_x509_certificate(record['HostCertificate'])
        device = x509.load_pem_x509_certificate(record['DeviceCertificate'])
        if not record.get('HostID') or not record.get('SystemBUID'):
            raise ValueError('HostID or SystemBUID missing')

        for name, cert in (('root', root), ('host', host),
                           ('device', device)):
            # Every certificate is signed by the root private key, and the
            # root signs itself.
            try:
                root.public_key().verify(cert.signature,
                                         cert.tbs_certificate_bytes,
                                         padding.PKCS1v15(),
                                         cert.signature_hash_algorithm)
            except Exception:
                raise ValueError('%s certificate does not chain to the root'
                                 % name)

        if not root.extensions.get_extension_for_class(
                x509.BasicConstraints).value.ca:
            raise ValueError('root certificate is not a CA')
        for name, cert in (('host', host), ('device', device)):
            if cert.extensions.get_extension_for_class(
                    x509.BasicConstraints).value.ca:
                raise ValueError('%s certificate is a CA' % name)
            usage = cert.extensions.get_extension_for_class(
                x509.KeyUsage).value
            if not (usage.digital_signature and usage.key_encipherment
                    and not usage.content_commitment
                    and not usage.data_encipherment
                    and not usage.key_agreement
                    and not usage.key_cert_sign and not usage.crl_sign):
                raise ValueError('%s certificate key usage is %s'
                                 % (name, usage))

        public_key = self.device.key.public_key()
        if device.public_key().public_numbers() != public_key.public_numbers():
            raise ValueError('device certificate carries a foreign key')
        # RFC 5280 method 1: the SHA-1 of the public key bit string.
        expected = x509.SubjectKeyIdentifier.from_public_key(public_key)
        found = device.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier).value
        if found.digest != expected.digest:
            raise ValueError('device certificate subject key identifier %s '
                             'does not match the device key'
                             % found.digest.hex())

        lifetime = not_valid_after(device) - datetime.datetime.now(
            datetime.timezone.utc)
        if lifetime < MIN_DEVICE_CERT_LIFETIME:
            raise ValueError('device certificate expires in %s' % lifetime)

        return ('root is a CA and self-signed (%s), host and device '
                'certificates chain to it, neither is a CA, both carry '
                'digitalSignature+keyEncipherment, device SKI %s matches the '
                'device key, device certificate valid for %d days'
                % (root.signature_hash_algorithm.name,
                   found.digest.hex(), lifetime.days))

    def _check_saved_record(self, data):
        """Check the record the host stores for itself.

        The Pair request strips the private keys out, so they are only
        visible here; libimobiledevice reads the root key back out of this
        record to authenticate the session TLS (src/idevice.c).
        """
        record = plistlib.loads(data)
        for name in ('Root', 'Host'):
            cert = x509.load_pem_x509_certificate(record[name +
                                                         'Certificate'])
            key = serialization.load_pem_private_key(
                record[name + 'PrivateKey'], None)
            if (key.public_key().public_numbers()
                    != cert.public_key().public_numbers()):
                raise ValueError('%sPrivateKey does not match %sCertificate'
                                 % (name, name))
        return 'root and host private keys match their certificates'

    def _start_session(self, request):
        host_id = request.get('HostID')
        known = self.device.pair_record
        if not known or known.get('HostID') != host_id:
            self.log('lockdown: StartSession HostID=%s -> InvalidHostID'
                     % host_id)
            return {'Request': 'StartSession', 'Error': 'InvalidHostID'}
        session_id = str(uuid.uuid4()).upper()
        self.log('lockdown: StartSession HostID=%s -> SessionID=%s '
                 'EnableSessionSSL=true' % (host_id, session_id))
        return {'Request': 'StartSession', 'Result': 'Success',
                'SessionID': session_id, 'EnableSessionSSL': True}

    # ---- session TLS -------------------------------------------------------

    def _ssl_context(self):
        record = self.device.pair_record
        cert = os.path.join(self._tmpdir, 'device.pem')
        with open(cert, 'wb') as handle:
            handle.write(record['DeviceCertificate'])
            handle.write(self.device.key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        with warnings.catch_warnings():
            # The enum member is deprecated, TLS 1.0 itself still works and
            # libimobiledevice pins it for devices below iOS 10
            # (src/idevice.c).
            warnings.simplefilter('ignore', DeprecationWarning)
            context.minimum_version = ssl.TLSVersion.TLSv1
        context.set_ciphers('DEFAULT:@SECLEVEL=0')
        # The host presents the RootCertificate as its client certificate.
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(
            cadata=record['RootCertificate'].decode('ascii'))
        context.load_cert_chain(cert)
        return context

    async def _enable_ssl(self, reader, writer):
        # Stop reading before the StartSession reply reaches the host, so its
        # ClientHello cannot land in the stream buffer that start_tls() is
        # about to replace.
        writer.transport.pause_reading()
        await writer.start_tls(self._ssl_context())
        session = writer.get_extra_info('ssl_object')
        peer = x509.load_der_x509_certificate(session.getpeercert(True))
        root = x509.load_pem_x509_certificate(
            self.device.pair_record['RootCertificate'])
        self.log('tls: session established version=%s cipher=%s client '
                 'certificate subject=%s (%s)'
                 % (session.version(), session.cipher()[0], subject_text(peer),
                    'matches RootCertificate from the pair record'
                    if peer == root else 'NOT the RootCertificate'))
        return reader, writer


async def main_async(args):
    log = Log(args.log)
    emulator = Emulator(args, log)
    if os.path.exists(args.socket):
        os.unlink(args.socket)
    server = await asyncio.start_unix_server(emulator.handle_usbmux,
                                             path=args.socket)
    log('ready: udid=%s ProductVersion=%s socket=%s'
        % (emulator.device.udid, args.product_version, args.socket))

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signame in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(signame, stop.set)
    await stop.wait()

    log('stopping on signal')
    server.close()
    await server.wait_closed()
    emulator.close()
    with contextlib.suppress(OSError):
        os.unlink(args.socket)
    log.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--socket', default='/tmp/idevice-emulator.sock',
                        help='Unix socket to serve the usbmuxd protocol on')
    parser.add_argument('--log', default='/tmp/idevice-emulator.log',
                        help='file to write one line per event to')
    parser.add_argument('--udid',
                        default='1e2f3a4b5c6d7e8f90a1b2c3d4e5f60718293a4b',
                        help='UDID the emulated device reports')
    parser.add_argument('--product-version', default='18.6',
                        help='iOS version the emulated device reports')
    parser.add_argument('--product-type', default='iPhone15,2')
    parser.add_argument('--device-name', default='CI Emulated Device')
    parser.add_argument('--wifi-address', default='00:1a:2b:3c:4d:5e')
    args = parser.parse_args()
    asyncio.run(main_async(args))
    return 0


if __name__ == '__main__':
    sys.exit(main())
