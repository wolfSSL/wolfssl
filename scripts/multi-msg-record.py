#!/usr/bin/env python3
#
# multi-msg-record.py
#
# Python half of scripts/multi-msg-record.test (the bash wrapper handles
# NETWORK_UNSHARE_HELPER / AM_BWRAPPED and the python3 availability
# check, then execs this script).
#
# Tests that wolfSSL correctly processes TLS records containing multiple
# handshake messages packed into a single record.
#
# Uses tlslite-ng as the TLS peer to craft multi-message records:
#
#   TLS 1.2  – Each connection tests TWO code paths back-to-back:
#                1. Initial handshake: RecordMergingSocket rewrites separate
#                   plaintext ServerHello + Certificate + ServerKeyExchange +
#                   ServerHelloDone records into one multi-message TLS
#                   record before forwarding to the wolfSSL client.
#                2. Renegotiation on the same connection: tlslite-ng is
#                   monkey-patched to coalesce SH+Cert+SKE+SHD into ONE
#                   encrypted handshake record (exercises the
#                   curSize -= padSz CBC-padding path and the AEAD path).
#
#   TLS 1.3  – tlslite-ng's _queue_message / _queue_flush mechanism already
#              coalesces EncryptedExtensions + Certificate + CertificateVerify
#              + Finished into a single encrypted record.  The test verifies
#              that wolfSSL parses this correctly.
#
# Multiple cipher suites are tested for both protocol versions.
#
# Requirements: python3, tlslite-ng  (pip install tlslite-ng)

import socket
import struct
import subprocess
import os
import sys
import threading
import time
import types

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
WOLFSSL_DIR = os.path.dirname(SCRIPT_DIR)
WOLF_CLIENT = os.path.join(WOLFSSL_DIR, "examples", "client", "client")
CERT_DIR = os.path.join(WOLFSSL_DIR, "certs")

# ---------------------------------------------------------------------------
# Bypass a strict tlslite-ng validation that rejects wolfSSL's ClientHello
# when the client advertises FFDHE groups in a TLS-1.3-only hello.
# This must happen before importing TLSConnection.
#
# If tlslite-ng isn't installed we exit 77 so automake marks the test
# SKIPped instead of FAILed.
# ---------------------------------------------------------------------------
try:
    import tlslite.tlsconnection                # noqa: E402
    import tlslite.recordlayer                   # noqa: E402
    tlslite.tlsconnection.TLS_1_3_FORBIDDEN_GROUPS = frozenset()

    from tlslite import (                       # noqa: E402
        TLSConnection, HandshakeSettings, X509CertChain, parsePEMKey,
    )
    from tlslite.constants import ContentType   # noqa: E402
    from tlslite.extensions import RenegotiationInfoExtension  # noqa: E402
    from tlslite.constants import ExtensionType  # noqa: E402
    from tlslite.messages import HelloMessage, Message as TLSMessage  # noqa: E402
except ImportError as e:
    sys.stdout.write(
        "tlslite-ng not installed ({}); skipping multi-msg-record test\n"
        "  (install with: pip install tlslite-ng)\n".format(e))
    sys.exit(77)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
HS_NAMES = {
    2: "SH", 4: "NST", 8: "EE", 11: "Cert", 12: "SKE",
    13: "CR", 14: "SHD", 15: "CV", 16: "CKE", 20: "Fin",
}

PASS_COUNT = 0
FAIL_COUNT = 0
SKIP_COUNT = 0


def passed(label):
    global PASS_COUNT
    PASS_COUNT += 1
    print(f"  PASS: {label}")


def failed(label):
    global FAIL_COUNT
    FAIL_COUNT += 1
    print(f"  FAIL: {label}")


def skipped(label):
    global SKIP_COUNT
    SKIP_COUNT += 1
    print(f"  SKIP: {label}")


def detect_wolf_features():
    """Probe the wolfSSL client binary to find which features are
    compiled in.  Used to decide which test phases to run.

    Returns dict with boolean keys: tls12, tls13, secure_reneg.
    """
    feats = {"tls12": False, "tls13": False, "secure_reneg": False}

    # ./client -V  ->  e.g. "3:4:d(downgrade):e(either):"
    try:
        r = subprocess.run([WOLF_CLIENT, "-V"],
                           capture_output=True, timeout=5)
        parts = r.stdout.decode("utf-8", errors="replace").strip().split(":")
        feats["tls12"] = "3" in parts
        feats["tls13"] = "4" in parts
    except Exception:
        pass

    # ./client -?  -> help text includes "-R" only when
    # HAVE_SECURE_RENEGOTIATION is defined.
    try:
        r = subprocess.run([WOLF_CLIENT, "-?"],
                           capture_output=True, timeout=5)
        htxt = r.stdout.decode("utf-8", errors="replace")
        feats["secure_reneg"] = ("Allow Secure Renegotiation" in htxt)
    except Exception:
        pass

    return feats


def _load_chain(cert_file):
    with open(cert_file) as f:
        chain = X509CertChain()
        chain.parsePemList(f.read())
    return chain


def _load_key(key_file):
    with open(key_file) as f:
        return parsePEMKey(f.read(), private=True)


def _parse_hs_types(data):
    """Parse handshake message types from raw handshake content."""
    msgs = []
    off = 0
    while off + 4 <= len(data):
        ht = data[off]
        hl = struct.unpack("!I", b"\x00" + bytes(data[off + 1 : off + 4]))[0]
        msgs.append(HS_NAMES.get(ht, f"T{ht}"))
        off += 4 + hl
    return msgs


def _get_free_port():
    """Get an available TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _listen_socket():
    """Bind a listening TCP socket on localhost with the standard test timeout."""
    port = _get_free_port()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(1)
    srv.settimeout(15)
    return srv, port


def _run_wolf_client(port, version, cipher, extra=()):
    """Invoke the wolfSSL example client against 127.0.0.1:port."""
    cmd = [WOLF_CLIENT, "-h", "127.0.0.1", "-p", str(port),
           "-v", version, "-A", os.path.join(CERT_DIR, "ca-cert.pem"),
           "-g", *extra]
    if cipher:
        cmd.extend(["-l", cipher])
    return subprocess.run(cmd, capture_output=True, timeout=15)


class _SendRecordTrace:
    """Context manager that wraps RecordLayer.sendRecord to log every record."""

    def __init__(self):
        self.log = []
        self._orig = None

    def __enter__(self):
        self._orig = tlslite.recordlayer.RecordLayer.sendRecord
        log = self.log
        orig = self._orig

        def wrapper(self_rl, msg):
            data = msg.write()
            ct = msg.contentType
            encrypted = bool(self_rl._writeState
                             and self_rl._writeState.encContext)
            hs_msgs = []
            if ct == ContentType.handshake:
                hs_msgs = _parse_hs_types(data)
            log.append((ct, encrypted, len(data), hs_msgs))
            yield from orig(self_rl, msg)

        tlslite.recordlayer.RecordLayer.sendRecord = wrapper
        return self.log

    def __exit__(self, *exc):
        tlslite.recordlayer.RecordLayer.sendRecord = self._orig


# ---------------------------------------------------------------------------
# RecordMergingSocket  (TLS 1.2 plaintext record merging)
# ---------------------------------------------------------------------------
class RecordMergingSocket:
    """Socket wrapper that rewrites consecutive TLS handshake records into
    a single multi-message record.  Only merges plaintext records that
    precede ChangeCipherSpec."""

    def __init__(self, sock):
        self._sock = sock
        self._pending = bytearray()
        self._ver = 0x0303
        self._after_ccs = False
        self.merged_msgs = []          # [(n_msgs, [names], size)]

    def _flush(self):
        if not self._pending:
            return
        msgs = _parse_hs_types(self._pending)
        n = len(msgs)
        hdr = struct.pack("!BHH", 22, self._ver, len(self._pending))
        self._sock.sendall(hdr + bytes(self._pending))
        self.merged_msgs.append((n, msgs, len(self._pending)))
        self._pending = bytearray()

    # Called by BufferedSocket (one record per call, or multiple from flush)
    def _process(self, data):
        data = bytearray(data)
        off = 0
        while off + 5 <= len(data):
            ct = data[off]
            ver = struct.unpack("!H", data[off + 1 : off + 3])[0]
            rlen = struct.unpack("!H", data[off + 3 : off + 5])[0]
            if off + 5 + rlen > len(data):
                break
            payload = data[off + 5 : off + 5 + rlen]
            if not self._after_ccs and ct == 22:
                self._pending.extend(payload)
                self._ver = ver
            else:
                if ct == 20:
                    self._after_ccs = True
                self._flush()
                self._sock.sendall(bytes(data[off : off + 5 + rlen]))
            off += 5 + rlen

    def send(self, data):
        self._process(data)
        return len(data)

    def sendall(self, data):
        self._process(data)

    def recv(self, bufsize):
        self._flush()
        return self._sock.recv(bufsize)

    def __getattr__(self, name):
        return getattr(self._sock, name)


# ---------------------------------------------------------------------------
# Test runners
# ---------------------------------------------------------------------------
def run_tls12_test(cipher_wolf, cert_chain, priv_key, label,
                   do_reneg=True):
    """TLS 1.2 test – one connection optionally exercises two code paths:

    Phase 1 (plaintext grouping, initial handshake):
        RecordMergingSocket rewrites separate plaintext ServerHello,
        Certificate, ServerKeyExchange and ServerHelloDone records into
        one multi-message TLS record before delivery to wolfSSL.

    Phase 2 (encrypted grouping, renegotiation on same connection):
        tlslite-ng server is monkey-patched to coalesce SH+Cert+SKE+SHD
        into a single encrypted handshake record inside the renegotiation
        (exercises wolfSSL's encrypted multi-message parsing including
        curSize -= padSz for CBC padding).

    Phase 2 is skipped when do_reneg=False (e.g. the wolfSSL client was
    built without HAVE_SECURE_RENEGOTIATION).
    """
    srv, port = _listen_socket()

    result = {"ok": False, "error": ""}
    msock_ref = [None]
    trace_log = []
    reneg_active = [False]
    verify_data = {'client': None, 'server': None}

    # --- monkey-patches (used only during this connection) ----------------
    orig_calc_key = tlslite.tlsconnection.calc_key

    def capturing_calc_key(*args, **kwargs):
        res = orig_calc_key(*args, **kwargs)
        lbl = args[3] if len(args) > 3 else kwargs.get('label', b'')
        if lbl == b"client finished" and verify_data['client'] is None:
            verify_data['client'] = bytearray(res)
        elif lbl == b"server finished" and verify_data['server'] is None:
            verify_data['server'] = bytearray(res)
        return res

    orig_getExt = HelloMessage.getExtension

    def patched_getExt(self, ext_type):
        ext = orig_getExt(self, ext_type)
        if (ext_type == ExtensionType.renegotiation_info
                and ext is not None and reneg_active[0]):
            ext._internal_value = bytearray(0)
        return ext

    orig_rie_create = RenegotiationInfoExtension.create

    def patched_rie_create(self, data):
        if reneg_active[0] and data == bytearray(0):
            combined = (bytearray(verify_data['client'])
                        + bytearray(verify_data['server']))
            return orig_rie_create(self, combined)
        return orig_rie_create(self, data)

    # ----------------------------------------------------------------------
    def server():
        try:
            tlslite.tlsconnection.calc_key = capturing_calc_key
            HelloMessage.getExtension = patched_getExt
            RenegotiationInfoExtension.create = patched_rie_create

            conn, _ = srv.accept()
            conn.settimeout(15)
            msock = RecordMergingSocket(conn)
            msock_ref[0] = msock
            tls = TLSConnection(msock)
            settings = HandshakeSettings()
            settings.minVersion = (3, 3)
            settings.maxVersion = (3, 3)

            # ---------- Phase 1: initial handshake (plaintext grouping) ----
            tls.handshakeServer(certChain=cert_chain, privateKey=priv_key,
                                settings=settings)
            tlslite.tlsconnection.calc_key = orig_calc_key

            data = tls.recv(4096)

            if do_reneg:
                # ---------- Phase 2: trigger + run renegotiation ----------
                hr = TLSMessage(ContentType.handshake,
                                bytearray([0, 0, 0, 0]))
                for _ in tls._sendMsg(hr, randomizeFirstBlock=False,
                                      update_hashes=False):
                    pass

                # Bypass tlslite-ng renegotiation guards
                tls.closed = True
                tls.session = None
                reneg_active[0] = True

                # Coalesce handshake messages into ONE encrypted TLS record
                def coalescing_sendMsgs(self, msgs):
                    for msg in msgs:
                        self._queue_message(msg)
                    yield from self._queue_flush()
                tls._sendMsgs = types.MethodType(coalescing_sendMsgs, tls)

                with _SendRecordTrace() as log:
                    tls.handshakeServer(certChain=cert_chain,
                                        privateKey=priv_key,
                                        settings=settings)
                reneg_active[0] = False
                trace_log.extend(log)

            if data:
                tls.send(data)
            tls.close()
            result["ok"] = True
        except Exception as e:
            import traceback
            result["error"] = traceback.format_exc()
        finally:
            tlslite.tlsconnection.calc_key = orig_calc_key
            HelloMessage.getExtension = orig_getExt
            RenegotiationInfoExtension.create = orig_rie_create
            reneg_active[0] = False
            srv.close()

    st = threading.Thread(target=server, daemon=True)
    st.start()
    time.sleep(0.1)

    proc = _run_wolf_client(port, "3", cipher_wolf,
                            extra=("-R",) if do_reneg else ())
    st.join(timeout=5)

    if proc.returncode != 0 or not result["ok"]:
        err = (result["error"]
               or proc.stderr.decode("utf-8", errors="replace")[:400])
        failed(f"{label}: connection failed ({err})")
        return False

    ok = True

    # Phase 1 verification: plaintext multi-message record
    msock = msock_ref[0]
    has_pt_grouped = False
    for n, msgs, sz in (msock.merged_msgs if msock else []):
        if n > 1:
            has_pt_grouped = True
            passed(f"{label} [plaintext]: {n} msgs "
                   f"[{'+'.join(msgs)}] in one record ({sz} bytes)")
    if not has_pt_grouped:
        failed(f"{label} [plaintext]: no multi-message record detected")
        ok = False

    # Phase 2 verification: encrypted multi-message record (renego)
    if do_reneg:
        has_enc_grouped = False
        for ct, enc, sz, msgs in trace_log:
            if ct == ContentType.handshake and enc and len(msgs) > 1:
                has_enc_grouped = True
                passed(f"{label} [encrypted]: {len(msgs)} msgs "
                       f"[{'+'.join(msgs)}] in one record ({sz} bytes)")
        if not has_enc_grouped:
            failed(f"{label} [encrypted]: no multi-message "
                   f"encrypted record")
            ok = False

    return ok


def run_tls13_test(cipher_wolf, cert_chain, priv_key, label):
    """TLS 1.3: verify tlslite-ng sends multi-msg encrypted record and
    wolfSSL client processes it."""
    srv, port = _listen_socket()

    result = {"ok": False, "error": ""}

    def server():
        try:
            conn, _ = srv.accept()
            conn.settimeout(15)
            tls = TLSConnection(conn)
            settings = HandshakeSettings()
            settings.minVersion = (3, 4)
            settings.maxVersion = (3, 4)
            tls.handshakeServer(certChain=cert_chain, privateKey=priv_key,
                                settings=settings)
            data = tls.recv(4096)
            if data:
                tls.send(data)
            tls.close()
            result["ok"] = True
        except Exception as e:
            result["error"] = str(e)
        finally:
            srv.close()

    with _SendRecordTrace() as log:
        st = threading.Thread(target=server, daemon=True)
        st.start()
        time.sleep(0.1)

        proc = _run_wolf_client(port, "4", cipher_wolf)
        st.join(timeout=5)

    if proc.returncode != 0 or not result["ok"]:
        err = result["error"] or proc.stderr.decode("utf-8", errors="replace")[:200]
        failed(f"{label}: handshake failed ({err})")
        return False

    # Check that at least one encrypted handshake record has multiple messages
    has_multi = False
    for ct, enc, sz, msgs in log:
        if ct == ContentType.handshake and enc and len(msgs) > 1:
            has_multi = True
            passed(f"{label}: {len(msgs)} encrypted msgs "
                   f"[{'+'.join(msgs)}] in one record ({sz} bytes)")
    if not has_multi:
        failed(f"{label}: no multi-message encrypted records")
        return False
    return True


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    if not os.path.isfile(WOLF_CLIENT):
        print(f"ERROR: wolfSSL client not found: {WOLF_CLIENT}")
        print("       Build wolfSSL first (./configure && make)")
        sys.exit(1)

    # Probe the client to see which features are compiled in so each
    # phase of the test is only run when it can succeed.
    feats = detect_wolf_features()

    # Load certificate / key pairs
    rsa_chain = _load_chain(os.path.join(CERT_DIR, "server-cert.pem"))
    rsa_key = _load_key(os.path.join(CERT_DIR, "server-key.pem"))

    print("=" * 60)
    print(" Multi-Message TLS Record Test")
    print("=" * 60)
    print(f"  wolfSSL features: TLS1.2={feats['tls12']} "
          f"TLS1.3={feats['tls13']} "
          f"secure_reneg={feats['secure_reneg']}")

    # ------------------------------------------------------------------
    # TLS 1.2 – plaintext (initial HS) + optional encrypted (renegotiation)
    # multi-message records, same connection per cipher suite.
    # ------------------------------------------------------------------
    tls12_suites = [
        # (wolfSSL cipher name,  description)
        (None,                              "default negotiated"),
        # AEAD (GCM)
        ("ECDHE-RSA-AES128-GCM-SHA256",    "ECDHE-RSA AES128-GCM"),
        ("ECDHE-RSA-AES256-GCM-SHA384",    "ECDHE-RSA AES256-GCM"),
        ("DHE-RSA-AES128-GCM-SHA256",      "DHE-RSA   AES128-GCM"),
        ("DHE-RSA-AES256-GCM-SHA384",      "DHE-RSA   AES256-GCM"),
        # CBC + HMAC (exercises padding path)
        ("ECDHE-RSA-AES128-SHA256",        "ECDHE-RSA AES128-CBC-SHA256"),
        ("ECDHE-RSA-AES256-SHA384",        "ECDHE-RSA AES256-CBC-SHA384"),
        ("DHE-RSA-AES128-SHA256",          "DHE-RSA   AES128-CBC-SHA256"),
        ("DHE-RSA-AES256-SHA256",          "DHE-RSA   AES256-CBC-SHA256"),
        # AEAD (ChaCha20-Poly1305)
        ("ECDHE-RSA-CHACHA20-POLY1305",    "ECDHE-RSA CHACHA20-POLY1305"),
        ("DHE-RSA-CHACHA20-POLY1305",      "DHE-RSA   CHACHA20-POLY1305"),
    ]

    if feats["tls12"]:
        if feats["secure_reneg"]:
            print("\n--- TLS 1.2: plaintext + encrypted multi-message "
                  "records ---")
            print("  Each connection verifies BOTH code paths:")
            print("    * initial handshake  -> plaintext SH+Cert+SKE+SHD")
            print("    * renegotiation      -> encrypted SH+Cert+SKE+SHD")
        else:
            print("\n--- TLS 1.2: plaintext multi-message records ---")
            print("  wolfSSL built without HAVE_SECURE_RENEGOTIATION;")
            print("  skipping the encrypted (renegotiation) half.")
        print("  Covers multiple key-exchanges, ciphers and MAC "
              "families.\n")

        for cipher, desc in tls12_suites:
            run_tls12_test(cipher, rsa_chain, rsa_key,
                           f"TLS1.2 {desc}",
                           do_reneg=feats["secure_reneg"])
        if not feats["secure_reneg"]:
            skipped("TLS1.2 encrypted multi-msg record "
                    "(requires HAVE_SECURE_RENEGOTIATION)")
    else:
        skipped(f"TLS 1.2 tests ({len(tls12_suites)} suites) - "
                "wolfSSL built without TLS 1.2")

    # ------------------------------------------------------------------
    # TLS 1.3 – encrypted multi-message records
    # ------------------------------------------------------------------
    tls13_suites = [
        # (wolfSSL cipher name, description)
        (None,                              "default negotiated"),
        ("TLS13-AES128-GCM-SHA256",        "AES-128-GCM"),
        ("TLS13-AES256-GCM-SHA384",        "AES-256-GCM"),
        ("TLS13-CHACHA20-POLY1305-SHA256",  "CHACHA20-POLY1305"),
    ]

    if feats["tls13"]:
        print("\n--- TLS 1.3: encrypted multi-message records ---")
        print("  Server sends EE+Cert+CV+Fin in a single encrypted "
              "record;")
        print("  wolfSSL client must decrypt and parse.\n")

        for cipher, desc in tls13_suites:
            run_tls13_test(cipher, rsa_chain, rsa_key,
                           f"TLS1.3 {desc}")
    else:
        skipped(f"TLS 1.3 tests ({len(tls13_suites)} suites) - "
                "wolfSSL built without TLS 1.3")

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    print()
    print("=" * 60)
    print(f" Results: {PASS_COUNT} passed, {FAIL_COUNT} failed, "
          f"{SKIP_COUNT} skipped")
    print("=" * 60)

    # If nothing at all could run, signal SKIP (exit 77) so automake
    # records the test as skipped rather than passed-with-nothing.
    if PASS_COUNT == 0 and FAIL_COUNT == 0:
        sys.exit(77)

    return FAIL_COUNT == 0


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
