# LUKS with wolfCrypt FIPS

Debian 13, x86_64; stock kernel/cryptsetup and matching headers.
Run as root with console access and an unpacked wolfSSL FIPS kernel-module bundle.

| Bundle | `FIPS_FLAVOR` | Data cipher | Key bits |
| --- | --- | --- | --- |
| FIPS 140-3 v5.2.4 | `v5.2.4` | `aes-cbc-essiv:sha256` | 256 |
| FIPS Ready | `ready` | `aes-xts-plain64` | 512 |

cryptsetup's userspace crypto is outside this integration.
**v5.2.4 ESSIV IV encryption uses kernel AES.**

## Packages

```sh
KVER=${KVER-$(uname -r)}
apt-get update
apt-get install -y build-essential gawk linux-headers-$KVER \
    mokutil openssl cryptsetup systemd-cryptsetup
```

## Settings

Set `WOLFSSL_SRC`, `FIPS_FLAVOR` and absolute `LUKS_DIR` (the parent directory).

```sh
cat > /etc/wolfcrypt-luks.conf <<'EOF'
LUKS_DIR=/path/to/linuxkm/luks
WOLFSSL_SRC=/root/wolfssl-5.9.4-commercial-fips-v5.2.4
FIPS_FLAVOR=v5.2.4
MOK_KEY=/root/wolfcrypt-mok/wolfcrypt-mok.key
MOK_CERT=/root/wolfcrypt-mok/wolfcrypt-mok.der
case "$FIPS_FLAVOR" in
    v5.2.4) LKCAPI_ALGS='cbc(aes),sha2' CONFIGURE_EXTRA=
            LUKS_CIPHER=aes-cbc-essiv:sha256 LUKS_KEY_SIZE=256
            GUARD_ALGS='cbc(aes) sha256' ;;
    ready)  LKCAPI_ALGS='xts(aes)' CONFIGURE_EXTRA=--enable-intelasm
            LUKS_CIPHER=aes-xts-plain64 LUKS_KEY_SIZE=512
            GUARD_ALGS='xts(aes)' ;;
esac
EOF
```

## Signing key

Keep the key for kernel updates.

```sh
install -d -m 0700 /root/wolfcrypt-mok
cd /root/wolfcrypt-mok
openssl req -new -x509 -newkey rsa:3072 -sha256 -nodes -days 3650 \
    -subj "/CN=wolfCrypt linuxkm module signing/" \
    -keyout wolfcrypt-mok.key -outform DER -out wolfcrypt-mok.der
chmod 0600 wolfcrypt-mok.key
```

**Secure Boot only:**

```sh
mokutil --timeout -1
mokutil --import /root/wolfcrypt-mok/wolfcrypt-mok.der
```

```sh
reboot
```

Console: **Enroll MOK → Continue → Yes**, enter the password, **Reboot**.

## Build

```sh
set -e
. /etc/wolfcrypt-luks.conf
KVER=${KVER-$(uname -r)}
KBUILD=/lib/modules/${KVER:?}/build
cd "$WOLFSSL_SRC"
./configure --enable-fips="$FIPS_FLAVOR" --enable-linuxkm \
    --enable-linuxkm-lkcapi-register="${LKCAPI_ALGS:?}" --with-linux-source="$KBUILD" $CONFIGURE_EXTRA
make -j"$(nproc)" module-with-matching-fips-hash-no-sign
SIG_HASH=$(sed -n 's/^CONFIG_MODULE_SIG_HASH="\(.*\)"/\1/p' "$KBUILD/.config")
"$KBUILD/scripts/sign-file" "$SIG_HASH" "$MOK_KEY" "$MOK_CERT" linuxkm/libwolfssl.ko
install -D -m 0644 linuxkm/libwolfssl.ko "/lib/modules/$KVER/extra/libwolfssl.ko"
depmod -a "$KVER"
```

## Boot guard

Use the selected cipher for guarded volumes. Load wolfCrypt before opening them;
existing mappings retain their driver.

```sh
. /etc/wolfcrypt-luks.conf
install -m 0755 "$LUKS_DIR/wolfcrypt-luks-guard" /usr/local/sbin/
install -m 0644 "$LUKS_DIR/wolfcrypt-luks-guard.service" /etc/systemd/system/
install -D -m 0644 "$LUKS_DIR/systemd-cryptsetup.conf" \
    /etc/systemd/system/systemd-cryptsetup@.service.d/wolfcrypt.conf
systemctl enable --now wolfcrypt-luks-guard.service
```

Loading sets `/proc/sys/crypto/fips_enabled=1` until reboot.

## Data volume (optional)

**Destroys `DEV` and overwrites the key file.**
A key on unencrypted root protects only a separately removed disk.

```sh
. /etc/wolfcrypt-luks.conf
DEV='/dev/disk/by-id/<your-disk>'
install -d -m 0700 /etc/cryptsetup-keys.d
( umask 077; head -c 64 /dev/urandom > /etc/cryptsetup-keys.d/securedata.key )
cryptsetup luksFormat --type luks2 --cipher "$LUKS_CIPHER" --key-size "$LUKS_KEY_SIZE" \
    --pbkdf pbkdf2 --hash sha256 \
    --key-file /etc/cryptsetup-keys.d/securedata.key --batch-mode "$DEV"
UUID=$(cryptsetup luksUUID "$DEV")
echo "securedata UUID=$UUID /etc/cryptsetup-keys.d/securedata.key luks" >> /etc/crypttab
```

## Encrypted root (optional)

Complete Build and Boot guard; back up root and retain a recovery entry.
**v5.2.4 only:** set `ROOT_LUKS` to root's LUKS partition and convert XTS.
Resume interruptions with the same command and `YES`.

```sh
ROOT_LUKS='/dev/disk/by-uuid/<root-LUKS-UUID>'
cryptsetup reencrypt --cipher aes-cbc-essiv:sha256 --key-size 256 --pbkdf pbkdf2 "$ROOT_LUKS"
```

```sh
. /etc/wolfcrypt-luks.conf
KVER=${KVER-$(uname -r)}
install -m 0755 "$LUKS_DIR/debian13/initramfs-hook" /etc/initramfs-tools/hooks/wolfcrypt-luks
install -m 0755 "$LUKS_DIR/debian13/initramfs-premount" /etc/initramfs-tools/scripts/init-premount/wolfcrypt-luks
update-initramfs -u -k "${KVER:?}"
lsinitramfs /boot/initrd.img-"$KVER" | grep -E 'libwolfssl\.ko|wolfcrypt-luks'
```

Images must contain the module, guard, config and `init-premount/wolfcrypt-luks`.

Guard failure: `(initramfs)` → `exit`. `exit` uses kernel AES. Rebuild the affected kernel's
module and initramfs; reboot.

## Reboot

```sh
reboot
```

## Kernel updates

Select the target release from `/lib/modules`:

```sh
KVER='<target kernel release>'
```

In one shell, repeat Packages and Build for this `KVER`, then the Encrypted root
block if applicable (skip re-encryption).

```sh
reboot
```
