[ "$(whoami)" != "root" ] && echo "Sorry, you are not root." && exit 1

rpm -ivh http://dl.fedoraproject.org/pub/epel/7/x86_64/e/epel-release-7-6.noarch.rpm
yum update
yum install -y \
    git autoconf libtool libffi-devel python-devel python3-devel python-pip

git clone https://github.com/wolfssl/wolfssl.git
[ $? -ne 0 ] && echo "\n\nCouldn't download wolfssl.\n\n" && exit 1

pushd wolfssl

./autogen.sh
./configure
make
make install
echo /usr/local/lib > wolfssl.conf
mv wolfssl.conf /etc/ld.so.conf
ldconfig

popd

rm -rf wolfssl

pushd /vagrant

pip install -r requirements-testing.txt

make check

popd

# pip install wolfssl
# [ $? -ne 0 ] && echo "\n\nCouldn't install wolfssl.\n\n" && exit 1
