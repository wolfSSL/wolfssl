# -*- mode: ruby -*-
# vi: set ft=ruby :

$setup = <<SCRIPT
apt-get update
apt-get install -y git autoconf libtool make valgrind libpq-dev
cp -rp /vagrant/ cyassl/

echo "cd cyassl"                                    >> .bashrc
echo "echo -e '\e[0;32mRunning cyassl sync\e[0m'"   >> .bashrc
echo "./pull_to_vagrant.sh"                         >> .bashrc

cd cyassl
./autogen.sh
./configure
make check

cd ..
chown -hR vagrant:vagrant cyassl/ /tmp/output

SCRIPT

VAGRANTFILE_API_VERSION = "2"

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
  config.vm.box = "hashicorp/precise64"
  config.vm.provision "shell", inline: $setup
end
