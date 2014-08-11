#!/bin/bash

# synchronize without .git and .gitignore to avoid output files
rsync --exclude .git --exclude-from .gitignore -rvt /vagrant/ ~/cyassl/

# synchronize everything else needed.
rsync -rvt /vagrant/.git         ~/cyassl/
rsync -rvt /vagrant/IDE          ~/cyassl/
rsync -rvt /vagrant/mcapi        ~/cyassl/
rsync -rvt /vagrant/mplabx       ~/cyassl/
rsync -rvt /vagrant/configure.ac ~/cyassl/
