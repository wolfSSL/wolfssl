#!/bin/bash

# client-test.sh

[ ! -x ./examples/client/client ] && echo -e "\n\nClient doesn't exist" && exit 1

# is our desired server there?
ping -c 2 -i 0.2 www.google.com
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "\n\nCouldn't find server, skipping" && exit 0

# client test against the server
./examples/client/client -h www.google.com -p 443 -g -d
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "\n\nClient connection failed" && exit 1

exit 0
