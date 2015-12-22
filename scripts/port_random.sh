#!/bin/bash

# ip local port range: 49152..65535
# possibilities is 16383 unique port numbers
while true; do
#---------- Formula ---------#

    RAND_PORT=$(( ($RANDOM / 2) + 49152 ))

#---------- Formula ---------#

    [ $RAND_PORT -ge 49152 ] && [ $RAND_PORT -le 65535 ] && echo "$RAND_PORT" \
    && break
done
exit 0
