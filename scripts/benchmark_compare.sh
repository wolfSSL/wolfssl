#!/bin/bash

FIRST_FILE=$1
SECOND_FILE=$2

declare -A symStats
declare -A asymStats
while IFS= read -r line; do
    if [[ $line == *"Symmetric Ciphers"* ]]; then
        mode=1
        read
        read
    elif [[ $line == *"Asymmetric Ciphers"* ]]; then
        mode=2
        read
        read
    else
        if [[ $line == *","* ]]; then
            declare -a fields
            IFS=',' read -ra fields <<< "$line"

            if [ $mode == 1 ]; then
                symStats["${fields[0]}"]=${fields[1]}
            elif [ $mode == 2 ]; then
                asymStats["${fields[0]}"]=${fields[1]}
            fi
        fi
    fi
done < $FIRST_FILE

while IFS= read -r line; do
    if [[ $line == *"Symmetric Ciphers"* ]]; then
        mode=1
        read
        read
    elif [[ $line == *"Asymmetric Ciphers"* ]]; then
        mode=2
        read
        read
    else
        if [[ $line == *","* ]]; then
            declare -a fields
            IFS=',' read -ra fields <<< "$line"

            if [ $mode == 1 ]; then
                if (( $(echo "${symStats["${fields[0]}"]} > ${fields[1]}" | bc -l) )); then
                    RES+="${fields[0]}: $FIRST_FILE (${symStats["${fields[0]}"]}) > $SECOND_FILE (${fields[1]})\n"
                else
                    RES+="${fields[0]}: $FIRST_FILE (${symStats["${fields[0]}"]}) < $SECOND_FILE (${fields[1]})\n"
                fi
            elif [ $mode == 2 ]; then
                if (( $(echo "${asymStats["${fields[0]}"]} > ${fields[1]}" | bc -l) )); then
                    RES+="${fields[0]}: $FIRST_FILE (${asymStats["${fields[0]}"]}) > $SECOND_FILE (${fields[1]})\n"
                else
                    RES+="${fields[0]}: $FIRST_FILE (${asymStats["${fields[0]}"]}) < $SECOND_FILE (${fields[1]})\n"
                fi
            fi
        fi
    fi
done < $SECOND_FILE

echo -e "$RES" | column -t
