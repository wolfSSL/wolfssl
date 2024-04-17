#!/bin/bash

FIRST_FILE=$1
SECOND_FILE=$2
THRESHOLD=${3:-"10"}

declare -A symStats
declare -A asymStats

mode=0
while IFS= read -r line; do
    if [[ $line == *"Symmetric Ciphers"* ]]; then
        mode=1
        read
        read
    elif [[ $line == *"Asymmetric Ciphers"* ]]; then
        mode=2
        read
        read
    fi
    if [ "$mode" = 1 ] || [ "$mode" = 2 ]; then
        if [[ $line == *","* ]]; then
            declare -a fields
            IFS=',' read -ra fields <<< "$line"
            ALGO=${fields[0]}
            VALUE=${fields[1]}

            if [ "$mode" = "1" ]; then
                symStats["${ALGO}"]=${VALUE}
            elif [ "$mode" = "2" ]; then
                asymStats["${ALGO}"]=${VALUE}
            fi
        fi
    fi
done < ${FIRST_FILE}

RED='\033[0;31m'
GRN='\033[0;32m'
NC='\033[0m' # No Color
function printData() { # printData <ALGO> <val1> <val2>
    ALGO=$1
    VAL1=$2
    VAL2=$3
    if (( $(echo "sqrt( (${VAL1} - ${VAL2})^2 ) < ${THRESHOLD}" | bc -l) )); then
        # take absolute value and check if less than a threshold
        echo "${ALGO},${GRN}${VAL1}${NC},=,${GRN}${VAL2}${NC}\n"
    elif (( $(echo "${VAL1} > ${VAL2}" | bc -l) )); then
        echo "${ALGO},${GRN}${VAL1}${NC},>,${VAL2}\n"
    else
        echo "${ALGO},${VAL1},<,${GRN}${VAL2}${NC}\n"
    fi
}

mode=0
while IFS= read -r line; do
    if [[ $line == *"Symmetric Ciphers"* ]]; then
        mode=1
        read
        read
    elif [[ $line == *"Asymmetric Ciphers"* ]]; then
        mode=2
        read
        read
    fi

    if [ "$mode" = 1 ] || [ "$mode" = 2 ]; then
        if [[ $line == *","* ]]; then
            declare -a fields
            IFS=',' read -ra fields <<< "$line"

            ALGO=${fields[0]}
            VALUE=${fields[1]}

            if [ "$mode" = "1" ]; then
                RES+=`printData "${ALGO}" "${symStats["${ALGO}"]}" "${VALUE}"`
            elif [ "$mode" = "2" ]; then
                RES+=`printData "${ALGO}" "${asymStats["${ALGO}"]}" "${VALUE}"`
            fi
        fi
    fi
done < ${SECOND_FILE}

echo -e "ALGO,${FIRST_FILE},difference,${SECOND_FILE}\n$RES" | column -t -s ','
