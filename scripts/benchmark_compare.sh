#!/bin/bash

FIRST_FILE=$1
SECOND_FILE=$2
THRESHOLD=${3:-"10"}

declare -A symStats
declare -A asymStats

function getAlgo() { # getAlgo <mode> <line>
    declare -a fields
    IFS=',' read -ra fields <<< "$line"
    if [ "$mode" = 1 ]; then
        echo "${fields[0]}"
    else
        if [ "${fields[2]}" = "" ]; then
            echo "${fields[0]}"
        else
            echo "${fields[0]}-${fields[2]}"
        fi
    fi
}

function getValue() { # getValue <mode> <line>
    declare -a fields
    IFS=',' read -ra fields <<< "$line"
    if [ "$mode" = 1 ]; then
        echo "${fields[1]}"
    else
        echo "${fields[4]}"
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
    elif [[ $line == "" ]]; then
        mode=0
    fi
    if [ "$mode" -ne 0 ]; then
            ALGO=`getAlgo "$mode" "$line"`
            VALUE=`getValue "$mode" "$line"`

            if [ "$mode" = "1" ]; then
                symStats["${ALGO}"]=${VALUE}
            elif [ "$mode" = "2" ]; then
                asymStats["${ALGO}"]=${VALUE}
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
        RES+="ALGO,${FIRST_FILE},diff(MB/s),${SECOND_FILE}\n"
        mode=1
        read
        read
    elif [[ $line == *"Asymmetric Ciphers"* ]]; then
        RES+="\nALGO,${FIRST_FILE},diff(ops/sec),${SECOND_FILE}\n"
        mode=2
        read
        read
    elif [[ $line == "" ]]; then
        mode=0
    fi
    if [ "$mode" -ne 0 ]; then
        if [[ $line == *","* ]]; then
            ALGO=`getAlgo "$mode" "$line"`
            VALUE=`getValue "$mode" "$line"`

            if [ "$mode" = "1" ]; then
                RES+=`printData "${ALGO}" "${symStats["${ALGO}"]}" "${VALUE}"`
            elif [ "$mode" = "2" ]; then
                RES+=`printData "${ALGO}" "${asymStats["${ALGO}"]}" "${VALUE}"`
            fi
        fi
    fi
done < ${SECOND_FILE}

echo -e "$RES" | column -t -s ',' -L
