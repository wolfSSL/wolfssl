#!/usr/bin/env bash
# This script is designed to compare the output of wolfcrypt/benchmark test
# application. If the file has an extension ".csv", then it will parse the
# comma separated format, otherwise it will use the standard output format. The
# green colored output field is the better result.
# Usage: benchmark_compare.sh <first file> <second file>
# You can define a few variables to set options:
# THRESHOLD  - set the threshold for equality between two results
# OUTPUT_CSV - set to "1" to print CSV

FIRST_FILE=$1
SECOND_FILE=$2
THRESHOLD=${THRESHOLD:-"10"}
OUTPUT_CSV=${OUTPUT_CSV:-"0"}

declare -A symStats
declare -A asymStats

function getAlgo() { # getAlgo <asCSV> <mode> <line>
    if [ "$asCSV" = 1 ]; then
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
    else
        if [ "$mode" = 1 ]; then
            echo "$line" | sed 's/ *[0-9]* MiB.*//g'
        else
            if [[ $line == "scrypt"* ]]; then
                echo "scrypt"
            else
                echo "$line" | sed 's/ *[0-9]* ops.*//g' | sed 's/ \+[0-9]\+ \+/-/g'
            fi
        fi
    fi
}

function getValue() { # getValue <asCSV> <mode> <line>
    if [ "$asCSV" = 1 ]; then
        declare -a fields
        IFS=',' read -ra fields <<< "$line"
        if [ "$mode" = 1 ]; then
            echo "${fields[1]}"
        else
            echo "${fields[4]}"
        fi
    else
        if [ "$mode" = 1 ]; then
            echo "$line" | sed 's/.*seconds, *//g' | sed 's/ *MiB\/s.*//g'
        else
            echo "$line" | sed 's/.* ms, *//g' | sed 's/ ops\/sec.*//g'
        fi
    fi
}

asCSV=0
mode=0
while IFS= read -r line; do
    if [[ $FIRST_FILE == *".csv" ]]; then
        asCSV=1
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
    else
        asCSV=0
        if [[ $line == *"MiB/s"* ]]; then
            mode=1
        elif [[ $line == *"ops/sec"* ]]; then
            mode=2
        else
            mode=0
        fi
    fi
    if [ "$mode" -ne 0 ]; then
            ALGO=`getAlgo "$asCSV" "$mode" "$line"`
            VALUE=`getValue "$asCSV" "$mode" "$line"`

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

asCSV=0
mode=0
while IFS= read -r line; do
    if [[ $SECOND_FILE == *".csv" ]]; then
        asCSV=1
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
    else
        asCSV=0
        if [[ $line == *"MiB/s"* ]]; then
            mode=1
        elif [[ $line == *"ops/sec"* ]]; then
            mode=2
        else
            mode=0
        fi
    fi
    if [ "$mode" -ne 0 ]; then
        if [[ $line == *","* ]]; then
            ALGO=`getAlgo "$asCSV" "$mode" "$line"`
            VALUE=`getValue "$asCSV" "$mode" "$line"`

            if [ "$mode" = "1" ]; then
                RES+=`printData "${ALGO}" "${symStats["${ALGO}"]}" "${VALUE}"`
            elif [ "$mode" = "2" ]; then
                RES+=`printData "${ALGO}" "${asymStats["${ALGO}"]}" "${VALUE}"`
            fi
        fi
    fi
done < ${SECOND_FILE}

if [ "${OUTPUT_CSV}" = "1" ]; then
    echo -e "$RES"
else
    echo -e "$RES" | column -t -s ',' -L
fi
