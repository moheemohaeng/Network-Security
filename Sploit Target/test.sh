#!/bin/bash

RST="$(tput sgr 0)"
FR="$(tput setaf 1)"
FG="$(tput setaf 2)"
FY="$(tput setaf 3)"
BD="$(tput bold)"

for ((i=1; i<=4; i++)); do
    if [ ! -f sploits/sploit$i ]; then
        RESULT="${FR}not found${RST}"
    else
        USER="$(echo "whoami" | sploits/sploit$i)"
        RC=$?
        if [ $RC -ne 0 ]; then
            RESULT="${FR}unexpected exit code $RC${RST}"
        elif [ "$USER" != "root" ]; then
            RESULT="${FR}fail${RST}"
        else
            RESULT="${FG}pass${RST}"
        fi
    fi
    echo "${BD}sploit$i${RST}: $RESULT"
done

