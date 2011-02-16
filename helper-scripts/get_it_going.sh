#!/bin/sh
vmware &
/etc/init.d/ufw stop
./msfconsole