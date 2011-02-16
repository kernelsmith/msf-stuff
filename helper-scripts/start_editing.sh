#!/bin/sh
kate=/opt/kde3/bin/kate
msf=/pentest/exploits/framework3/

$kate ${msf}/modules/post/windows/test/test-*.rb ${msf}/lib/msf/core/post/windows/*-josh.rb
