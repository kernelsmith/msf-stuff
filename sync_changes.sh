#!/bin/sh

if ! ( [ "$1" == "tomsf" ] || [ "$1" == "togit" ] ); then
	echo "Usage: $0 [tomsf|togit]"
	exit 1
fi

msfbase="/opt/metasploit3/msf3/"
githome="/home/ks/all/git/msf-shell-mixins/"

while read pair; do
	first=$(echo $pair | cut -d',' -f1)
	second=$(echo $pair | cut -d',' -f2)
	if [ "$1" == "togit" ]; then 
		src="$first" 
		dest="$second"
	else 
		if [ "$1" == "tomsf" ]; then src="$second" && dest="$first";fi
	fi
#	echo "Copying $src to $dest"
	cp -rv $src $dest
done <<__EOF__
$msfbase/lib/msf/core/post/windows/registry.rb,$githome/lib/msf/core/post/windows/registry.rb
$msfbase/lib/msf/core/post/windows/services.rb,$githome/lib/msf/core/post/windows/services.rb
$msfbase/lib/msf/core/post/windows/cli_parse.rb,$githome/lib/msf/core/post/windows/cli_parse.rb
$msfbase/test/modules/post/test/registry.rb,$githome/test/modules/post/test/registry.rb
$msfbase/test/modules/post/test/services.rb,$githome/test/modules/post/test/services.rb
__EOF__
