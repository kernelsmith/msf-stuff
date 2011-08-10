
def discover_hyperv(host, user=nil)
	raise ArgumentError,"Missing host argument" unless host
	
	# only support linux for now
	
	host_os = "linux"
	
	if host_os == linux
		script = %q{
		if [ $(which vmware) > /dev/null ]; then 
			# VMWARE, now find what product, TODO:  check what player does (if support), vmware server
			if [ vmware-installer -l | grep -eq [workstation|player ]; then echo "vmware workstation";fi
		else if [ which /bin/vim-cmd &> /dev/null ]; then echo "vmware esxi"
		else if [ which /bin/vmware-cmd &> /dev/null ]; then echo "vmware esx"
		else if [ which vmrun &> /dev/null ]; then echo "vmware server" # might need to move this into first one
	
		#TODO	 do other shit like windows mac etc
	end
	str = `"#{script}"`
end
