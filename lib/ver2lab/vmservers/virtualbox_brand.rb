module Labv2
module VmServers

#
### VIRTUALBOX Brand
#

class VirtualBoxVmServer < VmServer
	# doesn't need to be subclassed except for remote
	# unless vbox ever comes out with a vboxserver version or something
	@BASE_CMD = "VBoxManage".freeze

	def initialize(config = {})
		@brand = "virtualbox"
		super # check syntax
	end

	def running_list
		vm_names_and_uuids = run_hyperv_cmd("#{@BASE_CMD} list runningvms")
		return vm_names_and_uuids.scan(/\"(.*)\" {.*}/).flatten
	end

	def config_list
		vm_names_and_uuids =run_hyperv_cmd("#{@BASE_CMD} list vms")
		return vm_names_and_uuids.scan(/\"(.*)\" {.*}/).flatten
	end

	def config_list_uuid
		vm_names_and_uuids =run_hyperv_cmd("#{@BASE_CMD} list vms")
		return vm_names_and_uuids.scan(/\".*\" {(.*)}/).flatten
	end
		
	def dir_list(basepath=nil)
		# this only works for the local, it will need something different in remote
		vm_list = Find.find(basepath).select { |f| f =~ /\.xml$/ }
	end
end

class RemoteVirtualboxVmServer < VirtualboxVmServer
	require 'vm_mixins'
	# hardcode ssh for now
	# this implements the run_hyperv_cmd method
	include ::Labv2::Mixins::VmServer::Remote::Ssh
	attr_accessor :user		
	attr_accessor :host

	def initialize(config = {})	
		@user = config['user'] || nil
		@host = config['host'] || nil
		super # check syntax
	end
end # end RemoteVirtualboxVmServer

### End Virtualbox Brand

end
end

