
module Labv2
module Vms

#
## Vmware Brand
#

# Base VmwareVm Class
class VmwareVm < Vm
	# should be subclassed
	def initialize(config = {})
		config[:brand] == "vmware"	# force brand
		super
	end
	
	# alias vmx to location
	def vmx
		self.location
	end
	def vmx= (path)
		self.location= (path)
	end
end

class VmwareWorkstationVm < VmwareVm
	# could be used locally
	# if used remotely, require a VmServer object if here?
	@BASE_CMD = 'vmrun'.freeze
	
	def initialize(config = {})
		config[:brand] == "vmware_workstation"	# force brand
		super
	end
end
class VmwareServerVm < VmwareVm
	# could be used locally, odd, but could happen
	# if used remotely, require a VmServer object if here
	@BASE_CMD = 'vmrun'.freeze
	
	def initialize(config = {})
		config[:brand] == "vmware_server"	# force brand
		super
	end
end
class VmwareEsxVm < VmwareVm
	# can't be used locally
	# remote only, require a VmServer object if here
	#TODO: make sure esx actually uses a vmid like esxi does
	attr_reader :hyperv_id	# the vmid esx/i gives to the vm after it's registered
	attr_reader :esx_vmid	# synonym for :hyperv_id
	
	#TODO:  needs full path to vmware-cmd
	@BASE_CMD = 'vmware-cmd'.freeze
	
	def initialize(config = {})
		config[:brand] == "vmware_esx"	# force brand
		super
		
		# for now, require a hyperv_id, later can also accept location and have esx server resolve id
		@hyperv_id = config[:hyperv_id] || nil
		raise ArgumentError, "ESX VM must have a hyperv_id" unless @hyperv_id
		@esx_vmid = @hyperv_id
	end
	
	def to_s  # override to_s to add hyperv_id
		return "#{@name}: #{@brand}: #{@location}  #{@hyperv_id}"
	end
end

class VmwareEsxiVm < VmwareVm # or possibly < VmwareEsxVm
	# can't be used locally
	# remote only, require a VmServer object if here
	attr_reader :hyperv_id # the vmid esx/i gives to the vm after it's registered
	attr_reader :esx_vmid # syntax for hyperv_id
	attr_reader	:esxi_vmid
	
	@BASE_CMD = '/bin/vim-cmd'.freeze

	def initialize(config = {})
		config[:brand] == "vmware_esxi"	# force brand
		super
		
		# for now, require a hyperv_id, later can also accept location and have esxi server resolve id
		@hyperv_id = config[:hyperv_id] || nil
		raise ArgumentError, "ESXi VM must have a hyperv_id" unless @hyperv_id
		@esx_vmid = @hyperv_id
		@esxi_vmid = @hyperv_id
	end

	def to_s  # override to_s to add hyperv_id
		return "#{@name}: #{@brand}: #{@location}  #{@hyperv_id}"
	end
end



end
end

