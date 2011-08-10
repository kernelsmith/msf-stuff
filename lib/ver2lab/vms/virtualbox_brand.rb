module Labv2
module Vms

#
## Virtualbox Brand Vms
# 

# Base VirtalboxVm Class (no subclasses so far)
class VirtalboxVm < Vm
	# doesn't need to be subclassed yet as vbox only has the one hypervisor
	# could be used locally
	# if used remotely, require a VmServer object if here?
	
	def initialize(config = {})
		config[:location]) == "" unless config[:location] # Optional for virtualbox so un-nil it if nil
		config[:brand] == "virtalbox"	# force brand
		super
	end
	# alias ovf to location?
	def ovf
		self.location
	end
	def ovf= (path)
		self.location= (path)
	end

end # end VirtualboxVm Class

end
end

