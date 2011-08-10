module Labv2
module VmServers

class VmServer
	# this is the top level VmServer class, meant to be subclassed
	attr_accessor :uid
	attr_accessor :type
	attr_accessor :host
	attr_accessor :brand
	
	@BASE_CMD = nil # subclasses must define

	def initialize(config = {})
		@type = "local" unless @type # subclasses should override if they are remote
		@host = config[:host] || "localhost"
		@brand = config[:brand] || nil #unless @brand # subclasses should override # ask jcran about this
		super # check syntax
	end
	
	def get_all_vms
		raise NotImplmentedError, "#{__method__} Must be implemented in a subclass"
	end
	def get_running_vms
		raise NotImplmentedError, "#{__method__} Must be implemented in a subclass"
	end	
	def get_vms_inlocation
		raise NotImplmentedError, "#{__method__} Must be implemented in a subclass"
	end	
	def to_s
		#TODO:  Define to_s
	end
	private
		def run_hyperv_cmd(cmd)
			raw = `"#{shellescape(cmd)}"`
		end
	end
end # end VmServer Class

end # end Vms Module
end # end Labv2 Module
