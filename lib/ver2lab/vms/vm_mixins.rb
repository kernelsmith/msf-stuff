
module Labv2
module Mixins
module VmServer
module Remote

	def run_hyperv_cmd(cmd)
		raise NotImplmentedError, "#{__method__} Should be overridden by a submodule"
	end
	
	module Ssh
		private
		#override run_hyperv_cmd
		def run_hyperv_cmd(cmd)
			# gotta make sure user and host are in scope and defined
			raw = `"ssh #{@user}@#{@host} \"#{shellescape(cmd)}\""`
		end
		end
		# some key stuff and/or cred stuff?
	end # end Ssh Module
	
	module Telnet
		def run_hyperv_cmd(cmd)
			# this is just here as an example
			# do stuff using ruby telnet libraries
			raise NotImplmentedError, "#{__method__} Telnet Not Implemented"
		end
	end
	
	module SomeRemoteAPIdriver
		# use some fancy driver
	end # end SomeRemoteDriver Module
end # end Remote Module
end # end VmServer Module
end # end Mixins Module
end # end Lab Module
