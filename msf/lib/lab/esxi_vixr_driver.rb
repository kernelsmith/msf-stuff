require 'vm_driver'
##
## $Id: esxi_vixr_driver.rb 11753 2011-02-16 02:15:24Z jcran $
##

# This requires rhythmx's vixr driver from https://github.com/rhythmx/vixr 
# and below that, the VIX api from vmware http://www.vmware.com/support/developer/vix-api/

module Lab
module Drivers

class EsxiVixrDriver < VmDriver

	require 'timeout'
	
	attr_accessor :type
	attr_accessor :location
	
        # Checks if vixr is loaded correctly.
        @vixr_loaded = false

        # vixr is absolutely required to make this work, let's be nice if it's not avail
        def self.vixr_require
                begin
                        require 'vixr'
                rescue LoadError
                        return false
                end
                @vixr_loaded = true
        end
        
	def initialize(vmid, location, tools=false, user=nil, host=nil, pass=nil, credentials=nil, type=nil)

		::EsxiVixrDriver.vixr_require
        # versioning is not an issue atm, but if becomes one, check it here
		if not @vixr_loaded
			raise "Oops, no vixr installed. Consider using another vmware driver such as workstation\n" +
				"Or install the vixr driver and vix api --\n" +
				"Download vixr at https://github.com/rhythmx/vixr and follow the README\n"
				"Download and install vix-api at http://www.vmware.com/support/developer/vix-api/"
		end
		
		# TODO - Should proabably check file existence?	but won't be able until Vixr.connect
		#TODO:  unless user then raise ArgumentError, "Must provide a username" end
		unless host then raise ArgumentError, "Must provide a hostname" end

		@vmid = filter_input(vmid)
		@location = filter_input(location)
		@type = type
		#@user = filter_input(user)
		@user = "root"
		#@pass = filter_input(pass)
		#hardcode a password for now
		@pass = 'password'
		@host = filter_input(host)
		@tools = tools	# not used in command lines, no filter
		#@os = os	# not used in command lines, no filter
		# port will vary if not just used for esxi, vmserver = 8222?, esx = 80?
		@port = 443

		@credentials = credentials # individually filtered
		# TODO - Currently only implemented for the first set
		if @credentials.count > 0
			@vm_user = filter_input(@credentials[0]['user']) || "\'\'"
			@vm_pass = filter_input(@credentials[0]['pass']) || "\'\'"
			@vm_keyfile = filter_input(@credentials[0]['keyfile'])
		end
		
		# connect opts
		#:hosttype => VixAPI::Const::Provider::Workstation,
		#:hostname => nil,
		#:user => nil,
		#:pass => nil,
		#:port => 8222,    
        # vm opts
		#:vmxfile => nil,
		#:showgui => false,
		#:fromguest => true, # reset and poweroff will use the guest OS to shutdown
		#:deletefile => false,
		# could also use @vm.opt = {}
		
		connect_hash = {
						:hosttype => VixAPI::Const::Provider::Server2x, 
						:hostname => "https://#{@host}:443/sdk", 
						:user => @user, 
						:pass => @pass, 
						:port => @port
						}
		begin
		Timeout::timeout(10) { host = VixR.connect(connect_hash) }
		rescue ::Timeout::Error
		end
		
		raise(Exception, "Connection to host failed.  Connection parameters:  connect_hash.to_s") if not host
		
		@vm = host.open_vmx("#{@location.to_s}") || nil
	end

	def start
		@vm.power_on
	end

	def stop
		@vm.power_off
	end

	def suspend
		@vm.suspend
	end

	def pause
		@vm.pause
	end

	def reset
		@vm.reset
	end

	def create_snapshot(snapshot)
		raise Exception, "Command not currently implemented in Vixr"
		#snapshot = filter_input(snapshot)
		#vim-cmd vmsvc/snapshot.create [vmid:int] [snapName] [snapDescription] [inclMemory:bool]
		# this command requires the vmid as it's known by the server, we'd need vixr to implement a vmid method/property
		#system_command("ssh #{@user}@#{@host} \"vim-cmd vmsvc/snapshot.create #{@vm.vmid} #{snapshot} #{type} false\"")
	end

	def revert_snapshot(snapshot)
		raise Exception, "Command not currently implemented in Vixr"
		#snapshot = filter_input(snapshot)
		#vim-cmd vmsvc/snapshot.revert [vmid:int] [snapLevel] [snapIndex]
		# this command requires the vmid as it's known by the server, we'd need vixr to implement a vmid method/property
		# could also use a get_snapshots method for current snapshot levels & indices, assoc w/ snapName & descrip
		#system_command("ssh #{@user}@#{@host} \"vim-cmd vmsvc/snapshot.revert #{@vm.vmid} 0 0\"")
	end

	def delete_snapshot(snapshot)
		raise Exception, "Command not currently implemented in Vixr"
		#snapshot = filter_input(snapshot)
		# TODO: need to confirm the syntax here
		# vim-cmd vmsvc/snapshot.remove [vmid:int] [snapLevel:int] [snapIndex:int] [inclDescendents:bool]
		#system_command("ssh #{@user}@#{@host} \"vim-cmd vmsvc/snapshot.remove #{@vm.vmid} 0 0 true\"")
	end


	def run_command(command)
		command = filter_input(command)
		if @vm.login(@vm_user,@vm_pass)
			@vm.run_prog(command)
		end
	end
	
	def copy_from(from, to)
		from = filter_input(from)
		to = filter_input(to)
		@vm.cp_from_host(from,to)
	end

	def copy_to(from, to)
		from = filter_input(from)
		to = filter_input(to)
		@vm.cp_to_guest(from,to)
	end

	def check_file_exists(file)
		file = filter_input(file)
		@vm.file_exists?(file)
	end
	
	def check_dir_exists(directory)
		directory = filter_input(directory)
		@vm.dir_exists?(directory)
	end

	def create_directory(directory)
		directory = filter_input(directory)
		@vm.mkdir(directory)
	end
	
	def screendump(file=nil)
		file = filter_input(file)
		@vm.screendump(file)
	end

	def cleanup

	end

	def running?
		@vm.running?
	end

end

end 
end
