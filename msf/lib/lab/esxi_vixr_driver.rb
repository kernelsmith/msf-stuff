require 'vm_driver'
##
## $Id: esxi_vixr_driver.rb 11753 2011-02-16 02:15:24Z jcran $
##

# This requires rhythmx's vixr driver from https://github.com/rhythmx/vixr 
# and below that, the VIX api from vmware http://www.vmware.com/support/developer/vix-api/

module Lab
module Drivers

class EsxiVixrDriver < VmDriver

	attr_accessor :type
	attr_accessor :location

	def initialize(vmid, location, credentials=nil)

		begin 
			require 'vixr'
		rescue
			raise "Oops, no vixr installed. Consider using the regular workstation driver.\n" +
				"Or install the vixr driver and vix api --\n" +
				"https://github.com/rhythmx/vixr && http://www.vmware.com/support/developer/vix-api/"
		end
		
		@vmid = filter_input(vmid)
		@location = filter_input(location)
		if !File.exist?(@location)
			raise ArgumentError,"Couldn't find: " + location
		end

		@credentials = credentials

		# TODO - Currently only implemented for the first set
		if @credentials.count > 0
			@vm_user = filter_input(@credentials[0]['user']) || "\'\'"
			@vm_pass = filter_input(@credentials[0]['pass']) || "\'\'"
		end
		
		host = VixR.connect()
		vm = host.op0n_vmx(@location)
		
	end

	def start
		vm.power_on
	end

	def stop
		vm.power_off
	end

	def suspend
		vm.suspend
	end

	def pause
		vm.pause
	end

	def reset
		vm.reset
	end

	def create_snapshot(snapshot)
		snapshot = filter_input(snapshot)
		system_command("ssh #{@user}@#{@host} vmrun -T ws snapshot \\\'#{@location}\\\' #{snapshot} nogui")
	end

	def revert_snapshot(snapshot)
		snapshot = filter_input(snapshot)
		system_command("ssh #{@user}@#{@host} vmrun -T ws revertToSnapshot \\\'#{@location}\\\' #{snapshot} nogui")
	end

	def delete_snapshot(snapshot)
		snapshot = filter_input(snapshot)
		system_command("ssh #{@user}@#{@host} vmrun -T ws deleteSnapshot \\\'#{@location}\\\' #{snapshot} nogui" )
	end


	def run_command(command)
		command = filter_input(command)
		if vm.login(@vm_user,@vm_pass)
			vm.run_prog(command)
		end
	end
	
	def copy_from(from, to)
		from = filter_input(from)
		to = filter_input(to)
		cp_from_host(from,to)
	end

	def copy_to(from, to)
		from = filter_input(from)
		to = filter_input(to)
		vm.cp_to_guest(from,to)
	end

	def check_file_exists(file)
		file = filter_input(file)
		file_exists?(file)
	end

	def create_directory(directory)
		directory = filter_input(directory)
	end

	def cleanup

	end

	def running?
		vm.running?
	end

end

end 
end
