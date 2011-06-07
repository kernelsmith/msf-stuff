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

	def initialize(vmid, location, tools=false, user=nil, host=nil, pass=nil, credentials=nil)

		begin 
			require 'vixr'
		rescue
			raise "Oops, no vixr installed. Consider using the regular workstation driver.\n" +
				"Or install the vixr driver and vix api --\n" +
				"https://github.com/rhythmx/vixr && http://www.vmware.com/support/developer/vix-api/"
		end
		
		# TODO - Should proabably check file existence?	but won't be able until Vixr.connect
		#TODO:  unless user then raise ArgumentError, "Must provide a username" end
		unless host then raise ArgumentError, "Must provide a hostname" end

		@vmid = filter_input(vmid)
		@location = filter_input(location)
		#@user = filter_input(user)
		@user = "root"
		#@pass = filter_input(pass)
		@pass = 'password'
		@host = filter_input(host)
		@tools = tools	# not used in command lines, no filter
		#@os = os	# not used in command lines, no filter
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
		puts("DEBUG:  Connecting to remote server with:")
		puts("DEBUG:  Const=#{VixAPI::Const::Provider::Server2x} site=https://#{@host}:443/sdk u=#{@user} p=#{@pass} ort=#{@port}")
		#TODO:  Add timeout, otherwise this can hang
		host = VixR.connect(:hosttype => VixAPI::Const::Provider::Server2x, :hostname => "https://#{@host}", :user => @user, :pass => @pass, :port => @port)
		@vm = host.open_vmx("#{@location.to_s}") || nil
		puts("DEBUG:  vm handle is #{@vm.to_s}")
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
		if @vm.login(@vm_user,@vm_pass)
			@vm.run_prog(command)
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
		@vm.cp_to_guest(from,to)
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
		@vm.running?
	end

end

end 
end
