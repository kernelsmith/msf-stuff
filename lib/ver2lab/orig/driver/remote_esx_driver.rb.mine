require 'vm_driver'

##
## $Id: remote_esx_driver.rb 12713 2011-05-25 07:30:22Z jcran $
##

# This driver was built against: 
# VMware ESX Host Agent 4.1.0 build-348481


module Lab
module Drivers

class RemoteEsxDriver < VmDriver

	attr_accessor :location # among other things
	attr_accessor :esx_vmid
	#attr_accessor :type

	def initialize(vmid, esx_vmid=nil, location=nil, os=nil, tools=false, user=nil, host=nil, credentials=nil)

		unless user then raise ArgumentError, "Must provide a username" end
		unless host then raise ArgumentError, "Must provide a hostname" end
		if not esx_vmid and not location
			then raise ArgumentError, "Must provide an esx_vmid or a location"
		end

		@vmid = filter_command(vmid)
		@user = filter_command(user)
		@host = filter_command(host)
		
		# resolve esx_vmid or location depending on whether esx_vmid is provided or not
		if esx_vmid
			@esx_vmid = filter_id(esx_vmid)
			@location = ::Lab::Controllers::RemoteEsxController.get_location(@user,@host,@esx_vmid)

		else
			@location = filter_command(location)
			@esx_vmid = ::Lab::Controllers::RemoteEsxController.get_esx_vmid(@user,@host,@location)
		end

		@credentials = credentials # individually filtered
		@tools = tools	# not used in command lines, no filter
		@os = os	# not used in command lines, no filter

		# TODO - Currently only implemented for the first set
		if @credentials.count > 0
			@vm_user = filter_input(@credentials[0]['user'])
			@vm_pass = filter_input(@credentials[0]['pass'])
			@vm_keyfile = filter_input(@credentials[0]['keyfile'])
		end
	end

	def start
		system_command("ssh #{@user}@#{@host} \"vim-cmd vmsvc/power.on #{@esx_vmid}\"")
	end

	def stop
		system_command("ssh #{@user}@#{@host} \"vim-cmd vmsvc/power.off #{@esx_vmid}\"")
	end

	def suspend
		system_command("ssh #{@user}@#{@host} \"vim-cmd vmsvc/power.suspend #{@esx_vmid}\"")
	end

	def pause 	# no concept of pause?
		system_command("ssh #{@user}@#{@host} \"vim-cmd vmsvc/power.suspend #{@esx_vmid}\"")
	end

	def resume
		system_command("ssh #{@user}@#{@host} \"vim-cmd vmsvc/power.suspendResume #{@esx_vmid}\"")
	end

	def reset
		system_command("ssh #{@user}@#{@host} \"vim-cmd vmsvc/power.reset #{@esx_vmid}\"")
	end

	def create_snapshot(snapshot)
		snapshot = filter_input(snapshot)
		
		#vmware-vim-cmd vmsvc/snapshot.create [vmid: int] [snapshotName: string] 
		#			[snapshotDescription: string] [includeMemory:bool]

		system_command("ssh #{@user}@#{@host} \"vim-cmd vmsvc/snapshot.create #{@esx_vmid} #{snapshot} \'lab created snapshot\' 1 true\"")
	end

	def revert_snapshot(snapshot)
		raise "Not Implemented"

		#vmware-vim-cmd vmsvc/snapshot.revert [vmid: int] [snapshotlevel: int] [snapshotindex: int]
		# not sure how we can do this, would have to list snapshots and map name to level & index

		#snapshot = filter_input(snapshot)
		#system_command("ssh #{@user}@#{@host} \"vim-cmd vmsvc/snapshot.revert #{@esx_vmid} 0 0\"")
	end

	def delete_snapshot(snapshot)
		raise "Not Implemented"

		#snapshot = filter_input(snapshot)
		#system_command("ssh #{@user}@#{@host} \"vim-cmd vmsvc/snapshot.remove #{@esx_vmid} true 0 0\"")
	end
	
	def run_command(command)
		raise "Not Implemented"
	end
	
	def copy_from(from, to)
		raise "Not Implemented"
	end

	def copy_to(from, to)
		raise "Not Implemented"			
	end

	def check_file_exists(file)
		raise "Not Implemented"
	end

	def create_directory(directory)
		raise "Not Implemented"
	end

	def cleanup

	end

	def running?
		power_status_string = `ssh #{@user}@#{@host} \"vim-cmd vmsvc/power.getstate #{@esx_vmid}\"`
		return true if power_status_string =~ /Powered on/
	false
	end
	


end

end 
end
