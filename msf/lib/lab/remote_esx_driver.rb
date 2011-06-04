require 'vm_driver'

##
## $Id: remote_esx_driver.rb 12713 2011-05-25 07:30:22Z jcran $
##

module Lab
module Drivers

class RemoteEsxDriver < VmDriver

	attr_accessor :location # among other things

	def initialize(vmid, location, os=nil, tools=false, user=nil, host=nil, credentials=nil)

		## TODO - Should proabably check file existence?	
		unless user then raise ArgumentError, "Must provide a username" end
		unless host then raise ArgumentError, "Must provide a hostname" end

		@vmid = filter_input(vmid)
		@location = filter_input(location)
		@user = filter_input(user)
		@host = filter_input(host)
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
		system_command("ssh #{@user}@#{@host} \"vim-cmd vmsvc/power.on #{vmid}\"")
	end

	def stop
		system_command("ssh #{@user}@#{@host} \"vim-cmd vmsvc/power.shutdown #{vmid}\"")
		# or power.off?
	end

	def suspend
		system_command("ssh #{@user}@#{@host} \"vim-cmd vmsvc/power.suspend #{vmid}\"")
	end

	def pause
		system_command("ssh #{@user}@#{@host} \"vim-cmd vmsvc/power.suspend #{vmid}\"")
		# there doesn't appear to be a pause
	end

	def reset
		system_command("ssh #{@user}@#{@host} \"vim-cmd vmsvc/power.reset #{vmid}\"")
	end

	def create_snapshot(snapshot)
		snapshot = filter_input(snapshot)
		system_command("ssh #{@user}@#{@host} \"vim-cmd vmsvc/snapshot.create #{vmid} #{snapshot} lab-snap-#{Time.new} false\"")
		#vmware-vim-cmd vmsvc/snapshot.create [vmid: int] [snapshotName: string] 
		#										[snapshotDescription: string] [includeMemory:bool]

	end

	def revert_snapshot(snapshot)
		return
		snapshot = filter_input(snapshot)
		system_command("ssh #{@user}@#{@host} \"vim-cmd vmsvc/snapshot.revert #{vmid} 0 0\"")
		#vmware-vim-cmd vmsvc/snapshot.revert [vmid: int] [snapshotlevel: int] [snapshotindex: int]
		# not sure how we can do this, would have to list snapshots and map name to level & index
	end

	def delete_snapshot(snapshot)
		return
		snapshot = filter_input(snapshot)
		system_command("ssh #{@user}@#{@host} \"vim-cmd vmsvc/snapshot.remove #{vmid} true 0 0\"")
		#Usage: snapshot.remove vmid [removeChildren] [snapshotLevel] [snapshotIndex]
		# same comment as for revert
	end
	
	def run_command(command)
		puts("Not implemented")
		return
		# generate local & remote script paths
		script_rand_name = rand(10000)

		if @os == "windows"
			local_tempfile_path = "/tmp/lab_script_#{script_rand_name}.bat"
			remote_tempfile_path = "C:\\\\lab_script_#{script_rand_name}.bat"
			remote_run_command = remote_tempfile_path
		else
			local_tempfile_path = "/tmp/lab_script_#{script_rand_name}.sh"
			remote_tempfile_path = "/tmp/lab_script_#{script_rand_name}.sh"
			remote_run_command = "/bin/sh #{remote_tempfile_path}"
		end

		# write out our script locally
		File.open(local_tempfile_path, 'w') {|f| f.write(command) }

		# we really can't filter command, so we're gonna stick it in a script
		if @tools
			# copy it to the vm host - this is because we're a remote driver
			remote_copy_command = "scp #{local_tempfile_path} #{@user}@#{@host}:#{local_tempfile_path}"
			system_command(remote_copy_command)

			# we have it on the vm host, copy it to the vm guest
			vmrunstr = "ssh #{@user}@#{@host} \"vim-cmd vmsvc ws -gu #{@vm_user} -gp #{@vm_pass} " +
					"copyFileFromHostToGuest \'#{@location}\' \'#{local_tempfile_path}\' " +
					"\'#{remote_tempfile_path}\' nogui\""
			system_command(vmrunstr)

			# now run it on the guest
			vmrunstr = "ssh #{@user}@#{@host} \"vim-cmd vmsvc ws -gu #{@vm_user} -gp #{@vm_pass} " + 
					"runProgramInGuest \'#{@location}\' -noWait -activeWindow \'#{remote_run_command}\'\""
			system_command(vmrunstr)

			## CLEANUP
			# delete it on the guest
			vmrunstr = "ssh #{@user}@#{@host} \"vim-cmd vmsvc ws -gu #{@vm_user} -gp #{@vm_pass} " + 
					"deleteFileInGuest \'#{@location}\' \'#{remote_tempfile_path}\'\""
			#system_command(vmrunstr)

			# and delete it on the vm host
			vmhost_delete_command = "ssh #{@user}@#{@host} rm #{local_tempfile_path}"
			system_command(vmhost_delete_command)

			# delete it locally
			local_delete_command = "rm #{local_tempfile_path}"
			system_command(local_delete_command)
		else
			# since we can't copy easily w/o tools, let's just run it directly :/
			if @os == "linux"
				scp_to(local_tempfile_path, remote_tempfile_path)
				ssh_exec(remote_run_command)
				ssh_exec("rm #{remote_tempfile_path}")
			else
				raise "zomgwtfbbqnotools"
			end	
		end
	end
	
	def copy_from(from, to)
		puts("Not implemented")
		return
		from = filter_input(from)
		to = filter_input(to)
		if @tools 
			vmrunstr = "ssh #{@user}@#{@host} \"vim-cmd vmsvc ws -gu #{@vm_user} -gp #{@vm_pass} " +
					"copyFileFromGuestToHost \'#{@location}\' \'#{from}\' \'#{to}\' nogui\"" 
			system_command(vmrunstr)
		else
			scp_to(from,to)
		end
	end

	def copy_to(from, to)
		puts("Not implemented")
		return
		from = filter_input(from)
		to = filter_input(to)
		
		if @tools
			vmrunstr = "ssh #{@user}@#{@host} \"vim-cmd vmsvc ws -gu #{@vm_user} -gp #{@vm_pass} " +
					"copyFileFromHostToGuest \'#{@location}\' \'#{from}\' \'#{to}\' nogui\""  
			system_command(vmrunstr)
		else
			scp_to(from,to)
		end
	end

	def check_file_exists(file)
		puts("Not implemented")
		return
		if @tools
	
			file = filter_input(file)
			vmrunstr = "\"ssh #{@user}@#{@host} vim-cmd vmsvc ws -gu #{@vm_user} -gp #{@vm_pass} " +
					"fileExistsInGuest \'#{@location}\' \'{file}\' nogui\""
			system_command(vmrunstr)
		else
			raise "not implemented"
		end
	end

	def create_directory(directory)
		puts("Not implemented")
		return
		directory = filter_input(directory)
	
		if @tools
			vmrunstr = "\"ssh #{@user}@#{@host} vim-cmd vmsvc ws -gu #{@vm_user} -gp #{@vm_pass} " +
					"createDirectoryInGuest \'#{@location}\' \'#{directory}\' nogui\""
			system_command(vmrunstr)
		else
			ssh_exec(command)
		end
	end

	def cleanup

	end

	def running?
		## Get running VMs
		running_arr_hashes = Lab::Controllers::RemoteEsxController.running_list
		running_arr_hashes.each do |h|
			if h[:path].to_s =~ Regexp.new(@location.to_s)
				return true
			end
		end

		false
	end

end

end 
end
