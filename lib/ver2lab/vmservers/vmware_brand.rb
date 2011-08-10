module Labv2
module VmServers

#
### VMWARE Brand
#
class VmwareVmServer < VmServer
	# this is not vmware server, that's VmwareServerVmServer
	# this class is meant to be subclassed
	@BASE_CMD = nil

	def initialize(config = {})
		super
		@brand = "vmware"
	end
		
	def running_list
		raise NotImplmentedError, "#{__method__} Must be implemented in a subclass"
	end

	def dir_list(basepath=nil)
		raise NotImplmentedError, "#{__method__} Must be implemented in a subclass"
	end

	def config_list
		raise NotImplmentedError, "#{__method__} Must be implemented in a subclass"
	end
end # end VmwareVmServer

### Workstation

class VmwareWorkstationVmServer < VmwareVmServer
	@BASE_CMD = "vmrun".freeze # any subclasses should be using same BASE_CMD so let us freeze it
	
	def initialize(config = {})
		super # check syntax
	end
	# define all the start stop etc commands here, see the old driver
	def start(obj_vm)
		run_hyperv_cmd("{#@BASE_CMD} -T ws start \'#{obj_vm.location}\' nogui")
	end
	def open_uri(obj_vm,uri)
		if obj_vm.os.downcase == "windows" 
			command = "\"C:\\program files\\internet explorer\\iexplore.exe\" #{uri}"
		else
			command = "firefox #{uri}"
		end 
		run_command_in_vm(obj_vm,command)
	end
	private
		def run_command_in_vm(obj_vm,cmd)
			script_rand_name = rand(10000)

			if obj_vm.os == "windows"
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
			if obj_vm.tools
				# copy our local tempfile to the guest
				vmrunstr = "#{@BASE_CMD} -T ws -gu #{obj_vm.vm_user} -gp #{obj_vm.vm_pass} " +
						"copyFileFromHostToGuest \'#{obj_vm.location}\' \'#{local_tempfile_path}\'" +
						" \'#{remote_tempfile_path}\' nogui"
				run_hyperv_cmd(vmrunstr)

				# now run it on the guest
				vmrunstr = "vmrun -T ws -gu #{obj_vm.vm_user} -gp #{obj_vm.vm_pass} " + 
					"runProgramInGuest \'#{obj_vm.location}\' -noWait -activeWindow \'#{remote_run_command}\'"
				run_hyperv_cmd(vmrunstr)

				## CLEANUP
				# delete it on the guest
				vmrunstr = "vmrun -T ws -gu #{obj_vm.vm_user} -gp #{obj_vm.vm_pass} " + 
						"deleteFileInGuest \'#{obj_vm.location}\' \'#{remote_tempfile_path}\'"
				run_hyperv_cmd(vmrunstr)

				# delete it locally
				local_delete_command = "rm -f #{local_tempfile_path}"
				run_hyperv_cmd(local_delete_command)
			else
				# since we can't copy easily w/o tools, let's just run it directly :/
				if obj_vm.os == "linux"
				
					output_file = "/tmp/lab_command_output_#{rand(1000000)}"
				
					scp_to(local_tempfile_path, remote_tempfile_path)
					ssh_exec(remote_run_command + "> #{output_file}")
					scp_from(output_file, output_file)
				
					ssh_exec("rm -f #{output_file}")
					ssh_exec("rm -f #{remote_tempfile_path}")
				
					# Ghettohack!
					string = File.open(output_file,"r").read
					`rm -f #{output_file}`		
				else
					raise "zomgwtfbbqnotools"
				end	
			end
			return string
		end
	end
end
class RemoteVmwareWorkstationVmServer < VmwareWorkstationVmServer
	require 'vm_mixins'
	# hardcode ssh for now
	include ::Labv2::VmServer::Mixins::Remote::Ssh
	
	def initialize(config = {})
		@type = "remote"
		super # check syntax
	end
end

### VmwareServer

class VmwareServerVmServer < VmwareVmServer
	@BASE_CMD = "vmrun".freeze # any subclasses should be using same BASE_CMD so let us freeze it

	def initialize(config = {})
		super # check syntax
	end
	
	def running_list
		vm_list = run_hyperv_cmd("#{@BASE_CMD} list").split("\n")
		vm_list.shift
		return vm_list
	end

	def dir_list(basepath=nil)
		# this only works for the local, it will need something different in remote
		vm_list = Find.find(basepath).select { |f| f =~ /\.vmx$/ }
		return vm_list
	end

	def config_list
		# ?  TODO:  ??
	end
end
class RemoteVmwareServerVmServer < VmwareServerVmServer

	require 'vm_mixins'
	# hardcode ssh for now
	include ::Labv2::VmServer::Mixins::Remote::Ssh

	def initialize(config = {})
		@type = "remote"
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
	
	def running_list
		vm_list = run_hyperv_cmd("#{@BASE_CMD} list").split("\n")
		vm_list.shift
		return vm_list
	end

	def dir_list(basepath=nil)
		# this only works for the local, it will need something different in remote
		vm_list = Find.find(basepath).select { |f| f =~ /\.vmx$/ }
		return vm_list
	end

	def config_list
		# ?
	end
end

### VmwareEsxVmServer (Vix?)

class VmwareEsxVmServer < VmwareVmServer
end
class RemoteVmwareEsxVmServer < VmwareEsxVmServer
	require 'vm_mixins'
	# hardcode ssh for now
	include ::Labv2::VmServer::Mixins::Remote::Ssh
	
	def initialize(config = {})
		@type = "remote"
		super # check syntax
	end
end

### VmwareEsxiVmServer

class VmwareEsxiVmServer < VmwareVmServer
end
class RemoteVmwareEsxiVmServer < VmwareEsxiVmServer

	require 'vm_mixins'
	# hardcode ssh for now
	include ::Labv2::VmServer::Mixins::Remote::Ssh
	
	def initialize(config = {})
		@type = "remote"
		super # check syntax
	end
	
	private
		def hashify_getallmvs(raw_string)
			# so you can:
			# array_of_hashes = hashify_getallvms(`ssh user@server "vim-cmd vmsvc/getallvms"`)
        	arr = raw_string.scan(/^[0-9]+.+$/) # only the lines that start with numbers
        	array_of_hashes = []
        	arr.each do |line|
        	    arr_of_arrs = [:esx_vmid,:name,:datastore,:rel_path,:os,:vmx_type,:description].zip(line.split(" ",7))
        	    array_of_hashes << Hash[*arr_of_arrs.flatten]
        	end
        	return array_of_hashes
    	end
	end
end # end RemoteVmwareEsxiVmServer

#	
#	include ::Labv2::Mixins::VmServer::Remote
#	
#	attr_accessor :user		
#	attr_accessor :host
#	@BASE_CMD = "vmrun".freeze # subclasses shouldn't be changing this so freeze it

#	def initialize(config = {})	
#		@user = config['user'] || nil
#		@host = config['host'] || nil
#		@type = "remote".freeze # subclasses should not change, so freeze
#		super # check syntax
#	end #
#	def running_list
#		raise NotImplmentedError, "#{__method__} Must be implemented in a subclass"
#	end
#	def dir_list(basepath=nil)
#		raise NotImplmentedError, "#{__method__} Must be implemented in a subclass"
#	end
#end # end RemoteVmwareVmServer

### End Vmware Brand
