# This controller was built against: 
# VMware ESX Host Agent 4.1.0 build-348481

module Lab
module Controllers
module RemoteEsxController
		
	# Note that 3.5 was different (vmware-vim-cmd)
	VIM_CMD = '/bin/vim-cmd'.freeze

	def self.dir_list(basepath='[datastore1]')
		# basepath must either be a datastore such as [datastore1], or a 
		# full, absolute path such as /vmfs/volumes/4d8a1e76-74ef4b20-6e11-0019b9cb8915/vms, or a
		# full path that starts with a datastore such as [datastore1]/vms/
		# note, you can get away w/o the brackets []
		# tho we could hard code [datastore1] as /vmfs/volumes/datastore1 and so on, let's be l33t
		
		if basepath =~ /^\[.+\]/  # if basepath starts with and looks like a datastore
			# resolve the datastore to abs path
			puts "Resolving datastore (#{basepath}) with server"
			remote_cmd = "ssh #{user}@#{host} \"#{VIM_CMD} hostsvc/datastore/info datastore1 | grep path\""
			raw = `#{remote_cmd}`
			if raw =~ /Datastore not found/
				raise "#{basepath} not recognized by the server as a valid datastore" 
			else
				root_path = raw.split('"')[1] 
				basepath.gsub!(/^\[.+\]/,root_path) # replace 
			end
		end
		remote_cmd = "ssh #{user}@#{host} \"find ${basepath} -name \"*.vmx\"\""
		vm_list = `#{remote_cmd}`.split("\n")
	end

	def self.running_list(user, host)
		user.gsub!(/(\W)*/, '')
		host.gsub!(/(\W)*/, '')

		# first get all registered vms
		registered_vms = self.get_vms(user, host) || []
		running_vms = []

		# now let's see which ones are running
		# this is less ghetto then connecting multiple times
		script_get_all_power_states = %q{for item in $(/bin/vim-cmd vmsvc/getallvms | egrep ^[0-9]+ | awk '{print $1}');do echo -en "${item} $(vim-cmd vmsvc/power.getstate ${item} | grep -v Retrieved) \n";done'}.freeze
		remote_cmd = "ssh #{user}@#{host} #{script_get_all_power_states}"
		# returns 304 Powered on\n305 Powered off    etc
		raw = `#{remote_cmd}`
		registered_vms.each do |vm|
			running_vms << vm if raw =~ /#{vm[:id]} Powered on/			
		end

		return running_vms
	end

private 

	def self.get_vms(user, host)
		user.gsub!(/(\W)*/, '')
		host.gsub!(/(\W)*/, '')
		
		vms = [] # array of VM hashes
		remote_cmd = "ssh #{user}@#{host} \"#{VIM_CMD} vmsvc/getallvms | grep ^[0-9] | sed 's/[[:blank:]]\\{3,\\}/ /g'\""
		raw = `#{remote_cmd}`.split("\n")

		raw.each do |line|
			# So effing ghetto
			id_and_name = line.split('[datastore').first
			id = id_and_name.split(' ').first
	
			## TODO - there's surely a better way to do this.
			name_array = id_and_name.split(' ')
			name_array.shift
			name = name_array.join(' ')
			vms << {:id => id, :name => name}
		end
		
		return vms
	end
	
end
end
end
