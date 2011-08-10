# This controller was built against: 
# VMware ESX Host Agent 4.1.0 build-348481

module Lab
module Controllers
module RemoteEsxController
		
	# Note that 3.5 was different (vmware-vim-cmd)
	VIM_CMD = '/bin/vim-cmd'.freeze
	$BUGGER = false
	
	def self.bugger(msg="")
		puts "DEBUG:  from #{caller[0].split('`')[1].gsub("'",'')} #{msg}" if $BUGGER	
	end

	def self.dir_list(user=nil,host=nil,basepath='[datastore1]')
		# This can only work if we already know the ssh user and host, which we don't until we
		#  instantiate a Vm, so this is gonna have to stay as unimplemented until that's worked out
		
		raise "#{__method__} not Implemented yet, see comments"
		user.gsub!(/(\W)*/, '')
		host.gsub!(/(\W)*/, '')
		# basepath must either be a datastore such as [datastore1], or a 
		# full, absolute path such as /vmfs/volumes/4d8a1e76-74ef4b20-6e11-0019b9cb8915/vms, or a
		# full path that starts with a datastore such as [datastore1]/vms/
		# note, you can get away w/o the brackets []
		# tho we could hard code [datastore1] as /vmfs/volumes/datastore1 and so on, let's be l33t
		
		datastore = basepath.scan(/^\[.+\]/).first.to_s # stuff between the brackets, inclusive
		if datastore and not datastore.empty?
			# resolve the datastore to abs path		
			puts "Resolving datastore (#{datastore}) with server"
			root_path = self.resolve_datastore(user,host,datastore)
			basepath.gsub!(/^\[.+\]/,root_path) # replace 
		end
		remote_cmd = "ssh #{user}@#{host} \"find #{basepath} -name \"*.vmx\"\""
		self.bugger("running remote command:  #{remote_cmd}")
		vmx_list = `#{remote_cmd}`.split("\n")
	end

	def self.running_list(user, host)
		user.gsub!(/(\W)*/, '')
		host.gsub!(/(\W)*/, '')

		# first get all registered vms
		registered_vms = self.get_vms(user, host) || []
		running_vms = []

		# now let's see which ones are running
		# this is ghetto, but less ghetto then connecting multiple times
		script_get_all_power_states = %Q{for item in $(#{registered_vms.map {|h| h[:esx_vmid] }.join(' ')});do echo -en \\\"${item} $(#{VIM_CMD} vmsvc/power.getstate ${item} | grep -v Retrieved)\\n\\\";done}
		remote_cmd = "ssh #{user}@#{host} \"#{script_get_all_power_states}\""
		self.bugger("running remote command:  #{remote_cmd}")		
		# returns 304 Powered on\n305 Powered off  etc
		raw = `#{remote_cmd}`
		registered_vms.each do |vmh|
			if raw =~ /^#{vmh[:esx_vmid]} Powered on/
				vm[:state] = "on"
				running_vms << vm 
			elsif raw =~ /^#{vmh[:esx_vmid]} Powered off/
				vm[:state] = "off"
			else
				vm[:state] = "unknown"
			end
		end

		return running_vms
	end
	def self.get_location(user,host,esx_vmid)
		# takes an esx_vmid
		# returns the location of the vm with that id as
		# "[datastore1] the_vmx_that_i_want.vmx"
		
		raise ArgumentError, "esx_vmid must be a number" if ! esx_vmid =~ /^[0-9]+$/
		
		remote_cmd = "ssh #{user}@#{host} \"#{VIM_CMD} vmsvc/get.summary #{esx_vmid} | grep vmPathName\""
		self.bugger("running remote command:  #{remote_cmd}")
		raw = `#{remote_cmd}`
		if raw =~ /vim.fault.NotFound/ or raw.empty?
			raise "#{esx_vmid} not recognized by the server as a valid id"
			return nil
		else
			# vmPathName = "[datastore1] ubuntu-server.vmx",
			return raw.split('"')[1].to_s
		end
	end
	def self.get_esx_vmid(user,host,loc)
		# takes a location as:	[datastorename] rest/of/path/to/my_vmx
		# it will also support just rest/of/path/to/my_vmx but you run the risk of getting the
		# wrong datastore should there be two identical paths on 2 different datastores
		
		user.gsub!(/(\W)*/, '')
		host.gsub!(/(\W)*/, '')
		if not loc =~ /^\[.+\]/
			puts "Warning: your location doesn't seem to have a datastore in it.\n" +
				"Datastore resolution could be incorrect.\n" +
				"I will use the first path I find that includes your relative path"
		end
				
		vms = self.get_vms(user,host)
		vms.each do |vmh|
			if "#{vmh[:datastore]} #{vmh[:rel_path]}" =~ /#{Regexp.escape(loc)}/
				return vmh[:esx_vmid]
			end
		end
	end

private 
	def self.get_vms(user, host)
		user.gsub!(/(\W)*/, '')
		host.gsub!(/(\W)*/, '')
		
		vms = self.getallvms(user,host) # array of raw vm hashes
		# :esx_vmid,:name,:datastore,:rel_path,:os,:vmx_type,:description etc
		
		#let's clean up the hash and make it pallatable to other driver/controller code
		vms.each do |h|
			h[:vmid] = h[:name] if (h[:vmid] = nil or h[:vmid] = '')
			h[:location] = "#{h[:datastore]} #{h[:rel_path]}"
			if h[:os] =~ /^win/
				h[:os] = "windows"
			else 
				h[:os] = "linux" # there's a million different things esx/i will put here, screw it
			end
		end
		#bugger("vms is #{vms.inspect}")
		return vms
	end
	
	def self.getallvms(user,host) # use get_vms instead of this unless you want the raw stuff
		remote_cmd = "ssh #{user}@#{host} \"#{VIM_CMD} vmsvc/getallvms\""
		self.bugger("running remote command:  #{remote_cmd}")
		raw = `#{remote_cmd}`
		vms = [] # array of vm hashes
		# :esx_vmid,:name,:datastore,:rel_path,:os,:vmx_type,:description
		vms = self.hashify_getallmvs(raw)
	end
	
	def self.hashify_getallmvs(raw_string)
		arr = raw_string.scan(/^[0-9]+.+$/) # only the lines that start with numbers
		array_of_hashes = []
		arr.each do |line|
			arr_of_arrs = [:esx_vmid,:name,:datastore,:rel_path,:os,:vmx_type,:description].zip(line.split(" ",7))
			array_of_hashes << Hash[*arr_of_arrs.flatten]
		end
		return array_of_hashes
	end
	def self.resolve_datastore(user,host,loc='[datastore1]')
		##  This may no longer be needed.  Keeping for now.
		# takes a location as either:
		#	[datastorename] blah/blahblah
		#	/vmfs/volumes/uuid/blahblah
		#	/vmfs/volumes/datastorename/blahblah
		# returns abs path to the datastore (e.g. /vmfs/volumes/uuid) if loc looks like a datastore
		# returns the name of the datstore as "[name]" if loc looks like a path
		
		if loc =~ /\[.+\]/ # then resolve datastore to path and return it
			dsname = loc.scan(/\[.+\]/).first.gsub!(/\[/,'').gsub!(/\]/,'')
			remote_cmd = "ssh #{user}@#{host} \"#{VIM_CMD} hostsvc/datastore/info #{dsname} | grep path\""
			self.bugger("running remote command:  #{remote_cmd}")
			raw = `#{remote_cmd}`
			if raw =~ /Datastore not found/ or raw.empty?
				raise "#{dsname} not recognized by the server as a valid datastore"
				return nil
			else
				# path = "/vmfs/volumes/uuid"
				return raw.split('"')[1].to_s
			end
		else # then resolve path to datstore and return it
			# treat loc as an absolute path that needs to be converted to a datastore
			# it could be /vmfs/volumes/uuid/blah or /vmfs/volumes/datastorename/blah (tho sorta dumb)
			uuid_regex = '[a-fA-F0-9]{8}-[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}'
			if loc =~ /#{uuid_regex}/
				remote_cmd = "ssh #{user}@#{host} \"#{VIM_CMD} hostsvc/datastore/listsummary | egrep \'name|url\' |\""
				self.bugger("running remote command:  #{remote_cmd}")
				raw = `#{remote_cmd}` # name = "datastore1",\n url = "/vmfs/volumes/uuid", 
				uuid = loc.scan(/#{uuid_regex}/).first
				arr = raw.scan("/n")
				name = ''
				arr.each_with_index do |elem,idx|
					if elem =~ /#{uuid_regex}/
						name = arr[idx-1].split('"')[1] # then give me datastore name from prev. line
						return "[#{name}]"
					end
				end
			else
				name = loc.split(/\//)[3] #assumes datastores mounted like /somedir/somevoldir/datastores
				return "[#{name}]"
			end
		end
	end
	
end
end
end

