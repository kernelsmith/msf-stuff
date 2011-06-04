module Lab
module Controllers
module RemoteEsxController

	VIM_CMD = 'vim-cmd'.freeze
	#VIM_CMD = 'vmware-vim-cmd'.freeze
		# do we need to know esx 3.5 vs 4?
		# esx4 command = vim-cmd
		# esx3.5 command = vmware-vim-cmd?
		# for now, let's just assume esx4

	def self.config_list
		user.gsub!(/(\W)*/, '')
		host.gsub!(/(\W)*/, '')
		
		all_registered_vms = [] # array of VM hashes
		raw = ''
		
		remote_cmd = "ssh #{user}@#{host} \"#{VIM_CMD} vmsvc/getallvms\""
		puts "running #{remote_cmd}"
		raw = `#{remote_cmd}`.scan(/^[0-9]+ .*/).flatten # only lines that start with numbers
		
		raw.each do |esxline|
			# esxi uses an annoying [datastore1] representation
			# vmid name [storage] path guestOS vmtype notes
			#   0   1       2       3     4       5     6
			# let's translate it if we see [...]
			if esxline =~ /^\[.+\]/ # if we have [...]
				esxline.gsub!(/\[.+\]/,'') # get rid of brackets[]
				all = esxline.split(" \t",7) || []
				# convert the array to a hash, for my sanity, thanks tockitj
				hashish = Hash[ *[ :id,:name,:storage,:path,:os,:type,:description ].zip(all).flatten
				#combine storage and path as /vmfs/volumes/:storage/:path
				# could parse vmware-vim-cmd /hostsvc/summary/fsvolume if need be
				hashish[:path] = "/vmfs/volumes/#{hashish[:storage]}/#{hashish[:path]}"
				all_registered_vms << hashish
				
			else
				# in case there isn't a [datastore] type entry
				# need to see what the output looks like if any vm is ever returned w/o [datastore]
				# for now, just hang on to all the parts
				all = esxline.split(" \t",7) || []
				all_registered_vms << Hash[ *[ :id,:name,:storage,:path,:os,:type,:description ].zip(all).flatten ]
			end
		end
		
		return all_running_vms
	end

	def self.running_list(user, host)
		user.gsub!(/(\W)*/, '')
		host.gsub!(/(\W)*/, '')

		all_running_vms = []
		# first get all registered vms
		all_registered_vms = self.config_list || {}

		# now let's see which one's are running
		# TODO:  this is ghetto, would be better not to connect repeatedly
		all_registered_vms.each do |h|
			remote_cmd = "ssh #{user}@#{host} \"#{VIM_CMD} vmsvc/power.getstate #{h[:id]}\""
			puts "running #{remote_cmd}"
			raw = `#{remote_cmd}`
			# if raw has 'Powered on', it's on
			all_running_vms << h if raw =~ /Powered on/				
		end
		return all_running_vms
	end

	def self.dir_list(basepath=nil)
		vm_list = Find.find(basepath).select { |f| f =~ /\.vmx$/ }
		return vm_list
	end
		
end
end
end
