module Lab
module Controllers
module RemoteQemuController

	# this is whole ball of shit as qemu is not like other hyupervisors, esp
	# since it's not a hypervisor.  Getting info from and talking to a qemu "vm"
	# requires starting qemu with -monitor <socket> and connectin with sockets

	def self.running_list(user, host)
		user.gsub!(/(\W)*/, '')
		host.gsub!(/(\W)*/, '')

		# insert lots of crap

		return vm_list
	end

	def self.dir_list(basepath=nil)
		vm_list = Find.find(basepath).select { |f| f =~ /\.vmx$/ }
		return vm_list
	end
end
end
end
