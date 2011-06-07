module Lab
module Controllers
module EsxiVixrController

	def self.running_list
		puts("Not implemented yet")

		#return vm_list
		return
	end

	def self.dir_list(basepath=nil)
		vm_list = Find.find(basepath).select { |f| f =~ /\.vmx$/ }

		return vm_list
	end
end
end
end
