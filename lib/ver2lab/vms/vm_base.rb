
module Labv2
module Vms

class Vm
	# necessary attribs for all vms
	attr_accessor :name			# unique reference to this vm
	attr_accessor :location		# path to vm config file
	attr_accessor :brand		# the vm brand, like vmware, virtualbox, dynagen etc
	attr_accessor :os			# windows or linux
	attr_reader   :vmserver_uid # this must match the a previously defined server's :uid
	
	# optional attribs, depending on subclass changes
	attr_accessor :arch			# 32 or 64
	attr_reader   :obj_vmserver	# associated VmServer object
	attr_accessor :hyperv_id	# id used by the hypervisor to id the vm, varies greatly by brand
	attr_accessor :descripition	# str, arbitrary description
	attr_accessor :tools		# bool
	attr_accessor :tags			# array of tags like ["cracker","sploit","ie8","meterpreter"]
	#attr_accessor :possible_server_types	# [ remote, vmware, virtualbox, etc ]

	## Initialize takes a vm configuration hash of the form
	##   {:name => "name", :location => "/path/to/vm_def_file", etc}
	## and an array of avail_vmservers (instantied when the yaml file is parsed)
	## location is gernally a path to the vm definition file or uri to it
	
	def initialize(config = {}, avail_vmservers)	

		# Mandatory
		@name = config[:name] 			|| nil # not used in command lines
		raise "Missing name" unless @name
		@location = config[:location] 	|| nil #filter depends on hyperv type but general fs filter applies
		raise "Missing location" unless @location
		@brand = config[:brand] 		|| nil
		raise "Missing brand" unless @brand
		@vmserver_uid = config[:vmserver_uid] || nil # associated vmserver_uid
		raise "Missing vmserver_uid" unless vmserver_uid

		#optional
		@hyperv_id = config[:description] 	|| nil 	#filter depends on hyperv type
		@description = config[:description] || nil 	# not used in command lines
		@tools = config[:tools] 			|| false # don't filter this, not used in cmdlines
		@tags = config[:tags] 				|| [] 	# don't filter this, not used in cmdlines
		@os = config[:os] 					|| nil # don't filter this, not used in cmdlines			
		@arch = config[:arch] 				|| nil # don't filter this, not used in cmdlines
		
		#defined by subclasses
		#@possible_server_types = config[:possible_server_types]	|| []

		# Load in a list of modifiers. These provide additional methods
		# TODO - currently it is up to the user to verify that 
		# modifiers are properly used with the correct VM image. If not, 
		# the results are likely to be disasterous. 		
		#@modifiers = config['modifiers']

		#Only dynagen
		@platform = config[:platform]
		
		# Now handle the modifiers - for now, just eval'm
 		#@modifiers.each { |modifier|  self.class.send(:include, eval("Lab::Modifier::#{modifier}"))}
 		
 		# finally, link the vm to it's server object
 		@obj_vmserver = resolve_vmserver(@vmserver_uid,avail_vmservers) || nil
 		raise  LabdefError "The vmserver with uid @vmserver_uid could not be found in " +
 			"#{avail_vmservers.inspect} you must use relink_to_server before you can use this " +
 			"vm" unless @obj_vmserver
		
	end
	
	def running?
		run_if_server_supports("#{__method__}",@obj_vmserver,self)
	end

	def start
		run_if_server_supports("#{__method__}",@obj_vmserver,self)
	end

	def stop
		run_if_server_supports("#{__method__}",@obj_vmserver,self)
	end

	def pause
		run_if_server_supports("#{__method__}",@obj_vmserver,self)
	end

	def suspend
		run_if_server_supports("#{__method__}",@obj_vmserver,self)
	end
	
	def reset
		run_if_server_supports("#{__method__}",@obj_vmserver,self)
	end
	
	def resume
		run_if_server_supports("#{__method__}",@obj_vmserver,self)
	end

	def create_snapshot(snapshot)
		run_if_server_supports("#{__method__}",@obj_vmserver,self,snapshot)
	end

	def revert_snapshot(snapshot)
		run_if_server_supports("#{__method__}",@obj_vmserver,self,snapshot)
	end

	def delete_snapshot(snapshot)
		run_if_server_supports("#{__method__}",@obj_vmserver,self,snapshot)
	end

	def revert_and_start(snapshot)
		run_if_server_supports("#{__method__}",@obj_vmserver,self,snapshot)
	end

	def copy_to(from,to)
		run_if_server_supports("#{__method__}",@obj_vmserver,self,from,to)
	end
	
	def copy_from(from,to)
		run_if_server_supports("#{__method__}",@obj_vmserver,self,from,to)
	end

	def check_file_exists(file)
		run_if_server_supports("#{__method__}",@obj_vmserver,self,file)
	end
	
	def create_directory(directory)
		run_if_server_supports("#{__method__}",@obj_vmserver,self,file)
	end

	def open_uri(uri)
		raise "This should be overridden by a subclass"
		# we don't filter the uri, as it's getting tossed into a script 
		# by the driver
		run_if_server_supports("#{__method__}",@obj_vmserver,self,uri)
	end

	def to_s
		return "#{@name}: #{@brand}: #{@location}"
	end

	def to_yaml
		# TODO:  this
		out =  " - vmid: #{@vmid}\n"
		out += "   driver: #{@driver_type}\n"
		out += "   location: #{@driver.location}\n"
		out += "   type: #{@type}\n"
		out += "   tools: #{@tools}\n"
		out += "   os: #{@os}\n"
		out += "   arch: #{@arch}\n"
		if @user or @host # Remote vm/drivers only
			out += "   user: #{@user}\n"
			out += "   host: #{@host}\n"
		end

		out += "   credentials:\n"
		@credentials.each do |credential|		
			out += "     - user: #{credential['user']}\n"
			out += "       pass: #{credential['pass']}\n"
		end
		
	 	return out
	end
	def relink_to_server(obj_vmserver)
		raise(RuntimeError,"VM can't be relinked because it is running") unless self.running? = false
		raise(RuntimeError,"Vm can't be relinked because " +
			"it's brand doesn't match the new server's brand") unless self.brand == obj_vmserver.brand
		@obj_vmserver = obj_vmserver
	end
private

	def filter_input(string)
		return unless string
					
		if !(string =~ /^[(!)\d*\w*\s*\[\]\{\}\/\\\.\-\"\(\)]*$/)
			raise "WARNING! Invalid character in: #{string}"
		end

		string
	end
	
	def resolve_vmserver(uid,avail_vmservers)
		matches = []
		matches = avail_vmservers.select {|vmsrv| vmsrv[:uid] = uid}
		matches.first # return only the first just in case there's somehow more than one
	end
	
	def run_if_server_supports(meth,obj_vmserver,obj_vm)
		obj_vmserver.respond_to("#{meth}") ? obj_vmserver.send("#{meth}",obj_vm) : raise(NotImplmentedError,\
		"The VmServer (#{obj_vmserver.to_s}) does not appear to support the #{meth} method")
	end
end

end # end Vms Module
end # end Lab Module
