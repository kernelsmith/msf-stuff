
##
## This is the main lab controller. Require this controller to get all 
## lab functionality. 
##
##

$:.unshift(File.expand_path(File.dirname(__FILE__)))
$:.unshift(File.expand_path(File.join(File.dirname(__FILE__), 'vms')))
$:.unshift(File.expand_path(File.join(File.dirname(__FILE__), 'vmservers')))
#$:.unshift(File.expand_path(File.join(File.dirname(__FILE__), 'modifier')))

require 'find'
require 'yaml'
require 'enumerator'
require 'fileutils'

require 'vm'
require 'vmserver'
#require 'modifiers'

module Labv2
	
	class LabdefError << Exception
		
	end
	
	class LabController 

		include Enumerable
		include Labv2::Vms
		include Labv2::Vmservers


		def initialize (labdef=nil)
			@vm_servers = [] ## Start with an empty array of vm_servers
			@vms = [] ## Start with an empty array of vms

			## labdef is a big array of hashes, use yaml to store
			## vm_servers must be defined before vms in labdef
			## this could be overcome by changing the vm init method and using relink_to
			labdef = [] unless labdef 
			
			## Create vm objects from the lab definition
			load_vms(labdef)
		end
		
		def clear!
			@vms = []
		end

		def [](x)
			find_by_name(x)
		end

		def find_by_name(name)
			@vms.each do |vm|
				if (vm.name.to_s == name.to_s)
					return vm
				end
			end
			return nil
		end

		def add_vm(name,server_uid,type,os,location,credentials=nil,user=nil,host=nil)			
			
			@vms << Vm.new( {	'name' => name, 
						#TODO: finish this
						'location' => location, 
						'credentials' => credentials,
						'user' => user,
						'host' => host} )
		end

		def remove_by_vmid(vmid)
			@vms.delete(self.find_by_name(name))
		end	

		def from_file(file)
			labdef = YAML::load_file(file)
			load_vms(labdef)
		end

		def load_vms(vms)
			vms.each do |item|
				begin
					if item[:uid]
						serv = VmServer.new(item)
						@vm_servers << serv unless false # add an include name check here
					else
						vm = Vm.new(item)
						@vms << vm unless includes_name? vm.name
					end
				rescue LabdefError => e
					puts "Warning: #{e.to_s}"
					next
				rescue Exception => e
					# TODO -  this needs to go into a logfile and be raised up to an interface.
					puts "Invalid VM definition"
					puts "Exception: #{e.to_s}"
				end 
			end
			# relink the vms to vmservers in case they weren't defined in the right order
			@vms.each do |item|
				begin
					unless item[:obj_vmserver]
						item.relink_to_server(@vm_servers.select{|x| x[:uid] == item[:server_uid]}.first)	
					end
				end
			end
		end

		def to_file(file)
			File.open(file, 'w') { |f| @vms.each { |vm| f.puts vm.to_yaml } } 
		end

		def each &block
			@vms.each { |vm| yield vm }
		end

		def includes?(specified_vm)
			@vms.each { |vm| if (vm == specified_vm) then return true end  }
		end

		def includes_name?(name)
			@vms.each do |vm| 
				return true if (vm.name == name)
			end
			return false
		end

		def build_from_dir(brand, dir, clear=false)
		
			if clear
				@vms = []
			end
			
			#TODO:  Require the full brand, like vmware_workstation or add a method somehwere which
			#		Can figure out the best Vm Brand Class to instantiate
			if brand =~ /vmware/i
				vm_list = ::Labv2::Vms::dir_list(dir)
			elsif brand =~ /[virtualbox|vbox]/i
				# Do vbox stuff
			else
				raise TypeError, "Unsupported VM Type"
			end

#			if driver_type.downcase == "workstation"
#				vm_list = ::Lab::Controllers::WorkstationController::dir_list(dir)
#			elsif driver_type.downcase == "workstation_vixr"	
#				vm_list = ::Lab::Controllers::WorkstationVixrController::dir_list(dir)

#			else
#				raise TypeError, "Unsupported VM Type"
#			end
			
			vm_list.each_index do |index|
				@vms << Vm.new( {'vmid' => "vm_#{index}", 'driver' => driver_type, 'location' => vm_list[index]} )
			end
		end

		def build_from_running(driver_type=nil, user=nil, host=nil, clear=false)
		
			if clear
				@vms = []
			end

			case driver_type.intern
				when :workstation
					vm_list = ::Lab::Controllers::WorkstationController::running_list
					
					vm_list.each do |item|
			
						## Name the VM
						index = @vms.count + 1
	
						## Add it to the vm list
						@vms << Vm.new( {	'vmid' => "vm_#{index}",
									'driver' => driver_type, 
									'location' => item, 
									'user' => user,
									'host' => host } )
					end
					
				when :remote_workstation
					vm_list = ::Lab::Controllers::RemoteWorkstationController::running_list(user, host)
					
					vm_list.each do |item|
			
						## Name the VM
						index = @vms.count + 1
	
						## Add it to the vm list
						@vms << Vm.new( {	'vmid' => "vm_#{index}",
									'driver' => driver_type, 
									'location' => item, 
									'user' => user,
									'host' => host } )
					end
					
				when :virtualbox
					vm_list = ::Lab::Controllers::VirtualBoxController::running_list
					
					# TODO - why are user and host specified here?

					vm_list.each do |item|
						## Add it to the vm list
						@vms << Vm.new( {	'vmid' => "#{item}",
									'driver' => driver_type,
									'location' => nil, # this will be filled in by the driver
									'user' => user,
									'host' => host } )
					end

				when :remote_esx
					vm_list = ::Lab::Controllers::RemoteEsxController::running_list(user,host)
					
					vm_list.each do |item|
						@vms << Vm.new( {	'vmid' => "#{item[:id]}",
									'name' => "#{item[:name]}",
									'driver' => driver_type, 
									'user' => user,
									'host' => host } )
					end
						
				else
					raise TypeError, "Unsupported VM Type"
				end

		end	

		def build_from_config(driver_type=nil, user=nil, host=nil, clear=false)
		
			if clear
				@vms = []
			end

			case driver_type.intern
				when :virtualbox
					vm_list = ::Lab::Controllers::VirtualBoxController::config_list
					
					vm_list.each do |item|
						## Add it to the vm list
						@vms << Vm.new( {	'vmid' => "#{item}",
									'driver' => driver_type, 
									'location' => nil, 
									'user' => user,
									'host' => host } )
					end
						
				else
					raise TypeError, "Unsupported VM Type"
				end

		end	

		def running?(vmid)
			if includes_vmid?(vmid)
				return self.find_by_vmid(vmid).running?
			end
			return false 
		end
	end
end