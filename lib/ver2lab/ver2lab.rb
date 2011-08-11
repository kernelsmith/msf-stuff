##
## $Id$
##

$:.unshift(File.join(File.expand_path(File.dirname(__FILE__)), '..', 'lib', 'ver2lab'))

require 'yaml'
require 'lab_controller'

module Msf

class Plugin::Ver2lab < Msf::Plugin
	class Ver2labCommandDispatcher
		include Msf::Ui::Console::CommandDispatcher

		attr_accessor :controller
		
		def initialize(driver)
			super(driver)
			@controller = nil
		end

		#
		# Returns the hash of commands supported by this dispatcher.
		#
		def commands
		{
			"lab_help" => "lab_help <lab command> - Show that command's description.",
			"lab_show" => "lab_show - show all vms in the lab.",
			"lab_show_running" => "lab_show_running - show running vms.",
			"lab_load" => "lab_load [file] - load a lab definition from disk.", 			
			"lab_save" => "lab_save [filename] - persist a lab definition in a file.",
			"lab_load_running" => "lab_load_running [type] [user] [host] - use the running vms to create a lab.", 
			"lab_load_config" => "lab_load_config [type] [user] [host] - use the vms in the config to create a lab.", 
			"lab_load_dir" => "lab_load_dir [type] [directory] - create a lab from a specified directory.",
			"lab_clear" => "lab_clear - clear the running lab.",	
			"lab_start" => "lab_start [name+|all] start the specified vm.",
			"lab_reset" => "lab_reset [name+|all] reset the specified vm.",
			"lab_suspend" => "lab_suspend [name+|all] suspend the specified vm.",
			"lab_stop" => "lab_stop [name+|all] stop the specified vm.",
			"lab_revert" => "lab_revert [name+|all] [snapshot] revert the specified vm.",
			"lab_snapshot" => "lab_snapshot [name+|all] [snapshot] snapshot all targets for this exploit.",
			"lab_run_command" => "lab_run_command [name+|all] [command] run a command on all targets.",
			"lab_browse_to" => "lab_browse_to [name+|all] [uri] use the default browser to browse to a uri."
		}
		end

		def name
			"Ver2Lab"
		end
	
		##
		## Regular Lab Commands
		## 

		def cmd_lab_load(*args)
			return lab_usage unless args.count == 1 
			load_from_file(args[0])
		end

		def cmd_lab_load_running(*args)
			return lab_usage if args.empty?
			
			if args[0] =~ /^remote_/
				return lab_usage unless args.count == 3 
				## Expect a username & password
				@controller.build_from_running(args[0], args[1], args[2])
			else
				return lab_usage unless args.count == 1 
				@controller.build_from_running(args[0])
			end
		end

		def cmd_lab_load_config(*args)
			return lab_usage if args.empty?
			
			if args[0] =~ /^remote_/
				return lab_usage unless args.count == 3 
				## Expect a username & password
				@controller.build_from_config(args[0], args[1], args[2])
			else
				return lab_usage unless args.count == 1 
				@controller.build_from_config(args[0])
			end
		end

		def cmd_lab_load_dir(*args)	
			return lab_usage unless args.count == 2
			@controller.build_from_dir(args[0],args[1],true)
		end

		def cmd_lab_clear(*args)
			@controller.clear!
	        end

		def cmd_lab_save(*args)		
			return lab_usage if args.empty?
			@controller.to_file(args[0])
		end
		

		## 
		## Commands for dealing with a currently-loaded lab
		## 

		def cmd_lab_show(*args)
			if args.empty?
				hlp_print_lab
			else
				args.each_vm do |name|
					if @controller.includes_name? name
						print_line @controller[name].to_yaml
					else
						print_error "Unknown vm '#{name}'"
					end 
				end
	        end
	    end

		def cmd_lab_show_running(*args)
			hlp_print_lab_running
        end
	        
		def cmd_lab_start(*args)
			return lab_usage if args.empty?
		
			if args[0] == "all"
				@controller.each_vm do |vm| 
					print_line "Starting lab vm #{vm.name}."	
					if !vm.running?
						vm.start
					else
						print_line "Lab vm #{vm.name} already running."	
					end
				end
			else
				args.each_vm do |arg|
					if @controller.includes_name? arg
						vm = @controller.find_by_name(arg)	
						if !vm.running?
							print_line "Starting lab vm #{vm.name}."	
							vm.start
						else
							print_line "Lab vm #{vm.name} already running."	
						end
					end	
				end
			end
		end
	     
		def cmd_lab_stop(*args)
			return lab_usage if args.empty?
		
			if args[0] == "all"
				@controller.each_vm do |vm| 
					print_line "Stopping lab vm #{vm.name}."	
					if vm.running?
						vm.stop
					else
						print_line "Lab vm #{vm.name} not running."	
					end
				end
			else
				args.each_vm do |arg|
					if @controller.includes_name? arg
						vm = @controller.find_by_name(arg)	
						if vm.running?
							print_line "Stopping lab vm #{vm.name}."	
							vm.stop
						else
							print_line "Lab vm #{vm.name} not running."	
						end
					end	
				end
			end
	        end

		def cmd_lab_suspend(*args)
			return lab_usage if args.empty?
					
			if args[0] == "all"
				@controller.each_vm{ |vm| vm.suspend }
			else
				args.each_vm do |arg|
					if @controller.includes_name? arg
						if @controller.find_by_name(arg).running?
							print_line "Suspending lab vm #{arg}."
							@controller.find_by_name(arg).suspend
						end	
					end	
				end
			end
	        end

		def cmd_lab_reset(*args)
			return lab_usage if args.empty?
		
			if args[0] == "all"
				print_line "Resetting all lab vms."
				@controller.each_vm{ |vm| vm.reset }
			else
				args.each_vm do |arg|
					if @controller.includes_name? arg
						if @controller.find_by_name(arg).running?
							print_line "Resetting lab vm #{arg}."
							@controller.find_by_name(arg).reset	
						end
					end	
				end
			end
	        end


		def cmd_lab_snapshot(*args)
			return lab_usage if args.count < 2
			snapshot = args[args.count-1] 	
		
			if args[0] == "all"
				print_line "Snapshotting all lab vms to snapshot: #{snapshot}."
				@controller.each_vm{ |vm| vm.create_snapshot(snapshot) }
			else
				args[0..-2].each_vm do |name_arg|
					next unless @controller.includes_name? name_arg
					print_line "Snapshotting #{name_arg} to snapshot: #{snapshot}."
					@controller[name_arg].create_snapshot(snapshot)
				end
			end
	        end


		def cmd_lab_revert(*args)
			return lab_usage if args.count < 2
			snapshot = args[args.count-1] 		

			if args[0] == "all"
				print_line "Reverting all lab vms to snapshot: #{snapshot}."
				@controller.each_vm{ |vm| vm.revert_snapshot(snapshot) }
			else
				args[0..-2].each_vm do |name_arg|
					next unless @controller.includes_name? name_arg
					print_line "Reverting #{name_arg} to snapshot: #{snapshot}."
					@controller[name_arg].revert_snapshot(snapshot)	
				end
			end
	        end


		def cmd_lab_run_command(*args)
			return lab_usage if args.empty?
			command = args[args.count-1]
			if args[0] == "all"
				print_line "Running command #{command} on all vms."
					@controller.each_vm do |vm| 
						if vm.running?
							print_line "#{vm.name} running command: #{command}."
							vm.run_command(command)
						end
					end
			else
				args[0..-2].each_vm do |name_arg|
					next unless @controller.includes_name? name_arg
					if @controller[name_arg].running?
						print_line "#{name_arg} running command: #{command}."					
						@controller[name_arg].run_command(command)
					end
				end
			end
	        end

		def cmd_lab_browse_to(*args)
			return lab_usage if args.empty?
			uri = args[args.count-1]
			if args[0] == "all"
				print_line "Opening: #{uri} on all vms."
				@controller.each_vm do |vm| 
					if vm.running?
						print_line "#{vm.name} opening to uri: #{uri}."
						vm.open_uri(uri)
					end
				end
			else
				args[0..-2].each_vm do |name_arg|
					next unless @controller.includes_name? name_arg
					if @controller[name_arg].running?
						print_line "#{name_arg} opening to uri: #{uri}."
						@controller[name_arg].open_uri(uri)
					end
				end
			end
		end
	

		##
		## Commands for help
		##
		
		def longest_cmd_size
			commands.keys.map {|x| x.size}.sort.last
		end

		# No extended help yet, but this is where more detailed documentation
		# on particular commands would live. Key is command, (not cmd_command),
		# value is the documentation.
		def extended_help
			{
				"lab_fake_cmd" =>              "This is a fake command. It's got its own special docs." +
					(" " * longest_cmd_size) + "It might be long so deal with formatting somehow."
			}
		end

		# Map for usages
		def lab_usage
			caller[0][/`cmd_(.*)'/]               #`
			cmd = $1
			if extended_help[cmd] || commands[cmd]
				cmd_lab_help cmd
			else # Should never really get here...
				print_error "Unknown command. Try 'help'"
			end
		end

		def cmd_lab_help(*args)
			if args.empty?
				commands.each_pair {|k,v| print_line "%-#{longest_cmd_size}s - %s" % [k,v] }
			else
				args.each_vm do |c|
					if extended_help[c] || commands[c]
						print_line "%-#{longest_cmd_size}s - %s" % [c,extended_help[c] || commands[c]]
					else
						print_error "Unknown command '#{c}'"
					end
				end
			end

			print_line 
			print_line "In order to use this plugin, you'll want to configure a .yml lab file"
			print_line "You can find an example in data/lab/test_targets.yml" 
			print_line
		end


		private
			def load_from_file
				
			end
			
			def hlp_print_lab
				indent = '    '

				tbl = Rex::Ui::Text::Table.new(
					'Header'  => 'Available Lab VMs',
					'Indent'  => indent.length,
					'Columns' => [ 'name', 'Name', 'Location', "Power?" ]
				)

				@controller.each_vm do |vm| 
					tbl << [ 	vm.name,
							vm.name,
							vm.location, ]
						#	vm.running?]
				end
			
				print_line tbl.to_s
			end
				
			def hlp_print_lab_running
				indent = '    ' 

				tbl = Rex::Ui::Text::Table.new(
					'Header'  => 'Running Lab VMs',
					'Indent'  => indent.length,
					'Columns' => [ 'name', 'Name', 'Location', 'Power?' ]
				)

				@controller.each_vm do |vm|
					if vm.running? 
						tbl << [ 	vm.name, 
								vm.name,
								vm.location, ]
							#	vm.running?]
					end	
				end
				print_line tbl.to_s
			end


	end
	
	#
	# The constructor is called when an instance of the plugin is created.  The
	# framework instance that the plugin is being associated with is passed in
	# the framework parameter.  Plugins should call the parent constructor when
	# inheriting from Msf::Plugin to ensure that the framework attribute on
	# their instance gets set.
	#
	def initialize(framework, opts)
		super

		## Register the commands above
		console_dispatcher = add_console_dispatcher(Ver2labCommandDispatcher)

		@controller = ::Labv2::LabController.new

		## Share the vms
		console_dispatcher.controller = @controller
	end


	#
	# The cleanup routine for plugins gives them a chance to undo any actions
	# they may have done to the framework.  For instance, if a console
	# dispatcher was added, then it should be removed in the cleanup routine.
	#
	def cleanup
		# If we had previously registered a console dispatcher with the console,
		# deregister it now.
		remove_console_dispatcher('Ver2Lab')
	end

	#
	# This method returns a short, friendly name for the plugin.
	#
	def name
		"Ver2Lab"
	end

	#
	# This method returns a brief description of the plugin.  It should be no
	# more than 60 characters, but there are no hard limits.
	#
	def desc
		"Adds the ability to manage VMs"
	end
	
end ## End Class
end ## End Module
