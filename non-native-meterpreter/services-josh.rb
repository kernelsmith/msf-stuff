
module Msf
class Post

module WindowsServices

	$blab = false 

	#
	# List all Windows Services present.  Returns an Array containing the names
	# of the services.
	#
	def service_list
		#SERVICE_NAME: Winmgmt
		#DISPLAY_NAME: Windows Management Instrumentation
        	# <...etc...>
		#
		services = []
		begin
			cmd = "cmd.exe /c sc query type= service"
			print_status "Running command: #{cmd}" if $blab
			results = session.shell_command_token_win32(cmd)
			print_status "raw results are:\n#{results}" if $blab
			if results =~ /SERVICE_NAME:/
				results.each_line do |line| 
					if line =~ /SERVICE_NAME:/
						h = win_parse_results(line)
						print_status "parse hash is #{h.inspect}" if $blab
						services << h['SERVICE_NAME']
					end 
				end
			elsif results =~ /(^Error:.*|FAILED.*:)/
				error_hash = win_parse_error(results)
			elsif results =~ /SYNTAX:/
				# Syntax error
				error_hash = win_parse_error("ERROR:Syntax Error, cmd was #{cmd}")
			else
				error_hash = win_parse_error("ERROR:Unknown error running sc.exe")
			end
		end
		return services
	end
	#
	# Get Windows Service config information. 
	#
	# Info returned stuffed into a hash with all info that sc.exe qc <service_name> will cough up
	# Service name is case sensitive.
	# Hash keys match the keys returned by sc.exe qc <service_name>
	# e.g returns {
	# "SERVICE_NAME" => "winmgmt",
	# "TYPE" => "20 WIN32_SHARE_PROCESS",
	# "START_TYPE" => "2 AUTO_START",
	# <...>
	# "DEPENDENCIES" => "RPCSS,OTHER",
	# "SERVICE_START_NAME" => "LocalSystem" }
	# etc.  see sc qc /? for more info
	#
	def service_query_config(name)
		service = {}
		begin
			cmd = "cmd.exe /c sc qc #{name.chomp}"
			print_status "Running command: #{cmd}" if $blab
			results = session.shell_command_token_win32(cmd)
			#print_status "raw results are:\n#{results}" if $blab
			if results =~ /SUCCESS/
				#[SC] QueryServiceConfig SUCCESS
				#
				#SERVICE_NAME: winmgmt
				#        TYPE               : 20  WIN32_SHARE_PROCESS
				#        START_TYPE         : 2   AUTO_START
				#        ERROR_CONTROL      : 0   IGNORE
				#        BINARY_PATH_NAME   : C:\Windows\system32\svchost.exe -k netsvcs
				#        <...>
				#        DISPLAY_NAME       : Windows Management Instrumentation
				#        DEPENDENCIES       : RPCSS
				#        		    : OTHER
				#        SERVICE_START_NAME : LocalSystem
				# 
				service = win_parse_results(results)
			elsif results =~ /(^Error:.*|FAILED.*:)/
				error_hash = win_parse_error(results)
			elsif results =~ /SYNTAX:/
				# Syntax error
				error_hash = win_parse_error("ERROR:Syntax Error, cmd was #{cmd}")
			else
				error_hash = win_parse_error("ERROR:Unknown error running sc.exe qc")
			end
		end
		return service
	end
	
	#
	# Get Windows Service information. 
	#
	# Information returned in a hash with display name, startup mode and
	# command executed by the service. Service name is case sensitive.  Hash
	# keys are Name, Start, Command and Credentials.  Here for compatibility with meterp version
	def service_info(name)
		service = {}
		begin
			h = service_query_config(name)
			service['Name'] = h['SERVICE_NAME']
			service["Startup"] = normalize_mode(h['START_TYPE'])
			service['Command'] = h['BINARY_PATH_NAME']
			service['Credentials'] = h['SERVICE_START_NAME']
		end
		return service
	end

	#
	# Get Extended Windows Service information. 
	#
	# Info returned stuffed into a hash with all info that sc.exe queryex <service_name> will cough up
	# Service name is case sensitive.
	# Hash keys match the keys returned by sc.exe qc <service_name>
	# e.g returns {
	# "SERVICE_NAME" => "winmgmt",
	# "TYPE" => "20 WIN32_SHARE_PROCESS",
	# "STATE" => "4 RUNNING,STOPPABLE,PAUSABLE,ACCEPTS_SHUTDOWN",
	# <...>
	# "PID" = > "1088",
	# "FLAGS" => nil}
	# etc.  see sc queryex /? for more info
	#
	def service_query_ex(name)
		service = {}
		begin
			cmd = "cmd.exe /c sc queryex #{name.chomp}"
			print_status "Running command: #{cmd}" if $blab
			results = session.shell_command_token_win32(cmd)
			#print_status "raw results are:\n#{results}" if $blab
			if results =~ /SERVICE_NAME/ # NOTE: you can't use /SUCCESS/ here
				#SERVICE_NAME: winmgmt
				#        TYPE               : 20  WIN32_SHARE_PROCESS
				#        STATE              : 4  RUNNING
				#                                (STOPPABLE,PAUSABLE,ACCEPTS_SHUTDOWN)
				#        WIN32_EXIT_CODE    : 0  (0x0)
				#        SERVICE_EXIT_CODE  : 0  (0x0)
				#        CHECKPOINT         : 0x0
				#        WAIT_HINT          : 0x0
				#        PID                : 1088
				#        FLAGS              :
				# 
				# need to test to ensure all results can be parsed this way
				service = win_parse_results(results)
			elsif results =~ /(^Error:.*|FAILED.*:)/
				error_hash = win_parse_error(results)
			elsif results =~ /SYNTAX:/
				# Syntax error
				error_hash = win_parse_error("ERROR:Syntax Error, cmd was #{cmd}")
			else
				error_hash = win_parse_error("ERROR:Unknown error running sc.exe")
			end
		end
		return service
	end
	
	#
	# Get Windows Service state only. 
	#
	# returns a string with state info such as "4 RUNNING,STOPPABLE,PAUSABLE,ACCEPTS_SHUTDOWN"
	# could normalize it to just "RUNNING" if you want
	#
	
	def service_query_state(name)
		state = ""
		begin
			h = service_query_ex(name)
			state = h["STATE"]
		end
		return state
	end

	#
	# Changes a given service startup mode, name and mode must be provided.
	#
	# Mode is an int or string with either 2/auto, 3/manual or 4/disable for the
	# corresponding setting. The name of the service is case sensitive.
	#
	#sc <server> config [service name] start= <boot|system|auto|demand|disabled|delayed-auto>
	def service_change_startup(name,mode)
		boo = false
		begin
			mode = normalize_mode(mode)
			cmd = "cmd.exe /c sc config #{name} start= #{mode}"
			print_status "Running command: #{cmd}" if $blab
			results = session.shell_command_token_win32(cmd)
			print_status "raw results are:\n#{results}" if $blab
			if results =~ /SUCCESS/
				boo = true
			elsif results =~ /(^Error:.*|FAILED.*:)/
				error_hash = win_parse_error(results)
				if error_hash['ERRVAL'] == 1056
				#	inty = 1
				elsif error_hash['ERRVAL'] == 1058
				#	inty = 2
				end
			elsif results =~ /SYNTAX:/
				# Syntax error
				error_hash = win_parse_error("ERROR:Syntax Error, cmd was #{cmd}")
			else
				error_hash = win_parse_error("ERROR:Unknown error running sc.exe")
			end
		end
		return boo
	end

	#
	# Create a service that runs it's own process.
	#
	# It takes as values the service name as string, the display name as
	# string, the path of the executable on the host that will execute at
	# startup as string and the startup type as an int or string of 2/Auto,
	# 3/Manual, or 4/disable, default is Auto.
	# this should be converted to take a hash so a variable number of options can be provided
	#
	def service_create(name, display_name = "Server Service", executable_on_host = "", mode = "auto")
		#  sc create [service name] [binPath= ] <option1> <option2>...
		boo = false
		begin
			mode = normalize_mode(mode)
			cmd = "cmd.exe /c sc create #{name} binPath= \"#{executable_on_host}\" " +
				"start= #{mode} DisplayName= \"#{display_name}\""
			print_status "Running command: #{cmd}" if $blab
			results = session.shell_command_token_win32(cmd)
			print_status "raw results are:\n#{results}" if $blab
			if results =~ /SUCCESS/
				inty = 0
			elsif results =~ /(^Error:.*|FAILED.*:)/
				error_hash = win_parse_error(results)
				if error_hash['ERRVAL'] == 1056
				#	inty = 1
				elsif error_hash['ERRVAL'] == 1058
				#	inty = 2
				end
			elsif results =~ /SYNTAX:/
				# Syntax error
				error_hash = win_parse_error("ERROR:Syntax Error, cmd was #{cmd}")
			else
				error_hash = win_parse_error("ERROR:Unknown error running sc.exe") 
			end

		end
	end

	#
	# Start a service.
	#
	# Returns 0 if service started, 1 if service is already started and 2 if
	# service is disabled.
	#
	def service_start(name)
		boo = false
		begin
			cmd = "cmd.exe /c sc start #{name}"
			print_status "Running command: #{cmd}" if $blab
			results = session.shell_command_token_win32(cmd)
			print_status "raw results are:\n#{results}" if $blab
			if results =~ /(SUCCESS|START_PENDING)/
				boo = true
				#inty = 0
			elsif results =~ /(^Error:.*|FAILED.*:)/
				error_hash = win_parse_error(results)
				if error_hash['ERRVAL'] == 1056
				#	inty = 1
				elsif error_hash['ERRVAL'] == 1058
				#	inty = 2
				end
			elsif results =~ /SYNTAX:/
				# Syntax error
				error_hash = win_parse_error("ERROR:Syntax Error, cmd was #{cmd}")
			else
				error_hash = win_parse_error("ERROR:Unknown error running sc.exe")  
			end
		end
		return boo
	end

	#
	# Stop a service.
	#
	# Returns 0 if service is stopped successfully, 1 if service is already
	# stopped or disabled and 2 if the service can not be stopped.
	#
	def service_stop(name)
		boo = false
		begin
			cmd = "cmd.exe /c sc stop #{name}"
			print_status "Running command: #{cmd}" if $blab
			results = session.shell_command_token_win32(cmd)
			print_status "raw results are:\n#{results}" if $blab
			if results =~ /SUCCESS/
				inty = 0
			elsif results =~ /(^Error:.*|FAILED.*:)/
				error_hash = win_parse_error(results)
				if error_hash['ERRVAL'] == 1056
				#	inty = 1
				elsif error_hash['ERRVAL'] == 1058
				#	inty = 2
				end
			elsif results =~ /SYNTAX:/
				# Syntax error
				error_hash = win_parse_error("ERROR:Syntax Error, cmd was #{cmd}")
			else
				error_hash = win_parse_error("ERROR:Unknown error running sc.exe")  
			end
		end
		return boo
	end

	#
	# Delete a service
	#
	def service_delete(name)
		boo = false
		begin
			cmd = "cmd.exe /c sc delete #{name}"
			print_status "Running command: #{cmd}" if $blab
			results = session.shell_command_token_win32(cmd)
			print_status "raw results are:\n#{results}" if $blab
			if results =~ /SUCCESS/
				boo = true
			elsif match_arr = /^Error:.*|FAILED.*:/.match(results)
				error_hash = win_parse_error(results)
				if error_hash['ERRVAL'] == 1056
				#	inty = 1
				elsif error_hash['ERRVAL'] == 1058
				#	inty = 2
				end
			elsif results =~ /SYNTAX:/
				# Syntax error
				error_hash = win_parse_error("ERROR:Syntax Error, cmd was #{cmd}")
			else
				error_hash = win_parse_error("ERROR:Unknown error running sc.exe")  
			end
		end
		return boo

	end

	protected
	#
	# parses output of some windows CLI commands and returns hash with the keys/vals detected
	# 	if the item has multiple values, they will all be returned in the val separated by commas
	#
		# Example would return:
		# {
		#	'SERVICE_NAME'	=> "dumbservice",
		#	'DISPLAY_NAME'	=> "KernelSmith Dumb Service - User-mod",
		#	'STATE'		=> "4  RUNNING",
		#	'START_TYPE'	=> "2   AUTO_START",
		#	'BINARY_PATH_NAME' => "C:\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted",
		#	'DEPENDENCIES'	=> "PlugPlay,DumberService"
		#	<...etc...>
		# }
	def win_parse_results(str)
		#
		#--- sc.exe example (somewhat contrived)
		#SERVICE_NAME: dumbservice
		#DISPLAY_NAME: KernelSmith Dumb Service - User-mode
	        #TYPE               : 20  WIN32_SHARE_PROCESS
	        #STATE              : 4  RUNNING
		#                        (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
	        #START_TYPE         : 2   AUTO_START
	        #BINARY_PATH_NAME   : C:\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted
		#DEPENDENCIES       : PlugPlay
		#                   : DumberService
		#SERVICE_START_NAME : LocalSystem
	        #PID                : 368
	        #FLAGS              :
		#--- END sc.exe example
		#
		print_status "Parsing results string: #{str}" if $blab
		tip = false
		hashish = Hash.new(nil)
		lastkey = nil
		str.each_line do |line|
			line.chomp! 
			line.gsub!("\t",' ') # lose any tabs
			if (tip == true && line =~ /^ + :/)
				# then this is probably a continuation of the previous, let's append to previous
				# NOTE:  this will NOT pickup the (NOT_STOPPABLE, NOT_PAUSABLE), see next, but it
				# 	 will pickup when there's multiple dependencies
				print_status "Caught line continuation with :" if $blab
				arr = line.scan(/\w+/)
				val = arr.join(',') # join with commas, tho there is probably only one item in arr
				hashish[lastkey] << ",#{val}" # append to old val with preceding ','
				# if that's confusing, maybe:  hashish[lastkey] = "#{hashish[lastkey]},#{val}"
				tip = false
			elsif (tip == true && line =~ /^ + \(/)
				# then this is probably a continuation of the previous, let's append to previous
				# NOTE:  this WILL pickup (NOT_STOPPABLE, NOT_PAUSABLE) etc
				print_status "Caught line continuation with (" if $blab
				arr = line.scan(/\w+/) # put each "word" into an array
				val = arr.join(',') # join back together with commas in case comma wasn't the sep
				hashish[lastkey] << ",#{val}" # append to old val with preceding ','
				# if that's confusing, maybe:  hashish[lastkey] = "#{hashish[lastkey]},#{val}"
				tip = false			
			elsif line =~ /^ *[A-Z]+[_]*[A-Z]+.*:/
				tip = true
				arr = line.split(':')
				#print_status "Array split is #{arr.inspect}" if $blab
				k = arr[0].strip
				# grab all remaining fields for hash val in case ':' present in val
				v = arr[1..-1].join(':').strip
				# now add this entry to the hash
				#print_status "Adding the following hash entry: #{k} => #{v}" if $blab
				hashish[k] = v 
				lastkey = k
			end
		end
		return hashish
	end
	
	#
	# parses error output of some windows CLI commands and returns hash with the keys/vals detected
	#  always returns hash as follow but ERRVAL only comes back from sc.exe using 'FAILED' keyword
		# Example, returns:
		# {
		#	'ERROR'		=> "The specified service does not exist as an installed service",
		#	'ERRVAL'	=> 1060
		# }
		# Note, most of the time the ERRVAL will be nil, it's not usually provided
	def win_parse_error(str)
		#--- sc.exe error example
		#[SC] EnumQueryServicesStatus:OpenService FAILED 1060:
		#
		#The specified service does not exist as an installed service.
		#--- END sc.exe error example
		#
		#--- reg.exe error example
		#ERROR: Invalid key name.
		#Type "REG QUERY /?" for usage.
		#--- END reg.exe error example
		#['ERROR'] => "INVALID KEY NAME."
		#['ERRVAL'] => nil
		hashish = {
				'ERROR' => "Unknown Error",
				'ERRVAL' => nil
			  }
		if ma = /^error:.*/i.match(str) # if line starts with Error: just pass to regular parser
			hashish.merge!(win_parse_results(ma[0].upcase)) #upcase required to satisfy regular parser
			# merge results.  Results from win_parse_results will override any duplicates in hashish
		elsif ma = /FAILED +[0-9]+/.match(str) # look for 'FAILED ' followed by some numbers
			print_status "Found FAILED, ma is #{ma.inspect}" if $blab
			sa = ma[0].split(' ')
			print_status "sa is #{sa.inspect}" if $blab
			hashish['ERRVAL'] = sa[1].chomp.to_i
			#above intended to capture the numbers after the word 'FAILED' as ['ERRVAL']
			ma = /^[^\[\n].+/.match(str)
			print_status "ma is #{ma.inspect}" if $blab
			hashish['ERROR'] = ma[0].chomp.strip
			#above intended to capture first non-empty line not starting with '[' or \n into ['ERROR']
		else
			# do nothing, defaults are good
		end
		print_error "Error hash:  #{hashish.inspect}" if $blab
		print_error "This error hash is optionally available:  #{hashish.pretty_inspect}"
		return hashish
	end
	
	#
	# Ensures mode is what sc.exe wants to see, e.g. takes 2 or "AUTO_START" etc & returns "auto"  
	#
	def normalize_mode(mode)
		mode = mode.to_s # someone could theoretically pass me a 2 instead of "2"
		# accepted boot|system|auto|demand|disabled
		if mode =~ /(0|BOOT)/i
			mode = "boot"
		elsif mode =~ /(1|SYSTEM)/i
			mode = "system"
		elsif mode =~ /(2|AUTO)/i
			mode = "auto"
		elsif mode =~ /(3|DEMAND|MANUAL)/i
			mode = "demand"
		elsif mode =~ /(4|DISABLED)/i
			mode = "disabled"
		end			
	end

end

end
end
