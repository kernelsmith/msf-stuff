#
# by kernelsmith (kernelsmith+\x40+kernelsmith+\.com)
#

require 'msf/core'
require 'rex'
require 'msf/core/post/windows/services'

class Metasploit3 < Msf::Post

	include Msf::Post::WindowsServices

	def initialize(info={})
		super( update_info( info,
				'Name'          => 'test',
				'Description'   => %q{ This module will test windows services methods within a shell},
				'License'       => MSF_LICENSE,
				'Author'        => [ 'kernelsmith'],
				'Version'       => '$Revision: 11663 $',
				'Platform'      => [ 'windows' ],
				'SessionTypes'  => [ 'shell' ]
			))
		register_options(
			[
				OptBool.new("VERBOSE" , [ true, "Verbose output, doesn't do anything ATM", true]),
				OptString.new("QSERVICE" , [true, "Service (keyname) to query", "winmgmt"]),
				OptString.new("NSERVICE" , [true, "New Service (keyname) to create/del", "testes"]),
				OptString.new("MODE" , [true, "Mode to use for startup/create tests", "demand"]),
				OptString.new("DNAME" , [true, "Display name used for create test", "Cool display name"]),
				OptString.new("BINPATH" , [true, "Binary path for create test", "C:\\WINDOWS\\system32\\svchost.exe -k netsvcs"]),
			], self.class)

	end

	def run
		print_status "Running against session #{datastore["SESSION"]}" 

		print_line "*"*60
		print_status "TESTING service_list"
		results = service_list
		print_status "results: #{results.class} #{results.inspect}"

		print_line "*"*60
		print_status "TESTING service_info on servicename: #{datastore["QSERVICE"]}"
		results = service_info(datastore['QSERVICE'])
		print_status "results: #{results.class} #{results.pretty_inspect}"

		print_line "*"*60
		print_status "TESTING service_query_ex on servicename: #{datastore["QSERVICE"]}"
		results = service_query_ex(datastore['QSERVICE'])
		print_status "results: #{results.class} #{results.pretty_inspect}"

		print_line "*"*60
		print_status "TESTING service_query_config on servicename: #{datastore["QSERVICE"]}"
		results = service_query_config(datastore['QSERVICE'])
		print_status "results: #{results.class} #{results.pretty_inspect}"

		print_line "*"*60
		print_status "TESTING service_change_startup on servicename: #{datastore['QSERVICE']} to #{datastore['MODE']}"
		results = service_change_startup(datastore['QSERVICE'],datastore['MODE'])
		print_status "results: #{results.class} #{results.pretty_inspect}"
		print_status "current config of this service #{service_query_config(datastore['QSERVICE']).pretty_inspect}"
		print_status "Setting startup mode back to auto, hope that's what you want"
		results = service_change_startup(datastore['QSERVICE'],"auto")
		print_status "results: #{results.class} #{results.pretty_inspect}"
		print_status "current config of this service #{service_query_config(datastore['QSERVICE']).pretty_inspect}"

		print_line "*"*60
		print_status "TESTING service_create on servicename: #{datastore['NSERVICE']} using\n" +
					"display_name: #{datastore['DNAME']}, executable_on_host: " + "#{datastore['BINPATH']}, and startupmode: #{datastore['MODE']}"
		results = service_create(datastore['NSERVICE'],datastore['DNAME'],datastore['BINPATH'],datastore['MODE'])
		print_status "results: #{results.class} #{results.pretty_inspect}"
		print_status "current state of this service #{service_query_ex(datastore['NSERVICE']).pretty_inspect}"
		print_status "current config of this service #{service_query_config(datastore['QSERVICE']).pretty_inspect}"

		print_line "*"*60
		print_status "TESTING service_start on servicename: #{datastore['NSERVICE']}"
		results = service_start(datastore['NSERVICE'])
		print_status "results: #{results.class} #{results.pretty_inspect}"
		print_status "current state of this service #{service_query_ex(datastore['NSERVICE']).pretty_inspect}"

		print_line "*"*60
		print_status "TESTING service_stop on servicename: #{datastore['NSERVICE']}"
		results = service_stop(datastore['NSERVICE'])
		print_status "results: #{results.class} #{results.pretty_inspect}"
		print_status "current state of this service #{service_query_ex(datastore['NSERVICE']).pretty_inspect}"

		print_line "*"*60
		print_status "TESTING service_delete on servicename: #{datastore['NSERVICE']}"
		results = service_delete(datastore['NSERVICE'])
		print_status "results: #{results.class} #{results.pretty_inspect}"
		print_status "current state of this service #{service_query_ex(datastore['NSERVICE']).pretty_inspect}"
		print_line "*"*60
		print_status "Testing complete."
	end

end