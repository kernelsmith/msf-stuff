#
# by kernelsmith (kernelsmith+\x40+kernelsmith+\.com)
#

require 'msf/core'
require 'rex'
require 'msf/core/post/windows/registry'

class Metasploit3 < Msf::Post

	include Msf::Post::Registry

	def initialize(info={})
		super( update_info( info,
				'Name'          => 'test',
				'Description'   => %q{ This module will test registry methods within a shell},
				'License'       => MSF_LICENSE,
				'Author'        => [ 'kernelsmith'],
				'Version'       => '$Revision: 11663 $',
				'Platform'      => [ 'windows' ],
				'SessionTypes'  => [ 'shell' ]
			))
		register_options(
		[
				OptBool.new("VERBOSE" , [ true, "Verbose output, doesn't do anything ATM", true]),
				OptString.new("KEY" , [true, "Registry key to test", "HKLM\\Software\\Microsoft\\Active Setup"]),
				OptString.new("VALUE" , [true, "Registry value to test", "DisableRepair"]),
			], self.class)

	end

	def run
		print_status("Running against session #{datastore["SESSION"]}")
		print_line "*"*60
		print_status "TESTING get_val_info for key:#{datastore['KEY']}, val:#{datastore['VALUE']}"
		results = registry_getvalinfo(datastore['KEY'],datastore['VALUE'])
		print_status ("results: #{results.class} #{results.pretty_inspect}")

		print_line "*"*60
		print_status "TESTING get_val_data for key:#{datastore['KEY']}, val:#{datastore['VALUE']}"
		results = registry_getvaldata(datastore['KEY'],datastore['VALUE'])
		print_status ("results: #{results.class} #{results.pretty_inspect}")

		print_line "*"*60
		print_status "TESTING create_key for key:#{datastore['KEY']}\\test"
		results = registry_createkey("#{datastore['KEY']}\\test")
		print_status ("results: #{results.class} #{results.pretty_inspect}")

		print_line "*"*60
		print_status "TESTING set_val_data for key:#{datastore['KEY']}\\test, val:test, data:test, type:REG_SZ"
		results = registry_setvaldata("#{datastore['KEY']}\\test","test","test","REG_SZ")
		print_status ("results: #{results.class} #{results.pretty_inspect}")

		print_line "*"*60
		print_status "Getting val_info for newly created key:#{datastore['KEY']}\\test, val:test"
		results = registry_getvalinfo("#{datastore['KEY']}\\test","test")
		print_status ("results: #{results.class} #{results.pretty_inspect}")

		print_line "*"*60
		print_status "TESTING del_val_data for key:#{datastore['KEY']}\\test, val:test"
		results = registry_deleteval("#{datastore['KEY']}\\test","test")
		print_status ("results: #{results.class} #{results.pretty_inspect}")

		print_line "*"*60
		print_status "TESTING del_key"
		results = registry_delkey("#{datastore['KEY']}\\test")
		print_status ("results: #{results.class} #{results.pretty_inspect}")

		print_line "*"*60
		print_status "Getting val_info for deleted key:#{datastore['KEY']}\\test, val:test " +
					"this should fail gracefully, returning nils"
		results = registry_getvalinfo("#{datastore['KEY']}\\test","test")
		print_status ("results: #{results.class} #{results.pretty_inspect}")

		print_line "*"*60
		print_status "TESTING enum_keys"
		results = registry_enumkeys(datastore['KEY'])
		print_status ("results: #{results.class} #{results.pretty_inspect}")

		print_line "*"*60
		print_status "TESTING enum_vals"
		results = registry_enumvals(datastore['KEY'])
		print_status ("results: #{results.class} #{results.pretty_inspect}")
		print_line "*"*60
		print_status "Testing complete."
	end

end