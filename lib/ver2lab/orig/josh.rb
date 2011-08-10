  require 'vm_controller'
  vm_controller = ::Lab::Controllers::VmController.new(YAML.load_file(lab_def)) 
  vm_controller['vm1'].start
  vm_controller['vm1'].snapshot("clean") 
  vm_controller['vm1'].run_command("rm /etc/resolv.conf")
  vm_controller['vm1'].open_uri("http://autopwn:8080")
  vm_controller['vm1'].revert("clean")

