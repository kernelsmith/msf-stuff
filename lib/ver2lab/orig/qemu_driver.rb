require 'vm_driver'

##
## $Id: workstation_driver.rb 12771 2011-05-30 19:11:13Z kernelsmith $
##

module Lab
module Drivers

class QemuDriver < VmDriver

	attr_accessor :type
	attr_accessor :location

	def initialize(vmid, location, credentials=nil)
		@vmid = filter_input(vmid)
		@location = filter_input(location)
		if !File.exist?(@location)
			raise ArgumentError,"Couldn't find: " + @location
		end

		@credentials = credentials

		# TODO - Currently only implemented for the first set
		if @credentials.count > 0
			@vm_user = filter_input(@credentials[0]['user'])
			@vm_pass = filter_input(@credentials[0]['pass'])
		end
	end

	def start
		system_command("qemu -loadvm -name #{@vmid}" + "\"#{@location}\"")
		#-loadvm, -readconfig, -writeconfig
	end

	def stop
		system_command("qemu -system_powerdown" + "\"#{@location}\"")
	end

	def suspend
		system_command("qemu -stop" + "\"#{@location}\"")
	end

	def pause
		system_command("qemu -stop" + "\"#{@location}\"")
	end

	def reset
		system_command("qemu -system_reset" + "\"#{@location}\"")
	end

	def create_snapshot(snapshot)
		# need to suspend first?  May get corrupted 
		snapshot = filter_input(snapshot)
		system_command("qemu-img snapshot -c \"#{snapshot}\" " + "\"#{@location}\" ")
	end

	def revert_snapshot(snapshot)
		snapshot = filter_input(snapshot)
		system_command("qemu-img snapshot -a \"#{snapshot}\" " + "\"#{@location}\" ")
	end

	def delete_snapshot(snapshot)
		snapshot = filter_input(snapshot)
		system_command("qemu-img snapshot -d \"#{snapshot}\" " + "\"#{@location}\" " )
	end

	def run_command(command)
		command = filter_input(command)
		vmrunstr = "vmrun -T ws -gu \"#{@vm_user}\" -gp \"#{@vm_pass} \" " +
				"runProgramInGuest \"#{@location}\" \"#{command}\""
		system_command(vmrunstr)
	end
	
	def copy_from(from, to)
		from = filter_input(from)
		to = filter_input(to)
		vmrunstr = "vmrun -T ws -gu #{@vm_user} -gp #{@vm_pass} copyFileFromGuestToHost" +
				" \"#{@location}\" \"#{from}\" \"#{to}\"" 
		system_command(vmrunstr)
	end

	def copy_to(from, to)
		from = filter_input(from)
		to = filter_input(to)
		vmrunstr = "vmrun -T ws -gu #{@vm_user} -gp #{@vm_pass} copyFileFromHostToGuest" +
				" \"#{@location}\" \"#{from}\" \"#{to}\""  
		system_command(vmrunstr)
	end

	def check_file_exists(file)
		file = filter_input(file)
		vmrunstr = "vmrun -T ws -gu {user} -gp #{@vm_pass} fileExistsInGuest " +
				"\"#{@location}\" \"#{file}\" "
		system_command(vmrunstr)
	end

	def create_directory(directory)
		directory = filter_input(directory)
		vmrunstr = "vmrun -T ws -gu #{@vm_user} -gp #{@vm_pass} createDirectoryInGuest " +
				" \"#{@location}\" \"#{directory}\" "
		system_command(vmrunstr)
	end

	def cleanup

	end

	def running?
		## Get running Vms
		running = `vmrun list`
		running_array = running.split("\n")
		running_array.shift

		running_array.each do |vmx|
			if vmx.to_s == @location.to_s
				return true
			end
		end

		return false
	end

end

end 
end
#-------------------------------------------------------------------------

usage: qemu [options] [disk_image]

'disk_image' is a raw hard image image for IDE hard disk 0

Standard options:
-h or -help     display this help and exit
-version        display version information and exit
-M machine      select emulated machine (-M ? for list)
-cpu cpu        select CPU (-cpu ? for list)
-smp n[,maxcpus=cpus][,cores=cores][,threads=threads][,sockets=sockets]
                set the number of CPUs to 'n' [default=1]
                maxcpus= maximum number of total cpus, including
                  offline CPUs for hotplug etc.
                cores= number of CPU cores on one socket
                threads= number of threads on one CPU core
                sockets= number of discrete sockets in the system
-numa node[,mem=size][,cpus=cpu[-cpu]][,nodeid=node]
-fda/-fdb file  use 'file' as floppy disk 0/1 image
-hda/-hdb file  use 'file' as IDE hard disk 0/1 image
-hdc/-hdd file  use 'file' as IDE hard disk 2/3 image
-cdrom file     use 'file' as IDE cdrom image (cdrom is ide1 master)
-drive [file=file][,if=type][,bus=n][,unit=m][,media=d][,index=i]
       [,cyls=c,heads=h,secs=s[,trans=t]][,snapshot=on|off]
       [,cache=writethrough|writeback|none][,format=f][,serial=s]
       [,addr=A][,id=name][,aio=threads|native]
       [,boot=on|off]
                use 'file' as a drive image
-set group.id.arg=value
                set <arg> parameter for item <id> of type <group>
                i.e. -set drive.$id.file=/path/to/image
-global driver.property=value
                set a global default for a driver property
-mtdblock file  use 'file' as on-board Flash memory image
-sd file        use 'file' as SecureDigital card image
-pflash file    use 'file' as a parallel flash image
-boot [order=drives][,once=drives][,menu=on|off]
                'drives': floppy (a), hard disk (c), CD-ROM (d), network (n)
-snapshot       write to temporary files instead of disk image files
-m megs         set virtual RAM size to megs MB [default=384]
-k language     use keyboard layout (for example 'fr' for French)
-audio-help     print list of audio drivers and their options
-soundhw c1,... enable audio support
                and only specified sound cards (comma separated list)
                use -soundhw ? to get the list of supported cards
                use -soundhw all to enable all of them
-usb            enable the USB driver (will be the default soon)
-usbdevice name add the host or guest USB device 'name'
-device driver[,options]  add device
-name string1[,process=string2]    set the name of the guest
            string1 sets the window title and string2 the process name (on Linux)
-uuid %08x-%04x-%04x-%04x-%012x
                specify machine UUID

Display options:
-nographic      disable graphical output and redirect serial I/Os to console
-curses         use a curses/ncurses interface instead of SDL
-no-frame       open SDL window without a frame and window decorations
-alt-grab       use Ctrl-Alt-Shift to grab mouse (instead of Ctrl-Alt)
-ctrl-grab       use Right-Ctrl to grab mouse (instead of Ctrl-Alt)
-no-quit        disable SDL window close capability
-sdl            enable SDL
-portrait       rotate graphical output 90 deg left (only PXA LCD)
-vga [std|cirrus|vmware|xenfb|none]
                select video card type
-full-screen    start in full screen
-vnc display    start a VNC server on display

1 target only:
-win2k-hack     use it when installing Windows 2000 to avoid a disk full bug
-no-fd-bootchk  disable boot signature checking for floppy disks
-no-acpi        disable ACPI
-no-hpet        disable HPET
-balloon none   disable balloon device
-balloon virtio[,addr=str]
                enable virtio balloon device (default)
-acpitable [sig=str][,rev=n][,oem_id=str][,oem_table_id=str][,oem_rev=n][,asl_compiler_id=str][,asl_compiler_rev=n][,data=file1[:file2]...]
                ACPI table description
-smbios file=binary
                Load SMBIOS entry from binary file
-smbios type=0[,vendor=str][,version=str][,date=str][,release=%d.%d]
                Specify SMBIOS type 0 fields
-smbios type=1[,manufacturer=str][,product=str][,version=str][,serial=str]
              [,uuid=uuid][,sku=str][,family=str]
                Specify SMBIOS type 1 fields

Network options:
-net nic[,vlan=n][,macaddr=mac][,model=type][,name=str][,addr=str][,vectors=v]
                create a new Network Interface Card and connect it to VLAN 'n'
-net user[,vlan=n][,name=str][,net=addr[/mask]][,host=addr][,restrict=y|n]
         [,hostname=host][,dhcpstart=addr][,dns=addr][,tftp=dir][,bootfile=f]
         [,hostfwd=rule][,guestfwd=rule][,smb=dir[,smbserver=addr]]
                connect the user mode network stack to VLAN 'n', configure its
                DHCP server and enabled optional services
-net tap[,vlan=n][,name=str][,fd=h][,ifname=name][,script=file][,downscript=dfile][,sndbuf=nbytes][,vnet_hdr=on|off]
                connect the host TAP network interface to VLAN 'n' and use the
                network scripts 'file' (default=/etc/qemu-ifup)
                and 'dfile' (default=/etc/qemu-ifdown);
                use '[down]script=no' to disable script execution;
                use 'fd=h' to connect to an already opened TAP interface
                use 'sndbuf=nbytes' to limit the size of the send buffer; the
                default of 'sndbuf=1048576' can be disabled using 'sndbuf=0'
                use vnet_hdr=off to avoid enabling the IFF_VNET_HDR tap flag; use
                vnet_hdr=on to make the lack of IFF_VNET_HDR support an error condition
-net socket[,vlan=n][,name=str][,fd=h][,listen=[host]:port][,connect=host:port]
                connect the vlan 'n' to another VLAN using a socket connection
-net socket[,vlan=n][,name=str][,fd=h][,mcast=maddr:port]
                connect the vlan 'n' to multicast maddr and port
-net dump[,vlan=n][,file=f][,len=n]
                dump traffic on vlan 'n' to file 'f' (max n bytes per packet)
-net none       use it alone to have zero network devices; if no -net option
                is provided, the default is '-net nic -net user'
-netdev [user|tap|socket],id=str[,option][,option][,...]

Character device options:
-chardev null,id=id
-chardev socket,id=id[,host=host],port=host[,to=to][,ipv4][,ipv6][,nodelay]
         [,server][,nowait][,telnet] (tcp)
-chardev socket,id=id,path=path[,server][,nowait][,telnet] (unix)
-chardev udp,id=id[,host=host],port=port[,localaddr=localaddr]
         [,localport=localport][,ipv4][,ipv6]
-chardev msmouse,id=id
-chardev vc,id=id[[,width=width][,height=height]][[,cols=cols][,rows=rows]]
-chardev file,id=id,path=path
-chardev pipe,id=id,path=path
-chardev pty,id=id
-chardev stdio,id=id
-chardev tty,id=id,path=path
-chardev parport,id=id,path=path

Bluetooth(R) options:
-bt hci,null    dumb bluetooth HCI - doesn't respond to commands
-bt hci,host[:id]
                use host's HCI with the given name
-bt hci[,vlan=n]
                emulate a standard HCI in virtual scatternet 'n'
-bt vhci[,vlan=n]
                add host computer to virtual scatternet 'n' using VHCI
-bt device:dev[,vlan=n]
                emulate a bluetooth device 'dev' in scatternet 'n'

Linux/Multiboot boot specific:
-kernel bzImage use 'bzImage' as kernel image
-append cmdline use 'cmdline' as kernel command line
-initrd file    use 'file' as initial ram disk

Debug/Expert options:
-serial dev     redirect the serial port to char device 'dev'
-parallel dev   redirect the parallel port to char device 'dev'
-monitor dev    redirect the monitor to char device 'dev'
-qmp dev        like -monitor but opens in 'control' mode.
-mon chardev=[name][,mode=readline|control][,default]
-pidfile file   write PID to 'file'
-singlestep   always run in singlestep mode
-S              freeze CPU at startup (use 'c' to start execution)
-gdb dev        wait for gdb connection on 'dev'
-s              shorthand for -gdb tcp::1234
-d item1,...    output log to /tmp/qemu.log (use -d ? for a list of log items)
-hdachs c,h,s[,t]
                force hard disk 0 physical geometry and the optional BIOS
                translation (t=none or lba) (usually qemu can guess them)
-L path         set the directory for the BIOS, VGA BIOS and keymaps
-bios file      set the filename for the BIOS
-enable-kvm     enable KVM full virtualization support
-no-reboot      exit instead of rebooting
-no-shutdown    stop before shutdown
-loadvm [tag|id]
                start right away with a saved state (loadvm in monitor)
-daemonize      daemonize QEMU after initializing
-option-rom rom load a file, rom, into the option ROM space
-clock          force the use of the given methods for timer alarm.
                To see what timers are available use -clock ?
-rtc [base=utc|localtime|date][,clock=host|vm][,driftfix=none|slew]
                set the RTC base and clock, enable drift fix for clock ticks
-icount [N|auto]
                enable virtual instruction counter with 2^N clock ticks per
                instruction
-watchdog i6300esb|ib700
                enable virtual hardware watchdog [default=none]
-watchdog-action reset|shutdown|poweroff|pause|debug|none
                action when watchdog fires [default=reset]
-echr chr       set terminal escape character instead of ctrl-a
-virtioconsole c
                set virtio console
-show-cursor    show cursor
-tb-size n      set TB size
-incoming p     prepare for incoming migration, listen on port p
-nodefaults     don't create default devices.
-chroot dir     Chroot to dir just before starting the VM.
-runas user     Change to user id user just before starting the VM.
-readconfig <file>
-writeconfig <file>
                read/write config file
-no-kvm         disable KVM hardware virtualization
-no-kvm-irqchip disable KVM kernel mode PIC/IOAPIC/LAPIC
-no-kvm-pit     disable KVM kernel mode PIT
-no-kvm-pit-reinjection disable KVM kernel mode PIT interrupt reinjection
-pcidevice host=bus:dev.func[,dma=none][,name=string]
                expose a PCI device to the guest OS.
                dma=none: don't perform any dma translations (default is to use an iommu)
                'string' is used in log output.
-enable-nesting enable support for running a VM inside the VM (AMD only)
-nvram FILE          provide ia64 nvram contents
-tdf                 enable guest time drift compensation
-kvm-shadow-memory MEGABYTES
                     allocate MEGABYTES for kvm mmu shadowing
-mem-path FILE       provide backing storage for guest RAM
-mem-prealloc        preallocate guest memory (use with -mempath)
usage: qemu-img command [command options]
QEMU disk image utility

Command syntax:
  check [-f fmt] filename
  create [-f fmt] [-o options] filename [size]
  commit [-f fmt] filename
  convert [-c] [-f fmt] [-O output_fmt] [-o options] filename [filename2 [...]] output_filename
  info [-f fmt] filename
  snapshot [-l | -a snapshot | -c snapshot | -d snapshot] filename

Command parameters:
  'filename' is a disk image filename
  'fmt' is the disk image format. It is guessed automatically in most cases
  'size' is the disk image size in bytes. Optional suffixes
    'k' or 'K' (kilobyte, 1024), 'M' (megabyte, 1024k), 'G' (gigabyte, 1024M)
    and T (terabyte, 1024G) are supported. 'b' is ignored.
  'output_filename' is the destination disk image filename
  'output_fmt' is the destination format
  'options' is a comma separated list of format specific options in a
    name=value format. Use -o ? for an overview of the options supported by the
    used format
  '-c' indicates that target image must be compressed (qcow format only)
  '-h' with or without a command shows this help and lists the supported formats

Parameters to snapshot subcommand:
  'snapshot' is the name of the snapshot to create, apply or delete
  '-a' applies a snapshot (revert disk to saved state)
  '-c' creates a snapshot
  '-d' deletes a snapshot
  '-l' lists all snapshots in the given image

Supported formats: cow qcow vdi vmdk cloop dmg bochs vpc vvfat qcow2 parallels nbd host_cdrom host_floppy host_device raw tftp ftps ftp https http



