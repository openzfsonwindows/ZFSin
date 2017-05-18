
# To setup a development environment for compiling ZFS.


Download free development Windows 10 image from Microsoft.

https://developer.microsoft.com/en-us/windows/downloads/virtual-machines

and create two VMs.

* Host (running Visual Studio and Kernel Debugger)
* Target (runs the compiled kernel module)

It is recommended that the VMs are placed on static IP, as they
can change IP with all the crashes, and you have to configure the remote kernel development again.

Go download the Windows Driver Kit 10

https://developer.microsoft.com/en-us/windows/hardware/windows-driver-kit

and install on both VMs.


On Target VM, complete the guide specified here, under
section "Prepare the target computer for provisioning".

https://msdn.microsoft.com/windows/hardware/drivers/gettingstarted/provision-a-target-computer-wdk-8-1?f=255&MSPPError=-2147217396

Which mostly entails running:

C:\Program Files (x86)\Windows Kits\10\Remote\x64\WDK Test Target Setup x64-x64_en-us.msi

* reboot Target VM


On the Host VM, continue the guide to configure Visual Studio 2015.

* Load Visual Studio 2015, there is no need to load the project yet.
* Menu > Driver > Test > Configure Devices
* Click "Add New Device"
* In "Display name:" enter "Target"
* In "Device type:" leave as "Computer"
* In "Network host name:" enter IP of Target VM, for me "172.16.248.103"
* Provisioning options: o Provision device and choose debugger settings.
* Click "Next >"

It now confirms that it talked to the Target, and note here that
"Host IP" it that of the Host VM, for me, "172.16.248.102", and not to be confused by the Target IP entered on previous screen.

* Click "Next >"

Watch and wait as remote items are installed on the Target VM. It
will most likely reboot the Target VM as well.

I've had dialog boxes pop up and I agree to installation, but I am not sure they are supposed to. They probably shouldn't, it would seem it failed
to put WDKRemoteUser in Administators group. If that happens, use "lusrmgr.msc" to correct it.

The task "Creating system restore point" will most likely fail and that is acceptable, however, if other tasks fail, you may need to retry until they work.

At the end of the run, the output window offers a link to the full log, which is worth reading if you encounter issues.

When things fail, I start a CMD prompt as Administrator, and paste in the commands that fail, from the log file. It would be nice if this process just worked though.

If your version of .NET newer, just move along.

The Target VM should reboot, and login as "WDKRemoteUser".



On Host VM with Visual Studio 2015, you may need to download the
GitHub extension if you intend to be part of development environment.

https://visualstudio.github.com/


---


Host and Target VMs are now configured.

* Load ZFSin solution
* Menu > Debug > ZFSin Properties
* Configuration Properties > Debugging
"Debugging tools for Windows - Kernel Debugger"
Remote Computer Name: Target

* Configuration Properties > Driver Install > Deployment
Target Device Name: Target
[Tick] Remove previous driver versions
O Hardware ID Driver Update
Root\ZFSin


To receive the Debug Prints on Host, you need to move

contrib/DebugPrints.reg

to the Target VM, and run it. Or you can run DbgView on the
Target VM to see the prints on that VM.



Run the compiled Target

* Compile solution
* Menu > Debug > Start Debugging (F5)

wait a while, for VS15 to deplay the .sys file on Target and start it.





Target VM optionals.

If you find it frustrating to do development work when Windows Defender or
Windows Updates run, you can disable those in gpedit.msc

* Computer Configuration > Administrative Templates >
     Windows Components >
	 Windows Defender
	 Windows Updates


---

# Milestones


  ✓ Compile SPL sources
  *  Godzillion warnings yet to be addressed

  ✓ Port SPL sources, atomics, mutex, kmem, condvars
  *  C11 _Atomics in kmem not yet handled

  ✓ Compile ZFS sources, stubbing out code as needed

  ✓ Include kernel zlib library

  ✓ Load and Unload SPL and ZFS code

  ✓ Port kernel `zfs_ioctl.c` to accept ioctls from userland

  ✓ Compile userland libspl, libzpool, libzfs, ...

  ✓ Include pthread wrapper library
  *  Replaced with thin pthread.h file

  ✓ Include userland zlib library

  ✓ Compile cmd/zpool

  ✓ Port functions in libzpool, libzfs. Iterate disks, ioctl

  ✓ Test ioctl from zpool to talk to kernel

  ✓ Port kernel `vdev_disk.c` / `vdev_file.c` to issue IO

  ✓ Port over cmd/zfs

  ✓ Add ioctl calls to MOUNT and create Volume to attach

  ⃝ Add ioctl calls to UNMOUNT and detach and delete Volume

  ⃝ Port kernel `zfs_vnops.c` / `zfs_vnops_windows.c`
  *  Implemented: open/read/write/close/mkdir/rmdir/create

  ⃝ Correct file information (dates, size, etc)


---

# Design issues that need addressing.

* Windows do not handle EFI labels, for now they are parsed with
libefi, and we send offset and size with the filename, that both
libzfs and kernel will parse out and use. This works for a proof
of concept.

Possibly a more proper solution would be to write a thin virtual
hard disk driver, which reads the EFI label and present just the
partitions.

* vdev_disk.c spawns a thread to get around that IoCompletionRoutine
is called in a different context, to sleep until signalled. Is there
a better way to do async in Windows?

* ThreadId should be checked, using PsGetCurrentThreadId() but
it makes zio_taskq_member(taskq_member()) crash. Investigate.

* Functions in posix.c need sustenance.
