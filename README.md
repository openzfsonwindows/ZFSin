
# To setup a development environment for compiling ZFS.


Download free development Windows 10 image from Microsoft.

https://developer.microsoft.com/en-us/windows/downloads/virtual-machines

and create two VMs.

The newer VM images comes with Visual Studio 2017, but this is
currently not compatible with Kernel Development. At the moment, the
correct version to use is Visual Studio 2015 update 3. You can
download and install it for free. But it can be a challenge to find as
Microsoft hides it well. They also put VCredist 2008, 2012, 2013 and
2017 on there but skipped 2015 for some reason. They dropped the ball
that day. You will have to use Add/Remove Programs to uninstall 2017
version before you can install 2015.

* Host (running Visual Studio and Kernel Debugger)
* Target (runs the compiled kernel module)

It is recommended that the VMs are placed on static IP, as they can
change IP with all the crashes, and you have to configure the remote
kernel development again.

Go download the Windows Driver Kit 10

https://developer.microsoft.com/en-us/windows/hardware/windows-driver-kit

and install on both VMs. You will need both the SDK and WDK.


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
"Host IP" it that of the Host VM, for me, "172.16.248.102", and not to
be confused by the Target IP entered on previous screen.

* Click "Next >"

Watch and wait as remote items are installed on the Target VM. It
will most likely reboot the Target VM as well.

I've had dialog boxes pop up and I agree to installation, but I am not
sure they are supposed to. They probably shouldn't, it would seem it
failed to put WDKRemoteUser in Administators group. If that happens,
use "lusrmgr.msc" to correct it.

The task "Creating system restore point" will most likely fail and
that is acceptable, however, if other tasks fail, you may need to
retry until they work.

At the end of the run, the output window offers a link to the full
log, which is worth reading if you encounter issues.

When things fail, I start a CMD prompt as Administrator, and paste in
the commands that fail, from the log file. It would be nice if this
process just worked though.

If your version of .NET newer, just move along.

The Target VM should reboot, and login as "WDKRemoteUser".


It is recommended you get GIT bash for Windows and install:

https://git-scm.com/downloads


---


Host and Target VMs are now configured.

First time you load the project it might default to

Debug : ARM

you probably want to change ARM ==> X64.

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


You can run DbgView on the Target VM to see the kernel prints on that VM.


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


  ✅ Compile SPL sources
  *  Godzillion warnings yet to be addressed

  ✅ Port SPL sources, atomics, mutex, kmem, condvars
  *  C11 _Atomics in kmem not yet handled

  ✅ Compile ZFS sources, stubbing out code as needed

  ✅ Include kernel zlib library

  ✅ Load and Unload SPL and ZFS code

  ✅ Port kernel `zfs_ioctl.c` to accept ioctls from userland

  ✅ Compile userland libspl, libzpool, libzfs, ...

  ✅ Include pthread wrapper library
  *  Replaced with thin pthread.h file

  ✅ Include userland zlib library

  ✅ Compile cmd/zpool

  ✅ Port functions in libzpool, libzfs. Iterate disks, ioctl

  ✅ Test ioctl from zpool to talk to kernel

  ✅ Port kernel `vdev_disk.c` / `vdev_file.c` to issue IO

  ✅ Port over cmd/zfs

  ✅ Add ioctl calls to MOUNT and create Volume to attach

  ✅ Add ioctl calls to UNMOUNT and detach and delete Volume

  ✅ Port kernel `zfs_vnops.c` / `zfs_vnops_windows.c`
  *  Many special cases missing, flags to create/read/etc

  ✅ Correct file information (dates, size, etc)

  ✅ Basic DOS usage

  ✅ Simple Notepad text edit, executables also work.

  ✅ Basic drag'n'drop in Explorer

  ✅ zfs send / recv, file and pipe.

  ❎ ZVOL support

  ✅ git clone ZFS repo on ZFS mounted fs

  ❎ Compile ZFS on top of ZFS
  *  VS catches on fire loading project

  ❎ Scrooge McDuck style swim in cash

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

* The Volume created for MOUNT has something wrong with it, we are
  unable to query it for mountpoint, currently has to string compare a
  list of all mounts. Possibly also related is that we can not call
  any of the functions to set mountpoint to change it. This needs to
  be researched.

* Find a way to get system RAM in SPL, so we can size up the kmem as
expected. Currently looks up the information in the Registry.
kmem should also use Windows signals
"\KernelObjects\LowMemoryCondition" to sense pressure.

* Creating filebased pools would look like:
```
# fsutil file createnew C:\poolfile.bin 200000000
# zpool.exe create TEST \\?\C:\poolfile.bin

Note that "\\?\C:\" needs to be escaped in bash shell, ie
"\\\\?\\C:\\".

        TEST                   ONLINE       0     0     0
        \??\C:\poolfile.bin  ONLINE       0     0     0
```
