
** Open ZFS On Windows **

As this Windows Driver is not yet signed, it is required that Windows is booted
into Test Mode.

If the Desktop does not display "Test Mode" in the bottom right corner, 
you will need to run;

"bcdedit.exe -set testsigning on"

** THIS IS AN EARLY ALPHA OF OPEN ZFS **

It is recommended that this software is only used on test VMs, with test POOLS
and test DATA. The Developer(s) can not be held responsible if you lose your
Windows, and/or data using this software. This is the wild west people, 
the edge of the frontier.

Having said that, if you find yourself in a boot loop - when Windows 10 fails to
boot two times in a row, you can enter the Advanced Console, and delete the 
ZFSin.SYS file from C:\Windows\Drivers to boot normally.

