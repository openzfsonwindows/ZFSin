SUBDIRS  = zfs-tests/tests/functional/ctime
SUBDIRS += zfs-tests/tests/functional/exec
SUBDIRS += zfs-tests/cmd/chg_usr_exec
SUBDIRS += zfs-tests/cmd/mktree
SUBDIRS += zfs-tests/cmd/file_write
SUBDIRS += zfs-tests/cmd/mkbusy
SUBDIRS += zfs-tests/cmd/randfree_file
SUBDIRS += zfs-tests/cmd/largest_file
SUBDIRS += zfs-tests/cmd/rm_lnkcnt_zero_file
SUBDIRS += zfs-tests/cmd/readmmap
SUBDIRS += zfs-tests/cmd/mmapwrite
SUBDIRS += zfs-tests/cmd/file_trunc
SUBDIRS += zfs-tests/cmd/file_check

abs_top_srcdir = @abs_top_srcdir@
SHELL = /bin/bash

AUTOMAKE_OPTIONS = foreign

ctags:
	$(RM) $(top_srcdir)/tags
	find $(top_srcdir) -name .git -prune -o -name '*.[hc]' | xargs ctags

etags:
	$(RM) $(top_srcdir)/TAGS
	find $(top_srcdir) -name .pc -prune -o -name '*.[hc]' | xargs etags -a

test: test_verify zfs-tests/cmd
	@KEEP="`zpool list -H -oname`" \
	 STF_TOOLS=$(abs_top_srcdir)/test-runner/stf \
	 STF_SUITE=$(abs_top_srcdir)/zfs-tests \
	 DISKS="$(shell for i in {1..3}; do \
	    rm -f /var/tmp/zfs_test-$$i; \
	    $(abs_top_srcdir)/scripts/mkfile 25000m /var/tmp/zfs_test-$$i; \
	    echo "/var/tmp/zfs_test-$$i "; \
	   done)" \
	 su zfs-tests -c "ksh $(abs_top_srcdir)/zfs-tests/cmd/scripts/zfstest.ksh $$RUNFILE"

test_hw: test_verify zfs-tests/cmd
	@KEEP="`zpool list -H -oname`" \
	 STF_TOOLS=$(abs_top_srcdir)/test-runner/stf \
	 STF_SUITE=$(abs_top_srcdir)/zfs-tests \
	 DISKS="/dev/disk1 /dev/disk2 /dev/disk3" \
	 su zfs-tests -c "ksh $(abs_top_srcdir)/zfs-tests/cmd/scripts/zfstest.ksh $$RUNFILE"

test_existing: test_verify zfs-tests/cmd
	@KEEP="`zpool list -H -oname`" \
	 STF_TOOLS=$(abs_top_srcdir)/test-runner/stf \
	 STF_SUITE=$(abs_top_srcdir)/zfs-tests \
	 DISKS="/var/tmp/zfs_test-1 /var/tmp/zfs_test-2 /var/tmp/zfs_test-3" \
	 su zfs-tests -c "ksh $(abs_top_srcdir)/zfs-tests/cmd/scripts/zfstest.ksh $$RUNFILE"


test_verify:
	@# -------------------------------------------------------------------
	@# adduser --home /var/tmp/test_results --shell /usr/bin/ksh --gecos "ZFS Test Suite" --disabled-password zfs-tests
	@# echo 'zfs-tests	ALL = (ALL:ALL) NOPASSWD: ALL' >> /etc/sudoers
	@# -------------------------------------------------------------------
	@( if ! id zfs-tests > /dev/null 2>&1; then \
		echo "ERROR: You must create a 'zfs-tests' user to run the test as."; \
		exit 1; \
	   fi; \
	   if ! su - zfs-tests -c "sudo ls" > /dev/null 2>&1; then \
		echo "ERROR: User zfs-tests is not allowed to run sudo without password."; \
		exit 1; \
	   fi)

zfs-tests/cmd:
	@(for subdir in $(SUBDIRS); do \
		make -C $$subdir all; \
	done)

clean:
	@(for subdir in $(SUBDIRS); do \
		make -C $$subdir clean; \
	done)

tags: ctags etags

.PHONY: test zfs-tests/cmd

# Tell versions [3.59,3.63) of GNU make to not export all variables.
# Otherwise a system limit (for SysV at least) may be exceeded.
.NOEXPORT:
