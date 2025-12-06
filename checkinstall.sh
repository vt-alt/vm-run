#!/bin/bash
# checkinstall tests for vm-run

. /etc/os-release
PS4=$'\n+ '
set -ex
# qemu in tcg mode can hang un-def-5.10 kernel on ppc64 if smp>1 on "smp:
# Bringing up secondary CPUs" message.
ls -l /dev/kvm
set | grep ^LD_

# Simulate filetrigger run
find /boot > /tmp/filelist
/usr/lib/rpm/posttrans-filetriggers /tmp/filelist
rm /tmp/filelist
# Remove trigger so it does not re-create '/tmp/vm-ext4.img'.
> /usr/lib/rpm/z-vm-createimage.filetrigger

kvm-ok
timeout 300 vm-run --heredoc <<-'EOF'
	uname -a
	echo $USER '(date)' "(date)"
EOF
# Will say: root (date) (date)

# Check for RLIMIT_AS. QEMU is not very reliable about memory allocations and
# will not always catch ENOMEM, sometimes it will just crash of obscurely hang.
( if ulimit -v $((64*1024*1024)); then timeout 60 vm-run date; fi )
( if ulimit -v $((32*1024*1024)); then timeout 60 vm-run date; fi )
( if ulimit -v $((16*1024*1024)); then timeout 60 vm-run date; fi )
( if ulimit -v $(( 8*1024*1024)); then timeout 60 vm-run --maxcpu=8 date; fi )
( if ulimit -v $(( 4*1024*1024)); then timeout 60 vm-run --maxcpu=2 date; fi )

timeout 300 vm-run --kvm=cond "date; date"
# Should show neither syntax error nor username.
timeout 300 vm-run --kvm=cond echo '(date)' '$USER'
# Network and access to ping(1).
timeout 300 vm-run --kvm=cond ping 127.1 -c 1
timeout 300 vm-run --kvm=cond mount
if type -p busybox; then
	timeout 300 vm-run --initrd --append=rddebug 'uname -a; exit 7' || test $? -eq 7
else
	echo >&2 "No busybox thus --initrd test skipped."
fi
! timeout --preserve-status 300 vm-run "true; false; true" || exit 1
# Delete artifacts after failed runs.
rm /tmp/vm.* /tmp/initramfs-*-*-alt*.img
timeout 300 vm-run --mem=max free -g
timeout 300 vm-run --cpu=max lscpu
df -h /tmp
timeout 300 vm-run --tmp=max df -h /tmp
! rm /tmp/vm-tmpfs.qcow2 || exit 1
timeout 300 vm-run --verbose --overlay=ext4 uname -a
! rmdir /mnt/0 || exit 1
! rm /usr/src/ext4.0.img || exit 1
timeout 300 vm-run --rootfs --verbose df
# The image is created by rpm-build-vm-createimage
rm /tmp/vm-ext4.img
timeout 300 vm-run --hvc --no-quiet 'dmesg -r | grep -E "printk:( legacy)? console \[hvc0\] enabled"'
timeout 300 vm-run --tcg --mem='' --cpu=1 cat /proc/cpuinfo

if [ "$ALT_BRANCH_ID" = sisyphus ]; then
	rpm -qa PROVIDES=kernel-latest | grep '^kernel-image-'
fi

! rm /tmp/initramfs-*-*-alt*.img || exit 1
! rm /tmp/vm.* || exit 1

exit 0
