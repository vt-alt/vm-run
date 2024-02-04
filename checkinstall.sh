#!/bin/bash
# checkinstall tests for vm-run

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

timeout 300 vm-run --kvm=cond "date; date"
# Should show neither syntax error nor username.
timeout 300 vm-run --kvm=cond echo '(date)' '$USER'
if type -p busybox; then
	timeout 300 vm-run --initrd --append=rddebug 'uname -a; exit 7' || test $? -eq 7
fi
! timeout --preserve-status 300 vm-run "true; false; true" || exit 1
timeout 300 vm-run --mem=max free -g
timeout 300 vm-run --mem=256 --cpu=max lscpu
df -h /tmp
timeout 300 vm-run --tmp=max df -h /tmp
rm /tmp/vm-tmpfs.qcow2
timeout 300 vm-run --verbose --overlay=ext4 uname -a
rmdir /mnt/0
rm /usr/src/ext4.0.img
timeout 300 vm-run --rootfs --verbose df
rm /tmp/vm-ext4.img
timeout 300 vm-run --hvc --no-quiet 'dmesg -r | grep Unknown'
timeout 300 vm-run --tcg --mem='' --cpu=1 cat /proc/cpuinfo

# Clean up without '-f' ensures these files existed.
rm /tmp/initramfs-*un-def-alt*.img

# SCRIPT and exit code files form each vm-run invocation. Each SCRIPT file
# should correspond to '.ret' file.
find /tmp/vm.?????????? -maxdepth 0 | xargs -t -i -n1 rm {} {}.ret
