# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2019 Vitaly Chikunov <vt@altlinux.org>
%define _unpackaged_files_terminate_build 1
%define _stripped_files_terminate_build 1

Name: rpm-build-vm
Version: 1.36
Release: alt1

Summary: RPM helper to run tests in virtualised environment
License: GPL-2.0-only
Group: Development/Other

Source: %name-%version.tar

%define supported_arches %ix86 x86_64 ppc64le aarch64 armh

%ifarch %supported_arches
BuildRequires: glibc-devel-static
BuildRequires: libblkid-devel-static
# For %%check.
BuildRequires: /dev/kvm
BuildRequires: shellcheck

# Try to load un-def kernel this way to avoid "forbidden dependencies"
# from sisyphus_check.
Requires(pre): kernel >= 5.7
%endif

Requires(pre): %name-run = %EVR

%ifarch %supported_arches
%description
RPM helper to run QEMU inside hasher. This is mainly intended
for %%check section to test software under better emulated root
than fakeroot.

This is similar to multiple vm scripts, virtme, vido, and eudyptula-boot.
%else
%description
This package is a stub instead of RPM helper to run QEMU inside hasher
on supported architectures (this one (%_arch) is unsupported).
%endif

%package run
Summary: vm-run virtualized runner
Group: Development/Other

# Other arches will get a stub which will always return success
%ifarch %supported_arches
Requires: mount

# /proc is required for qemu 9p to work, otherwise you'll get
# confusing ENOENT when creating a file. This is because
# `qemu/hw/9pfs/9p-local.c:fchmodat_nofollow' is doing chmod
# over `/proc/self/fd/%%d'.
Requires: /proc
Requires: /dev/kvm

%ifarch %ix86 x86_64
Requires: qemu-system-x86-core
%endif
%ifarch ppc64le
Requires: qemu-system-ppc-core
%endif
%ifarch aarch64
Requires: qemu-system-aarch64-core
%endif
%ifarch armh
# No KVM support in the kernel for this arch.
Requires: qemu-system-arm-core
# AArch64-native qemu-system-aarch64 binary to use KVM.
Requires: qemu-system-aarch64-core-bundle
%endif

%endif

%ifarch %supported_arches
%description run
RPM helper to run QEMU inside hasher. This is mainly intended
for %%check section to test software under better emulated root
than fakeroot.

This is similar to multiple vm scripts, virtme, vido, and eudyptula-boot.

This package is vm-run scripts only (without requirement on the kernel).
%else
%description run
This package is a stub instead of RPM helper to run QEMU inside hasher
on supported architectures (this one (%_arch) is unsupported).
%endif

%package createimage
Summary: Filetrigger to create ext4 image for vm-run
Group: Development/Other
BuildArch: noarch
Requires: %name = %EVR

%description createimage
This is optional package containing a filetrigger to create an ext4 image
at "/tmp/vm-ext4.img" out of your hasher root to run vm-run with it as rootfs.

%package checkinstall
Summary: Checkinstall for vm-run
Group: Development/Other
BuildArch: noarch
Requires(pre): %name-createimage = %EVR
Requires(pre): time

%description checkinstall
Run checkinstall tests for vm-run.

%prep
%setup

%ifarch %supported_arches
%build
%{?optflags_lto:%global optflags_lto %optflags_lto -ffat-lto-objects}
CFLAGS="%optflags" make
%endif

make check

%install
%ifnarch %supported_arches
install -D -p -m 0755 vm-run-stub %buildroot%_bindir/vm-run
%else
install -D -p -m 0755 vm-run      %buildroot%_bindir/vm-run
install -D -p -m 0755 vm-create-image %buildroot%_bindir/vm-create-image
install -D -p -m 0755 vm-init     %buildroot%_libexecdir/vm-run/vm-init
install -D -p -m 0755 initrd-init %buildroot%_libexecdir/vm-run/initrd-init
install -D -p -m 0755 fakesudo    %buildroot%_libexecdir/vm-run/vm-fakesudo
install -D -p -m 0755 filetrigger %buildroot%_rpmlibdir/vm-run.filetrigger
install -D -p -m 0755 createimage %buildroot%_rpmlibdir/z-vm-createimage.filetrigger
install -Dp bash_completion %buildroot%_sysconfdir/bashrc.d/vm_completion.sh
%endif
install -D -p -m 0755 vm-resize   %buildroot%_bindir/vm-resize

%pre run
# Only allow to install inside of hasher.
[ -d /.host -a -d /.in -a -d /.out ] || {
        echo >&2 'rpm-build-vm-run is not allowed outside hasher environments'
        exit 1
}

%files

%files checkinstall

%files createimage
%ifarch %supported_arches
%_rpmlibdir/z-vm-createimage.filetrigger
%endif

%files run
%_bindir/vm-run
%_bindir/vm-resize

%ifarch %supported_arches
%_bindir/vm-create-image
%_libexecdir/vm-run
%_rpmlibdir/vm-run.filetrigger
%_sysconfdir/bashrc.d/vm*.sh

%post run
# Required in case of --udevd option to vm-run
mkdir -p /run/udev
chmod a+twx /run/udev

# Just in case
mkdir -p /run/dbus
chmod a+twx /run/dbus

# u&mount should to be readable to use inside vm
control mount unprivileged

# Useful for enable audit for some kernel-modules tests
[ ! -x /sbin/auditctl ] || chmod a+rx /sbin/auditctl

# For --overlay=
chmod a+twx /mnt

# Allow user creation (for openssh)
chmod a+r /etc/login.defs
%endif

%pre checkinstall
set -ex
# qemu in tcg mode can hang un-def-5.10 kernel on ppc64 if smp>1 on "smp:
# Bringing up secondary CPUs" message.
%ifarch %supported_arches
ls -l /dev/kvm
set | grep ^LD_
%endif

# Simualte filetrigger run
find /boot > /tmp/filelist
%_rpmlibdir/posttrans-filetriggers /tmp/filelist

timeout 300 vm-run --verbose uname -a
timeout 300 vm-run --verbose --overlay=ext4 uname -a
! timeout --preserve-status 300 vm-run --verbose exit 1
timeout 300 vm-run --rootfs --verbose df

%ifarch %ix86 x86_64 ppc64le aarch64 armh
%check
# Verify availability of KVM in girar & beehiver.
ls -l /dev/kvm && test -w /dev/kvm
%endif

%changelog
* Mon Nov 07 2022 Vitaly Chikunov <vt@altlinux.org> 1.36-alt1
- Add vm-create-image tool that can generate ext4 image out of hasher root.
- vm-run: Support for booting from ext4 image using --rootfs=
  (or --create-rootfs=) option(s). This way you have full root access to the
  system tree.
  Note that 9p is still (bind) mounted over '/usr/src', so you can place your
  test artifacts there.
- Add rpm-build-vm-createimage package with filetrigger to automatically
  generate that ext4 rootfs image. (If you need super precise uids/gids on
  the copies of hasher files, otherwise they maybe roughed to root:root.)
- Bunch of small code and help text improvements.
- Simplistic bash completion support.

* Mon Aug 08 2022 Vitaly Chikunov <vt@altlinux.org> 1.35-alt1
- Fix (uninstalled) kernels list.
- Allow to run auditctl.

* Sun Jun 12 2022 Vitaly Chikunov <vt@altlinux.org> 1.34-alt1
- Fix always 0 exit code. (Add build test for this case.)

* Fri May 13 2022 Vitaly Chikunov <vt@altlinux.org> 1.33-alt1
- Replace egrep with grep -E.
- Change default TMPDIR value to /tmp (to be on top-level tmpfs).

* Tue Apr 19 2022 Vitaly Chikunov <vt@altlinux.org> 1.32-alt1
- Modprobe overlay if '--overlay' is used.

* Sat Feb 12 2022 Vitaly Chikunov <vt@altlinux.org> 1.31-alt1
- Allow to vm-run on uninstalled kernels (developer mode).

* Sun Jan 30 2022 Vitaly Chikunov <vt@altlinux.org> 1.30-alt1
- Enable QEMU '-sandbox' (seccomp) by default.
- Run temporary depmod when --depmod is not specified.
- Handle QEMU abnormal exits with explanation to users.

* Tue Jan 25 2022 Vitaly Chikunov <vt@altlinux.org> 1.29-alt1
- Allow core dumps for qemu run (for coredumpctl).

* Sat Jan 22 2022 Vitaly Chikunov <vt@altlinux.org> 1.28-alt1
- Remove stray dependence on qemu-system-aarch64-core-bundle.
- Do not exclude armh from KVM support.

* Thu Dec 16 2021 Vitaly Chikunov <vt@altlinux.org> 1.27-alt1
- Added KVM support for aarch32.

* Sun Dec 05 2021 Vitaly Chikunov <vt@altlinux.org> 1.26-alt1
- Add vm-resize tool (simpler version of resize(1)).

* Sat Oct 23 2021 Vitaly Chikunov <vt@altlinux.org> 1.25-alt1
- Fix `--cpu=' option after previous change.

* Fri Oct 22 2021 Gleb F-Malinovskiy <glebfm@altlinux.org> 1.24-alt1
- vm-run: explicitly pass CPU topology to qemu.

* Wed Aug 25 2021 Vitaly Chikunov <vt@altlinux.org> 1.23-alt2
- Fix compiling with LTO.

* Tue May 11 2021 Vitaly Chikunov <vt@altlinux.org> 1.23-alt1
- Improve `--udevd' support of mount.

* Mon Apr 05 2021 Ivan A. Melnikov <iv@altlinux.org> 1.22-alt2
- Fix checkinstall package on unsupported architectures

* Sun Apr 04 2021 Vitaly Chikunov <vt@altlinux.org> 1.22-alt1
- Add --kvm=cond option for conditional run
- spec: Test /dev/kvm presence in the %%check

* Sun Apr 04 2021 Vitaly Chikunov <vt@altlinux.org> 1.21-alt2
- Add /dev/kvm test in %%check for girar and ALT beekeeper.

* Sun Apr 04 2021 Vitaly Chikunov <vt@altlinux.org> 1.21-alt1
- Allow to use --kernels to list what is available.
- Do not auto-run depmod for %%buildroot kernels.
- Allow to use OVMF firmware.
- Allow to disable KVM with --tcg option.
- Experimental --fat= directory share with guest.
- Support microvm machine boot (without PCI).
- Allow to pass more options to qemu.

* Mon Jan 25 2021 Vitaly Chikunov <vt@altlinux.org> 1.20-alt1
- Try to catch accidental qemu crashes.

* Wed Jan 13 2021 Vitaly Chikunov <vt@altlinux.org> 1.19-alt2
- spec: Add timeout to checkinstall tests.

* Sun Jan 10 2021 Vitaly Chikunov <vt@altlinux.org> 1.19-alt1
- Avoid 9p warning about msize being too low.

* Fri Dec 04 2020 Vitaly Chikunov <vt@altlinux.org> 1.18-alt2
- Warning if there is attempt to install rpm-build-vm-run outside of hasher.

* Sat Nov 14 2020 Vitaly Chikunov <vt@altlinux.org> 1.18-alt1
- Support to find and run uncompressed vmlinux kernels.

* Fri Sep 25 2020 Vitaly Chikunov <vt@altlinux.org> 1.17-alt1
- Skip copying non-existent modules into initramfs.

* Tue Sep 08 2020 Vitaly Chikunov <vt@altlinux.org> 1.16-alt1
- Fix checkinstall.

* Sat Sep 05 2020 Vitaly Chikunov <vt@altlinux.org> 1.15-alt1
- Split into two packages, with kernel dependence and without it.
- Remove dependence on make-initrd by generating own initramfs.

* Mon Aug 17 2020 Vitaly Chikunov <vt@altlinux.org> 1.14-alt1
- armh: Enable tcg support.

* Wed Aug 12 2020 Vitaly Chikunov <vt@altlinux.org> 1.13-alt1
- Make kernel shutdown quicker.

* Mon Aug 10 2020 Vitaly Chikunov <vt@altlinux.org> 1.12-alt1
- Make console output non-truncated on shutdown.
- Fix tty support for console.

* Sat Aug 08 2020 Vitaly Chikunov <vt@altlinux.org> 1.11-alt1
- x86_64,i586: Try to make kernel more robust with 'no_timer_check'.
- spec: Move checkinstall %%pre outside of %%ifarch to fix noarch check.

* Thu Jul 02 2020 Vitaly Chikunov <vt@altlinux.org> 1.10-alt1
- ppc: Use cap-ccf-assist=off for kvm-type=HV.

* Tue Jun 30 2020 Vitaly Chikunov <vt@altlinux.org> 1.9-alt1
- Propagate exported functions into vm subshell.

* Sat Jun 20 2020 Vitaly Chikunov <vt@altlinux.org> 1.8-alt1
- aarch64: Fix `.gic_version not found' (qemu).
- spec: Fix `different set of noarch packages' (girar).

* Mon Feb 24 2020 Vitaly Chikunov <vt@altlinux.org> 1.7-alt2
- Require /dev/kvm.

* Fri Jan 24 2020 Vitaly Chikunov <vt@altlinux.org> 1.7-alt1
- ppc: Make use of KVM.

* Thu Jan 23 2020 Vitaly Chikunov <vt@altlinux.org> 1.6-alt1
- Fix `Multiple devices detected in same VirtFS export' warning.

* Thu Jan 23 2020 Vitaly Chikunov <vt@altlinux.org> 1.5-alt1
- aarch64: Make use of KVM.

* Mon Dec 30 2019 Ivan A. Melnikov <iv@altlinux.org> 1.4.1-alt3
- Fix build on qemu-less architectures (closes: #37629).

* Sat Dec 28 2019 Vitaly Chikunov <vt@altlinux.org> 1.4.1-alt2
- Fix build on unsupported arches.

* Mon Dec 16 2019 Vitaly Chikunov <vt@altlinux.org> 1.4.1-alt1
- Quickfix of 1.4 (MAXMEM handling).

* Mon Dec 16 2019 Vitaly Chikunov <vt@altlinux.org> 1.4-alt2
- Optimize spec.
- Add checkinstall package.

* Mon Dec 16 2019 Vitaly Chikunov <vt@altlinux.org> 1.4-alt1
- Limit 32-bit system memory.

* Thu Dec 12 2019 Vitaly Chikunov <vt@altlinux.org> 1.3-alt1
- Initialize cpu and mem to the max, support share_network=1,
  handle multiple kernels using --kernel= option.

* Sat Aug 31 2019 Vitaly Chikunov <vt@altlinux.org> 1.2-alt1
- Improvements corresponding to v1.2.

* Mon Aug 19 2019 Vitaly Chikunov <vt@altlinux.org> 1.1-alt1
- Do not use `qemu' binary on x86 due to qemu repackage.

* Mon Aug 19 2019 Vitaly Chikunov <vt@altlinux.org> 1.0-alt5
- Make stub vm-run output a warning message

* Sun Aug 18 2019 Michael Shigorin <mike@altlinux.org> 1.0-alt4
- Rework to provide a stub package on qemu-unsupported arches
  (that can be added into BuildRequires: unconditionally).

* Thu Aug 15 2019 Vitaly Chikunov <vt@altlinux.org> 1.0-alt3
- Add ExclusiveArch for only supported arches.

* Mon Aug 12 2019 Vitaly Chikunov <vt@altlinux.org> 1.0-alt2
- Improvements for ppc64le.

* Mon Aug 05 2019 Vitaly Chikunov <vt@altlinux.org> 1.0-alt1
- Initial version.

