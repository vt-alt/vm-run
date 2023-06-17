ALT Linux tool to run commands using QEMU/KVM booted Linux kernel in `%check`
section (of .spec) to run tests requiring (virtualized) root permissions or
kernel testing fully under user.

Filesystem is mounted over 9pfs by default, but creation of ext4 image is also
supported. There are multiple options to experiment with BIOS or UEFI boot,
secureboot, microvm machine, VirtIO/SCSI devices, hvc console, etc.

Collection of links to similar tools & scripts:

* https://lkml.org/lkml/2011/11/5/83 (run-qemu) 2011-2012
* https://github.com/arapov/wrap-qemukvm 2012-2013
* https://github.com/g2p/vido 2013-2017
* https://github.com/amluto/virtme 2014-2021
* https://github.com/vincentbernat/eudyptula-boot 2014-2022
* https://github.com/legionus/vm 2015-2020
* https://github.com/osandov/osandov-linux 2015-2023
* https://github.com/cirosantilli/runlinux.git 2015-2017
* https://github.com/systemd/mkosi 2016-
* https://github.com/rapido-linux/rapido 2016-
* https://github.com/jollheef/out-of-tree 2018-
* https://github.com/YADRO-KNS/ktest 2018-2020
* https://gitlab.com/cip-project/cip-core/isar-cip-core/blob/master/start-qemu.sh 2019-
* https://github.com/obirvalger/vml 2021-
* https://github.com/klark973/vm 2023-
