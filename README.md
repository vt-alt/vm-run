ALT Linux specific tool to run commands using Qemu/KVM booted Linux kernel in
%check section (of .spec) to run tests requiring (virtualized) root permissions
or kernel testing. Filesystem is mounted over 9pfs.

Collection of links to similar tools & scripts:

* https://lkml.org/lkml/2011/11/5/83 (run-qemu) 2011-2012
* https://github.com/arapov/wrap-qemukvm 2012-2013
* https://github.com/g2p/vido 2013-2017
* https://github.com/amluto/virtme 2014-2020
* https://github.com/vincentbernat/eudyptula-boot 2014-2021
* https://github.com/legionus/vm 2015-2020
* https://github.com/osandov/osandov-linux 2015-2021
* https://github.com/cirosantilli/runlinux.git 2015-2017
* https://github.com/systemd/mkosi 2016-
* https://github.com/rapido-linux/rapido 2016-
* https://github.com/jollheef/out-of-tree 2018-2021
* https://github.com/YADRO-KNS/ktest 2018-2020
* https://gitlab.com/cip-project/cip-core/isar-cip-core/blob/master/start-qemu.sh 2019-
