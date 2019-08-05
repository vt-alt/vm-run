# Config file for make-initrd

STATEDIR = /tmp
FEATURES += add-modules
DISABLE_GUESS += root fstab resume ucode rdshell keyboard
DISABLE_FEATURES += buildinfo cleanup compress
MODULES_ADD += 9p 9pnet_virtio virtio_pci

# Put /sbin/init-bin this way
PUT_DIRS += /usr/lib/rpm-build-vm
