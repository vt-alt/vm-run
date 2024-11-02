#!/usr/bin/env -S just --justfile

_list:
        @just --list

ci +branches="sisyphus p11 p10":
	for branch in {{branches}}; do \
		just bb $branch; \
		just checkinstall $branch; \
	done

bb branch="sisyphus":
        gum spin --show-error --title='Building for {{branch}}...' -- bb --repo={{branch}}

enter branch="sisyphus": (bb branch)
	bb --repo={{branch}} --ini
	hsh-install rpm-build-vm
	hsh-shell --mountpoints=/proc,/dev/pts,/dev/kvm

checkinstall branch="default":
	hsh-install rpm-build-vm-checkinstall |& tee log-{{branch}}.ci
