#!/bin/sh
ln -sfv $PWD/xc_ptlsim.c $1/tools/libxc
ln -sfv $PWD/xc_ptlsim.h $1/tools/libxc
patch -p1 -d $1 < ptlsim-xen-hypervisor.diff 
patch -p1 -d $1 < ptlsim-xen-tools.diff 
patch -p1 -d $1 < xen-3.x-k8-cpufreq.diff
