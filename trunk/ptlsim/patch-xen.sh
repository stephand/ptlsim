#!/bin/sh
ln -sfv $PWD/xc_ptlsim.c $1/tools/libxc
ln -sfv $PWD/xc_ptlsim.h $1/tools/libxc
patch -p1 -d $1 < ptlsim-xen-3.x.diff 
