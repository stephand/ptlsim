/*
 * PTLsim: Cycle Accurate x86-64 Simulator
 * First object to link
 *
 * Copyright 2003-2008 Matt T. Yourst <yourst@yourst.com>
 */

.intel_syntax

.section .ctors
.global ctor_list
ctor_list:
.previous
