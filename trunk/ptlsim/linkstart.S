/*
 * PTLsim: Cycle Accurate x86-64 Simulator
 * First object to link
 *
 * Copyright 2000-2005 Matt T. Yourst <yourst@yourst.com>
 */

.intel_syntax

.section .ctors
.global ctor_list
ctor_list:
.previous
