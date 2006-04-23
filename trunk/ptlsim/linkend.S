/*
 * PTLsim: Cycle Accurate x86-64 Simulator
 * Last object to link
 *
 * Copyright 2000-2005 Matt T. Yourst <yourst@yourst.com>
 */

.intel_syntax

.section .ctors
.global ctor_list_end
ctor_list_end:
.previous
