// -*- c++ -*-
//
// PTLsim: Cycle Accurate x86-64 Simulator
// Data Cache
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
// 02110-1301, USA.
//
// Copyright 2000-2008 Matt T. Yourst <yourst@yourst.com>
// Copyright (c) 2008-2012 Advanced Micro Devices, Inc.
// Contributed by Stephan Diestelhorst <stephan.diestelhorst@amd.com>
//

#ifndef _DCACHE_H_
#define _DCACHE_H_

#include <ptlsim.h>

#ifdef CORE_GENERIC
#include <dache-generic.h>
#else
#ifdef CORE_AMD_K8
#include <dcache-amd-k8.h>
#else
#ifdef CORE_AMD_BARCELONA_ASF
#include <dcache-amd-barcelona-asf.h>
#else
#error Please specify a core flavour by defining CORE_XXX in ptlsim.h!
#endif
#endif
#endif

#endif // _DCACHE_H_
