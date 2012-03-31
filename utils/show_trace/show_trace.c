/**
 * Convert the trace binary format to a simple ASCII representation.
 * @author stephan.diestelhorst@amd.com
 * @date 9.10.2009
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * Copyright (c) 2009-2010 Advanced Micro Devices, Inc.
 * Contributed by Stephan Diestelhorst <stephan.diestelhorst@amd.com>
 *
 */

#include <stdio.h>
#include "../../trace_event.h"
int main(int argc, const char* argv[]) {
	struct TraceEvent e;
	FILE *f = stdin;

	while (!feof(f)) {
		if (fread(&e, sizeof(e), 1, f) != 1) continue;
		printf("%2i.%02i %15li %lx\n", e.coreid, e.threadid, e.cycle, e.rip);
	}
	return 0;
}


