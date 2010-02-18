/**
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
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
 * Tests NEG instructions for all possible register sizes.
 *
 * Author: Stephan Diestelhorst (stephan.diestelhorst@amd.com)
 * Date:   18.02.2010
 *
 * Copyright (c) 2010, Advanced Micro Devices, Inc.
 */
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

uint64_t xlat_addr32(void* base, uint64_t offs) {
	uint64_t out;
	asm (
		".byte 0x67 \n\t"
		"xlat"
		:"=a"(out)
		:"b"(base), "0"(offs));
	return out;
}
uint64_t xlat_addr64(void* base, uint64_t offs) {
	uint64_t out;
	asm (
		"xlat"
		:"=a"(out)
		:"b"(base), "0"(offs));
	return out;
}
uint8_t xlat_arr[]={0xCC};
int main() {
	uint64_t offs = 0xDEADBEEFFEEDBA00;
	uint64_t res;

	res = xlat_addr32(xlat_arr, offs);
	printf("XLAT (32-bit addr) of %p+%i (%lx) -> %x (%lx)\n", xlat_arr,
	       (int)(offs & 0xFF), offs, (int)(res & 0xFF), res);


	// Put bogus offs into the higher 32-bits of the address to check 32-bit addressing.
	void *xlat_arr_bogus = (void*)(0xDEADBEEF00000000 | (((uint64_t)xlat_arr) & 0xFFFFFFFF));
	printf("Bogus addr: %p\n", xlat_arr_bogus);

	res = xlat_addr32(xlat_arr_bogus, offs);
	printf("XLAT (32-bit bogus addr) of %p+%i (%lx) -> %x (%lx)\n", xlat_arr_bogus,
	       (int)(offs & 0xFF), offs, (int)(res & 0xFF), res);

	res = xlat_addr64(xlat_arr, offs);
	printf("XLAT (64-bit addr) of %p+%i (%lx) -> %x (%lx)\n", xlat_arr,
	       (int)(offs & 0xFF), offs, (int)(res & 0xFF), res);
	return 0;
}
