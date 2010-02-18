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

int64_t zero_sub8(int64_t in) {
	int64_t out;
	asm (
		"sub %%al, %%bl"
		:"=b"(out)
		:"a"(in), "0"(0));
	return out;
}
int64_t zero_sub16(int64_t in) {
	int64_t out;
	asm (
		"sub %%ax, %%bx"
		:"=b"(out)
		:"a"(in), "0"(0));
	return out;
}
int64_t zero_sub32(int64_t in) {
	int64_t out;
	asm (
		"sub %%eax, %%ebx"
		:"=b"(out)
		:"a"(in), "0"(0));
	return out;
}
int64_t zero_sub64(int64_t in) {
	int64_t out;
	asm (
		"sub %%rax, %%rbx"
		:"=b"(out)
		:"a"(in), "0"(0));
	return out;
}
int64_t neg8(int64_t in) {
	int64_t out;
	asm (
		"neg %%al"
		:"=a"(out)
		:"0"(in));
	return out;
}
int64_t neg16(int64_t in) {
	int64_t out;
	asm (
		"neg %%ax"
		:"=a"(out)
		:"0"(in));
	return out;
}
int64_t neg32(int64_t in) {
	int64_t out;
	asm (
		"neg %%eax"
		:"=a"(out)
		:"0"(in));
	return out;
}
int64_t neg64(int64_t in) {
	int64_t out;
	asm (
		"neg %%rax"
		:"=a"(out)
		:"0"(in));
	return out;
}
int main() {
	int64_t data = 0xDEADBEEFFEEDBACC;
	printf(" NEG8: %lx -> %lx\n", data,  neg8(data));
	printf("NEG16: %lx -> %lx\n", data, neg16(data));
	printf("NEG32: %lx -> %lx\n", data, neg32(data));
	printf("NEG64: %lx -> %lx\n", data, neg64(data));
	printf(" ZERO_SUB8: %lx -> %lx\n", data,  zero_sub8(data));
	printf("ZERO_SUB16: %lx -> %lx\n", data, zero_sub16(data));
	printf("ZERO_SUB32: %lx -> %lx\n", data, zero_sub32(data));
	printf("ZERO_SUB64: %lx -> %lx\n", data, zero_sub64(data));
	return 0;
}
