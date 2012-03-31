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
 * Tests CMPXCHG and XADD instructions that just operate on registers.
 *
 * Author: Stephan Diestelhorst (stephan.diestelhorst@amd.com)
 * Date:   18.02.2010
 *
 * Copyright (c) 2010, Advanced Micro Devices, Inc.
 */
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

int cmpxchg_reg2reg(uint64_t test, uint64_t new, uint64_t *loc) {
    uint8_t out;
    asm (
        "cmpxchg %3, %0  \n\t"
        "sete %1             " 
        :"=r"(*loc), "=r"(out)
        :"a"(test), "r"(new), "0"(*loc));
    return out;
}
uint64_t xadd_reg2reg(uint64_t new, uint64_t *loc) {
    uint64_t out;
    asm (
        "xadd %1, %0  \n\t"
        :"=r"(*loc), "=r"(out)
        :"1"(new), "0"(*loc));
    return out;
}

int main() {
    uint64_t test, new, old_loc, loc;
    int res;
    
    test = 0;
    loc  = 0;
    new  = 1;
    
    old_loc = loc;
    res = cmpxchg_reg2reg(test, new, &loc);
    printf("CMPXCHG (%li == %li) new = %li -> %i loc = %li\n", old_loc, test, new, res, loc);

    test = 6;
    loc  = 5;
    new  = 10;
    
    old_loc = loc;
    res = cmpxchg_reg2reg(test, new, &loc);
    printf("CMPXCHG (%li == %li) new = %li -> %i loc = %li\n", old_loc, test, new, res, loc);

    old_loc = xadd_reg2reg(new, &loc);
    printf("XADD old_loc = %li new = %li loc = %li\n", old_loc, new, loc);

    return 0;
}
