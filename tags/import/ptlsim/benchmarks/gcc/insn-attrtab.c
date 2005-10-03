/* Generated automatically by the program `genattrtab'
from the machine description file `md'.  */

#include "config.h"
#include "rtl.h"
#include "insn-config.h"
#include "recog.h"
#include "regs.h"
#include "real.h"
#include "output.h"
#include "insn-attr.h"

#define operands recog_operand

int
insn_current_length (insn)
     rtx insn;
{
  switch (recog_memoized (insn))
    {
    case -1:
      if (GET_CODE (PATTERN (insn)) != ASM_INPUT
          && asm_noperands (PATTERN (insn)) < 0)
        fatal_insn_not_found (insn);
    default:
      return 0;

    }
}

int
insn_variable_length_p (insn)
     rtx insn;
{
  switch (recog_memoized (insn))
    {
    case -1:
      if (GET_CODE (PATTERN (insn)) != ASM_INPUT
          && asm_noperands (PATTERN (insn)) < 0)
        fatal_insn_not_found (insn);
    default:
      return 0;

    }
}

int
insn_default_length (insn)
     rtx insn;
{
  switch (recog_memoized (insn))
    {
    case 281:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if ((which_alternative == 0) || (which_alternative == 1))
        {
	  return 2;
        }
      else if (which_alternative == 2)
        {
	  return 4;
        }
      else
        {
	  return 4;
        }

    case 233:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if ((which_alternative != 0) && (which_alternative != 1))
        {
	  return 2;
        }
      else
        {
	  return 1;
        }

    case 228:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if (((which_alternative != 0) && (which_alternative != 1)) && (which_alternative != 2))
        {
	  return 2;
        }
      else
        {
	  return 1;
        }

    case 223:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if (which_alternative != 0)
        {
	  return 2;
        }
      else
        {
	  return 1;
        }

    case 264:
    case 262:
    case 127:
    case 126:
    case 121:
    case 120:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if (which_alternative == 0)
        {
	  return 2;
        }
      else
        {
	  return 1;
        }

    case 108:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if (which_alternative == 4)
        {
	  return 2;
        }
      else
        {
	  return 1;
        }

    case 278:
      return 0;

    case 269:
    case 259:
    case 46:
      return 3;

    case 252:
    case 235:
    case 230:
    case 225:
    case 129:
    case 123:
      return 4;

    case -1:
      if (GET_CODE (PATTERN (insn)) != ASM_INPUT
          && asm_noperands (PATTERN (insn)) < 0)
        fatal_insn_not_found (insn);
    case 243:
    case 242:
    case 237:
    case 234:
    case 229:
    case 224:
    case 208:
    case 202:
    case 191:
    case 190:
    case 189:
    case 178:
    case 177:
    case 176:
    case 134:
    case 102:
    case 101:
    case 100:
    case 99:
    case 98:
    case 97:
    case 96:
    case 95:
    case 94:
    case 52:
    case 51:
    case 50:
    case 49:
    case 48:
    case 47:
    case 45:
    case 44:
    case 43:
    case 42:
    case 41:
    case 40:
    case 39:
    case 12:
    case 104:
      return 2;

    default:
      return 1;

    }
}

int
result_ready_cost (insn)
     rtx insn;
{
  switch (recog_memoized (insn))
    {
    case 233:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if ((which_alternative == 2) && (! (((m88k_cpu) == (CPU_M88100)))))
        {
	  return 4;
        }
      else if (((which_alternative == 0) || (which_alternative == 1)) && (! (((m88k_cpu) == (CPU_M88100)))))
        {
	  return 2;
        }
      else
        {
	  return 1;
        }

    case 228:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if ((which_alternative == 3) && (! (((m88k_cpu) == (CPU_M88100)))))
        {
	  return 4;
        }
      else if (((which_alternative == 2) && (! (((m88k_cpu) == (CPU_M88100))))) || (((which_alternative == 0) || (which_alternative == 1)) && (! (((m88k_cpu) == (CPU_M88100))))))
        {
	  return 2;
        }
      else
        {
	  return 1;
        }

    case 223:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if ((which_alternative == 1) && (! (((m88k_cpu) == (CPU_M88100)))))
        {
	  return 4;
        }
      else if ((which_alternative == 0) && (! (((m88k_cpu) == (CPU_M88100)))))
        {
	  return 2;
        }
      else
        {
	  return 1;
        }

    case 213:
      if (((m88k_cpu) == (CPU_M88100)))
        {
	  return 30 /* 0x1e */;
        }
      else
        {
	  return 25 /* 0x19 */;
        }

    case 214:
    case 212:
    case 211:
    case 210:
      if (((m88k_cpu) == (CPU_M88100)))
        {
	  return 60 /* 0x3c */;
        }
      else
        {
	  return 45 /* 0x2d */;
        }

    case 207:
    case 205:
      if (((m88k_cpu) == (CPU_M88100)))
        {
	  return 38 /* 0x26 */;
        }
      else
        {
	  return 35 /* 0x23 */;
        }

    case 200:
      if (((m88k_cpu) == (CPU_M88100)))
        {
	  return 7;
        }
      else
        {
	  return 5;
        }

    case 168:
    case 165:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if (! (((m88k_cpu) == (CPU_M88100))))
        {
	  return 5;
        }
      else if (which_alternative == 1)
        {
	  return 4;
        }
      else
        {
	  return 3;
        }

    case 261:
    case 201:
    case 199:
    case 198:
    case 197:
    case 187:
    case 186:
    case 185:
    case 174:
    case 173:
    case 172:
    case 167:
    case 164:
    case 163:
      if (! (((m88k_cpu) == (CPU_M88100))))
        {
	  return 5;
        }
      else
        {
	  return 4;
        }

    case 195:
    case 188:
    case 184:
    case 175:
    case 171:
    case 166:
    case 161:
    case 160:
      if (! (((m88k_cpu) == (CPU_M88100))))
        {
	  return 5;
        }
      else
        {
	  return 3;
        }

    case 158:
    case 156:
    case 154:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if (which_alternative == 3)
        {
	  return 3;
        }
      else if (((which_alternative == 0) && (! (((m88k_cpu) == (CPU_M88100))))) || (((which_alternative == 1) || (which_alternative == 2)) && (! (((m88k_cpu) == (CPU_M88100))))))
        {
	  return 2;
        }
      else
        {
	  return 1;
        }

    case 151:
    case 149:
    case 147:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if (which_alternative == 2)
        {
	  return 3;
        }
      else if (((which_alternative == 0) || (which_alternative == 1)) && (! (((m88k_cpu) == (CPU_M88100)))))
        {
	  return 2;
        }
      else
        {
	  return 1;
        }

    case 241:
    case 240:
    case 239:
    case 238:
    case 139:
    case 138:
    case 137:
    case 136:
      return 3;

    case 132:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if ((which_alternative == 1) || (which_alternative == 6))
        {
	  return 3;
        }
      else if (((which_alternative == 0) || ((which_alternative == 3) || ((which_alternative == 4) || (which_alternative == 5)))) && (! (((m88k_cpu) == (CPU_M88100)))))
        {
	  return 2;
        }
      else
        {
	  return 1;
        }

    case 127:
    case 121:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if ((which_alternative == 0) && (! (((m88k_cpu) == (CPU_M88100)))))
        {
	  return 4;
        }
      else if ((which_alternative == 1) || (which_alternative == 6))
        {
	  return 3;
        }
      else if (((which_alternative == 3) || ((which_alternative == 4) || (which_alternative == 5))) && (! (((m88k_cpu) == (CPU_M88100)))))
        {
	  return 2;
        }
      else
        {
	  return 1;
        }

    case 264:
    case 262:
    case 126:
    case 120:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if ((which_alternative == 0) && (! (((m88k_cpu) == (CPU_M88100)))))
        {
	  return 4;
        }
      else if ((which_alternative == 1) && (! (((m88k_cpu) == (CPU_M88100)))))
        {
	  return 2;
        }
      else
        {
	  return 1;
        }

    case 117:
    case 114:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if (which_alternative == 1)
        {
	  return 3;
        }
      else if ((which_alternative != 2) && (! (((m88k_cpu) == (CPU_M88100)))))
        {
	  return 2;
        }
      else
        {
	  return 1;
        }

    case 108:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if ((which_alternative == 4) && (! (((m88k_cpu) == (CPU_M88100)))))
        {
	  return 4;
        }
      else if (((which_alternative == 3) && (! (((m88k_cpu) == (CPU_M88100))))) || (((which_alternative == 0) || ((which_alternative == 1) || (which_alternative == 2))) && (! (((m88k_cpu) == (CPU_M88100))))))
        {
	  return 2;
        }
      else
        {
	  return 1;
        }

    case 107:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if ((which_alternative == 1) || (which_alternative == 8))
        {
	  return 3;
        }
      else if (((which_alternative == 4) && (! (((m88k_cpu) == (CPU_M88100))))) || ((((which_alternative == 0) || (which_alternative == 3)) || ((which_alternative == 5) || ((which_alternative == 6) || (which_alternative == 7)))) && (! (((m88k_cpu) == (CPU_M88100))))))
        {
	  return 2;
        }
      else
        {
	  return 1;
        }

    case 61:
    case 60:
    case 59:
      if (((m88k_cpu) == (CPU_M88100)))
        {
	  return 4;
        }
      else
        {
	  return 2;
        }

    case 58:
      if (((m88k_cpu) == (CPU_M88100)))
        {
	  return 3;
        }
      else
        {
	  return 2;
        }

    case 280:
    case 279:
    case 275:
    case 273:
    case 271:
    case 268:
    case 143:
    case 142:
    case 141:
    case 140:
    case 102:
    case 101:
    case 100:
    case 99:
    case 98:
    case 97:
    case 96:
    case 95:
    case 94:
    case 52:
    case 51:
    case 50:
    case 49:
    case 48:
    case 47:
    case 45:
    case 44:
    case 43:
    case 42:
    case 41:
    case 40:
    case 39:
      return 1;

    case -1:
      if (GET_CODE (PATTERN (insn)) != ASM_INPUT
          && asm_noperands (PATTERN (insn)) < 0)
        fatal_insn_not_found (insn);
    case 281:
    case 269:
    case 259:
    case 252:
    case 243:
    case 242:
    case 237:
    case 235:
    case 234:
    case 230:
    case 229:
    case 225:
    case 224:
    case 208:
    case 202:
    case 191:
    case 190:
    case 189:
    case 178:
    case 177:
    case 176:
    case 134:
    case 129:
    case 123:
    case 46:
    case 12:
      if (! (((m88k_cpu) == (CPU_M88100))))
        {
	  return 4;
        }
      else
        {
	  return 1;
        }

    default:
      if (! (((m88k_cpu) == (CPU_M88100))))
        {
	  return 2;
        }
      else
        {
	  return 1;
        }

    }
}

int
div_unit_ready_cost (insn)
     rtx insn;
{
  switch (recog_memoized (insn))
    {
    case 213:
      if (! (((m88k_cpu) == (CPU_M88100))))
        {
	  return 25 /* 0x19 */;
        }
      else
        {
	  return 45 /* 0x2d */;
        }

    case 207:
    case 205:
      if (! (((m88k_cpu) == (CPU_M88100))))
        {
	  return 35 /* 0x23 */;
        }
      else
        {
	  return 45 /* 0x2d */;
        }

    case -1:
      if (GET_CODE (PATTERN (insn)) != ASM_INPUT
          && asm_noperands (PATTERN (insn)) < 0)
        fatal_insn_not_found (insn);
    default:
      return 45 /* 0x2d */;

    }
}

unsigned int
div_unit_blockage_range (insn)
     rtx insn;
{
  switch (recog_memoized (insn))
    {
    case -1:
      if (GET_CODE (PATTERN (insn)) != ASM_INPUT
          && asm_noperands (PATTERN (insn)) < 0)
        fatal_insn_not_found (insn);
    default:
      return 1638445 /* 0x19002d */;

    }
}

int
fpadd110_unit_ready_cost (insn)
     rtx insn;
{
  switch (recog_memoized (insn))
    {
    case 61:
    case 60:
    case 59:
    case 58:
      if (! (((m88k_cpu) == (CPU_M88100))))
        {
	  return 2;
        }
      else
        {
	  return 5;
        }

    case -1:
      if (GET_CODE (PATTERN (insn)) != ASM_INPUT
          && asm_noperands (PATTERN (insn)) < 0)
        fatal_insn_not_found (insn);
    default:
      return 5;

    }
}

unsigned int
fpadd110_unit_blockage_range (insn)
     rtx insn;
{
  switch (recog_memoized (insn))
    {
    case 168:
    case 165:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if (((which_alternative == 1) && (! (((m88k_cpu) == (CPU_M88100))))) || ((which_alternative == 0) && (! (((m88k_cpu) == (CPU_M88100))))))
        {
	  return 131074 /* 0x20002 */;
        }
      else
        {
	  return 131076 /* 0x20004 */;
        }

    case 261:
    case 188:
    case 187:
    case 186:
    case 185:
    case 184:
    case 175:
    case 174:
    case 173:
    case 172:
    case 171:
    case 167:
    case 166:
    case 164:
    case 163:
    case 161:
    case 160:
      if (! (((m88k_cpu) == (CPU_M88100))))
        {
	  return 131074 /* 0x20002 */;
        }
      else
        {
	  return 131076 /* 0x20004 */;
        }

    case -1:
      if (GET_CODE (PATTERN (insn)) != ASM_INPUT
          && asm_noperands (PATTERN (insn)) < 0)
        fatal_insn_not_found (insn);
    default:
      return 131076 /* 0x20004 */;

    }
}

int
fpadd100_unit_ready_cost (insn)
     rtx insn;
{
  switch (recog_memoized (insn))
    {
    case 213:
      if (((m88k_cpu) == (CPU_M88100)))
        {
	  return 30 /* 0x1e */;
        }
      else
        {
	  return 60 /* 0x3c */;
        }

    case 207:
    case 205:
      if (((m88k_cpu) == (CPU_M88100)))
        {
	  return 38 /* 0x26 */;
        }
      else
        {
	  return 60 /* 0x3c */;
        }

    case 168:
    case 165:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if ((which_alternative == 1) && (((m88k_cpu) == (CPU_M88100))))
        {
	  return 4;
        }
      else if ((which_alternative == 0) && (((m88k_cpu) == (CPU_M88100))))
        {
	  return 3;
        }
      else
        {
	  return 60 /* 0x3c */;
        }

    case 261:
    case 187:
    case 186:
    case 185:
    case 174:
    case 173:
    case 172:
    case 167:
    case 164:
    case 163:
    case 61:
    case 60:
    case 59:
      if (((m88k_cpu) == (CPU_M88100)))
        {
	  return 4;
        }
      else
        {
	  return 60 /* 0x3c */;
        }

    case 188:
    case 184:
    case 175:
    case 171:
    case 166:
    case 161:
    case 160:
    case 58:
      if (((m88k_cpu) == (CPU_M88100)))
        {
	  return 3;
        }
      else
        {
	  return 60 /* 0x3c */;
        }

    case -1:
      if (GET_CODE (PATTERN (insn)) != ASM_INPUT
          && asm_noperands (PATTERN (insn)) < 0)
        fatal_insn_not_found (insn);
    default:
      return 60 /* 0x3c */;

    }
}

unsigned int
fpadd100_unit_blockage_range (insn)
     rtx insn;
{
  switch (recog_memoized (insn))
    {
    case 214:
    case 213:
    case 212:
    case 211:
    case 210:
    case 207:
    case 205:
      if (((m88k_cpu) == (CPU_M88100)))
        {
	  return 65592 /* 0x10038 */;
        }
      else
        {
	  return 65594 /* 0x1003a */;
        }

    case 168:
    case 165:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if ((which_alternative == 1) && (((m88k_cpu) == (CPU_M88100))))
        {
	  return 65593 /* 0x10039 */;
        }
      else
        {
	  return 65594 /* 0x1003a */;
        }

    case 261:
    case 187:
    case 186:
    case 185:
    case 174:
    case 173:
    case 172:
    case 167:
    case 164:
    case 163:
    case 61:
    case 60:
    case 59:
      if (((m88k_cpu) == (CPU_M88100)))
        {
	  return 65593 /* 0x10039 */;
        }
      else
        {
	  return 65594 /* 0x1003a */;
        }

    case -1:
      if (GET_CODE (PATTERN (insn)) != ASM_INPUT
          && asm_noperands (PATTERN (insn)) < 0)
        fatal_insn_not_found (insn);
    default:
      return 65594 /* 0x1003a */;

    }
}

int
fpmul110_unit_ready_cost (insn)
     rtx insn;
{
  switch (recog_memoized (insn))
    {
    case -1:
      if (GET_CODE (PATTERN (insn)) != ASM_INPUT
          && asm_noperands (PATTERN (insn)) < 0)
        fatal_insn_not_found (insn);
    default:
      return 5;

    }
}

int
fpmul100_unit_ready_cost (insn)
     rtx insn;
{
  switch (recog_memoized (insn))
    {
    case 201:
    case 199:
    case 198:
    case 197:
      if (((m88k_cpu) == (CPU_M88100)))
        {
	  return 4;
        }
      else
        {
	  return 7;
        }

    case 195:
      if (((m88k_cpu) == (CPU_M88100)))
        {
	  return 3;
        }
      else
        {
	  return 7;
        }

    case -1:
      if (GET_CODE (PATTERN (insn)) != ASM_INPUT
          && asm_noperands (PATTERN (insn)) < 0)
        fatal_insn_not_found (insn);
    default:
      return 7;

    }
}

unsigned int
fpmul100_unit_blockage_range (insn)
     rtx insn;
{
  switch (recog_memoized (insn))
    {
    case 200:
      if (((m88k_cpu) == (CPU_M88100)))
        {
	  return 65537 /* 0x10001 */;
        }
      else
        {
	  return 65541 /* 0x10005 */;
        }

    case 201:
    case 199:
    case 198:
    case 197:
      if (((m88k_cpu) == (CPU_M88100)))
        {
	  return 65540 /* 0x10004 */;
        }
      else
        {
	  return 65541 /* 0x10005 */;
        }

    case -1:
      if (GET_CODE (PATTERN (insn)) != ASM_INPUT
          && asm_noperands (PATTERN (insn)) < 0)
        fatal_insn_not_found (insn);
    default:
      return 65541 /* 0x10005 */;

    }
}

int
mem110_unit_ready_cost (insn)
     rtx insn;
{
  switch (recog_memoized (insn))
    {
    case 143:
    case 142:
    case 141:
    case 140:
      if (! (((m88k_cpu) == (CPU_M88100))))
        {
	  return 1;
        }
      else
        {
	  return 3;
        }

    case 132:
    case 127:
    case 121:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if (((which_alternative != 0) && ((which_alternative != 1) && ((which_alternative != 3) && ((which_alternative != 4) && ((which_alternative != 5) && (which_alternative != 6)))))) && (! (((m88k_cpu) == (CPU_M88100)))))
        {
	  return 1;
        }
      else
        {
	  return 3;
        }

    case 117:
    case 114:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if ((which_alternative == 2) && (! (((m88k_cpu) == (CPU_M88100)))))
        {
	  return 1;
        }
      else
        {
	  return 3;
        }

    case 107:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if (((which_alternative == 2) || (which_alternative == 9)) && (! (((m88k_cpu) == (CPU_M88100)))))
        {
	  return 1;
        }
      else
        {
	  return 3;
        }

    case -1:
      if (GET_CODE (PATTERN (insn)) != ASM_INPUT
          && asm_noperands (PATTERN (insn)) < 0)
        fatal_insn_not_found (insn);
    default:
      return 3;

    }
}

unsigned int
mem110_unit_blockage_range (insn)
     rtx insn;
{
  switch (recog_memoized (insn))
    {
    case 158:
    case 156:
    case 154:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if ((which_alternative == 3) && (! (((m88k_cpu) == (CPU_M88100)))))
        {
	  return 131074 /* 0x20002 */;
        }
      else
        {
	  return 131075 /* 0x20003 */;
        }

    case 151:
    case 149:
    case 147:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if ((which_alternative == 2) && (! (((m88k_cpu) == (CPU_M88100)))))
        {
	  return 131074 /* 0x20002 */;
        }
      else
        {
	  return 131075 /* 0x20003 */;
        }

    case 241:
    case 240:
    case 239:
    case 238:
    case 139:
    case 138:
    case 137:
    case 136:
      if (! (((m88k_cpu) == (CPU_M88100))))
        {
	  return 131074 /* 0x20002 */;
        }
      else
        {
	  return 131075 /* 0x20003 */;
        }

    case 132:
    case 127:
    case 121:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if (((which_alternative == 1) || (which_alternative == 6)) && (! (((m88k_cpu) == (CPU_M88100)))))
        {
	  return 131074 /* 0x20002 */;
        }
      else
        {
	  return 131075 /* 0x20003 */;
        }

    case 117:
    case 114:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if ((which_alternative == 1) && (! (((m88k_cpu) == (CPU_M88100)))))
        {
	  return 131074 /* 0x20002 */;
        }
      else
        {
	  return 131075 /* 0x20003 */;
        }

    case 107:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if (((which_alternative == 1) || (which_alternative == 8)) && (! (((m88k_cpu) == (CPU_M88100)))))
        {
	  return 131074 /* 0x20002 */;
        }
      else
        {
	  return 131075 /* 0x20003 */;
        }

    case -1:
      if (GET_CODE (PATTERN (insn)) != ASM_INPUT
          && asm_noperands (PATTERN (insn)) < 0)
        fatal_insn_not_found (insn);
    default:
      return 131075 /* 0x20003 */;

    }
}

int
mem100_unit_ready_cost (insn)
     rtx insn;
{
  switch (recog_memoized (insn))
    {
    case 220:
    case 219:
    case 218:
    case 217:
    case 216:
    case 143:
    case 142:
    case 141:
    case 140:
      if (((m88k_cpu) == (CPU_M88100)))
        {
	  return 1;
        }
      else
        {
	  return 3;
        }

    case 132:
    case 127:
    case 121:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if (((which_alternative != 0) && ((which_alternative != 1) && ((which_alternative != 3) && ((which_alternative != 4) && ((which_alternative != 5) && (which_alternative != 6)))))) && (((m88k_cpu) == (CPU_M88100))))
        {
	  return 1;
        }
      else
        {
	  return 3;
        }

    case 117:
    case 114:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if ((which_alternative == 2) && (((m88k_cpu) == (CPU_M88100))))
        {
	  return 1;
        }
      else
        {
	  return 3;
        }

    case 107:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if (((which_alternative == 2) || (which_alternative == 9)) && (((m88k_cpu) == (CPU_M88100))))
        {
	  return 1;
        }
      else
        {
	  return 3;
        }

    case -1:
      if (GET_CODE (PATTERN (insn)) != ASM_INPUT
          && asm_noperands (PATTERN (insn)) < 0)
        fatal_insn_not_found (insn);
    default:
      return 3;

    }
}

unsigned int
mem100_unit_blockage_range (insn)
     rtx insn;
{
  switch (recog_memoized (insn))
    {
    case 158:
    case 156:
    case 154:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if ((which_alternative == 3) && (((m88k_cpu) == (CPU_M88100))))
        {
	  return 65538 /* 0x10002 */;
        }
      else
        {
	  return 65539 /* 0x10003 */;
        }

    case 151:
    case 149:
    case 147:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if ((which_alternative == 2) && (((m88k_cpu) == (CPU_M88100))))
        {
	  return 65538 /* 0x10002 */;
        }
      else
        {
	  return 65539 /* 0x10003 */;
        }

    case 241:
    case 240:
    case 239:
    case 238:
    case 139:
    case 138:
    case 137:
    case 136:
      if (((m88k_cpu) == (CPU_M88100)))
        {
	  return 65538 /* 0x10002 */;
        }
      else
        {
	  return 65539 /* 0x10003 */;
        }

    case 132:
    case 127:
    case 121:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if (((which_alternative == 1) || (which_alternative == 6)) && (((m88k_cpu) == (CPU_M88100))))
        {
	  return 65538 /* 0x10002 */;
        }
      else
        {
	  return 65539 /* 0x10003 */;
        }

    case 117:
    case 114:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if ((which_alternative == 1) && (((m88k_cpu) == (CPU_M88100))))
        {
	  return 65538 /* 0x10002 */;
        }
      else
        {
	  return 65539 /* 0x10003 */;
        }

    case 107:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if (((which_alternative == 1) || (which_alternative == 8)) && (((m88k_cpu) == (CPU_M88100))))
        {
	  return 65538 /* 0x10002 */;
        }
      else
        {
	  return 65539 /* 0x10003 */;
        }

    case -1:
      if (GET_CODE (PATTERN (insn)) != ASM_INPUT
          && asm_noperands (PATTERN (insn)) < 0)
        fatal_insn_not_found (insn);
    default:
      return 65539 /* 0x10003 */;

    }
}

int
bit_unit_ready_cost (insn)
     rtx insn;
{
  switch (recog_memoized (insn))
    {
    case -1:
      if (GET_CODE (PATTERN (insn)) != ASM_INPUT
          && asm_noperands (PATTERN (insn)) < 0)
        fatal_insn_not_found (insn);
    default:
      return 2;

    }
}

int
alu_unit_ready_cost (insn)
     rtx insn;
{
  switch (recog_memoized (insn))
    {
    case 223:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if ((which_alternative == 0) && (! (((m88k_cpu) == (CPU_M88100)))))
        {
	  return 2;
        }
      else
        {
	  return 4;
        }

    case 158:
    case 156:
    case 154:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if (((which_alternative == 1) || (which_alternative == 2)) && (! (((m88k_cpu) == (CPU_M88100)))))
        {
	  return 2;
        }
      else
        {
	  return 4;
        }

    case 233:
    case 228:
    case 151:
    case 149:
    case 147:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if (((which_alternative == 0) || (which_alternative == 1)) && (! (((m88k_cpu) == (CPU_M88100)))))
        {
	  return 2;
        }
      else
        {
	  return 4;
        }

    case 132:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if ((((which_alternative == 3) || ((which_alternative == 4) || (which_alternative == 5))) && (! (((m88k_cpu) == (CPU_M88100))))) || ((which_alternative == 0) && (! (((m88k_cpu) == (CPU_M88100))))))
        {
	  return 2;
        }
      else
        {
	  return 4;
        }

    case 131:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if (((which_alternative == 1) && (! (((m88k_cpu) == (CPU_M88100))))) || ((which_alternative == 0) && (! (((m88k_cpu) == (CPU_M88100))))))
        {
	  return 2;
        }
      else
        {
	  return 4;
        }

    case 127:
    case 121:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if (((which_alternative == 3) || ((which_alternative == 4) || (which_alternative == 5))) && (! (((m88k_cpu) == (CPU_M88100)))))
        {
	  return 2;
        }
      else
        {
	  return 4;
        }

    case 264:
    case 262:
    case 126:
    case 120:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if ((which_alternative == 1) && (! (((m88k_cpu) == (CPU_M88100)))))
        {
	  return 2;
        }
      else
        {
	  return 4;
        }

    case 117:
    case 114:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if (((which_alternative != 1) && (which_alternative != 2)) && (! (((m88k_cpu) == (CPU_M88100)))))
        {
	  return 2;
        }
      else
        {
	  return 4;
        }

    case 108:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if (((which_alternative == 0) || ((which_alternative == 1) || (which_alternative == 2))) && (! (((m88k_cpu) == (CPU_M88100)))))
        {
	  return 2;
        }
      else
        {
	  return 4;
        }

    case 107:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if ((((which_alternative == 5) || ((which_alternative == 6) || (which_alternative == 7))) && (! (((m88k_cpu) == (CPU_M88100))))) || (((which_alternative == 0) || (which_alternative == 3)) && (! (((m88k_cpu) == (CPU_M88100))))))
        {
	  return 2;
        }
      else
        {
	  return 4;
        }

    case 278:
    case 265:
    case 263:
    case 260:
    case 255:
    case 253:
    case 236:
    case 231:
    case 226:
    case 221:
    case 220:
    case 219:
    case 218:
    case 217:
    case 216:
    case 215:
    case 194:
    case 193:
    case 192:
    case 182:
    case 181:
    case 180:
    case 179:
    case 169:
    case 133:
    case 128:
    case 122:
    case 118:
    case 115:
    case 112:
    case 111:
    case 110:
    case 109:
    case 104:
    case 103:
    case 81:
    case 76:
    case 57:
    case 38:
    case 36:
    case 34:
    case 32:
    case 28:
    case 27:
    case 26:
    case 25:
      if (! (((m88k_cpu) == (CPU_M88100))))
        {
	  return 2;
        }
      else
        {
	  return 4;
        }

    case -1:
      if (GET_CODE (PATTERN (insn)) != ASM_INPUT
          && asm_noperands (PATTERN (insn)) < 0)
        fatal_insn_not_found (insn);
    default:
      return 4;

    }
}

unsigned int
alu_unit_blockage_range (insn)
     rtx insn;
{
  switch (recog_memoized (insn))
    {
    case 233:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if ((which_alternative == 2) && (! (((m88k_cpu) == (CPU_M88100)))))
        {
	  return 65537 /* 0x10001 */;
        }
      else
        {
	  return 65539 /* 0x10003 */;
        }

    case 228:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if ((which_alternative == 3) && (! (((m88k_cpu) == (CPU_M88100)))))
        {
	  return 65537 /* 0x10001 */;
        }
      else
        {
	  return 65539 /* 0x10003 */;
        }

    case 223:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if ((which_alternative == 1) && (! (((m88k_cpu) == (CPU_M88100)))))
        {
	  return 65537 /* 0x10001 */;
        }
      else
        {
	  return 65539 /* 0x10003 */;
        }

    case 264:
    case 262:
    case 127:
    case 126:
    case 121:
    case 120:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if ((which_alternative == 0) && (! (((m88k_cpu) == (CPU_M88100)))))
        {
	  return 65537 /* 0x10001 */;
        }
      else
        {
	  return 65539 /* 0x10003 */;
        }

    case 108:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if ((which_alternative == 4) && (! (((m88k_cpu) == (CPU_M88100)))))
        {
	  return 65537 /* 0x10001 */;
        }
      else
        {
	  return 65539 /* 0x10003 */;
        }

    case -1:
      if (GET_CODE (PATTERN (insn)) != ASM_INPUT
          && asm_noperands (PATTERN (insn)) < 0)
        fatal_insn_not_found (insn);
    case 281:
    case 269:
    case 259:
    case 252:
    case 243:
    case 242:
    case 237:
    case 235:
    case 234:
    case 230:
    case 229:
    case 225:
    case 224:
    case 208:
    case 202:
    case 191:
    case 190:
    case 189:
    case 178:
    case 177:
    case 176:
    case 134:
    case 129:
    case 123:
    case 46:
    case 12:
      if (! (((m88k_cpu) == (CPU_M88100))))
        {
	  return 65537 /* 0x10001 */;
        }
      else
        {
	  return 65539 /* 0x10003 */;
        }

    default:
      return 65539 /* 0x10003 */;

    }
}

int
function_units_used (insn)
     rtx insn;
{
  switch (recog_memoized (insn))
    {
    case 233:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if (((which_alternative == 2) && (! (((m88k_cpu) == (CPU_M88100))))) || (((which_alternative == 0) || (which_alternative == 1)) && (! (((m88k_cpu) == (CPU_M88100))))))
        {
	  return 0;
        }
      else
        {
	  return -1 /* 0xffffffff */;
        }

    case 228:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if (((which_alternative == 3) && (! (((m88k_cpu) == (CPU_M88100))))) || (((which_alternative == 0) || (which_alternative == 1)) && (! (((m88k_cpu) == (CPU_M88100))))))
        {
	  return 0;
        }
      else if ((which_alternative == 2) && (! (((m88k_cpu) == (CPU_M88100)))))
        {
	  return 1;
        }
      else
        {
	  return -1 /* 0xffffffff */;
        }

    case 220:
    case 219:
    case 218:
    case 217:
    case 216:
      if (((m88k_cpu) == (CPU_M88100)))
        {
	  return 2;
        }
      else
        {
	  return 0;
        }

    case 214:
    case 213:
    case 212:
    case 211:
    case 210:
    case 207:
    case 205:
      if (((m88k_cpu) == (CPU_M88100)))
        {
	  return 6;
        }
      else
        {
	  return 8;
        }

    case 201:
    case 200:
    case 199:
    case 198:
    case 197:
    case 195:
      if (((m88k_cpu) == (CPU_M88100)))
        {
	  return 4;
        }
      else
        {
	  return 5;
        }

    case 168:
    case 165:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if ((which_alternative == 1) && (((m88k_cpu) == (CPU_M88100))))
        {
	  return 6;
        }
      else if ((which_alternative == 1) && (! (((m88k_cpu) == (CPU_M88100)))))
        {
	  return 7;
        }
      else if ((which_alternative == 0) && (((m88k_cpu) == (CPU_M88100))))
        {
	  return 6;
        }
      else if ((which_alternative == 0) && (! (((m88k_cpu) == (CPU_M88100)))))
        {
	  return 7;
        }
      else
        {
	  return -1 /* 0xffffffff */;
        }

    case 158:
    case 156:
    case 154:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if (((which_alternative == 1) || (which_alternative == 2)) && (! (((m88k_cpu) == (CPU_M88100)))))
        {
	  return 0;
        }
      else if ((which_alternative == 0) && (! (((m88k_cpu) == (CPU_M88100)))))
        {
	  return 1;
        }
      else if ((which_alternative == 3) && (((m88k_cpu) == (CPU_M88100))))
        {
	  return 2;
        }
      else if ((which_alternative == 3) && (! (((m88k_cpu) == (CPU_M88100)))))
        {
	  return 3;
        }
      else
        {
	  return -1 /* 0xffffffff */;
        }

    case 151:
    case 149:
    case 147:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if (((which_alternative == 0) || (which_alternative == 1)) && (! (((m88k_cpu) == (CPU_M88100)))))
        {
	  return 0;
        }
      else if ((which_alternative == 2) && (((m88k_cpu) == (CPU_M88100))))
        {
	  return 2;
        }
      else if ((which_alternative == 2) && (! (((m88k_cpu) == (CPU_M88100)))))
        {
	  return 3;
        }
      else
        {
	  return -1 /* 0xffffffff */;
        }

    case 241:
    case 240:
    case 239:
    case 238:
    case 143:
    case 142:
    case 141:
    case 140:
    case 139:
    case 138:
    case 137:
    case 136:
      if (((m88k_cpu) == (CPU_M88100)))
        {
	  return 2;
        }
      else
        {
	  return 3;
        }

    case 132:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if ((((which_alternative == 3) || ((which_alternative == 4) || (which_alternative == 5))) && (! (((m88k_cpu) == (CPU_M88100))))) || ((which_alternative == 0) && (! (((m88k_cpu) == (CPU_M88100))))))
        {
	  return 0;
        }
      else if (((which_alternative == 1) || (which_alternative == 6)) && (((m88k_cpu) == (CPU_M88100))))
        {
	  return 2;
        }
      else if (((which_alternative == 1) || (which_alternative == 6)) && (! (((m88k_cpu) == (CPU_M88100)))))
        {
	  return 3;
        }
      else if (((which_alternative != 0) && ((which_alternative != 1) && ((which_alternative != 3) && ((which_alternative != 4) && ((which_alternative != 5) && (which_alternative != 6)))))) && (((m88k_cpu) == (CPU_M88100))))
        {
	  return 2;
        }
      else if (((which_alternative != 0) && ((which_alternative != 1) && ((which_alternative != 3) && ((which_alternative != 4) && ((which_alternative != 5) && (which_alternative != 6)))))) && (! (((m88k_cpu) == (CPU_M88100)))))
        {
	  return 3;
        }
      else
        {
	  return -1 /* 0xffffffff */;
        }

    case 223:
    case 131:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if (((which_alternative == 1) && (! (((m88k_cpu) == (CPU_M88100))))) || ((which_alternative == 0) && (! (((m88k_cpu) == (CPU_M88100))))))
        {
	  return 0;
        }
      else
        {
	  return -1 /* 0xffffffff */;
        }

    case 127:
    case 121:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if (((which_alternative == 0) && (! (((m88k_cpu) == (CPU_M88100))))) || (((which_alternative == 3) || ((which_alternative == 4) || (which_alternative == 5))) && (! (((m88k_cpu) == (CPU_M88100))))))
        {
	  return 0;
        }
      else if (((which_alternative == 1) || (which_alternative == 6)) && (((m88k_cpu) == (CPU_M88100))))
        {
	  return 2;
        }
      else if (((which_alternative == 1) || (which_alternative == 6)) && (! (((m88k_cpu) == (CPU_M88100)))))
        {
	  return 3;
        }
      else if (((which_alternative != 0) && ((which_alternative != 1) && ((which_alternative != 3) && ((which_alternative != 4) && ((which_alternative != 5) && (which_alternative != 6)))))) && (((m88k_cpu) == (CPU_M88100))))
        {
	  return 2;
        }
      else if (((which_alternative != 0) && ((which_alternative != 1) && ((which_alternative != 3) && ((which_alternative != 4) && ((which_alternative != 5) && (which_alternative != 6)))))) && (! (((m88k_cpu) == (CPU_M88100)))))
        {
	  return 3;
        }
      else
        {
	  return -1 /* 0xffffffff */;
        }

    case 264:
    case 262:
    case 126:
    case 120:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if (((which_alternative == 0) && (! (((m88k_cpu) == (CPU_M88100))))) || ((which_alternative == 1) && (! (((m88k_cpu) == (CPU_M88100))))))
        {
	  return 0;
        }
      else
        {
	  return -1 /* 0xffffffff */;
        }

    case 117:
    case 114:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if (((which_alternative != 1) && (which_alternative != 2)) && (! (((m88k_cpu) == (CPU_M88100)))))
        {
	  return 0;
        }
      else if ((which_alternative == 1) && (((m88k_cpu) == (CPU_M88100))))
        {
	  return 2;
        }
      else if ((which_alternative == 1) && (! (((m88k_cpu) == (CPU_M88100)))))
        {
	  return 3;
        }
      else if ((which_alternative == 2) && (((m88k_cpu) == (CPU_M88100))))
        {
	  return 2;
        }
      else if ((which_alternative == 2) && (! (((m88k_cpu) == (CPU_M88100)))))
        {
	  return 3;
        }
      else
        {
	  return -1 /* 0xffffffff */;
        }

    case 108:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if (((which_alternative == 4) && (! (((m88k_cpu) == (CPU_M88100))))) || (((which_alternative == 0) || ((which_alternative == 1) || (which_alternative == 2))) && (! (((m88k_cpu) == (CPU_M88100))))))
        {
	  return 0;
        }
      else if ((which_alternative == 3) && (! (((m88k_cpu) == (CPU_M88100)))))
        {
	  return 1;
        }
      else
        {
	  return -1 /* 0xffffffff */;
        }

    case 107:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if ((((which_alternative == 5) || ((which_alternative == 6) || (which_alternative == 7))) && (! (((m88k_cpu) == (CPU_M88100))))) || (((which_alternative == 0) || (which_alternative == 3)) && (! (((m88k_cpu) == (CPU_M88100))))))
        {
	  return 0;
        }
      else if ((which_alternative == 4) && (! (((m88k_cpu) == (CPU_M88100)))))
        {
	  return 1;
        }
      else if (((which_alternative == 1) || (which_alternative == 8)) && (((m88k_cpu) == (CPU_M88100))))
        {
	  return 2;
        }
      else if (((which_alternative == 1) || (which_alternative == 8)) && (! (((m88k_cpu) == (CPU_M88100)))))
        {
	  return 3;
        }
      else if (((which_alternative == 2) || (which_alternative == 9)) && (((m88k_cpu) == (CPU_M88100))))
        {
	  return 2;
        }
      else if (((which_alternative == 2) || (which_alternative == 9)) && (! (((m88k_cpu) == (CPU_M88100)))))
        {
	  return 3;
        }
      else
        {
	  return -1 /* 0xffffffff */;
        }

    case 261:
    case 188:
    case 187:
    case 186:
    case 185:
    case 184:
    case 175:
    case 174:
    case 173:
    case 172:
    case 171:
    case 167:
    case 166:
    case 164:
    case 163:
    case 161:
    case 160:
    case 61:
    case 60:
    case 59:
    case 58:
      if (((m88k_cpu) == (CPU_M88100)))
        {
	  return 6;
        }
      else
        {
	  return 7;
        }

    case 280:
    case 279:
    case 275:
    case 273:
    case 271:
    case 268:
    case 102:
    case 101:
    case 100:
    case 99:
    case 98:
    case 97:
    case 96:
    case 95:
    case 94:
    case 52:
    case 51:
    case 50:
    case 49:
    case 48:
    case 47:
    case 45:
    case 44:
    case 43:
    case 42:
    case 41:
    case 40:
    case 39:
      return -1 /* 0xffffffff */;

    case 274:
    case 258:
    case 257:
    case 256:
    case 254:
    case 251:
    case 249:
    case 247:
    case 245:
    case 79:
    case 78:
    case 77:
    case 74:
    case 73:
    case 72:
    case 30:
    case 29:
    case 11:
    case 10:
    case 9:
    case 8:
      if (! (((m88k_cpu) == (CPU_M88100))))
        {
	  return 1;
        }
      else
        {
	  return -1 /* 0xffffffff */;
        }

    case -1:
      if (GET_CODE (PATTERN (insn)) != ASM_INPUT
          && asm_noperands (PATTERN (insn)) < 0)
        fatal_insn_not_found (insn);
    default:
      if (! (((m88k_cpu) == (CPU_M88100))))
        {
	  return 0;
        }
      else
        {
	  return -1 /* 0xffffffff */;
        }

    }
}

int
num_delay_slots (insn)
     rtx insn;
{
  switch (recog_memoized (insn))
    {
    case 280:
    case 279:
    case 275:
    case 273:
    case 271:
    case 268:
    case 102:
    case 101:
    case 100:
    case 99:
    case 98:
    case 97:
    case 96:
    case 95:
    case 94:
    case 52:
    case 51:
    case 50:
    case 49:
    case 48:
    case 47:
    case 45:
    case 44:
    case 43:
    case 42:
    case 41:
    case 40:
    case 39:
      return 1;

    case -1:
      if (GET_CODE (PATTERN (insn)) != ASM_INPUT
          && asm_noperands (PATTERN (insn)) < 0)
        fatal_insn_not_found (insn);
    default:
      return 0;

    }
}

enum attr_cpu
get_attr_cpu ()
{
	return CPU_M88100;
}

enum attr_fpu
get_attr_fpu (insn)
     rtx insn;
{
  switch (recog_memoized (insn))
    {
    case 261:
    case 214:
    case 213:
    case 212:
    case 211:
    case 210:
    case 207:
    case 205:
    case 201:
    case 200:
    case 199:
    case 198:
    case 197:
    case 195:
    case 188:
    case 187:
    case 186:
    case 185:
    case 184:
    case 175:
    case 174:
    case 173:
    case 172:
    case 171:
    case 168:
    case 167:
    case 166:
    case 165:
    case 164:
    case 163:
    case 161:
    case 160:
    case 61:
    case 60:
    case 59:
    case 58:
      return FPU_YES;

    case -1:
      if (GET_CODE (PATTERN (insn)) != ASM_INPUT
          && asm_noperands (PATTERN (insn)) < 0)
        fatal_insn_not_found (insn);
    default:
      return FPU_NO;

    }
}

enum attr_type
get_attr_type (insn)
     rtx insn;
{
  switch (recog_memoized (insn))
    {
    case 233:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if ((which_alternative == 0) || (which_alternative == 1))
        {
	  return TYPE_ARITH;
        }
      else
        {
	  return TYPE_MARITH;
        }

    case 228:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if ((which_alternative == 0) || (which_alternative == 1))
        {
	  return TYPE_ARITH;
        }
      else if (which_alternative == 2)
        {
	  return TYPE_BIT;
        }
      else
        {
	  return TYPE_MARITH;
        }

    case 158:
    case 156:
    case 154:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if (which_alternative == 0)
        {
	  return TYPE_BIT;
        }
      else if ((which_alternative == 1) || (which_alternative == 2))
        {
	  return TYPE_ARITH;
        }
      else
        {
	  return TYPE_LOAD;
        }

    case 151:
    case 149:
    case 147:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if ((which_alternative == 0) || (which_alternative == 1))
        {
	  return TYPE_ARITH;
        }
      else
        {
	  return TYPE_LOAD;
        }

    case 132:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if (which_alternative == 0)
        {
	  return TYPE_ARITH;
        }
      else if (which_alternative == 1)
        {
	  return TYPE_LOAD;
        }
      else if (which_alternative == 2)
        {
	  return TYPE_STORE;
        }
      else if ((which_alternative == 3) || ((which_alternative == 4) || (which_alternative == 5)))
        {
	  return TYPE_MOV;
        }
      else if (which_alternative == 6)
        {
	  return TYPE_LOAD;
        }
      else
        {
	  return TYPE_STORE;
        }

    case 127:
    case 121:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if (which_alternative == 0)
        {
	  return TYPE_MARITH;
        }
      else if (which_alternative == 1)
        {
	  return TYPE_LOADD;
        }
      else if (which_alternative == 2)
        {
	  return TYPE_STORE;
        }
      else if ((which_alternative == 3) || ((which_alternative == 4) || (which_alternative == 5)))
        {
	  return TYPE_MOV;
        }
      else if (which_alternative == 6)
        {
	  return TYPE_LOADD;
        }
      else
        {
	  return TYPE_STORE;
        }

    case 108:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if ((which_alternative == 0) || ((which_alternative == 1) || (which_alternative == 2)))
        {
	  return TYPE_ARITH;
        }
      else if (which_alternative == 3)
        {
	  return TYPE_BIT;
        }
      else
        {
	  return TYPE_MARITH;
        }

    case 107:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if (which_alternative == 0)
        {
	  return TYPE_ARITH;
        }
      else if (which_alternative == 1)
        {
	  return TYPE_LOAD;
        }
      else if (which_alternative == 2)
        {
	  return TYPE_STORE;
        }
      else if (which_alternative == 3)
        {
	  return TYPE_ARITH;
        }
      else if (which_alternative == 4)
        {
	  return TYPE_BIT;
        }
      else if ((which_alternative == 5) || ((which_alternative == 6) || (which_alternative == 7)))
        {
	  return TYPE_MOV;
        }
      else if (which_alternative == 8)
        {
	  return TYPE_LOAD;
        }
      else
        {
	  return TYPE_STORE;
        }

    case 114:
    case 117:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if (which_alternative == 0)
        {
	  return TYPE_ARITH;
        }
      else if (which_alternative == 1)
        {
	  return TYPE_LOAD;
        }
      else if (which_alternative == 2)
        {
	  return TYPE_STORE;
        }
      else
        {
	  return TYPE_ARITH;
        }

    case 120:
    case 126:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if (which_alternative == 0)
        {
	  return TYPE_MARITH;
        }
      else
        {
	  return TYPE_MOV;
        }

    case 131:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if (which_alternative == 0)
        {
	  return TYPE_ARITH;
        }
      else
        {
	  return TYPE_MOV;
        }

    case 165:
    case 168:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if (which_alternative == 0)
        {
	  return TYPE_SPADD;
        }
      else
        {
	  return TYPE_DPADD;
        }

    case 223:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if (which_alternative == 0)
        {
	  return TYPE_ARITH;
        }
      else
        {
	  return TYPE_MARITH;
        }

    case 262:
    case 264:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if (which_alternative == 0)
        {
	  return TYPE_MARITH;
        }
      else
        {
	  return TYPE_ARITH;
        }

    case -1:
      if (GET_CODE (PATTERN (insn)) != ASM_INPUT
          && asm_noperands (PATTERN (insn)) < 0)
        fatal_insn_not_found (insn);
    case 46:
    case 202:
    case 208:
    case 242:
    case 243:
    case 269:
    case 281:
      return TYPE_WEIRD;

    case 12:
    case 123:
    case 129:
    case 134:
    case 176:
    case 177:
    case 178:
    case 189:
    case 190:
    case 191:
    case 224:
    case 225:
    case 229:
    case 230:
    case 234:
    case 235:
    case 237:
    case 252:
    case 259:
      return TYPE_MARITH;

    case 8:
    case 9:
    case 10:
    case 11:
    case 29:
    case 30:
    case 72:
    case 73:
    case 74:
    case 77:
    case 78:
    case 79:
    case 245:
    case 247:
    case 249:
    case 251:
    case 254:
    case 256:
    case 257:
    case 258:
    case 274:
      return TYPE_BIT;

    case 195:
      return TYPE_IMUL;

    case 200:
      return TYPE_DPMUL;

    case 197:
    case 198:
    case 199:
    case 201:
      return TYPE_SPMUL;

    case 205:
    case 207:
      return TYPE_IDIV;

    case 210:
    case 211:
    case 212:
    case 214:
      return TYPE_DPDIV;

    case 213:
      return TYPE_SPDIV;

    case 59:
    case 60:
    case 61:
      return TYPE_DPCMP;

    case 58:
      return TYPE_SPCMP;

    case 163:
    case 164:
    case 167:
    case 172:
    case 173:
    case 174:
    case 185:
    case 186:
    case 187:
    case 261:
      return TYPE_DPADD;

    case 160:
    case 161:
    case 166:
    case 171:
    case 175:
    case 184:
    case 188:
      return TYPE_SPADD;

    case 216:
    case 217:
    case 218:
    case 219:
    case 220:
      return TYPE_LOADA;

    case 139:
      return TYPE_LOADD;

    case 140:
    case 141:
    case 142:
    case 143:
      return TYPE_STORE;

    case 136:
    case 137:
    case 138:
    case 238:
    case 239:
    case 240:
    case 241:
      return TYPE_LOAD;

    case 271:
    case 273:
      return TYPE_CALL;

    case 268:
    case 275:
    case 279:
    case 280:
      return TYPE_JUMP;

    case 39:
    case 40:
    case 41:
    case 42:
    case 43:
    case 44:
    case 45:
    case 47:
    case 48:
    case 49:
    case 50:
    case 51:
    case 52:
    case 94:
    case 95:
    case 96:
    case 97:
    case 98:
    case 99:
    case 100:
    case 101:
    case 102:
      return TYPE_BRANCH;

    default:
      return TYPE_ARITH;

    }
}

int
eligible_for_delay (delay_insn, slot, candidate_insn, flags)
     rtx delay_insn;
     int slot;
     rtx candidate_insn;
     int flags;
{
  rtx insn;

  if (slot >= 1)
    abort ();

  insn = delay_insn;
  switch (recog_memoized (insn))
    {
    case 273:
    case 271:
      slot += 2 * 1;
      break;
      break;

    case 280:
    case 279:
    case 275:
    case 268:
    case 102:
    case 101:
    case 100:
    case 99:
    case 98:
    case 97:
    case 96:
    case 95:
    case 94:
    case 52:
    case 51:
    case 50:
    case 49:
    case 48:
    case 47:
    case 45:
    case 44:
    case 43:
    case 42:
    case 41:
    case 40:
    case 39:
      slot += 1 * 1;
      break;
      break;

    case -1:
      if (GET_CODE (PATTERN (insn)) != ASM_INPUT
          && asm_noperands (PATTERN (insn)) < 0)
        fatal_insn_not_found (insn);
    default:
      slot += 0 * 1;
      break;
      break;

    }

  if (slot < 1)
    abort ();

  insn = candidate_insn;
  switch (slot)
    {
    case 2:
      switch (recog_memoized (insn))
	{
        case 233:
	  insn_extract (insn);
	  if (! constrain_operands (INSN_CODE (insn), reload_completed))
	    fatal_insn_not_found (insn);
	  if ((which_alternative == 0) || (which_alternative == 1))
	    {
	      return 1;
	    }
	  else
	    {
	      return 0;
	    }

        case 228:
	  insn_extract (insn);
	  if (! constrain_operands (INSN_CODE (insn), reload_completed))
	    fatal_insn_not_found (insn);
	  if (which_alternative != 3)
	    {
	      return 1;
	    }
	  else
	    {
	      return 0;
	    }

        case 223:
	  insn_extract (insn);
	  if (! constrain_operands (INSN_CODE (insn), reload_completed))
	    fatal_insn_not_found (insn);
	  if (which_alternative == 0)
	    {
	      return 1;
	    }
	  else
	    {
	      return 0;
	    }

        case 264:
        case 262:
        case 127:
        case 126:
        case 121:
        case 120:
	  insn_extract (insn);
	  if (! constrain_operands (INSN_CODE (insn), reload_completed))
	    fatal_insn_not_found (insn);
	  if (which_alternative != 0)
	    {
	      return 1;
	    }
	  else
	    {
	      return 0;
	    }

        case 108:
	  insn_extract (insn);
	  if (! constrain_operands (INSN_CODE (insn), reload_completed))
	    fatal_insn_not_found (insn);
	  if (which_alternative != 4)
	    {
	      return 1;
	    }
	  else
	    {
	      return 0;
	    }

        case -1:
	  if (GET_CODE (PATTERN (insn)) != ASM_INPUT
	      && asm_noperands (PATTERN (insn)) < 0)
	    fatal_insn_not_found (insn);
        case 281:
        case 273:
        case 271:
        case 269:
        case 259:
        case 252:
        case 243:
        case 242:
        case 237:
        case 235:
        case 234:
        case 230:
        case 229:
        case 225:
        case 224:
        case 208:
        case 202:
        case 191:
        case 190:
        case 189:
        case 178:
        case 177:
        case 176:
        case 134:
        case 129:
        case 123:
        case 102:
        case 101:
        case 100:
        case 99:
        case 98:
        case 97:
        case 96:
        case 95:
        case 94:
        case 52:
        case 51:
        case 50:
        case 49:
        case 48:
        case 47:
        case 46:
        case 45:
        case 44:
        case 43:
        case 42:
        case 41:
        case 40:
        case 39:
        case 12:
	  return 0;

        default:
	  return 1;

      }
    case 1:
      switch (recog_memoized (insn))
	{
        case 228:
	  insn_extract (insn);
	  if (! constrain_operands (INSN_CODE (insn), reload_completed))
	    fatal_insn_not_found (insn);
	  if (which_alternative != 3)
	    {
	      return 1;
	    }
	  else
	    {
	      return 0;
	    }

        case 223:
	  insn_extract (insn);
	  if (! constrain_operands (INSN_CODE (insn), reload_completed))
	    fatal_insn_not_found (insn);
	  if (which_alternative == 0)
	    {
	      return 1;
	    }
	  else
	    {
	      return 0;
	    }

        case 158:
        case 156:
        case 154:
	  insn_extract (insn);
	  if (! constrain_operands (INSN_CODE (insn), reload_completed))
	    fatal_insn_not_found (insn);
	  if ((which_alternative == 0) || ((which_alternative == 1) || (which_alternative == 2)))
	    {
	      return 1;
	    }
	  else
	    {
	      return 0;
	    }

        case 233:
        case 151:
        case 149:
        case 147:
	  insn_extract (insn);
	  if (! constrain_operands (INSN_CODE (insn), reload_completed))
	    fatal_insn_not_found (insn);
	  if ((which_alternative == 0) || (which_alternative == 1))
	    {
	      return 1;
	    }
	  else
	    {
	      return 0;
	    }

        case 132:
	  insn_extract (insn);
	  if (! constrain_operands (INSN_CODE (insn), reload_completed))
	    fatal_insn_not_found (insn);
	  if ((which_alternative != 1) && (which_alternative != 6))
	    {
	      return 1;
	    }
	  else
	    {
	      return 0;
	    }

        case 127:
        case 121:
	  insn_extract (insn);
	  if (! constrain_operands (INSN_CODE (insn), reload_completed))
	    fatal_insn_not_found (insn);
	  if ((which_alternative != 0) && ((which_alternative != 1) && (which_alternative != 6)))
	    {
	      return 1;
	    }
	  else
	    {
	      return 0;
	    }

        case 264:
        case 262:
        case 126:
        case 120:
	  insn_extract (insn);
	  if (! constrain_operands (INSN_CODE (insn), reload_completed))
	    fatal_insn_not_found (insn);
	  if (which_alternative != 0)
	    {
	      return 1;
	    }
	  else
	    {
	      return 0;
	    }

        case 117:
        case 114:
	  insn_extract (insn);
	  if (! constrain_operands (INSN_CODE (insn), reload_completed))
	    fatal_insn_not_found (insn);
	  if (which_alternative != 1)
	    {
	      return 1;
	    }
	  else
	    {
	      return 0;
	    }

        case 108:
	  insn_extract (insn);
	  if (! constrain_operands (INSN_CODE (insn), reload_completed))
	    fatal_insn_not_found (insn);
	  if (which_alternative != 4)
	    {
	      return 1;
	    }
	  else
	    {
	      return 0;
	    }

        case 107:
	  insn_extract (insn);
	  if (! constrain_operands (INSN_CODE (insn), reload_completed))
	    fatal_insn_not_found (insn);
	  if ((which_alternative != 1) && (which_alternative != 8))
	    {
	      return 1;
	    }
	  else
	    {
	      return 0;
	    }

        case 278:
        case 274:
        case 265:
        case 263:
        case 260:
        case 258:
        case 257:
        case 256:
        case 255:
        case 254:
        case 253:
        case 251:
        case 249:
        case 247:
        case 245:
        case 236:
        case 231:
        case 226:
        case 221:
        case 220:
        case 219:
        case 218:
        case 217:
        case 216:
        case 215:
        case 194:
        case 193:
        case 192:
        case 182:
        case 181:
        case 180:
        case 179:
        case 169:
        case 143:
        case 142:
        case 141:
        case 140:
        case 133:
        case 131:
        case 128:
        case 122:
        case 118:
        case 115:
        case 112:
        case 111:
        case 110:
        case 109:
        case 104:
        case 103:
        case 81:
        case 79:
        case 78:
        case 77:
        case 76:
        case 74:
        case 73:
        case 72:
        case 57:
        case 38:
        case 36:
        case 34:
        case 32:
        case 30:
        case 29:
        case 28:
        case 27:
        case 26:
        case 25:
        case 11:
        case 10:
        case 9:
        case 8:
	  return 1;

        case -1:
	  if (GET_CODE (PATTERN (insn)) != ASM_INPUT
	      && asm_noperands (PATTERN (insn)) < 0)
	    fatal_insn_not_found (insn);
        default:
	  return 0;

      }
    default:
      abort ();
    }
}

int
eligible_for_annul_true (delay_insn, slot, candidate_insn, flags)
     rtx delay_insn;
     int slot;
     rtx candidate_insn;
     int flags;
{
  rtx insn;

  if (slot >= 1)
    abort ();

  insn = delay_insn;
  switch (recog_memoized (insn))
    {
    case 273:
    case 271:
      slot += 2 * 1;
      break;
      break;

    case 280:
    case 279:
    case 275:
    case 268:
    case 102:
    case 101:
    case 100:
    case 99:
    case 98:
    case 97:
    case 96:
    case 95:
    case 94:
    case 52:
    case 51:
    case 50:
    case 49:
    case 48:
    case 47:
    case 45:
    case 44:
    case 43:
    case 42:
    case 41:
    case 40:
    case 39:
      slot += 1 * 1;
      break;
      break;

    case -1:
      if (GET_CODE (PATTERN (insn)) != ASM_INPUT
          && asm_noperands (PATTERN (insn)) < 0)
        fatal_insn_not_found (insn);
    default:
      slot += 0 * 1;
      break;
      break;

    }

  if (slot < 1)
    abort ();

  insn = candidate_insn;
  switch (slot)
    {
    case 2:
      switch (recog_memoized (insn))
	{
        case -1:
	  if (GET_CODE (PATTERN (insn)) != ASM_INPUT
	      && asm_noperands (PATTERN (insn)) < 0)
	    fatal_insn_not_found (insn);
        default:
	  return 0;

      }
    case 1:
      switch (recog_memoized (insn))
	{
        case 280:
        case 279:
        case 275:
        case 273:
        case 271:
        case 268:
        case 102:
        case 101:
        case 100:
        case 99:
        case 98:
        case 97:
        case 96:
        case 95:
        case 94:
        case 52:
        case 51:
        case 50:
        case 49:
        case 48:
        case 47:
        case 45:
        case 44:
        case 43:
        case 42:
        case 41:
        case 40:
        case 39:
	  return 0;

        case -1:
	  if (GET_CODE (PATTERN (insn)) != ASM_INPUT
	      && asm_noperands (PATTERN (insn)) < 0)
	    fatal_insn_not_found (insn);
        default:
	  return 1;

      }
    default:
      abort ();
    }
}

static int
div_unit_blockage (executing_insn, candidate_insn)
     rtx executing_insn;
     rtx candidate_insn;
{
  rtx insn;
  int casenum;

  insn = executing_insn;
  switch (recog_memoized (insn))
    {
    case 213:
      casenum = 0;
      break;

    case 214:
    case 212:
    case 211:
    case 210:
      casenum = 1;
      break;

    case -1:
      if (GET_CODE (PATTERN (insn)) != ASM_INPUT
          && asm_noperands (PATTERN (insn)) < 0)
        fatal_insn_not_found (insn);
    default:
      casenum = 2;
      break;

    }

  insn = candidate_insn;
  switch (casenum)
    {
    case 0:
      return 25 /* 0x19 */;

    case 1:
      return 45 /* 0x2d */;

    case 2:
      return 35 /* 0x23 */;

    }
}

static int
fpadd110_unit_blockage (executing_insn, candidate_insn)
     rtx executing_insn;
     rtx candidate_insn;
{
  rtx insn;
  int casenum;

  insn = executing_insn;
  switch (recog_memoized (insn))
    {
    case 261:
    case 188:
    case 187:
    case 186:
    case 185:
    case 184:
    case 175:
    case 174:
    case 173:
    case 172:
    case 171:
    case 168:
    case 167:
    case 166:
    case 165:
    case 164:
    case 163:
    case 161:
    case 160:
      casenum = 0;
      break;

    case -1:
      if (GET_CODE (PATTERN (insn)) != ASM_INPUT
          && asm_noperands (PATTERN (insn)) < 0)
        fatal_insn_not_found (insn);
    default:
      casenum = 1;
      break;

    }

  insn = candidate_insn;
  switch (casenum)
    {
    case 0:
      switch (recog_memoized (insn))
	{
        case 168:
        case 165:
	  insn_extract (insn);
	  if (! constrain_operands (INSN_CODE (insn), reload_completed))
	    fatal_insn_not_found (insn);
	  return 2;

        case 261:
        case 188:
        case 187:
        case 186:
        case 185:
        case 184:
        case 175:
        case 174:
        case 173:
        case 172:
        case 171:
        case 167:
        case 166:
        case 164:
        case 163:
        case 161:
        case 160:
	  return 2;

        case -1:
	  if (GET_CODE (PATTERN (insn)) != ASM_INPUT
	      && asm_noperands (PATTERN (insn)) < 0)
	    fatal_insn_not_found (insn);
        default:
	  return 4;

      }

    case 1:
      return 2;

    }
}

static int
fpadd100_unit_blockage (executing_insn, candidate_insn)
     rtx executing_insn;
     rtx candidate_insn;
{
  rtx insn;
  int casenum;

  insn = executing_insn;
  switch (recog_memoized (insn))
    {
    case 213:
      casenum = 2;
      break;

    case 214:
    case 212:
    case 211:
    case 210:
      casenum = 3;
      break;

    case 168:
    case 165:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if ((which_alternative == 0) && (((m88k_cpu) == (CPU_M88100))))
        {
	  casenum = 0;
        }
      else if ((which_alternative == 1) && (((m88k_cpu) == (CPU_M88100))))
        {
	  casenum = 1;
        }
      else
        {
	  casenum = 4;
        }
      break;

    case 261:
    case 187:
    case 186:
    case 185:
    case 174:
    case 173:
    case 172:
    case 167:
    case 164:
    case 163:
    case 61:
    case 60:
    case 59:
      casenum = 1;
      break;

    case 188:
    case 184:
    case 175:
    case 171:
    case 166:
    case 161:
    case 160:
    case 58:
      casenum = 0;
      break;

    case -1:
      if (GET_CODE (PATTERN (insn)) != ASM_INPUT
          && asm_noperands (PATTERN (insn)) < 0)
        fatal_insn_not_found (insn);
    default:
      casenum = 4;
      break;

    }

  insn = candidate_insn;
  switch (casenum)
    {
    case 0:
      return 1;

    case 1:
      switch (recog_memoized (insn))
	{
        case 168:
        case 165:
	  insn_extract (insn);
	  if (! constrain_operands (INSN_CODE (insn), reload_completed))
	    fatal_insn_not_found (insn);
	  if ((which_alternative == 1) && (((m88k_cpu) == (CPU_M88100))))
	    {
	      return 1;
	    }
	  else
	    {
	      return 2;
	    }

        case 261:
        case 214:
        case 213:
        case 212:
        case 211:
        case 210:
        case 207:
        case 205:
        case 187:
        case 186:
        case 185:
        case 174:
        case 173:
        case 172:
        case 167:
        case 164:
        case 163:
        case 61:
        case 60:
        case 59:
	  return 1;

        case -1:
	  if (GET_CODE (PATTERN (insn)) != ASM_INPUT
	      && asm_noperands (PATTERN (insn)) < 0)
	    fatal_insn_not_found (insn);
        default:
	  return 2;

      }

    case 2:
      switch (recog_memoized (insn))
	{
        case 214:
        case 213:
        case 212:
        case 211:
        case 210:
        case 207:
        case 205:
	  return 26 /* 0x1a */;

        case 168:
        case 165:
	  insn_extract (insn);
	  if (! constrain_operands (INSN_CODE (insn), reload_completed))
	    fatal_insn_not_found (insn);
	  if ((which_alternative == 1) && (((m88k_cpu) == (CPU_M88100))))
	    {
	      return 27 /* 0x1b */;
	    }
	  else
	    {
	      return 28 /* 0x1c */;
	    }

        case 261:
        case 187:
        case 186:
        case 185:
        case 174:
        case 173:
        case 172:
        case 167:
        case 164:
        case 163:
        case 61:
        case 60:
        case 59:
	  return 27 /* 0x1b */;

        case -1:
	  if (GET_CODE (PATTERN (insn)) != ASM_INPUT
	      && asm_noperands (PATTERN (insn)) < 0)
	    fatal_insn_not_found (insn);
        default:
	  return 28 /* 0x1c */;

      }

    case 3:
      switch (recog_memoized (insn))
	{
        case 214:
        case 213:
        case 212:
        case 211:
        case 210:
        case 207:
        case 205:
	  return 56 /* 0x38 */;

        case 168:
        case 165:
	  insn_extract (insn);
	  if (! constrain_operands (INSN_CODE (insn), reload_completed))
	    fatal_insn_not_found (insn);
	  if ((which_alternative == 1) && (((m88k_cpu) == (CPU_M88100))))
	    {
	      return 57 /* 0x39 */;
	    }
	  else
	    {
	      return 58 /* 0x3a */;
	    }

        case 261:
        case 187:
        case 186:
        case 185:
        case 174:
        case 173:
        case 172:
        case 167:
        case 164:
        case 163:
        case 61:
        case 60:
        case 59:
	  return 57 /* 0x39 */;

        case -1:
	  if (GET_CODE (PATTERN (insn)) != ASM_INPUT
	      && asm_noperands (PATTERN (insn)) < 0)
	    fatal_insn_not_found (insn);
        default:
	  return 58 /* 0x3a */;

      }

    case 4:
      switch (recog_memoized (insn))
	{
        case 214:
        case 213:
        case 212:
        case 211:
        case 210:
        case 207:
        case 205:
	  return 34 /* 0x22 */;

        case 168:
        case 165:
	  insn_extract (insn);
	  if (! constrain_operands (INSN_CODE (insn), reload_completed))
	    fatal_insn_not_found (insn);
	  if ((which_alternative == 1) && (((m88k_cpu) == (CPU_M88100))))
	    {
	      return 35 /* 0x23 */;
	    }
	  else
	    {
	      return 36 /* 0x24 */;
	    }

        case 261:
        case 187:
        case 186:
        case 185:
        case 174:
        case 173:
        case 172:
        case 167:
        case 164:
        case 163:
        case 61:
        case 60:
        case 59:
	  return 35 /* 0x23 */;

        case -1:
	  if (GET_CODE (PATTERN (insn)) != ASM_INPUT
	      && asm_noperands (PATTERN (insn)) < 0)
	    fatal_insn_not_found (insn);
        default:
	  return 36 /* 0x24 */;

      }

    }
}

static int
fpmul100_unit_blockage (executing_insn, candidate_insn)
     rtx executing_insn;
     rtx candidate_insn;
{
  rtx insn;
  int casenum;

  insn = executing_insn;
  switch (recog_memoized (insn))
    {
    case 200:
      casenum = 1;
      break;

    case 201:
    case 199:
    case 198:
    case 197:
      casenum = 0;
      break;

    case -1:
      if (GET_CODE (PATTERN (insn)) != ASM_INPUT
          && asm_noperands (PATTERN (insn)) < 0)
        fatal_insn_not_found (insn);
    default:
      casenum = 2;
      break;

    }

  insn = candidate_insn;
  switch (casenum)
    {
    case 0:
      switch (recog_memoized (insn))
	{
        case 201:
        case 200:
        case 199:
        case 198:
        case 197:
	  return 1;

        case -1:
	  if (GET_CODE (PATTERN (insn)) != ASM_INPUT
	      && asm_noperands (PATTERN (insn)) < 0)
	    fatal_insn_not_found (insn);
        default:
	  return 2;

      }

    case 1:
      switch (recog_memoized (insn))
	{
        case 200:
	  return 1;

        case 201:
        case 199:
        case 198:
        case 197:
	  return 4;

        case -1:
	  if (GET_CODE (PATTERN (insn)) != ASM_INPUT
	      && asm_noperands (PATTERN (insn)) < 0)
	    fatal_insn_not_found (insn);
        default:
	  return 5;

      }

    case 2:
      return 1;

    }
}

static int
mem110_unit_blockage (executing_insn, candidate_insn)
     rtx executing_insn;
     rtx candidate_insn;
{
  rtx insn;
  int casenum;

  insn = executing_insn;
  switch (recog_memoized (insn))
    {
    case 158:
    case 156:
    case 154:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      casenum = 0;
      break;

    case 151:
    case 149:
    case 147:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      casenum = 0;
      break;

    case 241:
    case 240:
    case 239:
    case 238:
    case 139:
    case 138:
    case 137:
    case 136:
      casenum = 0;
      break;

    case 132:
    case 127:
    case 121:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if (((which_alternative == 1) || (which_alternative == 6)) && (! (((m88k_cpu) == (CPU_M88100)))))
        {
	  casenum = 0;
        }
      else
        {
	  casenum = 1;
        }
      break;

    case 117:
    case 114:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if ((which_alternative == 1) && (! (((m88k_cpu) == (CPU_M88100)))))
        {
	  casenum = 0;
        }
      else
        {
	  casenum = 1;
        }
      break;

    case 107:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if (((which_alternative == 1) || (which_alternative == 8)) && (! (((m88k_cpu) == (CPU_M88100)))))
        {
	  casenum = 0;
        }
      else
        {
	  casenum = 1;
        }
      break;

    case -1:
      if (GET_CODE (PATTERN (insn)) != ASM_INPUT
          && asm_noperands (PATTERN (insn)) < 0)
        fatal_insn_not_found (insn);
    default:
      casenum = 1;
      break;

    }

  insn = candidate_insn;
  switch (casenum)
    {
    case 0:
      switch (recog_memoized (insn))
	{
        case 158:
        case 156:
        case 154:
	  insn_extract (insn);
	  if (! constrain_operands (INSN_CODE (insn), reload_completed))
	    fatal_insn_not_found (insn);
	  return 2;

        case 151:
        case 149:
        case 147:
	  insn_extract (insn);
	  if (! constrain_operands (INSN_CODE (insn), reload_completed))
	    fatal_insn_not_found (insn);
	  return 2;

        case 241:
        case 240:
        case 239:
        case 238:
        case 139:
        case 138:
        case 137:
        case 136:
	  return 2;

        case 132:
        case 127:
        case 121:
	  insn_extract (insn);
	  if (! constrain_operands (INSN_CODE (insn), reload_completed))
	    fatal_insn_not_found (insn);
	  if (((which_alternative == 1) || (which_alternative == 6)) && (! (((m88k_cpu) == (CPU_M88100)))))
	    {
	      return 2;
	    }
	  else
	    {
	      return 3;
	    }

        case 117:
        case 114:
	  insn_extract (insn);
	  if (! constrain_operands (INSN_CODE (insn), reload_completed))
	    fatal_insn_not_found (insn);
	  if ((which_alternative == 1) && (! (((m88k_cpu) == (CPU_M88100)))))
	    {
	      return 2;
	    }
	  else
	    {
	      return 3;
	    }

        case 107:
	  insn_extract (insn);
	  if (! constrain_operands (INSN_CODE (insn), reload_completed))
	    fatal_insn_not_found (insn);
	  if (((which_alternative == 1) || (which_alternative == 8)) && (! (((m88k_cpu) == (CPU_M88100)))))
	    {
	      return 2;
	    }
	  else
	    {
	      return 3;
	    }

        case -1:
	  if (GET_CODE (PATTERN (insn)) != ASM_INPUT
	      && asm_noperands (PATTERN (insn)) < 0)
	    fatal_insn_not_found (insn);
        default:
	  return 3;

      }

    case 1:
      return 2;

    }
}

static int
mem100_unit_blockage (executing_insn, candidate_insn)
     rtx executing_insn;
     rtx candidate_insn;
{
  rtx insn;
  int casenum;

  insn = executing_insn;
  switch (recog_memoized (insn))
    {
    case 158:
    case 156:
    case 154:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      casenum = 1;
      break;

    case 151:
    case 149:
    case 147:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      casenum = 1;
      break;

    case 220:
    case 219:
    case 218:
    case 217:
    case 216:
    case 143:
    case 142:
    case 141:
    case 140:
      casenum = 0;
      break;

    case 241:
    case 240:
    case 239:
    case 238:
    case 138:
    case 137:
    case 136:
      casenum = 1;
      break;

    case 132:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if (((which_alternative != 0) && ((which_alternative != 1) && ((which_alternative != 3) && ((which_alternative != 4) && ((which_alternative != 5) && (which_alternative != 6)))))) && (((m88k_cpu) == (CPU_M88100))))
        {
	  casenum = 0;
        }
      else if (((which_alternative == 1) || (which_alternative == 6)) && (((m88k_cpu) == (CPU_M88100))))
        {
	  casenum = 1;
        }
      else
        {
	  casenum = 2;
        }
      break;

    case 127:
    case 121:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if (((which_alternative != 0) && ((which_alternative != 1) && ((which_alternative != 3) && ((which_alternative != 4) && ((which_alternative != 5) && (which_alternative != 6)))))) && (((m88k_cpu) == (CPU_M88100))))
        {
	  casenum = 0;
        }
      else
        {
	  casenum = 2;
        }
      break;

    case 117:
    case 114:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if ((which_alternative == 2) && (((m88k_cpu) == (CPU_M88100))))
        {
	  casenum = 0;
        }
      else if ((which_alternative == 1) && (((m88k_cpu) == (CPU_M88100))))
        {
	  casenum = 1;
        }
      else
        {
	  casenum = 2;
        }
      break;

    case 107:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if (((which_alternative == 2) || (which_alternative == 9)) && (((m88k_cpu) == (CPU_M88100))))
        {
	  casenum = 0;
        }
      else if (((which_alternative == 1) || (which_alternative == 8)) && (((m88k_cpu) == (CPU_M88100))))
        {
	  casenum = 1;
        }
      else
        {
	  casenum = 2;
        }
      break;

    case -1:
      if (GET_CODE (PATTERN (insn)) != ASM_INPUT
          && asm_noperands (PATTERN (insn)) < 0)
        fatal_insn_not_found (insn);
    default:
      casenum = 2;
      break;

    }

  insn = candidate_insn;
  switch (casenum)
    {
    case 0:
      return 1;

    case 1:
      switch (recog_memoized (insn))
	{
        case 158:
        case 156:
        case 154:
	  insn_extract (insn);
	  if (! constrain_operands (INSN_CODE (insn), reload_completed))
	    fatal_insn_not_found (insn);
	  return 1;

        case 151:
        case 149:
        case 147:
	  insn_extract (insn);
	  if (! constrain_operands (INSN_CODE (insn), reload_completed))
	    fatal_insn_not_found (insn);
	  return 1;

        case 241:
        case 240:
        case 239:
        case 238:
        case 139:
        case 138:
        case 137:
        case 136:
	  return 1;

        case 132:
        case 127:
        case 121:
	  insn_extract (insn);
	  if (! constrain_operands (INSN_CODE (insn), reload_completed))
	    fatal_insn_not_found (insn);
	  if (((which_alternative == 1) || (which_alternative == 6)) && (((m88k_cpu) == (CPU_M88100))))
	    {
	      return 1;
	    }
	  else
	    {
	      return 3;
	    }

        case 117:
        case 114:
	  insn_extract (insn);
	  if (! constrain_operands (INSN_CODE (insn), reload_completed))
	    fatal_insn_not_found (insn);
	  if ((which_alternative == 1) && (((m88k_cpu) == (CPU_M88100))))
	    {
	      return 1;
	    }
	  else
	    {
	      return 3;
	    }

        case 107:
	  insn_extract (insn);
	  if (! constrain_operands (INSN_CODE (insn), reload_completed))
	    fatal_insn_not_found (insn);
	  if (((which_alternative == 1) || (which_alternative == 8)) && (((m88k_cpu) == (CPU_M88100))))
	    {
	      return 1;
	    }
	  else
	    {
	      return 3;
	    }

        case -1:
	  if (GET_CODE (PATTERN (insn)) != ASM_INPUT
	      && asm_noperands (PATTERN (insn)) < 0)
	    fatal_insn_not_found (insn);
        default:
	  return 3;

      }

    case 2:
      switch (recog_memoized (insn))
	{
        case 158:
        case 156:
        case 154:
	  insn_extract (insn);
	  if (! constrain_operands (INSN_CODE (insn), reload_completed))
	    fatal_insn_not_found (insn);
	  return 2;

        case 151:
        case 149:
        case 147:
	  insn_extract (insn);
	  if (! constrain_operands (INSN_CODE (insn), reload_completed))
	    fatal_insn_not_found (insn);
	  return 2;

        case 241:
        case 240:
        case 239:
        case 238:
        case 139:
        case 138:
        case 137:
        case 136:
	  return 2;

        case 132:
        case 127:
        case 121:
	  insn_extract (insn);
	  if (! constrain_operands (INSN_CODE (insn), reload_completed))
	    fatal_insn_not_found (insn);
	  if (((which_alternative == 1) || (which_alternative == 6)) && (((m88k_cpu) == (CPU_M88100))))
	    {
	      return 2;
	    }
	  else
	    {
	      return 3;
	    }

        case 117:
        case 114:
	  insn_extract (insn);
	  if (! constrain_operands (INSN_CODE (insn), reload_completed))
	    fatal_insn_not_found (insn);
	  if ((which_alternative == 1) && (((m88k_cpu) == (CPU_M88100))))
	    {
	      return 2;
	    }
	  else
	    {
	      return 3;
	    }

        case 107:
	  insn_extract (insn);
	  if (! constrain_operands (INSN_CODE (insn), reload_completed))
	    fatal_insn_not_found (insn);
	  if (((which_alternative == 1) || (which_alternative == 8)) && (((m88k_cpu) == (CPU_M88100))))
	    {
	      return 2;
	    }
	  else
	    {
	      return 3;
	    }

        case -1:
	  if (GET_CODE (PATTERN (insn)) != ASM_INPUT
	      && asm_noperands (PATTERN (insn)) < 0)
	    fatal_insn_not_found (insn);
        default:
	  return 3;

      }

    }
}

static int
mem100_unit_conflict_cost (executing_insn, candidate_insn)
     rtx executing_insn;
     rtx candidate_insn;
{
  rtx insn;
  int casenum;

  insn = executing_insn;
  switch (recog_memoized (insn))
    {
    case 158:
    case 156:
    case 154:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      casenum = 1;
      break;

    case 151:
    case 149:
    case 147:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      casenum = 1;
      break;

    case 220:
    case 219:
    case 218:
    case 217:
    case 216:
    case 143:
    case 142:
    case 141:
    case 140:
      casenum = 0;
      break;

    case 241:
    case 240:
    case 239:
    case 238:
    case 138:
    case 137:
    case 136:
      casenum = 1;
      break;

    case 132:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if (((which_alternative != 0) && ((which_alternative != 1) && ((which_alternative != 3) && ((which_alternative != 4) && ((which_alternative != 5) && (which_alternative != 6)))))) && (((m88k_cpu) == (CPU_M88100))))
        {
	  casenum = 0;
        }
      else if (((which_alternative == 1) || (which_alternative == 6)) && (((m88k_cpu) == (CPU_M88100))))
        {
	  casenum = 1;
        }
      else
        {
	  casenum = 2;
        }
      break;

    case 127:
    case 121:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if (((which_alternative != 0) && ((which_alternative != 1) && ((which_alternative != 3) && ((which_alternative != 4) && ((which_alternative != 5) && (which_alternative != 6)))))) && (((m88k_cpu) == (CPU_M88100))))
        {
	  casenum = 0;
        }
      else
        {
	  casenum = 2;
        }
      break;

    case 117:
    case 114:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if ((which_alternative == 2) && (((m88k_cpu) == (CPU_M88100))))
        {
	  casenum = 0;
        }
      else if ((which_alternative == 1) && (((m88k_cpu) == (CPU_M88100))))
        {
	  casenum = 1;
        }
      else
        {
	  casenum = 2;
        }
      break;

    case 107:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if (((which_alternative == 2) || (which_alternative == 9)) && (((m88k_cpu) == (CPU_M88100))))
        {
	  casenum = 0;
        }
      else if (((which_alternative == 1) || (which_alternative == 8)) && (((m88k_cpu) == (CPU_M88100))))
        {
	  casenum = 1;
        }
      else
        {
	  casenum = 2;
        }
      break;

    case -1:
      if (GET_CODE (PATTERN (insn)) != ASM_INPUT
          && asm_noperands (PATTERN (insn)) < 0)
        fatal_insn_not_found (insn);
    default:
      casenum = 2;
      break;

    }

  insn = candidate_insn;
  switch (casenum)
    {
    case 0:
      return 1;

    case 1:
      return 1;

    case 2:
      return 2;

    }
}

static int
alu_unit_blockage (executing_insn, candidate_insn)
     rtx executing_insn;
     rtx candidate_insn;
{
  rtx insn;
  int casenum;

  insn = executing_insn;
  switch (recog_memoized (insn))
    {
    case 223:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if ((which_alternative == 0) && (! (((m88k_cpu) == (CPU_M88100)))))
        {
	  casenum = 0;
        }
      else
        {
	  casenum = 1;
        }
      break;

    case 158:
    case 156:
    case 154:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      casenum = 0;
      break;

    case 233:
    case 228:
    case 151:
    case 149:
    case 147:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if (((which_alternative == 0) || (which_alternative == 1)) && (! (((m88k_cpu) == (CPU_M88100)))))
        {
	  casenum = 0;
        }
      else
        {
	  casenum = 1;
        }
      break;

    case 132:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      casenum = 0;
      break;

    case 127:
    case 121:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if (((which_alternative == 3) || ((which_alternative == 4) || (which_alternative == 5))) && (! (((m88k_cpu) == (CPU_M88100)))))
        {
	  casenum = 0;
        }
      else
        {
	  casenum = 1;
        }
      break;

    case 264:
    case 262:
    case 126:
    case 120:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if ((which_alternative == 1) && (! (((m88k_cpu) == (CPU_M88100)))))
        {
	  casenum = 0;
        }
      else
        {
	  casenum = 1;
        }
      break;

    case 117:
    case 114:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      casenum = 0;
      break;

    case 108:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      if (((which_alternative == 0) || ((which_alternative == 1) || (which_alternative == 2))) && (! (((m88k_cpu) == (CPU_M88100)))))
        {
	  casenum = 0;
        }
      else
        {
	  casenum = 1;
        }
      break;

    case 107:
      insn_extract (insn);
      if (! constrain_operands (INSN_CODE (insn), reload_completed))
        fatal_insn_not_found (insn);
      casenum = 0;
      break;

    case 278:
    case 265:
    case 263:
    case 260:
    case 255:
    case 253:
    case 236:
    case 231:
    case 226:
    case 221:
    case 220:
    case 219:
    case 218:
    case 217:
    case 216:
    case 215:
    case 194:
    case 193:
    case 192:
    case 182:
    case 181:
    case 180:
    case 179:
    case 169:
    case 133:
    case 131:
    case 128:
    case 122:
    case 118:
    case 115:
    case 112:
    case 111:
    case 110:
    case 109:
    case 104:
    case 103:
    case 81:
    case 76:
    case 57:
    case 38:
    case 36:
    case 34:
    case 32:
    case 28:
    case 27:
    case 26:
    case 25:
      casenum = 0;
      break;

    case -1:
      if (GET_CODE (PATTERN (insn)) != ASM_INPUT
          && asm_noperands (PATTERN (insn)) < 0)
        fatal_insn_not_found (insn);
    default:
      casenum = 1;
      break;

    }

  insn = candidate_insn;
  switch (casenum)
    {
    case 0:
      return 1;

    case 1:
      switch (recog_memoized (insn))
	{
        case 233:
	  insn_extract (insn);
	  if (! constrain_operands (INSN_CODE (insn), reload_completed))
	    fatal_insn_not_found (insn);
	  if ((which_alternative == 2) && (! (((m88k_cpu) == (CPU_M88100)))))
	    {
	      return 1;
	    }
	  else
	    {
	      return 3;
	    }

        case 228:
	  insn_extract (insn);
	  if (! constrain_operands (INSN_CODE (insn), reload_completed))
	    fatal_insn_not_found (insn);
	  if ((which_alternative == 3) && (! (((m88k_cpu) == (CPU_M88100)))))
	    {
	      return 1;
	    }
	  else
	    {
	      return 3;
	    }

        case 223:
	  insn_extract (insn);
	  if (! constrain_operands (INSN_CODE (insn), reload_completed))
	    fatal_insn_not_found (insn);
	  if ((which_alternative == 1) && (! (((m88k_cpu) == (CPU_M88100)))))
	    {
	      return 1;
	    }
	  else
	    {
	      return 3;
	    }

        case 264:
        case 262:
        case 127:
        case 126:
        case 121:
        case 120:
	  insn_extract (insn);
	  if (! constrain_operands (INSN_CODE (insn), reload_completed))
	    fatal_insn_not_found (insn);
	  if ((which_alternative == 0) && (! (((m88k_cpu) == (CPU_M88100)))))
	    {
	      return 1;
	    }
	  else
	    {
	      return 3;
	    }

        case 108:
	  insn_extract (insn);
	  if (! constrain_operands (INSN_CODE (insn), reload_completed))
	    fatal_insn_not_found (insn);
	  if ((which_alternative == 4) && (! (((m88k_cpu) == (CPU_M88100)))))
	    {
	      return 1;
	    }
	  else
	    {
	      return 3;
	    }

        case -1:
	  if (GET_CODE (PATTERN (insn)) != ASM_INPUT
	      && asm_noperands (PATTERN (insn)) < 0)
	    fatal_insn_not_found (insn);
        case 281:
        case 269:
        case 259:
        case 252:
        case 243:
        case 242:
        case 237:
        case 235:
        case 234:
        case 230:
        case 229:
        case 225:
        case 224:
        case 208:
        case 202:
        case 191:
        case 190:
        case 189:
        case 178:
        case 177:
        case 176:
        case 134:
        case 129:
        case 123:
        case 46:
        case 12:
	  return 1;

        default:
	  return 3;

      }

    }
}

struct function_unit_desc function_units[] = {
  {"alu", 1, 1, 0, 1, 1, alu_unit_ready_cost, 0, 3, alu_unit_blockage_range, alu_unit_blockage}, 
  {"bit", 2, 1, 0, 2, 2, bit_unit_ready_cost, 0, 2, 0, 0}, 
  {"mem100", 4, 1, 0, 0, 2, mem100_unit_ready_cost, mem100_unit_conflict_cost, 3, mem100_unit_blockage_range, mem100_unit_blockage}, 
  {"mem110", 8, 1, 0, 2, 2, mem110_unit_ready_cost, 0, 3, mem110_unit_blockage_range, mem110_unit_blockage}, 
  {"fpmul100", 16, 1, 0, 1, 1, fpmul100_unit_ready_cost, 0, 5, fpmul100_unit_blockage_range, fpmul100_unit_blockage}, 
  {"fpmul110", 32, 1, 0, 2, 2, fpmul110_unit_ready_cost, 0, 2, 0, 0}, 
  {"fpadd100", 64, 1, 5, 1, 1, fpadd100_unit_ready_cost, 0, 58, fpadd100_unit_blockage_range, fpadd100_unit_blockage}, 
  {"fpadd110", 128, 1, 0, 2, 2, fpadd110_unit_ready_cost, 0, 4, fpadd110_unit_blockage_range, fpadd110_unit_blockage}, 
  {"div", 256, 1, 1, 2, 2, div_unit_ready_cost, 0, 45, div_unit_blockage_range, div_unit_blockage}, 
};

int
const_num_delay_slots (insn)
     rtx insn;
{
  switch (recog_memoized (insn))
    {
    default:
      return 1;
    }
}
