/* Generated automatically by the program `genrecog'
from the machine description file `md'.  */

#include "config.h"
#include "rtl.h"
#include "insn-config.h"
#include "recog.h"
#include "real.h"
#include "output.h"
#include "flags.h"

extern rtx gen_split_1 ();
extern rtx gen_split_2 ();
extern rtx gen_split_3 ();
extern rtx gen_split_4 ();
extern rtx gen_split_5 ();
extern rtx gen_split_6 ();
extern rtx gen_split_7 ();
extern rtx gen_split_13 ();
extern rtx gen_split_14 ();
extern rtx gen_split_15 ();
extern rtx gen_split_16 ();
extern rtx gen_split_17 ();
extern rtx gen_split_18 ();
extern rtx gen_split_19 ();
extern rtx gen_split_20 ();
extern rtx gen_split_21 ();
extern rtx gen_split_22 ();
extern rtx gen_split_23 ();
extern rtx gen_split_24 ();
extern rtx gen_split_31 ();
extern rtx gen_split_33 ();
extern rtx gen_split_35 ();
extern rtx gen_split_37 ();
extern rtx gen_split_75 ();
extern rtx gen_split_80 ();
extern rtx gen_split_125 ();

/* `recog' contains a decision tree
   that recognizes whether the rtx X0 is a valid instruction.

   recog returns -1 if the rtx is not valid.
   If the rtx is valid, recog returns a nonnegative number
   which is the insn code number for the pattern that matched.
   This is the same as the order in the machine description of
   the entry that matched.  This number can be used as an index into
   entry that matched.  This number can be used as an index into various
   insn_* tables, such as insn_templates, insn_outfun, and insn_n_operands
   (found in insn-output.c).

   The third argument to recog is an optional pointer to an int.
   If present, recog will accept a pattern if it matches except for
   missing CLOBBER expressions at the end.  In that case, the value
   pointed to by the optional pointer will be set to the number of
   CLOBBERs that need to be added (it should be initialized to zero by
   the caller).  If it is set nonzero, the caller should allocate a
   PARALLEL of the appropriate size, copy the initial entries, and call
   add_clobbers (found in insn-emit.c) to fill in the CLOBBERs.

   The function split_insns returns 0 if the rtl could not
   be split or the split rtl in a SEQUENCE if it can be.*/

rtx recog_operand[MAX_RECOG_OPERANDS];

rtx *recog_operand_loc[MAX_RECOG_OPERANDS];

rtx *recog_dup_loc[MAX_DUP_OPERANDS];

char recog_dup_num[MAX_DUP_OPERANDS];

#define operands recog_operand

int
recog_1 (x0, insn, pnum_clobbers)
     register rtx x0;
     rtx insn;
     int *pnum_clobbers;
{
  register rtx *ro = &recog_operand[0];
  register rtx x1, x2, x3, x4, x5;
  int tem;

  x1 = XEXP (x0, 1);
  if (GET_MODE (x1) != SImode)
    goto ret0;
  switch (GET_CODE (x1))
    {
    case ASHIFT:
      goto L80;
    case IOR:
      goto L59;
    case AND:
      goto L73;
    case NOT:
      goto L561;
    case NEG:
      goto L600;
    case HIGH:
      goto L715;
    case EQ:
    case NE:
    case LT:
    case LE:
    case GE:
    case GT:
    case LTU:
    case LEU:
    case GEU:
    case GTU:
      if (relop (x1, SImode))
	{
	  ro[1] = x1;
	  goto L551;
	}
    }
  L555:
  if (even_relop (x1, SImode))
    {
      ro[1] = x1;
      goto L556;
    }
  if (odd_relop (x1, SImode))
    {
      ro[1] = x1;
      goto L583;
    }
  goto ret0;

  L80:
  x2 = XEXP (x1, 0);
  switch (GET_CODE (x2))
    {
    case ZERO_EXTRACT:
      if (GET_MODE (x2) == SImode && 1)
	goto L81;
      break;
    case CONST_INT:
      if (XWINT (x2, 0) == -1 && 1)
	goto L55;
    }
  goto ret0;

  L81:
  x3 = XEXP (x2, 0);
  if (register_operand (x3, SImode))
    {
      ro[1] = x3;
      goto L82;
    }
  goto ret0;

  L82:
  x3 = XEXP (x2, 1);
  if (GET_CODE (x3) == CONST_INT && int5_operand (x3, SImode))
    {
      ro[2] = x3;
      goto L83;
    }
  goto ret0;

  L83:
  x3 = XEXP (x2, 2);
  if (GET_CODE (x3) == CONST_INT && int5_operand (x3, SImode))
    {
      ro[3] = x3;
      goto L84;
    }
  goto ret0;

  L84:
  x2 = XEXP (x1, 1);
  if (GET_CODE (x2) == CONST_INT && int5_operand (x2, SImode))
    {
      ro[4] = x2;
      if (INTVAL (operands[2]) + INTVAL (operands[3]) + INTVAL (operands[4]) == 32)
	return 12;
      }
  goto ret0;

  L55:
  x2 = XEXP (x1, 1);
  if (register_operand (x2, SImode))
    {
      ro[1] = x2;
      return 8;
    }
  goto ret0;

  L59:
  x2 = XEXP (x1, 0);
  if (GET_MODE (x2) != SImode)
    goto ret0;
  if (GET_CODE (x2) == ASHIFT && 1)
    goto L60;
  if (register_operand (x2, SImode))
    {
      ro[1] = x2;
      goto L67;
    }
  goto ret0;

  L60:
  x3 = XEXP (x2, 0);
  if (GET_CODE (x3) == CONST_INT && XWINT (x3, 0) == -1 && 1)
    goto L61;
  goto ret0;

  L61:
  x3 = XEXP (x2, 1);
  if (register_operand (x3, SImode))
    {
      ro[1] = x3;
      goto L62;
    }
  goto ret0;

  L62:
  x2 = XEXP (x1, 1);
  if (register_operand (x2, SImode))
    {
      ro[2] = x2;
      return 9;
    }
  goto ret0;

  L67:
  x2 = XEXP (x1, 1);
  if (GET_MODE (x2) == SImode && GET_CODE (x2) == ASHIFT && 1)
    goto L68;
  goto ret0;

  L68:
  x3 = XEXP (x2, 0);
  if (GET_CODE (x3) == CONST_INT && XWINT (x3, 0) == -1 && 1)
    goto L69;
  goto ret0;

  L69:
  x3 = XEXP (x2, 1);
  if (register_operand (x3, SImode))
    {
      ro[2] = x3;
      return 10;
    }
  goto ret0;

  L73:
  x2 = XEXP (x1, 0);
  if (GET_MODE (x2) == SImode && GET_CODE (x2) == ASHIFT && 1)
    goto L74;
  goto ret0;

  L74:
  x3 = XEXP (x2, 0);
  if (register_operand (x3, SImode))
    {
      ro[1] = x3;
      goto L75;
    }
  goto ret0;

  L75:
  x3 = XEXP (x2, 1);
  if (GET_CODE (x3) == CONST_INT && int5_operand (x3, SImode))
    {
      ro[2] = x3;
      goto L76;
    }
  goto ret0;

  L76:
  x2 = XEXP (x1, 1);
  if (immediate_operand (x2, SImode))
    {
      ro[3] = x2;
      if (mak_mask_p (INTVAL (operands[3]) >> INTVAL (operands[2])))
	return 11;
      }
  goto ret0;

  L561:
  x2 = XEXP (x1, 0);
  if (odd_relop (x2, SImode))
    {
      ro[1] = x2;
      goto L562;
    }
  goto ret0;

  L562:
  x3 = XEXP (x2, 0);
  if (register_operand (x3, CCEVENmode))
    {
      ro[2] = x3;
      goto L563;
    }
  goto ret0;

  L563:
  x3 = XEXP (x2, 1);
  if (GET_CODE (x3) == CONST_INT && XWINT (x3, 0) == 0 && 1)
    return 74;
  goto ret0;

  L600:
  x2 = XEXP (x1, 0);
  if (GET_MODE (x2) != SImode)
    goto ret0;
  if (GET_CODE (x2) == NOT && 1)
    goto L601;
  if (relop (x2, SImode))
    {
      ro[1] = x2;
      goto L589;
    }
  L594:
  if (even_relop (x2, SImode))
    {
      ro[1] = x2;
      goto L595;
    }
  if (odd_relop (x2, SImode))
    {
      ro[1] = x2;
      goto L626;
    }
  goto ret0;

  L601:
  x3 = XEXP (x2, 0);
  if (odd_relop (x3, SImode))
    {
      ro[1] = x3;
      goto L602;
    }
  goto ret0;

  L602:
  x4 = XEXP (x3, 0);
  if (register_operand (x4, CCEVENmode))
    {
      ro[2] = x4;
      goto L603;
    }
  goto ret0;

  L603:
  x4 = XEXP (x3, 1);
  if (GET_CODE (x4) == CONST_INT && XWINT (x4, 0) == 0 && 1)
    return 79;
  goto ret0;

  L589:
  x3 = XEXP (x2, 0);
  if (register_operand (x3, CCmode))
    {
      ro[2] = x3;
      goto L590;
    }
  goto L594;

  L590:
  x3 = XEXP (x2, 1);
  if (GET_CODE (x3) == CONST_INT && XWINT (x3, 0) == 0 && 1)
    return 77;
  goto L594;

  L595:
  x3 = XEXP (x2, 0);
  if (register_operand (x3, CCEVENmode))
    {
      ro[2] = x3;
      goto L596;
    }
  goto ret0;

  L596:
  x3 = XEXP (x2, 1);
  if (GET_CODE (x3) == CONST_INT && XWINT (x3, 0) == 0 && 1)
    return 78;
  goto ret0;

  L626:
  x3 = XEXP (x2, 0);
  if (register_operand (x3, CCEVENmode))
    {
      ro[2] = x3;
      goto L627;
    }
  goto ret0;

  L627:
  x3 = XEXP (x2, 1);
  if (GET_CODE (x3) == CONST_INT && XWINT (x3, 0) == 0 && pnum_clobbers != 0 && 1)
    {
      *pnum_clobbers = 1;
      return 81;
    }
  goto ret0;

  L715:
  x2 = XEXP (x1, 0);
  if (GET_MODE (x2) == SImode && GET_CODE (x2) == UNSPEC && XINT (x2, 1) == 0 && XVECLEN (x2, 0) == 1 && 1)
    goto L716;
  goto ret0;

  L716:
  x3 = XVECEXP (x2, 0, 0);
  if (GET_CODE (x3) == LABEL_REF && 1)
    goto L717;
  goto ret0;

  L717:
  x4 = XEXP (x3, 0);
  ro[1] = x4;
  return 103;

  L551:
  x2 = XEXP (x1, 0);
  if (register_operand (x2, CCmode))
    {
      ro[2] = x2;
      goto L552;
    }
  goto L555;

  L552:
  x2 = XEXP (x1, 1);
  if (GET_CODE (x2) == CONST_INT && XWINT (x2, 0) == 0 && 1)
    return 72;
  goto L555;

  L556:
  x2 = XEXP (x1, 0);
  if (register_operand (x2, CCEVENmode))
    {
      ro[2] = x2;
      goto L557;
    }
  goto ret0;

  L557:
  x2 = XEXP (x1, 1);
  if (GET_CODE (x2) == CONST_INT && XWINT (x2, 0) == 0 && 1)
    return 73;
  goto ret0;

  L583:
  x2 = XEXP (x1, 0);
  if (register_operand (x2, CCEVENmode))
    {
      ro[2] = x2;
      goto L584;
    }
  goto ret0;

  L584:
  x2 = XEXP (x1, 1);
  if (GET_CODE (x2) == CONST_INT && XWINT (x2, 0) == 0 && pnum_clobbers != 0 && 1)
    {
      *pnum_clobbers = 1;
      return 76;
    }
  goto ret0;
 ret0: return -1;
}

int
recog_2 (x0, insn, pnum_clobbers)
     register rtx x0;
     rtx insn;
     int *pnum_clobbers;
{
  register rtx *ro = &recog_operand[0];
  register rtx x1, x2, x3, x4, x5;
  int tem;

  x1 = XEXP (x0, 1);
  switch (GET_MODE (x1))
    {
    case SImode:
      switch (GET_CODE (x1))
	{
	case AND:
	  goto L1206;
	case IOR:
	  goto L1228;
	case NOT:
	  goto L1250;
	case XOR:
	  goto L1256;
	case ASHIFTRT:
	  goto L1280;
	case LSHIFTRT:
	  goto L1285;
	case ASHIFT:
	  goto L1306;
	case ROTATERT:
	  goto L1321;
	case FFS:
	  goto L1335;
	case SIGN_EXTRACT:
	  goto L1339;
	case ZERO_EXTRACT:
	  goto L1351;
	case NEG:
	  goto L1381;
	}
    }
  if (address_operand (x1, SImode))
    {
      ro[1] = x1;
      if (m88k_gp_threshold > 0 && symbolic_address_p (operands[1]))
	return 215;
      }
  L1190:
  if (address_operand (x1, HImode))
    {
      ro[1] = x1;
      return 216;
    }
  L1193:
  if (address_operand (x1, SImode))
    {
      ro[1] = x1;
      return 217;
    }
  L1196:
  if (address_operand (x1, DImode))
    {
      ro[1] = x1;
      return 218;
    }
  L1199:
  if (address_operand (x1, SFmode))
    {
      ro[1] = x1;
      return 219;
    }
  L1202:
  if (address_operand (x1, DFmode))
    {
      ro[1] = x1;
      return 220;
    }
  goto ret0;

  L1206:
  x2 = XEXP (x1, 0);
  if (GET_MODE (x2) == SImode && GET_CODE (x2) == NOT && 1)
    goto L1207;
  if (arith32_operand (x2, SImode))
    {
      ro[1] = x2;
      goto L1213;
    }
  goto ret0;

  L1207:
  x3 = XEXP (x2, 0);
  if (register_operand (x3, SImode))
    {
      ro[1] = x3;
      goto L1208;
    }
  goto ret0;

  L1208:
  x2 = XEXP (x1, 1);
  if (register_operand (x2, SImode))
    {
      ro[2] = x2;
      return 221;
    }
  goto ret0;

  L1213:
  x2 = XEXP (x1, 1);
  if (arith32_operand (x2, SImode))
    {
      ro[2] = x2;
      return 223;
    }
  goto ret0;

  L1228:
  x2 = XEXP (x1, 0);
  if (GET_MODE (x2) == SImode && GET_CODE (x2) == NOT && 1)
    goto L1229;
  if (arith32_operand (x2, SImode))
    {
      ro[1] = x2;
      goto L1235;
    }
  goto ret0;

  L1229:
  x3 = XEXP (x2, 0);
  if (register_operand (x3, SImode))
    {
      ro[1] = x3;
      goto L1230;
    }
  goto ret0;

  L1230:
  x2 = XEXP (x1, 1);
  if (register_operand (x2, SImode))
    {
      ro[2] = x2;
      return 226;
    }
  goto ret0;

  L1235:
  x2 = XEXP (x1, 1);
  if (arith32_operand (x2, SImode))
    {
      ro[2] = x2;
      return 228;
    }
  goto ret0;

  L1250:
  x2 = XEXP (x1, 0);
  if (GET_MODE (x2) != SImode)
    goto ret0;
  if (GET_CODE (x2) == XOR && 1)
    goto L1251;
  if (register_operand (x2, SImode))
    {
      ro[1] = x2;
      return 236;
    }
  goto ret0;

  L1251:
  x3 = XEXP (x2, 0);
  if (register_operand (x3, SImode))
    {
      ro[1] = x3;
      goto L1252;
    }
  goto ret0;

  L1252:
  x3 = XEXP (x2, 1);
  if (register_operand (x3, SImode))
    {
      ro[2] = x3;
      return 231;
    }
  goto ret0;

  L1256:
  x2 = XEXP (x1, 0);
  if (arith32_operand (x2, SImode))
    {
      ro[1] = x2;
      goto L1257;
    }
  goto ret0;

  L1257:
  x2 = XEXP (x1, 1);
  if (arith32_operand (x2, SImode))
    {
      ro[2] = x2;
      return 233;
    }
  goto ret0;

  L1280:
  x2 = XEXP (x1, 0);
  if (GET_MODE (x2) != SImode)
    goto ret0;
  if (memory_operand (x2, SImode))
    {
      ro[1] = x2;
      goto L1281;
    }
  L1311:
  if (register_operand (x2, SImode))
    {
      ro[1] = x2;
      goto L1312;
    }
  goto ret0;

  L1281:
  x2 = XEXP (x1, 1);
  if (GET_CODE (x2) != CONST_INT)
    {
      x2 = XEXP (x1, 0);
    goto L1311;
    }
  if (XWINT (x2, 0) == 24 && 1)
    if (! SCALED_ADDRESS_P (XEXP (operands[1], 0)))
      return 238;
  if (XWINT (x2, 0) == 16 && 1)
    if (! SCALED_ADDRESS_P (XEXP (operands[1], 0)))
      return 240;
  x2 = XEXP (x1, 0);
  goto L1311;

  L1312:
  x2 = XEXP (x1, 1);
  if (arith5_operand (x2, SImode))
    {
      ro[2] = x2;
      return 247;
    }
  goto ret0;

  L1285:
  x2 = XEXP (x1, 0);
  if (GET_MODE (x2) != SImode)
    goto ret0;
  if (memory_operand (x2, SImode))
    {
      ro[1] = x2;
      goto L1286;
    }
  L1316:
  if (register_operand (x2, SImode))
    {
      ro[1] = x2;
      goto L1317;
    }
  goto ret0;

  L1286:
  x2 = XEXP (x1, 1);
  if (GET_CODE (x2) != CONST_INT)
    {
      x2 = XEXP (x1, 0);
    goto L1316;
    }
  if (XWINT (x2, 0) == 24 && 1)
    if (! SCALED_ADDRESS_P (XEXP (operands[1], 0)))
      return 239;
  if (XWINT (x2, 0) == 16 && 1)
    if (! SCALED_ADDRESS_P (XEXP (operands[1], 0)))
      return 241;
  x2 = XEXP (x1, 0);
  goto L1316;

  L1317:
  x2 = XEXP (x1, 1);
  if (arith5_operand (x2, SImode))
    {
      ro[2] = x2;
      return 249;
    }
  goto ret0;

  L1306:
  x2 = XEXP (x1, 0);
  if (register_operand (x2, SImode))
    {
      ro[1] = x2;
      goto L1307;
    }
  goto ret0;

  L1307:
  x2 = XEXP (x1, 1);
  if (arith5_operand (x2, SImode))
    {
      ro[2] = x2;
      return 245;
    }
  goto ret0;

  L1321:
  x2 = XEXP (x1, 0);
  if (register_operand (x2, SImode))
    {
      ro[1] = x2;
      goto L1322;
    }
  goto ret0;

  L1322:
  x2 = XEXP (x1, 1);
  if (arith_operand (x2, SImode))
    {
      ro[2] = x2;
      return 251;
    }
  goto ret0;

  L1335:
  x2 = XEXP (x1, 0);
  if (pnum_clobbers != 0 && register_operand (x2, SImode))
    {
      ro[1] = x2;
      *pnum_clobbers = 2;
      return 252;
    }
  goto ret0;

  L1339:
  x2 = XEXP (x1, 0);
  if (register_operand (x2, SImode))
    {
      ro[1] = x2;
      goto L1340;
    }
  goto ret0;

  L1340:
  x2 = XEXP (x1, 1);
  if (GET_CODE (x2) != CONST_INT)
    goto ret0;
  if (XWINT (x2, 0) == 32 && 1)
    goto L1341;
  L1346:
  if (int5_operand (x2, SImode))
    {
      ro[2] = x2;
      goto L1347;
    }
  goto ret0;

  L1341:
  x2 = XEXP (x1, 2);
  if (GET_CODE (x2) == CONST_INT && XWINT (x2, 0) == 0 && 1)
    return 253;
  x2 = XEXP (x1, 1);
  goto L1346;

  L1347:
  x2 = XEXP (x1, 2);
  if (GET_CODE (x2) == CONST_INT && int5_operand (x2, SImode))
    {
      ro[3] = x2;
      return 254;
    }
  goto ret0;

  L1351:
  x2 = XEXP (x1, 0);
  if (register_operand (x2, SImode))
    {
      ro[1] = x2;
      goto L1352;
    }
  goto ret0;

  L1352:
  x2 = XEXP (x1, 1);
  if (GET_CODE (x2) != CONST_INT)
    goto ret0;
  if (XWINT (x2, 0) == 32 && 1)
    goto L1353;
  L1358:
  if (int5_operand (x2, SImode))
    {
      ro[2] = x2;
      goto L1359;
    }
  goto ret0;

  L1353:
  x2 = XEXP (x1, 2);
  if (GET_CODE (x2) == CONST_INT && XWINT (x2, 0) == 0 && 1)
    return 255;
  x2 = XEXP (x1, 1);
  goto L1358;

  L1359:
  x2 = XEXP (x1, 2);
  if (GET_CODE (x2) == CONST_INT && int5_operand (x2, SImode))
    {
      ro[3] = x2;
      return 256;
    }
  goto ret0;

  L1381:
  x2 = XEXP (x1, 0);
  if (arith_operand (x2, SImode))
    {
      ro[1] = x2;
      return 260;
    }
  goto ret0;
 ret0: return -1;
}

int
recog_3 (x0, insn, pnum_clobbers)
     register rtx x0;
     rtx insn;
     int *pnum_clobbers;
{
  register rtx *ro = &recog_operand[0];
  register rtx x1, x2, x3, x4, x5;
  int tem;

  x1 = XEXP (x0, 1);
  switch (GET_MODE (x1))
    {
    case DFmode:
      switch (GET_CODE (x1))
	{
	case SUBREG:
	  if (XINT (x1, 1) == 0 && 1)
	    goto L800;
	  break;
	case FLOAT_EXTEND:
	  goto L872;
	case FLOAT:
	  goto L892;
	case PLUS:
	  goto L913;
	case MINUS:
	  goto L1013;
	case MULT:
	  goto L1113;
	case DIV:
	  goto L1159;
	case NEG:
	  goto L1390;
	case ABS:
	  goto L1398;
	}
    }
  if (immediate_operand (x1, DFmode))
    {
      ro[1] = x1;
      return 129;
    }
  goto ret0;

  L800:
  x2 = XEXP (x1, 0);
  if (GET_MODE (x2) == SImode && GET_CODE (x2) == LO_SUM && 1)
    goto L801;
  goto ret0;

  L801:
  x3 = XEXP (x2, 0);
  if (register_operand (x3, SImode))
    {
      ro[1] = x3;
      goto L802;
    }
  goto ret0;

  L802:
  x3 = XEXP (x2, 1);
  if (immediate_operand (x3, SImode))
    {
      ro[2] = x3;
      if (!flag_pic)
	return 128;
      }
  goto ret0;

  L872:
  x2 = XEXP (x1, 0);
  if (register_operand (x2, SFmode))
    goto L877;
  goto ret0;

  L877:
  ro[1] = x2;
  if (! TARGET_88110)
    return 160;
  L878:
  ro[1] = x2;
  if (TARGET_88110)
    return 161;
  goto ret0;

  L892:
  x2 = XEXP (x1, 0);
  if (register_operand (x2, SImode))
    {
      ro[1] = x2;
      return 165;
    }
  goto ret0;

  L913:
  x2 = XEXP (x1, 0);
  if (GET_MODE (x2) != DFmode)
    goto ret0;
  if (GET_CODE (x2) == FLOAT_EXTEND && 1)
    goto L914;
  if (register_operand (x2, DFmode))
    {
      ro[1] = x2;
      goto L921;
    }
  goto ret0;

  L914:
  x3 = XEXP (x2, 0);
  if (register_operand (x3, SFmode))
    {
      ro[1] = x3;
      goto L915;
    }
  goto ret0;

  L915:
  x2 = XEXP (x1, 1);
  if (GET_MODE (x2) != DFmode)
    goto ret0;
  if (GET_CODE (x2) == FLOAT_EXTEND && 1)
    goto L916;
  if (register_operand (x2, DFmode))
    {
      ro[2] = x2;
      return 173;
    }
  goto ret0;

  L916:
  x3 = XEXP (x2, 0);
  if (register_operand (x3, SFmode))
    {
      ro[2] = x3;
      return 171;
    }
  goto ret0;

  L921:
  x2 = XEXP (x1, 1);
  if (GET_MODE (x2) != DFmode)
    goto ret0;
  if (GET_CODE (x2) == FLOAT_EXTEND && 1)
    goto L922;
  if (register_operand (x2, DFmode))
    {
      ro[2] = x2;
      return 174;
    }
  goto ret0;

  L922:
  x3 = XEXP (x2, 0);
  if (register_operand (x3, SFmode))
    {
      ro[2] = x3;
      return 172;
    }
  goto ret0;

  L1013:
  x2 = XEXP (x1, 0);
  if (GET_MODE (x2) != DFmode)
    goto ret0;
  if (GET_CODE (x2) == FLOAT_EXTEND && 1)
    goto L1014;
  if (register_operand (x2, DFmode))
    {
      ro[1] = x2;
      goto L1021;
    }
  goto ret0;

  L1014:
  x3 = XEXP (x2, 0);
  if (register_operand (x3, SFmode))
    {
      ro[1] = x3;
      goto L1015;
    }
  goto ret0;

  L1015:
  x2 = XEXP (x1, 1);
  if (GET_MODE (x2) != DFmode)
    goto ret0;
  if (GET_CODE (x2) == FLOAT_EXTEND && 1)
    goto L1016;
  if (register_operand (x2, DFmode))
    {
      ro[2] = x2;
      return 186;
    }
  goto ret0;

  L1016:
  x3 = XEXP (x2, 0);
  if (register_operand (x3, SFmode))
    {
      ro[2] = x3;
      return 184;
    }
  goto ret0;

  L1021:
  x2 = XEXP (x1, 1);
  if (GET_MODE (x2) != DFmode)
    goto ret0;
  if (GET_CODE (x2) == FLOAT_EXTEND && 1)
    goto L1022;
  if (register_operand (x2, DFmode))
    {
      ro[2] = x2;
      return 187;
    }
  goto ret0;

  L1022:
  x3 = XEXP (x2, 0);
  if (register_operand (x3, SFmode))
    {
      ro[2] = x3;
      return 185;
    }
  goto ret0;

  L1113:
  x2 = XEXP (x1, 0);
  if (GET_MODE (x2) != DFmode)
    goto ret0;
  if (GET_CODE (x2) == FLOAT_EXTEND && 1)
    goto L1114;
  if (register_operand (x2, DFmode))
    {
      ro[1] = x2;
      goto L1121;
    }
  goto ret0;

  L1114:
  x3 = XEXP (x2, 0);
  if (register_operand (x3, SFmode))
    {
      ro[1] = x3;
      goto L1115;
    }
  goto ret0;

  L1115:
  x2 = XEXP (x1, 1);
  if (GET_MODE (x2) != DFmode)
    goto ret0;
  if (GET_CODE (x2) == FLOAT_EXTEND && 1)
    goto L1116;
  if (register_operand (x2, DFmode))
    {
      ro[2] = x2;
      return 199;
    }
  goto ret0;

  L1116:
  x3 = XEXP (x2, 0);
  if (register_operand (x3, SFmode))
    {
      ro[2] = x3;
      return 197;
    }
  goto ret0;

  L1121:
  x2 = XEXP (x1, 1);
  if (GET_MODE (x2) != DFmode)
    goto ret0;
  if (GET_CODE (x2) == FLOAT_EXTEND && 1)
    goto L1122;
  if (register_operand (x2, DFmode))
    {
      ro[2] = x2;
      return 200;
    }
  goto ret0;

  L1122:
  x3 = XEXP (x2, 0);
  if (register_operand (x3, SFmode))
    {
      ro[2] = x3;
      return 198;
    }
  goto ret0;

  L1159:
  x2 = XEXP (x1, 0);
  if (GET_MODE (x2) != DFmode)
    goto ret0;
  if (GET_CODE (x2) == FLOAT_EXTEND && 1)
    goto L1160;
  if (register_operand (x2, DFmode))
    {
      ro[1] = x2;
      goto L1167;
    }
  goto ret0;

  L1160:
  x3 = XEXP (x2, 0);
  if (register_operand (x3, SFmode))
    {
      ro[1] = x3;
      goto L1161;
    }
  goto ret0;

  L1161:
  x2 = XEXP (x1, 1);
  if (GET_MODE (x2) != DFmode)
    goto ret0;
  if (GET_CODE (x2) == FLOAT_EXTEND && 1)
    goto L1162;
  if (register_operand (x2, DFmode))
    {
      ro[2] = x2;
      return 212;
    }
  goto ret0;

  L1162:
  x3 = XEXP (x2, 0);
  if (register_operand (x3, SFmode))
    {
      ro[2] = x3;
      return 210;
    }
  goto ret0;

  L1167:
  x2 = XEXP (x1, 1);
  if (GET_MODE (x2) != DFmode)
    goto ret0;
  if (GET_CODE (x2) == FLOAT_EXTEND && 1)
    goto L1168;
  if (register_operand (x2, DFmode))
    {
      ro[2] = x2;
      return 214;
    }
  goto ret0;

  L1168:
  x3 = XEXP (x2, 0);
  if (register_operand (x3, SFmode))
    {
      ro[2] = x3;
      return 211;
    }
  goto ret0;

  L1390:
  x2 = XEXP (x1, 0);
  if (register_operand (x2, DFmode))
    {
      ro[1] = x2;
      return 262;
    }
  goto ret0;

  L1398:
  x2 = XEXP (x1, 0);
  if (register_operand (x2, DFmode))
    {
      ro[1] = x2;
      return 264;
    }
  goto ret0;
 ret0: return -1;
}

int
recog_4 (x0, insn, pnum_clobbers)
     register rtx x0;
     rtx insn;
     int *pnum_clobbers;
{
  register rtx *ro = &recog_operand[0];
  register rtx x1, x2, x3, x4, x5;
  int tem;

  x1 = XEXP (x0, 1);
  x2 = XEXP (x1, 0);
  if (relop_no_unsigned (x2, VOIDmode))
    {
      ro[0] = x2;
      goto L391;
    }
  L398:
  if (equality_op (x2, VOIDmode))
    {
      ro[0] = x2;
      goto L407;
    }
  L631:
  if (relop (x2, VOIDmode))
    {
      ro[0] = x2;
      goto L632;
    }
  L639:
  if (even_relop (x2, VOIDmode))
    {
      ro[0] = x2;
      goto L640;
    }
  if (odd_relop (x2, VOIDmode))
    {
      ro[0] = x2;
      goto L648;
    }
  L460:
  switch (GET_CODE (x2))
    {
    case NE:
      goto L461;
    }
  L471:
  if (GET_CODE (x2) == EQ && 1)
    goto L472;
  goto ret0;

  L391:
  x3 = XEXP (x2, 0);
  switch (GET_MODE (x3))
    {
    case SImode:
      if (register_operand (x3, SImode))
	{
	  ro[1] = x3;
	  goto L392;
	}
      break;
    case DImode:
      if (GET_CODE (x3) == SIGN_EXTEND && 1)
	goto L419;
    }
  goto L398;

  L392:
  x3 = XEXP (x2, 1);
  if (GET_CODE (x3) == CONST_INT && XWINT (x3, 0) == 0 && 1)
    goto L393;
  goto L398;

  L393:
  x2 = XEXP (x1, 1);
  if (pc_or_label_ref (x2, VOIDmode))
    {
      ro[2] = x2;
      goto L394;
    }
  x2 = XEXP (x1, 0);
  goto L398;

  L394:
  x2 = XEXP (x1, 2);
  if (pc_or_label_ref (x2, VOIDmode))
    {
      ro[3] = x2;
      return 39;
    }
  x2 = XEXP (x1, 0);
  goto L398;

  L419:
  x4 = XEXP (x3, 0);
  if (register_operand (x4, SImode))
    {
      ro[1] = x4;
      goto L420;
    }
  goto L398;

  L420:
  x3 = XEXP (x2, 1);
  if (GET_CODE (x3) == CONST_INT && XWINT (x3, 0) == 0 && 1)
    goto L421;
  goto L398;

  L421:
  x2 = XEXP (x1, 1);
  if (pc_or_label_ref (x2, VOIDmode))
    {
      ro[2] = x2;
      goto L422;
    }
  x2 = XEXP (x1, 0);
  goto L398;

  L422:
  x2 = XEXP (x1, 2);
  if (pc_or_label_ref (x2, VOIDmode))
    {
      ro[3] = x2;
      return 42;
    }
  x2 = XEXP (x1, 0);
  goto L398;

  L407:
  x3 = XEXP (x2, 0);
  switch (GET_MODE (x3))
    {
    case SImode:
      if (GET_CODE (x3) == ZERO_EXTRACT && 1)
	goto L408;
      if (register_operand (x3, SImode))
	{
	  ro[1] = x3;
	  goto L400;
	}
      break;
    case DImode:
      switch (GET_CODE (x3))
	{
	case ZERO_EXTEND:
	  goto L428;
	}
      break;
    case DFmode:
      if (GET_CODE (x3) == FLOAT_EXTEND && 1)
	goto L437;
      if (register_operand (x3, DFmode))
	{
	  ro[1] = x3;
	  goto L454;
	}
      break;
    case SFmode:
      if (register_operand (x3, SFmode))
	{
	  ro[1] = x3;
	  goto L446;
	}
    }
  goto L631;

  L408:
  x4 = XEXP (x3, 0);
  if (register_operand (x4, SImode))
    {
      ro[1] = x4;
      goto L409;
    }
  goto L631;

  L409:
  x4 = XEXP (x3, 1);
  if (GET_CODE (x4) == CONST_INT && XWINT (x4, 0) == 31 && 1)
    goto L410;
  goto L631;

  L410:
  x4 = XEXP (x3, 2);
  if (GET_CODE (x4) == CONST_INT && XWINT (x4, 0) == 1 && 1)
    goto L411;
  goto L631;

  L411:
  x3 = XEXP (x2, 1);
  if (GET_CODE (x3) == CONST_INT && XWINT (x3, 0) == 0 && 1)
    goto L412;
  goto L631;

  L412:
  x2 = XEXP (x1, 1);
  if (pc_or_label_ref (x2, VOIDmode))
    {
      ro[2] = x2;
      goto L413;
    }
  x2 = XEXP (x1, 0);
  goto L631;

  L413:
  x2 = XEXP (x1, 2);
  if (pc_or_label_ref (x2, VOIDmode))
    {
      ro[3] = x2;
      return 41;
    }
  x2 = XEXP (x1, 0);
  goto L631;

  L400:
  x3 = XEXP (x2, 1);
  if (GET_CODE (x3) == CONST_INT && XWINT (x3, 0) == -2147483647-1 && 1)
    goto L401;
  goto L631;

  L401:
  x2 = XEXP (x1, 1);
  if (pc_or_label_ref (x2, VOIDmode))
    {
      ro[2] = x2;
      goto L402;
    }
  x2 = XEXP (x1, 0);
  goto L631;

  L402:
  x2 = XEXP (x1, 2);
  if (pc_or_label_ref (x2, VOIDmode))
    {
      ro[3] = x2;
      return 40;
    }
  x2 = XEXP (x1, 0);
  goto L631;

  L428:
  x4 = XEXP (x3, 0);
  if (register_operand (x4, SImode))
    {
      ro[1] = x4;
      goto L429;
    }
  goto L631;

  L429:
  x3 = XEXP (x2, 1);
  if (GET_CODE (x3) == CONST_INT && XWINT (x3, 0) == 0 && 1)
    goto L430;
  goto L631;

  L430:
  x2 = XEXP (x1, 1);
  if (pc_or_label_ref (x2, VOIDmode))
    {
      ro[2] = x2;
      goto L431;
    }
  x2 = XEXP (x1, 0);
  goto L631;

  L431:
  x2 = XEXP (x1, 2);
  if (pc_or_label_ref (x2, VOIDmode))
    {
      ro[3] = x2;
      return 43;
    }
  x2 = XEXP (x1, 0);
  goto L631;

  L437:
  x4 = XEXP (x3, 0);
  if (register_operand (x4, SFmode))
    {
      ro[1] = x4;
      goto L438;
    }
  goto L631;

  L438:
  x3 = XEXP (x2, 1);
  if (GET_CODE (x3) == CONST_INT && XWINT (x3, 0) == 0 && 1)
    goto L439;
  goto L631;

  L439:
  x2 = XEXP (x1, 1);
  if (pc_or_label_ref (x2, VOIDmode))
    {
      ro[2] = x2;
      goto L440;
    }
  x2 = XEXP (x1, 0);
  goto L631;

  L440:
  x2 = XEXP (x1, 2);
  if (pc_or_label_ref (x2, VOIDmode))
    {
      ro[3] = x2;
      return 44;
    }
  x2 = XEXP (x1, 0);
  goto L631;

  L454:
  x3 = XEXP (x2, 1);
  if (GET_CODE (x3) == CONST_INT && XWINT (x3, 0) == 0 && 1)
    goto L455;
  goto L631;

  L455:
  x2 = XEXP (x1, 1);
  if (pc_or_label_ref (x2, VOIDmode))
    {
      ro[2] = x2;
      goto L456;
    }
  x2 = XEXP (x1, 0);
  goto L631;

  L456:
  x2 = XEXP (x1, 2);
  if (pc_or_label_ref (x2, VOIDmode))
    {
      ro[3] = x2;
      return 46;
    }
  x2 = XEXP (x1, 0);
  goto L631;

  L446:
  x3 = XEXP (x2, 1);
  if (GET_CODE (x3) == CONST_INT && XWINT (x3, 0) == 0 && 1)
    goto L447;
  goto L631;

  L447:
  x2 = XEXP (x1, 1);
  if (pc_or_label_ref (x2, VOIDmode))
    {
      ro[2] = x2;
      goto L448;
    }
  x2 = XEXP (x1, 0);
  goto L631;

  L448:
  x2 = XEXP (x1, 2);
  if (pc_or_label_ref (x2, VOIDmode))
    {
      ro[3] = x2;
      return 45;
    }
  x2 = XEXP (x1, 0);
  goto L631;

  L632:
  x3 = XEXP (x2, 0);
  if (register_operand (x3, CCmode))
    {
      ro[1] = x3;
      goto L633;
    }
  goto L639;

  L633:
  x3 = XEXP (x2, 1);
  if (GET_CODE (x3) == CONST_INT && XWINT (x3, 0) == 0 && 1)
    goto L634;
  goto L639;

  L634:
  x2 = XEXP (x1, 1);
  if (pc_or_label_ref (x2, VOIDmode))
    {
      ro[2] = x2;
      goto L635;
    }
  x2 = XEXP (x1, 0);
  goto L639;

  L635:
  x2 = XEXP (x1, 2);
  if (pc_or_label_ref (x2, VOIDmode))
    {
      ro[3] = x2;
      return 94;
    }
  x2 = XEXP (x1, 0);
  goto L639;

  L640:
  x3 = XEXP (x2, 0);
  if (register_operand (x3, CCEVENmode))
    {
      ro[1] = x3;
      goto L641;
    }
  goto L471;

  L641:
  x3 = XEXP (x2, 1);
  if (GET_CODE (x3) == CONST_INT && XWINT (x3, 0) == 0 && 1)
    goto L642;
  goto L471;

  L642:
  x2 = XEXP (x1, 1);
  if (pc_or_label_ref (x2, VOIDmode))
    {
      ro[2] = x2;
      goto L643;
    }
  x2 = XEXP (x1, 0);
  goto L471;

  L643:
  x2 = XEXP (x1, 2);
  if (pc_or_label_ref (x2, VOIDmode))
    {
      ro[3] = x2;
      return 95;
    }
  x2 = XEXP (x1, 0);
  goto L471;

  L648:
  x3 = XEXP (x2, 0);
  if (register_operand (x3, CCEVENmode))
    {
      ro[1] = x3;
      goto L649;
    }
  goto L460;

  L649:
  x3 = XEXP (x2, 1);
  if (GET_CODE (x3) == CONST_INT && XWINT (x3, 0) == 0 && 1)
    goto L650;
  goto L460;

  L650:
  x2 = XEXP (x1, 1);
  if (pc_or_label_ref (x2, VOIDmode))
    {
      ro[2] = x2;
      goto L651;
    }
  x2 = XEXP (x1, 0);
  goto L460;

  L651:
  x2 = XEXP (x1, 2);
  if (pc_or_label_ref (x2, VOIDmode))
    {
      ro[3] = x2;
      return 96;
    }
  x2 = XEXP (x1, 0);
  goto L460;

  L461:
  x3 = XEXP (x2, 0);
  switch (GET_MODE (x3))
    {
    case SImode:
      switch (GET_CODE (x3))
	{
	case SIGN_EXTRACT:
	  goto L462;
	case ZERO_EXTRACT:
	  goto L484;
	case AND:
	  goto L516;
	}
    }
  if (relop (x3, VOIDmode))
    {
      ro[0] = x3;
      goto L657;
    }
  L666:
  if (even_relop (x3, VOIDmode))
    {
      ro[0] = x3;
      goto L667;
    }
  if (odd_relop (x3, VOIDmode))
    {
      ro[0] = x3;
      goto L677;
    }
  goto ret0;

  L462:
  x4 = XEXP (x3, 0);
  if (register_operand (x4, SImode))
    {
      ro[0] = x4;
      goto L463;
    }
  goto ret0;

  L463:
  x4 = XEXP (x3, 1);
  if (GET_CODE (x4) == CONST_INT && XWINT (x4, 0) == 1 && 1)
    goto L464;
  goto ret0;

  L464:
  x4 = XEXP (x3, 2);
  if (GET_CODE (x4) == CONST_INT && int5_operand (x4, SImode))
    {
      ro[1] = x4;
      goto L465;
    }
  goto ret0;

  L465:
  x3 = XEXP (x2, 1);
  if (GET_CODE (x3) == CONST_INT && XWINT (x3, 0) == 0 && 1)
    goto L466;
  goto ret0;

  L466:
  x2 = XEXP (x1, 1);
  if (pc_or_label_ref (x2, VOIDmode))
    {
      ro[2] = x2;
      goto L467;
    }
  goto ret0;

  L467:
  x2 = XEXP (x1, 2);
  if (pc_or_label_ref (x2, VOIDmode))
    {
      ro[3] = x2;
      return 47;
    }
  goto ret0;

  L484:
  x4 = XEXP (x3, 0);
  if (register_operand (x4, SImode))
    {
      ro[0] = x4;
      goto L485;
    }
  goto ret0;

  L485:
  x4 = XEXP (x3, 1);
  if (GET_CODE (x4) == CONST_INT && XWINT (x4, 0) == 1 && 1)
    goto L486;
  goto ret0;

  L486:
  x4 = XEXP (x3, 2);
  if (GET_CODE (x4) == CONST_INT && int5_operand (x4, SImode))
    {
      ro[1] = x4;
      goto L487;
    }
  goto ret0;

  L487:
  x3 = XEXP (x2, 1);
  if (GET_CODE (x3) == CONST_INT && XWINT (x3, 0) == 0 && 1)
    goto L488;
  goto ret0;

  L488:
  x2 = XEXP (x1, 1);
  if (pc_or_label_ref (x2, VOIDmode))
    {
      ro[2] = x2;
      goto L489;
    }
  goto ret0;

  L489:
  x2 = XEXP (x1, 2);
  if (pc_or_label_ref (x2, VOIDmode))
    {
      ro[3] = x2;
      return 49;
    }
  goto ret0;

  L516:
  x4 = XEXP (x3, 0);
  if (reg_or_bbx_mask_operand (x4, SImode))
    {
      ro[0] = x4;
      goto L517;
    }
  goto ret0;

  L517:
  x4 = XEXP (x3, 1);
  if (reg_or_bbx_mask_operand (x4, SImode))
    {
      ro[1] = x4;
      goto L518;
    }
  goto ret0;

  L518:
  x3 = XEXP (x2, 1);
  if (GET_CODE (x3) == CONST_INT && XWINT (x3, 0) == 0 && 1)
    goto L519;
  goto ret0;

  L519:
  x2 = XEXP (x1, 1);
  if (pc_or_label_ref (x2, VOIDmode))
    {
      ro[2] = x2;
      goto L520;
    }
  goto ret0;

  L520:
  x2 = XEXP (x1, 2);
  if (pc_or_label_ref (x2, VOIDmode))
    {
      ro[3] = x2;
      if ((GET_CODE (operands[0]) == CONST_INT)
   != (GET_CODE (operands[1]) == CONST_INT))
	return 52;
      }
  goto ret0;

  L657:
  x4 = XEXP (x3, 0);
  if (register_operand (x4, CCmode))
    {
      ro[1] = x4;
      goto L658;
    }
  goto L666;

  L658:
  x4 = XEXP (x3, 1);
  if (GET_CODE (x4) == CONST_INT && XWINT (x4, 0) == 0 && 1)
    goto L659;
  goto L666;

  L659:
  x3 = XEXP (x2, 1);
  if (GET_CODE (x3) == CONST_INT && XWINT (x3, 0) == 0 && 1)
    goto L660;
  x3 = XEXP (x2, 0);
  goto L666;

  L660:
  x2 = XEXP (x1, 1);
  if (pc_or_label_ref (x2, VOIDmode))
    {
      ro[2] = x2;
      goto L661;
    }
  x2 = XEXP (x1, 0);
  x3 = XEXP (x2, 0);
  goto L666;

  L661:
  x2 = XEXP (x1, 2);
  if (pc_or_label_ref (x2, VOIDmode))
    {
      ro[3] = x2;
      return 97;
    }
  x2 = XEXP (x1, 0);
  x3 = XEXP (x2, 0);
  goto L666;

  L667:
  x4 = XEXP (x3, 0);
  if (register_operand (x4, CCEVENmode))
    {
      ro[1] = x4;
      goto L668;
    }
  goto ret0;

  L668:
  x4 = XEXP (x3, 1);
  if (GET_CODE (x4) == CONST_INT && XWINT (x4, 0) == 0 && 1)
    goto L669;
  goto ret0;

  L669:
  x3 = XEXP (x2, 1);
  if (GET_CODE (x3) == CONST_INT && XWINT (x3, 0) == 0 && 1)
    goto L670;
  goto ret0;

  L670:
  x2 = XEXP (x1, 1);
  if (pc_or_label_ref (x2, VOIDmode))
    {
      ro[2] = x2;
      goto L671;
    }
  goto ret0;

  L671:
  x2 = XEXP (x1, 2);
  if (pc_or_label_ref (x2, VOIDmode))
    {
      ro[3] = x2;
      return 98;
    }
  goto ret0;

  L677:
  x4 = XEXP (x3, 0);
  if (register_operand (x4, CCEVENmode))
    {
      ro[1] = x4;
      goto L678;
    }
  goto ret0;

  L678:
  x4 = XEXP (x3, 1);
  if (GET_CODE (x4) == CONST_INT && XWINT (x4, 0) == 0 && 1)
    goto L679;
  goto ret0;

  L679:
  x3 = XEXP (x2, 1);
  if (GET_CODE (x3) == CONST_INT && XWINT (x3, 0) == 0 && 1)
    goto L680;
  goto ret0;

  L680:
  x2 = XEXP (x1, 1);
  if (pc_or_label_ref (x2, VOIDmode))
    {
      ro[2] = x2;
      goto L681;
    }
  goto ret0;

  L681:
  x2 = XEXP (x1, 2);
  if (pc_or_label_ref (x2, VOIDmode))
    {
      ro[3] = x2;
      return 99;
    }
  goto ret0;

  L472:
  x3 = XEXP (x2, 0);
  switch (GET_MODE (x3))
    {
    case SImode:
      switch (GET_CODE (x3))
	{
	case SIGN_EXTRACT:
	  goto L473;
	case ZERO_EXTRACT:
	  goto L495;
	case AND:
	  goto L506;
	}
    }
  if (relop (x3, VOIDmode))
    {
      ro[0] = x3;
      goto L687;
    }
  L696:
  if (even_relop (x3, VOIDmode))
    {
      ro[0] = x3;
      goto L697;
    }
  if (odd_relop (x3, VOIDmode))
    {
      ro[0] = x3;
      goto L707;
    }
  goto ret0;

  L473:
  x4 = XEXP (x3, 0);
  if (register_operand (x4, SImode))
    {
      ro[0] = x4;
      goto L474;
    }
  goto ret0;

  L474:
  x4 = XEXP (x3, 1);
  if (GET_CODE (x4) == CONST_INT && XWINT (x4, 0) == 1 && 1)
    goto L475;
  goto ret0;

  L475:
  x4 = XEXP (x3, 2);
  if (GET_CODE (x4) == CONST_INT && int5_operand (x4, SImode))
    {
      ro[1] = x4;
      goto L476;
    }
  goto ret0;

  L476:
  x3 = XEXP (x2, 1);
  if (GET_CODE (x3) == CONST_INT && XWINT (x3, 0) == 0 && 1)
    goto L477;
  goto ret0;

  L477:
  x2 = XEXP (x1, 1);
  if (pc_or_label_ref (x2, VOIDmode))
    {
      ro[2] = x2;
      goto L478;
    }
  goto ret0;

  L478:
  x2 = XEXP (x1, 2);
  if (pc_or_label_ref (x2, VOIDmode))
    {
      ro[3] = x2;
      return 48;
    }
  goto ret0;

  L495:
  x4 = XEXP (x3, 0);
  if (register_operand (x4, SImode))
    {
      ro[0] = x4;
      goto L496;
    }
  goto ret0;

  L496:
  x4 = XEXP (x3, 1);
  if (GET_CODE (x4) == CONST_INT && XWINT (x4, 0) == 1 && 1)
    goto L497;
  goto ret0;

  L497:
  x4 = XEXP (x3, 2);
  if (GET_CODE (x4) == CONST_INT && int5_operand (x4, SImode))
    {
      ro[1] = x4;
      goto L498;
    }
  goto ret0;

  L498:
  x3 = XEXP (x2, 1);
  if (GET_CODE (x3) == CONST_INT && XWINT (x3, 0) == 0 && 1)
    goto L499;
  goto ret0;

  L499:
  x2 = XEXP (x1, 1);
  if (pc_or_label_ref (x2, VOIDmode))
    {
      ro[2] = x2;
      goto L500;
    }
  goto ret0;

  L500:
  x2 = XEXP (x1, 2);
  if (pc_or_label_ref (x2, VOIDmode))
    {
      ro[3] = x2;
      return 50;
    }
  goto ret0;

  L506:
  x4 = XEXP (x3, 0);
  if (reg_or_bbx_mask_operand (x4, SImode))
    {
      ro[0] = x4;
      goto L507;
    }
  goto ret0;

  L507:
  x4 = XEXP (x3, 1);
  if (reg_or_bbx_mask_operand (x4, SImode))
    {
      ro[1] = x4;
      goto L508;
    }
  goto ret0;

  L508:
  x3 = XEXP (x2, 1);
  if (GET_CODE (x3) == CONST_INT && XWINT (x3, 0) == 0 && 1)
    goto L509;
  goto ret0;

  L509:
  x2 = XEXP (x1, 1);
  if (pc_or_label_ref (x2, VOIDmode))
    {
      ro[2] = x2;
      goto L510;
    }
  goto ret0;

  L510:
  x2 = XEXP (x1, 2);
  if (pc_or_label_ref (x2, VOIDmode))
    {
      ro[3] = x2;
      if ((GET_CODE (operands[0]) == CONST_INT)
   != (GET_CODE (operands[1]) == CONST_INT))
	return 51;
      }
  goto ret0;

  L687:
  x4 = XEXP (x3, 0);
  if (register_operand (x4, CCmode))
    {
      ro[1] = x4;
      goto L688;
    }
  goto L696;

  L688:
  x4 = XEXP (x3, 1);
  if (GET_CODE (x4) == CONST_INT && XWINT (x4, 0) == 0 && 1)
    goto L689;
  goto L696;

  L689:
  x3 = XEXP (x2, 1);
  if (GET_CODE (x3) == CONST_INT && XWINT (x3, 0) == 0 && 1)
    goto L690;
  x3 = XEXP (x2, 0);
  goto L696;

  L690:
  x2 = XEXP (x1, 1);
  if (pc_or_label_ref (x2, VOIDmode))
    {
      ro[2] = x2;
      goto L691;
    }
  x2 = XEXP (x1, 0);
  x3 = XEXP (x2, 0);
  goto L696;

  L691:
  x2 = XEXP (x1, 2);
  if (pc_or_label_ref (x2, VOIDmode))
    {
      ro[3] = x2;
      return 100;
    }
  x2 = XEXP (x1, 0);
  x3 = XEXP (x2, 0);
  goto L696;

  L697:
  x4 = XEXP (x3, 0);
  if (register_operand (x4, CCEVENmode))
    {
      ro[1] = x4;
      goto L698;
    }
  goto ret0;

  L698:
  x4 = XEXP (x3, 1);
  if (GET_CODE (x4) == CONST_INT && XWINT (x4, 0) == 0 && 1)
    goto L699;
  goto ret0;

  L699:
  x3 = XEXP (x2, 1);
  if (GET_CODE (x3) == CONST_INT && XWINT (x3, 0) == 0 && 1)
    goto L700;
  goto ret0;

  L700:
  x2 = XEXP (x1, 1);
  if (pc_or_label_ref (x2, VOIDmode))
    {
      ro[2] = x2;
      goto L701;
    }
  goto ret0;

  L701:
  x2 = XEXP (x1, 2);
  if (pc_or_label_ref (x2, VOIDmode))
    {
      ro[3] = x2;
      return 101;
    }
  goto ret0;

  L707:
  x4 = XEXP (x3, 0);
  if (register_operand (x4, CCEVENmode))
    {
      ro[1] = x4;
      goto L708;
    }
  goto ret0;

  L708:
  x4 = XEXP (x3, 1);
  if (GET_CODE (x4) == CONST_INT && XWINT (x4, 0) == 0 && 1)
    goto L709;
  goto ret0;

  L709:
  x3 = XEXP (x2, 1);
  if (GET_CODE (x3) == CONST_INT && XWINT (x3, 0) == 0 && 1)
    goto L710;
  goto ret0;

  L710:
  x2 = XEXP (x1, 1);
  if (pc_or_label_ref (x2, VOIDmode))
    {
      ro[2] = x2;
      goto L711;
    }
  goto ret0;

  L711:
  x2 = XEXP (x1, 2);
  if (pc_or_label_ref (x2, VOIDmode))
    {
      ro[3] = x2;
      return 102;
    }
  goto ret0;
 ret0: return -1;
}

int
recog_5 (x0, insn, pnum_clobbers)
     register rtx x0;
     rtx insn;
     int *pnum_clobbers;
{
  register rtx *ro = &recog_operand[0];
  register rtx x1, x2, x3, x4, x5;
  int tem;

  x1 = XEXP (x0, 0);
  switch (GET_MODE (x1))
    {
    case SImode:
      if (register_operand (x1, SImode))
	{
	  ro[0] = x1;
	  goto L53;
	}
    L730:
      if (nonimmediate_operand (x1, SImode))
	{
	  ro[0] = x1;
	  goto L731;
	}
    L733:
      if (register_operand (x1, SImode))
	{
	  ro[0] = x1;
	  goto L737;
	}
    L999:
      if (reg_or_0_operand (x1, SImode))
	{
	  ro[0] = x1;
	  goto L1000;
	}
    L1186:
      if (register_operand (x1, SImode))
	{
	  ro[0] = x1;
	  goto L1205;
	}
      break;
    case CCEVENmode:
      if (register_operand (x1, CCEVENmode))
	{
	  ro[0] = x1;
	  goto L243;
	}
      break;
    case CCmode:
      if (GET_CODE (x1) == REG && XINT (x1, 0) == 0 && 1)
	goto L995;
    L264:
      if (register_operand (x1, CCmode))
	{
	  ro[0] = x1;
	  goto L265;
	}
      break;
    case HImode:
      if (nonimmediate_operand (x1, HImode))
	{
	  ro[0] = x1;
	  goto L757;
	}
    L759:
      if (register_operand (x1, HImode))
	{
	  ro[0] = x1;
	  goto L760;
	}
      break;
    case QImode:
      if (nonimmediate_operand (x1, QImode))
	{
	  ro[0] = x1;
	  goto L766;
	}
    L768:
      if (register_operand (x1, QImode))
	{
	  ro[0] = x1;
	  goto L769;
	}
      break;
    case DImode:
      if (register_operand (x1, DImode))
	{
	  ro[0] = x1;
	  goto L775;
	}
    L777:
      if (nonimmediate_operand (x1, DImode))
	{
	  ro[0] = x1;
	  goto L778;
	}
    L780:
      if (register_operand (x1, DImode))
	{
	  ro[0] = x1;
	  goto L781;
	}
      break;
    case DFmode:
      if (register_operand (x1, DFmode))
	{
	  ro[0] = x1;
	  goto L793;
	}
    L795:
      if (nonimmediate_operand (x1, DFmode))
	{
	  ro[0] = x1;
	  goto L796;
	}
    L798:
      if (register_operand (x1, DFmode))
	{
	  ro[0] = x1;
	  goto L799;
	}
      break;
    case SFmode:
      if (register_operand (x1, SFmode))
	{
	  ro[0] = x1;
	  goto L808;
	}
    L810:
      if (nonimmediate_operand (x1, SFmode))
	{
	  ro[0] = x1;
	  goto L811;
	}
    L813:
      if (register_operand (x1, SFmode))
	{
	  ro[0] = x1;
	  goto L814;
	}
      break;
    case BLKmode:
      if (memory_operand (x1, BLKmode))
	{
	  ro[0] = x1;
	  goto L835;
	}
    }
  switch (GET_CODE (x1))
    {
    case ZERO_EXTRACT:
      if (GET_MODE (x1) == SImode && 1)
	goto L1362;
      break;
    case PC:
      goto L1462;
    case SUBREG:
    case REG:
    L1451:
      if (register_operand (x1, VOIDmode))
	{
	  ro[0] = x1;
	  goto L1452;
	}
    }
  goto ret0;
 L53:
  tem = recog_1 (x0, insn, pnum_clobbers);
  if (tem >= 0) return tem;
  x1 = XEXP (x0, 0);
  goto L730;

  L731:
  x1 = XEXP (x0, 1);
  if (move_operand (x1, SImode))
    {
      ro[1] = x1;
      if ((register_operand (operands[0], SImode)
    || register_operand (operands[1], SImode)
    || operands[1] == const0_rtx))
	return 107;
      }
  x1 = XEXP (x0, 0);
  goto L733;

  L737:
  x1 = XEXP (x0, 1);
  switch (GET_MODE (x1))
    {
    case SImode:
      switch (GET_CODE (x1))
	{
	case LO_SUM:
	  goto L738;
	case HIGH:
	  goto L749;
	case ZERO_EXTEND:
	  goto L848;
	case SIGN_EXTEND:
	  goto L860;
	case FIX:
	  goto L900;
	case PLUS:
	  goto L908;
	case MINUS:
	  goto L1008;
	case MULT:
	  goto L1108;
	case DIV:
	  goto L1144;
	case UDIV:
	  goto L1149;
	}
    }
  if (arith32_operand (x1, SImode))
    {
      ro[1] = x1;
      return 108;
    }
  L829:
  if (memory_operand (x1, BLKmode))
    {
      ro[1] = x1;
      return 138;
    }
  x1 = XEXP (x0, 0);
  goto L999;

  L738:
  x2 = XEXP (x1, 0);
  if (register_operand (x2, SImode))
    {
      ro[1] = x2;
      goto L744;
    }
  x1 = XEXP (x0, 0);
  goto L999;

  L744:
  x2 = XEXP (x1, 1);
  if (GET_MODE (x2) == SImode && GET_CODE (x2) == UNSPEC && XINT (x2, 1) == 0 && XVECLEN (x2, 0) == 1 && 1)
    goto L745;
  if (immediate_operand (x2, SImode))
    {
      ro[2] = x2;
      return 109;
    }
  x1 = XEXP (x0, 0);
  goto L999;

  L745:
  x3 = XVECEXP (x2, 0, 0);
  if (immediate_operand (x3, SImode))
    {
      ro[2] = x3;
      return 110;
    }
  x1 = XEXP (x0, 0);
  goto L999;

  L749:
  x2 = XEXP (x1, 0);
  ro[1] = x2;
  return 111;
  L753:
  if (GET_MODE (x2) == SImode && GET_CODE (x2) == UNSPEC && XINT (x2, 1) == 0 && XVECLEN (x2, 0) == 1 && 1)
    goto L754;
  x1 = XEXP (x0, 0);
  goto L999;

  L754:
  x3 = XVECEXP (x2, 0, 0);
  ro[1] = x3;
  return 112;

  L848:
  x2 = XEXP (x1, 0);
  switch (GET_MODE (x2))
    {
    case HImode:
      if (move_operand (x2, HImode))
	{
	  ro[1] = x2;
	  if (GET_CODE (operands[1]) != CONST_INT)
	    return 147;
	  }
      break;
    case QImode:
      if (move_operand (x2, QImode))
	{
	  ro[1] = x2;
	  if (GET_CODE (operands[1]) != CONST_INT)
	    return 151;
	  }
    }
  x1 = XEXP (x0, 0);
  goto L999;

  L860:
  x2 = XEXP (x1, 0);
  switch (GET_MODE (x2))
    {
    case HImode:
      if (move_operand (x2, HImode))
	{
	  ro[1] = x2;
	  if (GET_CODE (operands[1]) != CONST_INT)
	    return 154;
	  }
      break;
    case QImode:
      if (move_operand (x2, QImode))
	{
	  ro[1] = x2;
	  if (GET_CODE (operands[1]) != CONST_INT)
	    return 158;
	  }
    }
  x1 = XEXP (x0, 0);
  goto L999;

  L900:
  x2 = XEXP (x1, 0);
  switch (GET_MODE (x2))
    {
    case DFmode:
      if (register_operand (x2, DFmode))
	{
	  ro[1] = x2;
	  return 167;
	}
      break;
    case SFmode:
      if (register_operand (x2, SFmode))
	{
	  ro[1] = x2;
	  return 168;
	}
    }
  x1 = XEXP (x0, 0);
  goto L999;

  L908:
  x2 = XEXP (x1, 0);
  if (add_operand (x2, SImode))
    {
      ro[1] = x2;
      goto L909;
    }
  x1 = XEXP (x0, 0);
  goto L999;

  L909:
  x2 = XEXP (x1, 1);
  if (add_operand (x2, SImode))
    {
      ro[2] = x2;
      return 169;
    }
  x1 = XEXP (x0, 0);
  goto L999;

  L1008:
  x2 = XEXP (x1, 0);
  if (register_operand (x2, SImode))
    {
      ro[1] = x2;
      goto L1009;
    }
  x1 = XEXP (x0, 0);
  goto L999;

  L1009:
  x2 = XEXP (x1, 1);
  if (arith32_operand (x2, SImode))
    {
      ro[2] = x2;
      return 182;
    }
  x1 = XEXP (x0, 0);
  goto L999;

  L1108:
  x2 = XEXP (x1, 0);
  if (arith32_operand (x2, SImode))
    {
      ro[1] = x2;
      goto L1109;
    }
  x1 = XEXP (x0, 0);
  goto L999;

  L1109:
  x2 = XEXP (x1, 1);
  if (arith32_operand (x2, SImode))
    {
      ro[2] = x2;
      return 195;
    }
  x1 = XEXP (x0, 0);
  goto L999;

  L1144:
  x2 = XEXP (x1, 0);
  if (register_operand (x2, SImode))
    {
      ro[1] = x2;
      goto L1145;
    }
  x1 = XEXP (x0, 0);
  goto L999;

  L1145:
  x2 = XEXP (x1, 1);
  if (arith_operand (x2, SImode))
    {
      ro[2] = x2;
      return 205;
    }
  x1 = XEXP (x0, 0);
  goto L999;

  L1149:
  x2 = XEXP (x1, 0);
  if (register_operand (x2, SImode))
    {
      ro[1] = x2;
      goto L1150;
    }
  x1 = XEXP (x0, 0);
  goto L999;

  L1150:
  x2 = XEXP (x1, 1);
  if (arith32_operand (x2, SImode))
    {
      ro[2] = x2;
      if (operands[2] != const0_rtx)
	return 207;
      }
  L1155:
  if (GET_CODE (x2) == CONST_INT && XWINT (x2, 0) == 0 && 1)
    return 208;
  x1 = XEXP (x0, 0);
  goto L999;

  L1000:
  x1 = XEXP (x0, 1);
  if (GET_MODE (x1) != SImode)
    {
      x1 = XEXP (x0, 0);
      goto L1186;
    }
  switch (GET_CODE (x1))
    {
    case PLUS:
      goto L1001;
    case MINUS:
      goto L1101;
    }
  x1 = XEXP (x0, 0);
  goto L1186;

  L1001:
  x2 = XEXP (x1, 0);
  if (reg_or_0_operand (x2, SImode))
    {
      ro[1] = x2;
      goto L1002;
    }
  x1 = XEXP (x0, 0);
  goto L1186;

  L1002:
  x2 = XEXP (x1, 1);
  if (GET_MODE (x2) == SImode && GET_CODE (x2) == UNSPEC && XINT (x2, 1) == 0 && XVECLEN (x2, 0) == 2 && 1)
    goto L1003;
  x1 = XEXP (x0, 0);
  goto L1186;

  L1003:
  x3 = XVECEXP (x2, 0, 0);
  if (reg_or_0_operand (x3, SImode))
    {
      ro[2] = x3;
      goto L1004;
    }
  x1 = XEXP (x0, 0);
  goto L1186;

  L1004:
  x3 = XVECEXP (x2, 0, 1);
  if (GET_MODE (x3) == CCmode && GET_CODE (x3) == REG && XINT (x3, 0) == 0 && 1)
    return 181;
  x1 = XEXP (x0, 0);
  goto L1186;

  L1101:
  x2 = XEXP (x1, 0);
  if (reg_or_0_operand (x2, SImode))
    {
      ro[1] = x2;
      goto L1102;
    }
  x1 = XEXP (x0, 0);
  goto L1186;

  L1102:
  x2 = XEXP (x1, 1);
  if (GET_MODE (x2) == SImode && GET_CODE (x2) == UNSPEC && XINT (x2, 1) == 1 && XVECLEN (x2, 0) == 2 && 1)
    goto L1103;
  x1 = XEXP (x0, 0);
  goto L1186;

  L1103:
  x3 = XVECEXP (x2, 0, 0);
  if (reg_or_0_operand (x3, SImode))
    {
      ro[2] = x3;
      goto L1104;
    }
  x1 = XEXP (x0, 0);
  goto L1186;

  L1104:
  x3 = XVECEXP (x2, 0, 1);
  if (GET_MODE (x3) == CCmode && GET_CODE (x3) == REG && XINT (x3, 0) == 0 && 1)
    return 194;
  x1 = XEXP (x0, 0);
  goto L1186;
 L1205:
  tem = recog_2 (x0, insn, pnum_clobbers);
  if (tem >= 0) return tem;
  x1 = XEXP (x0, 0);
  goto L1451;

  L243:
  x1 = XEXP (x0, 1);
  switch (GET_MODE (x1))
    {
    case CCEVENmode:
      switch (GET_CODE (x1))
	{
	case AND:
	  goto L244;
	case IOR:
	  goto L255;
	}
      break;
    case CCmode:
      switch (GET_CODE (x1))
	{
	case ROTATE:
	  goto L271;
	case IOR:
	  goto L296;
	}
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L244:
  x2 = XEXP (x1, 0);
  switch (GET_MODE (x2))
    {
    case CCmode:
      switch (GET_CODE (x2))
	{
	case NOT:
	  goto L383;
	case ROTATE:
	  goto L354;
	}
    }
  if (partial_ccmode_register_operand (x2, VOIDmode))
    {
      ro[1] = x2;
      goto L251;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L383:
  x3 = XEXP (x2, 0);
  if (GET_MODE (x3) == CCmode && GET_CODE (x3) == ROTATE && 1)
    goto L384;
  if (partial_ccmode_register_operand (x3, VOIDmode))
    {
      ro[1] = x3;
      goto L246;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L384:
  x4 = XEXP (x3, 0);
  if (partial_ccmode_register_operand (x4, VOIDmode))
    {
      ro[1] = x4;
      goto L385;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L385:
  x4 = XEXP (x3, 1);
  if (GET_CODE (x4) == CONST_INT && int5_operand (x4, CCmode))
    {
      ro[2] = x4;
      goto L386;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L386:
  x2 = XEXP (x1, 1);
  if (pnum_clobbers != 0 && partial_ccmode_register_operand (x2, VOIDmode))
    {
      ro[3] = x2;
      *pnum_clobbers = 1;
      return 38;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L246:
  x2 = XEXP (x1, 1);
  if (partial_ccmode_register_operand (x2, VOIDmode))
    {
      ro[2] = x2;
      return 25;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L354:
  x3 = XEXP (x2, 0);
  if (partial_ccmode_register_operand (x3, VOIDmode))
    {
      ro[1] = x3;
      goto L355;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L355:
  x3 = XEXP (x2, 1);
  if (GET_CODE (x3) == CONST_INT && int5_operand (x3, CCmode))
    {
      ro[2] = x3;
      goto L356;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L356:
  x2 = XEXP (x1, 1);
  if (pnum_clobbers != 0 && partial_ccmode_register_operand (x2, VOIDmode))
    {
      ro[3] = x2;
      *pnum_clobbers = 1;
      return 36;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L251:
  x2 = XEXP (x1, 1);
  if (partial_ccmode_register_operand (x2, VOIDmode))
    {
      ro[2] = x2;
      return 26;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L255:
  x2 = XEXP (x1, 0);
  if (GET_MODE (x2) == CCmode && GET_CODE (x2) == NOT && 1)
    goto L326;
  if (partial_ccmode_register_operand (x2, VOIDmode))
    {
      ro[1] = x2;
      goto L262;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L326:
  x3 = XEXP (x2, 0);
  if (GET_MODE (x3) == CCmode && GET_CODE (x3) == ROTATE && 1)
    goto L327;
  if (partial_ccmode_register_operand (x3, VOIDmode))
    {
      ro[1] = x3;
      goto L257;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L327:
  x4 = XEXP (x3, 0);
  if (partial_ccmode_register_operand (x4, VOIDmode))
    {
      ro[1] = x4;
      goto L328;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L328:
  x4 = XEXP (x3, 1);
  if (GET_CODE (x4) == CONST_INT && int5_operand (x4, CCmode))
    {
      ro[2] = x4;
      goto L329;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L329:
  x2 = XEXP (x1, 1);
  if (pnum_clobbers != 0 && partial_ccmode_register_operand (x2, VOIDmode))
    {
      ro[3] = x2;
      *pnum_clobbers = 1;
      return 34;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L257:
  x2 = XEXP (x1, 1);
  if (partial_ccmode_register_operand (x2, VOIDmode))
    {
      ro[2] = x2;
      return 27;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L262:
  x2 = XEXP (x1, 1);
  if (partial_ccmode_register_operand (x2, VOIDmode))
    {
      ro[2] = x2;
      return 28;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L271:
  x2 = XEXP (x1, 0);
  if (partial_ccmode_register_operand (x2, VOIDmode))
    {
      ro[1] = x2;
      goto L272;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L272:
  x2 = XEXP (x1, 1);
  if (GET_CODE (x2) == CONST_INT && int5_operand (x2, CCmode))
    {
      ro[2] = x2;
      return 30;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L296:
  x2 = XEXP (x1, 0);
  if (GET_MODE (x2) == CCmode && GET_CODE (x2) == ROTATE && 1)
    goto L297;
  x1 = XEXP (x0, 0);
  goto L1451;

  L297:
  x3 = XEXP (x2, 0);
  if (partial_ccmode_register_operand (x3, VOIDmode))
    {
      ro[1] = x3;
      goto L298;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L298:
  x3 = XEXP (x2, 1);
  if (GET_CODE (x3) == CONST_INT && int5_operand (x3, CCmode))
    {
      ro[2] = x3;
      goto L299;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L299:
  x2 = XEXP (x1, 1);
  if (pnum_clobbers != 0 && partial_ccmode_register_operand (x2, VOIDmode))
    {
      ro[3] = x2;
      *pnum_clobbers = 1;
      return 32;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L995:
  x1 = XEXP (x0, 1);
  if (GET_MODE (x1) != CCmode)
    {
      x1 = XEXP (x0, 0);
      goto L264;
    }
  if (GET_CODE (x1) != UNSPEC)
    {
      x1 = XEXP (x0, 0);
    goto L264;
    }
  if (XINT (x1, 1) == 0 && XVECLEN (x1, 0) == 2 && 1)
    goto L996;
  if (XINT (x1, 1) == 1 && XVECLEN (x1, 0) == 2 && 1)
    goto L1096;
  x1 = XEXP (x0, 0);
  goto L264;

  L996:
  x2 = XVECEXP (x1, 0, 0);
  if (reg_or_0_operand (x2, SImode))
    {
      ro[0] = x2;
      goto L997;
    }
  x1 = XEXP (x0, 0);
  goto L264;

  L997:
  x2 = XVECEXP (x1, 0, 1);
  if (reg_or_0_operand (x2, SImode))
    {
      ro[1] = x2;
      return 180;
    }
  x1 = XEXP (x0, 0);
  goto L264;

  L1096:
  x2 = XVECEXP (x1, 0, 0);
  if (reg_or_0_operand (x2, SImode))
    {
      ro[0] = x2;
      goto L1097;
    }
  x1 = XEXP (x0, 0);
  goto L264;

  L1097:
  x2 = XVECEXP (x1, 0, 1);
  if (reg_or_0_operand (x2, SImode))
    {
      ro[1] = x2;
      return 193;
    }
  x1 = XEXP (x0, 0);
  goto L264;

  L265:
  x1 = XEXP (x0, 1);
  if (GET_MODE (x1) != CCmode)
    {
      x1 = XEXP (x0, 0);
      goto L1451;
    }
  switch (GET_CODE (x1))
    {
    case ROTATE:
      goto L266;
    case COMPARE:
      goto L524;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L266:
  x2 = XEXP (x1, 0);
  if (register_operand (x2, CCmode))
    {
      ro[1] = x2;
      goto L267;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L267:
  x2 = XEXP (x1, 1);
  if (GET_CODE (x2) == CONST_INT && int5_operand (x2, CCmode))
    {
      ro[2] = x2;
      return 29;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L524:
  x2 = XEXP (x1, 0);
  switch (GET_MODE (x2))
    {
    case SImode:
      if (register_operand (x2, SImode))
	{
	  ro[1] = x2;
	  goto L525;
	}
      break;
    case SFmode:
      if (register_operand (x2, SFmode))
	{
	  ro[1] = x2;
	  goto L530;
	}
      break;
    case DFmode:
      if (GET_CODE (x2) == FLOAT_EXTEND && 1)
	goto L541;
      if (register_operand (x2, DFmode))
	{
	  ro[1] = x2;
	  goto L535;
	}
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L525:
  x2 = XEXP (x1, 1);
  if (arith_operand (x2, SImode))
    {
      ro[2] = x2;
      return 57;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L530:
  x2 = XEXP (x1, 1);
  if (real_or_0_operand (x2, SFmode))
    {
      ro[2] = x2;
      return 58;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L541:
  x3 = XEXP (x2, 0);
  if (register_operand (x3, SFmode))
    {
      ro[1] = x3;
      goto L542;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L542:
  x2 = XEXP (x1, 1);
  if (register_operand (x2, DFmode))
    {
      ro[2] = x2;
      return 60;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L535:
  x2 = XEXP (x1, 1);
  if (GET_MODE (x2) != DFmode)
    {
      x1 = XEXP (x0, 0);
      goto L1451;
    }
  if (GET_CODE (x2) == FLOAT_EXTEND && 1)
    goto L536;
  if (real_or_0_operand (x2, DFmode))
    {
      ro[2] = x2;
      return 61;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L536:
  x3 = XEXP (x2, 0);
  if (register_operand (x3, SFmode))
    {
      ro[2] = x3;
      return 59;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L757:
  x1 = XEXP (x0, 1);
  if (move_operand (x1, HImode))
    {
      ro[1] = x1;
      if ((register_operand (operands[0], HImode)
    || register_operand (operands[1], HImode)
    || operands[1] == const0_rtx))
	return 114;
      }
  x1 = XEXP (x0, 0);
  goto L759;

  L760:
  x1 = XEXP (x0, 1);
  switch (GET_MODE (x1))
    {
    case HImode:
      switch (GET_CODE (x1))
	{
	case SUBREG:
	  if (XINT (x1, 1) == 0 && 1)
	    goto L761;
	  break;
	case ZERO_EXTEND:
	  goto L852;
	case SIGN_EXTEND:
	  goto L864;
	}
      break;
    case BLKmode:
      if (memory_operand (x1, BLKmode))
	{
	  ro[1] = x1;
	  return 137;
	}
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L761:
  x2 = XEXP (x1, 0);
  if (GET_MODE (x2) == SImode && GET_CODE (x2) == LO_SUM && 1)
    goto L762;
  x1 = XEXP (x0, 0);
  goto L1451;

  L762:
  x3 = XEXP (x2, 0);
  if (register_operand (x3, SImode))
    {
      ro[1] = x3;
      goto L763;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L763:
  x3 = XEXP (x2, 1);
  if (immediate_operand (x3, SImode))
    {
      ro[2] = x3;
      if (!flag_pic)
	return 115;
      }
  x1 = XEXP (x0, 0);
  goto L1451;

  L852:
  x2 = XEXP (x1, 0);
  if (GET_MODE (x2) == QImode && move_operand (x2, QImode))
    {
      ro[1] = x2;
      if (GET_CODE (operands[1]) != CONST_INT)
	return 149;
      }
  x1 = XEXP (x0, 0);
  goto L1451;

  L864:
  x2 = XEXP (x1, 0);
  if (GET_MODE (x2) == QImode && move_operand (x2, QImode))
    {
      ro[1] = x2;
      if (GET_CODE (operands[1]) != CONST_INT)
	return 156;
      }
  x1 = XEXP (x0, 0);
  goto L1451;

  L766:
  x1 = XEXP (x0, 1);
  if (move_operand (x1, QImode))
    {
      ro[1] = x1;
      if ((register_operand (operands[0], QImode)
    || register_operand (operands[1], QImode)
    || operands[1] == const0_rtx))
	return 117;
      }
  x1 = XEXP (x0, 0);
  goto L768;

  L769:
  x1 = XEXP (x0, 1);
  switch (GET_MODE (x1))
    {
    case QImode:
      if (GET_CODE (x1) == SUBREG && XINT (x1, 1) == 0 && 1)
	goto L770;
      break;
    case BLKmode:
      if (memory_operand (x1, BLKmode))
	{
	  ro[1] = x1;
	  return 136;
	}
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L770:
  x2 = XEXP (x1, 0);
  if (GET_MODE (x2) == SImode && GET_CODE (x2) == LO_SUM && 1)
    goto L771;
  x1 = XEXP (x0, 0);
  goto L1451;

  L771:
  x3 = XEXP (x2, 0);
  if (register_operand (x3, SImode))
    {
      ro[1] = x3;
      goto L772;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L772:
  x3 = XEXP (x2, 1);
  if (immediate_operand (x3, SImode))
    {
      ro[2] = x3;
      if (!flag_pic)
	return 118;
      }
  x1 = XEXP (x0, 0);
  goto L1451;

  L775:
  x1 = XEXP (x0, 1);
  if (GET_CODE (x1) == CONST_INT && XWINT (x1, 0) == 0 && 1)
    return 120;
  x1 = XEXP (x0, 0);
  goto L777;

  L778:
  x1 = XEXP (x0, 1);
  if (nonimmediate_operand (x1, DImode))
    {
      ro[1] = x1;
      return 121;
    }
  x1 = XEXP (x0, 0);
  goto L780;

  L781:
  x1 = XEXP (x0, 1);
  switch (GET_MODE (x1))
    {
    case DImode:
      switch (GET_CODE (x1))
	{
	case SUBREG:
	  if (XINT (x1, 1) == 0 && 1)
	    goto L782;
	  break;
	case PLUS:
	  goto L966;
	case MINUS:
	  goto L1066;
	case AND:
	  goto L1217;
	case IOR:
	  goto L1239;
	case NOT:
	  goto L1261;
	case XOR:
	  goto L1267;
	}
      break;
    case BLKmode:
      if (memory_operand (x1, BLKmode))
	{
	  ro[1] = x1;
	  return 139;
	}
    }
  if (immediate_operand (x1, DImode))
    {
      ro[1] = x1;
      return 123;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L782:
  x2 = XEXP (x1, 0);
  if (GET_MODE (x2) == SImode && GET_CODE (x2) == LO_SUM && 1)
    goto L783;
  x1 = XEXP (x0, 0);
  goto L1451;

  L783:
  x3 = XEXP (x2, 0);
  if (register_operand (x3, SImode))
    {
      ro[1] = x3;
      goto L784;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L784:
  x3 = XEXP (x2, 1);
  if (immediate_operand (x3, SImode))
    {
      ro[2] = x3;
      if (!flag_pic)
	return 122;
      }
  x1 = XEXP (x0, 0);
  goto L1451;

  L966:
  x2 = XEXP (x1, 0);
  if (GET_MODE (x2) != DImode)
    {
      x1 = XEXP (x0, 0);
      goto L1451;
    }
  if (GET_CODE (x2) == ZERO_EXTEND && 1)
    goto L967;
  if (register_operand (x2, DImode))
    {
      ro[1] = x2;
      goto L952;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L967:
  x3 = XEXP (x2, 0);
  if (register_operand (x3, SImode))
    {
      ro[1] = x3;
      goto L968;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L968:
  x2 = XEXP (x1, 1);
  if (pnum_clobbers != 0 && register_operand (x2, DImode))
    {
      ro[2] = x2;
      *pnum_clobbers = 1;
      return 177;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L952:
  x2 = XEXP (x1, 1);
  if (GET_MODE (x2) != DImode)
    {
      x1 = XEXP (x0, 0);
      goto L1451;
    }
  if (GET_CODE (x2) == ZERO_EXTEND && 1)
    goto L953;
  if (pnum_clobbers != 0 && register_operand (x2, DImode))
    {
      ro[2] = x2;
      *pnum_clobbers = 1;
      return 178;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L953:
  x3 = XEXP (x2, 0);
  if (pnum_clobbers != 0 && register_operand (x3, SImode))
    {
      ro[2] = x3;
      *pnum_clobbers = 1;
      return 176;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L1066:
  x2 = XEXP (x1, 0);
  if (GET_MODE (x2) != DImode)
    {
      x1 = XEXP (x0, 0);
      goto L1451;
    }
  if (GET_CODE (x2) == ZERO_EXTEND && 1)
    goto L1067;
  if (register_operand (x2, DImode))
    {
      ro[1] = x2;
      goto L1052;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L1067:
  x3 = XEXP (x2, 0);
  if (register_operand (x3, SImode))
    {
      ro[1] = x3;
      goto L1068;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L1068:
  x2 = XEXP (x1, 1);
  if (pnum_clobbers != 0 && register_operand (x2, DImode))
    {
      ro[2] = x2;
      *pnum_clobbers = 1;
      return 190;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L1052:
  x2 = XEXP (x1, 1);
  if (GET_MODE (x2) != DImode)
    {
      x1 = XEXP (x0, 0);
      goto L1451;
    }
  if (GET_CODE (x2) == ZERO_EXTEND && 1)
    goto L1053;
  if (pnum_clobbers != 0 && register_operand (x2, DImode))
    {
      ro[2] = x2;
      *pnum_clobbers = 1;
      return 191;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L1053:
  x3 = XEXP (x2, 0);
  if (pnum_clobbers != 0 && register_operand (x3, SImode))
    {
      ro[2] = x3;
      *pnum_clobbers = 1;
      return 189;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L1217:
  x2 = XEXP (x1, 0);
  if (GET_MODE (x2) == DImode && GET_CODE (x2) == NOT && 1)
    goto L1218;
  if (arith64_operand (x2, DImode))
    {
      ro[1] = x2;
      goto L1224;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L1218:
  x3 = XEXP (x2, 0);
  if (register_operand (x3, DImode))
    {
      ro[1] = x3;
      goto L1219;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L1219:
  x2 = XEXP (x1, 1);
  if (register_operand (x2, DImode))
    {
      ro[2] = x2;
      return 224;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L1224:
  x2 = XEXP (x1, 1);
  if (arith64_operand (x2, DImode))
    {
      ro[2] = x2;
      return 225;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L1239:
  x2 = XEXP (x1, 0);
  if (GET_MODE (x2) == DImode && GET_CODE (x2) == NOT && 1)
    goto L1240;
  if (arith64_operand (x2, DImode))
    {
      ro[1] = x2;
      goto L1246;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L1240:
  x3 = XEXP (x2, 0);
  if (register_operand (x3, DImode))
    {
      ro[1] = x3;
      goto L1241;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L1241:
  x2 = XEXP (x1, 1);
  if (register_operand (x2, DImode))
    {
      ro[2] = x2;
      return 229;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L1246:
  x2 = XEXP (x1, 1);
  if (arith64_operand (x2, DImode))
    {
      ro[2] = x2;
      return 230;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L1261:
  x2 = XEXP (x1, 0);
  if (GET_MODE (x2) != DImode)
    {
      x1 = XEXP (x0, 0);
      goto L1451;
    }
  if (GET_CODE (x2) == XOR && 1)
    goto L1262;
  if (register_operand (x2, DImode))
    {
      ro[1] = x2;
      return 237;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L1262:
  x3 = XEXP (x2, 0);
  if (register_operand (x3, DImode))
    {
      ro[1] = x3;
      goto L1263;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L1263:
  x3 = XEXP (x2, 1);
  if (register_operand (x3, DImode))
    {
      ro[2] = x3;
      return 234;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L1267:
  x2 = XEXP (x1, 0);
  if (arith64_operand (x2, DImode))
    {
      ro[1] = x2;
      goto L1268;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L1268:
  x2 = XEXP (x1, 1);
  if (arith64_operand (x2, DImode))
    {
      ro[2] = x2;
      return 235;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L793:
  x1 = XEXP (x0, 1);
  if (GET_CODE (x1) == CONST_INT && XWINT (x1, 0) == 0 && 1)
    return 126;
  x1 = XEXP (x0, 0);
  goto L795;

  L796:
  x1 = XEXP (x0, 1);
  if (nonimmediate_operand (x1, DFmode))
    {
      ro[1] = x1;
      return 127;
    }
  x1 = XEXP (x0, 0);
  goto L798;
 L799:
  tem = recog_3 (x0, insn, pnum_clobbers);
  if (tem >= 0) return tem;
  x1 = XEXP (x0, 0);
  goto L1451;

  L808:
  x1 = XEXP (x0, 1);
  if (GET_CODE (x1) == CONST_INT && XWINT (x1, 0) == 0 && 1)
    return 131;
  x1 = XEXP (x0, 0);
  goto L810;

  L811:
  x1 = XEXP (x0, 1);
  if (nonimmediate_operand (x1, SFmode))
    {
      ro[1] = x1;
      return 132;
    }
  x1 = XEXP (x0, 0);
  goto L813;

  L814:
  x1 = XEXP (x0, 1);
  switch (GET_MODE (x1))
    {
    case SFmode:
      switch (GET_CODE (x1))
	{
	case SUBREG:
	  if (XINT (x1, 1) == 0 && 1)
	    goto L815;
	  break;
	case FLOAT_TRUNCATE:
	  goto L1385;
	case FLOAT:
	  goto L896;
	case PLUS:
	  goto L937;
	case MINUS:
	  goto L1037;
	case MULT:
	  goto L1137;
	case DIV:
	  goto L1178;
	case NEG:
	  goto L1394;
	case ABS:
	  goto L1402;
	}
    }
  if (immediate_operand (x1, SFmode))
    {
      ro[1] = x1;
      if (operands[1] != const0_rtx)
	return 134;
      }
  x1 = XEXP (x0, 0);
  goto L1451;

  L815:
  x2 = XEXP (x1, 0);
  if (GET_MODE (x2) == SImode && GET_CODE (x2) == LO_SUM && 1)
    goto L816;
  x1 = XEXP (x0, 0);
  goto L1451;

  L816:
  x3 = XEXP (x2, 0);
  if (register_operand (x3, SImode))
    {
      ro[1] = x3;
      goto L817;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L817:
  x3 = XEXP (x2, 1);
  if (immediate_operand (x3, SImode))
    {
      ro[2] = x3;
      if (!flag_pic)
	return 133;
      }
  x1 = XEXP (x0, 0);
  goto L1451;

  L1385:
  x2 = XEXP (x1, 0);
  if (GET_MODE (x2) != DFmode)
    {
      x1 = XEXP (x0, 0);
      goto L1451;
    }
  if (GET_CODE (x2) == NEG && 1)
    goto L1386;
  if (register_operand (x2, DFmode))
    goto L887;
  x1 = XEXP (x0, 0);
  goto L1451;

  L1386:
  x3 = XEXP (x2, 0);
  if (register_operand (x3, DFmode))
    {
      ro[1] = x3;
      return 261;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L887:
  ro[1] = x2;
  if (! TARGET_88110)
    return 163;
  L888:
  ro[1] = x2;
  if (TARGET_88110)
    return 164;
  x1 = XEXP (x0, 0);
  goto L1451;

  L896:
  x2 = XEXP (x1, 0);
  if (register_operand (x2, SImode))
    {
      ro[1] = x2;
      return 166;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L937:
  x2 = XEXP (x1, 0);
  if (register_operand (x2, SFmode))
    {
      ro[1] = x2;
      goto L938;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L938:
  x2 = XEXP (x1, 1);
  if (register_operand (x2, SFmode))
    {
      ro[2] = x2;
      return 175;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L1037:
  x2 = XEXP (x1, 0);
  if (register_operand (x2, SFmode))
    {
      ro[1] = x2;
      goto L1038;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L1038:
  x2 = XEXP (x1, 1);
  if (register_operand (x2, SFmode))
    {
      ro[2] = x2;
      return 188;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L1137:
  x2 = XEXP (x1, 0);
  if (register_operand (x2, SFmode))
    {
      ro[1] = x2;
      goto L1138;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L1138:
  x2 = XEXP (x1, 1);
  if (register_operand (x2, SFmode))
    {
      ro[2] = x2;
      return 201;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L1178:
  x2 = XEXP (x1, 0);
  if (register_operand (x2, SFmode))
    {
      ro[1] = x2;
      goto L1179;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L1179:
  x2 = XEXP (x1, 1);
  if (register_operand (x2, SFmode))
    {
      ro[2] = x2;
      return 213;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L1394:
  x2 = XEXP (x1, 0);
  if (register_operand (x2, SFmode))
    {
      ro[1] = x2;
      return 263;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L1402:
  x2 = XEXP (x1, 0);
  if (register_operand (x2, SFmode))
    {
      ro[1] = x2;
      return 265;
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L835:
  x1 = XEXP (x0, 1);
  switch (GET_MODE (x1))
    {
    case QImode:
      if (register_operand (x1, QImode))
	{
	  ro[1] = x1;
	  return 140;
	}
      break;
    case HImode:
      if (register_operand (x1, HImode))
	{
	  ro[1] = x1;
	  return 141;
	}
      break;
    case SImode:
      if (register_operand (x1, SImode))
	{
	  ro[1] = x1;
	  return 142;
	}
      break;
    case DImode:
      if (register_operand (x1, DImode))
	{
	  ro[1] = x1;
	  return 143;
	}
    }
  x1 = XEXP (x0, 0);
  goto L1451;

  L1362:
  x2 = XEXP (x1, 0);
  if (register_operand (x2, SImode))
    {
      ro[0] = x2;
      goto L1363;
    }
  goto ret0;

  L1363:
  x2 = XEXP (x1, 1);
  if (GET_CODE (x2) == CONST_INT && int5_operand (x2, SImode))
    {
      ro[1] = x2;
      goto L1364;
    }
  goto ret0;

  L1364:
  x2 = XEXP (x1, 2);
  if (GET_CODE (x2) == CONST_INT && int5_operand (x2, SImode))
    {
      ro[2] = x2;
      goto L1365;
    }
  goto ret0;

  L1365:
  x1 = XEXP (x0, 1);
  if (GET_CODE (x1) != CONST_INT)
    goto ret0;
  if (XWINT (x1, 0) == 0 && 1)
    return 257;
  if (GET_CODE (x1) != CONST_INT)
    goto ret0;
  if (XWINT (x1, 0) == -1 && 1)
    return 258;
  L1377:
  if (int32_operand (x1, SImode))
    {
      ro[3] = x1;
      return 259;
    }
  goto ret0;

  L1462:
  x1 = XEXP (x0, 1);
  if (register_operand (x1, SImode))
    {
      ro[0] = x1;
      return 279;
    }
  switch (GET_CODE (x1))
    {
    case IF_THEN_ELSE:
      goto L390;
    case LABEL_REF:
      goto L1466;
    }
  goto ret0;
 L390:
  return recog_4 (x0, insn, pnum_clobbers);

  L1466:
  x2 = XEXP (x1, 0);
  ro[0] = x2;
  return 280;

  L1452:
  x1 = XEXP (x0, 1);
  if (GET_CODE (x1) == CALL && 1)
    goto L1453;
  goto ret0;

  L1453:
  x2 = XEXP (x1, 0);
  if (GET_MODE (x2) == SImode && GET_CODE (x2) == MEM && 1)
    goto L1454;
  goto ret0;

  L1454:
  x3 = XEXP (x2, 0);
  if (call_address_operand (x3, SImode))
    {
      ro[1] = x3;
      goto L1455;
    }
  goto ret0;

  L1455:
  x2 = XEXP (x1, 1);
  if (pnum_clobbers != 0 && 1)
    {
      ro[2] = x2;
      *pnum_clobbers = 1;
      return 273;
    }
  goto ret0;
 ret0: return -1;
}

int
recog_6 (x0, insn, pnum_clobbers)
     register rtx x0;
     rtx insn;
     int *pnum_clobbers;
{
  register rtx *ro = &recog_operand[0];
  register rtx x1, x2, x3, x4, x5;
  int tem;

  x1 = XVECEXP (x0, 0, 0);
  x2 = XEXP (x1, 0);
  switch (GET_MODE (x2))
    {
    case CCEVENmode:
      if (register_operand (x2, CCEVENmode))
	{
	  ro[0] = x2;
	  goto L286;
	}
      break;
    case SImode:
      if (GET_CODE (x2) == REG && XINT (x2, 0) == 1 && 1)
	goto L721;
    L574:
      if (register_operand (x2, SImode))
	{
	  ro[0] = x2;
	  goto L616;
	}
    L984:
      if (reg_or_0_operand (x2, SImode))
	{
	  ro[0] = x2;
	  goto L985;
	}
      break;
    case DImode:
      if (register_operand (x2, DImode))
	{
	  ro[0] = x2;
	  goto L942;
	}
    }
  if (GET_CODE (x2) == PC && 1)
    goto L1406;
  L1443:
  if (register_operand (x2, VOIDmode))
    {
      ro[0] = x2;
      goto L1444;
    }
  goto ret0;

  L286:
  x2 = XEXP (x1, 1);
  switch (GET_MODE (x2))
    {
    case CCmode:
      switch (GET_CODE (x2))
	{
	case IOR:
	  goto L287;
	}
      break;
    case CCEVENmode:
      switch (GET_CODE (x2))
	{
	case IOR:
	  goto L315;
	case AND:
	  goto L344;
	}
    }
  x2 = XEXP (x1, 0);
  goto L1443;

  L287:
  x3 = XEXP (x2, 0);
  if (GET_MODE (x3) == CCmode && GET_CODE (x3) == ROTATE && 1)
    goto L288;
  x2 = XEXP (x1, 0);
  goto L1443;

  L288:
  x4 = XEXP (x3, 0);
  if (partial_ccmode_register_operand (x4, VOIDmode))
    {
      ro[1] = x4;
      goto L289;
    }
  x2 = XEXP (x1, 0);
  goto L1443;

  L289:
  x4 = XEXP (x3, 1);
  if (GET_CODE (x4) == CONST_INT && int5_operand (x4, CCmode))
    {
      ro[2] = x4;
      goto L290;
    }
  x2 = XEXP (x1, 0);
  goto L1443;

  L290:
  x3 = XEXP (x2, 1);
  if (partial_ccmode_register_operand (x3, VOIDmode))
    {
      ro[3] = x3;
      goto L291;
    }
  x2 = XEXP (x1, 0);
  goto L1443;

  L291:
  x1 = XVECEXP (x0, 0, 1);
  if (GET_CODE (x1) == CLOBBER && 1)
    goto L292;
  x1 = XVECEXP (x0, 0, 0);
  x2 = XEXP (x1, 0);
  goto L1443;

  L292:
  x2 = XEXP (x1, 0);
  if (scratch_operand (x2, CCEVENmode))
    {
      ro[4] = x2;
      return 32;
    }
  x1 = XVECEXP (x0, 0, 0);
  x2 = XEXP (x1, 0);
  goto L1443;

  L315:
  x3 = XEXP (x2, 0);
  if (GET_MODE (x3) == CCmode && GET_CODE (x3) == NOT && 1)
    goto L316;
  x2 = XEXP (x1, 0);
  goto L1443;

  L316:
  x4 = XEXP (x3, 0);
  if (GET_MODE (x4) == CCmode && GET_CODE (x4) == ROTATE && 1)
    goto L317;
  x2 = XEXP (x1, 0);
  goto L1443;

  L317:
  x5 = XEXP (x4, 0);
  if (partial_ccmode_register_operand (x5, VOIDmode))
    {
      ro[1] = x5;
      goto L318;
    }
  x2 = XEXP (x1, 0);
  goto L1443;

  L318:
  x5 = XEXP (x4, 1);
  if (GET_CODE (x5) == CONST_INT && int5_operand (x5, CCmode))
    {
      ro[2] = x5;
      goto L319;
    }
  x2 = XEXP (x1, 0);
  goto L1443;

  L319:
  x3 = XEXP (x2, 1);
  if (partial_ccmode_register_operand (x3, VOIDmode))
    {
      ro[3] = x3;
      goto L320;
    }
  x2 = XEXP (x1, 0);
  goto L1443;

  L320:
  x1 = XVECEXP (x0, 0, 1);
  if (GET_CODE (x1) == CLOBBER && 1)
    goto L321;
  x1 = XVECEXP (x0, 0, 0);
  x2 = XEXP (x1, 0);
  goto L1443;

  L321:
  x2 = XEXP (x1, 0);
  if (scratch_operand (x2, CCEVENmode))
    {
      ro[4] = x2;
      return 34;
    }
  x1 = XVECEXP (x0, 0, 0);
  x2 = XEXP (x1, 0);
  goto L1443;

  L344:
  x3 = XEXP (x2, 0);
  if (GET_MODE (x3) != CCmode)
    {
      x2 = XEXP (x1, 0);
      goto L1443;
    }
  switch (GET_CODE (x3))
    {
    case ROTATE:
      goto L345;
    case NOT:
      goto L373;
    }
  x2 = XEXP (x1, 0);
  goto L1443;

  L345:
  x4 = XEXP (x3, 0);
  if (partial_ccmode_register_operand (x4, VOIDmode))
    {
      ro[1] = x4;
      goto L346;
    }
  x2 = XEXP (x1, 0);
  goto L1443;

  L346:
  x4 = XEXP (x3, 1);
  if (GET_CODE (x4) == CONST_INT && int5_operand (x4, CCmode))
    {
      ro[2] = x4;
      goto L347;
    }
  x2 = XEXP (x1, 0);
  goto L1443;

  L347:
  x3 = XEXP (x2, 1);
  if (partial_ccmode_register_operand (x3, VOIDmode))
    {
      ro[3] = x3;
      goto L348;
    }
  x2 = XEXP (x1, 0);
  goto L1443;

  L348:
  x1 = XVECEXP (x0, 0, 1);
  if (GET_CODE (x1) == CLOBBER && 1)
    goto L349;
  x1 = XVECEXP (x0, 0, 0);
  x2 = XEXP (x1, 0);
  goto L1443;

  L349:
  x2 = XEXP (x1, 0);
  if (scratch_operand (x2, CCEVENmode))
    {
      ro[4] = x2;
      return 36;
    }
  x1 = XVECEXP (x0, 0, 0);
  x2 = XEXP (x1, 0);
  goto L1443;

  L373:
  x4 = XEXP (x3, 0);
  if (GET_MODE (x4) == CCmode && GET_CODE (x4) == ROTATE && 1)
    goto L374;
  x2 = XEXP (x1, 0);
  goto L1443;

  L374:
  x5 = XEXP (x4, 0);
  if (partial_ccmode_register_operand (x5, VOIDmode))
    {
      ro[1] = x5;
      goto L375;
    }
  x2 = XEXP (x1, 0);
  goto L1443;

  L375:
  x5 = XEXP (x4, 1);
  if (GET_CODE (x5) == CONST_INT && int5_operand (x5, CCmode))
    {
      ro[2] = x5;
      goto L376;
    }
  x2 = XEXP (x1, 0);
  goto L1443;

  L376:
  x3 = XEXP (x2, 1);
  if (partial_ccmode_register_operand (x3, VOIDmode))
    {
      ro[3] = x3;
      goto L377;
    }
  x2 = XEXP (x1, 0);
  goto L1443;

  L377:
  x1 = XVECEXP (x0, 0, 1);
  if (GET_CODE (x1) == CLOBBER && 1)
    goto L378;
  x1 = XVECEXP (x0, 0, 0);
  x2 = XEXP (x1, 0);
  goto L1443;

  L378:
  x2 = XEXP (x1, 0);
  if (scratch_operand (x2, CCEVENmode))
    {
      ro[4] = x2;
      return 38;
    }
  x1 = XVECEXP (x0, 0, 0);
  x2 = XEXP (x1, 0);
  goto L1443;

  L721:
  x2 = XEXP (x1, 1);
  if (GET_CODE (x2) == PC && 1)
    goto L722;
  x2 = XEXP (x1, 0);
  goto L574;

  L722:
  x1 = XVECEXP (x0, 0, 1);
  if (GET_CODE (x1) == SET && 1)
    goto L723;
  x1 = XVECEXP (x0, 0, 0);
  x2 = XEXP (x1, 0);
  goto L574;

  L723:
  x2 = XEXP (x1, 0);
  if (register_operand (x2, SImode))
    {
      ro[0] = x2;
      goto L724;
    }
  x1 = XVECEXP (x0, 0, 0);
  x2 = XEXP (x1, 0);
  goto L574;

  L724:
  x2 = XEXP (x1, 1);
  if (GET_MODE (x2) == SImode && GET_CODE (x2) == LO_SUM && 1)
    goto L725;
  x1 = XVECEXP (x0, 0, 0);
  x2 = XEXP (x1, 0);
  goto L574;

  L725:
  x3 = XEXP (x2, 0);
  if (rtx_equal_p (x3, ro[0]) && 1)
    goto L726;
  x1 = XVECEXP (x0, 0, 0);
  x2 = XEXP (x1, 0);
  goto L574;

  L726:
  x3 = XEXP (x2, 1);
  if (GET_MODE (x3) == SImode && GET_CODE (x3) == UNSPEC && XINT (x3, 1) == 0 && XVECLEN (x3, 0) == 1 && 1)
    goto L727;
  x1 = XVECEXP (x0, 0, 0);
  x2 = XEXP (x1, 0);
  goto L574;

  L727:
  x4 = XVECEXP (x3, 0, 0);
  if (GET_CODE (x4) == LABEL_REF && 1)
    goto L728;
  x1 = XVECEXP (x0, 0, 0);
  x2 = XEXP (x1, 0);
  goto L574;

  L728:
  x5 = XEXP (x4, 0);
  ro[1] = x5;
  return 104;

  L616:
  x2 = XEXP (x1, 1);
  if (GET_MODE (x2) != SImode)
    {
      x2 = XEXP (x1, 0);
      goto L984;
    }
  if (GET_CODE (x2) == NEG && 1)
    goto L617;
  if (odd_relop (x2, SImode))
    {
      ro[1] = x2;
      goto L576;
    }
  x2 = XEXP (x1, 0);
  goto L984;

  L617:
  x3 = XEXP (x2, 0);
  if (odd_relop (x3, SImode))
    {
      ro[1] = x3;
      goto L618;
    }
  x2 = XEXP (x1, 0);
  goto L984;

  L618:
  x4 = XEXP (x3, 0);
  if (register_operand (x4, CCEVENmode))
    {
      ro[2] = x4;
      goto L619;
    }
  x2 = XEXP (x1, 0);
  goto L984;

  L619:
  x4 = XEXP (x3, 1);
  if (GET_CODE (x4) == CONST_INT && XWINT (x4, 0) == 0 && 1)
    goto L620;
  x2 = XEXP (x1, 0);
  goto L984;

  L620:
  x1 = XVECEXP (x0, 0, 1);
  if (GET_CODE (x1) == CLOBBER && 1)
    goto L621;
  x1 = XVECEXP (x0, 0, 0);
  x2 = XEXP (x1, 0);
  goto L984;

  L621:
  x2 = XEXP (x1, 0);
  if (scratch_operand (x2, SImode))
    {
      ro[3] = x2;
      return 81;
    }
  x1 = XVECEXP (x0, 0, 0);
  x2 = XEXP (x1, 0);
  goto L984;

  L576:
  x3 = XEXP (x2, 0);
  if (register_operand (x3, CCEVENmode))
    {
      ro[2] = x3;
      goto L577;
    }
  x2 = XEXP (x1, 0);
  goto L984;

  L577:
  x3 = XEXP (x2, 1);
  if (GET_CODE (x3) == CONST_INT && XWINT (x3, 0) == 0 && 1)
    goto L578;
  x2 = XEXP (x1, 0);
  goto L984;

  L578:
  x1 = XVECEXP (x0, 0, 1);
  if (GET_CODE (x1) == CLOBBER && 1)
    goto L579;
  x1 = XVECEXP (x0, 0, 0);
  x2 = XEXP (x1, 0);
  goto L984;

  L579:
  x2 = XEXP (x1, 0);
  if (scratch_operand (x2, SImode))
    {
      ro[3] = x2;
      return 76;
    }
  x1 = XVECEXP (x0, 0, 0);
  x2 = XEXP (x1, 0);
  goto L984;

  L985:
  x2 = XEXP (x1, 1);
  if (GET_MODE (x2) != SImode)
    {
      x2 = XEXP (x1, 0);
      goto L1443;
    }
  switch (GET_CODE (x2))
    {
    case PLUS:
      goto L986;
    case MINUS:
      goto L1086;
    }
  x2 = XEXP (x1, 0);
  goto L1443;

  L986:
  x3 = XEXP (x2, 0);
  if (reg_or_0_operand (x3, SImode))
    {
      ro[1] = x3;
      goto L987;
    }
  x2 = XEXP (x1, 0);
  goto L1443;

  L987:
  x3 = XEXP (x2, 1);
  if (reg_or_0_operand (x3, SImode))
    {
      ro[2] = x3;
      goto L988;
    }
  x2 = XEXP (x1, 0);
  goto L1443;

  L988:
  x1 = XVECEXP (x0, 0, 1);
  if (GET_CODE (x1) == SET && 1)
    goto L989;
  x1 = XVECEXP (x0, 0, 0);
  x2 = XEXP (x1, 0);
  goto L1443;

  L989:
  x2 = XEXP (x1, 0);
  if (GET_MODE (x2) == CCmode && GET_CODE (x2) == REG && XINT (x2, 0) == 0 && 1)
    goto L990;
  x1 = XVECEXP (x0, 0, 0);
  x2 = XEXP (x1, 0);
  goto L1443;

  L990:
  x2 = XEXP (x1, 1);
  if (GET_MODE (x2) == CCmode && GET_CODE (x2) == UNSPEC && XINT (x2, 1) == 0 && XVECLEN (x2, 0) == 2 && 1)
    goto L991;
  x1 = XVECEXP (x0, 0, 0);
  x2 = XEXP (x1, 0);
  goto L1443;

  L991:
  x3 = XVECEXP (x2, 0, 0);
  if (rtx_equal_p (x3, ro[1]) && 1)
    goto L992;
  x1 = XVECEXP (x0, 0, 0);
  x2 = XEXP (x1, 0);
  goto L1443;

  L992:
  x3 = XVECEXP (x2, 0, 1);
  if (rtx_equal_p (x3, ro[2]) && 1)
    return 179;
  x1 = XVECEXP (x0, 0, 0);
  x2 = XEXP (x1, 0);
  goto L1443;

  L1086:
  x3 = XEXP (x2, 0);
  if (reg_or_0_operand (x3, SImode))
    {
      ro[1] = x3;
      goto L1087;
    }
  x2 = XEXP (x1, 0);
  goto L1443;

  L1087:
  x3 = XEXP (x2, 1);
  if (reg_or_0_operand (x3, SImode))
    {
      ro[2] = x3;
      goto L1088;
    }
  x2 = XEXP (x1, 0);
  goto L1443;

  L1088:
  x1 = XVECEXP (x0, 0, 1);
  if (GET_CODE (x1) == SET && 1)
    goto L1089;
  x1 = XVECEXP (x0, 0, 0);
  x2 = XEXP (x1, 0);
  goto L1443;

  L1089:
  x2 = XEXP (x1, 0);
  if (GET_MODE (x2) == CCmode && GET_CODE (x2) == REG && XINT (x2, 0) == 0 && 1)
    goto L1090;
  x1 = XVECEXP (x0, 0, 0);
  x2 = XEXP (x1, 0);
  goto L1443;

  L1090:
  x2 = XEXP (x1, 1);
  if (GET_MODE (x2) == CCmode && GET_CODE (x2) == UNSPEC && XINT (x2, 1) == 1 && XVECLEN (x2, 0) == 2 && 1)
    goto L1091;
  x1 = XVECEXP (x0, 0, 0);
  x2 = XEXP (x1, 0);
  goto L1443;

  L1091:
  x3 = XVECEXP (x2, 0, 0);
  if (rtx_equal_p (x3, ro[1]) && 1)
    goto L1092;
  x1 = XVECEXP (x0, 0, 0);
  x2 = XEXP (x1, 0);
  goto L1443;

  L1092:
  x3 = XVECEXP (x2, 0, 1);
  if (rtx_equal_p (x3, ro[2]) && 1)
    return 192;
  x1 = XVECEXP (x0, 0, 0);
  x2 = XEXP (x1, 0);
  goto L1443;

  L942:
  x2 = XEXP (x1, 1);
  if (GET_MODE (x2) != DImode)
    {
      x2 = XEXP (x1, 0);
      goto L1443;
    }
  switch (GET_CODE (x2))
    {
    case PLUS:
      goto L958;
    case MINUS:
      goto L1058;
    }
  x2 = XEXP (x1, 0);
  goto L1443;

  L958:
  x3 = XEXP (x2, 0);
  if (GET_MODE (x3) != DImode)
    {
      x2 = XEXP (x1, 0);
      goto L1443;
    }
  if (GET_CODE (x3) == ZERO_EXTEND && 1)
    goto L959;
  if (register_operand (x3, DImode))
    {
      ro[1] = x3;
      goto L944;
    }
  x2 = XEXP (x1, 0);
  goto L1443;

  L959:
  x4 = XEXP (x3, 0);
  if (register_operand (x4, SImode))
    {
      ro[1] = x4;
      goto L960;
    }
  x2 = XEXP (x1, 0);
  goto L1443;

  L960:
  x3 = XEXP (x2, 1);
  if (register_operand (x3, DImode))
    {
      ro[2] = x3;
      goto L961;
    }
  x2 = XEXP (x1, 0);
  goto L1443;

  L961:
  x1 = XVECEXP (x0, 0, 1);
  if (GET_CODE (x1) == CLOBBER && 1)
    goto L962;
  x1 = XVECEXP (x0, 0, 0);
  x2 = XEXP (x1, 0);
  goto L1443;

  L962:
  x2 = XEXP (x1, 0);
  if (GET_MODE (x2) == CCmode && GET_CODE (x2) == REG && XINT (x2, 0) == 0 && 1)
    return 177;
  x1 = XVECEXP (x0, 0, 0);
  x2 = XEXP (x1, 0);
  goto L1443;

  L944:
  x3 = XEXP (x2, 1);
  if (GET_MODE (x3) != DImode)
    {
      x2 = XEXP (x1, 0);
      goto L1443;
    }
  if (GET_CODE (x3) == ZERO_EXTEND && 1)
    goto L945;
  if (register_operand (x3, DImode))
    {
      ro[2] = x3;
      goto L975;
    }
  x2 = XEXP (x1, 0);
  goto L1443;

  L945:
  x4 = XEXP (x3, 0);
  if (register_operand (x4, SImode))
    {
      ro[2] = x4;
      goto L946;
    }
  x2 = XEXP (x1, 0);
  goto L1443;

  L946:
  x1 = XVECEXP (x0, 0, 1);
  if (GET_CODE (x1) == CLOBBER && 1)
    goto L947;
  x1 = XVECEXP (x0, 0, 0);
  x2 = XEXP (x1, 0);
  goto L1443;

  L947:
  x2 = XEXP (x1, 0);
  if (GET_MODE (x2) == CCmode && GET_CODE (x2) == REG && XINT (x2, 0) == 0 && 1)
    return 176;
  x1 = XVECEXP (x0, 0, 0);
  x2 = XEXP (x1, 0);
  goto L1443;

  L975:
  x1 = XVECEXP (x0, 0, 1);
  if (GET_CODE (x1) == CLOBBER && 1)
    goto L976;
  x1 = XVECEXP (x0, 0, 0);
  x2 = XEXP (x1, 0);
  goto L1443;

  L976:
  x2 = XEXP (x1, 0);
  if (GET_MODE (x2) == CCmode && GET_CODE (x2) == REG && XINT (x2, 0) == 0 && 1)
    return 178;
  x1 = XVECEXP (x0, 0, 0);
  x2 = XEXP (x1, 0);
  goto L1443;

  L1058:
  x3 = XEXP (x2, 0);
  if (GET_MODE (x3) != DImode)
    {
      x2 = XEXP (x1, 0);
      goto L1443;
    }
  if (GET_CODE (x3) == ZERO_EXTEND && 1)
    goto L1059;
  if (register_operand (x3, DImode))
    {
      ro[1] = x3;
      goto L1044;
    }
  x2 = XEXP (x1, 0);
  goto L1443;

  L1059:
  x4 = XEXP (x3, 0);
  if (register_operand (x4, SImode))
    {
      ro[1] = x4;
      goto L1060;
    }
  x2 = XEXP (x1, 0);
  goto L1443;

  L1060:
  x3 = XEXP (x2, 1);
  if (register_operand (x3, DImode))
    {
      ro[2] = x3;
      goto L1061;
    }
  x2 = XEXP (x1, 0);
  goto L1443;

  L1061:
  x1 = XVECEXP (x0, 0, 1);
  if (GET_CODE (x1) == CLOBBER && 1)
    goto L1062;
  x1 = XVECEXP (x0, 0, 0);
  x2 = XEXP (x1, 0);
  goto L1443;

  L1062:
  x2 = XEXP (x1, 0);
  if (GET_MODE (x2) == CCmode && GET_CODE (x2) == REG && XINT (x2, 0) == 0 && 1)
    return 190;
  x1 = XVECEXP (x0, 0, 0);
  x2 = XEXP (x1, 0);
  goto L1443;

  L1044:
  x3 = XEXP (x2, 1);
  if (GET_MODE (x3) != DImode)
    {
      x2 = XEXP (x1, 0);
      goto L1443;
    }
  if (GET_CODE (x3) == ZERO_EXTEND && 1)
    goto L1045;
  if (register_operand (x3, DImode))
    {
      ro[2] = x3;
      goto L1075;
    }
  x2 = XEXP (x1, 0);
  goto L1443;

  L1045:
  x4 = XEXP (x3, 0);
  if (register_operand (x4, SImode))
    {
      ro[2] = x4;
      goto L1046;
    }
  x2 = XEXP (x1, 0);
  goto L1443;

  L1046:
  x1 = XVECEXP (x0, 0, 1);
  if (GET_CODE (x1) == CLOBBER && 1)
    goto L1047;
  x1 = XVECEXP (x0, 0, 0);
  x2 = XEXP (x1, 0);
  goto L1443;

  L1047:
  x2 = XEXP (x1, 0);
  if (GET_MODE (x2) == CCmode && GET_CODE (x2) == REG && XINT (x2, 0) == 0 && 1)
    return 189;
  x1 = XVECEXP (x0, 0, 0);
  x2 = XEXP (x1, 0);
  goto L1443;

  L1075:
  x1 = XVECEXP (x0, 0, 1);
  if (GET_CODE (x1) == CLOBBER && 1)
    goto L1076;
  x1 = XVECEXP (x0, 0, 0);
  x2 = XEXP (x1, 0);
  goto L1443;

  L1076:
  x2 = XEXP (x1, 0);
  if (GET_MODE (x2) == CCmode && GET_CODE (x2) == REG && XINT (x2, 0) == 0 && 1)
    return 191;
  x1 = XVECEXP (x0, 0, 0);
  x2 = XEXP (x1, 0);
  goto L1443;

  L1406:
  x2 = XEXP (x1, 1);
  if (register_operand (x2, SImode))
    {
      ro[0] = x2;
      goto L1407;
    }
  if (GET_CODE (x2) == IF_THEN_ELSE && 1)
    goto L1490;
  goto ret0;

  L1407:
  x1 = XVECEXP (x0, 0, 1);
  if (GET_CODE (x1) == USE && 1)
    goto L1408;
  goto ret0;

  L1408:
  x2 = XEXP (x1, 0);
  if (GET_CODE (x2) == LABEL_REF && 1)
    goto L1409;
  goto ret0;

  L1409:
  x3 = XEXP (x2, 0);
  ro[1] = x3;
  return 268;

  L1490:
  x3 = XEXP (x2, 0);
  if (relop_no_unsigned (x3, VOIDmode))
    {
      ro[0] = x3;
      goto L1491;
    }
  goto ret0;

  L1491:
  x4 = XEXP (x3, 0);
  if (register_operand (x4, SImode))
    {
      ro[1] = x4;
      goto L1492;
    }
  goto ret0;

  L1492:
  x4 = XEXP (x3, 1);
  if (GET_CODE (x4) == CONST_INT && XWINT (x4, 0) == 0 && 1)
    goto L1493;
  goto ret0;

  L1493:
  x3 = XEXP (x2, 1);
  if (GET_CODE (x3) == LABEL_REF && 1)
    goto L1494;
  goto ret0;

  L1494:
  x4 = XEXP (x3, 0);
  ro[2] = x4;
  goto L1495;

  L1495:
  x3 = XEXP (x2, 2);
  if (GET_CODE (x3) == PC && 1)
    goto L1496;
  goto ret0;

  L1496:
  x1 = XVECEXP (x0, 0, 1);
  if (GET_CODE (x1) == SET && 1)
    goto L1497;
  goto ret0;

  L1497:
  x2 = XEXP (x1, 0);
  if (rtx_equal_p (x2, ro[1]) && 1)
    goto L1498;
  goto ret0;

  L1498:
  x2 = XEXP (x1, 1);
  if (GET_MODE (x2) == SImode && GET_CODE (x2) == PLUS && 1)
    goto L1499;
  goto ret0;

  L1499:
  x3 = XEXP (x2, 0);
  if (rtx_equal_p (x3, ro[1]) && 1)
    goto L1500;
  goto ret0;

  L1500:
  x3 = XEXP (x2, 1);
  if (pnum_clobbers != 0 && add_operand (x3, SImode))
    {
      ro[3] = x3;
      if (find_reg_note (insn, REG_NONNEG, 0))
	{
	  *pnum_clobbers = 2;
	  return 281;
	}
      }
  goto ret0;

  L1444:
  x2 = XEXP (x1, 1);
  if (GET_CODE (x2) == CALL && 1)
    goto L1445;
  goto ret0;

  L1445:
  x3 = XEXP (x2, 0);
  if (GET_MODE (x3) == SImode && GET_CODE (x3) == MEM && 1)
    goto L1446;
  goto ret0;

  L1446:
  x4 = XEXP (x3, 0);
  if (call_address_operand (x4, SImode))
    {
      ro[1] = x4;
      goto L1447;
    }
  goto ret0;

  L1447:
  x3 = XEXP (x2, 1);
  ro[2] = x3;
  goto L1448;

  L1448:
  x1 = XVECEXP (x0, 0, 1);
  if (GET_CODE (x1) == CLOBBER && 1)
    goto L1449;
  goto ret0;

  L1449:
  x2 = XEXP (x1, 0);
  if (GET_MODE (x2) == SImode && GET_CODE (x2) == REG && XINT (x2, 0) == 1 && 1)
    return 273;
  goto ret0;
 ret0: return -1;
}

int
recog (x0, insn, pnum_clobbers)
     register rtx x0;
     rtx insn;
     int *pnum_clobbers;
{
  register rtx *ro = &recog_operand[0];
  register rtx x1, x2, x3, x4, x5;
  int tem;

  L51:
  switch (GET_CODE (x0))
    {
    case SET:
      goto L52;
    case PARALLEL:
      if (XVECLEN (x0, 0) == 2 && 1)
	goto L284;
      if (XVECLEN (x0, 0) == 3 && 1)
	goto L1324;
      if (XVECLEN (x0, 0) == 4 && 1)
	goto L1411;
      break;
    case TRAP_IF:
      if (XINT (x0, 1) == 503 && 1)
	goto L1140;
      if (XINT (x0, 1) == 7 && 1)
	goto L1298;
      break;
    case CALL:
      goto L1438;
    case CONST_INT:
      if (XWINT (x0, 0) == 0 && 1)
	return 274;
      break;
    case RETURN:
      if (reload_completed)
	return 275;
      break;
    case UNSPEC_VOLATILE:
      if (XINT (x0, 1) == 0 && XVECLEN (x0, 0) == 1 && 1)
	goto L1459;
    }
  goto ret0;
 L52:
  return recog_5 (x0, insn, pnum_clobbers);

  L284:
  x1 = XVECEXP (x0, 0, 0);
  switch (GET_CODE (x1))
    {
    case SET:
      goto L285;
    case CALL:
      goto L1432;
    }
  goto ret0;
 L285:
  return recog_6 (x0, insn, pnum_clobbers);

  L1432:
  x2 = XEXP (x1, 0);
  if (GET_MODE (x2) == SImode && GET_CODE (x2) == MEM && 1)
    goto L1433;
  goto ret0;

  L1433:
  x3 = XEXP (x2, 0);
  if (call_address_operand (x3, SImode))
    {
      ro[0] = x3;
      goto L1434;
    }
  goto ret0;

  L1434:
  x2 = XEXP (x1, 1);
  ro[1] = x2;
  goto L1435;

  L1435:
  x1 = XVECEXP (x0, 0, 1);
  if (GET_CODE (x1) == CLOBBER && 1)
    goto L1436;
  goto ret0;

  L1436:
  x2 = XEXP (x1, 0);
  if (GET_MODE (x2) == SImode && GET_CODE (x2) == REG && XINT (x2, 0) == 1 && 1)
    return 271;
  goto ret0;

  L1324:
  x1 = XVECEXP (x0, 0, 0);
  if (GET_CODE (x1) == SET && 1)
    goto L1325;
  goto ret0;

  L1325:
  x2 = XEXP (x1, 0);
  if (register_operand (x2, SImode))
    {
      ro[0] = x2;
      goto L1326;
    }
  if (GET_CODE (x2) == PC && 1)
    goto L1424;
  goto ret0;

  L1326:
  x2 = XEXP (x1, 1);
  if (GET_MODE (x2) == SImode && GET_CODE (x2) == FFS && 1)
    goto L1327;
  goto ret0;

  L1327:
  x3 = XEXP (x2, 0);
  if (register_operand (x3, SImode))
    {
      ro[1] = x3;
      goto L1328;
    }
  goto ret0;

  L1328:
  x1 = XVECEXP (x0, 0, 1);
  if (GET_CODE (x1) == CLOBBER && 1)
    goto L1329;
  goto ret0;

  L1329:
  x2 = XEXP (x1, 0);
  if (GET_MODE (x2) == CCmode && GET_CODE (x2) == REG && XINT (x2, 0) == 0 && 1)
    goto L1330;
  goto ret0;

  L1330:
  x1 = XVECEXP (x0, 0, 2);
  if (GET_CODE (x1) == CLOBBER && 1)
    goto L1331;
  goto ret0;

  L1331:
  x2 = XEXP (x1, 0);
  if (scratch_operand (x2, SImode))
    {
      ro[2] = x2;
      return 252;
    }
  goto ret0;

  L1424:
  x2 = XEXP (x1, 1);
  ro[0] = x2;
  goto L1425;

  L1425:
  x1 = XVECEXP (x0, 0, 1);
  if (GET_CODE (x1) == USE && 1)
    goto L1426;
  goto ret0;

  L1426:
  x2 = XEXP (x1, 0);
  if (register_operand (x2, SImode))
    {
      ro[1] = x2;
      goto L1427;
    }
  goto ret0;

  L1427:
  x1 = XVECEXP (x0, 0, 2);
  if (GET_CODE (x1) == USE && 1)
    goto L1428;
  goto ret0;

  L1428:
  x2 = XEXP (x1, 0);
  if (GET_CODE (x2) == LABEL_REF && 1)
    goto L1429;
  goto ret0;

  L1429:
  x3 = XEXP (x2, 0);
  if (pnum_clobbers != 0 && 1)
    {
      ro[2] = x3;
      *pnum_clobbers = 1;
      return 269;
    }
  goto ret0;

  L1411:
  x1 = XVECEXP (x0, 0, 0);
  if (GET_CODE (x1) == SET && 1)
    goto L1412;
  goto ret0;

  L1412:
  x2 = XEXP (x1, 0);
  if (GET_CODE (x2) == PC && 1)
    goto L1413;
  goto ret0;

  L1413:
  x2 = XEXP (x1, 1);
  ro[0] = x2;
  goto L1414;
  L1470:
  if (GET_CODE (x2) == IF_THEN_ELSE && 1)
    goto L1471;
  goto ret0;

  L1414:
  x1 = XVECEXP (x0, 0, 1);
  if (GET_CODE (x1) == USE && 1)
    goto L1415;
  x1 = XVECEXP (x0, 0, 0);
  x2 = XEXP (x1, 1);
  goto L1470;

  L1415:
  x2 = XEXP (x1, 0);
  if (register_operand (x2, SImode))
    {
      ro[1] = x2;
      goto L1416;
    }
  x1 = XVECEXP (x0, 0, 0);
  x2 = XEXP (x1, 1);
  goto L1470;

  L1416:
  x1 = XVECEXP (x0, 0, 2);
  if (GET_CODE (x1) == USE && 1)
    goto L1417;
  x1 = XVECEXP (x0, 0, 0);
  x2 = XEXP (x1, 1);
  goto L1470;

  L1417:
  x2 = XEXP (x1, 0);
  if (GET_CODE (x2) == LABEL_REF && 1)
    goto L1418;
  x1 = XVECEXP (x0, 0, 0);
  x2 = XEXP (x1, 1);
  goto L1470;

  L1418:
  x3 = XEXP (x2, 0);
  ro[2] = x3;
  goto L1419;

  L1419:
  x1 = XVECEXP (x0, 0, 3);
  if (GET_CODE (x1) == CLOBBER && 1)
    goto L1420;
  x1 = XVECEXP (x0, 0, 0);
  x2 = XEXP (x1, 1);
  goto L1470;

  L1420:
  x2 = XEXP (x1, 0);
  if (GET_MODE (x2) == SImode && GET_CODE (x2) == REG && XINT (x2, 0) == 1 && 1)
    return 269;
  x1 = XVECEXP (x0, 0, 0);
  x2 = XEXP (x1, 1);
  goto L1470;

  L1471:
  x3 = XEXP (x2, 0);
  if (relop_no_unsigned (x3, VOIDmode))
    {
      ro[0] = x3;
      goto L1472;
    }
  goto ret0;

  L1472:
  x4 = XEXP (x3, 0);
  if (register_operand (x4, SImode))
    {
      ro[1] = x4;
      goto L1473;
    }
  goto ret0;

  L1473:
  x4 = XEXP (x3, 1);
  if (GET_CODE (x4) == CONST_INT && XWINT (x4, 0) == 0 && 1)
    goto L1474;
  goto ret0;

  L1474:
  x3 = XEXP (x2, 1);
  if (GET_CODE (x3) == LABEL_REF && 1)
    goto L1475;
  goto ret0;

  L1475:
  x4 = XEXP (x3, 0);
  ro[2] = x4;
  goto L1476;

  L1476:
  x3 = XEXP (x2, 2);
  if (GET_CODE (x3) == PC && 1)
    goto L1477;
  goto ret0;

  L1477:
  x1 = XVECEXP (x0, 0, 1);
  if (GET_CODE (x1) == SET && 1)
    goto L1478;
  goto ret0;

  L1478:
  x2 = XEXP (x1, 0);
  if (rtx_equal_p (x2, ro[1]) && 1)
    goto L1479;
  goto ret0;

  L1479:
  x2 = XEXP (x1, 1);
  if (GET_MODE (x2) == SImode && GET_CODE (x2) == PLUS && 1)
    goto L1480;
  goto ret0;

  L1480:
  x3 = XEXP (x2, 0);
  if (rtx_equal_p (x3, ro[1]) && 1)
    goto L1481;
  goto ret0;

  L1481:
  x3 = XEXP (x2, 1);
  if (add_operand (x3, SImode))
    {
      ro[3] = x3;
      goto L1482;
    }
  goto ret0;

  L1482:
  x1 = XVECEXP (x0, 0, 2);
  if (GET_CODE (x1) == CLOBBER && 1)
    goto L1483;
  goto ret0;

  L1483:
  x2 = XEXP (x1, 0);
  if (scratch_operand (x2, SImode))
    {
      ro[4] = x2;
      goto L1484;
    }
  goto ret0;

  L1484:
  x1 = XVECEXP (x0, 0, 3);
  if (GET_CODE (x1) == CLOBBER && 1)
    goto L1485;
  goto ret0;

  L1485:
  x2 = XEXP (x1, 0);
  if (scratch_operand (x2, SImode))
    {
      ro[5] = x2;
      if (find_reg_note (insn, REG_NONNEG, 0))
	return 281;
      }
  goto ret0;

  L1140:
  x1 = XEXP (x0, 0);
  if (GET_CODE (x1) == CONST_INT && XWINT (x1, 0) == 1 && 1)
    return 202;
  goto ret0;

  L1298:
  x1 = XEXP (x0, 0);
  switch (GET_CODE (x1))
    {
    case GTU:
      goto L1299;
    case CONST_INT:
      if (XWINT (x1, 0) == 1 && 1)
	return 243;
    }
  goto ret0;

  L1299:
  x2 = XEXP (x1, 0);
  if (register_operand (x2, SImode))
    {
      ro[0] = x2;
      goto L1300;
    }
  goto ret0;

  L1300:
  x2 = XEXP (x1, 1);
  if (arith_operand (x2, SImode))
    {
      ro[1] = x2;
      return 242;
    }
  goto ret0;

  L1438:
  x1 = XEXP (x0, 0);
  if (GET_MODE (x1) == SImode && GET_CODE (x1) == MEM && 1)
    goto L1439;
  goto ret0;

  L1439:
  x2 = XEXP (x1, 0);
  if (call_address_operand (x2, SImode))
    {
      ro[0] = x2;
      goto L1440;
    }
  goto ret0;

  L1440:
  x1 = XEXP (x0, 1);
  if (pnum_clobbers != 0 && 1)
    {
      ro[1] = x1;
      *pnum_clobbers = 1;
      return 271;
    }
  goto ret0;

  L1459:
  x1 = XVECEXP (x0, 0, 0);
  if (GET_CODE (x1) == CONST_INT && XWINT (x1, 0) == 0 && 1)
    return 278;
  goto ret0;
 ret0: return -1;
}

rtx
split_1 (x0, insn)
     register rtx x0;
     rtx insn;
{
  register rtx *ro = &recog_operand[0];
  register rtx x1, x2, x3, x4, x5;
  rtx tem;

  x1 = XVECEXP (x0, 0, 0);
  x2 = XEXP (x1, 1);
  if (GET_MODE (x2) != SImode)
    goto ret0;
  switch (GET_CODE (x2))
    {
    case IOR:
      goto L89;
    case AND:
      goto L167;
    case NEG:
      goto L608;
    case NE:
    case LE:
    case GE:
    case LEU:
    case GEU:
      if (odd_relop (x2, SImode))
	{
	  ro[1] = x2;
	  goto L568;
	}
    }
  goto ret0;

  L89:
  x3 = XEXP (x2, 0);
  if (GET_MODE (x3) == SImode && GET_CODE (x3) == NEG && 1)
    goto L90;
  if (even_relop (x3, VOIDmode))
    {
      ro[1] = x3;
      goto L132;
    }
  if (odd_relop (x3, VOIDmode))
    {
      ro[1] = x3;
      goto L144;
    }
  goto ret0;

  L90:
  x4 = XEXP (x3, 0);
  if (even_relop (x4, VOIDmode))
    {
      ro[1] = x4;
      goto L91;
    }
  if (odd_relop (x4, VOIDmode))
    {
      ro[1] = x4;
      goto L105;
    }
  goto ret0;

  L91:
  x5 = XEXP (x4, 0);
  if (partial_ccmode_register_operand (x5, VOIDmode))
    {
      ro[2] = x5;
      goto L92;
    }
  goto ret0;

  L92:
  x5 = XEXP (x4, 1);
  if (GET_CODE (x5) == CONST_INT && XWINT (x5, 0) == 0 && 1)
    goto L93;
  goto ret0;

  L93:
  x3 = XEXP (x2, 1);
  if (GET_MODE (x3) == SImode && GET_CODE (x3) == NEG && 1)
    goto L94;
  goto ret0;

  L94:
  x4 = XEXP (x3, 0);
  if (relop (x4, VOIDmode))
    {
      ro[3] = x4;
      goto L95;
    }
  goto ret0;

  L95:
  x5 = XEXP (x4, 0);
  if (partial_ccmode_register_operand (x5, VOIDmode))
    {
      ro[4] = x5;
      goto L96;
    }
  goto ret0;

  L96:
  x5 = XEXP (x4, 1);
  if (GET_CODE (x5) == CONST_INT && XWINT (x5, 0) == 0 && 1)
    goto L97;
  goto ret0;

  L97:
  x1 = XVECEXP (x0, 0, 1);
  if (GET_CODE (x1) == CLOBBER && 1)
    goto L98;
  goto ret0;

  L98:
  x2 = XEXP (x1, 0);
  if (register_operand (x2, SImode))
    {
      ro[5] = x2;
      return gen_split_13 (operands);
    }
  goto ret0;

  L105:
  x5 = XEXP (x4, 0);
  if (partial_ccmode_register_operand (x5, VOIDmode))
    {
      ro[2] = x5;
      goto L106;
    }
  goto ret0;

  L106:
  x5 = XEXP (x4, 1);
  if (GET_CODE (x5) == CONST_INT && XWINT (x5, 0) == 0 && 1)
    goto L107;
  goto ret0;

  L107:
  x3 = XEXP (x2, 1);
  if (GET_MODE (x3) == SImode && GET_CODE (x3) == NEG && 1)
    goto L108;
  goto ret0;

  L108:
  x4 = XEXP (x3, 0);
  if (odd_relop (x4, VOIDmode))
    {
      ro[3] = x4;
      goto L109;
    }
  if (even_relop (x4, VOIDmode))
    {
      ro[3] = x4;
      goto L123;
    }
  goto ret0;

  L109:
  x5 = XEXP (x4, 0);
  if (partial_ccmode_register_operand (x5, VOIDmode))
    {
      ro[4] = x5;
      goto L110;
    }
  goto ret0;

  L110:
  x5 = XEXP (x4, 1);
  if (GET_CODE (x5) == CONST_INT && XWINT (x5, 0) == 0 && 1)
    goto L111;
  goto ret0;

  L111:
  x1 = XVECEXP (x0, 0, 1);
  if (GET_CODE (x1) == CLOBBER && 1)
    goto L112;
  goto ret0;

  L112:
  x2 = XEXP (x1, 0);
  if (register_operand (x2, SImode))
    {
      ro[5] = x2;
      return gen_split_14 (operands);
    }
  goto ret0;

  L123:
  x5 = XEXP (x4, 0);
  if (partial_ccmode_register_operand (x5, VOIDmode))
    {
      ro[4] = x5;
      goto L124;
    }
  goto ret0;

  L124:
  x5 = XEXP (x4, 1);
  if (GET_CODE (x5) == CONST_INT && XWINT (x5, 0) == 0 && 1)
    goto L125;
  goto ret0;

  L125:
  x1 = XVECEXP (x0, 0, 1);
  if (GET_CODE (x1) == CLOBBER && 1)
    goto L126;
  goto ret0;

  L126:
  x2 = XEXP (x1, 0);
  if (register_operand (x2, SImode))
    {
      ro[5] = x2;
      return gen_split_15 (operands);
    }
  goto ret0;

  L132:
  x4 = XEXP (x3, 0);
  if (partial_ccmode_register_operand (x4, VOIDmode))
    {
      ro[2] = x4;
      goto L133;
    }
  goto ret0;

  L133:
  x4 = XEXP (x3, 1);
  if (GET_CODE (x4) == CONST_INT && XWINT (x4, 0) == 0 && 1)
    goto L134;
  goto ret0;

  L134:
  x3 = XEXP (x2, 1);
  if (relop (x3, VOIDmode))
    {
      ro[3] = x3;
      goto L135;
    }
  goto ret0;

  L135:
  x4 = XEXP (x3, 0);
  if (partial_ccmode_register_operand (x4, VOIDmode))
    {
      ro[4] = x4;
      goto L136;
    }
  goto ret0;

  L136:
  x4 = XEXP (x3, 1);
  if (GET_CODE (x4) == CONST_INT && XWINT (x4, 0) == 0 && 1)
    goto L137;
  goto ret0;

  L137:
  x1 = XVECEXP (x0, 0, 1);
  if (GET_CODE (x1) == CLOBBER && 1)
    goto L138;
  goto ret0;

  L138:
  x2 = XEXP (x1, 0);
  if (register_operand (x2, SImode))
    {
      ro[5] = x2;
      if (GET_CODE (operands[1]) == GET_CODE (operands[3])
   || GET_CODE (operands[1]) == reverse_condition (GET_CODE (operands[3])))
	return gen_split_16 (operands);
      }
  goto ret0;

  L144:
  x4 = XEXP (x3, 0);
  if (partial_ccmode_register_operand (x4, VOIDmode))
    {
      ro[2] = x4;
      goto L145;
    }
  goto ret0;

  L145:
  x4 = XEXP (x3, 1);
  if (GET_CODE (x4) == CONST_INT && XWINT (x4, 0) == 0 && 1)
    goto L146;
  goto ret0;

  L146:
  x3 = XEXP (x2, 1);
  if (odd_relop (x3, VOIDmode))
    {
      ro[3] = x3;
      goto L147;
    }
  if (even_relop (x3, VOIDmode))
    {
      ro[3] = x3;
      goto L159;
    }
  goto ret0;

  L147:
  x4 = XEXP (x3, 0);
  if (partial_ccmode_register_operand (x4, VOIDmode))
    {
      ro[4] = x4;
      goto L148;
    }
  goto ret0;

  L148:
  x4 = XEXP (x3, 1);
  if (GET_CODE (x4) == CONST_INT && XWINT (x4, 0) == 0 && 1)
    goto L149;
  goto ret0;

  L149:
  x1 = XVECEXP (x0, 0, 1);
  if (GET_CODE (x1) == CLOBBER && 1)
    goto L150;
  goto ret0;

  L150:
  x2 = XEXP (x1, 0);
  if (register_operand (x2, SImode))
    {
      ro[5] = x2;
      if (GET_CODE (operands[1]) == GET_CODE (operands[3]))
	return gen_split_17 (operands);
      }
  goto ret0;

  L159:
  x4 = XEXP (x3, 0);
  if (partial_ccmode_register_operand (x4, VOIDmode))
    {
      ro[4] = x4;
      goto L160;
    }
  goto ret0;

  L160:
  x4 = XEXP (x3, 1);
  if (GET_CODE (x4) == CONST_INT && XWINT (x4, 0) == 0 && 1)
    goto L161;
  goto ret0;

  L161:
  x1 = XVECEXP (x0, 0, 1);
  if (GET_CODE (x1) == CLOBBER && 1)
    goto L162;
  goto ret0;

  L162:
  x2 = XEXP (x1, 0);
  if (register_operand (x2, SImode))
    {
      ro[5] = x2;
      if (GET_CODE (operands[1]) == reverse_condition (GET_CODE (operands[3])))
	return gen_split_18 (operands);
      }
  goto ret0;

  L167:
  x3 = XEXP (x2, 0);
  if (GET_MODE (x3) == SImode && GET_CODE (x3) == NEG && 1)
    goto L168;
  if (even_relop (x3, VOIDmode))
    {
      ro[1] = x3;
      goto L210;
    }
  if (odd_relop (x3, VOIDmode))
    {
      ro[1] = x3;
      goto L222;
    }
  goto ret0;

  L168:
  x4 = XEXP (x3, 0);
  if (even_relop (x4, VOIDmode))
    {
      ro[1] = x4;
      goto L169;
    }
  if (odd_relop (x4, VOIDmode))
    {
      ro[1] = x4;
      goto L183;
    }
  goto ret0;

  L169:
  x5 = XEXP (x4, 0);
  if (partial_ccmode_register_operand (x5, VOIDmode))
    {
      ro[2] = x5;
      goto L170;
    }
  goto ret0;

  L170:
  x5 = XEXP (x4, 1);
  if (GET_CODE (x5) == CONST_INT && XWINT (x5, 0) == 0 && 1)
    goto L171;
  goto ret0;

  L171:
  x3 = XEXP (x2, 1);
  if (GET_MODE (x3) == SImode && GET_CODE (x3) == NEG && 1)
    goto L172;
  goto ret0;

  L172:
  x4 = XEXP (x3, 0);
  if (relop (x4, VOIDmode))
    {
      ro[3] = x4;
      goto L173;
    }
  goto ret0;

  L173:
  x5 = XEXP (x4, 0);
  if (partial_ccmode_register_operand (x5, VOIDmode))
    {
      ro[4] = x5;
      goto L174;
    }
  goto ret0;

  L174:
  x5 = XEXP (x4, 1);
  if (GET_CODE (x5) == CONST_INT && XWINT (x5, 0) == 0 && 1)
    goto L175;
  goto ret0;

  L175:
  x1 = XVECEXP (x0, 0, 1);
  if (GET_CODE (x1) == CLOBBER && 1)
    goto L176;
  goto ret0;

  L176:
  x2 = XEXP (x1, 0);
  if (register_operand (x2, SImode))
    {
      ro[5] = x2;
      return gen_split_19 (operands);
    }
  goto ret0;

  L183:
  x5 = XEXP (x4, 0);
  if (partial_ccmode_register_operand (x5, VOIDmode))
    {
      ro[2] = x5;
      goto L184;
    }
  goto ret0;

  L184:
  x5 = XEXP (x4, 1);
  if (GET_CODE (x5) == CONST_INT && XWINT (x5, 0) == 0 && 1)
    goto L185;
  goto ret0;

  L185:
  x3 = XEXP (x2, 1);
  if (GET_MODE (x3) == SImode && GET_CODE (x3) == NEG && 1)
    goto L186;
  goto ret0;

  L186:
  x4 = XEXP (x3, 0);
  if (odd_relop (x4, VOIDmode))
    {
      ro[3] = x4;
      goto L187;
    }
  if (even_relop (x4, VOIDmode))
    {
      ro[3] = x4;
      goto L201;
    }
  goto ret0;

  L187:
  x5 = XEXP (x4, 0);
  if (partial_ccmode_register_operand (x5, VOIDmode))
    {
      ro[4] = x5;
      goto L188;
    }
  goto ret0;

  L188:
  x5 = XEXP (x4, 1);
  if (GET_CODE (x5) == CONST_INT && XWINT (x5, 0) == 0 && 1)
    goto L189;
  goto ret0;

  L189:
  x1 = XVECEXP (x0, 0, 1);
  if (GET_CODE (x1) == CLOBBER && 1)
    goto L190;
  goto ret0;

  L190:
  x2 = XEXP (x1, 0);
  if (register_operand (x2, SImode))
    {
      ro[5] = x2;
      return gen_split_20 (operands);
    }
  goto ret0;

  L201:
  x5 = XEXP (x4, 0);
  if (partial_ccmode_register_operand (x5, VOIDmode))
    {
      ro[4] = x5;
      goto L202;
    }
  goto ret0;

  L202:
  x5 = XEXP (x4, 1);
  if (GET_CODE (x5) == CONST_INT && XWINT (x5, 0) == 0 && 1)
    goto L203;
  goto ret0;

  L203:
  x1 = XVECEXP (x0, 0, 1);
  if (GET_CODE (x1) == CLOBBER && 1)
    goto L204;
  goto ret0;

  L204:
  x2 = XEXP (x1, 0);
  if (register_operand (x2, SImode))
    {
      ro[5] = x2;
      return gen_split_21 (operands);
    }
  goto ret0;

  L210:
  x4 = XEXP (x3, 0);
  if (partial_ccmode_register_operand (x4, VOIDmode))
    {
      ro[2] = x4;
      goto L211;
    }
  goto ret0;

  L211:
  x4 = XEXP (x3, 1);
  if (GET_CODE (x4) == CONST_INT && XWINT (x4, 0) == 0 && 1)
    goto L212;
  goto ret0;

  L212:
  x3 = XEXP (x2, 1);
  if (relop (x3, VOIDmode))
    {
      ro[3] = x3;
      goto L213;
    }
  goto ret0;

  L213:
  x4 = XEXP (x3, 0);
  if (partial_ccmode_register_operand (x4, VOIDmode))
    {
      ro[4] = x4;
      goto L214;
    }
  goto ret0;

  L214:
  x4 = XEXP (x3, 1);
  if (GET_CODE (x4) == CONST_INT && XWINT (x4, 0) == 0 && 1)
    goto L215;
  goto ret0;

  L215:
  x1 = XVECEXP (x0, 0, 1);
  if (GET_CODE (x1) == CLOBBER && 1)
    goto L216;
  goto ret0;

  L216:
  x2 = XEXP (x1, 0);
  if (register_operand (x2, SImode))
    {
      ro[5] = x2;
      if (GET_CODE (operands[1]) == GET_CODE (operands[3])
   || GET_CODE (operands[1]) == reverse_condition (GET_CODE (operands[3])))
	return gen_split_22 (operands);
      }
  goto ret0;

  L222:
  x4 = XEXP (x3, 0);
  if (partial_ccmode_register_operand (x4, VOIDmode))
    {
      ro[2] = x4;
      goto L223;
    }
  goto ret0;

  L223:
  x4 = XEXP (x3, 1);
  if (GET_CODE (x4) == CONST_INT && XWINT (x4, 0) == 0 && 1)
    goto L224;
  goto ret0;

  L224:
  x3 = XEXP (x2, 1);
  if (odd_relop (x3, VOIDmode))
    {
      ro[3] = x3;
      goto L225;
    }
  if (even_relop (x3, VOIDmode))
    {
      ro[3] = x3;
      goto L237;
    }
  goto ret0;

  L225:
  x4 = XEXP (x3, 0);
  if (partial_ccmode_register_operand (x4, VOIDmode))
    {
      ro[4] = x4;
      goto L226;
    }
  goto ret0;

  L226:
  x4 = XEXP (x3, 1);
  if (GET_CODE (x4) == CONST_INT && XWINT (x4, 0) == 0 && 1)
    goto L227;
  goto ret0;

  L227:
  x1 = XVECEXP (x0, 0, 1);
  if (GET_CODE (x1) == CLOBBER && 1)
    goto L228;
  goto ret0;

  L228:
  x2 = XEXP (x1, 0);
  if (register_operand (x2, SImode))
    {
      ro[5] = x2;
      if (GET_CODE (operands[1]) == GET_CODE (operands[3]))
	return gen_split_23 (operands);
      }
  goto ret0;

  L237:
  x4 = XEXP (x3, 0);
  if (partial_ccmode_register_operand (x4, VOIDmode))
    {
      ro[4] = x4;
      goto L238;
    }
  goto ret0;

  L238:
  x4 = XEXP (x3, 1);
  if (GET_CODE (x4) == CONST_INT && XWINT (x4, 0) == 0 && 1)
    goto L239;
  goto ret0;

  L239:
  x1 = XVECEXP (x0, 0, 1);
  if (GET_CODE (x1) == CLOBBER && 1)
    goto L240;
  goto ret0;

  L240:
  x2 = XEXP (x1, 0);
  if (register_operand (x2, SImode))
    {
      ro[5] = x2;
      if (GET_CODE (operands[1]) == reverse_condition (GET_CODE (operands[3])))
	return gen_split_24 (operands);
      }
  goto ret0;

  L608:
  x3 = XEXP (x2, 0);
  if (odd_relop (x3, SImode))
    {
      ro[1] = x3;
      goto L609;
    }
  goto ret0;

  L609:
  x4 = XEXP (x3, 0);
  if (register_operand (x4, CCEVENmode))
    {
      ro[2] = x4;
      goto L610;
    }
  goto ret0;

  L610:
  x4 = XEXP (x3, 1);
  if (GET_CODE (x4) == CONST_INT && XWINT (x4, 0) == 0 && 1)
    goto L611;
  goto ret0;

  L611:
  x1 = XVECEXP (x0, 0, 1);
  if (GET_CODE (x1) == CLOBBER && 1)
    goto L612;
  goto ret0;

  L612:
  x2 = XEXP (x1, 0);
  if (register_operand (x2, SImode))
    {
      ro[3] = x2;
      return gen_split_80 (operands);
    }
  goto ret0;

  L568:
  x3 = XEXP (x2, 0);
  if (register_operand (x3, CCEVENmode))
    {
      ro[2] = x3;
      goto L569;
    }
  goto ret0;

  L569:
  x3 = XEXP (x2, 1);
  if (GET_CODE (x3) == CONST_INT && XWINT (x3, 0) == 0 && 1)
    goto L570;
  goto ret0;

  L570:
  x1 = XVECEXP (x0, 0, 1);
  if (GET_CODE (x1) == CLOBBER && 1)
    goto L571;
  goto ret0;

  L571:
  x2 = XEXP (x1, 0);
  if (register_operand (x2, SImode))
    {
      ro[3] = x2;
      return gen_split_75 (operands);
    }
  goto ret0;
 ret0: return 0;
}

rtx
split_insns (x0, insn)
     register rtx x0;
     rtx insn;
{
  register rtx *ro = &recog_operand[0];
  register rtx x1, x2, x3, x4, x5;
  rtx tem;

  L0:
  switch (GET_CODE (x0))
    {
    case SET:
      goto L1;
    case PARALLEL:
      if (XVECLEN (x0, 0) == 2 && 1)
	goto L86;
    }
  goto ret0;

  L1:
  x1 = XEXP (x0, 0);
  switch (GET_MODE (x1))
    {
    case SImode:
      if (register_operand (x1, SImode))
	{
	  ro[0] = x1;
	  goto L2;
	}
      break;
    case DFmode:
      if (register_operand (x1, DFmode))
	{
	  ro[0] = x1;
	  goto L790;
	}
    }
  goto ret0;

  L2:
  x1 = XEXP (x0, 1);
  if (GET_MODE (x1) != SImode)
    goto ret0;
  switch (GET_CODE (x1))
    {
    case MINUS:
      goto L3;
    case PLUS:
      goto L24;
    }
  goto ret0;

  L3:
  x2 = XEXP (x1, 0);
  if (register_operand (x2, SImode))
    {
      ro[1] = x2;
      goto L4;
    }
  goto ret0;

  L4:
  x2 = XEXP (x1, 1);
  if (GET_MODE (x2) != SImode)
    goto ret0;
  switch (GET_CODE (x2))
    {
    case GEU:
      goto L5;
    case LEU:
      goto L12;
    case EQ:
      goto L19;
    case XOR:
      goto L47;
    }
  goto ret0;

  L5:
  x3 = XEXP (x2, 0);
  if (register_operand (x3, SImode))
    {
      ro[2] = x3;
      goto L6;
    }
  goto ret0;

  L6:
  x3 = XEXP (x2, 1);
  if (register_operand (x3, SImode))
    {
      ro[3] = x3;
      return gen_split_1 (operands);
    }
  goto ret0;

  L12:
  x3 = XEXP (x2, 0);
  if (register_operand (x3, SImode))
    {
      ro[3] = x3;
      goto L13;
    }
  goto ret0;

  L13:
  x3 = XEXP (x2, 1);
  if (register_operand (x3, SImode))
    {
      ro[2] = x3;
      return gen_split_2 (operands);
    }
  goto ret0;

  L19:
  x3 = XEXP (x2, 0);
  if (register_operand (x3, SImode))
    {
      ro[2] = x3;
      goto L20;
    }
  goto ret0;

  L20:
  x3 = XEXP (x2, 1);
  if (GET_CODE (x3) == CONST_INT && XWINT (x3, 0) == 0 && 1)
    return gen_split_3 (operands);
  goto ret0;

  L47:
  x3 = XEXP (x2, 0);
  if (GET_MODE (x3) == SImode && GET_CODE (x3) == LSHIFTRT && 1)
    goto L48;
  goto ret0;

  L48:
  x4 = XEXP (x3, 0);
  if (register_operand (x4, SImode))
    {
      ro[2] = x4;
      goto L49;
    }
  goto ret0;

  L49:
  x4 = XEXP (x3, 1);
  if (GET_CODE (x4) == CONST_INT && XWINT (x4, 0) == 31 && 1)
    goto L50;
  goto ret0;

  L50:
  x3 = XEXP (x2, 1);
  if (GET_CODE (x3) == CONST_INT && XWINT (x3, 0) == 1 && 1)
    return gen_split_7 (operands);
  goto ret0;

  L24:
  x2 = XEXP (x1, 0);
  if (GET_MODE (x2) != SImode)
    goto ret0;
  switch (GET_CODE (x2))
    {
    case LTU:
      goto L25;
    case GTU:
      goto L32;
    case NE:
      goto L39;
    }
  goto ret0;

  L25:
  x3 = XEXP (x2, 0);
  if (register_operand (x3, SImode))
    {
      ro[2] = x3;
      goto L26;
    }
  goto ret0;

  L26:
  x3 = XEXP (x2, 1);
  if (register_operand (x3, SImode))
    {
      ro[3] = x3;
      goto L27;
    }
  goto ret0;

  L27:
  x2 = XEXP (x1, 1);
  if (register_operand (x2, SImode))
    {
      ro[1] = x2;
      return gen_split_4 (operands);
    }
  goto ret0;

  L32:
  x3 = XEXP (x2, 0);
  if (register_operand (x3, SImode))
    {
      ro[3] = x3;
      goto L33;
    }
  goto ret0;

  L33:
  x3 = XEXP (x2, 1);
  if (register_operand (x3, SImode))
    {
      ro[2] = x3;
      goto L34;
    }
  goto ret0;

  L34:
  x2 = XEXP (x1, 1);
  if (register_operand (x2, SImode))
    {
      ro[1] = x2;
      return gen_split_5 (operands);
    }
  goto ret0;

  L39:
  x3 = XEXP (x2, 0);
  if (register_operand (x3, SImode))
    {
      ro[2] = x3;
      goto L40;
    }
  goto ret0;

  L40:
  x3 = XEXP (x2, 1);
  if (GET_CODE (x3) == CONST_INT && XWINT (x3, 0) == 0 && 1)
    goto L41;
  goto ret0;

  L41:
  x2 = XEXP (x1, 1);
  if (register_operand (x2, SImode))
    {
      ro[1] = x2;
      return gen_split_6 (operands);
    }
  goto ret0;

  L790:
  x1 = XEXP (x0, 1);
  if (register_operand (x1, DFmode))
    {
      ro[1] = x1;
      if (reload_completed
   && GET_CODE (operands[0]) == REG && !XRF_REGNO_P (REGNO (operands[0]))
   && GET_CODE (operands[1]) == REG && !XRF_REGNO_P (REGNO (operands[1])))
	return gen_split_125 (operands);
      }
  goto ret0;

  L86:
  x1 = XVECEXP (x0, 0, 0);
  if (GET_CODE (x1) == SET && 1)
    goto L87;
  goto ret0;

  L87:
  x2 = XEXP (x1, 0);
  switch (GET_MODE (x2))
    {
    case SImode:
      if (register_operand (x2, SImode))
	{
	  ro[0] = x2;
	  goto L88;
	}
      break;
    case CCEVENmode:
      if (register_operand (x2, CCEVENmode))
	{
	  ro[0] = x2;
	  goto L276;
	}
    }
  goto ret0;
 L88:
  return split_1 (x0, insn);

  L276:
  x2 = XEXP (x1, 1);
  if (GET_MODE (x2) != CCEVENmode)
    goto ret0;
  switch (GET_CODE (x2))
    {
    case IOR:
      goto L277;
    case AND:
      goto L334;
    }
  goto ret0;

  L277:
  x3 = XEXP (x2, 0);
  if (GET_MODE (x3) != CCmode)
    goto ret0;
  switch (GET_CODE (x3))
    {
    case ROTATE:
      goto L278;
    case NOT:
      goto L305;
    }
  goto ret0;

  L278:
  x4 = XEXP (x3, 0);
  if (partial_ccmode_register_operand (x4, VOIDmode))
    {
      ro[1] = x4;
      goto L279;
    }
  goto ret0;

  L279:
  x4 = XEXP (x3, 1);
  if (GET_CODE (x4) == CONST_INT && int5_operand (x4, CCmode))
    {
      ro[2] = x4;
      goto L280;
    }
  goto ret0;

  L280:
  x3 = XEXP (x2, 1);
  if (partial_ccmode_register_operand (x3, VOIDmode))
    {
      ro[3] = x3;
      goto L281;
    }
  goto ret0;

  L281:
  x1 = XVECEXP (x0, 0, 1);
  if (GET_CODE (x1) == CLOBBER && 1)
    goto L282;
  goto ret0;

  L282:
  x2 = XEXP (x1, 0);
  if (register_operand (x2, CCEVENmode))
    {
      ro[4] = x2;
      return gen_split_31 (operands);
    }
  goto ret0;

  L305:
  x4 = XEXP (x3, 0);
  if (GET_MODE (x4) == CCmode && GET_CODE (x4) == ROTATE && 1)
    goto L306;
  goto ret0;

  L306:
  x5 = XEXP (x4, 0);
  if (partial_ccmode_register_operand (x5, VOIDmode))
    {
      ro[1] = x5;
      goto L307;
    }
  goto ret0;

  L307:
  x5 = XEXP (x4, 1);
  if (GET_CODE (x5) == CONST_INT && int5_operand (x5, CCmode))
    {
      ro[2] = x5;
      goto L308;
    }
  goto ret0;

  L308:
  x3 = XEXP (x2, 1);
  if (partial_ccmode_register_operand (x3, VOIDmode))
    {
      ro[3] = x3;
      goto L309;
    }
  goto ret0;

  L309:
  x1 = XVECEXP (x0, 0, 1);
  if (GET_CODE (x1) == CLOBBER && 1)
    goto L310;
  goto ret0;

  L310:
  x2 = XEXP (x1, 0);
  if (register_operand (x2, CCEVENmode))
    {
      ro[4] = x2;
      return gen_split_33 (operands);
    }
  goto ret0;

  L334:
  x3 = XEXP (x2, 0);
  if (GET_MODE (x3) != CCmode)
    goto ret0;
  switch (GET_CODE (x3))
    {
    case ROTATE:
      goto L335;
    case NOT:
      goto L362;
    }
  goto ret0;

  L335:
  x4 = XEXP (x3, 0);
  if (partial_ccmode_register_operand (x4, VOIDmode))
    {
      ro[1] = x4;
      goto L336;
    }
  goto ret0;

  L336:
  x4 = XEXP (x3, 1);
  if (GET_CODE (x4) == CONST_INT && int5_operand (x4, CCmode))
    {
      ro[2] = x4;
      goto L337;
    }
  goto ret0;

  L337:
  x3 = XEXP (x2, 1);
  if (partial_ccmode_register_operand (x3, VOIDmode))
    {
      ro[3] = x3;
      goto L338;
    }
  goto ret0;

  L338:
  x1 = XVECEXP (x0, 0, 1);
  if (GET_CODE (x1) == CLOBBER && 1)
    goto L339;
  goto ret0;

  L339:
  x2 = XEXP (x1, 0);
  if (register_operand (x2, CCEVENmode))
    {
      ro[4] = x2;
      return gen_split_35 (operands);
    }
  goto ret0;

  L362:
  x4 = XEXP (x3, 0);
  if (GET_MODE (x4) == CCmode && GET_CODE (x4) == ROTATE && 1)
    goto L363;
  goto ret0;

  L363:
  x5 = XEXP (x4, 0);
  if (partial_ccmode_register_operand (x5, VOIDmode))
    {
      ro[1] = x5;
      goto L364;
    }
  goto ret0;

  L364:
  x5 = XEXP (x4, 1);
  if (GET_CODE (x5) == CONST_INT && int5_operand (x5, CCmode))
    {
      ro[2] = x5;
      goto L365;
    }
  goto ret0;

  L365:
  x3 = XEXP (x2, 1);
  if (partial_ccmode_register_operand (x3, VOIDmode))
    {
      ro[3] = x3;
      goto L366;
    }
  goto ret0;

  L366:
  x1 = XVECEXP (x0, 0, 1);
  if (GET_CODE (x1) == CLOBBER && 1)
    goto L367;
  goto ret0;

  L367:
  x2 = XEXP (x1, 0);
  if (register_operand (x2, CCEVENmode))
    {
      ro[4] = x2;
      return gen_split_37 (operands);
    }
  goto ret0;
 ret0: return 0;
}

