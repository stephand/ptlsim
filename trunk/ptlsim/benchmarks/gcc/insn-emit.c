/* Generated automatically by the program `genemit'
from the machine description file `md'.  */

#include "config.h"
#include "rtl.h"
#include "expr.h"
#include "real.h"
#include "output.h"
#include "insn-config.h"

#include "insn-flags.h"

#include "insn-codes.h"

extern char *insn_operand_constraint[][MAX_RECOG_OPERANDS];

extern rtx recog_operand[];
#define operands emit_operand

#define FAIL goto _fail

#define DONE goto _done

rtx
gen_m88k_rcs_id (operand0)
     rtx operand0;
{
  rtx operands[1];
  rtx _val = 0;
  start_sequence ();
  operands[0] = operand0;
{ static char rcs_id[] = "$What: <@(#) m88k.md,v	1.1.1.2.2.2> $";
     FAIL; }
  operand0 = operands[0];
  emit (operand0);
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_split_1 (operands)
     rtx *operands;
{
  rtx operand0;
  rtx operand1;
  rtx operand2;
  rtx operand3;
  rtx _val = 0;
  start_sequence ();

  operand0 = operands[0];
  operand1 = operands[1];
  operand2 = operands[2];
  operand3 = operands[3];
  emit_insn (gen_rtx (SET, VOIDmode,
	gen_rtx (REG, CCmode,
	0),
	gen_rtx (UNSPEC, CCmode,
	gen_rtvec (2,
		operand2,
		operand3),
	1)));
  emit_insn (gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (PLUS, SImode,
	operand1,
	gen_rtx (UNSPEC, SImode,
	gen_rtvec (2,
		const0_rtx,
		gen_rtx (REG, CCmode,
	0)),
	0))));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_split_2 (operands)
     rtx *operands;
{
  rtx operand0;
  rtx operand1;
  rtx operand2;
  rtx operand3;
  rtx _val = 0;
  start_sequence ();

  operand0 = operands[0];
  operand1 = operands[1];
  operand2 = operands[2];
  operand3 = operands[3];
  emit_insn (gen_rtx (SET, VOIDmode,
	gen_rtx (REG, CCmode,
	0),
	gen_rtx (UNSPEC, CCmode,
	gen_rtvec (2,
		operand2,
		operand3),
	1)));
  emit_insn (gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (PLUS, SImode,
	operand1,
	gen_rtx (UNSPEC, SImode,
	gen_rtvec (2,
		const0_rtx,
		gen_rtx (REG, CCmode,
	0)),
	0))));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_split_3 (operands)
     rtx *operands;
{
  rtx operand0;
  rtx operand1;
  rtx operand2;
  rtx _val = 0;
  start_sequence ();

  operand0 = operands[0];
  operand1 = operands[1];
  operand2 = operands[2];
  emit_insn (gen_rtx (SET, VOIDmode,
	gen_rtx (REG, CCmode,
	0),
	gen_rtx (UNSPEC, CCmode,
	gen_rtvec (2,
		const0_rtx,
		operand2),
	1)));
  emit_insn (gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (PLUS, SImode,
	operand1,
	gen_rtx (UNSPEC, SImode,
	gen_rtvec (2,
		const0_rtx,
		gen_rtx (REG, CCmode,
	0)),
	0))));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_split_4 (operands)
     rtx *operands;
{
  rtx operand0;
  rtx operand1;
  rtx operand2;
  rtx operand3;
  rtx _val = 0;
  start_sequence ();

  operand0 = operands[0];
  operand1 = operands[1];
  operand2 = operands[2];
  operand3 = operands[3];
  emit_insn (gen_rtx (SET, VOIDmode,
	gen_rtx (REG, CCmode,
	0),
	gen_rtx (UNSPEC, CCmode,
	gen_rtvec (2,
		operand2,
		operand3),
	1)));
  emit_insn (gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (MINUS, SImode,
	operand1,
	gen_rtx (UNSPEC, SImode,
	gen_rtvec (2,
		const0_rtx,
		gen_rtx (REG, CCmode,
	0)),
	1))));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_split_5 (operands)
     rtx *operands;
{
  rtx operand0;
  rtx operand1;
  rtx operand2;
  rtx operand3;
  rtx _val = 0;
  start_sequence ();

  operand0 = operands[0];
  operand1 = operands[1];
  operand2 = operands[2];
  operand3 = operands[3];
  emit_insn (gen_rtx (SET, VOIDmode,
	gen_rtx (REG, CCmode,
	0),
	gen_rtx (UNSPEC, CCmode,
	gen_rtvec (2,
		operand2,
		operand3),
	1)));
  emit_insn (gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (MINUS, SImode,
	operand1,
	gen_rtx (UNSPEC, SImode,
	gen_rtvec (2,
		const0_rtx,
		gen_rtx (REG, CCmode,
	0)),
	1))));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_split_6 (operands)
     rtx *operands;
{
  rtx operand0;
  rtx operand1;
  rtx operand2;
  rtx _val = 0;
  start_sequence ();

  operand0 = operands[0];
  operand1 = operands[1];
  operand2 = operands[2];
  emit_insn (gen_rtx (SET, VOIDmode,
	gen_rtx (REG, CCmode,
	0),
	gen_rtx (UNSPEC, CCmode,
	gen_rtvec (2,
		const0_rtx,
		operand2),
	1)));
  emit_insn (gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (MINUS, SImode,
	operand1,
	gen_rtx (UNSPEC, SImode,
	gen_rtvec (2,
		const0_rtx,
		gen_rtx (REG, CCmode,
	0)),
	1))));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_split_7 (operands)
     rtx *operands;
{
  rtx operand0;
  rtx operand1;
  rtx operand2;
  rtx _val = 0;
  start_sequence ();

  operand0 = operands[0];
  operand1 = operands[1];
  operand2 = operands[2];
  emit_insn (gen_rtx (SET, VOIDmode,
	gen_rtx (REG, CCmode,
	0),
	gen_rtx (UNSPEC, CCmode,
	gen_rtvec (2,
		operand2,
		operand2),
	0)));
  emit_insn (gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (MINUS, SImode,
	operand1,
	gen_rtx (UNSPEC, SImode,
	gen_rtvec (2,
		const0_rtx,
		gen_rtx (REG, CCmode,
	0)),
	1))));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_split_13 (operands)
     rtx *operands;
{
  rtx operand0;
  rtx operand1;
  rtx operand2;
  rtx operand3;
  rtx operand4;
  rtx operand5;
  rtx _val = 0;
  start_sequence ();
operands[5] = gen_rtx(SUBREG, CCEVENmode, operands[5], 0);
   if (GET_CODE (operands[1]) == GET_CODE (operands[3]))
     ; /* The conditions match.  */
   else if (GET_CODE (operands[1])
	    == reverse_condition (GET_CODE (operands[3])))
     /* Reverse the condition by complimenting the compare word.  */
     operands[4] = gen_rtx (NOT, CCmode, operands[4]);
   else
     {
       /* Make the condition pairs line up by rotating the compare word.  */
       int cv1 = condition_value (operands[1]);
       int cv2 = condition_value (operands[3]);

       operands[4] = gen_rtx (ROTATE, CCmode, operands[4],
			      gen_rtx (CONST_INT, VOIDmode,
				       ((cv2 & ~1) - (cv1 & ~1)) & 0x1f));
       /* Reverse the condition if needed.  */
       if ((cv1 & 1) != (cv2 & 1))
	 operands[4] = gen_rtx (NOT, CCmode, operands[4]);
     }
  operand0 = operands[0];
  operand1 = operands[1];
  operand2 = operands[2];
  operand3 = operands[3];
  operand4 = operands[4];
  operand5 = operands[5];
  emit_insn (gen_rtx (SET, VOIDmode,
	operand5,
	gen_rtx (IOR, CCEVENmode,
	operand4,
	operand2)));
  emit_insn (gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (NEG, SImode,
	gen_rtx (GET_CODE (operand1), GET_MODE (operand1),
		operand5,
		const0_rtx))));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_split_14 (operands)
     rtx *operands;
{
  rtx operand0;
  rtx operand1;
  rtx operand2;
  rtx operand3;
  rtx operand4;
  rtx operand5;
  rtx _val = 0;
  start_sequence ();
operands[5] = gen_rtx(SUBREG, CCEVENmode, operands[5], 0);
   if (GET_CODE (operands[1]) == GET_CODE (operands[3]))
     ; /* The conditions match.  */
   else
     {
       /* Make the condition pairs line up by rotating the compare word.  */
       int cv1 = condition_value (operands[1]);
       int cv2 = condition_value (operands[3]);

       operands[4] = gen_rtx (ROTATE, CCmode, operands[4],
			      gen_rtx (CONST_INT, VOIDmode,
				       (cv2 - cv1) & 0x1f));
     }
  operand0 = operands[0];
  operand1 = operands[1];
  operand2 = operands[2];
  operand3 = operands[3];
  operand4 = operands[4];
  operand5 = operands[5];
  emit_insn (gen_rtx (SET, VOIDmode,
	operand5,
	gen_rtx (AND, CCEVENmode,
	operand4,
	operand2)));
  emit_insn (gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (NEG, SImode,
	gen_rtx (GET_CODE (operand1), GET_MODE (operand1),
		operand5,
		const0_rtx))));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_split_15 (operands)
     rtx *operands;
{
  rtx operand0;
  rtx operand1;
  rtx operand2;
  rtx operand3;
  rtx operand4;
  rtx operand5;
  rtx _val = 0;
  start_sequence ();
operands[5] = gen_rtx(SUBREG, CCEVENmode, operands[5], 0);
  if (GET_CODE (operands[1])
	    == reverse_condition (GET_CODE (operands[3])))
     ; 
   else
     {
       /* Make the condition pairs line up by rotating the compare word.  */
       int cv1 = condition_value (operands[1]);
       int cv2 = condition_value (operands[3]);

       operands[2] = gen_rtx (ROTATE, CCmode, operands[2],
			      gen_rtx (CONST_INT, VOIDmode,
				       ((cv1 & ~1) - (cv2 & ~1)) & 0x1f));
     }
  operand0 = operands[0];
  operand1 = operands[1];
  operand2 = operands[2];
  operand3 = operands[3];
  operand4 = operands[4];
  operand5 = operands[5];
  emit_insn (gen_rtx (SET, VOIDmode,
	operand5,
	gen_rtx (IOR, CCEVENmode,
	gen_rtx (NOT, CCmode,
	operand2),
	operand4)));
  emit_insn (gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (NEG, SImode,
	gen_rtx (GET_CODE (operand3), GET_MODE (operand3),
		operand5,
		const0_rtx))));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_split_16 (operands)
     rtx *operands;
{
  rtx operand0;
  rtx operand1;
  rtx operand2;
  rtx operand3;
  rtx operand4;
  rtx operand5;
  rtx _val = 0;
  start_sequence ();
operands[5] = gen_rtx(SUBREG, CCEVENmode, operands[5], 0);
   /* Reverse the condition by  complimenting the compare word.  */
   if (GET_CODE (operands[1]) != GET_CODE (operands[3]))
      operands[4] = gen_rtx (NOT, CCmode, operands[4]);
  operand0 = operands[0];
  operand1 = operands[1];
  operand2 = operands[2];
  operand3 = operands[3];
  operand4 = operands[4];
  operand5 = operands[5];
  emit_insn (gen_rtx (SET, VOIDmode,
	operand5,
	gen_rtx (IOR, CCEVENmode,
	operand4,
	operand2)));
  emit_insn (gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (GET_CODE (operand1), GET_MODE (operand1),
		operand5,
		const0_rtx)));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_split_17 (operands)
     rtx *operands;
{
  rtx operand0;
  rtx operand1;
  rtx operand2;
  rtx operand3;
  rtx operand4;
  rtx operand5;
  rtx _val = 0;
  start_sequence ();
operands[5] = gen_rtx(SUBREG, CCEVENmode, operands[5], 0);
  operand0 = operands[0];
  operand1 = operands[1];
  operand2 = operands[2];
  operand3 = operands[3];
  operand4 = operands[4];
  operand5 = operands[5];
  emit_insn (gen_rtx (SET, VOIDmode,
	operand5,
	gen_rtx (AND, CCEVENmode,
	operand4,
	operand2)));
  emit_insn (gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (GET_CODE (operand1), GET_MODE (operand1),
		operand5,
		const0_rtx)));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_split_18 (operands)
     rtx *operands;
{
  rtx operand0;
  rtx operand1;
  rtx operand2;
  rtx operand3;
  rtx operand4;
  rtx operand5;
  rtx _val = 0;
  start_sequence ();
operands[5] = gen_rtx(SUBREG, CCEVENmode, operands[5], 0);
  operand0 = operands[0];
  operand1 = operands[1];
  operand2 = operands[2];
  operand3 = operands[3];
  operand4 = operands[4];
  operand5 = operands[5];
  emit_insn (gen_rtx (SET, VOIDmode,
	operand5,
	gen_rtx (IOR, CCEVENmode,
	gen_rtx (NOT, CCmode,
	operand4),
	operand2)));
  emit_insn (gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (GET_CODE (operand1), GET_MODE (operand1),
		operand5,
		const0_rtx)));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_split_19 (operands)
     rtx *operands;
{
  rtx operand0;
  rtx operand1;
  rtx operand2;
  rtx operand3;
  rtx operand4;
  rtx operand5;
  rtx _val = 0;
  start_sequence ();
operands[5] = gen_rtx(SUBREG, CCEVENmode, operands[5], 0);
   if (GET_CODE (operands[1]) == GET_CODE (operands[3]))
     ; /* The conditions match.  */
   else if (GET_CODE (operands[1])
	    == reverse_condition (GET_CODE (operands[3])))
     /* Reverse the condition by complimenting the compare word.  */
     operands[4] = gen_rtx (NOT, CCmode, operands[4]);
   else
     {
       /* Make the condition pairs line up by rotating the compare word.  */
       int cv1 = condition_value (operands[1]);
       int cv2 = condition_value (operands[3]);
       operands[4] = gen_rtx (ROTATE, CCmode, operands[4],
			      gen_rtx (CONST_INT, VOIDmode,
				       ((cv2 & ~1) - (cv1 & ~1)) & 0x1f));
       /* Reverse the condition if needed.  */
       if ((cv1 & 1) != (cv2 & 1))
	 operands[4] = gen_rtx (NOT, CCmode, operands[4]);
     }
  operand0 = operands[0];
  operand1 = operands[1];
  operand2 = operands[2];
  operand3 = operands[3];
  operand4 = operands[4];
  operand5 = operands[5];
  emit_insn (gen_rtx (SET, VOIDmode,
	operand5,
	gen_rtx (AND, CCEVENmode,
	operand4,
	operand2)));
  emit_insn (gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (NEG, SImode,
	gen_rtx (GET_CODE (operand1), GET_MODE (operand1),
		operand5,
		const0_rtx))));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_split_20 (operands)
     rtx *operands;
{
  rtx operand0;
  rtx operand1;
  rtx operand2;
  rtx operand3;
  rtx operand4;
  rtx operand5;
  rtx _val = 0;
  start_sequence ();
operands[5] = gen_rtx(SUBREG, CCEVENmode, operands[5], 0);
   if (GET_CODE (operands[1]) == GET_CODE (operands[3]))
     ; /* The conditions match.  */
   else
     {
       /* Make the condition pairs line up by rotating the compare word.  */
       int cv1 = condition_value (operands[1]);
       int cv2 = condition_value (operands[3]);
       operands[4] = gen_rtx (ROTATE, CCmode, operands[4],
			      gen_rtx (CONST_INT, VOIDmode,
				       (cv2 - cv1) & 0x1f));
     }
  operand0 = operands[0];
  operand1 = operands[1];
  operand2 = operands[2];
  operand3 = operands[3];
  operand4 = operands[4];
  operand5 = operands[5];
  emit_insn (gen_rtx (SET, VOIDmode,
	operand5,
	gen_rtx (IOR, CCEVENmode,
	operand4,
	operand2)));
  emit_insn (gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (NEG, SImode,
	gen_rtx (GET_CODE (operand1), GET_MODE (operand1),
		operand5,
		const0_rtx))));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_split_21 (operands)
     rtx *operands;
{
  rtx operand0;
  rtx operand1;
  rtx operand2;
  rtx operand3;
  rtx operand4;
  rtx operand5;
  rtx _val = 0;
  start_sequence ();
operands[5] = gen_rtx(SUBREG, CCEVENmode, operands[5], 0);
   if (GET_CODE (operands[1])
	    == reverse_condition (GET_CODE (operands[3])))
	;
   else
     {
       /* Make the condition pairs line up by rotating the compare word.  */
       int cv1 = condition_value (operands[1]);
       int cv2 = condition_value (operands[3]);
       operands[2] = gen_rtx (ROTATE, CCmode, operands[2],
			      gen_rtx (CONST_INT, VOIDmode,
				       ((cv1 & ~1) - (cv2 & ~1)) & 0x1f));
     }
  operand0 = operands[0];
  operand1 = operands[1];
  operand2 = operands[2];
  operand3 = operands[3];
  operand4 = operands[4];
  operand5 = operands[5];
  emit_insn (gen_rtx (SET, VOIDmode,
	operand5,
	gen_rtx (AND, CCEVENmode,
	gen_rtx (NOT, CCmode,
	operand2),
	operand4)));
  emit_insn (gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (NEG, SImode,
	gen_rtx (GET_CODE (operand3), GET_MODE (operand3),
		operand5,
		const0_rtx))));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_split_22 (operands)
     rtx *operands;
{
  rtx operand0;
  rtx operand1;
  rtx operand2;
  rtx operand3;
  rtx operand4;
  rtx operand5;
  rtx _val = 0;
  start_sequence ();
operands[5] = gen_rtx(SUBREG, CCEVENmode, operands[5], 0);
   /* Reverse the condition by  complimenting the compare word.  */
   if (GET_CODE (operands[1]) != GET_CODE (operands[3]))
      operands[4] = gen_rtx (NOT, CCmode, operands[4]);
  operand0 = operands[0];
  operand1 = operands[1];
  operand2 = operands[2];
  operand3 = operands[3];
  operand4 = operands[4];
  operand5 = operands[5];
  emit_insn (gen_rtx (SET, VOIDmode,
	operand5,
	gen_rtx (AND, CCEVENmode,
	operand4,
	operand2)));
  emit_insn (gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (GET_CODE (operand1), GET_MODE (operand1),
		operand5,
		const0_rtx)));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_split_23 (operands)
     rtx *operands;
{
  rtx operand0;
  rtx operand1;
  rtx operand2;
  rtx operand3;
  rtx operand4;
  rtx operand5;
  rtx _val = 0;
  start_sequence ();
operands[5] = gen_rtx(SUBREG, CCEVENmode, operands[5], 0);
  operand0 = operands[0];
  operand1 = operands[1];
  operand2 = operands[2];
  operand3 = operands[3];
  operand4 = operands[4];
  operand5 = operands[5];
  emit_insn (gen_rtx (SET, VOIDmode,
	operand5,
	gen_rtx (IOR, CCEVENmode,
	operand4,
	operand2)));
  emit_insn (gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (GET_CODE (operand1), GET_MODE (operand1),
		operand5,
		const0_rtx)));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_split_24 (operands)
     rtx *operands;
{
  rtx operand0;
  rtx operand1;
  rtx operand2;
  rtx operand3;
  rtx operand4;
  rtx operand5;
  rtx _val = 0;
  start_sequence ();
operands[5] = gen_rtx(SUBREG, CCEVENmode, operands[5], 0);
  operand0 = operands[0];
  operand1 = operands[1];
  operand2 = operands[2];
  operand3 = operands[3];
  operand4 = operands[4];
  operand5 = operands[5];
  emit_insn (gen_rtx (SET, VOIDmode,
	operand5,
	gen_rtx (AND, CCEVENmode,
	gen_rtx (NOT, CCmode,
	operand2),
	operand4)));
  emit_insn (gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (GET_CODE (operand3), GET_MODE (operand3),
		operand5,
		const0_rtx)));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_split_31 (operands)
     rtx *operands;
{
  rtx operand0;
  rtx operand1;
  rtx operand2;
  rtx operand3;
  rtx operand4;
  rtx _val = 0;
  start_sequence ();

  operand0 = operands[0];
  operand1 = operands[1];
  operand2 = operands[2];
  operand3 = operands[3];
  operand4 = operands[4];
  emit_insn (gen_rtx (SET, VOIDmode,
	operand4,
	gen_rtx (ROTATE, CCmode,
	operand1,
	operand2)));
  emit_insn (gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (IOR, CCEVENmode,
	operand4,
	operand3)));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_split_33 (operands)
     rtx *operands;
{
  rtx operand0;
  rtx operand1;
  rtx operand2;
  rtx operand3;
  rtx operand4;
  rtx _val = 0;
  start_sequence ();

  operand0 = operands[0];
  operand1 = operands[1];
  operand2 = operands[2];
  operand3 = operands[3];
  operand4 = operands[4];
  emit_insn (gen_rtx (SET, VOIDmode,
	operand4,
	gen_rtx (ROTATE, CCmode,
	operand1,
	operand2)));
  emit_insn (gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (IOR, CCEVENmode,
	gen_rtx (NOT, CCmode,
	operand4),
	operand3)));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_split_35 (operands)
     rtx *operands;
{
  rtx operand0;
  rtx operand1;
  rtx operand2;
  rtx operand3;
  rtx operand4;
  rtx _val = 0;
  start_sequence ();

  operand0 = operands[0];
  operand1 = operands[1];
  operand2 = operands[2];
  operand3 = operands[3];
  operand4 = operands[4];
  emit_insn (gen_rtx (SET, VOIDmode,
	operand4,
	gen_rtx (ROTATE, CCmode,
	operand1,
	operand2)));
  emit_insn (gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (AND, CCEVENmode,
	operand4,
	operand3)));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_split_37 (operands)
     rtx *operands;
{
  rtx operand0;
  rtx operand1;
  rtx operand2;
  rtx operand3;
  rtx operand4;
  rtx _val = 0;
  start_sequence ();

  operand0 = operands[0];
  operand1 = operands[1];
  operand2 = operands[2];
  operand3 = operands[3];
  operand4 = operands[4];
  emit_insn (gen_rtx (SET, VOIDmode,
	operand4,
	gen_rtx (ROTATE, CCmode,
	operand1,
	operand2)));
  emit_insn (gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (AND, CCEVENmode,
	gen_rtx (NOT, CCmode,
	operand4),
	operand3)));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_test (operand0, operand1)
     rtx operand0;
     rtx operand1;
{
  rtx operand2;
  rtx operands[3];
  rtx _val = 0;
  start_sequence ();
  operands[0] = operand0;
  operands[1] = operand1;

{
  if (m88k_compare_reg)
    abort ();

  if (GET_CODE (operands[0]) == CONST_INT
      && ! SMALL_INT (operands[0]))
    operands[0] = force_reg (SImode, operands[0]);

  if (GET_CODE (operands[1]) == CONST_INT
      && ! SMALL_INT (operands[1]))
    operands[1] = force_reg (SImode, operands[1]);

  operands[2] = m88k_compare_reg = gen_reg_rtx (CCmode);
}
  operand0 = operands[0];
  operand1 = operands[1];
  operand2 = operands[2];
  emit_insn (gen_rtx (SET, VOIDmode,
	operand2,
	gen_rtx (COMPARE, CCmode,
	operand0,
	operand1)));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_cmpsi (operand0, operand1)
     rtx operand0;
     rtx operand1;
{
  rtx operand2;
  rtx operands[3];
  rtx _val = 0;
  start_sequence ();
  operands[0] = operand0;
  operands[1] = operand1;

{
  if (GET_CODE (operands[0]) == CONST_INT
      || GET_CODE (operands[1]) == CONST_INT)
    {
      m88k_compare_reg = 0;
      m88k_compare_op0 = operands[0];
      m88k_compare_op1 = operands[1];
      DONE;
    }
  operands[2] = m88k_compare_reg = gen_reg_rtx (CCmode);
}
  operand0 = operands[0];
  operand1 = operands[1];
  operand2 = operands[2];
  emit_insn (gen_rtx (SET, VOIDmode,
	operand2,
	gen_rtx (COMPARE, CCmode,
	operand0,
	operand1)));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_cmpsf (operand0, operand1)
     rtx operand0;
     rtx operand1;
{
  rtx operand2;
  rtx operands[3];
  rtx _val = 0;
  start_sequence ();
  operands[0] = operand0;
  operands[1] = operand1;
operands[2] = m88k_compare_reg = gen_reg_rtx (CCmode);
  operand0 = operands[0];
  operand1 = operands[1];
  operand2 = operands[2];
  emit_insn (gen_rtx (SET, VOIDmode,
	operand2,
	gen_rtx (COMPARE, CCmode,
	operand0,
	operand1)));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_cmpdf (operand0, operand1)
     rtx operand0;
     rtx operand1;
{
  rtx operand2;
  rtx operands[3];
  rtx _val = 0;
  start_sequence ();
  operands[0] = operand0;
  operands[1] = operand1;

{
  operands[0] = legitimize_operand (operands[0], DFmode);
  operands[1] = legitimize_operand (operands[1], DFmode);
  operands[2] = m88k_compare_reg = gen_reg_rtx (CCmode);
}
  operand0 = operands[0];
  operand1 = operands[1];
  operand2 = operands[2];
  emit_insn (gen_rtx (SET, VOIDmode,
	operand2,
	gen_rtx (COMPARE, CCmode,
	operand0,
	operand1)));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_seq (operand0)
     rtx operand0;
{
  rtx operand1;
  rtx operands[2];
  rtx _val = 0;
  start_sequence ();
  operands[0] = operand0;
operands[1] = emit_test (EQ, SImode);
  operand0 = operands[0];
  operand1 = operands[1];
  emit_insn (gen_rtx (SET, VOIDmode,
	operand0,
	operand1));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_sne (operand0)
     rtx operand0;
{
  rtx operand1;
  rtx operands[2];
  rtx _val = 0;
  start_sequence ();
  operands[0] = operand0;
operands[1] = emit_test (NE, SImode);
  operand0 = operands[0];
  operand1 = operands[1];
  emit_insn (gen_rtx (SET, VOIDmode,
	operand0,
	operand1));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_sgt (operand0)
     rtx operand0;
{
  rtx operand1;
  rtx operands[2];
  rtx _val = 0;
  start_sequence ();
  operands[0] = operand0;
operands[1] = emit_test (GT, SImode);
  operand0 = operands[0];
  operand1 = operands[1];
  emit_insn (gen_rtx (SET, VOIDmode,
	operand0,
	operand1));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_sgtu (operand0)
     rtx operand0;
{
  rtx operand1;
  rtx operands[2];
  rtx _val = 0;
  start_sequence ();
  operands[0] = operand0;
operands[1] = emit_test (GTU, SImode);
  operand0 = operands[0];
  operand1 = operands[1];
  emit_insn (gen_rtx (SET, VOIDmode,
	operand0,
	operand1));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_slt (operand0)
     rtx operand0;
{
  rtx operand1;
  rtx operands[2];
  rtx _val = 0;
  start_sequence ();
  operands[0] = operand0;
operands[1] = emit_test (LT, SImode);
  operand0 = operands[0];
  operand1 = operands[1];
  emit_insn (gen_rtx (SET, VOIDmode,
	operand0,
	operand1));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_sltu (operand0)
     rtx operand0;
{
  rtx operand1;
  rtx operands[2];
  rtx _val = 0;
  start_sequence ();
  operands[0] = operand0;
operands[1] = emit_test (LTU, SImode);
  operand0 = operands[0];
  operand1 = operands[1];
  emit_insn (gen_rtx (SET, VOIDmode,
	operand0,
	operand1));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_sge (operand0)
     rtx operand0;
{
  rtx operand1;
  rtx operands[2];
  rtx _val = 0;
  start_sequence ();
  operands[0] = operand0;
operands[1] = emit_test (GE, SImode);
  operand0 = operands[0];
  operand1 = operands[1];
  emit_insn (gen_rtx (SET, VOIDmode,
	operand0,
	operand1));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_sgeu (operand0)
     rtx operand0;
{
  rtx operand1;
  rtx operands[2];
  rtx _val = 0;
  start_sequence ();
  operands[0] = operand0;
operands[1] = emit_test (GEU, SImode);
  operand0 = operands[0];
  operand1 = operands[1];
  emit_insn (gen_rtx (SET, VOIDmode,
	operand0,
	operand1));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_sle (operand0)
     rtx operand0;
{
  rtx operand1;
  rtx operands[2];
  rtx _val = 0;
  start_sequence ();
  operands[0] = operand0;
operands[1] = emit_test (LE, SImode);
  operand0 = operands[0];
  operand1 = operands[1];
  emit_insn (gen_rtx (SET, VOIDmode,
	operand0,
	operand1));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_sleu (operand0)
     rtx operand0;
{
  rtx operand1;
  rtx operands[2];
  rtx _val = 0;
  start_sequence ();
  operands[0] = operand0;
operands[1] = emit_test (LEU, SImode);
  operand0 = operands[0];
  operand1 = operands[1];
  emit_insn (gen_rtx (SET, VOIDmode,
	operand0,
	operand1));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_split_75 (operands)
     rtx *operands;
{
  rtx operand0;
  rtx operand1;
  rtx operand2;
  rtx operand3;
  rtx _val = 0;
  start_sequence ();

  operand0 = operands[0];
  operand1 = operands[1];
  operand2 = operands[2];
  operand3 = operands[3];
  emit_insn (gen_rtx (SET, VOIDmode,
	operand3,
	gen_rtx (NOT, SImode,
	gen_rtx (GET_CODE (operand1), GET_MODE (operand1),
		operand2,
		const0_rtx))));
  emit_insn (gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (NOT, SImode,
	operand3)));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_split_80 (operands)
     rtx *operands;
{
  rtx operand0;
  rtx operand1;
  rtx operand2;
  rtx operand3;
  rtx _val = 0;
  start_sequence ();

  operand0 = operands[0];
  operand1 = operands[1];
  operand2 = operands[2];
  operand3 = operands[3];
  emit_insn (gen_rtx (SET, VOIDmode,
	operand3,
	gen_rtx (NEG, SImode,
	gen_rtx (NOT, SImode,
	gen_rtx (GET_CODE (operand1), GET_MODE (operand1),
		operand2,
		const0_rtx)))));
  emit_insn (gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (XOR, SImode,
	operand3,
	const1_rtx)));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_bcnd (operand0, operand1)
     rtx operand0;
     rtx operand1;
{
  rtx operands[2];
  rtx _val = 0;
  start_sequence ();
  operands[0] = operand0;
  operands[1] = operand1;
if (m88k_compare_reg) abort ();
  operand0 = operands[0];
  operand1 = operands[1];
  emit_jump_insn (gen_rtx (SET, VOIDmode,
	pc_rtx,
	gen_rtx (IF_THEN_ELSE, VOIDmode,
	operand0,
	gen_rtx (LABEL_REF, VOIDmode,
	operand1),
	pc_rtx)));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_bxx (operand0, operand1)
     rtx operand0;
     rtx operand1;
{
  rtx operands[2];
  rtx _val = 0;
  start_sequence ();
  operands[0] = operand0;
  operands[1] = operand1;
if (m88k_compare_reg == 0) abort ();
  operand0 = operands[0];
  operand1 = operands[1];
  emit_jump_insn (gen_rtx (SET, VOIDmode,
	pc_rtx,
	gen_rtx (IF_THEN_ELSE, VOIDmode,
	operand0,
	gen_rtx (LABEL_REF, VOIDmode,
	operand1),
	pc_rtx)));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_beq (operand0)
     rtx operand0;
{
  rtx operand1;
  rtx operands[2];
  rtx _val = 0;
  start_sequence ();
  operands[0] = operand0;
if (m88k_compare_reg == 0)
     {
       emit_bcnd (EQ, operands[0]);
       DONE;
     }
   operands[1] = m88k_compare_reg;
  operand0 = operands[0];
  operand1 = operands[1];
  emit_jump_insn (gen_rtx (SET, VOIDmode,
	pc_rtx,
	gen_rtx (IF_THEN_ELSE, VOIDmode,
	gen_rtx (EQ, VOIDmode,
	operand1,
	const0_rtx),
	gen_rtx (LABEL_REF, VOIDmode,
	operand0),
	pc_rtx)));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_bne (operand0)
     rtx operand0;
{
  rtx operand1;
  rtx operands[2];
  rtx _val = 0;
  start_sequence ();
  operands[0] = operand0;
if (m88k_compare_reg == 0)
     {
       emit_bcnd (NE, operands[0]);
       DONE;
     }
   operands[1] = m88k_compare_reg;
  operand0 = operands[0];
  operand1 = operands[1];
  emit_jump_insn (gen_rtx (SET, VOIDmode,
	pc_rtx,
	gen_rtx (IF_THEN_ELSE, VOIDmode,
	gen_rtx (NE, VOIDmode,
	operand1,
	const0_rtx),
	gen_rtx (LABEL_REF, VOIDmode,
	operand0),
	pc_rtx)));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_bgt (operand0)
     rtx operand0;
{
  rtx operand1;
  rtx operands[2];
  rtx _val = 0;
  start_sequence ();
  operands[0] = operand0;
if (m88k_compare_reg == 0)
     {
       emit_bcnd (GT, operands[0]);
       DONE;
     }
   operands[1] = m88k_compare_reg;
  operand0 = operands[0];
  operand1 = operands[1];
  emit_jump_insn (gen_rtx (SET, VOIDmode,
	pc_rtx,
	gen_rtx (IF_THEN_ELSE, VOIDmode,
	gen_rtx (GT, VOIDmode,
	operand1,
	const0_rtx),
	gen_rtx (LABEL_REF, VOIDmode,
	operand0),
	pc_rtx)));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_bgtu (operand0)
     rtx operand0;
{
  rtx operand1;
  rtx operands[2];
  rtx _val = 0;
  start_sequence ();
  operands[0] = operand0;
if (m88k_compare_reg == 0)
     {
       emit_jump_insn (gen_bxx (emit_test (GTU, VOIDmode), operands[0]));
       DONE;
     }
   operands[1] = m88k_compare_reg;
  operand0 = operands[0];
  operand1 = operands[1];
  emit_jump_insn (gen_rtx (SET, VOIDmode,
	pc_rtx,
	gen_rtx (IF_THEN_ELSE, VOIDmode,
	gen_rtx (GTU, VOIDmode,
	operand1,
	const0_rtx),
	gen_rtx (LABEL_REF, VOIDmode,
	operand0),
	pc_rtx)));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_blt (operand0)
     rtx operand0;
{
  rtx operand1;
  rtx operands[2];
  rtx _val = 0;
  start_sequence ();
  operands[0] = operand0;
if (m88k_compare_reg == 0)
     {
       emit_bcnd (LT, operands[0]);
       DONE;
     }
   operands[1] = m88k_compare_reg;
  operand0 = operands[0];
  operand1 = operands[1];
  emit_jump_insn (gen_rtx (SET, VOIDmode,
	pc_rtx,
	gen_rtx (IF_THEN_ELSE, VOIDmode,
	gen_rtx (LT, VOIDmode,
	operand1,
	const0_rtx),
	gen_rtx (LABEL_REF, VOIDmode,
	operand0),
	pc_rtx)));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_bltu (operand0)
     rtx operand0;
{
  rtx operand1;
  rtx operands[2];
  rtx _val = 0;
  start_sequence ();
  operands[0] = operand0;
if (m88k_compare_reg == 0)
     {
       emit_jump_insn (gen_bxx (emit_test (LTU, VOIDmode), operands[0]));
       DONE;
     }
   operands[1] = m88k_compare_reg;
  operand0 = operands[0];
  operand1 = operands[1];
  emit_jump_insn (gen_rtx (SET, VOIDmode,
	pc_rtx,
	gen_rtx (IF_THEN_ELSE, VOIDmode,
	gen_rtx (LTU, VOIDmode,
	operand1,
	const0_rtx),
	gen_rtx (LABEL_REF, VOIDmode,
	operand0),
	pc_rtx)));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_bge (operand0)
     rtx operand0;
{
  rtx operand1;
  rtx operands[2];
  rtx _val = 0;
  start_sequence ();
  operands[0] = operand0;
if (m88k_compare_reg == 0)
     {
       emit_bcnd (GE, operands[0]);
       DONE;
     }
   operands[1] = m88k_compare_reg;
  operand0 = operands[0];
  operand1 = operands[1];
  emit_jump_insn (gen_rtx (SET, VOIDmode,
	pc_rtx,
	gen_rtx (IF_THEN_ELSE, VOIDmode,
	gen_rtx (GE, VOIDmode,
	operand1,
	const0_rtx),
	gen_rtx (LABEL_REF, VOIDmode,
	operand0),
	pc_rtx)));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_bgeu (operand0)
     rtx operand0;
{
  rtx operand1;
  rtx operands[2];
  rtx _val = 0;
  start_sequence ();
  operands[0] = operand0;
if (m88k_compare_reg == 0)
     {
       emit_jump_insn (gen_bxx (emit_test (GEU, VOIDmode), operands[0]));
       DONE;
     }
   operands[1] = m88k_compare_reg;
  operand0 = operands[0];
  operand1 = operands[1];
  emit_jump_insn (gen_rtx (SET, VOIDmode,
	pc_rtx,
	gen_rtx (IF_THEN_ELSE, VOIDmode,
	gen_rtx (GEU, VOIDmode,
	operand1,
	const0_rtx),
	gen_rtx (LABEL_REF, VOIDmode,
	operand0),
	pc_rtx)));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_ble (operand0)
     rtx operand0;
{
  rtx operand1;
  rtx operands[2];
  rtx _val = 0;
  start_sequence ();
  operands[0] = operand0;
if (m88k_compare_reg == 0)
     {
       emit_bcnd (LE, operands[0]);
       DONE;
     }
   operands[1] = m88k_compare_reg;
  operand0 = operands[0];
  operand1 = operands[1];
  emit_jump_insn (gen_rtx (SET, VOIDmode,
	pc_rtx,
	gen_rtx (IF_THEN_ELSE, VOIDmode,
	gen_rtx (LE, VOIDmode,
	operand1,
	const0_rtx),
	gen_rtx (LABEL_REF, VOIDmode,
	operand0),
	pc_rtx)));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_bleu (operand0)
     rtx operand0;
{
  rtx operand1;
  rtx operands[2];
  rtx _val = 0;
  start_sequence ();
  operands[0] = operand0;
if (m88k_compare_reg == 0)
     {
       emit_jump_insn (gen_bxx (emit_test (LEU, VOIDmode), operands[0]));
       DONE;
     }
   operands[1] = m88k_compare_reg;
  operand0 = operands[0];
  operand1 = operands[1];
  emit_jump_insn (gen_rtx (SET, VOIDmode,
	pc_rtx,
	gen_rtx (IF_THEN_ELSE, VOIDmode,
	gen_rtx (LEU, VOIDmode,
	operand1,
	const0_rtx),
	gen_rtx (LABEL_REF, VOIDmode,
	operand0),
	pc_rtx)));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_locate1 (operand0, operand1)
     rtx operand0;
     rtx operand1;
{
  return gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (HIGH, SImode,
	gen_rtx (UNSPEC, SImode,
	gen_rtvec (1,
		gen_rtx (LABEL_REF, VOIDmode,
	operand1)),
	0)));
}

rtx
gen_locate2 (operand0, operand1)
     rtx operand0;
     rtx operand1;
{
  return gen_rtx (PARALLEL, VOIDmode,
	gen_rtvec (2,
		gen_rtx (SET, VOIDmode,
	gen_rtx (REG, SImode,
	1),
	pc_rtx),
		gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (LO_SUM, SImode,
	operand0,
	gen_rtx (UNSPEC, SImode,
	gen_rtvec (1,
		gen_rtx (LABEL_REF, VOIDmode,
	operand1)),
	0)))));
}

rtx
gen_movsi (operand0, operand1)
     rtx operand0;
     rtx operand1;
{
  rtx operands[2];
  rtx _val = 0;
  start_sequence ();
  operands[0] = operand0;
  operands[1] = operand1;

{
  if (emit_move_sequence (operands, SImode, 0))
    DONE;
}
  operand0 = operands[0];
  operand1 = operands[1];
  emit_insn (gen_rtx (SET, VOIDmode,
	operand0,
	operand1));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_reload_insi (operand0, operand1, operand2)
     rtx operand0;
     rtx operand1;
     rtx operand2;
{
  rtx operands[3];
  rtx _val = 0;
  start_sequence ();
  operands[0] = operand0;
  operands[1] = operand1;
  operands[2] = operand2;

{
  if (emit_move_sequence (operands, SImode, operands[2]))
    DONE;

  /* We don't want the clobber emitted, so handle this ourselves.  */
  emit_insn (gen_rtx (SET, VOIDmode, operands[0], operands[1]));
  DONE;
}
  operand0 = operands[0];
  operand1 = operands[1];
  operand2 = operands[2];
  emit_insn (gen_rtx (SET, VOIDmode,
	operand0,
	operand1));
  emit_insn (gen_rtx (CLOBBER, VOIDmode,
	operand2));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_movhi (operand0, operand1)
     rtx operand0;
     rtx operand1;
{
  rtx operands[2];
  rtx _val = 0;
  start_sequence ();
  operands[0] = operand0;
  operands[1] = operand1;

{
  if (emit_move_sequence (operands, HImode, 0))
    DONE;
}
  operand0 = operands[0];
  operand1 = operands[1];
  emit_insn (gen_rtx (SET, VOIDmode,
	operand0,
	operand1));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_movqi (operand0, operand1)
     rtx operand0;
     rtx operand1;
{
  rtx operands[2];
  rtx _val = 0;
  start_sequence ();
  operands[0] = operand0;
  operands[1] = operand1;

{
  if (emit_move_sequence (operands, QImode, 0))
    DONE;
}
  operand0 = operands[0];
  operand1 = operands[1];
  emit_insn (gen_rtx (SET, VOIDmode,
	operand0,
	operand1));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_movdi (operand0, operand1)
     rtx operand0;
     rtx operand1;
{
  rtx operands[2];
  rtx _val = 0;
  start_sequence ();
  operands[0] = operand0;
  operands[1] = operand1;

{
  if (emit_move_sequence (operands, DImode, 0))
    DONE;
}
  operand0 = operands[0];
  operand1 = operands[1];
  emit_insn (gen_rtx (SET, VOIDmode,
	operand0,
	operand1));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_movdf (operand0, operand1)
     rtx operand0;
     rtx operand1;
{
  rtx operands[2];
  rtx _val = 0;
  start_sequence ();
  operands[0] = operand0;
  operands[1] = operand1;

{
  if (emit_move_sequence (operands, DFmode, 0))
    DONE;
}
  operand0 = operands[0];
  operand1 = operands[1];
  emit_insn (gen_rtx (SET, VOIDmode,
	operand0,
	operand1));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_split_125 (operands)
     rtx *operands;
{
  rtx operand0;
  rtx operand1;
  rtx operand2;
  rtx operand3;
  rtx operand4;
  rtx operand5;
  rtx _val = 0;
  start_sequence ();

{ operands[2] = operand_subword (operands[0], 0, 0, DFmode);
  operands[3] = operand_subword (operands[1], 0, 0, DFmode);
  operands[4] = operand_subword (operands[0], 1, 0, DFmode);
  operands[5] = operand_subword (operands[1], 1, 0, DFmode); }
  operand0 = operands[0];
  operand1 = operands[1];
  operand2 = operands[2];
  operand3 = operands[3];
  operand4 = operands[4];
  operand5 = operands[5];
  emit_insn (gen_rtx (SET, VOIDmode,
	operand2,
	operand3));
  emit_insn (gen_rtx (SET, VOIDmode,
	operand4,
	operand5));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_movsf (operand0, operand1)
     rtx operand0;
     rtx operand1;
{
  rtx operands[2];
  rtx _val = 0;
  start_sequence ();
  operands[0] = operand0;
  operands[1] = operand1;

{
  if (emit_move_sequence (operands, SFmode, 0))
    DONE;
}
  operand0 = operands[0];
  operand1 = operands[1];
  emit_insn (gen_rtx (SET, VOIDmode,
	operand0,
	operand1));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_movstrsi (operand0, operand1, operand2, operand3)
     rtx operand0;
     rtx operand1;
     rtx operand2;
     rtx operand3;
{
  rtx operands[4];
  rtx _val = 0;
  start_sequence ();
  operands[0] = operand0;
  operands[1] = operand1;
  operands[2] = operand2;
  operands[3] = operand3;

{
  rtx dest_mem = operands[0];
  rtx src_mem = operands[1];
  operands[0] = copy_to_mode_reg (SImode, XEXP (operands[0], 0));
  operands[1] = copy_to_mode_reg (SImode, XEXP (operands[1], 0));
  expand_block_move (dest_mem, src_mem, operands);
  DONE;
}
  operand0 = operands[0];
  operand1 = operands[1];
  operand2 = operands[2];
  operand3 = operands[3];
  emit (gen_rtx (PARALLEL, VOIDmode,
	gen_rtvec (3,
		gen_rtx (SET, VOIDmode,
	gen_rtx (MEM, BLKmode,
	operand0),
	gen_rtx (MEM, BLKmode,
	operand1)),
		gen_rtx (USE, VOIDmode,
	operand2),
		gen_rtx (USE, VOIDmode,
	operand3))));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_call_block_move (operand0, operand1, operand2, operand3, operand4, operand5)
     rtx operand0;
     rtx operand1;
     rtx operand2;
     rtx operand3;
     rtx operand4;
     rtx operand5;
{
  rtx operands[6];
  rtx _val = 0;
  start_sequence ();
  emit_insn (gen_rtx (SET, VOIDmode,
	gen_rtx (REG, SImode,
	3),
	gen_rtx (MINUS, SImode,
	operand2,
	operand3)));
  emit_insn (gen_rtx (SET, VOIDmode,
	operand5,
	operand4));
  emit_insn (gen_rtx (SET, VOIDmode,
	gen_rtx (REG, SImode,
	2),
	gen_rtx (MINUS, SImode,
	operand1,
	operand3)));
  emit_insn (gen_rtx (USE, VOIDmode,
	gen_rtx (REG, SImode,
	2)));
  emit_insn (gen_rtx (USE, VOIDmode,
	gen_rtx (REG, SImode,
	3)));
  emit_insn (gen_rtx (USE, VOIDmode,
	operand5));
  emit_call_insn (gen_rtx (PARALLEL, VOIDmode,
	gen_rtvec (2,
		gen_rtx (SET, VOIDmode,
	gen_rtx (REG, DImode,
	2),
	gen_rtx (CALL, VOIDmode,
	gen_rtx (MEM, SImode,
	operand0),
	const0_rtx)),
		gen_rtx (CLOBBER, VOIDmode,
	gen_rtx (REG, SImode,
	1)))));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_call_movstrsi_loop (operand0, operand1, operand2, operand3, operand4, operand5, operand6)
     rtx operand0;
     rtx operand1;
     rtx operand2;
     rtx operand3;
     rtx operand4;
     rtx operand5;
     rtx operand6;
{
  rtx operands[7];
  rtx _val = 0;
  start_sequence ();
  emit_insn (gen_rtx (SET, VOIDmode,
	gen_rtx (REG, SImode,
	3),
	gen_rtx (MINUS, SImode,
	operand2,
	operand3)));
  emit_insn (gen_rtx (SET, VOIDmode,
	operand5,
	operand4));
  emit_insn (gen_rtx (SET, VOIDmode,
	gen_rtx (REG, SImode,
	2),
	gen_rtx (MINUS, SImode,
	operand1,
	operand3)));
  emit_insn (gen_rtx (SET, VOIDmode,
	gen_rtx (REG, SImode,
	6),
	operand6));
  emit_insn (gen_rtx (USE, VOIDmode,
	gen_rtx (REG, SImode,
	2)));
  emit_insn (gen_rtx (USE, VOIDmode,
	gen_rtx (REG, SImode,
	3)));
  emit_insn (gen_rtx (USE, VOIDmode,
	operand5));
  emit_insn (gen_rtx (USE, VOIDmode,
	gen_rtx (REG, SImode,
	6)));
  emit_call_insn (gen_rtx (PARALLEL, VOIDmode,
	gen_rtvec (2,
		gen_rtx (SET, VOIDmode,
	gen_rtx (REG, DImode,
	2),
	gen_rtx (CALL, VOIDmode,
	gen_rtx (MEM, SImode,
	operand0),
	const0_rtx)),
		gen_rtx (CLOBBER, VOIDmode,
	gen_rtx (REG, SImode,
	1)))));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_zero_extendhisi2 (operand0, operand1)
     rtx operand0;
     rtx operand1;
{
  rtx operands[2];
  rtx _val = 0;
  start_sequence ();
  operands[0] = operand0;
  operands[1] = operand1;

{
  if (GET_CODE (operands[1]) == MEM
      && symbolic_address_p (XEXP (operands[1], 0)))
    operands[1]
      = legitimize_address (flag_pic, operands[1], 0, 0);
}
  operand0 = operands[0];
  operand1 = operands[1];
  emit_insn (gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (ZERO_EXTEND, SImode,
	operand1)));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_zero_extendqihi2 (operand0, operand1)
     rtx operand0;
     rtx operand1;
{
  rtx operands[2];
  rtx _val = 0;
  start_sequence ();
  operands[0] = operand0;
  operands[1] = operand1;

{
  if (GET_CODE (operands[1]) == MEM
      && symbolic_address_p (XEXP (operands[1], 0)))
    operands[1]
      = legitimize_address (flag_pic, operands[1], 0, 0);
}
  operand0 = operands[0];
  operand1 = operands[1];
  emit_insn (gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (ZERO_EXTEND, HImode,
	operand1)));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_zero_extendqisi2 (operand0, operand1)
     rtx operand0;
     rtx operand1;
{
  rtx operands[2];
  rtx _val = 0;
  start_sequence ();
  operands[0] = operand0;
  operands[1] = operand1;

{
  if (GET_CODE (operands[1]) == MEM
      && symbolic_address_p (XEXP (operands[1], 0)))
    {
      operands[1]
	= legitimize_address (flag_pic, operands[1], 0, 0);
      emit_insn (gen_rtx (SET, VOIDmode, operands[0],
			  gen_rtx (ZERO_EXTEND, SImode, operands[1])));
      DONE;
    }
}
  operand0 = operands[0];
  operand1 = operands[1];
  emit_insn (gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (ZERO_EXTEND, SImode,
	operand1)));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_extendsidi2 (operand0, operand1)
     rtx operand0;
     rtx operand1;
{
  rtx operands[2];
  rtx _val = 0;
  start_sequence ();
  emit_insn (gen_rtx (SET, VOIDmode,
	gen_rtx (SUBREG, SImode,
	operand0,
	1),
	operand1));
  emit_insn (gen_rtx (SET, VOIDmode,
	gen_rtx (SUBREG, SImode,
	operand0,
	0),
	gen_rtx (ASHIFTRT, SImode,
	gen_rtx (SUBREG, SImode,
	operand0,
	1),
	GEN_INT (31))));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_extendhisi2 (operand0, operand1)
     rtx operand0;
     rtx operand1;
{
  rtx operands[2];
  rtx _val = 0;
  start_sequence ();
  operands[0] = operand0;
  operands[1] = operand1;

{
  if (GET_CODE (operands[1]) == MEM
      && symbolic_address_p (XEXP (operands[1], 0)))
    operands[1]
      = legitimize_address (flag_pic, operands[1], 0, 0);
}
  operand0 = operands[0];
  operand1 = operands[1];
  emit_insn (gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (SIGN_EXTEND, SImode,
	operand1)));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_extendqihi2 (operand0, operand1)
     rtx operand0;
     rtx operand1;
{
  rtx operands[2];
  rtx _val = 0;
  start_sequence ();
  operands[0] = operand0;
  operands[1] = operand1;

{
  if (GET_CODE (operands[1]) == MEM
      && symbolic_address_p (XEXP (operands[1], 0)))
    operands[1]
      = legitimize_address (flag_pic, operands[1], 0, 0);
}
  operand0 = operands[0];
  operand1 = operands[1];
  emit_insn (gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (SIGN_EXTEND, HImode,
	operand1)));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_extendqisi2 (operand0, operand1)
     rtx operand0;
     rtx operand1;
{
  rtx operands[2];
  rtx _val = 0;
  start_sequence ();
  operands[0] = operand0;
  operands[1] = operand1;

{
  if (GET_CODE (operands[1]) == MEM
      && symbolic_address_p (XEXP (operands[1], 0)))
    operands[1]
      = legitimize_address (flag_pic, operands[1], 0, 0);
}
  operand0 = operands[0];
  operand1 = operands[1];
  emit_insn (gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (SIGN_EXTEND, SImode,
	operand1)));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_extendsfdf2 (operand0, operand1)
     rtx operand0;
     rtx operand1;
{
  return gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (FLOAT_EXTEND, DFmode,
	operand1));
}

rtx
gen_truncdfsf2 (operand0, operand1)
     rtx operand0;
     rtx operand1;
{
  return gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (FLOAT_TRUNCATE, SFmode,
	operand1));
}

rtx
gen_floatsidf2 (operand0, operand1)
     rtx operand0;
     rtx operand1;
{
  return gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (FLOAT, DFmode,
	operand1));
}

rtx
gen_floatsisf2 (operand0, operand1)
     rtx operand0;
     rtx operand1;
{
  return gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (FLOAT, SFmode,
	operand1));
}

rtx
gen_fix_truncdfsi2 (operand0, operand1)
     rtx operand0;
     rtx operand1;
{
  return gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (FIX, SImode,
	operand1));
}

rtx
gen_fix_truncsfsi2 (operand0, operand1)
     rtx operand0;
     rtx operand1;
{
  return gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (FIX, SImode,
	operand1));
}

rtx
gen_addsi3 (operand0, operand1, operand2)
     rtx operand0;
     rtx operand1;
     rtx operand2;
{
  return gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (PLUS, SImode,
	operand1,
	operand2));
}

rtx
gen_adddf3 (operand0, operand1, operand2)
     rtx operand0;
     rtx operand1;
     rtx operand2;
{
  rtx operands[3];
  rtx _val = 0;
  start_sequence ();
  operands[0] = operand0;
  operands[1] = operand1;
  operands[2] = operand2;

{
  operands[1] = legitimize_operand (operands[1], DFmode);
  operands[2] = legitimize_operand (operands[2], DFmode);
}
  operand0 = operands[0];
  operand1 = operands[1];
  operand2 = operands[2];
  emit_insn (gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (PLUS, DFmode,
	operand1,
	operand2)));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_addsf3 (operand0, operand1, operand2)
     rtx operand0;
     rtx operand1;
     rtx operand2;
{
  return gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (PLUS, SFmode,
	operand1,
	operand2));
}

rtx
gen_adddi3 (operand0, operand1, operand2)
     rtx operand0;
     rtx operand1;
     rtx operand2;
{
  return gen_rtx (PARALLEL, VOIDmode, gen_rtvec (2,
		gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (PLUS, DImode,
	operand1,
	operand2)),
		gen_rtx (CLOBBER, VOIDmode,
	gen_rtx (REG, CCmode,
	0))));
}

rtx
gen_subsi3 (operand0, operand1, operand2)
     rtx operand0;
     rtx operand1;
     rtx operand2;
{
  return gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (MINUS, SImode,
	operand1,
	operand2));
}

rtx
gen_subdf3 (operand0, operand1, operand2)
     rtx operand0;
     rtx operand1;
     rtx operand2;
{
  rtx operands[3];
  rtx _val = 0;
  start_sequence ();
  operands[0] = operand0;
  operands[1] = operand1;
  operands[2] = operand2;

{
  operands[1] = legitimize_operand (operands[1], DFmode);
  operands[2] = legitimize_operand (operands[2], DFmode);
}
  operand0 = operands[0];
  operand1 = operands[1];
  operand2 = operands[2];
  emit_insn (gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (MINUS, DFmode,
	operand1,
	operand2)));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_subsf3 (operand0, operand1, operand2)
     rtx operand0;
     rtx operand1;
     rtx operand2;
{
  return gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (MINUS, SFmode,
	operand1,
	operand2));
}

rtx
gen_subdi3 (operand0, operand1, operand2)
     rtx operand0;
     rtx operand1;
     rtx operand2;
{
  return gen_rtx (PARALLEL, VOIDmode, gen_rtvec (2,
		gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (MINUS, DImode,
	operand1,
	operand2)),
		gen_rtx (CLOBBER, VOIDmode,
	gen_rtx (REG, CCmode,
	0))));
}

rtx
gen_mulsi3 (operand0, operand1, operand2)
     rtx operand0;
     rtx operand1;
     rtx operand2;
{
  return gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (MULT, SImode,
	operand1,
	operand2));
}

rtx
gen_muldf3 (operand0, operand1, operand2)
     rtx operand0;
     rtx operand1;
     rtx operand2;
{
  rtx operands[3];
  rtx _val = 0;
  start_sequence ();
  operands[0] = operand0;
  operands[1] = operand1;
  operands[2] = operand2;

{
  operands[1] = legitimize_operand (operands[1], DFmode);
  operands[2] = legitimize_operand (operands[2], DFmode);
}
  operand0 = operands[0];
  operand1 = operands[1];
  operand2 = operands[2];
  emit_insn (gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (MULT, DFmode,
	operand1,
	operand2)));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_mulsf3 (operand0, operand1, operand2)
     rtx operand0;
     rtx operand1;
     rtx operand2;
{
  return gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (MULT, SFmode,
	operand1,
	operand2));
}

rtx
gen_trap_divide_by_zero ()
{
  return gen_rtx (TRAP_IF, VOIDmode,
	const1_rtx,
	503);
}

rtx
gen_tcnd_divide_by_zero (operand0, operand1)
     rtx operand0;
     rtx operand1;
{
  rtx operands[2];
  rtx _val = 0;
  start_sequence ();
  operands[0] = operand0;
  operands[1] = operand1;

{
  emit_insn (gen_cmpsi (operands[0], const0_rtx));
  emit_jump_insn (gen_bne (operands[1]));
  emit_insn (gen_trap_divide_by_zero ());
  DONE;
}
  operand0 = operands[0];
  operand1 = operands[1];
  emit_jump_insn (gen_rtx (SET, VOIDmode,
	pc_rtx,
	gen_rtx (IF_THEN_ELSE, VOIDmode,
	gen_rtx (EQ, VOIDmode,
	operand0,
	const0_rtx),
	pc_rtx,
	operand1)));
  emit_insn (gen_rtx (TRAP_IF, VOIDmode,
	const1_rtx,
	503));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_divsi3 (operand0, operand1, operand2)
     rtx operand0;
     rtx operand1;
     rtx operand2;
{
  rtx operands[3];
  rtx _val = 0;
  start_sequence ();
  operands[0] = operand0;
  operands[1] = operand1;
  operands[2] = operand2;

{
  rtx op0 = operands[0];
  rtx op1 = operands[1];
  rtx op2 = operands[2];
  rtx join_label;

  /* @@ This needs to be reworked.  Torbjorn Granlund has suggested making
     it a runtime (perhaps quite special).  */

  if (GET_CODE (op1) == CONST_INT)
    op1 = force_reg (SImode, op1);

  else if (GET_CODE (op2) == CONST_INT
	   && ! SMALL_INT (operands[2]))
    op2 = force_reg (SImode, op2);

  if (op2 == const0_rtx)
    {
      emit_insn (gen_trap_divide_by_zero ());
      emit_insn (gen_dummy (op0));
      DONE;
    }

  if (TARGET_USE_DIV)
    {
      emit_move_insn (op0, gen_rtx (DIV, SImode, op1, op2));
      if (TARGET_CHECK_ZERO_DIV && GET_CODE (op2) != CONST_INT)
	{
	  rtx label = gen_label_rtx ();
	  emit_insn (gen_tcnd_divide_by_zero (op2, label));
	  emit_label (label);
	  emit_insn (gen_dummy (op0));
	}
      DONE;
    }

  join_label = gen_label_rtx ();
  if (GET_CODE (op1) == CONST_INT)
    {
      int neg = FALSE;
      rtx neg_op2 = gen_reg_rtx (SImode);
      rtx label1 = gen_label_rtx ();

      if (INTVAL (op1) < 0)
	{
	  neg = TRUE;
	  op1 = gen_rtx (CONST_INT, VOIDmode, -INTVAL (op1));
	}
      op1 = force_reg (SImode, op1);

      emit_insn (gen_negsi2 (neg_op2, op2));
      emit_insn (gen_cmpsi (op2, const0_rtx));
      emit_jump_insn (gen_bgt (label1));
						/* constant / 0-or-negative */
      emit_move_insn (op0, gen_rtx (UDIV, SImode, op1, neg_op2));
      if (!neg)
	emit_insn (gen_negsi2 (op0, op0));

      if (TARGET_CHECK_ZERO_DIV)
	emit_insn (gen_tcnd_divide_by_zero (op2, join_label));
      emit_jump_insn (gen_jump (join_label));
      emit_barrier ();

      emit_label (label1);			/* constant / positive */
      emit_move_insn (op0, gen_rtx (UDIV, SImode, op1, op2));
      if (neg)
	emit_insn (gen_negsi2 (op0, op0));
    }

  else if (GET_CODE (op2) == CONST_INT)
    {
      int neg = FALSE;
      rtx neg_op1 = gen_reg_rtx (SImode);
      rtx label1 = gen_label_rtx ();

      if (INTVAL (op2) < 0)
	{
	  neg = TRUE;
	  op2 = gen_rtx (CONST_INT, VOIDmode, -INTVAL (op2));
	}
      else if (! SMALL_INT (operands[2]))
	op2 = force_reg (SImode, op2);

      emit_insn (gen_negsi2 (neg_op1, op1));
      emit_insn (gen_cmpsi (op1, const0_rtx));
      emit_jump_insn (gen_bge (label1));
						/* 0-or-negative / constant */
      emit_move_insn (op0, gen_rtx (UDIV, SImode, neg_op1, op2));
      if (!neg)
	emit_insn (gen_negsi2 (op0, op0));

      emit_jump_insn (gen_jump (join_label));
      emit_barrier ();

      emit_label (label1);			/* positive / constant */
      emit_move_insn (op0, gen_rtx (UDIV, SImode, op1, op2));
      if (neg)
	emit_insn (gen_negsi2 (op0, op0));
    }

  else
    {
      rtx neg_op1 = gen_reg_rtx (SImode);
      rtx neg_op2 = gen_reg_rtx (SImode);
      rtx label1 = gen_label_rtx ();
      rtx label2 = gen_label_rtx ();
      rtx label3 = gen_label_rtx ();
      rtx label4;

      emit_insn (gen_negsi2 (neg_op2, op2));
      emit_insn (gen_cmpsi (op2, const0_rtx));
      emit_jump_insn (gen_bgt (label1));

      emit_insn (gen_negsi2 (neg_op1, op1));
      emit_insn (gen_cmpsi (op1, const0_rtx));
      emit_jump_insn (gen_bge (label2));
						/* negative / negative-or-0 */
      emit_move_insn (op0, gen_rtx (UDIV, SImode, neg_op1, neg_op2));

      if (TARGET_CHECK_ZERO_DIV)
	{
	  label4 = gen_label_rtx ();
	  emit_insn (gen_cmpsi (op2, const0_rtx));
	  emit_jump_insn (gen_bne (join_label));
	  emit_label (label4);
	  emit_insn (gen_trap_divide_by_zero ());
	}
      emit_jump_insn (gen_jump (join_label));
      emit_barrier ();

      emit_label (label2);			/* pos.-or-0 / neg.-or-0 */
      emit_move_insn (op0, gen_rtx (UDIV, SImode, op1, neg_op2));

      if (TARGET_CHECK_ZERO_DIV)
	{
	  emit_insn (gen_cmpsi (op2, const0_rtx));
	  emit_jump_insn (gen_beq (label4));
	}

      emit_insn (gen_negsi2 (op0, op0));
      emit_jump_insn (gen_jump (join_label));
      emit_barrier ();

      emit_label (label1);
      emit_insn (gen_negsi2 (neg_op1, op1));
      emit_insn (gen_cmpsi (op1, const0_rtx));
      emit_jump_insn (gen_bge (label3));
						/* negative / positive */
      emit_move_insn (op0, gen_rtx (UDIV, SImode, neg_op1, op2));
      emit_insn (gen_negsi2 (op0, op0));
      emit_jump_insn (gen_jump (join_label));
      emit_barrier ();

      emit_label (label3);			/* positive-or-0 / positive */
      emit_move_insn (op0, gen_rtx (UDIV, SImode, op1, op2));
    }

  emit_label (join_label);

  emit_insn (gen_dummy (op0));
  DONE;
}
  operand0 = operands[0];
  operand1 = operands[1];
  operand2 = operands[2];
  emit_insn (gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (DIV, SImode,
	operand1,
	operand2)));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_udivsi3 (operand0, operand1, operand2)
     rtx operand0;
     rtx operand1;
     rtx operand2;
{
  rtx operands[3];
  rtx _val = 0;
  start_sequence ();
  operands[0] = operand0;
  operands[1] = operand1;
  operands[2] = operand2;

{
  rtx op2 = operands[2];

  if (op2 == const0_rtx)
    {
      emit_insn (gen_trap_divide_by_zero ());
      emit_insn (gen_dummy (operands[0]));
      DONE;
    }
  else if (GET_CODE (op2) != CONST_INT && TARGET_CHECK_ZERO_DIV)
    {
      rtx label = gen_label_rtx ();
      emit_insn (gen_rtx (SET, VOIDmode, operands[0],
			  gen_rtx (UDIV, SImode, operands[1], op2)));
      emit_insn (gen_tcnd_divide_by_zero (op2, label));
      emit_label (label);
      emit_insn (gen_dummy (operands[0]));
      DONE;
    }
}
  operand0 = operands[0];
  operand1 = operands[1];
  operand2 = operands[2];
  emit_insn (gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (UDIV, SImode,
	operand1,
	operand2)));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_divdf3 (operand0, operand1, operand2)
     rtx operand0;
     rtx operand1;
     rtx operand2;
{
  rtx operands[3];
  rtx _val = 0;
  start_sequence ();
  operands[0] = operand0;
  operands[1] = operand1;
  operands[2] = operand2;

{
  operands[1] = legitimize_operand (operands[1], DFmode);
  if (real_power_of_2_operand (operands[2]))
    {
      union real_extract u;
      bcopy (&CONST_DOUBLE_LOW (operands[2]), &u, sizeof u);
      emit_insn (gen_muldf3 (operands[0], operands[1],
			     CONST_DOUBLE_FROM_REAL_VALUE (1.0/u.d, DFmode)));
      DONE;
    }
  else if (! register_operand (operands[2], DFmode))
    operands[2] = force_reg (DFmode, operands[2]);
}
  operand0 = operands[0];
  operand1 = operands[1];
  operand2 = operands[2];
  emit_insn (gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (DIV, DFmode,
	operand1,
	operand2)));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_divsf3 (operand0, operand1, operand2)
     rtx operand0;
     rtx operand1;
     rtx operand2;
{
  return gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (DIV, SFmode,
	operand1,
	operand2));
}

rtx
gen_andsi3 (operand0, operand1, operand2)
     rtx operand0;
     rtx operand1;
     rtx operand2;
{
  rtx operands[3];
  rtx _val = 0;
  start_sequence ();
  operands[0] = operand0;
  operands[1] = operand1;
  operands[2] = operand2;

{
  if (GET_CODE (operands[2]) == CONST_INT)
    {
      int value = INTVAL (operands[2]);

      if (! (SMALL_INTVAL (value)
	     || (value & 0xffff0000) == 0xffff0000
	     || (value & 0xffff) == 0xffff
	     || (value & 0xffff) == 0
	     || integer_ok_for_set (~value)))
	{
	  emit_insn (gen_andsi3 (operands[0], operands[1],
				 gen_rtx (CONST_INT, VOIDmode,
					  value | 0xffff)));
	  operands[1] = operands[0];
	  operands[2] = gen_rtx (CONST_INT, VOIDmode, value | 0xffff0000);
	}
    }
}
  operand0 = operands[0];
  operand1 = operands[1];
  operand2 = operands[2];
  emit_insn (gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (AND, SImode,
	operand1,
	operand2)));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_anddi3 (operand0, operand1, operand2)
     rtx operand0;
     rtx operand1;
     rtx operand2;
{
  return gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (AND, DImode,
	operand1,
	operand2));
}

rtx
gen_iorsi3 (operand0, operand1, operand2)
     rtx operand0;
     rtx operand1;
     rtx operand2;
{
  rtx operands[3];
  rtx _val = 0;
  start_sequence ();
  operands[0] = operand0;
  operands[1] = operand1;
  operands[2] = operand2;

{
  if (GET_CODE (operands[2]) == CONST_INT)
    {
      int value = INTVAL (operands[2]);

      if (! (SMALL_INTVAL (value)
	     || (value & 0xffff) == 0
	     || integer_ok_for_set (value)))
	{
	  emit_insn (gen_iorsi3 (operands[0], operands[1],
				 gen_rtx (CONST_INT, VOIDmode,
					  value & 0xffff0000)));
	  operands[1] = operands[0];
	  operands[2] = gen_rtx (CONST_INT, VOIDmode, value & 0xffff);
	}
    }
}
  operand0 = operands[0];
  operand1 = operands[1];
  operand2 = operands[2];
  emit_insn (gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (IOR, SImode,
	operand1,
	operand2)));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_iordi3 (operand0, operand1, operand2)
     rtx operand0;
     rtx operand1;
     rtx operand2;
{
  return gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (IOR, DImode,
	operand1,
	operand2));
}

rtx
gen_xorsi3 (operand0, operand1, operand2)
     rtx operand0;
     rtx operand1;
     rtx operand2;
{
  rtx operands[3];
  rtx _val = 0;
  start_sequence ();
  operands[0] = operand0;
  operands[1] = operand1;
  operands[2] = operand2;

{
  if (GET_CODE (operands[2]) == CONST_INT)
    {
      int value = INTVAL (operands[2]);

      if (! (SMALL_INTVAL (value)
	     || (value & 0xffff) == 0))
	{
	  emit_insn (gen_xorsi3 (operands[0], operands[1],
				 gen_rtx (CONST_INT, VOIDmode,
					  value & 0xffff0000)));
	  operands[1] = operands[0];
	  operands[2] = gen_rtx (CONST_INT, VOIDmode, value & 0xffff);
	}
    }
}
  operand0 = operands[0];
  operand1 = operands[1];
  operand2 = operands[2];
  emit_insn (gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (XOR, SImode,
	operand1,
	operand2)));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_xordi3 (operand0, operand1, operand2)
     rtx operand0;
     rtx operand1;
     rtx operand2;
{
  return gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (XOR, DImode,
	operand1,
	operand2));
}

rtx
gen_one_cmplsi2 (operand0, operand1)
     rtx operand0;
     rtx operand1;
{
  return gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (NOT, SImode,
	operand1));
}

rtx
gen_one_cmpldi2 (operand0, operand1)
     rtx operand0;
     rtx operand1;
{
  return gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (NOT, DImode,
	operand1));
}

rtx
gen_tbnd (operand0, operand1)
     rtx operand0;
     rtx operand1;
{
  return gen_rtx (TRAP_IF, VOIDmode,
	gen_rtx (GTU, VOIDmode,
	operand0,
	operand1),
	7);
}

rtx
gen_ashlsi3 (operand0, operand1, operand2)
     rtx operand0;
     rtx operand1;
     rtx operand2;
{
  rtx operands[3];
  rtx _val = 0;
  start_sequence ();
  operands[0] = operand0;
  operands[1] = operand1;
  operands[2] = operand2;

{
  if (GET_CODE (operands[2]) == CONST_INT)
    {
      if ((unsigned) INTVAL (operands[2]) > 31)
	{
	  if (TARGET_TRAP_LARGE_SHIFT)
	    emit_insn (gen_tbnd (force_reg (SImode, operands[2]),
				 gen_rtx (CONST_INT, VOIDmode, 31)));
	  else
	    emit_move_insn (operands[0], const0_rtx);
	  DONE;
	}
    }

  else if (TARGET_TRAP_LARGE_SHIFT)
    emit_insn (gen_tbnd (operands[2], gen_rtx (CONST_INT, VOIDmode, 31)));

  else if (TARGET_HANDLE_LARGE_SHIFT)
    {
      rtx reg = gen_reg_rtx (SImode);
      emit_insn (gen_cmpsi (operands[2], gen_rtx (CONST_INT, VOIDmode, 31)));
      emit_insn (gen_sleu (reg));
      emit_insn (gen_andsi3 (reg, operands[1], reg));
      operands[1] = reg;
    }
}
  operand0 = operands[0];
  operand1 = operands[1];
  operand2 = operands[2];
  emit_insn (gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (ASHIFT, SImode,
	operand1,
	operand2)));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_ashrsi3 (operand0, operand1, operand2)
     rtx operand0;
     rtx operand1;
     rtx operand2;
{
  rtx operands[3];
  rtx _val = 0;
  start_sequence ();
  operands[0] = operand0;
  operands[1] = operand1;
  operands[2] = operand2;

{
  if (GET_CODE (operands[2]) == CONST_INT)
    {
      if ((unsigned) INTVAL (operands[2]) > 31)
	{
	  if (TARGET_TRAP_LARGE_SHIFT)
	    {
	      emit_insn (gen_tbnd (force_reg (SImode, operands[2]),
				   gen_rtx (CONST_INT, VOIDmode, 31)));
	      DONE;
	    }
	  else
	    operands[2] = gen_rtx (CONST_INT, VOIDmode, 31);
	}
    }

  else if (TARGET_TRAP_LARGE_SHIFT)
    emit_insn (gen_tbnd (operands[2], gen_rtx (CONST_INT, VOIDmode, 31)));

  else if (TARGET_HANDLE_LARGE_SHIFT)
    {
      rtx reg = gen_reg_rtx (SImode);
      emit_insn (gen_cmpsi (operands[2], gen_rtx (CONST_INT, VOIDmode, 31)));
      emit_insn (gen_sgtu (reg));
      emit_insn (gen_iorsi3 (reg, operands[2], reg));
      operands[2] = reg;
    }
}
  operand0 = operands[0];
  operand1 = operands[1];
  operand2 = operands[2];
  emit_insn (gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (ASHIFTRT, SImode,
	operand1,
	operand2)));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_lshrsi3 (operand0, operand1, operand2)
     rtx operand0;
     rtx operand1;
     rtx operand2;
{
  rtx operands[3];
  rtx _val = 0;
  start_sequence ();
  operands[0] = operand0;
  operands[1] = operand1;
  operands[2] = operand2;

{
  if (GET_CODE (operands[2]) == CONST_INT)
    {
      if ((unsigned) INTVAL (operands[2]) > 31)
	{
	  if (TARGET_TRAP_LARGE_SHIFT)
	    emit_insn (gen_tbnd (force_reg (SImode, operands[2]),
				 gen_rtx (CONST_INT, VOIDmode, 31)));
	  else
	    emit_move_insn (operands[0], const0_rtx);
	  DONE;
	}
    }

  else if (TARGET_TRAP_LARGE_SHIFT)
    emit_insn (gen_tbnd (operands[2], gen_rtx (CONST_INT, VOIDmode, 31)));

  else if (TARGET_HANDLE_LARGE_SHIFT)
    {
      rtx reg = gen_reg_rtx (SImode);
      emit_insn (gen_cmpsi (operands[2], gen_rtx (CONST_INT, VOIDmode, 31)));
      emit_insn (gen_sleu (reg));
      emit_insn (gen_andsi3 (reg, operands[1], reg));
      operands[1] = reg;
    }
}
  operand0 = operands[0];
  operand1 = operands[1];
  operand2 = operands[2];
  emit_insn (gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (LSHIFTRT, SImode,
	operand1,
	operand2)));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_rotlsi3 (operand0, operand1, operand2)
     rtx operand0;
     rtx operand1;
     rtx operand2;
{
  rtx operands[3];
  rtx _val = 0;
  start_sequence ();
  operands[0] = operand0;
  operands[1] = operand1;
  operands[2] = operand2;

{
  if (GET_CODE (operands[2]) == CONST_INT
      && (unsigned) INTVAL (operands[2]) >= 32)
    operands[2] = gen_rtx (CONST_INT, VOIDmode,
			   (32 - INTVAL (operands[2])) % 32);
  else
    {
      rtx op = gen_reg_rtx (SImode);
      emit_insn (gen_negsi2 (op, operands[2]));
      operands[2] = op;
    }
}
  operand0 = operands[0];
  operand1 = operands[1];
  operand2 = operands[2];
  emit_insn (gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (ROTATERT, SImode,
	operand1,
	operand2)));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_rotrsi3 (operand0, operand1, operand2)
     rtx operand0;
     rtx operand1;
     rtx operand2;
{
  return gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (ROTATERT, SImode,
	operand1,
	operand2));
}

rtx
gen_ffssi2 (operand0, operand1)
     rtx operand0;
     rtx operand1;
{
  return gen_rtx (PARALLEL, VOIDmode, gen_rtvec (3,
		gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (FFS, SImode,
	operand1)),
		gen_rtx (CLOBBER, VOIDmode,
	gen_rtx (REG, CCmode,
	0)),
		gen_rtx (CLOBBER, VOIDmode,
	gen_rtx (SCRATCH, SImode, 0))));
}

rtx
gen_extv (operand0, operand1, operand2, operand3)
     rtx operand0;
     rtx operand1;
     rtx operand2;
     rtx operand3;
{
  return gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (SIGN_EXTRACT, SImode,
	operand1,
	operand2,
	operand3));
}

rtx
gen_extzv (operand0, operand1, operand2, operand3)
     rtx operand0;
     rtx operand1;
     rtx operand2;
     rtx operand3;
{
  return gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (ZERO_EXTRACT, SImode,
	operand1,
	operand2,
	operand3));
}

rtx
gen_negsi2 (operand0, operand1)
     rtx operand0;
     rtx operand1;
{
  return gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (NEG, SImode,
	operand1));
}

rtx
gen_negdf2 (operand0, operand1)
     rtx operand0;
     rtx operand1;
{
  return gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (NEG, DFmode,
	operand1));
}

rtx
gen_negsf2 (operand0, operand1)
     rtx operand0;
     rtx operand1;
{
  return gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (NEG, SFmode,
	operand1));
}

rtx
gen_absdf2 (operand0, operand1)
     rtx operand0;
     rtx operand1;
{
  return gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (ABS, DFmode,
	operand1));
}

rtx
gen_abssf2 (operand0, operand1)
     rtx operand0;
     rtx operand1;
{
  return gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (ABS, SFmode,
	operand1));
}

rtx
gen_casesi (operand0, operand1, operand2, operand3, operand4)
     rtx operand0;
     rtx operand1;
     rtx operand2;
     rtx operand3;
     rtx operand4;
{
  rtx operands[5];
  rtx _val = 0;
  start_sequence ();
  operands[0] = operand0;
  operands[1] = operand1;
  operands[2] = operand2;
  operands[3] = operand3;
  operands[4] = operand4;

{
  register rtx index_diff = gen_reg_rtx (SImode);
  register rtx low = gen_rtx (CONST_INT, VOIDmode, -INTVAL (operands[1]));
  register rtx label = gen_rtx (LABEL_REF, VOIDmode, operands[3]);
  register rtx base;

  if (! CASE_VECTOR_INSNS)
    /* These instructions are likely to be scheduled and made loop invariant.
       This decreases the cost of the dispatch at the expense of the default
       case.  */
    base = force_reg (SImode, memory_address_noforce (SImode, label));

  /* Compute the index difference and handle the default case.  */
  emit_insn (gen_addsi3 (index_diff,
			 force_reg (SImode, operands[0]),
			 ADD_INT (low) ? low : force_reg (SImode, low)));
  emit_insn (gen_cmpsi (index_diff, operands[2]));
  /* It's possible to replace this branch with sgtu/iorsi3 and adding a -1
     entry to the table.  However, that doesn't seem to win on the m88110.  */
  emit_jump_insn (gen_bgtu (operands[4]));

  if (CASE_VECTOR_INSNS)
    /* Call the jump that will branch to the appropriate case.  */
    emit_jump_insn (gen_casesi_enter (label, index_diff, operands[3]));
  else
    /* Load the table entry and jump to it.  */
    emit_jump_insn (gen_casesi_jump (gen_reg_rtx (SImode), base, index_diff, operands[3]));

  /* Claim that flow drops into the table so it will be adjacent by not
     emitting a barrier.  */
  DONE;
}
  operand0 = operands[0];
  operand1 = operands[1];
  operand2 = operands[2];
  operand3 = operands[3];
  operand4 = operands[4];
  emit (operand0);
  emit (operand1);
  emit (operand2);
  emit (operand3);
  emit (operand4);
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_casesi_jump (operand0, operand1, operand2, operand3)
     rtx operand0;
     rtx operand1;
     rtx operand2;
     rtx operand3;
{
  rtx operands[4];
  rtx _val = 0;
  start_sequence ();
  emit_insn (gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (MEM, SImode,
	gen_rtx (PLUS, SImode,
	operand1,
	gen_rtx (MULT, SImode,
	operand2,
	GEN_INT (4))))));
  emit_jump_insn (gen_rtx (PARALLEL, VOIDmode,
	gen_rtvec (2,
		gen_rtx (SET, VOIDmode,
	pc_rtx,
	operand0),
		gen_rtx (USE, VOIDmode,
	gen_rtx (LABEL_REF, VOIDmode,
	operand3)))));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_casesi_enter (operand0, operand1, operand2)
     rtx operand0;
     rtx operand1;
     rtx operand2;
{
  return gen_rtx (PARALLEL, VOIDmode, gen_rtvec (4,
		gen_rtx (SET, VOIDmode,
	pc_rtx,
	operand0),
		gen_rtx (USE, VOIDmode,
	operand1),
		gen_rtx (USE, VOIDmode,
	gen_rtx (LABEL_REF, VOIDmode,
	operand2)),
		gen_rtx (CLOBBER, VOIDmode,
	gen_rtx (REG, SImode,
	1))));
}

rtx
gen_call (operand0, operand1)
     rtx operand0;
     rtx operand1;
{
  rtx operands[2];
  rtx _val = 0;
  start_sequence ();
  operands[0] = operand0;
  operands[1] = operand1;

{
  if (GET_CODE (operands[0]) == MEM
      && ! call_address_operand (XEXP (operands[0], 0), SImode))
    operands[0] = gen_rtx (MEM, GET_MODE (operands[0]),
			   force_reg (Pmode, XEXP (operands[0], 0)));
}
  operand0 = operands[0];
  operand1 = operands[1];
  emit_call_insn (gen_rtx (PARALLEL, VOIDmode,
	gen_rtvec (2,
		gen_rtx (CALL, VOIDmode,
	operand0,
	operand1),
		gen_rtx (CLOBBER, VOIDmode,
	gen_rtx (REG, SImode,
	1)))));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_call_value (operand0, operand1, operand2)
     rtx operand0;
     rtx operand1;
     rtx operand2;
{
  rtx operands[3];
  rtx _val = 0;
  start_sequence ();
  operands[0] = operand0;
  operands[1] = operand1;
  operands[2] = operand2;

{
  if (GET_CODE (operands[1]) == MEM
      && ! call_address_operand (XEXP (operands[1], 0), SImode))
    operands[1] = gen_rtx (MEM, GET_MODE (operands[1]),
			   force_reg (Pmode, XEXP (operands[1], 0)));
}
  operand0 = operands[0];
  operand1 = operands[1];
  operand2 = operands[2];
  emit_call_insn (gen_rtx (PARALLEL, VOIDmode,
	gen_rtvec (2,
		gen_rtx (SET, VOIDmode,
	operand0,
	gen_rtx (CALL, VOIDmode,
	operand1,
	operand2)),
		gen_rtx (CLOBBER, VOIDmode,
	gen_rtx (REG, SImode,
	1)))));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_nop ()
{
  return const0_rtx;
}

rtx
gen_return ()
{
  return gen_rtx (RETURN, VOIDmode);
}

rtx
gen_prologue ()
{
  rtx _val = 0;
  start_sequence ();
m88k_expand_prologue (); DONE;
  emit_insn (const0_rtx);
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_epilogue ()
{
  rtx _val = 0;
  start_sequence ();
m88k_expand_epilogue ();
  emit_jump_insn (gen_rtx (RETURN, VOIDmode));
 _done:
  _val = gen_sequence ();
 _fail:
  end_sequence ();
  return _val;
}

rtx
gen_blockage ()
{
  return gen_rtx (UNSPEC_VOLATILE, VOIDmode,
	gen_rtvec (1,
		const0_rtx),
	0);
}

rtx
gen_indirect_jump (operand0)
     rtx operand0;
{
  return gen_rtx (SET, VOIDmode,
	pc_rtx,
	operand0);
}

rtx
gen_jump (operand0)
     rtx operand0;
{
  return gen_rtx (SET, VOIDmode,
	pc_rtx,
	gen_rtx (LABEL_REF, VOIDmode,
	operand0));
}

rtx
gen_decrement_and_branch_until_zero (operand0, operand1, operand2, operand3)
     rtx operand0;
     rtx operand1;
     rtx operand2;
     rtx operand3;
{
  return gen_rtx (PARALLEL, VOIDmode, gen_rtvec (4,
		gen_rtx (SET, VOIDmode,
	pc_rtx,
	gen_rtx (IF_THEN_ELSE, VOIDmode,
	gen_rtx (GET_CODE (operand0), VOIDmode,
		operand1,
		const0_rtx),
	gen_rtx (LABEL_REF, VOIDmode,
	operand2),
	pc_rtx)),
		gen_rtx (SET, VOIDmode,
	operand1,
	gen_rtx (PLUS, SImode,
	operand1,
	operand3)),
		gen_rtx (CLOBBER, VOIDmode,
	gen_rtx (SCRATCH, SImode, 0)),
		gen_rtx (CLOBBER, VOIDmode,
	gen_rtx (SCRATCH, SImode, 0))));
}

rtx
gen_dummy (operand0)
     rtx operand0;
{
  return gen_rtx (SET, VOIDmode,
	operand0,
	operand0);
}



void
add_clobbers (pattern, insn_code_number)
     rtx pattern;
     int insn_code_number;
{
  int i;

  switch (insn_code_number)
    {
    case 281:
      XVECEXP (pattern, 0, 2) = gen_rtx (CLOBBER, VOIDmode,
	gen_rtx (SCRATCH, SImode, 0));
      XVECEXP (pattern, 0, 3) = gen_rtx (CLOBBER, VOIDmode,
	gen_rtx (SCRATCH, SImode, 0));
      break;

    case 269:
      XVECEXP (pattern, 0, 3) = gen_rtx (CLOBBER, VOIDmode,
	gen_rtx (REG, SImode,
	1));
      break;

    case 252:
      XVECEXP (pattern, 0, 1) = gen_rtx (CLOBBER, VOIDmode,
	gen_rtx (REG, CCmode,
	0));
      XVECEXP (pattern, 0, 2) = gen_rtx (CLOBBER, VOIDmode,
	gen_rtx (SCRATCH, SImode, 0));
      break;

    case 191:
    case 190:
    case 189:
    case 178:
    case 177:
    case 176:
      XVECEXP (pattern, 0, 1) = gen_rtx (CLOBBER, VOIDmode,
	gen_rtx (REG, CCmode,
	0));
      break;

    case 81:
    case 76:
      XVECEXP (pattern, 0, 1) = gen_rtx (CLOBBER, VOIDmode,
	gen_rtx (SCRATCH, SImode, 0));
      break;

    case 38:
    case 36:
    case 34:
    case 32:
      XVECEXP (pattern, 0, 1) = gen_rtx (CLOBBER, VOIDmode,
	gen_rtx (SCRATCH, CCEVENmode, 0));
      break;

    default:
      abort ();
    }
}

void
init_mov_optab ()
{
#ifdef HAVE_movcceven
  if (HAVE_movcceven)
    mov_optab->handlers[(int) CCEVENmode].insn_code = CODE_FOR_movcceven;
#endif
}
