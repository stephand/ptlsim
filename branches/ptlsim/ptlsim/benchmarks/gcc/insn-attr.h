/* Generated automatically by the program `genattr'
from the machine description file `md'.  */

#ifndef PROTO
#if defined (USE_PROTOTYPES) ? USE_PROTOTYPES : defined (__STDC__)
#define PROTO(ARGS) ARGS
#else
#define PROTO(ARGS) ()
#endif
#endif
#define HAVE_ATTR_alternative
#define get_attr_alternative(insn) which_alternative
#define HAVE_ATTR_cpu
enum attr_cpu {CPU_M88100, CPU_M88110, CPU_M88000};
extern enum attr_cpu get_attr_cpu ();

#define HAVE_ATTR_type
enum attr_type {TYPE_BRANCH, TYPE_JUMP, TYPE_CALL, TYPE_LOAD, TYPE_STORE, TYPE_LOADD, TYPE_LOADA, TYPE_SPADD, TYPE_DPADD, TYPE_SPCMP, TYPE_DPCMP, TYPE_SPDIV, TYPE_DPDIV, TYPE_IDIV, TYPE_SPMUL, TYPE_DPMUL, TYPE_IMUL, TYPE_ARITH, TYPE_BIT, TYPE_MOV, TYPE_MARITH, TYPE_WEIRD};
extern enum attr_type get_attr_type ();

#define HAVE_ATTR_fpu
enum attr_fpu {FPU_YES, FPU_NO};
extern enum attr_fpu get_attr_fpu ();

#define HAVE_ATTR_length
extern int get_attr_length ();
extern void init_lengths ();
extern void shorten_branches PROTO((rtx));
extern int insn_default_length PROTO((rtx));
extern int insn_variable_length_p PROTO((rtx));
extern int insn_current_length PROTO((rtx));

extern int *insn_addresses;
extern int insn_current_address;

#define DELAY_SLOTS
extern int num_delay_slots PROTO((rtx));
extern int eligible_for_delay PROTO((rtx, int, rtx, int));

extern int const_num_delay_slots PROTO((rtx));

#define ANNUL_IFTRUE_SLOTS
extern int eligible_for_annul_true ();
#define INSN_SCHEDULING

extern int result_ready_cost PROTO((rtx));
extern int function_units_used PROTO((rtx));

extern struct function_unit_desc
{
  char *name;
  int bitmask;
  int multiplicity;
  int simultaneity;
  int default_cost;
  int max_issue_delay;
  int (*ready_cost_function) ();
  int (*conflict_cost_function) ();
  int max_blockage;
  unsigned int (*blockage_range_function) ();
  int (*blockage_function) ();
} function_units[];

#define FUNCTION_UNITS_SIZE 9
#define MIN_MULTIPLICITY 1
#define MAX_MULTIPLICITY 1
#define MIN_SIMULTANEITY 0
#define MAX_SIMULTANEITY 5
#define MIN_READY_COST 1
#define MAX_READY_COST 60
#define MIN_ISSUE_DELAY 1
#define MAX_ISSUE_DELAY 2
#define MIN_BLOCKAGE 1
#define MAX_BLOCKAGE 58
#define BLOCKAGE_BITS 7
#define INSN_QUEUE_SIZE 64

#define ATTR_FLAG_forward	0x1
#define ATTR_FLAG_backward	0x2
#define ATTR_FLAG_likely	0x4
#define ATTR_FLAG_very_likely	0x8
#define ATTR_FLAG_unlikely	0x10
#define ATTR_FLAG_very_unlikely	0x20
