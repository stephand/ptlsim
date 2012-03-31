LLB=$(grep "ASF_MAX_LINES *=" asf.h | sed "s/.*= *\([0-9]*\).*/\1/")
CACHE=$(grep -q "^#define ENABLE_ASF_CACHE_BASED" config.h && echo ".L1_RS")
echo LLB_${LLB}${CACHE}

