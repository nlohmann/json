# This code depends on make tool being used
DEPFILES=$(wildcard $(addsuffix .d, ${OBJECTFILES} ${TESTOBJECTFILES}))
ifneq (${DEPFILES},)
include ${DEPFILES}
endif
