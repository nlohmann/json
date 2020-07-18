# 
# Generated Makefile - do not edit! 
# 
# Edit the Makefile in the project folder instead (../Makefile). Each target
# has a pre- and a post- target defined where you can add customization code.
#
# This makefile implements macros and targets common to all configurations.
#
# NOCDDL


# Building and Cleaning subprojects are done by default, but can be controlled with the SUB
# macro. If SUB=no, subprojects will not be built or cleaned. The following macro
# statements set BUILD_SUB-CONF and CLEAN_SUB-CONF to .build-reqprojects-conf
# and .clean-reqprojects-conf unless SUB has the value 'no'
SUB_no=NO
SUBPROJECTS=${SUB_${SUB}}
BUILD_SUBPROJECTS_=.build-subprojects
BUILD_SUBPROJECTS_NO=
BUILD_SUBPROJECTS=${BUILD_SUBPROJECTS_${SUBPROJECTS}}
CLEAN_SUBPROJECTS_=.clean-subprojects
CLEAN_SUBPROJECTS_NO=
CLEAN_SUBPROJECTS=${CLEAN_SUBPROJECTS_${SUBPROJECTS}}


# Project Name
PROJECTNAME=NlohmannMacroBuilder

# Active Configuration
DEFAULTCONF=Release
CONF=${DEFAULTCONF}

# All Configurations
ALLCONFS=Release 


# build
.build-impl: .build-pre .validate-impl .depcheck-impl
	@#echo "=> Running $@... Configuration=$(CONF)"
	"${MAKE}" -f nbproject/Makefile-${CONF}.mk QMAKE=${QMAKE} SUBPROJECTS=${SUBPROJECTS} .build-conf


# clean
.clean-impl: .clean-pre .validate-impl .depcheck-impl
	@#echo "=> Running $@... Configuration=$(CONF)"
	"${MAKE}" -f nbproject/Makefile-${CONF}.mk QMAKE=${QMAKE} SUBPROJECTS=${SUBPROJECTS} .clean-conf


# clobber 
.clobber-impl: .clobber-pre .depcheck-impl
	@#echo "=> Running $@..."
	for CONF in ${ALLCONFS}; \
	do \
	    "${MAKE}" -f nbproject/Makefile-$${CONF}.mk QMAKE=${QMAKE} SUBPROJECTS=${SUBPROJECTS} .clean-conf; \
	done

# all 
.all-impl: .all-pre .depcheck-impl
	@#echo "=> Running $@..."
	for CONF in ${ALLCONFS}; \
	do \
	    "${MAKE}" -f nbproject/Makefile-$${CONF}.mk QMAKE=${QMAKE} SUBPROJECTS=${SUBPROJECTS} .build-conf; \
	done

# build tests
.build-tests-impl: .build-impl .build-tests-pre
	@#echo "=> Running $@... Configuration=$(CONF)"
	"${MAKE}" -f nbproject/Makefile-${CONF}.mk SUBPROJECTS=${SUBPROJECTS} .build-tests-conf

# run tests
.test-impl: .build-tests-impl .test-pre
	@#echo "=> Running $@... Configuration=$(CONF)"
	"${MAKE}" -f nbproject/Makefile-${CONF}.mk SUBPROJECTS=${SUBPROJECTS} .test-conf

# dependency checking support
.depcheck-impl:
	@echo "# This code depends on make tool being used" >.dep.inc
	@if [ -n "${MAKE_VERSION}" ]; then \
	    echo "DEPFILES=\$$(wildcard \$$(addsuffix .d, \$${OBJECTFILES} \$${TESTOBJECTFILES}))" >>.dep.inc; \
	    echo "ifneq (\$${DEPFILES},)" >>.dep.inc; \
	    echo "include \$${DEPFILES}" >>.dep.inc; \
	    echo "endif" >>.dep.inc; \
	else \
	    echo ".KEEP_STATE:" >>.dep.inc; \
	    echo ".KEEP_STATE_FILE:.make.state.\$${CONF}" >>.dep.inc; \
	fi

# configuration validation
.validate-impl:
	@if [ ! -f nbproject/Makefile-${CONF}.mk ]; \
	then \
	    echo ""; \
	    echo "Error: can not find the makefile for configuration '${CONF}' in project ${PROJECTNAME}"; \
	    echo "See 'make help' for details."; \
	    echo "Current directory: " `pwd`; \
	    echo ""; \
	fi
	@if [ ! -f nbproject/Makefile-${CONF}.mk ]; \
	then \
	    exit 1; \
	fi


# help
.help-impl: .help-pre
	@echo "This makefile supports the following configurations:"
	@echo "    ${ALLCONFS}"
	@echo ""
	@echo "and the following targets:"
	@echo "    build  (default target)"
	@echo "    clean"
	@echo "    clobber"
	@echo "    all"
	@echo "    help"
	@echo ""
	@echo "Makefile Usage:"
	@echo "    make [CONF=<CONFIGURATION>] [SUB=no] build"
	@echo "    make [CONF=<CONFIGURATION>] [SUB=no] clean"
	@echo "    make [SUB=no] clobber"
	@echo "    make [SUB=no] all"
	@echo "    make help"
	@echo ""
	@echo "Target 'build' will build a specific configuration and, unless 'SUB=no',"
	@echo "    also build subprojects."
	@echo "Target 'clean' will clean a specific configuration and, unless 'SUB=no',"
	@echo "    also clean subprojects."
	@echo "Target 'clobber' will remove all built files from all configurations and,"
	@echo "    unless 'SUB=no', also from subprojects."
	@echo "Target 'all' will will build all configurations and, unless 'SUB=no',"
	@echo "    also build subprojects."
	@echo "Target 'help' prints this message."
	@echo ""

