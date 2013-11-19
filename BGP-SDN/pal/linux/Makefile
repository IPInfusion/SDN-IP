#------------------------------------------------------------------------------
#
# This is the generic makefile placed in the directories within the product
# to take instructions from the top level make, and generate dependencies,
# code, and to even clean up behind itself.
#
# It includes a Rules.dir file which allows it to know some of what is going
# on, and to derive (also from variables set in the top level makefile) what
# needs to be done for the platform under compile, and in what directories the
# output files need to be placed.
#
# This file should never need to be edited directly.
#

#------------------------------------------------------------------------------
#
# Checking and setup
#

#
# Default build; tell user to specify an available option
#
default:
	@echo " "
	@echo "Please specify what to do. Standard make targets are available:"
	@echo " "
	@echo "	all		(make all available modules)"
	@echo "	dep		(make all dependencies)"
	@echo "	forcedep	(force all dependencies to be remade)"
	@echo "	clean		(clean up from a previous make)"
	@echo " "

#
# A quick check to be sure things are where we expect
#
ifeq ($(wildcard Rules.dir),$(empty))
  $(warning .)
  $(warning This directory does not contain a Rules.dir file.  This file is)
  $(warning required for correct operation.)
  $(warning .)
  $(error Aborting)
endif
#
# Bring in needed includes.  Yes, it *is* intentional that we include
# the Rules.dir file twice when we aren't started from the platform dir.
# This is because of the way make treats variables in target lines.
#
ifeq ($(BLD_BASE),$(empty))
  ifneq ($(IPI_BGPSDN_PLATFORM),$(empty))
    # Rules.dir may need build name
    BLD_NAME=$(IPI_BGPSDN_PLATFORM)
    include Rules.dir
    BLD_NAME=
    ifneq ($(wildcard $(TOP_DIR)/platform/$(IPI_BGPSDN_PLATFORM)),$(empty))
      include $(TOP_DIR)/platform/$(IPI_BGPSDN_PLATFORM)/Rules.platform
      include Rules.dir
      ifneq ($(IPI_BGPSDN_PLATFORM),$(BLD_NAME))
        $(warning .)
        $(warning Your platform specification disagrees with the rules file)
        $(warning for the platform.  Please check it.)
        $(warning .)
        $(error Aborting)
      endif
    else
      $(warning .)
      $(warning Your platform specification points to a directory which)
      $(warning does not contain the needed files.  Please check it.)
      $(warning .)
      $(error Aborting)
    endif
  else
    $(warning .)
    $(warning You must specify the platform if you expect to run make in)
    $(warning a module directory.  Set IPI_BGPSDN_PLATFORM equal to the name)
    $(warning selected for your platform.)
    $(warning .)
    $(error Aborting)
  endif
else
  include Rules.dir
  include $(TOP_DIR)/platform/$(BLD_NAME)/Rules.platform
endif

#
# Another quick check, this time on the local stuff
#
ifeq ($(DIR_NAME),$(empty))
  $(warning .)
  $(warning Files which are critical to the make process are missing.)
  $(warning Please be sure the product is complete and intact.)
  $(warning .)
  $(error Aborting)
endif

#
# Paths for storing things (don't change)
#
DIR_BASE=$(PRD_BASE)/$(DIR_OFFS)$(DIR_NAME)
DIR_OBJB=$(OBJ_BASE)/$(DIR_NAME)
DIR_DEPF=$(DEP_BASE)/$(DIR_NAME).dep
DIR_LIBF=$(OBJ_BASE)/$(DIR_NAME)$(LIB_SUFF)
DIR_EXEF=$(EXE_BASE)/$(DIR_NAME)$(BIN_SUFF)

#
# Collect output lists
#
DIR_OBJS=$(addprefix $(DIR_OBJB)/,$(DIR_SRCS:.c=$(OBJ_SUFF)))
DIR_DEPS=$(addprefix dep-,$(DIR_SRCS:.c=$(OBJ_SUFF)))
DIR_CSRC=$(wildcard *.c)
DIR_COBJ=$(addprefix $(DIR_OBJB)/,$(DIR_CSRC:.c=$(OBJ_SUFF)))
DIR_ASRC=
DIR_AHDR=
DIR_AOBJ=
DIR_ADEP=
DIR_AOBB=

#
# Conditional stuff
#
ifneq ($(DIR_ADDS),$(empty))
  ifneq ($(wildcard $(addsuffix /*.c,$(DIR_ADDS))),$(empty))
    DIR_ASRC=$(wildcard $(addsuffix /*.c,$(DIR_ADDS)))
    DIR_AHDR=$(wildcard $(addsuffix /*.h,$(DIR_ADDS)))
    DIR_AOBJ=$(addprefix $(DIR_OBJB)/,$(DIR_ASRC:.c=$(OBJ_SUFF)))
    DIR_ADEP=$(addprefix dep-,$(DIR_ASRC:.c=$(OBJ_SUFF)))
    DIR_AOBB=$(addprefix $(DIR_OBJB)/,$(DIR_ADDS))
  endif
endif
ifneq ($(DIR_ADDD),$(empty))
  ifneq ($(wildcard $(addsuffic /*.c,$(DIR_ADDD))),$(empty))
    DIR_AOBB=$(addprefix $(DIR_OBJB)/,$(DIR_ADDD))
  endif
endif
ifeq ($(DIR_MODE),out)
  DIR_OUTP=$(DIR_EXEF)
  DIR_OUTD=$(DIR_OBJS) $(DIR_AOBJ) $(DIR_ALLP)
else
  ifeq ($(DIR_MODE),lib)
    DIR_OUTP=$(DIR_LIBF)
    DIR_OUTD=$(DIR_OBJS) $(DIR_AOBJ) $(DIR_ALLP)
  else
    ifeq ($(DIR_MODE),nul)
      DIR_OUTP=$(DIR_OBJS) $(DIR_AOBJ)
      DIR_OUTD=$(DIR_ALLP)
    else
      $(warning .)
      $(warning DIR_MODE must be set to one of three options.  It does)
      $(warning not appear to be set correctly.  Check trailing spaces.)
      $(warning .)
      $(warning To build an executable, set DIR_MODE=out)
      $(warning To build a library, set     DIR_MODE=lib)
      $(warning To build only objects, set  DIR_MODE=nul)
      $(warning .)
      $(error Aborting)
    endif
  endif
endif

#
# Make configuration
#
#.EXPORT_ALL_VARIABLES:
#export

#------------------------------------------------------------------------------
#
# Interface makes
#

#
# Make everything in this directory
#
all: all-dir-names $(DIR_DEPF) $(DIR_ALLP) $(DIR_OUTP)

#
# Clean up the output from making everything in this directory
#
clean: all-dir-names $(DIR_CLNP)
	$(RM) $(DIR_COBJ) $(DIR_AOBJ) $(DIR_XOBJ) $(DIR_DEPF) $(DIR_XDEP) $(DIR_OUTP)

#
# Make dependencies
#
dep: all-dir-names $(DIR_DEPF)
	@true

fdep forcedep:
	$(RM) $(DIR_DEPF)
	$(MAKE) dep
ifneq ($(DIR_FDEP),$(empty))
	$(MAKE) $(DIR_FDEP)
endif

#------------------------------------------------------------------------------
#
# Internal makes
#

#
# Make sure the output directories exist
#
all-dir-names: $(addprefix dir-,$(OBJ_BASE) $(DIR_OBJB) $(DIR_AOBB) $(DEP_BASE) $(EXE_BASE))
$(addprefix dir-,$(OBJ_BASE) $(DIR_OBJB) $(DIR_AOBB) $(DEP_BASE) $(EXE_BASE)) :
	@if test ! -d $(patsubst dir-%,%,$@) ; then $(MKDIR) $(patsubst dir-%,%,$@) ; fi
   
#
# Dependencies for the sources.
#
$(DIR_DEPF): $(DIR_DEPP)
ifneq ($(DIR_DEPS)$(DIR_ADEP),$(empty))
	if test -f $(DIR_DEPF) ; then $(RM) $(DIR_DEPF) ; fi
	if test -f $(DIR_DEPF).x ; then $(RM) $(DIR_DEPF).x ; fi
	touch $(DIR_DEPF).x
	if $(MAKE) $(DIR_DEPS) $(DIR_ADEP); then mv $(DIR_DEPF).x $(DIR_DEPF) ; else $(RM) $(DIR_DEPF).x ; fi
endif
	test -f $(DIR_DEPF)
$(DIR_DEPS) $(DIR_ADEP):
	@$(ECHO_NOCR) "$(DIR_OBJB)/$(patsubst dep-%,%,$(patsubst %$(@F),%,$@))" >> $(DIR_DEPF).x
	$(MAKE_SINGLE_DEPS) $(MODULE_CFLAGS) $(patsubst dep-%$(OBJ_SUFF),%.c,$@) >> $(DIR_DEPF).x

#
# Make the object files from the sources and store them elsewhere
#
$(DIR_OBJS) $(DIR_AOBJ): $(DIR_DEPF)
	$(MAKE_SINGLE_FILE) $(MODULE_CFLAGS) -o $@ $(patsubst $(DIR_OBJB)/%$(OBJ_SUFF),%.c,$@)

#
# This builds an executable where applicable
#
$(DIR_EXEF): $(DIR_OUTD)
	$(MAKE_OUTPUT_FILE) -o $(EXE_BASE)/$(DIR_NAME)$(EXE_SUFF) $(wildcard $(OBJ_BASE)/$(DIR_NAME)/*$(OBJ_SUFF)) $(wildcard $(OBJ_BASE)/$(BLD_NAME)/*$(OBJ_SUFF)) $(wildcard $(LDLIBS))

#
# This builds a library where applicable
#
$(DIR_LIBF): $(DIR_OUTD)
	$(MAKE_LIBRARY_FILE) $(OBJ_BASE)/$(DIR_NAME)$(LIB_SUFF) $(wildcard $(OBJ_BASE)/$(DIR_NAME)/*$(OBJ_SUFF)) $(wildcard $(patsubst %,$(OBJ_BASE)/$(DIR_NAME)/%/*$(OBJ_SUFF),$(DIR_ADDS))) $(wildcard $(OBJ_ADDS)) 

#
# Include the dependency file so we are sure about the sources.
#
ifneq ($(wildcard $(DIR_DEPF)),$(empty))
include $(wildcard $(DIR_DEPF))
endif

