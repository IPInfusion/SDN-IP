# Copyright (C) 2013 IP Infusion, Inc.  All rights reserved.

#------------------------------------------------------------------------------
#
# This is the generic top level makefile, placed in platform/<platform> in
# the tree.  It contains basic instructions which are platform independent
# instructing make on how to figure out which dirs contain products, and
# how to use the makefiles in those dirs to make the products.
#
# It includes a Rules.platform file which contains all of the platform
# specific operations and definitions.
#
# This makefile should not need to be edited directly.
#

#------------------------------------------------------------------------------
#
# Checking and setup
#

#
# Make sure the environment has been configured
#
ifeq ($(wildcard Rules.options),$(empty))
  $(warning .)
  $(warning This source tree is not configured correctly. : it is missing)
  $(warning the Rules.options file.  Please run the configuration script,)
  $(warning or check the configuration files to be sure they are correct.)
  $(warning .)
  $(error Aborting)
endif

#
# This is for relative directory work, since GNU make has problem with colons
# in target/dependency filenames, but some OSes require them.  *sigh*
#
TOP_DIR=../..

#
# Get the platform information
#
include Rules.platform
ifneq ($(IPI_BGPSDN_PLATFORM),$(empty))
  ifneq ($(IPI_BGPSDN_PLATFORM),$(BLD_NAME))
    $(warning .)
    $(warning Please either unset IPI_BGPSDN_PLATFORM, or set it to the)
    $(warning correct value for this platform, which is '$(BLD_NAME)'.)
    $(warning .)
    $(error Aborting)
  endif
else
  IPI_BGPSDN_PLATFORM=$(BLD_NAME)
endif

#
# Make sure the platform information contains at least a sensible
# list of executables to build
#
ifeq ($(ALL_EXES),$(empty))
  $(warning .)
  $(warning This source tree does not appear to contain, or to be configured)
  $(warning to build, any executable daemons.  Please check the configuration)
  $(warning files to be sure they are correct.)
  $(warning .)
  $(error Aborting)
endif

#
# Make sure the platform information contains at least a sensible
# list of directories to build
#
ifeq ($(ALL_TGTD),$(empty))
  $(warning .)
  $(warning This source tree does not appear to contain, or to be configured)
  $(warning to build, any executable daemons.  Please check the configuration)
  $(warning files to be sure they are correct.)
  $(warning .)
  $(error Aborting)
endif

#
# Make configurations
#
.EXPORT_ALL_VARIABLES:
export

#------------------------------------------------------------------------------
#
# Interface makes
#
# All of these are intended simply as user interface.  They are not used in
# descriptions which follow in the implementation section, but they do call
# make recursively with targets from the next section as appropriate.
#

#
# Default build; tell user to specify an available option
#
help:
ifneq ($(ALL_TGTD),$(empty))
	@echo " "
	@echo "I refuse to guess what you want.  Please be more specific."
	@echo " "
	@echo "Make targets which exist only at the top level are :"
	@echo " "
	@echo "	distclean	(remove all working files not in distribution)"
	@echo "	install		(install binaries and samples (makes first))"
	@echo " "
	@echo "Standard make targets (which apply to the top level as well as"
	@echo "to all available modules) include :"
	@echo " "
	@echo "	all		(make all available modules)"
	@echo "	dep		(make all dependencies)"
	@echo "	forcedep	(force all dependencies to be remade)"
	@echo "	clean		(clean up from a previous make)"
	@echo " "
	@echo "You may also make these targets in individual directories."
	@echo "Do this by indicating {target}-{directory}, for eg, all-lib,"
	@echo "choosing from the targets above and the directories below."
	@echo "This source tree is configured to work with these directores :"
	@$(ECHO_FORM) "$(patsubst %,\n\t%,$(ALL_TGTD))"
	@echo " "
	@echo "You may additionally make a single protocol daemon.  This will"
	@echo "build the executable for the specified daemon.  Do this by"
	@echo "indicating {daemon}, for eg ripd, choosing from the daemons"
	@echo "below.  This source tree supports making these daemons :"
	@$(ECHO_FORM) "$(patsubst %,\n\t%,$(ALL_EXES))"
	@echo " "
	@echo "For make aps toolkit, use: 'aps_toolkit'. This will generate "
	@echo "below daemons, libary and object file :"
	@$(ECHO_FORM) "$(patsubst %,\n\t%,$(APS_OUTPUT))"
	@echo " "
else
	@echo " "
	@echo "This source tree does not appear to contain any code, or it"
	@echo "has not been configured properly."
	@echo " "
	@test ! -f Makefile
endif

#
# Make everything in all available directories
#
all:	
	$(MAKE) $(DEP_BASE)/platform.dep
	$(MAKE) $(patsubst %,$(EXE_BASE)/%$(EXE_SUFF),$(ALL_EXES)) 

#
# Make dependencies
#
# The 'realdep' target is bogus but needed because of the dep subdirectory.
#
dep: realdep
realdep:
	$(MAKE) $(DEP_BASE)/platform.dep
	$(MAKE) $(patsubst %,$(DEP_BASE)/%.dep,$(ALL_TGTD))

#
# Remake dependencies even if they seem to be okay
#
fdep: forcedep
forcedep: 
	$(RM) $(DEP_BASE)/platform.dep
	$(MAKE) $(DEP_BASE)/platform.dep
	$(MAKE) $(addprefix forcedep-,$(ALL_TGTD))

#
# Clean everything up
#
clean: 
	$(MAKE) $(addprefix clean-,$(ALL_TGTD))
	$(RM) dep/platform.dep
	$(RM) $(patsubst %,$(EXE_BASE)/%$(EXE_SUFF),$(ALL_EXES))

#
# Throw out everything that's not meant to be in the base tarball
#
distclean: 
	find $(TOP_DIR) -name core -exec $(RM) \{\} \;
	$(RR) $(EXE_BASE) $(OBJ_BASE) $(DEP_BASE)
	$(RM) $(BLD_BASE)/Rules.options
	$(RM) $(BLD_BASE)/config.h
	$(RM) $(TOP_DIR)/config.cache
	$(RM) $(TOP_DIR)/config.status
	$(RM) $(TOP_DIR)/config.log

#
# This installs the executables and sample configurations
#
install:
	$(MAKE) $(DEP_BASE)/platform.dep
	$(MAKE) $(patsubst %,$(EXE_BASE)/%$(EXE_SUFF),$(ALL_EXES))
	$(MAKE) $(addprefix install-exe-$(EXE_BASE)/,$(ALL_EXES))
	$(MAKE) $(addprefix install-cfg-$(TOP_DIR)/,$(ALL_EXES))
	if test ! -d /var/log/bgpsdn ; then mkdir /var/log/bgpsdn ; fi

#
# Makes all for directories
#
$(addprefix all-,$(ALL_TGTD)):
	@if test ! -f $(patsubst all-%,$(TOP_DIR)/%/Makefile,$@) ; then $(ECHO_FORM) "\nMake aborted : Unable to find $(patsubst all-%,$(TOP_DIR)/%/Makefile,$@)\n" ; test ! -f Makefile ; fi
	$(MAKE) $(DEP_BASE)/platform.dep
	$(MAKE) -C $(TOP_DIR)/$(patsubst all-%,%,$@) all

#
# Makes clean for directories
#
$(addprefix clean-,$(ALL_TGTD)):
	@if test ! -f $(patsubst clean-%,$(TOP_DIR)/%/Makefile,$@) ; then $(ECHO_FORM) "\nMake aborted : Unable to find $(patsubst clean-%,$(TOP_DIR)/%/Makefile,$@)\n" ; test ! -f Makefile ; fi
	$(MAKE) -C $(TOP_DIR)/$(patsubst clean-%,%,$@) clean

#
# Makes dep for directories
#
$(addprefix dep-,$(ALL_TGTD)):
	@if test ! -f $(patsubst dep-%,$(TOP_DIR)/%/Makefile,$@) ; then $(ECHO_FORM) "\nMake aborted : Unable to find $(patsubst dep-%,$(TOP_DIR)/%/Makefile,$@)\n" ; test ! -f Makefile ; fi
	$(MAKE) $(DEP_BASE)/platform.dep
	$(MAKE) -C $(TOP_DIR)/$(patsubst dep-%,%,$@) dep

#
# Makes forcedep for directories
#
$(addprefix forcedep-,$(ALL_TGTD)):
	@if test ! -f $(patsubst forcedep-%,$(TOP_DIR)/%/Makefile,$@) ; then $(ECHO_FORM) "\nMake aborted : Unable to find $(patsubst forcedep-%,$(TOP_DIR)/%/Makefile,$@)\n" ; test ! -f Makefile ; fi
	$(MAKE) $(DEP_BASE)/platform.dep
	$(MAKE) -C $(TOP_DIR)/$(patsubst forcedep-%,%,$@) forcedep

#
# Makes the daemon executables
#
$(ALL_EXES):
	@if test ! -f $(patsubst %,$(TOP_DIR)/%/Makefile,$@) ; then $(ECHO_FORM) "\nMake aborted : Unable to find $(patsubst %,$(TOP_DIR)/%/Makefile,$@)\n" ; test ! -f Makefile ; fi
	$(MAKE) $(DEP_BASE)/platform.dep
	$(MAKE) $(EXE_BASE)/$@$(EXE_SUFF)

#------------------------------------------------------------------------------
#
# Implementation makes
#
# All of these involve long pathname work, but are used because they
# can shortcut steps in the make process which are not needed because
# things are already up to date.  However, since the pathnames are all
# absolute and are adjusted according to environment settings, these
# are intended only for internal use, and should not be invoked from
# the shell by the user.
#
# Most of these targets are real files, so some use others as dependencies.
#
# WARNING : Direct requests against these without having the dep files
# built first will probably not work.  This is why the user interface
# section above is done as it is.
#

#
# This makes the libraries; same way as 'all' works, but directly
#
$(patsubst %,$(OBJ_BASE)/%$(LIB_SUFF),$(ALL_TGTD)): $(DEP_BASE)/platform.dep
	@if test ! -f $(patsubst $(OBJ_BASE)%$(LIB_SUFF),$(TOP_DIR)%/Makefile,$@) ; then $(ECHO_FORM) "\nMake aborted : Unable to find $(patsubst $(OBJ_BASE)%$(LIB_SUFF),$(TOP_DIR)%/Makefile,$@)\n" ; test ! -f Makefile ; fi
	$(MAKE) -C $(patsubst $(OBJ_BASE)%$(LIB_SUFF),$(TOP_DIR)%,$@) all

#
# This builds IMI/IMISH/VTYSH
# 
$(patsubst %,$(EXE_BASE)/%$(EXE_SUFF),$(ALL_EXEI)): $(DEP_BASE)/platform.dep
	@if test ! -f $(patsubst $(EXE_BASE)%$(EXE_SUFF),$(TOP_DIR)%/Makefile,$@) ; then $(ECHO_FORM) "\nMake aborted : Unable to find $(patsubst $(EXE_BASE)%$(EXE_SUFF),$(TOP_DIR)%/Makefile,$@)\n" ; test ! -f Makefile ; fi
	@if test ! -f $(patsubst $(EXE_BASE)%$(EXE_SUFF),$(BLD_BASE)%.c,$@) ; then $(ECHO_FORM) "\nMake aborted : Unable to find $(patsubst $(EXE_BASE)%$(EXE_SUFF),$(BLD_BASE)%.c,$@)\n" ; test ! -f Makefile ; fi
	$(MAKE_OUTPUT_FILE) -o $@ $(patsubst $(EXE_BASE)%$(EXE_SUFF),$(BLD_BASE)%.c,$@) -Wl,-\( $(patsubst $(EXE_BASE)%$(EXE_SUFF),$(OBJ_BASE)%$(LIB_SUFF),$@) $(EXTRA_LIBS) $(OBJ_BASE)/pal$(LIB_SUFF) $(OBJ_BASE)/lib$(LIB_SUFF) -Wl,-\) $(LDLIBS_FLAGS)


#
# This builds HSL
# 
$(patsubst %,$(EXE_BASE)/%$(EXE_SUFF),$(ALL_EXEHW)): $(DEP_BASE)/platform.dep
	@if test ! -f $(patsubst $(EXE_BASE)%$(EXE_SUFF),$(TOP_DIR)%/Makefile,$@) ; then $(ECHO_FORM) "\nMake aborted : Unable to find $(patsubst $(EXE_BASE)%$(EXE_SUFF),$(TOP_DIR)%/Makefile,$@)\n" ; test ! -f Makefile ; fi
	@if test ! -f $(patsubst $(EXE_BASE)%$(EXE_SUFF),$(BLD_BASE)%.c,$@) ; then $(ECHO_FORM) "\nMake aborted : Unable to find $(patsubst $(EXE_BASE)%$(EXE_SUFF),$(BLD_BASE)%.c,$@)\n" ; test ! -f Makefile ; fi
	$(MAKE_OUTPUT_FILE) -o $@ $(patsubst $(EXE_BASE)%$(EXE_SUFF),$(BLD_BASE)%.c,$@) -Wl,-\( $(patsubst $(EXE_BASE)%$(EXE_SUFF),$(OBJ_BASE)%$(LIB_SUFF),$@) $(HW_SDK_OBJS) $(HW_SDK_LIBS) $(EXTRA_LIBS) $(OBJ_BASE)/pal$(LIB_SUFF) $(OBJ_BASE)/lib$(LIB_SUFF) $(OBJ_BASE)/libhsl$(LIB_SUFF) $(HW_EXTRA_LIBS) -Wl,-\) $(LDLIBS_FLAGS)

#
# This builds executable files without implicit 'd'
# 
$(patsubst %,$(EXE_BASE)/%$(EXE_SUFF),$(ALL_EXEN)): $(DEP_BASE)/platform.dep
	@if test ! -f $(patsubst $(EXE_BASE)%$(EXE_SUFF),$(TOP_DIR)%/Makefile,$@) ; then $(ECHO_FORM) "\nMake aborted : Unable to find $(patsubst $(EXE_BASE)%$(EXE_SUFF),$(TOP_DIR)%/Makefile,$@)\n" ; test ! -f Makefile ; fi
	@if test ! -f $(patsubst $(EXE_BASE)%$(EXE_SUFF),$(BLD_BASE)%.c,$@) ; then $(ECHO_FORM) "\nMake aborted : Unable to find $(patsubst $(EXE_BASE)%$(EXE_SUFF),$(BLD_BASE)%.c,$@)\n" ; test ! -f Makefile ; fi
	$(MAKE_OUTPUT_FILE) -o $@ $(patsubst $(EXE_BASE)%$(EXE_SUFF),$(BLD_BASE)%.c,$@) -Wl,-\( $(patsubst $(EXE_BASE)%$(EXE_SUFF),$(OBJ_BASE)%$(LIB_SUFF),$@) $(EXTRA_LIBS) $(OBJ_BASE)/pal$(LIB_SUFF) $(OBJ_BASE)/lib$(LIB_SUFF) -Wl,-\) $(LDLIBS_FLAGS) $(EFENCE_LIB)

#
# This builds executable files with implicit 'd'
#
$(patsubst %,$(EXE_BASE)/%d$(EXE_SUFF),$(ALL_EXED)): $(DEP_BASE)/platform.dep
	@if test ! -f $(patsubst $(EXE_BASE)%$(EXE_SUFF),$(TOP_DIR)%/Makefile,$@) ; then $(ECHO_FORM) "\nMake aborted : Unable to find $(patsubst $(EXE_BASE)%$(EXE_SUFF),$(TOP_DIR)%/Makefile,$@)\n" ; test ! -f Makefile ; fi
	@if test ! -f $(patsubst $(EXE_BASE)%d$(EXE_SUFF),$(BLD_BASE)%.c,$@) ; then $(ECHO_FORM) "\nMake aborted : Unable to find $(patsubst $(EXE_BASE)%$(EXE_SUFF),$(BLD_BASE)%.c,$@)\n" ; test ! -f Makefile ; fi
	$(MAKE_OUTPUT_FILE) -o $@ $(patsubst $(EXE_BASE)%d$(EXE_SUFF),$(BLD_BASE)%.c,$@) -Wl,-\( $(patsubst $(EXE_BASE)%$(EXE_SUFF),$(OBJ_BASE)%$(LIB_SUFF),$@) $(EXTRA_LIBS) $(OBJ_BASE)/pal$(LIB_SUFF) $(OBJ_BASE)/lib$(LIB_SUFF) -Wl,-\) $(LDLIBS_FLAGS) $(EFENCE_LIB)

#
# Dependencies for the stuff built directly from this directory.
#
# This dependency file is purely synthetic and may include many files which
# really aren't needed, but the forced rebuild time is still minimised by
# the proper dependencies for each directory.
#
# We also say all this stuff in the file itself.  :-)
#
$(DEP_BASE)/platform.dep: $(BLD_BASE)/Rules.platform $(BLD_BASE)/Rules.options
	@if test ! -d $(DEP_BASE) ; then mkdir $(DEP_BASE) ; fi
	@if test -f $(DEP_BASE)/platform.dep ; then $(RM) $(DEP_BASE)/platform.dep ; fi
	@if test -f $(DEP_BASE)/platform.dep.x ; then $(RM) $(DEP_BASE)/platform.dep.x ; fi
	@echo "#" >> $(DEP_BASE)/platform.dep.x
	@echo "# WARNING : Synthetic dependencies file.  DO NOT EDIT." >> $(DEP_BASE)/platform.dep.x
	@echo "#" >> $(DEP_BASE)/platform.dep.x
	@echo "# This file is generated by the make process to be able to cross-reference" >> $(DEP_BASE)/platform.dep.x
	@echo "# dependencies and allow it to sense when it needs to rebuild libraries" >> $(DEP_BASE)/platform.dep.x
	@echo "# in order to have current input for the final output files." >> $(DEP_BASE)/platform.dep.x
	@echo "#" >> $(DEP_BASE)/platform.dep.x
	@echo "# Many of the dependencies in here are unneeded, but those will usually" >> $(DEP_BASE)/platform.dep.x
	@echo "# be resolved quickly when make transfers to the target directory and" >> $(DEP_BASE)/platform.dep.x
	@echo "# recombines the up-to-date files (recompiling any which are needed)." >> $(DEP_BASE)/platform.dep.x
	@echo "#" >> $(DEP_BASE)/platform.dep.x
	@echo " " >> $(DEP_BASE)/platform.dep.x
	if $(MAKE) $(patsubst %,plat-dep-lib-%,$(ALL_TGTD)) $(patsubst %,plat-dep-exe-%,$(ALL_EXES)) ; then $(MV) $(DEP_BASE)/platform.dep.x $(DEP_BASE)/platform.dep ; else $(RM) $(DEP_BASE)/platform.dep.x ; fi
	test -f $(DEP_BASE)/platform.dep

#
# Dependencies for the library targets(!)
#
# Provided so we detect change in a directory and do proper rebuild.
# Note this assumes only one level of subdirectories after top level dirs.
# Add line following pattern established here for more, but it will make the
# lines in the output very long (they are already quite long)...
#
$(addprefix plat-dep-lib-,$(ALL_TGTD)):
	@if test ! -f $(patsubst plat-dep-lib-%,$(TOP_DIR)/%/Makefile,$@) ; then $(ECHO_FORM) "\nMake aborted : Unable to find $(patsubst plat-dep-lib-%,$(TOP_DIR)/%/Makefile,$@)\n" ; test ! -f Makefile ; fi
	@echo "# Next line is top level dependencies for $(patsubst plat-dep-lib-%,%,$@) library target" >> $(DEP_BASE)/platform.dep.x
	@$(ECHO_NOCR) "$(patsubst plat-dep-lib-%,$(OBJ_BASE)/%$(LIB_SUFF),$@) :" >> $(DEP_BASE)/platform.dep.x
	@$(ECHO_NOCR) " $(wildcard $(patsubst plat-dep-lib-%,$(TOP_DIR)/%/*.[ch],$@))" >> $(DEP_BASE)/platform.dep.x
	@$(ECHO_NOCR) " $(wildcard $(patsubst plat-dep-lib-%,$(TOP_DIR)/%/*/*.[ch],$@))" >> $(DEP_BASE)/platform.dep.x
	@echo " " >> $(DEP_BASE)/platform.dep.x
	@echo " " >> $(DEP_BASE)/platform.dep.x

#
# Dependencies for VTYSH.
#
$(addprefix plat-dep-exe-,$(ALL_EXEI)):
	@if test ! -f $(patsubst plat-dep-exe-%,$(TOP_DIR)/%/Makefile,$@) ; then $(ECHO_FORM) "\nMake aborted : Unable to find $(patsubst plat-dep-exe-%,$(TOP_DIR)/%/Makefile,$@)\n" ; test ! -f Makefile ; fi
	@if test ! -f $(patsubst plat-dep-exe-%,$(BLD_BASE)/%.c,$@) ; then $(ECHO_FORM) "\nMake aborted : Unable to find $(patsubst plat-dep-exe-%,$(BLD_BASE)/%.c,$@)\n" ; test ! -f Makefile ; fi
	@echo "# Next line is library dependencies for $(patsubst plat-dep-exe-%,%,$@) executable target" >> $(DEP_BASE)/platform.dep.x
	@$(ECHO_NOCR) "$(patsubst plat-dep-exe-%,$(EXE_BASE)/%$(EXE_SUFF),$@):" >> $(DEP_BASE)/platform.dep.x
	@$(ECHO_NOCR) " $(patsubst plat-dep-exe-%,$(OBJ_BASE)/%$(LIB_SUFF),$@)" >> $(DEP_BASE)/platform.dep.x
	@$(ECHO_NOCR) " $(OBJ_BASE)/lib$(LIB_SUFF) $(OBJ_BASE)/pal$(LIB_SUFF) $(EXTRA_LIBS) " >> $(DEP_BASE)/platform.dep.x
	if ! $(MAKE_SINGLE_DEPS) -I$(patsubst plat-dep-exe-%,$(TOP_DIR)/%,$@) $(patsubst plat-dep-exe-%,$(BLD_BASE)/%.c,$@) > $(DEP_BASE)/platform.dep.y ; then $(RM) $(DEP_BASE)/platform.dep.y ; test -f $(DEP_BASE)/platform.dep.y ; fi
	( read line ; set $$line ; shift ; echo $$*) < $(DEP_BASE)/platform.dep.y >> $(DEP_BASE)/platform.dep.x
	@$(RM) $(DEP_BASE)/platform.dep.y
	@echo " " >> $(DEP_BASE)/platform.dep.x

#
# Dependencies for the executable targets without implicit 'd'
#
$(addprefix plat-dep-exe-,$(ALL_EXEN)):
	@if test ! -f $(patsubst plat-dep-exe-%,$(TOP_DIR)/%/Makefile,$@) ; then $(ECHO_FORM) "\nMake aborted : Unable to find $(patsubst plat-dep-exe-%,$(TOP_DIR)/%/Makefile,$@)\n" ; test ! -f Makefile ; fi
	@if test ! -f $(patsubst plat-dep-exe-%,$(BLD_BASE)/%.c,$@) ; then $(ECHO_FORM) "\nMake aborted : Unable to find $(patsubst plat-dep-exe-%,$(BLD_BASE)/%.c,$@)\n" ; test ! -f Makefile ; fi
	@echo "# Next line is library dependencies for $(patsubst plat-dep-exe-%,%,$@) executable target" >> $(DEP_BASE)/platform.dep.x
	@$(ECHO_NOCR) "$(patsubst plat-dep-exe-%,$(EXE_BASE)/%$(EXE_SUFF),$@):" >> $(DEP_BASE)/platform.dep.x
	@$(ECHO_NOCR) " $(patsubst plat-dep-exe-%,$(OBJ_BASE)/%$(LIB_SUFF),$@)" >> $(DEP_BASE)/platform.dep.x
	@$(ECHO_NOCR) " $(OBJ_BASE)/lib$(LIB_SUFF) $(OBJ_BASE)/pal$(LIB_SUFF) $(EXTRA_LIBS) " >> $(DEP_BASE)/platform.dep.x
	if ! $(MAKE_SINGLE_DEPS) -I$(patsubst plat-dep-exe-%,$(TOP_DIR)/%,$@) $(patsubst plat-dep-exe-%,$(BLD_BASE)/%.c,$@) > $(DEP_BASE)/platform.dep.y ; then $(RM) $(DEP_BASE)/platform.dep.y ; test -f $(DEP_BASE)/platform.dep.y ; fi
	( read line ; set $$line ; shift ; echo $$*) < $(DEP_BASE)/platform.dep.y >> $(DEP_BASE)/platform.dep.x
	@$(RM) $(DEP_BASE)/platform.dep.y
	@echo " " >> $(DEP_BASE)/platform.dep.x

#
# Dependencies for the executable targets with implicit 'd'
#
$(patsubst %,plat-dep-exe-%d,$(ALL_EXED)):
	@if test ! -f $(patsubst plat-dep-exe-%,$(TOP_DIR)/%/Makefile,$@) ; then $(ECHO_FORM) "\nMake aborted : Unable to find $(patsubst plat-dep-exe-%,$(TOP_DIR)/%/Makefile,$@)\n" ; test ! -f Makefile ; fi
	@if test ! -f $(patsubst plat-dep-exe-%d,$(BLD_BASE)/%.c,$@) ; then $(ECHO_FORM) "\nMake aborted : Unable to find $(patsubst plat-dep-exe-%d,$(BLD_BASE)/%.c,$@)\n" ; test ! -f Makefile ; fi
	@echo "# Next line is library dependencies for $(patsubst plat-dep-exe-%,%,$@) executable target" >> $(DEP_BASE)/platform.dep.x
	@$(ECHO_NOCR) "$(patsubst plat-dep-exe-%,$(EXE_BASE)/%$(EXE_SUFF),$@):" >> $(DEP_BASE)/platform.dep.x
	@$(ECHO_NOCR) " $(patsubst plat-dep-exe-%,$(OBJ_BASE)/%$(LIB_SUFF),$@)" >> $(DEP_BASE)/platform.dep.x
	@$(ECHO_NOCR) " $(OBJ_BASE)/lib$(LIB_SUFF) $(OBJ_BASE)/pal$(LIB_SUFF) $(EXTRA_LIBS) " >> $(DEP_BASE)/platform.dep.x
	if ! $(MAKE_SINGLE_DEPS) -I$(patsubst plat-dep-exe-%,$(TOP_DIR)/%,$@) $(patsubst plat-dep-exe-%d,$(BLD_BASE)/%.c,$@) > $(DEP_BASE)/platform.dep.y ; then $(RM) $(DEP_BASE)/platform.dep.y ; test -f $(DEP_BASE)/platform.dep.y ; fi
	( read line ; set $$line ; shift ; echo $$*) < $(DEP_BASE)/platform.dep.y >> $(DEP_BASE)/platform.dep.x
	@$(RM) $(DEP_BASE)/platform.dep.y
	@echo " " >> $(DEP_BASE)/platform.dep.x

#
# Dependencies for directories
#
$(patsubst %,$(DEP_BASE)/%.dep,$(ALL_TGTD)): $(BLD_BASE)/Rules.platform $(BLD_BASE)/Rules.options
	@if test ! -f $(patsubst $(DEP_BASE)%.dep,$(TOP_DIR)%/Makefile,$@) ; then $(ECHO_FORM) "\nMake aborted : Unable to find $(patsubst $(DEP_BASE)%.dep,$(TOP_DIR)%/Makefile,$@)\n" ; test ! -f Makefile ; fi
	$(MAKE) -C $(patsubst $(DEP_BASE)%.dep,$(TOP_DIR)%,$@) dep

#
# Do the installations of the executables
#
$(addprefix install-exe-$(EXE_BASE)/,$(ALL_EXES)):
	@if test ! -f $(patsubst install-exe-%,%,$@) ; then $(ECHO_FORM) "\nMake aborted : Unable to find $(patsubst install-exe-%,%,$@)\n" ; test ! -f Makefile ; fi
	@if test ! -d $(PREFIX) ; then mkdir $(PREFIX) ; if test ! -d $(PREFIX) ; then $(ECHO_FORM) "\nMake aborted : unable to access or create $(PREFIX)\n" ; test -d $(PREFIX) ; fi ; fi
	@if test ! -d $(INS_EXES) ; then mkdir $(INS_EXES) ; if test ! -d $(INS_EXES) ; then $(ECHO_FORM) "\nMake aborted : unable to access $(PREFIX)\n               or to make dir $(INS_EXES)\n" ; test -d $(INS_EXES) ; fi ; fi
	$(INS_ECMD) $(patsubst install-exe-%,%,$@) $(patsubst install-exe-$(EXE_BASE)%,$(INS_EXES)%,$@)

#
# Do the installation of the sample configurations
#
$(addprefix install-cfg-$(TOP_DIR)/,$(ALL_EXES)):
	@if test -f $(patsubst install-cfg-%,%,$@)/$(patsubst install-cfg-$(TOP_DIR)/%,%.conf.sample,$@) ; then if test ! -d $(PREFIX) ; then mkdir $(PREFIX) ; if test ! -d $(PREFIX) ; then $(ECHO_FORM) "\nMake aborted : unable to access or create $(PREFIX)\n"; test -d $(PREFIX) ; fi ; fi ; if test ! -d $(INS_CONF) ; then mkdir $(INS_CONF) ; if test ! -d $(INS_CONF) ; then $(ECHO_FORM) "|nMake aborted : unable to access $(PREFIX) or to make dir $(INS_CONF)\n" ; test -d $(INS_CONF) ; fi ; fi ; $(INS_CCMD) $(patsubst install-cfg-%,%,$@)/$(patsubst install-cfg-$(TOP_DIR)/%,%.conf.sample,$@) $(patsubst install-cfg-$(TOP_DIR)%,$(INS_CONF)%,$@).conf.sample ; fi


#
# Include the dependency file so we are sure about the sources.
# This strange trick only works because all (reasonable) user interface
# makes require this file be made, then it's here when we recurse down 
# and actually start to do stuff.
#
ifneq ($(wildcard $(DEP_BASE)/platform.dep),$(empty))
include $(wildcard $(DEP_BASE)/platform.dep)
endif

#
# This keeps make from stupidly assuming things we don't want assumed
#
$(patsubst %.c,%.a,$(wildcard *.c)) \
$(patsubst %.c,%.o,$(wildcard *.c)) \
$(patsubst %d,%,$(ALL_EXED))$(EXE_SUFF):
	@echo " "
	@echo "Unable to make $@.  Please run make without argument for help."
	@echo " "
	@test ! -f Makefile

