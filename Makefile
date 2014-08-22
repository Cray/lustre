# User variables

# Flavors to build
ALL_FLAVORS		?= cray_gem_s cray_gem_c cray_gem_s-cos cray_ari_s cray_ari_c cray_ari_s-cos cray_ari_m cray_lnet_gem_s cray_lnet_ari_s cray_lnet_gem_c cray_lnet_ari_c cray_ari_s-rhine cray_lnet_ari_s-rhine cray_ari_c-rhine
DEFAULT_FLAVORS         ?= $(filter cray_ari_c cray_ari_s-cos,$(ALL_FLAVORS))
DEFAULT_SLE		?= SLE_11_SP3
DEFAULT_CENT		?= CENTOS_6_4

# Set non default flavors to build based on any command line arguments
ifneq (,$(MAKECMDGOALS))
   $(warning "found command line args: $(MAKECMDGOALS)")
   FLAVOR_GOALS		:= $(foreach flavor, $(filter-out $(DEFAULT_FLAVORS),$(ALL_FLAVORS)), $(findstring $(flavor), $(MAKECMDGOALS)))
   FLAVOR_GOALS		:= $(strip $(FLAVOR_GOALS))
   ifneq (,$(FLAVOR_GOALS))
       $(warning "setting DEFAULT_FLAVORS := $(FLAVOR_GOALS)")
       DEFAULT_FLAVORS	:= $(FLAVOR_GOALS)
   endif
endif

# Now use FLAVORS to set up other variables
FLAVORS                 ?= $(DEFAULT_FLAVORS)
LINUX_FLAVORS		:= $(FLAVORS)
RPM_FLAVORS		:= $(filter-out bw,$(FLAVORS))

GEM_S_RPM_SPEC          ?= cray-lustre-gem_s.spec
GEM_S_COS_RPM_SPEC      ?= cray-lustre-gem_s-cos.spec
GEM_C_RPM_SPEC          ?= cray-lustre-gem_c.spec
ARI_S_RPM_SPEC          ?= cray-lustre-ari_s.spec
ARI_S_RHINE_RPM_SPEC    ?= cray-lustre-ari_s-rhine.spec
ARI_S_COS_RPM_SPEC      ?= cray-lustre-ari_s-cos.spec
ARI_S_SIM_RPM_SPEC      ?= cray-lustre-ari_s-sim.spec
ARI_C_RPM_SPEC          ?= cray-lustre-ari_c.spec
ARI_C_RHINE_RPM_SPEC    ?= cray-lustre-ari_c-rhine.spec
ARI_M_RPM_SPEC          ?= cray-lustre-ari_m.spec
LNET_DEVEL_SPEC         ?= cray-lnet-devel.spec
LNET_ARI_S_SPEC         ?= cray-lustre-lnet-ari_s.spec
LNET_ARI_S_RHINE_SPEC   ?= cray-lustre-lnet-ari_s-rhine.spec
LNET_GEM_S_SPEC         ?= cray-lustre-lnet-gem_s.spec
LNET_ARI_C_SPEC         ?= cray-lustre-lnet-ari_c.spec
LNET_GEM_C_SPEC         ?= cray-lustre-lnet-gem_c.spec

# variables for builds
LUS_BRANCH              ?= Cray-master
LUS_RHINE_BRANCH        ?= Cray-master-rhine
RPMDIR                  ?= $(PWD)/rpms_$(DEFAULT_SLE)
OBS_DIRS                := $(RPMDIR)
export OSC_BUILD_ROOT

# 
# by default we'll pull NIGHTLY for compute builds from the latest on css here:
# /cray/css/release/cray/build/xt/sles11sp2/x86_64/trunk-ari/working/latest/rpms/x86_64 
# we'll pull CENT_NIGHTLY for cos builds from the latest on css here:
# /cray/css/release/cray/build/xt/centos/6.4/x86_64/trunk-ari/working/latest/rpms/x86_64
# Note, we don't use multiple nightlies as we do for SLES
#
ifneq (,$(NIGHTLY2))
    OBS_BUILD_EXTRA     += -p $(NIGHTLY2)
endif
ifneq (,$(NIGHTLY1))
    OBS_BUILD_EXTRA     += -p $(NIGHTLY1)
endif
ifneq (,$(NIGHTLY))
    OBS_BUILD_EXTRA     += -p $(NIGHTLY)
endif
ifneq (,$(CENT_NIGHTLY))
    CENT_OBS_BUILD_EXTRA += -p $(CENT_NIGHTLY)
endif

# always create a directory to save RPMS
CENT_OBS_BUILD_EXTRA	+= --ccache -k $(RPMDIR)
OBS_BUILD_EXTRA		+= --ccache -k $(RPMDIR)

ifneq (,$(RELEASE_EXTRA))
    DOWNSTREAM_ENV      += "RELEASE_EXTRA=$(RELEASE_EXTRA)"
endif

.PHONY: $(LUSTRE_CONF_FILES)
.PHONY: RPM rpms cray_gem_s-rpms cray_gem_s-cos-rpms cray_gem_s-sim-rpms cray_gem_c-rpms devel-rpms cray_ari_s-rpms cray_ari_s-cos-rpms cray_ari_s-sim-rpms cray_ari_c-rpms
.PHONY: cray_lnet_ari_c-rpms cray_lnet_ari_s-rpms cray_lnet_gem_c-rpms cray_lnet_gem_s-rpms
.PHONY: cray_ari_s-rhine-rpms cray_lnet_ari_s-rhine-rpms cray_ari_c-rhine-rpms
.PHONY: $(FLAVORS)

# Generic targets
all: rpms

test: 
	@echo "PATH: $(PATH)"
	@echo "FLAVORS: $(FLAVORS)"
	@echo "DEFAULT_FLAVORS: $(DEFAULT_FLAVORS)"
	@echo "RPM_FLAVORS: $(RPM_FLAVORS)"
	@echo "LINUX_FLAVORS: $(LINUX_FLAVORS)"
	@echo "WITH: $(WITH_SS) $(WITH_GNI_S) $(WITH_GNI_S_SST)"

## RPM Targets

$(OBS_DIRS): 
	mkdir -vp $(OBS_DIRS)

obs_variables: $(OBS_DIRS)
ifeq ($(RPMDIR),)
	@echo "Cannot build rpms without RPMDIR environment variable set" 
	@/bin/false 
endif

RPM: rpms
rpms: devel-rpms $(addsuffix -rpms, $(RPM_FLAVORS))

# $< is the first pre-req, or the spec name here

devel-rpms: $(LNET_DEVEL_SPEC) obs_variables 
	obs build $(OBS_BUILD_EXTRA) --repo $(DEFAULT_SLE) cray-lustre:$(LUS_BRANCH) cray-lustre $<

cray_gem_s-rpms: $(GEM_S_RPM_SPEC) obs_variables 
	obs build $(OBS_BUILD_EXTRA) --repo $(DEFAULT_SLE) cray-lustre:$(LUS_BRANCH) cray-lustre $<

cray_gem_s-cos-rpms: $(GEM_S_COS_RPM_SPEC) obs_variables
	obs build $(CENT_OBS_BUILD_EXTRA) --repo $(DEFAULT_CENT) cray-lustre:$(LUS_BRANCH) cray-lustre $<

cray_ari_s-rpms: $(ARI_S_RPM_SPEC) obs_variables 
	obs build $(OBS_BUILD_EXTRA) --repo $(DEFAULT_SLE) cray-lustre:$(LUS_BRANCH) cray-lustre $<

cray_ari_s-rhine-rpms: $(ARI_S_RHINE_RPM_SPEC) obs_variables 
	obs build $(OBS_BUILD_EXTRA) --repo $(DEFAULT_SLE) cray-lustre:$(LUS_RHINE_BRANCH) cray-lustre $<

cray_ari_s-cos-rpms: $(ARI_S_COS_RPM_SPEC) obs_variables 
	obs build $(CENT_OBS_BUILD_EXTRA) --repo $(DEFAULT_CENT) cray-lustre:$(LUS_BRANCH) cray-lustre $<

cray_ari_s-sim-rpms: $(ARI_S_SIM_RPM_SPEC) obs_variables 
	obs build $(OBS_BUILD_EXTRA) --repo $(DEFAULT_SLE) cray-lustre:$(LUS_BRANCH) cray-lustre $<

cray_gem_c-rpms: $(GEM_C_RPM_SPEC) obs_variables 
	obs build $(OBS_BUILD_EXTRA) --repo $(DEFAULT_SLE) cray-lustre:$(LUS_BRANCH) cray-lustre $<

cray_ari_c-rpms: $(ARI_C_RPM_SPEC) obs_variables 
	obs build $(OBS_BUILD_EXTRA) --repo $(DEFAULT_SLE) cray-lustre:$(LUS_BRANCH) cray-lustre $<

cray_ari_c-rhine-rpms: $(ARI_C_RHINE_RPM_SPEC) obs_variables 
	obs build $(OBS_BUILD_EXTRA) --repo $(DEFAULT_SLE) cray-lustre:$(LUS_RHINE_BRANCH) cray-lustre $<

cray_ari_m-rpms: $(ARI_M_RPM_SPEC) obs_variables 
	obs build cray-lustre:$(LUS_BRANCH) cray-lustre $<

cray_lnet_ari_s-rpms: $(LNET_ARI_S_SPEC) obs_variables 
	obs build $(OBS_BUILD_EXTRA) --repo $(DEFAULT_SLE) cray-lustre:$(LUS_BRANCH) cray-lustre $<

cray_lnet_ari_s-rhine-rpms: $(LNET_ARI_S_RHINE_SPEC) obs_variables 
	obs build $(OBS_BUILD_EXTRA) --repo $(DEFAULT_SLE) cray-lustre:$(LUS_RHINE_BRANCH) cray-lustre $<

cray_lnet_gem_s-rpms: $(LNET_GEM_S_SPEC) obs_variables 
	obs build $(OBS_BUILD_EXTRA) --repo $(DEFAULT_SLE) cray-lustre:$(LUS_BRANCH) cray-lustre $<

cray_lnet_ari_c-rpms: $(LNET_ARI_C_SPEC) obs_variables 
	obs build $(OBS_BUILD_EXTRA) --repo $(DEFAULT_SLE) cray-lustre:$(LUS_BRANCH) cray-lustre $<

cray_lnet_gem_c-rpms: $(LNET_GEM_C_SPEC) obs_variables 
	obs build $(OBS_BUILD_EXTRA) --repo $(DEFAULT_SLE) cray-lustre:$(LUS_BRANCH) cray-lustre $<

## required header targets
headers:

## Clean targets
clean: 

distclean clobber:
FORCE:
