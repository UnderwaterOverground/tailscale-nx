#---------------------------------------------------------------------------------
# tailscale-nx sysmodule (Atmosphère libstratosphere 1.12.0).
# Built by the top-level `make sysmodule` inside the tsnx-build Docker image.
#---------------------------------------------------------------------------------
SYSMODULE_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
ATMOSPHERE_LIBS := $(SYSMODULE_DIR)/../../third_party/Atmosphere/libraries
include $(ATMOSPHERE_LIBS)/config/templates/stratosphere.mk

TARGET		:=	tailscale-nx
BUILD		:=	build
SOURCES		:=	source ../../native/driver ../../native/runtime ../../native/vsock
DATA		:=	data
INCLUDES	:=	source ../../native/driver ../../native/runtime ../../native/vsock ../../native/ctl ../../crates/tsnx-ffi/include
TITLE_ID	:=	4200000000005453

TSNX_BUILD_UNIX ?= $(shell date +%s)
RUST_LIB_DIR	?=	$(abspath $(SYSMODULE_DIR)/../../target/switch/aarch64-nintendo-switch-freestanding/release)
# No newlib stdio/printf: state files go through ams::fs, and the shared C
# code's snprintf is routed to libstratosphere's formatter (see
# tsnx_snprintf in main.cpp and tsnx_driver.h).
CFLAGS		+=	-DTSNX_BUILD_UNIX=$(TSNX_BUILD_UNIX) -Wno-error=sign-compare -DTSNX_NO_STDIO
CXXFLAGS	+=	-DTSNX_BUILD_UNIX=$(TSNX_BUILD_UNIX) -DTSNX_NO_STDIO
LIBS		:=	-ltsnx_ffi $(LIBS)

ifneq ($(BUILD),$(notdir $(CURDIR)))

export OUTPUT	:=	$(CURDIR)/$(TARGET)
export TOPDIR	:=	$(CURDIR)
export VPATH	:=	$(foreach dir,$(SOURCES),$(CURDIR)/$(dir))
export DEPSDIR	:=	$(CURDIR)/$(BUILD)

CFILES		:=	$(foreach dir,$(SOURCES),$(notdir $(wildcard $(dir)/*.c)))
CPPFILES	:=	$(foreach dir,$(SOURCES),$(notdir $(wildcard $(dir)/*.cpp)))
export LD	:=	$(CXX)
export OFILES	:=	$(CPPFILES:.cpp=.o) $(CFILES:.c=.o)
export INCLUDE	:=	$(foreach dir,$(INCLUDES),-I$(CURDIR)/$(dir)) \
			$(foreach dir,$(LIBDIRS),-I$(dir)/include) \
			$(foreach dir,$(AMS_LIBDIRS),-I$(dir)/include) \
			-I$(CURDIR)/$(BUILD)
export LIBPATHS	:=	$(foreach dir,$(LIBDIRS),-L$(dir)/lib) \
			$(foreach dir,$(AMS_LIBDIRS),-L$(dir)/$(ATMOSPHERE_LIBRARY_DIR)) \
			-L$(RUST_LIB_DIR)
export APP_JSON	:=	$(TOPDIR)/res/app.json
export RUST_LIB_DIR

.PHONY: $(BUILD) clean all dist

all: $(BUILD)

$(BUILD):
	@[ -d $@ ] || mkdir -p $@
	@$(MAKE) --no-print-directory -C $(BUILD) -f $(CURDIR)/Makefile

# SD card layout: atmosphere/contents/<tid>/{exefs.nsp,toolbox.json,flags/boot2.flag}
dist: all
	@rm -rf dist && mkdir -p dist/atmosphere/contents/$(TITLE_ID)/flags
	@cp $(TARGET).nsp dist/atmosphere/contents/$(TITLE_ID)/exefs.nsp
	@cp res/toolbox.json dist/atmosphere/contents/$(TITLE_ID)/
	@touch dist/atmosphere/contents/$(TITLE_ID)/flags/boot2.flag
	@echo "staged dist/atmosphere/contents/$(TITLE_ID)"

clean:
	@rm -fr $(BUILD) dist $(TARGET).elf $(TARGET).nso $(TARGET).npdm $(TARGET).nsp $(TARGET).map

else

DEPENDS	:=	$(OFILES:.o=.d)

all	:	$(OUTPUT).nsp
$(OUTPUT).nsp	:	$(OUTPUT).nso $(OUTPUT).npdm
$(OUTPUT).nso	:	$(OUTPUT).elf
$(OUTPUT).elf	:	$(OFILES) $(RUST_LIB_DIR)/libtsnx_ffi.a
$(OFILES)	:	$(ATMOSPHERE_LIBRARIES_DIR)/libstratosphere/$(ATMOSPHERE_LIBRARY_DIR)/libstratosphere.a

%.npdm	:	$(APP_JSON)
	@npdmtool $< $@
	@echo built ... $(notdir $@)

-include $(DEPENDS)

endif
