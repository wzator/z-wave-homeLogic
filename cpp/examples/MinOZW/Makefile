#
# Makefile for OpenzWave Mac OS X applications
# Greg Satz

# GNU make only

# requires libudev-dev

.SUFFIXES:	.d .cpp .o .a
.PHONY:	default clean


DEBUG_CFLAGS    := -Wall -Wno-format -g -DDEBUG
RELEASE_CFLAGS  := -Wall -Wno-unknown-pragmas -Wno-format -O3

DEBUG_LDFLAGS	:= -g

# Change for DEBUG or RELEASE
CFLAGS	:= -c $(DEBUG_CFLAGS)
LDFLAGS	:= $(DEBUG_LDFLAGS)


top_srcdir := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))../../../)


INCLUDES	:= -I $(top_srcdir)/cpp/src -I $(top_srcdir)/cpp/src/command_classes/ -I $(top_srcdir)/cpp/src/value_classes/ \
	-I $(top_srcdir)/cpp/src/platform/ -I $(top_srcdir)/cpp/src/platform/unix -I $(top_srcdir)/cpp/tinyxml/ -I $(top_srcdir)/cpp/hidapi/hidapi/ \
	-I /usr/include/mysql -I /usr/local/include -I /usr/include/gammu -I /usr/include/json-c

LIBS =  $(wildcard $(LIBDIR)/*.so $(top_builddir)/*.so $(top_builddir)/cpp/build/*.so )
LIBSDIR = $(abspath $(dir $(firstword $(LIBS))))
minozwsrc := $(notdir $(wildcard $(top_srcdir)/cpp/examples/MinOZW/*.cpp))
VPATH := $(top_srcdir)/cpp/examples/MinOZW

top_builddir ?= $(CURDIR)

default: $(top_builddir)/MinOZW
	
include $(top_srcdir)/cpp/build/support.mk

-include $(patsubst %.cpp,$(DEPDIR)/%.d,$(minozwsrc))

#if we are on a Mac, add these flags and libs to the compile and link phases 
ifeq ($(UNAME),Darwin)
CFLAGS += -DDARWIN
endif

$(OBJDIR)/MinOZW:	$(patsubst %.cpp,$(OBJDIR)/%.o,$(minozwsrc))
	@echo "Linking $(OBJDIR)/MinOZW"
	$(LD) $(LDFLAGS) -o $@ $< $(LIBS) -pthread -ludev -L/usr/lib/mysql -lmysqlclient -L/usr/local/lib -lgadu -lGammu -lstdc++ -lssh -lrt -g -ljson-c -lpaho-mqtt3c -L/usr/local/lib/ -ltelebot -L /srv/_ZWAVE/curl_install/lib/ -lcurl 

$(top_builddir)/MinOZW: $(top_srcdir)/cpp/examples/MinOZW/MinOZW.in $(OBJDIR)/MinOZW
	@echo "Creating Temporary Shell Launch Script"
	@$(SED) \
		-e 's|[@]LDPATH@|$(LIBSDIR)|g' \
		< "$<" > "$@"
	@chmod +x $(top_builddir)/MinOZW

clean:
	@rm -rf $(DEPDIR) $(OBJDIR) $(top_builddir)/MinOZW

ifeq ($(XMLLINT),)
xmltest:	$(XMLLINT)
	$(error xmllint command not found.)
else
xmltest:	$(XMLLINT)
	@$(XMLLINT) --noout --schema ../../../config/zwcfg.xsd zwcfg_*.xml
	@$(XMLLINT) --noout --schema ../../../config/zwscene.xsd zwscene.xml
endif

install: $(OBJDIR)/MinOZW
	@echo "Installing into Prefix: $(PREFIX)"
	@install -d $(DESTDIR)/$(PREFIX)/bin/
	@cp $(OBJDIR)/MinOZW $(DESTDIR)/$(PREFIX)/bin/MinOZW
	@chmod 755 $(DESTDIR)/$(PREFIX)/bin/MinOZW
