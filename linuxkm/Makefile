all: libwolfssl.ko

.PHONY: libwolfssl.ko

ifndef MODULE_TOP
MODULE_TOP=$(CURDIR)
endif

ifndef SRC_TOP
SRC_TOP=$(shell dirname $(MODULE_TOP))
endif

ifeq "$(KROOT)" ""
$(error $$KROOT is unset.)
endif

ifeq "$(AM_CFLAGS)$(CFLAGS)" ""
$(error $$AM_CFLAGS and $$CFLAGS are both unset.)
endif

ifeq "$(src_libwolfssl_la_OBJECTS)" ""
$(error $$src_libwolfssl_la_OBJECTS is unset.)
endif

WOLFSSL_CFLAGS=-DHAVE_CONFIG_H -I$(SRC_TOP) -DBUILDING_WOLFSSL $(AM_CFLAGS) $(CFLAGS) -Wframe-larger-than=65536 -mpreferred-stack-boundary=4
WOLFSSL_ASFLAGS=-DHAVE_CONFIG_H -I$(SRC_TOP) -DBUILDING_WOLFSSL $(AM_CCASFLAGS) $(CCASFLAGS)

WOLFSSL_OBJ_FILES=linuxkm/module_hooks.o $(patsubst %.lo, %.o, $(patsubst src/src_libwolfssl_la-%, src/%, $(patsubst src/libwolfssl_la-%, src/%, $(patsubst wolfcrypt/src/src_libwolfssl_la-%, wolfcrypt/src/%, $(src_libwolfssl_la_OBJECTS)))))

export WOLFSSL_CFLAGS WOLFSSL_ASFLAGS WOLFSSL_OBJ_FILES

libwolfssl.ko:
	@mkdir -p linuxkm src wolfcrypt/src
	@if [[ ! -h $(SRC_TOP)/Kbuild ]]; then ln -s $(MODULE_TOP)/Kbuild $(SRC_TOP)/Kbuild; fi
	make -C $(KROOT) M=$(MODULE_TOP) src=$(SRC_TOP)

.PHONY: clean

clean:
	@cd $(MODULE_TOP) && rm -f libwolfssl.ko Module.symvers built-in.a modules.order libwolfssl.mod libwolfssl.mod.c src/*.o wolfcrypt/src/*.o
