obj-m := mac80211_hwsim.o
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install
	depmod -A
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

