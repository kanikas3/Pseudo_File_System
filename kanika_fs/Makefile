MOD_NAME=kfs
obj-m += $(MOD_NAME).o

INSTALL_TARGET=user@192.168.53.89:~
KDIR=/home/user/Desktop/VM/linux-4.0.9

all:
	make -C $(KDIR) M=$(PWD) modules

# To avoid the password prompt each time you do make install, just
# install the host ssh key into the qemu VM by doing (on the host):
# ssh-keygen
# ssh-copy-id <ip address of the qemu vm>
install: all
	scp $(MOD_NAME).ko $(INSTALL_TARGET)

clean:
	make -C $(KDIR) M=$(PWD) clean

