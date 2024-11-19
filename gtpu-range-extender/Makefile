
CC_HOST ?= clang-18
CC_TARGET ?= aarch64-cortexa53-linux-gnu-gcc
OPT = -O3 -ggdb
BFLAGS = -Wall -Wextra -Waddress-of-packed-member -Wuninitialized -Wno-unused-function -fsanitize=address,undefined -Wmissing-prototypes -Werror=missing-prototypes -Werror=strict-prototypes -std=c99
CFILES := main.c nl.c netns.c gtpu.c pkt.c exithelper.c

.PHONY: all clean perms

all: clean tunsrv client server perms client_target #helper

tunsrv : $(CFILES)
	$(CC) $(OPT) $(BFLAGS) -o $@ $^
client : $(CFILES)
	$(CC) $(OPT) $(BFLAGS)  -DDO_B_C -o $@ $^
server : $(CFILES)
	$(CC) $(OPT) $(BFLAGS)  -DDO_B_S -o $@ $^

client_target : $(CFILES)
	$(CC_TARGET) $(OPT) $(BFLAGS) -DDO_B_C -o $@ $^


perms: tunsrv client server
	for f in $^; do sudo setcap "cap_net_admin,cap_net_raw,cap_sys_admin,cap_sys_ptrace+eip" $$f; done
# cp -a `which setcap` . && sudo chown root setcap && sudo chmod 4710 setcap
# sudo setcap "cap_net_admin,cap_net_raw,cap_sys_admin,cap_sys_ptrace+eip" $@
# find ~/.vscode-server -type f -executable -iname "lldb-server" | xargs -tn1 sudo setcap cap_net_admin,cap_net_raw,cap_sys_admin,cap_sys_ptrace+eip
# find ~/.vscode-server -type f -executable -iname "lldb*" | xargs -tn1 sudo setcap -r


clean :
	rm tunsrv || :
	rm client || :
	rm server || :
	rm client_target || :



