# Freebsd-Rootkit
The rootkit works on any recent versions of FreeBSD. At the system level it is a kernel module. It works by hooking functions, replacing syscalls and dynamically patching kernel structures.

## Functionalities

- The Rootkit catch all the keyboard entries
- It launch a remote shell receiving commands embedded in ICMP request to evade firewalls
- The module, processes and files are hidden by patching the associated system calls and kernel data-structures at boot time.
- The files accessed have their metadata (time of access, time of modification...) unmodified.
- The Rootkit is launched at every reboot of the system.

## Test
To launch the rootkit execute ./install.sh
