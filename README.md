# Freebsd-Rootkit
The rootkit works on any recent versions of FreeBSD. At the system level, the rootkit is a kernel module. It works by hooking functions, replacing syscalls and dynamically patching kernel structures

## Functionalities
- Persistence: the rootkit is launched at every reboot of the system
- Keylogger: all the keyboard entries are stored in a hidden file
- The rootkit launch a remote shell. The output of the shell is extracted over ICMP. The extraction is slow - but very difficult to detect. The only seen traffic is constituted of ping
- The associated module and process are hidden for any program in userspace.
- The files that the rootkit use are hidden. No program in userspace can see them.
 -All the accessed files have their metadata (time of access, time of modification...) unmodified.

## Test
To launch the rootkit execute ./install.sh