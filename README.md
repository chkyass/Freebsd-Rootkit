# Freebsd-Rootkit
The rootkit works on newer versions of freeBSD. At the system level, the rootkit is a kernel module. It works by hooking functions, replacing syscalls and dynamically patching kernel structures

## Functionalities
- Persitence: the rootkit is launched at every reboot of the system
- Keylogger: all the keyboard entries are stored in a hidden file
- The rootkit launch a remote shell. The output of the shell is extracted over icmp. The extraction is slow but very difficult to detect. The only seen trafic is constituted of ping
- The associated module and process are hidden for any programm in userspace.
- The files that the rootkit use are hidden. No programm in user space can see them.
- All the accessed files have their metadata (time of access, time of modification...) unmodified.

## Test
To launch the rootkit execute ./install.sh
