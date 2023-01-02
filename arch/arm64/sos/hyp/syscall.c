// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2022 - experimental arm64 sos module
 * Author: Adam Toth <tothadamster@gmail.com>
 */

#include <asm/esr.h>
#include <asm/unistd.h>
#include "sos_sysreg.h"
#include "trap_handler.h"
#include "syscall.h"

typedef void (*hcall_t)(struct kvm_cpu_context *, sos_syscall_direction_t);

#define HANDLE_FUNC(x)	[__NR_##x]     = (hcall_t)handle_sys_##x
#define HANDLE_FUNC2(x)	[__NR3264_##x] = (hcall_t)handle_sys_##x

#define UNUSED_PAR(x) (void)x
#define HANDLE_FUNC_DEF(x) static void handle_sys_##x(struct kvm_cpu_context * cpu, sos_syscall_direction_t dir)

HANDLE_FUNC_DEF(io_setup) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(io_destroy) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(io_submit) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(io_cancel) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(io_getevents) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(setxattr) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(lsetxattr) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(fsetxattr) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(getxattr) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(lgetxattr) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(fgetxattr) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(listxattr) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(llistxattr) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(flistxattr) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(removexattr) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(lremovexattr) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(fremovexattr) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(getcwd) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(lookup_dcookie) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(eventfd2) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(epoll_create1) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(epoll_ctl) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(epoll_pwait) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(dup) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(dup3) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(fcntl) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(inotify_init1) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(inotify_add_watch) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(inotify_rm_watch) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(ioctl) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(ioprio_set) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(ioprio_get) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(flock) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(mknodat) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(mkdirat) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(unlinkat) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(symlinkat) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(linkat) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

#ifdef __ARCH_WANT_RENAMEAT
HANDLE_FUNC_DEF(renameat) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}
#endif /* __ARCH_WANT_RENAMEAT */

HANDLE_FUNC_DEF(umount2) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(mount) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(pivot_root) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(nfsservctl) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(statfs) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(fstatfs) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(truncate) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(ftruncate) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(fallocate) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(faccessat) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(chdir) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(fchdir) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(chroot) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(fchmod) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(fchmodat) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(fchownat) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(fchown) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(openat) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(vhangup) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(pipe2) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(quotactl) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(getdents64) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(lseek) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(read) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(write) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(readv) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(writev) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(pread64) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(pwrite64) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(preadv) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(pwritev) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(sendfile) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
HANDLE_FUNC_DEF(pselect6) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(ppoll) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}
#endif

HANDLE_FUNC_DEF(signalfd4) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(vmsplice) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(splice) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(tee) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(readlinkat) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}
#if defined(__ARCH_WANT_NEW_STAT) || defined(__ARCH_WANT_STAT64)
HANDLE_FUNC_DEF(fstatat) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(fstat) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}
#endif

HANDLE_FUNC_DEF(sync) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(fsync) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(fdatasync) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}


#ifdef __ARCH_WANT_SYNC_FILE_RANGE2
HANDLE_FUNC_DEF(sync_file_range2) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}


#else
HANDLE_FUNC_DEF(sync_file_range) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}


#endif
HANDLE_FUNC_DEF(timerfd_create) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}


#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
HANDLE_FUNC_DEF(timerfd_settime) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(timerfd_gettime) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}
#endif

#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
HANDLE_FUNC_DEF(utimensat) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}
#endif

HANDLE_FUNC_DEF(acct) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(capget) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(capset) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(personality) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(exit) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(exit_group) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(waitid) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(set_tid_address) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(unshare) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}


#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
HANDLE_FUNC_DEF(futex) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}


#endif
HANDLE_FUNC_DEF(set_robust_list) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(get_robust_list) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
HANDLE_FUNC_DEF(nanosleep) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}
#endif

HANDLE_FUNC_DEF(getitimer) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(setitimer) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(kexec_load) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(init_module) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(delete_module) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(timer_create) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}


#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
HANDLE_FUNC_DEF(timer_gettime) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}


#endif
HANDLE_FUNC_DEF(timer_getoverrun) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}


#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
HANDLE_FUNC_DEF(timer_settime) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}


#endif
HANDLE_FUNC_DEF(timer_delete) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}


#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
HANDLE_FUNC_DEF(clock_settime) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(clock_gettime) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(clock_getres) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(clock_nanosleep) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}


#endif
HANDLE_FUNC_DEF(syslog) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(ptrace) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(sched_setparam) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(sched_setscheduler) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(sched_getscheduler) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(sched_getparam) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(sched_setaffinity) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(sched_getaffinity) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(sched_yield) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(sched_get_priority_max) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(sched_get_priority_min) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(sched_rr_get_interval) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(restart_syscall) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(kill) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(tkill) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(tgkill) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(sigaltstack) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(rt_sigsuspend) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(rt_sigaction) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(rt_sigprocmask) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(rt_sigpending) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}


#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
HANDLE_FUNC_DEF(rt_sigtimedwait) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}
#endif

HANDLE_FUNC_DEF(rt_sigqueueinfo) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(rt_sigreturn) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(setpriority) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(getpriority) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(reboot) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(setregid) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(setgid) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(setreuid) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(setuid) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(setresuid) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(getresuid) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(setresgid) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(getresgid) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(setfsuid) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(setfsgid) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(times) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(setpgid) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(getpgid) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(getsid) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(setsid) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(getgroups) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(setgroups) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(uname) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(sethostname) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(setdomainname) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

#ifdef __ARCH_WANT_SET_GET_RLIMIT
HANDLE_FUNC_DEF(getrlimit) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(setrlimit) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}
#endif

HANDLE_FUNC_DEF(getrusage) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(umask) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(prctl) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(getcpu) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
HANDLE_FUNC_DEF(gettimeofday) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(settimeofday) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(adjtimex) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}
#endif

HANDLE_FUNC_DEF(getpid) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(getppid) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(getuid) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(geteuid) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(getgid) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(getegid) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(gettid) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(sysinfo) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(mq_open) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(mq_unlink) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
HANDLE_FUNC_DEF(mq_timedsend) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(mq_timedreceive) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}
#endif

HANDLE_FUNC_DEF(mq_notify) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(mq_getsetattr) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(msgget) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(msgctl) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(msgrcv) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(msgsnd) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(semget) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(semctl) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
HANDLE_FUNC_DEF(semtimedop) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}
#endif

HANDLE_FUNC_DEF(semop) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(shmget) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(shmctl) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(shmat) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(shmdt) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(socket) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(socketpair) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(bind) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(listen) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(accept) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(connect) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(getsockname) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(getpeername) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(sendto) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(recvfrom) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(setsockopt) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(getsockopt) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(shutdown) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(sendmsg) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(recvmsg) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(readahead) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(brk) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(munmap) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(mremap) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(add_key) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(request_key) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(keyctl) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(clone) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(execve) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(mmap) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(fadvise64) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

#ifndef __ARCH_NOMMU
HANDLE_FUNC_DEF(swapon) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(swapoff) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(mprotect) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(msync) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(mlock) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(munlock) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(mlockall) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(munlockall) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(mincore) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(madvise) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(remap_file_pages) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(mbind) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(get_mempolicy) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(set_mempolicy) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(migrate_pages) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(move_pages) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}
#endif

HANDLE_FUNC_DEF(rt_tgsigqueueinfo) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(perf_event_open) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(accept4) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
HANDLE_FUNC_DEF(recvmmsg) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}
#endif

HANDLE_FUNC_DEF(arch_specific_syscall) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
HANDLE_FUNC_DEF(wait4) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}
#endif

HANDLE_FUNC_DEF(prlimit64) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(fanotify_init) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(fanotify_mark) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(name_to_handle_at) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(open_by_handle_at) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
HANDLE_FUNC_DEF(clock_adjtime) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}
#endif

HANDLE_FUNC_DEF(syncfs) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(setns) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(sendmmsg) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(process_vm_readv) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(process_vm_writev) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(kcmp) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(finit_module) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(sched_setattr) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(sched_getattr) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(renameat2) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(seccomp) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(getrandom) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(memfd_create) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(bpf) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(execveat) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(userfaultfd) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(membarrier) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(mlock2) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(copy_file_range) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(preadv2) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(pwritev2) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(pkey_mprotect) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(pkey_alloc) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(pkey_free) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(statx) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
HANDLE_FUNC_DEF(io_pgetevents) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}
#endif

HANDLE_FUNC_DEF(rseq) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(kexec_file_load) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

#if __BITS_PER_LONG == 32
HANDLE_FUNC_DEF(clock_gettime64) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(clock_settime64) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(clock_adjtime64) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(clock_getres_time64) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(clock_nanosleep_time64) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(timer_gettime64) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(timer_settime64) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(timerfd_gettime64) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(timerfd_settime64) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(utimensat_time64) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(pselect6_time64) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(ppoll_time64) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(io_pgetevents_time64) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(recvmmsg_time64) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(mq_timedsend_time64) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(mq_timedreceive_time64) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(semtimedop_time64) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(rt_sigtimedwait_time64) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(futex_time64) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(sched_rr_get_interval_time64) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}
#endif

HANDLE_FUNC_DEF(pidfd_send_signal) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(io_uring_setup) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(io_uring_enter) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(io_uring_register) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(open_tree) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(move_mount) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(fsopen) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(fsconfig) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(fsmount) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(fspick) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(pidfd_open) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

#ifdef __ARCH_WANT_SYS_CLONE3
HANDLE_FUNC_DEF(clone3) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}
#endif

HANDLE_FUNC_DEF(close_range) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(openat2) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(pidfd_getfd) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(faccessat2) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(process_madvise) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(epoll_pwait2) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(mount_setattr) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(landlock_create_ruleset) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(landlock_add_rule) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

HANDLE_FUNC_DEF(landlock_restrict_self) {
	UNUSED_PAR(cpu);
	UNUSED_PAR(dir);
	return;
}

static const hcall_t syscall_dispatcher[] = {
	HANDLE_FUNC(io_setup),
	HANDLE_FUNC(io_destroy),
	HANDLE_FUNC(io_submit),
	HANDLE_FUNC(io_cancel),
	HANDLE_FUNC(io_getevents),
	HANDLE_FUNC(setxattr),
	HANDLE_FUNC(lsetxattr),
	HANDLE_FUNC(fsetxattr),
	HANDLE_FUNC(getxattr),
	HANDLE_FUNC(lgetxattr),
	HANDLE_FUNC(fgetxattr),
	HANDLE_FUNC(listxattr),
	HANDLE_FUNC(llistxattr),
	HANDLE_FUNC(flistxattr),
	HANDLE_FUNC(removexattr),
	HANDLE_FUNC(lremovexattr),
	HANDLE_FUNC(fremovexattr),
	HANDLE_FUNC(getcwd),
	HANDLE_FUNC(lookup_dcookie),
	HANDLE_FUNC(eventfd2),
	HANDLE_FUNC(epoll_create1),
	HANDLE_FUNC(epoll_ctl),
	HANDLE_FUNC(epoll_pwait),
	HANDLE_FUNC(dup),
	HANDLE_FUNC(dup3),
	HANDLE_FUNC2(fcntl),
	HANDLE_FUNC(inotify_init1),
	HANDLE_FUNC(inotify_add_watch),
	HANDLE_FUNC(inotify_rm_watch),
	HANDLE_FUNC(ioctl),
	HANDLE_FUNC(ioprio_set),
	HANDLE_FUNC(ioprio_get),
	HANDLE_FUNC(flock),
	HANDLE_FUNC(mknodat),
	HANDLE_FUNC(mkdirat),
	HANDLE_FUNC(unlinkat),
	HANDLE_FUNC(symlinkat),
	HANDLE_FUNC(linkat),
#ifdef __ARCH_WANT_RENAMEAT
	HANDLE_FUNC(renameat),
#endif /* __ARCH_WANT_RENAMEAT */
	HANDLE_FUNC(umount2),
	HANDLE_FUNC(mount),
	HANDLE_FUNC(pivot_root),
	HANDLE_FUNC(nfsservctl),
	HANDLE_FUNC2(statfs),
	HANDLE_FUNC2(fstatfs),
	HANDLE_FUNC2(truncate),
	HANDLE_FUNC2(ftruncate),
	HANDLE_FUNC(fallocate),
	HANDLE_FUNC(faccessat),
	HANDLE_FUNC(chdir),
	HANDLE_FUNC(fchdir),
	HANDLE_FUNC(chroot),
	HANDLE_FUNC(fchmod),
	HANDLE_FUNC(fchmodat),
	HANDLE_FUNC(fchownat),
	HANDLE_FUNC(fchown),
	HANDLE_FUNC(openat),
	HANDLE_FUNC(vhangup),
	HANDLE_FUNC(pipe2),
	HANDLE_FUNC(quotactl),
	HANDLE_FUNC(getdents64),
	HANDLE_FUNC2(lseek),
	HANDLE_FUNC(read),
	HANDLE_FUNC(write),
	HANDLE_FUNC(readv),
	HANDLE_FUNC(writev),
	HANDLE_FUNC(pread64),
	HANDLE_FUNC(pwrite64),
	HANDLE_FUNC(preadv),
	HANDLE_FUNC(pwritev),
	HANDLE_FUNC2(sendfile),
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
	HANDLE_FUNC(pselect6),
	HANDLE_FUNC(ppoll),
#endif
	HANDLE_FUNC(signalfd4),
	HANDLE_FUNC(vmsplice),
	HANDLE_FUNC(splice),
	HANDLE_FUNC(tee),
	HANDLE_FUNC(readlinkat),
#if defined(__ARCH_WANT_NEW_STAT) || defined(__ARCH_WANT_STAT64)
    HANDLE_FUNC2(fstatat),
    HANDLE_FUNC2(fstat),
#endif
	HANDLE_FUNC(sync),
	HANDLE_FUNC(fsync),
	HANDLE_FUNC(fdatasync),
#ifdef __ARCH_WANT_SYNC_FILE_RANGE2
	HANDLE_FUNC(sync_file_range2),
#else
	HANDLE_FUNC(sync_file_range),
#endif
	HANDLE_FUNC(timerfd_create),
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
	HANDLE_FUNC(timerfd_settime),
	HANDLE_FUNC(timerfd_gettime),
#endif
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
	HANDLE_FUNC(utimensat),
#endif
	HANDLE_FUNC(acct),
	HANDLE_FUNC(capget),
	HANDLE_FUNC(capset),
	HANDLE_FUNC(personality),
	HANDLE_FUNC(exit),
	HANDLE_FUNC(exit_group),
	HANDLE_FUNC(waitid),
	HANDLE_FUNC(set_tid_address),
	HANDLE_FUNC(unshare),
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
	HANDLE_FUNC(futex),
#endif
	HANDLE_FUNC(set_robust_list),
	HANDLE_FUNC(get_robust_list),
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
	HANDLE_FUNC(nanosleep),
#endif
	HANDLE_FUNC(getitimer),
	HANDLE_FUNC(setitimer),
	HANDLE_FUNC(kexec_load),
	HANDLE_FUNC(init_module),
	HANDLE_FUNC(delete_module),
	HANDLE_FUNC(timer_create),
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
	HANDLE_FUNC(timer_gettime),
#endif
	HANDLE_FUNC(timer_getoverrun),
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
	HANDLE_FUNC(timer_settime),
#endif
	HANDLE_FUNC(timer_delete),
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
	HANDLE_FUNC(clock_settime),
	HANDLE_FUNC(clock_gettime),
	HANDLE_FUNC(clock_getres),
	HANDLE_FUNC(clock_nanosleep),
#endif
	HANDLE_FUNC(syslog),
	HANDLE_FUNC(ptrace),
	HANDLE_FUNC(sched_setparam),
	HANDLE_FUNC(sched_setscheduler),
	HANDLE_FUNC(sched_getscheduler),
	HANDLE_FUNC(sched_getparam),
	HANDLE_FUNC(sched_setaffinity),
	HANDLE_FUNC(sched_getaffinity),
	HANDLE_FUNC(sched_yield),
	HANDLE_FUNC(sched_get_priority_max),
	HANDLE_FUNC(sched_get_priority_min),
	HANDLE_FUNC(sched_rr_get_interval),
	HANDLE_FUNC(restart_syscall),
	HANDLE_FUNC(kill),
	HANDLE_FUNC(tkill),
	HANDLE_FUNC(tgkill),
	HANDLE_FUNC(sigaltstack),
	HANDLE_FUNC(rt_sigsuspend),
	HANDLE_FUNC(rt_sigaction),
	HANDLE_FUNC(rt_sigprocmask),
	HANDLE_FUNC(rt_sigpending),
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
	HANDLE_FUNC(rt_sigtimedwait),
#endif
	HANDLE_FUNC(rt_sigqueueinfo),
	HANDLE_FUNC(rt_sigreturn),
	HANDLE_FUNC(setpriority),
	HANDLE_FUNC(getpriority),
	HANDLE_FUNC(reboot),
	HANDLE_FUNC(setregid),
	HANDLE_FUNC(setgid),
	HANDLE_FUNC(setreuid),
	HANDLE_FUNC(setuid),
	HANDLE_FUNC(setresuid),
	HANDLE_FUNC(getresuid),
	HANDLE_FUNC(setresgid),
	HANDLE_FUNC(getresgid),
	HANDLE_FUNC(setfsuid),
	HANDLE_FUNC(setfsgid),
	HANDLE_FUNC(times),
	HANDLE_FUNC(setpgid),
	HANDLE_FUNC(getpgid),
	HANDLE_FUNC(getsid),
	HANDLE_FUNC(setsid),
	HANDLE_FUNC(getgroups),
	HANDLE_FUNC(setgroups),
	HANDLE_FUNC(uname),
	HANDLE_FUNC(sethostname),
	HANDLE_FUNC(setdomainname),
#ifdef __ARCH_WANT_SET_GET_RLIMIT
	HANDLE_FUNC(getrlimit),
	HANDLE_FUNC(setrlimit),
#endif
	HANDLE_FUNC(getrusage),
	HANDLE_FUNC(umask),
	HANDLE_FUNC(prctl),
	HANDLE_FUNC(getcpu),
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
	HANDLE_FUNC(gettimeofday),
	HANDLE_FUNC(settimeofday),
	HANDLE_FUNC(adjtimex),
#endif
	HANDLE_FUNC(getpid),
	HANDLE_FUNC(getppid),
	HANDLE_FUNC(getuid),
	HANDLE_FUNC(geteuid),
	HANDLE_FUNC(getgid),
	HANDLE_FUNC(getegid),
	HANDLE_FUNC(gettid),
	HANDLE_FUNC(sysinfo),
	HANDLE_FUNC(mq_open),
	HANDLE_FUNC(mq_unlink),
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
	HANDLE_FUNC(mq_timedsend),
	HANDLE_FUNC(mq_timedreceive),
#endif
	HANDLE_FUNC(mq_notify),
	HANDLE_FUNC(mq_getsetattr),
	HANDLE_FUNC(msgget),
	HANDLE_FUNC(msgctl),
	HANDLE_FUNC(msgrcv),
	HANDLE_FUNC(msgsnd),
	HANDLE_FUNC(semget),
	HANDLE_FUNC(semctl),
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
	HANDLE_FUNC(semtimedop),
#endif
	HANDLE_FUNC(semop),
	HANDLE_FUNC(shmget),
	HANDLE_FUNC(shmctl),
	HANDLE_FUNC(shmat),
	HANDLE_FUNC(shmdt),
	HANDLE_FUNC(socket),
	HANDLE_FUNC(socketpair),
	HANDLE_FUNC(bind),
	HANDLE_FUNC(listen),
	HANDLE_FUNC(accept),
	HANDLE_FUNC(connect),
	HANDLE_FUNC(getsockname),
	HANDLE_FUNC(getpeername),
	HANDLE_FUNC(sendto),
	HANDLE_FUNC(recvfrom),
	HANDLE_FUNC(setsockopt),
	HANDLE_FUNC(getsockopt),
	HANDLE_FUNC(shutdown),
	HANDLE_FUNC(sendmsg),
	HANDLE_FUNC(recvmsg),
	HANDLE_FUNC(readahead),
	HANDLE_FUNC(brk),
	HANDLE_FUNC(munmap),
	HANDLE_FUNC(mremap),
	HANDLE_FUNC(add_key),
	HANDLE_FUNC(request_key),
	HANDLE_FUNC(keyctl),
	HANDLE_FUNC(clone),
	HANDLE_FUNC(execve),
	HANDLE_FUNC2(mmap),
	HANDLE_FUNC2(fadvise64),
#ifndef __ARCH_NOMMU
	HANDLE_FUNC(swapon),
	HANDLE_FUNC(swapoff),
	HANDLE_FUNC(mprotect),
	HANDLE_FUNC(msync),
	HANDLE_FUNC(mlock),
	HANDLE_FUNC(munlock),
	HANDLE_FUNC(mlockall),
	HANDLE_FUNC(munlockall),
	HANDLE_FUNC(mincore),
	HANDLE_FUNC(madvise),
	HANDLE_FUNC(remap_file_pages),
	HANDLE_FUNC(mbind),
	HANDLE_FUNC(get_mempolicy),
	HANDLE_FUNC(set_mempolicy),
	HANDLE_FUNC(migrate_pages),
	HANDLE_FUNC(move_pages),
#endif
	HANDLE_FUNC(rt_tgsigqueueinfo),
	HANDLE_FUNC(perf_event_open),
	HANDLE_FUNC(accept4),
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
	HANDLE_FUNC(recvmmsg),
#endif
	HANDLE_FUNC(arch_specific_syscall),
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
	HANDLE_FUNC(wait4),
#endif
	HANDLE_FUNC(prlimit64),
	HANDLE_FUNC(fanotify_init),
	HANDLE_FUNC(fanotify_mark),
	HANDLE_FUNC(name_to_handle_at),
	HANDLE_FUNC(open_by_handle_at),
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
	HANDLE_FUNC(clock_adjtime),
#endif
	HANDLE_FUNC(syncfs),
	HANDLE_FUNC(setns),
	HANDLE_FUNC(sendmmsg),
	HANDLE_FUNC(process_vm_readv),
	HANDLE_FUNC(process_vm_writev),
	HANDLE_FUNC(kcmp),
	HANDLE_FUNC(finit_module),
	HANDLE_FUNC(sched_setattr),
	HANDLE_FUNC(sched_getattr),
	HANDLE_FUNC(renameat2),
	HANDLE_FUNC(seccomp),
	HANDLE_FUNC(getrandom),
	HANDLE_FUNC(memfd_create),
	HANDLE_FUNC(bpf),
	HANDLE_FUNC(execveat),
	HANDLE_FUNC(userfaultfd),
	HANDLE_FUNC(membarrier),
	HANDLE_FUNC(mlock2),
	HANDLE_FUNC(copy_file_range),
	HANDLE_FUNC(preadv2),
	HANDLE_FUNC(pwritev2),
	HANDLE_FUNC(pkey_mprotect),
	HANDLE_FUNC(pkey_alloc),
	HANDLE_FUNC(pkey_free),
	HANDLE_FUNC(statx),
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
	HANDLE_FUNC(io_pgetevents),
#endif
	HANDLE_FUNC(rseq),
	HANDLE_FUNC(kexec_file_load),
#if __BITS_PER_LONG == 32
	HANDLE_FUNC(clock_gettime64),
	HANDLE_FUNC(clock_settime64),
	HANDLE_FUNC(clock_adjtime64),
	HANDLE_FUNC(clock_getres_time64),
	HANDLE_FUNC(clock_nanosleep_time64),
	HANDLE_FUNC(timer_gettime64),
	HANDLE_FUNC(timer_settime64),
	HANDLE_FUNC(timerfd_gettime64),
	HANDLE_FUNC(timerfd_settime64),
	HANDLE_FUNC(utimensat_time64),
	HANDLE_FUNC(pselect6_time64),
	HANDLE_FUNC(ppoll_time64),
	HANDLE_FUNC(io_pgetevents_time64),
	HANDLE_FUNC(recvmmsg_time64),
	HANDLE_FUNC(mq_timedsend_time64),
	HANDLE_FUNC(mq_timedreceive_time64),
	HANDLE_FUNC(semtimedop_time64),
	HANDLE_FUNC(rt_sigtimedwait_time64),
	HANDLE_FUNC(futex_time64),
	HANDLE_FUNC(sched_rr_get_interval_time64),
#endif
	HANDLE_FUNC(pidfd_send_signal),
	HANDLE_FUNC(io_uring_setup),
	HANDLE_FUNC(io_uring_enter),
	HANDLE_FUNC(io_uring_register),
	HANDLE_FUNC(open_tree),
	HANDLE_FUNC(move_mount),
	HANDLE_FUNC(fsopen),
	HANDLE_FUNC(fsconfig),
	HANDLE_FUNC(fsmount),
	HANDLE_FUNC(fspick),
	HANDLE_FUNC(pidfd_open),
#ifdef __ARCH_WANT_SYS_CLONE3
	HANDLE_FUNC(clone3),
#endif
	HANDLE_FUNC(close_range),
	HANDLE_FUNC(openat2),
	HANDLE_FUNC(pidfd_getfd),
	HANDLE_FUNC(faccessat2),
	HANDLE_FUNC(process_madvise),
	HANDLE_FUNC(epoll_pwait2),
	HANDLE_FUNC(mount_setattr),
	HANDLE_FUNC(landlock_create_ruleset),
	HANDLE_FUNC(landlock_add_rule),
	HANDLE_FUNC(landlock_restrict_self),
};


void syscall_dispatcher_fcn(struct kvm_cpu_context * cpu, sos_syscall_direction_t dir) {

	u64 esr = sos_read_sysreg(SYS_ESR_EL1);

	if (ESR_ELx_EC_SVC64 == ESR_ELx_EC(esr)) {

		u64 scn = cpu_reg(cpu, 8);

		if (scn < NR_syscalls) {
			syscall_dispatcher[scn](cpu,dir);
		}
	}

}















