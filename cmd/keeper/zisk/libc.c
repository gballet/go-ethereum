// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

// Minimal OpenBSD libc replacement for running a GOOS=openbsd GOARCH=riscv64
// Go program on the ZisK zkVM, which has no operating system.
//
// On OpenBSD the Go runtime and the syscall package never issue system calls
// themselves: every OS interaction goes through a libc function. This file
// provides those functions for a machine with one hart, no MMU, no signals and
// no clock:
//
//   - Memory: mmap is a bump allocator over the ZisK RAM; nothing is ever
//     freed or reused, so fresh memory is always zero as the runtime expects.
//   - Threads: cooperative threads on the single hart, switched only when the
//     running one blocks or yields. The runtime needs a few (see "Threads"
//     below); goroutines themselves are multiplexed by the Go scheduler.
//   - Time: a virtual monotonic clock that only advances when all threads
//     sleep, so timers fire as soon as nothing else can run.
//   - I/O: writes to fd 1 and 2 go to the ZisK UART; there is no filesystem.
//
// Execution is deterministic. If all threads block without a timeout, the
// program is deadlocked and terminates.

typedef unsigned long uintptr_t;
typedef unsigned long size_t;
typedef long ssize_t;
typedef long off_t;
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
typedef unsigned long uint64_t;
typedef long int64_t;

// ZisK machine interface (zisk/core/src/mem.rs).
#define ZISK_UART_ADDR 0xa0400200UL
#define ZISK_SYSCALL_EXIT 93

// OpenBSD ABI constants (go/src/runtime/defs_openbsd_riscv64.go).
#define ENOENT 2
#define ESRCH 3
#define EINTR 4
#define EBADF 9
#define ENOMEM 12
#define EINVAL 22
#define EAGAIN 35
#define ENOSYS 78

#define SIGURG 16

#define PROT_NONE 0x0
#define MAP_FIXED 0x10
#define MAP_ANON 0x1000

#define SS_DISABLE 0x4

#define CTL_HW 6
#define HW_NCPU 3
#define HW_PAGESIZE 7
#define HW_NCPUONLINE 25

#define PAGE_SIZE 4096UL

// Size of a Go heap arena (heapArenaBytes on 64-bit non-Windows). The runtime
// requires arenas to be aligned to that size.
#define ARENA_SIZE (64UL << 20)

// Non-arena mappings at least this large are address-indexed runtime tables
// (page allocator summaries, scavenger index, heap arena index) sized for a
// 48-bit address space. See sparse_charge.
#define SPARSE_THRESHOLD (8UL << 20)

struct timespec {
	int64_t tv_sec;
	int64_t tv_nsec;
};

struct stack_t {
	void *ss_sp;
	size_t ss_size;
	int ss_flags;
};

struct rlimit {
	uint64_t rlim_cur;
	uint64_t rlim_max;
};

// Provided by zisk.ld.
extern char _heap_bottom[];
extern char _heap_top[];

// TLS block pointed to by tp. Go reserves a TLS slot for g that it only uses
// with cgo, which is never linked in.
char __zisk_tls[64] __attribute__((aligned(64)));

static int errno_value;

int *__errno(void) { return &errno_value; }

static long fail(int err) {
	errno_value = err;
	return -1;
}

void *memset(void *dst, int c, size_t n) {
	uint8_t *d = dst;
	while (n--) *d++ = (uint8_t)c;
	return dst;
}

void *memcpy(void *dst, const void *src, size_t n) {
	uint8_t *d = dst;
	const uint8_t *s = src;
	while (n--) *d++ = *s++;
	return dst;
}

static void uart_write(const char *buf, size_t n) {
	volatile uint8_t *uart = (volatile uint8_t *)ZISK_UART_ADDR;
	for (size_t i = 0; i < n; i++) *uart = (uint8_t)buf[i];
}

static void uart_puts(const char *s) {
	size_t n = 0;
	while (s[n]) n++;
	uart_write(s, n);
}

static void uart_hex(uint64_t v) {
	char buf[18] = {'0', 'x'};
	for (int i = 0; i < 16; i++) buf[2 + i] = "0123456789abcdef"[(v >> (60 - 4 * i)) & 0xf];
	uart_write(buf, sizeof(buf));
}

void exit(int status) {
	register long a0 __asm__("a0") = status;
	register long a7 __asm__("a7") = ZISK_SYSCALL_EXIT;
	__asm__ volatile("ecall" : : "r"(a0), "r"(a7) : "memory");
	for (;;) {
	}
}

static void fatal(const char *msg) {
	uart_puts("zisk libc: ");
	uart_puts(msg);
	uart_puts("\n");
	exit(2);
}

// __zisk_boot_frame writes the initial process stack the OpenBSD kernel would
// provide: argc, argv, envp and an empty auxv. GOGC=off keeps the garbage
// collector from ever starting, even before main.init runs.
static char arg0[] = "keeper";
static char env0[] = "GOGC=off";

void __zisk_boot_frame(uint64_t *sp) {
	sp[0] = 1;                 // argc
	sp[1] = (uint64_t)arg0;    // argv[0]
	sp[2] = 0;                 // argv terminator
	sp[3] = (uint64_t)env0;    // envp[0]
	sp[4] = 0;                 // envp terminator
	sp[5] = 0;                 // auxv AT_NULL
	sp[6] = 0;
}

// ---------------------------------------------------------------------------
// Memory
//
// The heap [_heap_bottom, _heap_top) is split in two bump-allocated zones:
//
//   - Heap arenas, 64MB-aligned, growing up from the first aligned address.
//     Only those are backed by as much memory as they request.
//   - Everything else, in the unaligned space before the first arena and after
//     the last one.
//
// Without an MMU a reservation cannot be backed lazily, yet the runtime
// reserves several 512MB tables indexed by address over a 48-bit address
// space. Since no address at or above _heap_top exists on this machine, only
// the first len * _heap_top / 2^48 bytes of such tables are ever touched. We
// therefore only charge that prefix (plus slack for page rounding) and let the
// untouched tail overlap whatever is allocated next.

static uintptr_t arena_next, arena_end;   // arena zone
static uintptr_t small_next, small_end;   // current small zone
static uintptr_t small2_next, small2_end; // next small zone
static int mem_ready;

static uintptr_t align_up(uintptr_t v, uintptr_t a) { return (v + a - 1) & ~(a - 1); }
static uintptr_t align_down(uintptr_t v, uintptr_t a) { return v & ~(a - 1); }

static void mem_init(void) {
	uintptr_t bottom = align_up((uintptr_t)_heap_bottom, PAGE_SIZE);
	uintptr_t top = align_down((uintptr_t)_heap_top, PAGE_SIZE);

	arena_next = align_up(bottom, ARENA_SIZE);
	arena_end = align_down(top, ARENA_SIZE);
	if (arena_end < arena_next) arena_end = arena_next;

	small_next = arena_end;
	small_end = top;
	small2_next = bottom;
	small2_end = arena_next;
	mem_ready = 1;
}

static uintptr_t sparse_charge(size_t len) {
	if (len < SPARSE_THRESHOLD) return align_up(len, PAGE_SIZE);
	uintptr_t touched = (uintptr_t)(((unsigned __int128)len * (uintptr_t)_heap_top) >> 48);
	return align_up(touched, PAGE_SIZE) + 2 * PAGE_SIZE;
}

static void *small_alloc(size_t len) {
	uintptr_t charge = sparse_charge(len);
	if (small_end - small_next < charge) {
		small_next = small2_next;
		small_end = small2_end;
		small2_next = small2_end = 0;
		if (small_end - small_next < charge) return 0;
	}
	void *p = (void *)small_next;
	small_next += charge;
	return p;
}

static void *arena_alloc(void *hint, size_t len) {
	if (hint != 0 && (uintptr_t)hint != arena_next) return 0;
	if (arena_end - arena_next < len) return 0;
	void *p = (void *)arena_next;
	arena_next += len;
	return p;
}

void *mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off) {
	(void)off;
	if (!mem_ready) mem_init();
	if (!(flags & MAP_ANON) || fd != -1) return (void *)fail(ENOSYS);
	if (len == 0) return (void *)fail(EINVAL);

	if (flags & MAP_FIXED) {
		// Committing (or re-protecting) part of an earlier reservation.
		uintptr_t a = (uintptr_t)addr;
		if (a < (uintptr_t)_heap_bottom || a + len > (uintptr_t)_heap_top || a + len < a) {
			uart_puts("zisk libc: MAP_FIXED outside RAM at ");
			uart_hex(a);
			uart_puts("\n");
			return (void *)fail(ENOMEM);
		}
		return addr;
	}

	// Heap arenas: the runtime first tries its arena hints (which only
	// succeed when contiguous with the previous arena), then falls back to
	// an unhinted reservation of one aligned arena plus alignment slack.
	void *p;
	if ((addr != 0 && len % ARENA_SIZE == 0) ||
	    (addr == 0 && prot == PROT_NONE && len == 2 * ARENA_SIZE)) {
		p = arena_alloc(addr, len);
	} else {
		p = small_alloc(len);
	}
	if (p == 0) return (void *)fail(ENOMEM);
	return p;
}

int munmap(void *addr, size_t len) {
	(void)addr;
	(void)len;
	return 0;
}

int madvise(void *addr, size_t len, int advice) {
	(void)addr;
	(void)len;
	(void)advice;
	return 0;
}

// ---------------------------------------------------------------------------
// Time: a virtual clock that only advances when every thread is blocked, to
// the earliest deadline among them. It starts at one second because the
// runtime treats a zero monotonic time as a broken clock.

static int64_t clock_ns = 1000000000;

static int64_t timespec_ns(const struct timespec *ts) {
	return ts->tv_sec * 1000000000 + ts->tv_nsec;
}

int clock_gettime(int clock_id, struct timespec *tp) {
	(void)clock_id;
	tp->tv_sec = clock_ns / 1000000000;
	tp->tv_nsec = clock_ns % 1000000000;
	return 0;
}

// ---------------------------------------------------------------------------
// Threads.
//
// The Go runtime needs more than one OS thread (M) even with GOMAXPROCS=1:
// sysmon runs on its own thread, and while package initializers run, the main
// goroutine is locked to the initial thread, so whenever it blocks (e.g. in
// gcenable) the runtime hands its P to a new thread to run other goroutines.
//
// Threads are cooperative: the running thread only gives up the hart when it
// blocks (__thrsleep, usleep, kevent) or yields (sched_yield). The next thread
// is picked round-robin among the runnable ones; if there is none, the clock
// jumps to the earliest deadline. This keeps execution deterministic.

#define MAX_THREADS 64
#define THREAD_STACK_SIZE (256 * 1024)
#define NO_DEADLINE (-1)

struct context {
	uint64_t ra, sp, s[12], fs[12];
};

enum { T_RUNNABLE, T_SLEEPING, T_DEAD };

struct thread {
	struct context ctx;
	int state;
	const volatile void *ident; // what a sleeping thread waits on, if anything
	int64_t deadline;           // when a sleeping thread times out, or NO_DEADLINE
	int timed_out;
};

// Thread 0 is the initial thread, running on the stack set up by crt0.S.
static struct thread threads[MAX_THREADS] = {{.state = T_RUNNABLE, .deadline = NO_DEADLINE}};
static int nthreads = 1;
static int current;

void __zisk_switch(struct context *from, struct context *to);
void __zisk_thread_start(void);

// schedule switches to the next thread that can run, which may be the
// current one if it is runnable and nobody else is.
static void schedule(void) {
	int next = -1;
	for (int i = 1; i <= nthreads && next < 0; i++) {
		int j = (current + i) % nthreads;
		struct thread *t = &threads[j];
		if (t->state == T_SLEEPING && t->deadline != NO_DEADLINE && t->deadline <= clock_ns) {
			t->state = T_RUNNABLE;
			t->timed_out = 1;
		}
		if (t->state == T_RUNNABLE) next = j;
	}
	if (next < 0) {
		for (int j = 0; j < nthreads; j++) {
			struct thread *t = &threads[j];
			if (t->state == T_SLEEPING && t->deadline != NO_DEADLINE &&
			    (next < 0 || t->deadline < threads[next].deadline)) {
				next = j;
			}
		}
		if (next < 0) fatal("deadlock: all threads are blocked without a timeout");
		clock_ns = threads[next].deadline;
		threads[next].state = T_RUNNABLE;
		threads[next].timed_out = 1;
	}
	if (next == current) return;
	int prev = current;
	current = next;
	__zisk_switch(&threads[prev].ctx, &threads[next].ctx);
}

// block puts the current thread to sleep until woken on ident or, if deadline
// is not NO_DEADLINE, until the clock reaches it. Returns whether it timed out.
static int block(const volatile void *ident, int64_t deadline) {
	struct thread *t = &threads[current];
	t->state = T_SLEEPING;
	t->ident = ident;
	t->deadline = deadline;
	t->timed_out = 0;
	schedule();
	return t->timed_out;
}

// wake makes up to n (all if n <= 0) threads sleeping on ident runnable and
// returns how many there were. The caller keeps running.
static int wake(const volatile void *ident, int n) {
	int woken = 0;
	for (int j = 0; j < nthreads && (n <= 0 || woken < n); j++) {
		struct thread *t = &threads[j];
		if (t->state == T_SLEEPING && t->ident == ident) {
			t->state = T_RUNNABLE;
			woken++;
		}
	}
	return woken;
}

void __zisk_thread_exit(void) {
	threads[current].state = T_DEAD;
	schedule();
	fatal("exited thread resumed");
}

int pthread_attr_init(void *attr) {
	(void)attr;
	return 0;
}

int pthread_attr_destroy(void *attr) {
	(void)attr;
	return 0;
}

int pthread_attr_getstacksize(void *attr, size_t *size) {
	(void)attr;
	*size = THREAD_STACK_SIZE;
	return 0;
}

int pthread_attr_setdetachstate(void *attr, int state) {
	(void)attr;
	(void)state;
	return 0;
}

int pthread_create(uint64_t *thread, void *attr, void *(*start)(void *), void *arg) {
	(void)attr;
	if (nthreads == MAX_THREADS) return EAGAIN;
	if (!mem_ready) mem_init();
	void *stack = small_alloc(THREAD_STACK_SIZE);
	if (stack == 0) return EAGAIN;
	struct thread *t = &threads[nthreads];
	t->ctx.ra = (uint64_t)__zisk_thread_start;
	t->ctx.sp = (uint64_t)stack + THREAD_STACK_SIZE;
	t->ctx.s[0] = (uint64_t)start;
	t->ctx.s[1] = (uint64_t)arg;
	t->state = T_RUNNABLE;
	t->deadline = NO_DEADLINE;
	*thread = (uint64_t)nthreads;
	nthreads++;
	return 0;
}

// __thrsleep and __thrwakeup back the runtime's semaphores (OpenBSD's futex
// equivalent). __thrsleep returns an error number rather than setting errno.
int __thrsleep(const volatile void *ident, int clock_id, const struct timespec *abstime,
               volatile void *lock, const int *abort) {
	(void)clock_id;
	(void)lock;
	if (abort != 0 && *abort != 0) return EINTR;
	if (block(ident, abstime != 0 ? timespec_ns(abstime) : NO_DEADLINE)) {
		return EAGAIN; // EWOULDBLOCK: timed out
	}
	return 0;
}

int __thrwakeup(const volatile void *ident, int n) {
	return wake(ident, n) > 0 ? 0 : ESRCH;
}

int usleep(uint32_t usec) {
	block(0, clock_ns + (int64_t)usec * 1000);
	return 0;
}

int sched_yield(void) {
	schedule();
	return 0;
}

int getthrid(void) { return 100000 + current; }
int getpid(void) { return 1; }
int issetugid(void) { return 0; }

// ---------------------------------------------------------------------------
// Signals are never delivered.

static void die_from_signal(int sig) {
	uart_puts("zisk libc: killed by signal ");
	char c[3] = {(char)('0' + sig / 10), (char)('0' + sig % 10), '\n'};
	uart_write(c, 3);
	exit(128 + sig);
}

static int raise_signal(int sig) {
	// SIGURG requests asynchronous preemption, which is not needed:
	// goroutines still get preempted cooperatively.
	if (sig != 0 && sig != SIGURG) die_from_signal(sig);
	return 0;
}

int thrkill(int tid, int sig, void *tcb) {
	(void)tid;
	(void)tcb;
	return raise_signal(sig);
}

int kill(int pid, int sig) {
	(void)pid;
	return raise_signal(sig);
}

int sigaction(int sig, const void *act, void *oact) {
	(void)sig;
	(void)act;
	if (oact != 0) memset(oact, 0, 16);
	return 0;
}

int pthread_sigmask(int how, const uint32_t *set, uint32_t *oset) {
	(void)how;
	(void)set;
	if (oset != 0) *oset = 0;
	return 0;
}

int sigaltstack(const struct stack_t *ss, struct stack_t *oss) {
	(void)ss;
	if (oss != 0) {
		oss->ss_sp = 0;
		oss->ss_size = 0;
		oss->ss_flags = SS_DISABLE;
	}
	return 0;
}

int setitimer(int which, const void *value, void *ovalue) {
	(void)which;
	(void)value;
	if (ovalue != 0) memset(ovalue, 0, 32);
	return 0;
}

// ---------------------------------------------------------------------------
// Network poller. The runtime starts it to wait for timers. There is nothing
// to poll besides its wakeup pipe, so waiting is a sleep until the timeout or
// until the pipe is written to.

#define KQUEUE_FD 3
#define PIPE_READ_FD 4
#define PIPE_WRITE_FD 5
#define EVFILT_READ (-1)

struct kevent {
	uint64_t ident;
	short filter;
	unsigned short flags;
	uint32_t fflags;
	int64_t data;
	void *udata;
};

static int pipe_pending; // the wakeup pipe has unread data
static const int kevent_waiters;

int kqueue(void) { return KQUEUE_FD; }

int kevent(int kq, const void *changelist, int nchanges, struct kevent *eventlist, int nevents,
           const struct timespec *timeout) {
	(void)kq;
	(void)changelist;
	(void)nchanges;
	if (nevents == 0) return 0;
	if (!pipe_pending) {
		if (timeout == 0) {
			block(&kevent_waiters, NO_DEADLINE);
		} else if (timespec_ns(timeout) > 0) {
			block(&kevent_waiters, clock_ns + timespec_ns(timeout));
		}
	}
	if (!pipe_pending) return 0;
	memset(eventlist, 0, sizeof(*eventlist));
	eventlist->ident = PIPE_READ_FD;
	eventlist->filter = EVFILT_READ;
	eventlist->data = 1;
	return 1;
}

int pipe2(int fds[2], int flags) {
	(void)flags;
	fds[0] = PIPE_READ_FD;
	fds[1] = PIPE_WRITE_FD;
	return 0;
}

// ---------------------------------------------------------------------------
// File descriptors: stdout/stderr go to the UART, there is no filesystem.

ssize_t write(int fd, const void *buf, size_t n) {
	switch (fd) {
	case 1:
	case 2:
		uart_write(buf, n);
		return (ssize_t)n;
	case PIPE_WRITE_FD:
		pipe_pending = 1;
		wake(&kevent_waiters, 0);
		return (ssize_t)n;
	default:
		return fail(EBADF);
	}
}

ssize_t read(int fd, void *buf, size_t n) {
	switch (fd) {
	case 0:
		return 0;
	case PIPE_READ_FD:
		if (!pipe_pending) return fail(EAGAIN);
		pipe_pending = 0;
		if (n == 0) return 0;
		*(uint8_t *)buf = 0;
		return 1;
	default:
		return fail(EBADF);
	}
}

int open(const char *path, int flags, int mode) {
	(void)path;
	(void)flags;
	(void)mode;
	return fail(ENOENT);
}

int openat(int dirfd, const char *path, int flags, int mode) {
	(void)dirfd;
	(void)path;
	(void)flags;
	(void)mode;
	return fail(ENOENT);
}

int close(int fd) {
	(void)fd;
	return 0;
}

// Every descriptor reports no flags: in particular not O_NONBLOCK, which keeps
// os.File away from the network poller.
int fcntl(int fd, int cmd, long arg) {
	(void)fd;
	(void)cmd;
	(void)arg;
	return 0;
}

// ---------------------------------------------------------------------------
// System information.

int sysctl(const int *name, unsigned int namelen, void *oldp, size_t *oldlenp,
           void *newp, size_t newlen) {
	(void)newp;
	(void)newlen;
	if (namelen == 2 && name[0] == CTL_HW && oldp != 0 && oldlenp != 0 && *oldlenp >= 4) {
		switch (name[1]) {
		case HW_NCPU:
		case HW_NCPUONLINE:
			*(int *)oldp = 1;
			*oldlenp = 4;
			return 0;
		case HW_PAGESIZE:
			*(int *)oldp = (int)PAGE_SIZE;
			*oldlenp = 4;
			return 0;
		}
	}
	return fail(ENOENT);
}

int getrlimit(int resource, struct rlimit *rlp) {
	(void)resource;
	rlp->rlim_cur = 1024;
	rlp->rlim_max = 1024;
	return 0;
}

int setrlimit(int resource, const struct rlimit *rlp) {
	(void)resource;
	(void)rlp;
	return 0;
}

// arc4random_buf seeds the runtime's random number generator (map seeds,
// scheduler randomization) and backs crypto/rand. A zkVM execution must be
// deterministic, so this is a fixed-seed splitmix64 stream: it is NOT a
// source of secret randomness.
static uint64_t rand_state = 0x9e3779b97f4a7c15UL;

void arc4random_buf(void *buf, size_t n) {
	uint8_t *b = buf;
	while (n > 0) {
		uint64_t z = (rand_state += 0x9e3779b97f4a7c15UL);
		z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9UL;
		z = (z ^ (z >> 27)) * 0x94d049bb133111ebUL;
		z ^= z >> 31;
		for (int i = 0; i < 8 && n > 0; i++, n--) *b++ = (uint8_t)(z >> (8 * i));
	}
}

// ---------------------------------------------------------------------------
// Functions referenced by the os and syscall packages that have no meaning
// without an operating system.

#define UNSUPPORTED(name) \
	long name(void) { return fail(ENOSYS); }

UNSUPPORTED(bind)
UNSUPPORTED(chmod)
UNSUPPORTED(connect)
UNSUPPORTED(dup3)
UNSUPPORTED(execve)
UNSUPPORTED(flock)
UNSUPPORTED(fstat)
UNSUPPORTED(fstatat)
UNSUPPORTED(fsync)
UNSUPPORTED(ftruncate)
UNSUPPORTED(getcwd)
UNSUPPORTED(getdents)
UNSUPPORTED(getpeername)
UNSUPPORTED(getrusage)
UNSUPPORTED(getsockname)
UNSUPPORTED(getsockopt)
UNSUPPORTED(listen)
UNSUPPORTED(lseek)
UNSUPPORTED(lstat)
UNSUPPORTED(mkdir)
UNSUPPORTED(pread)
UNSUPPORTED(readlinkat)
UNSUPPORTED(rename)
UNSUPPORTED(rmdir)
UNSUPPORTED(setsockopt)
UNSUPPORTED(socket)
UNSUPPORTED(stat)
UNSUPPORTED(unlink)
UNSUPPORTED(unlinkat)
