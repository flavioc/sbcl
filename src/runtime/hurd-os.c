/*
 * Hurd OS-dependent routines.
 */

/*
 * This software is part of the SBCL system. See the README file for
 * more information.
 *
 * This software is derived from the CMU CL system, which was
 * written at Carnegie Mellon University and released into the
 * public domain. The software is in the public domain and is
 * provided with absolutely no warranty. See the COPYING and CREDITS
 * files for more information.
 */

#include "thread.h"
#include "sbcl.h"
#include "globals.h"
#include "runtime.h"
#include "os.h"
#include "arch.h"
#include "interrupt.h"
#include "interr.h"
#include "lispregs.h"
#include "thread.h"
#include "genesis/static-symbols.h"
#include "genesis/fdefn.h"
#include <signal.h>
#include <limits.h>
#include <stdio.h>
#include <errno.h>
#include <dlfcn.h>
#if defined LISP_FEATURE_GENCGC
#include "gencgc-internal.h"
#endif

#ifdef LISP_FEATURE_MACH_EXCEPTION_HANDLER
#include <mach/mach.h>
#include <stdlib.h>
#endif

#if defined(LISP_FEATURE_SB_WTIMER)
# include <sys/types.h>
# include <sys/event.h>
# include <sys/time.h>
#endif

os_vm_size_t os_vm_page_size;

char *
os_get_runtime_executable_path(int external)
{
  return NULL;
}

#ifdef LISP_FEATURE_MACH_EXCEPTION_HANDLER

/* exc_server handles mach exception messages from the kernel and
 * calls catch exception raise. We use the system-provided
 * mach_msg_server, which, I assume, calls exc_server in a loop.
 *
 */
extern boolean_t exc_server();

void *
mach_exception_handler(void *port)
{
  mach_msg_server(exc_server, 2048, (mach_port_t) port, 0);
  /* mach_msg_server should never return, but it should dispatch mach
   * exceptions to our catch_exception_raise function
   */
  lose("mach_msg_server returned");
}

/* Sets up the thread that will listen for mach exceptions. note that
   the exception handlers will be run on this thread. This is
   different from the BSD-style signal handling situation in which the
   signal handlers run in the relevant thread directly. */

mach_port_t mach_exception_handler_port_set = MACH_PORT_NULL;
mach_port_t current_mach_task = MACH_PORT_NULL;

pthread_t
setup_mach_exception_handling_thread()
{
    kern_return_t ret;
    pthread_t mach_exception_handling_thread = NULL;
    pthread_attr_t attr;

    current_mach_task = mach_task_self();

    /* allocate a mach_port for this process */
    ret = mach_port_allocate(current_mach_task,
                             MACH_PORT_RIGHT_PORT_SET,
                             &mach_exception_handler_port_set);

    /* create the thread that will receive the mach exceptions */

    FSHOW((stderr, "Creating mach_exception_handler thread!\n"));

    pthread_attr_init(&attr);
    pthread_create(&mach_exception_handling_thread,
                   &attr,
                   mach_exception_handler,
                   (void*) mach_exception_handler_port_set);
    pthread_attr_destroy(&attr);

    return mach_exception_handling_thread;
}

struct exception_port_record
{
    struct thread * thread;
    struct exception_port_record * next;
};

//static OSQueueHead free_records = OS_ATOMIC_QUEUE_INIT;

/* We can't depend on arbitrary addresses to be accepted as mach port
 * names, particularly not on 64-bit platforms.  Instead, we allocate
 * records that point to the thread struct, and loop until one is accepted
 * as a port name.
 *
 * Threads are mapped to exception ports with a slot in the thread struct,
 * and exception ports are casted to records that point to the corresponding
 * thread.
 *
 * The lock-free free-list above is used as a cheap fast path.
 */
static mach_port_t
find_receive_port(struct thread * thread)
{
    mach_port_t ret;
    struct exception_port_record * curr, * to_free = NULL;
    unsigned long i;
    for (i = 1;; i++) {
        curr = OSAtomicDequeue(&free_records, offsetof(struct exception_port_record, next));
        if (curr == NULL) {
            curr = calloc(1, sizeof(struct exception_port_record));
            if (curr == NULL)
                lose("unable to allocate exception_port_record\n");
        }
#ifdef LISP_FEATURE_X86_64
        if ((mach_port_t)curr != (unsigned long)curr)
            goto skip;
#endif

        if (mach_port_allocate_name(current_mach_task,
                                    MACH_PORT_RIGHT_RECEIVE,
                                    (mach_port_t)curr))
            goto skip;
        curr->thread = thread;
        ret = (mach_port_t)curr;
        break;
        skip:
        curr->next = to_free;
        to_free = curr;
        if ((i % 1024) == 0)
            FSHOW((stderr, "Looped %lu times trying to allocate an exception port\n"));
    }
    while (to_free != NULL) {
        struct exception_port_record * current = to_free;
        to_free = to_free->next;
        free(current);
    }

    FSHOW((stderr, "Allocated exception port %x for thread %p\n", ret, thread));

    return ret;
}

/* tell the kernel that we want EXC_BAD_ACCESS exceptions sent to the
   exception port (which is being listened to do by the mach
   exception handling thread). */
kern_return_t
mach_lisp_thread_init(struct thread * thread)
{
    kern_return_t ret;
    mach_port_t current_mach_thread, thread_exception_port;

    /* allocate a named port for the thread */
    thread_exception_port
        = thread->mach_port_name
        = find_receive_port(thread);

    /* establish the right for the thread_exception_port to send messages */
    ret = mach_port_insert_right(current_mach_task,
                                 thread_exception_port,
                                 thread_exception_port,
                                 MACH_MSG_TYPE_MAKE_SEND);
    if (ret) {
        lose("mach_port_insert_right failed with return_code %d\n", ret);
    }

    current_mach_thread = mach_thread_self();
    ret = thread_set_exception_ports(current_mach_thread,
                                     EXC_MASK_BAD_ACCESS | EXC_MASK_BAD_INSTRUCTION,
                                     thread_exception_port,
                                     EXCEPTION_DEFAULT,
                                     THREAD_STATE_NONE);
    if (ret) {
        lose("thread_set_exception_ports failed with return_code %d\n", ret);
    }

    ret = mach_port_deallocate (current_mach_task, current_mach_thread);
    if (ret) {
        lose("mach_port_deallocate failed with return_code %d\n", ret);
    }

    ret = mach_port_move_member(current_mach_task,
                                thread_exception_port,
                                mach_exception_handler_port_set);
    if (ret) {
        lose("mach_port_move_member failed with return_code %d\n", ret);
    }

    return ret;
}

kern_return_t
mach_lisp_thread_destroy(struct thread *thread) {
    kern_return_t ret;
    mach_port_t port = thread->mach_port_name;
    FSHOW((stderr, "Deallocating mach port %x\n", port));
    mach_port_move_member(current_mach_task, port, MACH_PORT_NULL);
    mach_port_deallocate(current_mach_task, port);

    ret = mach_port_destroy(current_mach_task, port);
    ((struct exception_port_record*)port)->thread = NULL;
    OSAtomicEnqueue(&free_records, (void*)port, offsetof(struct exception_port_record, next));

    return ret;
}

void
setup_mach_exceptions() {
    setup_mach_exception_handling_thread();
    mach_lisp_thread_init(all_threads);
}

pid_t
mach_fork() {
    pid_t pid = fork();
    if (pid == 0) {
        setup_mach_exceptions();
        return pid;
    } else {
        return pid;
    }
}
#endif

void os_init(char *argv[], char *envp[])
{
    os_vm_page_size = BACKEND_PAGE_BYTES;
#ifdef LISP_FEATURE_MACH_EXCEPTION_HANDLER
    setup_mach_exception_handling_thread();
#endif
}


#ifdef LISP_FEATURE_SB_THREAD

inline void
os_sem_init(os_sem_t *sem, unsigned int value)
{
    if (KERN_SUCCESS!=semaphore_create(current_mach_task, sem, SYNC_POLICY_FIFO, (int)value))
        lose("os_sem_init(%p): %s", sem, strerror(errno));
}

inline void
os_sem_wait(os_sem_t *sem, char *what)
{
    kern_return_t ret;
  restart:
    FSHOW((stderr, "%s: os_sem_wait(%p)\n", what, sem));
    ret = semaphore_wait(*sem);
    FSHOW((stderr, "%s: os_sem_wait(%p) => %s\n", what, sem,
           KERN_SUCCESS==ret ? "ok" : strerror(errno)));
    switch (ret) {
    case KERN_SUCCESS:
        return;
        /* It is unclear just when we can get this, but a sufficiently
         * long wait seems to do that, at least sometimes.
         *
         * However, a wait that long is definitely abnormal for the
         * GC, so we complain before retrying.
         */
    case KERN_OPERATION_TIMED_OUT:
        fprintf(stderr, "%s: os_sem_wait(%p): %s", what, sem, strerror(errno));
        /* This is analogous to POSIX EINTR. */
    case KERN_ABORTED:
        goto restart;
    default:
        lose("%s: os_sem_wait(%p): %lu, %s", what, sem, ret, strerror(errno));
    }
}

void
os_sem_post(os_sem_t *sem, char *what)
{
    if (KERN_SUCCESS!=semaphore_signal(*sem))
        lose("%s: os_sem_post(%p): %s", what, sem, strerror(errno));
    FSHOW((stderr, "%s: os_sem_post(%p) ok\n", what, sem));
}

void
os_sem_destroy(os_sem_t *sem)
{
    if (-1==semaphore_destroy(current_mach_task, *sem))
        lose("os_sem_destroy(%p): %s", sem, strerror(errno));
}

#endif

#if defined(LISP_FEATURE_SB_WTIMER)

# error Completely untested. Go ahead! Remove this line, try your luck!

/*
 * Waitable timer implementation for the safepoint-based (SIGALRM-free)
 * timer facility using kqueue.
 *
 * Unlike FreeBSD with its ms (!) timer resolution, Darwin supports ns
 * timer resolution -- or at least it pretends to do so on the API
 * level (?).  To use it, we need the *64 versions of the functions and
 * structures.
 *
 * Unfortunately, I don't run Darwin, and can't test this code, so it's
 * just a hopeful translation from FreeBSD.
 */

int
os_create_wtimer()
{
    int kq = kqueue();
    if (kq == -1)
        lose("os_create_wtimer: kqueue");
    return kq;
}

int
os_wait_for_wtimer(int kq)
{
    struct kevent64_s ev;
    int n;
    if ( (n = kevent64(kq, 0, 0, &ev, 1, 0, 0)) == -1) {
        if (errno != EINTR)
            lose("os_wtimer_listen failed");
        n = 0;
    }
    return n != 1;
}

void
os_close_wtimer(int kq)
{
    if (close(kq) == -1)
        lose("os_close_wtimer failed");
}

void
os_set_wtimer(int kq, int sec, int nsec)
{
    int64_t nsec = ((int64_t) sec) * 1000000000 + (int64_t) nsec;

    struct kevent64_s ev;
    EV_SET64(&ev, 1, EVFILT_TIMER, EV_ADD|EV_ENABLE|EV_ONESHOT, NOTE_NSECONDS,
             nsec, 0, 0, 0);
    if (kevent64(kq, &ev, 1, 0, 0, 0, 0) == -1)
        perror("os_set_wtimer: kevent");
}

void
os_cancel_wtimer(int kq)
{
    struct kevent64_s ev;
    EV_SET64(&ev, 1, EVFILT_TIMER, EV_DISABLE, 0, 0, 0, 0, 0);
    if (kevent64(kq, &ev, 1, 0, 0, 0, 0) == -1 && errno != ENOENT)
        perror("os_cancel_wtimer: kevent");
}
#endif

os_vm_address_t
os_map(int fd, int offset, os_vm_address_t addr, os_vm_size_t len)
{
    addr = mmap(addr, len,
                OS_VM_PROT_ALL,
                MAP_PRIVATE | MAP_FILE | MAP_FIXED,
                fd, (off_t) offset);

    if (addr == MAP_FAILED) {
        perror("mmap");
        lose("unexpected mmap(..) failure\n");
    }

    return addr;
}

void
os_protect(os_vm_address_t address, os_vm_size_t length, os_vm_prot_t prot)
{
    if (mprotect(address, length, prot) == -1) {
        perror("mprotect");
    }
}

sigset_t *
os_context_sigmask_addr(os_context_t *context)
{
    return &context->uc_sigmask;
}

os_vm_address_t
os_validate(os_vm_address_t addr, os_vm_size_t len)
{
    int flags = MAP_PRIVATE | MAP_ANON;

    if (addr)
        flags |= MAP_FIXED;

    addr = mmap(addr, len, OS_VM_PROT_ALL, flags, -1, 0);

    if (addr == MAP_FAILED) {
        perror("mmap");
        return NULL;
    }

    return addr;
}

void
os_invalidate(os_vm_address_t addr, os_vm_size_t len)
{
    if (munmap(addr, len) == -1)
        perror("munmap");
}

static boolean
in_range_p(os_vm_address_t a, lispobj sbeg, size_t slen)
{
    char* beg = (char*) sbeg;
    char* end = (char*) sbeg + slen;
    char* adr = (char*) a;
    return (adr >= beg && adr < end);
}

boolean
is_valid_lisp_addr(os_vm_address_t addr)
{
    struct thread *th;

    if (in_range_p(addr, READ_ONLY_SPACE_START, READ_ONLY_SPACE_SIZE) ||
        in_range_p(addr, STATIC_SPACE_START, STATIC_SPACE_SIZE) ||
        in_range_p(addr, DYNAMIC_SPACE_START, dynamic_space_size))
        return 1;
    for_each_thread(th) {
        if (((os_vm_address_t)th->control_stack_start <= addr) &&
            (addr < (os_vm_address_t)th->control_stack_end))
            return 1;
        if (in_range_p(addr, (lispobj) th->binding_stack_start,
                       BINDING_STACK_SIZE))
            return 1;
    }
    return 0;
}

#if defined LISP_FEATURE_GENCGC

/*
 * The GENCGC needs to be hooked into whatever signal is raised for
 * page fault on this OS.
 */

void
memory_fault_handler(int signal, siginfo_t *siginfo, os_context_t *context)
{
    void *fault_addr = arch_get_bad_addr(signal, siginfo, context);

#if defined(LISP_FEATURE_RESTORE_TLS_SEGMENT_REGISTER_FROM_CONTEXT)
    FSHOW_SIGNAL((stderr, "/ TLS: restoring fs: %p in memory_fault_handler\n",
                  *CONTEXT_ADDR_FROM_STEM(fs)));
    os_restore_tls_segment_register(context);
#endif

    FSHOW((stderr, "Memory fault at: %p, PC: %p\n", fault_addr, *os_context_pc_addr(context)));

#ifdef LISP_FEATURE_SB_SAFEPOINT
    if (!handle_safepoint_violation(context, fault_addr))
#endif

    if (!gencgc_handle_wp_violation(fault_addr))
        if(!handle_guard_page_triggered(context,fault_addr))
            lisp_memory_fault_error(context, fault_addr);
}

#if defined(LISP_FEATURE_MACH_EXCEPTION_HANDLER)
void
mach_error_memory_fault_handler(int signal, siginfo_t *siginfo,
                                os_context_t *context) {
    lose("Unhandled memory fault. Exiting.");
}
#endif

void
os_install_interrupt_handlers(void)
{
    SHOW("os_install_interrupt_handlers()/bsd-os/defined(GENCGC)");
#if defined(LISP_FEATURE_MACH_EXCEPTION_HANDLER)
    undoably_install_low_level_interrupt_handler(SIG_MEMORY_FAULT,
                                                 mach_error_memory_fault_handler);
#else
    undoably_install_low_level_interrupt_handler(SIG_MEMORY_FAULT,
#if defined(LISP_FEATURE_FREEBSD) && !defined(__GLIBC__)
                                                 (__siginfohandler_t *)
#endif
                                                 memory_fault_handler);
#endif

#ifdef LISP_FEATURE_SB_THREAD
# ifdef LISP_FEATURE_SB_SAFEPOINT
#  ifdef LISP_FEATURE_SB_THRUPTION
    undoably_install_low_level_interrupt_handler(SIGPIPE, thruption_handler);
#  endif
# else
    undoably_install_low_level_interrupt_handler(SIG_STOP_FOR_GC,
                                                 sig_stop_for_gc_handler);
# endif
#endif
    SHOW("leaving os_install_interrupt_handlers()");
}

#else /* Currently PPC/Darwin/Cheney only */

static void
sigsegv_handler(int signal, siginfo_t *info, os_context_t *context)
{
#if 0
    unsigned int pc =  (unsigned int *)(*os_context_pc_addr(context));
#endif
    os_vm_address_t addr;

    addr = arch_get_bad_addr(signal, info, context);
    if (!cheneygc_handle_wp_violation(context, addr))
        if (!handle_guard_page_triggered(context, addr))
            interrupt_handle_now(signal, info, context);
}

void
os_install_interrupt_handlers(void)
{
    SHOW("os_install_interrupt_handlers()/bsd-os/!defined(GENCGC)");
    undoably_install_low_level_interrupt_handler(SIG_MEMORY_FAULT,
                                                 sigsegv_handler);
}

#endif /* defined GENCGC */
