/*  
 *      This file is part of frosted.
 *
 *      frosted is free software: you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License version 2, as 
 *      published by the Free Software Foundation.
 *      
 *
 *      frosted is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *      GNU General Public License for more details.
 *
 *      You should have received a copy of the GNU General Public License
 *      along with frosted.  If not, see <http://www.gnu.org/licenses/>.
 *
 *      Authors: Daniele Lacamera, Maxime Vincent
 *
 */  
#include "frosted.h"
#include "syscall_table.h"
#include "string.h" /* flibc string.h */
#include "signal.h"
#include "sys/wait.h"


/* Full kernel space separation */
#define RUN_HANDLER (0xfffffff1u)
#define MSP "msp"
#define PSP "psp"
#define RUN_KERNEL  (0xfffffff9u)
#define RUN_USER    (0xfffffffdu)


#define STACK_THRESHOLD 64

static char _my_x_str[11] = "";
static char *x_str(uint32_t x)
{
    int i;
    uint8_t val;
    _my_x_str[0] = '0';
    _my_x_str[1] = 'x';
    for (i = 0; i < 8; i++) {
        val = (((x >> ((7 - i) << 2)) & 0x0000000F));
        if (val < 10)
            _my_x_str[i + 2] = val + '0';
        else
            _my_x_str[i + 2] = (val - 10) + 'A';
    }
    _my_x_str[10] = 0;
    return _my_x_str;
}

static char _my_pid_str[6];
static char *pid_str(uint16_t p)
{
    int i = 0;
    if (p >= 10000) {
        _my_pid_str[i++] = (p/10000) + '0';
        p = p % 10000;
    }
    if (i > 0 || p >= 1000) {
        _my_pid_str[i++] = (p/1000) + '0';
        p = p % 1000;
    }
    if (i > 0 || p >= 100) {
        _my_pid_str[i++] = (p/100) + '0';
        p = p % 100;
    }
    if (i > 0 || p >= 10) {
        _my_pid_str[i++] = (p/10) + '0';
        p = p % 10;
    }
    _my_pid_str[i++] = p + '0';
    _my_pid_str[i] = 0;
    return _my_pid_str;
}

/* Array of syscalls */
static void *sys_syscall_handlers[_SYSCALLS_NR] = {

};

int sys_register_handler(uint32_t n, int(*_sys_c)(uint32_t arg1, uint32_t arg2, uint32_t arg3, uint32_t arg4, uint32_t arg5))
{
    if (n >= _SYSCALLS_NR)
        return -1; /* Attempting to register non-existing syscall */

    if (sys_syscall_handlers[n] != NULL)
        return -1; /* Syscall already registered */

    sys_syscall_handlers[n] = _sys_c;
    return 0;
} 


#define MAX_TASKS 16
#define BASE_TIMESLICE (20)
#define TIMESLICE(x) ((BASE_TIMESLICE) + ((x)->tb.prio << 2))
#define SCHEDULER_STACK_SIZE ((CONFIG_TASK_STACK_SIZE - sizeof(struct task_block)) - F_MALLOC_OVERHEAD)
#define INIT_SCHEDULER_STACK_SIZE (256)

struct __attribute__((packed)) nvic_stack_frame {
    uint32_t r0;
    uint32_t r1;
    uint32_t r2;
    uint32_t r3;
    uint32_t r12;
    uint32_t lr;
    uint32_t pc;
    uint32_t psr;
#   if (__CORTEX_M == 4) /* CORTEX-M4 saves FPU frame as well */
    uint32_t s0;
    uint32_t s1;
    uint32_t s2;
    uint32_t s3;
    uint32_t s4;
    uint32_t s5;
    uint32_t s6;
    uint32_t s7;
    uint32_t s8;
    uint32_t s9;
    uint32_t s10;
    uint32_t s11;
    uint32_t s12;
    uint32_t s13;
    uint32_t s14;
    uint32_t s15;
    uint32_t fpscr;
    uint32_t dummy;
#   endif
};
struct __attribute__((packed)) extra_stack_frame {
    uint32_t r4;
    uint32_t r5;
    uint32_t r6;
    uint32_t r7;
    uint32_t r8;
    uint32_t r9;
    uint32_t r10;
    uint32_t r11;
};

#define NVIC_FRAME_SIZE ((sizeof(struct nvic_stack_frame)))
#define EXTRA_FRAME_SIZE ((sizeof(struct extra_stack_frame)))


static void * _top_stack;
#define __inl inline
#define __naked __attribute__((naked))


#define TASK_FLAG_VFORK 0x01

struct filedesc {
    struct fnode *fno;
    uint32_t mask;
};


struct task_handler 
{
    int signo;
    void (*hdlr)(int);
    uint32_t mask;
    struct task_handler *next;
};

struct __attribute__((packed)) task_block {
    void (*start)(void *);
    void *arg;

    uint8_t state;
    uint8_t flags;
    uint16_t prio;

    uint16_t timeslice;
    uint16_t pid;

    uint16_t ppid;
    uint16_t n_files;

    int exitval;
    struct fnode *cwd;
    struct task_handler *sighdlr;
    sigset_t sigmask;
    sigset_t sigpend;
    struct filedesc *filedesc;
    void *sp;
    void *cur_stack;
    struct task *next;
    char * name;
};

struct __attribute__((packed)) task {
    struct task_block tb;
    uint32_t stack[SCHEDULER_STACK_SIZE / 4];
};

static struct task struct_task_kernel;
static struct task *const kernel = (struct task *)(&struct_task_kernel);


static int number_of_tasks = 0;

static void tasklist_add(struct task **list, volatile struct task *el)
{
    el->tb.next = *list;
    *list = el;
}

static int tasklist_del(struct task **list, uint16_t pid)
{
    struct task *t = *list;
    struct task *p = NULL;

    while (t) {
        if (t->tb.pid == pid) {
            if (p == NULL)
                *list = t->tb.next;
            else
                p->tb.next = t->tb.next;
            return 0;
        }
        p = t;
        t = t->tb.next;
    }
    return -1;
}

static struct task *tasklist_get(struct task **list, uint16_t pid)
{
    struct task *t = *list;
    while (t) {
        if (t->tb.pid == pid)
            return t;
        t = t->tb.next;
    }
    return NULL;

}

static struct task *tasks_running = NULL;
static struct task *tasks_idling = NULL;

static void idling_to_running(volatile struct task *t)
{
    if (tasklist_del(&tasks_idling, t->tb.pid) == 0)
        tasklist_add(&tasks_running, t);
}

static void running_to_idling(volatile struct task *t)
{
    if (t->tb.pid < 1)
        return;
    if (tasklist_del(&tasks_running, t->tb.pid) == 0)
        tasklist_add(&tasks_idling, t);
}

static int task_filedesc_del_from_task(struct task *t, int fd);
static void task_destroy(struct task *t)
{
    int i;
    for (i = 0; i < t->tb.n_files; i++) {
        task_filedesc_del_from_task(t, i);
    }
    tasklist_del(&tasks_idling, t->tb.pid);
    kfree(t->tb.filedesc);
    if (t->tb.arg) {
        char **arg = (char **)(t->tb.arg);
        i = 0;
        while(arg[i]) {
            f_free(arg[i]);
            i++;
        }
    }
    f_free(t->tb.arg);
    task_space_free(t);
    number_of_tasks--;
}

volatile struct task *_cur_task = NULL;


static int next_pid(void)
{
    static unsigned int next_available = 0;
    uint16_t ret = (uint16_t)((next_available) & 0xFFFF);
    next_available++;
    if (next_available > 0xFFFF) {
        next_available = 2;
    }
    while(tasklist_get(&tasks_idling, next_available) || tasklist_get(&tasks_running, next_available))
        next_available++;
    return ret;
}

/********************************/
/* Handling of file descriptors */
/********************************/
/********************************/
/********************************/
/**/
/**/
/**/
static int task_filedesc_add_to_task(volatile struct task *t, struct fnode *f)
{
    int i;
    void *re;
    if (!t || !f)
        return -EINVAL;
    for (i = 0; i < t->tb.n_files; i++) {
        if (t->tb.filedesc[i].fno == NULL) {
            t->tb.filedesc[i].fno = f;
            f->usage++;
            return i;
        }
    }
    t->tb.n_files++;
    re = (void *)krealloc(t->tb.filedesc, t->tb.n_files * sizeof(struct filedesc));
    if (!re)
        return -1;
    t->tb.filedesc = re;
    memset(&(t->tb.filedesc[t->tb.n_files - 1]), 0, sizeof(struct filedesc));
    t->tb.filedesc[t->tb.n_files - 1].fno = f;
    f->usage++;
    return t->tb.n_files - 1;
}

int task_filedesc_add(struct fnode *f)
{
    return task_filedesc_add_to_task(_cur_task, f);
}

static int task_filedesc_del_from_task(struct task *t, int fd)
{
    if (!t)
        return -EINVAL;
    if (!t->tb.filedesc[fd].fno)
        return -ENOENT;
    t->tb.filedesc[fd].fno->usage--;
    t->tb.filedesc[fd].fno = NULL;
}

int task_filedesc_del(int fd)
{
    return task_filedesc_del_from_task(_cur_task, fd);
}

int task_fd_setmask(int fd, uint32_t mask)
{
    struct fnode *fno = _cur_task->tb.filedesc[fd].fno;
    if (!fno)
        return -EINVAL;

    if ((mask & O_ACCMODE) != O_RDONLY) {
        if ((fno->flags & FL_WRONLY)== 0)
            return -EPERM;
    }

    _cur_task->tb.filedesc[fd].mask = mask;
    return 0;
}

uint32_t task_fd_getmask(int fd)
{
    if (_cur_task->tb.filedesc[fd].fno)
        return _cur_task->tb.filedesc[fd].mask;
    return 0;
}

struct fnode *task_filedesc_get(int fd)
{
    volatile struct task *t = _cur_task;
    if (fd < 0)
        return NULL;
    if (fd >= t->tb.n_files)
        return NULL;
    if (!t)
        return NULL;
    if (!t->tb.filedesc || (( t->tb.n_files - 1) < fd))
        return NULL;
    if (t->tb.filedesc[fd].fno == NULL)
        return NULL;
    return t->tb.filedesc[fd].fno;
}

int task_fd_readable(int fd)
{
    return 1;
}

int task_fd_writable(int fd)
{
    if (!task_filedesc_get(fd) || ((_cur_task->tb.filedesc[fd].mask & O_ACCMODE) == O_RDONLY))
        return 0;
    return 1;
}


int sys_dup_hdlr(int fd)
{
    volatile struct task *t = _cur_task;
    struct fnode *f = task_filedesc_get(fd);
    int newfd = -1;
    if (!f)
        return -1;
    return task_filedesc_add(f);
}

int sys_dup2_hdlr(int fd, int newfd)
{
    volatile struct task *t = _cur_task;
    struct fnode *f = task_filedesc_get(fd);
    if (newfd < 0)
        return -1;
    if (newfd == fd)
        return -1;
    if (!f)
        return -1;
    if (newfd >= t->tb.n_files)
        return -1;
    if (t->tb.filedesc[newfd].fno != NULL)
        task_filedesc_del(newfd);
    t->tb.filedesc[newfd].fno = f;
    return newfd;
}

/********************************/
/*            Signals           */
/********************************/
/********************************/
/********************************/
/**/
/**/
/**/
static void check_pending_signals(volatile struct task *t);


static int add_handler(volatile struct task *t, int signo, void (*hdlr)(int), uint32_t mask)
{
    
    struct task_handler *sighdlr;
    if (!t || (t->tb.pid < 1))
        return -EINVAL;

    sighdlr = kalloc(sizeof(struct task_handler));
    if (!sighdlr)
        return -ENOMEM;

    sighdlr->signo = signo;
    sighdlr->hdlr = hdlr;
    sighdlr->mask = mask;
    sighdlr->next = t->tb.sighdlr;
    t->tb.sighdlr = sighdlr;
    check_pending_signals(t);
    return 0;
}

static int del_handler(struct task *t, int signo)
{
    struct task_handler *sighdlr;
    struct task_handler *prev = NULL;
    if (!t || (t->tb.pid < 1))
        return -EINVAL;

    sighdlr = t->tb.sighdlr;
    while(sighdlr) {
        if (sighdlr->signo == signo) {
            if (prev == NULL) {
                t->tb.sighdlr = sighdlr->next;
            } else {
                prev->next = sighdlr->next;
            }
            kfree(sighdlr);
            check_pending_signals(t);
            return 0;
        }
        prev = sighdlr;
        sighdlr = sighdlr->next;
    }
    return -ESRCH;
}

void task_terminate(int pid);

static int catch_signal(volatile struct task *t, int signo, sigset_t orig_mask)
{
    int i;
    struct task_handler *sighdlr;
    struct task_handler *h = NULL;

    if (!t || (t->tb.pid < 1))
        return -EINVAL;

    if ((t->tb.state == TASK_ZOMBIE) || (t->tb.state == TASK_OVER))
        return -ESRCH;

    if (((1 << signo) & t->tb.sigmask) && (h->hdlr != SIG_IGN))
    {
        /* Signal is blocked via t->tb.sigmask */
        t->tb.sigpend |= (1 << signo);
        return 0;
    }

    /* Reset signal, if pending, as it's going to be handled. */
    t->tb.sigpend &= ~(1 << signo);

    sighdlr = t->tb.sighdlr;
    while(sighdlr) {
        if (signo == sighdlr->signo)
            h = sighdlr;
        sighdlr = sighdlr->next;
    }

    if ((h) && (signo != SIGKILL) && (signo != SIGSEGV)) {
        /* Handler is present */
        if (h->hdlr == SIG_IGN)
            return 0;

        if (_cur_task == t)
        {
            h->hdlr(signo); 
        } else {
            /* Execute signal handler on top of the current task stack */
            volatile struct nvic_stack_frame *nvic = t->tb.sp + EXTRA_FRAME_SIZE;
            nvic->pc = (uint32_t)h->hdlr;
            nvic->r0 = (uint32_t)signo;
            /* XXX: In order to use per-sigaction sa_mask, we need to set 
             * t->tb.sigmask here, and restore it in some way before the 
             * handler returns to nvic->lr.
             */
            task_resume(t->tb.pid);
        }
    } else {
        /* Handler not present: SIG_DFL */
        if (signo != SIGCHLD) {
            task_terminate(t->tb.pid);
        } else {
            task_resume(t->tb.pid);
        }
    }
    return 0;
}

static void check_pending_signals(volatile struct task *t)
{
    int i;
    t->tb.sigpend &= ~(t->tb.sigmask);
    while (t->tb.sigpend != 0u) {
        for (i = 1; i < SIGMAX; i++) {
            if ((1 << i) & t->tb.sigpend)
                catch_signal(t, i, t->tb.sigmask);
        }
    }
}

int sys_sigaction_hdlr(int arg1, int arg2, int arg3, int arg4, int arg5)
{
    struct sigaction *sa = (struct sigaction *)arg2;
    struct sigaction *sa_old = (struct sigaction *)arg3;
    
    if (_cur_task->tb.pid < 1)
        return -EINVAL;

    if (arg1 >= SIGMAX || arg1 < 1)
        return -EINVAL;

    /* TODO: Populate sa_old */
    add_handler(_cur_task, arg1, sa->sa_handler, sa->sa_mask);
    return 0; 
}

int sys_sigprocmask_hdlr(int how, const sigset_t *set, sigset_t *oldset)
{
    if (set  && (
                (how != SIG_SETMASK) && 
                (how != SIG_BLOCK) && 
                (how != SIG_UNBLOCK)
                ))
        return -EINVAL;

    if (!set && !oldset)
        return -EINVAL;

    if (oldset)
        *oldset = _cur_task->tb.sigmask;

    if (set) {
        if (how == SIG_SETMASK)
            _cur_task->tb.sigmask = *set;
        else if (how == SIG_BLOCK)
            _cur_task->tb.sigmask |= *set;
        else  
            _cur_task->tb.sigmask &= ~(*set);
        check_pending_signals(_cur_task);
    }
    return 0;
}

int sys_sigsuspend_hdlr(const sigset_t *mask)
{
    uint32_t orig_mask = _cur_task->tb.sigmask;
    if (!mask)
        return -EINVAL;

    _cur_task->tb.sigmask = ~(*mask);
    task_suspend();
    _cur_task->tb.sigmask = orig_mask;

    /* Success. */
    return -EINTR;
}


/********************************/
/*           Scheduler          */
/********************************/
/********************************/
/********************************/
/**/
/**/
/**/
struct fnode *task_getcwd(void)
{
    return _cur_task->tb.cwd;
}

void task_chdir(struct fnode *f)
{
    _cur_task->tb.cwd = f;
}

static __inl int in_kernel(void)
{
    return (_cur_task->tb.pid == 0);
}

static __inl void * msp_read(void)
{
    void * ret=NULL;
    asm volatile ("mrs %0, msp" : "=r" (ret));
    return ret;
}

static __inl void * psp_read(void)
{
    void * ret=NULL;
    asm volatile ("mrs %0, psp" : "=r" (ret));
    return ret;
}

static __inl void task_switch(void)
{
    int i, pid = _cur_task->tb.pid;
    volatile struct task *t = _cur_task;

    if (((t->tb.state != TASK_RUNNING) && (t->tb.state != TASK_RUNNABLE)) || (t->tb.next == NULL))
        t = tasks_running;
    else
        t = t->tb.next;
    t->tb.timeslice = TIMESLICE(t);
    t->tb.state = TASK_RUNNING;
    _cur_task = t;
}

int scheduler_ntasks(void)
{
    return number_of_tasks;
}

int scheduler_task_state(int pid)
{
    struct task *t = tasklist_get(&tasks_running, pid);
    if (!t) 
        t = tasklist_get(&tasks_idling, pid);
    if (t)
        return t->tb.state;
    else return TASK_OVER;
}

unsigned scheduler_stack_used(int pid)
{
    struct task *t = tasklist_get(&tasks_running, pid);
    if (!t) 
        t = tasklist_get(&tasks_idling, pid);
    if (t)
        return SCHEDULER_STACK_SIZE - ((char *)t->tb.sp - (char *)t->tb.cur_stack);
    else return 0;
}

char * scheduler_task_name(int pid)
{
    struct task *t = tasklist_get(&tasks_running, pid);
    if (!t) 
        t = tasklist_get(&tasks_idling, pid);
    if (t)
        return t->tb.name;
    else return NULL;
}

uint16_t scheduler_get_cur_pid(void)
{
    if (!_cur_task)
        return 0;
    return _cur_task->tb.pid;
}

uint16_t scheduler_get_cur_ppid(void)
{
    if (!_cur_task)
        return 0;
    return _cur_task->tb.ppid;
}

int task_running(void)
{
    return (_cur_task->tb.state == TASK_RUNNING);
}

int task_timeslice(void) 
{
    return (--_cur_task->tb.timeslice);
}

void task_end(void)
{
    running_to_idling(_cur_task);
    _cur_task->tb.state = TASK_ZOMBIE;
    asm volatile ( "mov %0, r0" : "=r" (_cur_task->tb.exitval));
    while(1) {
        if (_cur_task->tb.ppid > 0)
            task_resume(_cur_task->tb.ppid);
        task_suspend();
    }
}

static void task_resume_vfork(int pid);

static void *task_pass_args(void *_args)
{
    char **args = (char **)_args;
    char **new = NULL;
    int i = 0, n = 0;
    if (!_args)
        return NULL;
    while(args[n] != NULL) {
        n++;
    }
    new = f_malloc(MEM_USER, (n + 1) * (sizeof(char*)));

    if (!new)
        return NULL;

    new[n] = NULL;

    for(i = 0; i < n; i++) {
        size_t l = strlen(args[i]);
        if (l > 0) { 
            new[i] = f_malloc(MEM_USER, l + 1);
            if (!new[i])
                break;
            memcpy(new[i], args[i], l + 1);
        }
    }
    return new;
}

static void task_create_real(volatile struct task *new, void (*init)(void *), void *arg, unsigned int prio, uint32_t r9val)
{
    struct nvic_stack_frame *nvic_frame;
    struct extra_stack_frame *extra_frame;
    uint8_t *sp;

    new->tb.start = init;
    new->tb.arg = task_pass_args(arg);
    new->tb.timeslice = TIMESLICE(new);
    new->tb.state = TASK_RUNNABLE;
    new->tb.sighdlr = NULL;

    if ((new->tb.flags & TASK_FLAG_VFORK) != 0) {
        struct task *pt = tasklist_get(&tasks_idling, new->tb.ppid);
        if (!pt)
            pt = tasklist_get(&tasks_running, new->tb.ppid);
        if (pt) {
            /* Restore parent's stack */
            memcpy((void *)pt->tb.cur_stack, (void *)&new->stack, SCHEDULER_STACK_SIZE);
            task_resume_vfork(pt->tb.pid);
        }
        new->tb.flags &= (~TASK_FLAG_VFORK);
    }

    
    /* stack memory */
    sp = (((uint8_t *)(&new->stack)) + SCHEDULER_STACK_SIZE - NVIC_FRAME_SIZE);
    new->tb.cur_stack = &new->stack;

    /* Stack frame is at the end of the stack space */
    nvic_frame = (struct nvic_stack_frame *) sp;
    memset(nvic_frame, 0, NVIC_FRAME_SIZE);
    nvic_frame->r0 = (uint32_t) new->tb.arg;
    nvic_frame->pc = (uint32_t) new->tb.start;
    nvic_frame->lr = (uint32_t) task_end;
    nvic_frame->psr = 0x01000000u;
    sp -= EXTRA_FRAME_SIZE;
    extra_frame = (struct extra_stack_frame *)sp;
    extra_frame->r9 = r9val;
    new->tb.sp = (uint32_t *)sp;
} 

int task_create(void (*init)(void *), void *arg, unsigned int prio, uint32_t pic, char * name)
{
    struct task *new;
    int i;

    irq_off();
    new = task_space_alloc(sizeof(struct task));
    if (!new) {
        return -ENOMEM;
    }
    new->tb.pid = next_pid();
    new->tb.ppid = scheduler_get_cur_pid();
    new->tb.prio = prio;
    new->tb.filedesc = NULL;
    new->tb.n_files = 0;
    new->tb.flags = 0;
    new->tb.cwd = fno_search("/");
    new->tb.name = name;

    /* Inherit cwd, file descriptors from parent */
    if (new->tb.ppid > 1) { /* Start from parent #2 */
        new->tb.cwd = task_getcwd();
        for (i = 0; i < _cur_task->tb.n_files; i++) {
            task_filedesc_add_to_task(new, _cur_task->tb.filedesc[i].fno);
            new->tb.filedesc[i].mask = _cur_task->tb.filedesc[i].mask;
        }
    } 

    new->tb.next = NULL;
    tasklist_add(&tasks_running, new);

    number_of_tasks++;
    task_create_real(new, init, arg, prio, pic);
    new->tb.state = TASK_RUNNABLE;
    irq_on();
    return new->tb.pid;
}

int scheduler_exec(void (*init)(void *), void *args, uint32_t pic, char * name)
{
    volatile struct task *t = _cur_task;
    t->tb.name = name;
    task_create_real(t, init, (void *)args, t->tb.prio, pic);
    //asm volatile ("msr "PSP", %0" :: "r" (_cur_task->tb.sp + EXTRA_FRAME_SIZE));
    asm volatile ("msr "PSP", %0" :: "r" (_cur_task->tb.sp));
    _cur_task->tb.state = TASK_RUNNING;
    mpu_task_on((void *)(((uint32_t)_cur_task->tb.cur_stack) - (sizeof(struct task_block) + F_MALLOC_OVERHEAD) ));
    return 0;
}

int sys_execb_hdlr(uint32_t arg1, uint32_t arg2)
{
    return scheduler_exec((void (*)(void*))arg1, (void *)arg2, 0, "task");
}

static void task_suspend_to(int newstate);

int sys_vfork_hdlr(void)
{
    struct task *new;
    int i;
    uint32_t sp_off = (uint8_t *)_cur_task->tb.sp - (uint8_t *)_cur_task->tb.cur_stack;
    uint32_t vpid;

    irq_off();
    new = task_space_alloc(sizeof(struct task));
    if (!new) {
        return -ENOMEM;
    }
    vpid = next_pid();
    new->tb.pid = vpid;
    new->tb.ppid = scheduler_get_cur_pid();
    new->tb.prio = _cur_task->tb.prio;
    new->tb.filedesc = NULL;
    new->tb.n_files = 0;
    new->tb.flags = TASK_FLAG_VFORK;
    new->tb.cwd = task_getcwd();

    /* Inherit cwd, file descriptors from parent */
    if (new->tb.ppid > 1) { /* Start from parent #2 */
        for (i = 0; i < _cur_task->tb.n_files; i++) {
            task_filedesc_add_to_task(new, _cur_task->tb.filedesc[i].fno);
            new->tb.filedesc[i].mask = _cur_task->tb.filedesc[i].mask;
        }
        /* Inherit signal mask */
        new->tb.sigmask = _cur_task->tb.sigmask;
    } 

    new->tb.next = NULL;
    tasklist_add(&tasks_running, new);
    number_of_tasks++;

    /* Set parent's vfork retval by writing on stacked r0 */
    *((uint32_t *)(_cur_task->tb.sp + EXTRA_FRAME_SIZE)) = vpid;

    /* Copy parent's stack in own stack space, but don't use it:
     * sp remains in the parent's pool.
     * This will be restored upon exit/exec
     */
    memcpy(&new->stack, _cur_task->tb.cur_stack, SCHEDULER_STACK_SIZE);
    if (new != _cur_task) {
        new->tb.sp = _cur_task->tb.sp;
        new->tb.cur_stack = _cur_task->tb.cur_stack;
        new->tb.state = TASK_RUNNABLE;
    }
    irq_on();
    /* Vfork: Caller task suspends until child calls exec or exits */
    asm volatile ("msr "PSP", %0" :: "r" (new->tb.sp));
    task_suspend_to(TASK_FORKED);
    
    return vpid;
}

static __naked void save_kernel_context(void)
{
    asm volatile ("mrs r0, "MSP"           ");
    asm volatile ("stmdb r0!, {r4-r11}   ");
    asm volatile ("msr "MSP", r0           ");
    asm volatile ("isb");
    asm volatile ("bx lr                 ");
}

static __naked void save_task_context(void)
{
    asm volatile ("mrs r0, "PSP"           ");
    asm volatile ("stmdb r0!, {r4-r11}   ");
    asm volatile ("msr "PSP", r0           ");
    asm volatile ("isb");
    asm volatile ("bx lr                 ");
}


static uint32_t runnable = RUN_HANDLER;

static __naked void restore_kernel_context(void)
{
    asm volatile ("mrs r0, "MSP"          ");
    asm volatile ("ldmfd r0!, {r4-r11}  ");
    asm volatile ("msr "MSP", r0          ");
    asm volatile ("isb");
    asm volatile ("bx lr                 ");
}

static __naked void restore_task_context(void)
{
    asm volatile ("mrs r0, "PSP"          ");
    asm volatile ("ldmfd r0!, {r4-r11}  ");
    asm volatile ("msr "PSP", r0          ");
    asm volatile ("isb");
    asm volatile ("bx lr                 ");
}


/* C ABI cannot mess with the stack, we will */
void __naked  pend_sv_handler(void)
{
    /* save current context on current stack */
    if (in_kernel()) {
        save_kernel_context();
        asm volatile ("mrs %0, "MSP"" : "=r" (_top_stack));
        asm volatile ("isb");
    } else {
        save_task_context();
        asm volatile ("mrs %0, "PSP"" : "=r" (_top_stack));
        asm volatile ("isb");
    }

    asm volatile ("isb");


    /* save current SP to TCB */

    _cur_task->tb.sp = _top_stack;
    if (_cur_task->tb.state == TASK_RUNNING)
        _cur_task->tb.state = TASK_RUNNABLE;

    /* choose next task */
    task_switch();
    
    if (((int)(_cur_task->tb.sp) - (int)(&_cur_task->stack)) < STACK_THRESHOLD) {
        kprintf("PendSV: Process %d is running out of stack space!\n", _cur_task->tb.pid);
    }

    /* write new stack pointer and restore context */
    if (in_kernel()) {
        asm volatile ("msr "MSP", %0" :: "r" (_cur_task->tb.sp));
        asm volatile ("isb");
        asm volatile ("msr CONTROL, %0" :: "r" (0x00));
        asm volatile ("isb");
        restore_kernel_context();
        runnable = RUN_KERNEL;
    } else {
        mpu_task_on((void *)(((uint32_t)_cur_task->tb.cur_stack) - (sizeof(struct task_block) + F_MALLOC_OVERHEAD) ));
        asm volatile ("msr "PSP", %0" :: "r" (_cur_task->tb.sp));
        asm volatile ("isb");
        asm volatile ("msr CONTROL, %0" :: "r" (0x01));
        asm volatile ("isb");
        restore_task_context();
        runnable = RUN_USER;
    }

    /* Set return value selected by the restore procedure */ 
    asm volatile ("mov lr, %0" :: "r" (runnable));

    /* return (function is naked) */ 
    asm volatile ("bx lr          \n" );
}

void __inl pendsv_enable(void)
{
   *((uint32_t volatile *)0xE000ED04) = 0x10000000; 
}

void kernel_task_init(void)
{
    /* task0 = kernel */
    irq_off();
    kernel->tb.sp = msp_read(); // SP needs to be current SP
    kernel->tb.pid = next_pid();
    kernel->tb.ppid = scheduler_get_cur_pid();
    kernel->tb.prio = 0;
    kernel->tb.start = NULL;
    kernel->tb.arg = NULL;
    kernel->tb.filedesc = NULL;
    kernel->tb.n_files = 0;
    kernel->tb.timeslice = TIMESLICE(kernel);
    kernel->tb.state = TASK_RUNNABLE;
    kernel->tb.cwd = fno_search("/");
    kernel->tb.state = TASK_RUNNABLE;
    kernel->tb.next = NULL;
    tasklist_add(&tasks_running, kernel);
    irq_on();

    /* Set kernel as current task */
    _cur_task = kernel;
}



static void task_suspend_to(int newstate)
{
    if (_cur_task->tb.pid < 1)
        return;
    running_to_idling(_cur_task);
    if (_cur_task->tb.state == TASK_RUNNABLE || _cur_task->tb.state == TASK_RUNNING) {
        _cur_task->tb.timeslice = 0;
    }
    _cur_task->tb.state = newstate;
    schedule();
}

void task_suspend(void) {
    return task_suspend_to(TASK_WAITING);
}


void task_resume(int pid)
{
    struct task *t = tasklist_get(&tasks_idling, pid);
    if ((t) && t->tb.state == TASK_WAITING) {
        idling_to_running(t);
        t->tb.state = TASK_RUNNABLE;
    }
}

static void task_resume_vfork(int pid)
{
    struct task *t = tasklist_get(&tasks_idling, pid);
    if ((t) && t->tb.state == TASK_FORKED) {
        idling_to_running(t);
        t->tb.state = TASK_RUNNABLE;
    }
}

void task_terminate(int pid)
{
    struct task *t = tasklist_get(&tasks_running, pid);
    if (!t) 
        t = tasklist_get(&tasks_idling, pid);
    else
        running_to_idling(t);

    if (t) {
        t->tb.state = TASK_ZOMBIE;
        t->tb.timeslice = 0;

        if (t->tb.ppid > 0) {
            if (t->tb.flags & TASK_FLAG_VFORK) {
                struct task *pt = tasklist_get(&tasks_idling, t->tb.ppid);
                if (!pt)
                    pt = tasklist_get(&tasks_running, t->tb.ppid);
                /* Restore parent's stack */
                if (pt) {
                    memcpy((void *)pt->tb.cur_stack, (void *)&_cur_task->stack, SCHEDULER_STACK_SIZE);
                    t->tb.flags &= ~TASK_FLAG_VFORK;
                }
                task_resume_vfork(t->tb.ppid);
            }
            sys_kill_hdlr(t->tb.ppid, SIGCHLD);
        }
    }
}

static void sleepy_task_wakeup(uint32_t now, void *arg)
{
    int pid = (int)arg;
    task_resume(pid);
}

int sys_sleep_hdlr(uint32_t arg1, uint32_t arg2, uint32_t arg3, uint32_t arg4, uint32_t arg5)
{
    uint32_t pid = (uint32_t)scheduler_get_cur_pid();
    uint32_t timeout = jiffies + arg1;

    if (arg1 < 0)
        return -EINVAL;

    if (pid > 0) {
        ktimer_add(arg1, sleepy_task_wakeup, (void *)pid);
        if (timeout < jiffies) 
            return 0;

        task_suspend();
    }
    return 0;
}

int sys_thread_join_hdlr(uint32_t arg1, uint32_t arg2, uint32_t arg3, uint32_t arg4, uint32_t arg5)
{
    int to_arg = (int)arg2;
    uint32_t timeout;
    struct task *t = NULL; 
    uint32_t pid;

    if (arg1 <= 1)
        return -EINVAL;

    t = tasklist_get(&tasks_running, arg1);
    if (!t)
        t = tasklist_get(&tasks_idling, arg1);

    if (!t || _cur_task->tb.pid == arg1 || t->tb.ppid != _cur_task->tb.pid)
        return -EINVAL;

    if (t->tb.state == TASK_ZOMBIE) {
        t->tb.state = TASK_OVER;
        task_destroy(t);
        return 0; /* TODO: get task return value from stacked NVIC frame -> r0 */
    }

    if (to_arg == 0)
        return -EINVAL;

    if (to_arg > 0)  {
        pid = _cur_task->tb.pid;
        timeout = jiffies + to_arg;
        ktimer_add(to_arg, sleepy_task_wakeup, (void *)pid);
        if (timeout < jiffies)
            return -ETIMEDOUT;
    }
    task_suspend();
    return SYS_CALL_AGAIN;
}

int sys_waitpid_hdlr(uint32_t arg1, uint32_t arg2, uint32_t arg3)
{
    int *status = (int *)arg2;
    struct task *t = NULL;
    int pid = (int)arg1;
    int options = (int) arg3;
    if (pid == 0)
        return -EINVAL;

    if (pid < -1)
        return -ENOSYS;

    if (pid != -1) {
        t = tasklist_get(&tasks_running, pid);
        /* Check if pid is running, but it's not a child */
        if (t) {
            if (t->tb.ppid != _cur_task->tb.ppid)
                return -ESRCH;
            else {
                if ((options & WNOHANG) != 0)
                    return 0;
                task_suspend();
                return SYS_CALL_AGAIN;
            }
        }

        t = tasklist_get(&tasks_idling, pid);
        if (!t || (t->tb.ppid != _cur_task->tb.pid))
            return -ESRCH;
        if (t->tb.state == TASK_ZOMBIE)
            goto child_found;
        task_suspend();
        return SYS_CALL_AGAIN;
    }
    
    /* wait for all (pid = -1) */
    t = tasks_idling;
    while (t) {
        if ((t->tb.state == TASK_ZOMBIE) && (t->tb.ppid == _cur_task->tb.pid))
            goto child_found;
        t = t->tb.next;
    }
    task_suspend();
    return SYS_CALL_AGAIN;

child_found:
    if (arg2){
        *((int *)arg2) = t->tb.exitval;
    }
    pid = t->tb.pid;
    t->tb.state = TASK_OVER;
    task_destroy(t);
    return pid;
}


int sys_kill_hdlr(uint32_t arg1, uint32_t arg2, uint32_t arg3, uint32_t arg4, uint32_t arg5)
{
    struct task *t = tasklist_get(&tasks_idling, arg1);
    if (!t)
        t = tasklist_get(&tasks_running, arg1);
    if (!t)
        return -ESRCH;
    return catch_signal(t, arg2, t->tb.sigmask);
}

int sys_exit_hdlr(uint32_t arg1, uint32_t arg2, uint32_t arg3, uint32_t arg4, uint32_t arg)
{
    _cur_task->tb.exitval = (int)arg1;
    task_terminate(_cur_task->tb.pid);
}

int task_segfault(uint32_t address, uint32_t instruction, int flags)
{
    char segv_msg[128] = "Memory fault: process (pid=";
    if (in_kernel())
        return -1;
    if (_cur_task->tb.state == TASK_ZOMBIE)
        return 0;
    if ((_cur_task->tb.n_files > 2) &&  _cur_task->tb.filedesc[2].fno->owner->ops.write) {
        strcat(segv_msg, pid_str(_cur_task->tb.pid));
        if (flags == MEMFAULT_ACCESS) {
            strcat(segv_msg, ") attempted access to memory at ");
            strcat(segv_msg, x_str(address));
        }
        if (flags == MEMFAULT_DOUBLEFREE) {
            strcat(segv_msg, ") attempted double free");
        }
        strcat(segv_msg, ". Killed.\r\n");
        _cur_task->tb.filedesc[2].fno->owner->ops.write(_cur_task->tb.filedesc[2].fno, segv_msg, strlen(segv_msg));
    }
    task_terminate(_cur_task->tb.pid);
    return 0;
}

static uint32_t *a4 = NULL;
static uint32_t *a5 = NULL;
struct extra_stack_frame *stored_extra = NULL;
struct extra_stack_frame *copied_extra = NULL;

int __attribute__((naked)) sv_call_handler(uint32_t n, uint32_t arg1, uint32_t arg2, uint32_t arg3, uint32_t arg4, uint32_t arg5)
{
    if (n >= _SYSCALLS_NR)
        return -1;
    if (sys_syscall_handlers[n] == NULL)
        return -1;
    irq_off();

    save_task_context();
    asm volatile ("mrs %0, "PSP"" : "=r" (_top_stack));

    /* save current context on current stack */
    /*
    copied_extra = (struct extra_stack_frame *)_top_stack - EXTRA_FRAME_SIZE;
    stored_extra = (struct extra_stack_frame *)_top_stack + NVIC_FRAME_SIZE;
    memcpy(copied_extra, stored_extra, EXTRA_FRAME_SIZE);
    */


    /* save current SP to TCB */
    _cur_task->tb.sp = _top_stack;

    a4 = (uint32_t *)((uint8_t *)_cur_task->tb.sp + (EXTRA_FRAME_SIZE + NVIC_FRAME_SIZE));
    a5 = (uint32_t *)((uint8_t *)_cur_task->tb.sp + (EXTRA_FRAME_SIZE + NVIC_FRAME_SIZE + 4));

    /* Execute syscall */
    volatile int retval;
    int (*call)(uint32_t arg1, uint32_t arg2, uint32_t arg3, uint32_t arg4, uint32_t arg5) = NULL;


    call = sys_syscall_handlers[n];
    retval = call(arg1, arg2, arg3, *a4, *a5);

    /* Exec does not have a return value, and will use r0 as args for main()*/
    if ((call != sys_syscall_handlers[SYS_EXECB])
            && (call != sys_syscall_handlers[SYS_EXEC])
       )
        asm volatile ( "mov %0, r0" : "=r" 
            (*((uint32_t *)(_cur_task->tb.sp + EXTRA_FRAME_SIZE))) );
    irq_on();

    if (_cur_task->tb.state != TASK_RUNNING) {
        task_switch();
    }

    /* write new stack pointer and restore context */
    if (in_kernel()) {
        asm volatile ("msr "MSP", %0" :: "r" (_cur_task->tb.sp));
        asm volatile ("isb");
        asm volatile ("msr CONTROL, %0" :: "r" (0x00));
        asm volatile ("isb");
        restore_kernel_context();
        runnable = RUN_KERNEL;
    } else {
        mpu_task_on((void *)(((uint32_t)_cur_task->tb.cur_stack) - (sizeof(struct task_block) + F_MALLOC_OVERHEAD) ));
        asm volatile ("msr "PSP", %0" :: "r" (_cur_task->tb.sp));
        asm volatile ("isb");
        asm volatile ("msr CONTROL, %0" :: "r" (0x01));
        asm volatile ("isb");
        restore_task_context();
        runnable = RUN_USER;
    }

    /* Set return value selected by the restore procedure */ 
    asm volatile ("mov lr, %0" :: "r" (runnable));

    /* return (function is naked) */ 
    asm volatile ( "bx lr");
}
