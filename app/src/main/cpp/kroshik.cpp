#include <jni.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

struct cmdq_write_address_struct {
    uint32_t block_id;
    uint32_t offset;
    uint32_t value;
};
#define CMDQ_IOCTL_MAGIC 'x'
#define CMDQ_IOCTL_WRITE_ADDRESS _IOWR(CMDQ_IOCTL_MAGIC, 3, struct cmdq_write_address_struct)

#define BINDER_THREAD_EXIT _IOW('b', 6, __u32)

extern "C" {

JNIEXPORT jboolean JNICALL
Java_com_kostyfoss_kroshikroot_ExploitEngine_runMtkSuNative(JNIEnv *env, jclass clazz) {
    int mtk_fd = open("/dev/mtk_cmdq", O_RDONLY);
    if (mtk_fd < 0) {
        mtk_fd = open("/dev/mtk_disp", O_RDONLY);
    }
    if (mtk_fd < 0) {
        return JNI_FALSE;
    }
    struct cmdq_write_address_struct bad_cmd;
    bad_cmd.block_id = 0;
    bad_cmd.offset = 0;
    bad_cmd.value = 0x1337;
    int res = ioctl(mtk_fd, CMDQ_IOCTL_WRITE_ADDRESS, &bad_cmd);
    close(mtk_fd);
    return (res >= 0) ? JNI_TRUE : JNI_FALSE;
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
    int binder_fd = open("/dev/binder", O_RDONLY);
    if (binder_fd < 0) return JNI_FALSE;
    int err = ioctl(binder_fd, BINDER_THREAD_EXIT, NULL);
    close(binder_fd);
    return (err == 0) ? JNI_TRUE : JNI_FALSE;
}

}
