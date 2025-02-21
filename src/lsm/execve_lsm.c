#include <stdio.h>
#include <stdlib.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

int main(int argc, char **argv)
{
    struct bpf_object *obj;
    int prog_fd;
    int ret;

    // 加载 eBPF 程序
    obj = bpf_object__open("execve_lsm.bpf.o");
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open eBPF object: %s\n", strerror(errno));
        return 1;
    }

    // 加载 eBPF 程序到内核
    ret = bpf_object__load(obj);
    if (ret) {
        fprintf(stderr, "Failed to load eBPF object: %s\n", strerror(-ret));
        return 1;
    }

    // 获取 eBPF 程序的 fd
    prog_fd = bpf_program__fd(bpf_object__find_program_by_name(obj, "lsm_bprm_check_security"));
    if (prog_fd < 0) {
        fprintf(stderr, "Failed to find eBPF program: %s\n", strerror(-prog_fd));
        return 1;
    }

    // 将 eBPF 程序附加到 LSM 钩子,error
    ret = bpf_prog_attach(prog_fd, 0, BPF_LSM_MAC, 0);
    if (ret) {
        fprintf(stderr, "Failed to attach eBPF program: %s\n", strerror(-ret));
        return 1;
    }

    printf("eBPF program attached successfully\n");

    // 保持程序运行，以便 eBPF 程序继续工作
    while (1) {
        sleep(1);
    }

    bpf_object__close(obj);
    return 0;
}
