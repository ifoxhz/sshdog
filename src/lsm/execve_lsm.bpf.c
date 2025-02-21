//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
//#include <errno.h>

#define PATHLEN 256

char _license[] SEC("license") = "GPL";
#define EPERM 1 

SEC("lsm/bprm_check_security")
int BPF_PROG(lsm_bprm_check_security, struct linux_binprm *bprm) {
  char buf[PATHLEN];

  int len = bpf_probe_read_str(buf, sizeof(buf), bprm->filename);
    // 检查文件名是否为 "yong.sh"
  if (buf[2] == 'y' && buf[3] == 'o') {
        // 如果文件名是 "yong.sh"，则禁止执行
        bpf_printk("Blocked execution of %s\n", buf);
        return -EPERM;  // 返回权限错误，禁止执行
    }

  bpf_printk("Reject execution of %s command ", buf);
  return 0;
}
