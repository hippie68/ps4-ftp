#ifndef KERNEL_UTILS_H
#define KERNEL_UTILS_H

#include "fw_defines.h"
#include "ps4.h"

#define printf_notification(...)                       \
  do {                                                 \
    char message[256];                                 \
    snprintf(message, sizeof(message), ##__VA_ARGS__); \
    systemMessage(message);                            \
  } while (0)

struct auditinfo_addr {
  char useless[184];
};

struct ucred {
  uint32_t useless1;
  uint32_t cr_uid;
  uint32_t cr_ruid;
  uint32_t useless2;
  uint32_t useless3;
  uint32_t cr_rgid;
  uint32_t useless4;
  void *useless5;
  void *useless6;
  void *cr_prison;
  void *useless7;
  uint32_t useless8;
  void *useless9[2];
  void *useless10;
  struct auditinfo_addr useless11;
  uint32_t *cr_groups;
  uint32_t useless12;
};

struct filedesc {
  void *useless1[3];
  void *fd_rdir;
  void *fd_jdir;
};

struct proc {
  char useless[64];
  struct ucred *p_ucred;
  struct filedesc *p_fd;
};

struct thread {
  void *useless;
  struct proc *td_proc;
};

struct kpayload_get_fw_version_info {
  uint64_t uaddr;
};

struct kpayload_get_fw_version_args {
  void *syscall_handler;
  struct kpayload_get_fw_version_info *kpayload_get_fw_version_info;
};

struct kpayload_jailbreak_info {
  uint64_t fw_version;
};

struct kpayload_jailbreak_args {
  void *syscall_handler;
  struct kpayload_jailbreak_info *kpayload_jailbreak_info;
};


uint64_t get_fw_version(void);
int jailbreak(uint64_t fw_version);

#endif
