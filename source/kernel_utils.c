#include "kernel_utils.h"

#define X86_CR0_WP (1 << 16)

static inline __attribute__((always_inline)) uint64_t __readmsr(unsigned long __register) {
  unsigned long __edx;
  unsigned long __eax;
  __asm__("rdmsr"
          : "=d"(__edx), "=a"(__eax)
          : "c"(__register));
  return (((uint64_t)__edx) << 32) | (uint64_t)__eax;
}

static inline __attribute__((always_inline)) uint64_t readCr0(void) {
  uint64_t cr0;
  __asm__ volatile("movq %0, %%cr0"
                   : "=r"(cr0)
                   :
                   : "memory");
  return cr0;
}

static inline __attribute__((always_inline)) void writeCr0(uint64_t cr0) {
  __asm__ volatile("movq %%cr0, %0"
                   :
                   : "r"(cr0)
                   : "memory");
}

int kpayload_get_fw_version(struct thread *td, struct kpayload_get_fw_version_args *args) {
  void *kernel_base = 0;
  int (*copyout)(const void *kaddr, void *uaddr, size_t len) = 0;

  uint64_t fw_version = 0x666;

  if (!memcmp((char *)(&((uint8_t *)__readmsr(0xC0000082))[-K700_XFAST_SYSCALL]), (char[4]){0x7F, 0x45, 0x4C, 0x46}, 4)) {
    kernel_base = &((uint8_t *)__readmsr(0xC0000082))[-K700_XFAST_SYSCALL];
    if (!memcmp((char *)(kernel_base + K700_PRINTF), (char[12]){0x55, 0x48, 0x89, 0xE5, 0x53, 0x48, 0x83, 0xEC, 0x58, 0x48, 0x8D, 0x1D}, 12)) {
      fw_version = 0x700; // 7.00, 7.01, 7.02
      copyout = (void *)(kernel_base + K700_COPYOUT);
    } else if (!memcmp((char *)(kernel_base + K670_PRINTF), (char[12]){0x55, 0x48, 0x89, 0xE5, 0x53, 0x48, 0x83, 0xEC, 0x58, 0x48, 0x8D, 0x1D}, 12)) {
      fw_version = 0x670; // 6.70, 6.71, and 6.72
      copyout = (void *)(kernel_base + K670_COPYOUT);
    } else if (!memcmp((char *)(kernel_base + K620_PRINTF), (char[12]){0x55, 0x48, 0x89, 0xE5, 0x53, 0x48, 0x83, 0xEC, 0x58, 0x48, 0x8D, 0x1D}, 12)) {
      fw_version = 0x620; // 6.20
      copyout = (void *)(kernel_base + K620_COPYOUT);
    } else if (!memcmp((char *)(kernel_base + K600_PRINTF), (char[12]){0x55, 0x48, 0x89, 0xE5, 0x53, 0x48, 0x83, 0xEC, 0x58, 0x48, 0x8D, 0x1D}, 12)) {
      fw_version = 0x600; // 6.00 and 6.02
      copyout = (void *)(kernel_base + K600_COPYOUT);
    } else if (!memcmp((char *)(kernel_base + K555_PRINTF), (char[12]){0x55, 0x48, 0x89, 0xE5, 0x53, 0x48, 0x83, 0xEC, 0x58, 0x48, 0x8D, 0x1D}, 12)) {
      fw_version = 0x555; // 5.55 and 5.56
      copyout = (void *)(kernel_base + K555_COPYOUT);
    } +else if (!memcmp((char *)(kernel_base + K553_PRINTF), (char[12]){0x55, 0x48, 0x89, 0xE5, 0x53, 0x48, 0x83, 0xEC, 0x58, 0x48, 0x8D, 0x1D}, 12)) {
      fw_version = 0x553; // 5.53
      copyout = (void *)(kernel_base + K553_COPYOUT);
    } else if (!memcmp((char *)(kernel_base + K550_PRINTF), (char[12]){0x55, 0x48, 0x89, 0xE5, 0x53, 0x48, 0x83, 0xEC, 0x58, 0x48, 0x8D, 0x1D}, 12)) {
      fw_version = 0x550; // 5.50
      copyout = (void *)(kernel_base + K550_COPYOUT);
    } else if (!memcmp((char *)(kernel_base + K505_PRINTF), (char[12]){0x55, 0x48, 0x89, 0xE5, 0x53, 0x48, 0x83, 0xEC, 0x58, 0x48, 0x8D, 0x1D}, 12)) {
      fw_version = 0x505; // 5.05 and 5.07
      copyout = (void *)(kernel_base + K505_COPYOUT);
    } else if (!memcmp((char *)(kernel_base + K503_PRINTF), (char[12]){0x55, 0x48, 0x89, 0xE5, 0x53, 0x48, 0x83, 0xEC, 0x58, 0x48, 0x8D, 0x1D}, 12)) {
      fw_version = 0x503; // 5.03
      copyout = (void *)(kernel_base + K503_COPYOUT);
    } else if (!memcmp((char *)(kernel_base + K500_PRINTF), (char[12]){0x55, 0x48, 0x89, 0xE5, 0x53, 0x48, 0x83, 0xEC, 0x58, 0x48, 0x8D, 0x1D}, 12)) {
      fw_version = 0x500; // 5.00 and 5.01
      copyout = (void *)(kernel_base + K500_COPYOUT);
    }
  } else if (!memcmp((char *)(&((uint8_t *)__readmsr(0xC0000082))[-K470_XFAST_SYSCALL]), (char[4]){0x7F, 0x45, 0x4C, 0x46}, 4)) {
    kernel_base = &((uint8_t *)__readmsr(0xC0000082))[-K470_XFAST_SYSCALL];
    if (!memcmp((char *)(kernel_base + K470_PRINTF), (char[12]){0x55, 0x48, 0x89, 0xE5, 0x53, 0x48, 0x83, 0xEC, 0x58, 0x48, 0x8D, 0x1D}, 12)) {
      fw_version = 0x470; // 4.70
      copyout = (void *)(kernel_base + K470_COPYOUT);
    }
  } else if (!memcmp((char *)(&((uint8_t *)__readmsr(0xC0000082))[-K471_XFAST_SYSCALL]), (char[4]){0x7F, 0x45, 0x4C, 0x46}, 4)) {
    kernel_base = &((uint8_t *)__readmsr(0xC0000082))[-K471_XFAST_SYSCALL];
    if (!memcmp((char *)(kernel_base + K471_PRINTF), (char[12]){0x55, 0x48, 0x89, 0xE5, 0x53, 0x48, 0x83, 0xEC, 0x58, 0x48, 0x8D, 0x1D}, 12)) {
      fw_version = 0x471; // 4.71, 4.72, 4.73, and 4.74
      copyout = (void *)(kernel_base + K471_COPYOUT);
    }
  } else if (!memcmp((char *)(&((uint8_t *)__readmsr(0xC0000082))[-K450_XFAST_SYSCALL]), (char[4]){0x7F, 0x45, 0x4C, 0x46}, 4)) {
    kernel_base = &((uint8_t *)__readmsr(0xC0000082))[-K450_XFAST_SYSCALL];
    if (!memcmp((char *)(kernel_base + K450_PRINTF), (char[12]){0x55, 0x48, 0x89, 0xE5, 0x53, 0x48, 0x83, 0xEC, 0x58, 0x48, 0x8D, 0x1D}, 12)) {
      fw_version = 0x450; // 4.50 and 4.55
      copyout = (void *)(kernel_base + K450_COPYOUT);
    }
  } else if (!memcmp((char *)(&((uint8_t *)__readmsr(0xC0000082))[-K406_XFAST_SYSCALL]), (char[4]){0x7F, 0x45, 0x4C, 0x46}, 4)) {
    kernel_base = &((uint8_t *)__readmsr(0xC0000082))[-K406_XFAST_SYSCALL];
    if (!memcmp((char *)(kernel_base + K406_PRINTF), (char[12]){0x55, 0x48, 0x89, 0xE5, 0x53, 0x48, 0x83, 0xEC, 0x58, 0x48, 0x8D, 0x1D}, 12)) {
      // TODO: 4.06 and 4.07 overlap here even though other offsets to not
      fw_version = 0x406; // 4.06 and 4.07
      copyout = (void *)(kernel_base + K406_COPYOUT);
    }
  } else if (!memcmp((char *)(&((uint8_t *)__readmsr(0xC0000082))[-K405_XFAST_SYSCALL]), (char[4]){0x7F, 0x45, 0x4C, 0x46}, 4)) {
    kernel_base = &((uint8_t *)__readmsr(0xC0000082))[-K405_XFAST_SYSCALL];
    if (!memcmp((char *)(kernel_base + K405_PRINTF), (char[12]){0x55, 0x48, 0x89, 0xE5, 0x53, 0x48, 0x83, 0xEC, 0x58, 0x48, 0x8D, 0x1D}, 12)) {
      fw_version = 0x405; // 4.05
      copyout = (void *)(kernel_base + K405_COPYOUT);
    }
  } else if (!memcmp((char *)(&((uint8_t *)__readmsr(0xC0000082))[-K400_XFAST_SYSCALL]), (char[4]){0x7F, 0x45, 0x4C, 0x46}, 4)) {
    kernel_base = &((uint8_t *)__readmsr(0xC0000082))[-K400_XFAST_SYSCALL];
    if (!memcmp((char *)(kernel_base + K400_PRINTF), (char[12]){0x55, 0x48, 0x89, 0xE5, 0x53, 0x48, 0x83, 0xEC, 0x58, 0x48, 0x8D, 0x1D}, 12)) {
      fw_version = 0x400; // 4.00 and 4.01
      copyout = (void *)(kernel_base + K400_COPYOUT);
    }
  } else if (!memcmp((char *)(&((uint8_t *)__readmsr(0xC0000082))[-K370_XFAST_SYSCALL]), (char[4]){0x7F, 0x45, 0x4C, 0x46}, 4)) {
    kernel_base = &((uint8_t *)__readmsr(0xC0000082))[-K370_XFAST_SYSCALL];
    if (!memcmp((char *)(kernel_base + K370_PRINTF), (char[12]){0x55, 0x48, 0x89, 0xE5, 0x53, 0x48, 0x83, 0xEC, 0x58, 0x48, 0x8D, 0x1D}, 12)) {
      fw_version = 0x370; // 3.70
      copyout = (void *)(kernel_base + K370_COPYOUT);
    }
  } else if (!memcmp((char *)(&((uint8_t *)__readmsr(0xC0000082))[-K355_XFAST_SYSCALL]), (char[4]){0x7F, 0x45, 0x4C, 0x46}, 4)) {
    kernel_base = &((uint8_t *)__readmsr(0xC0000082))[-K355_XFAST_SYSCALL];
    if (!memcmp((char *)(kernel_base + K355_PRINTF), (char[12]){0x55, 0x48, 0x89, 0xE5, 0x53, 0x48, 0x83, 0xEC, 0x58, 0x48, 0x8D, 0x1D}, 12)) {
      fw_version = 0x355; // 3.55
      copyout = (void *)(kernel_base + K355_COPYOUT);
    }
  } else if (!memcmp((char *)(&((uint8_t *)__readmsr(0xC0000082))[-K350_XFAST_SYSCALL]), (char[4]){0x7F, 0x45, 0x4C, 0x46}, 4)) {
    kernel_base = &((uint8_t *)__readmsr(0xC0000082))[-K350_XFAST_SYSCALL];
    if (!memcmp((char *)(kernel_base + K350_PRINTF), (char[12]){0x55, 0x48, 0x89, 0xE5, 0x53, 0x48, 0x83, 0xEC, 0x58, 0x48, 0x8D, 0x1D}, 12)) {
      fw_version = 0x350; // 3.50
      copyout = (void *)(kernel_base + K350_COPYOUT);
    }
  } else {
    return -1;
  }

  uint64_t uaddr = args->kpayload_get_fw_version_info->uaddr;
  copyout(&fw_version, (uint64_t *)uaddr, 8);

  return 0;
}

int kpayload_jailbreak(struct thread *td, struct kpayload_jailbreak_args *args) {
  struct filedesc *fd;
  struct ucred *cred;
  fd = td->td_proc->p_fd;
  cred = td->td_proc->p_ucred;

  void *kernel_base;
  uint8_t *kernel_ptr;
  void **got_prison0;
  void **got_rootvnode;

  uint8_t *kmem;

  uint8_t *mmap_patch_1;
  uint8_t *mmap_patch_2;
  uint8_t *mmap_patch_3;

  uint64_t fw_version = args->kpayload_jailbreak_info->fw_version;

  if (fw_version == 0x350) {
    // 3.50
    kernel_base = &((uint8_t *)__readmsr(0xC0000082))[-K350_XFAST_SYSCALL];
    kernel_ptr = (uint8_t *)kernel_base;
    got_prison0 = (void **)&kernel_ptr[K350_PRISON_0];
    got_rootvnode = (void **)&kernel_ptr[K350_ROOTVNODE];

    mmap_patch_1 = &kernel_ptr[K350_MMAP_SELF_1];
    mmap_patch_2 = &kernel_ptr[K350_MMAP_SELF_2];
    mmap_patch_3 = &kernel_ptr[K350_MMAP_SELF_3];
  } else if (fw_version == 0x355) {
    // 3.55
    kernel_base = &((uint8_t *)__readmsr(0xC0000082))[-K355_XFAST_SYSCALL];
    kernel_ptr = (uint8_t *)kernel_base;
    got_prison0 = (void **)&kernel_ptr[K355_PRISON_0];
    got_rootvnode = (void **)&kernel_ptr[K355_ROOTVNODE];

    mmap_patch_1 = &kernel_ptr[K355_MMAP_SELF_1];
    mmap_patch_2 = &kernel_ptr[K355_MMAP_SELF_2];
    mmap_patch_3 = &kernel_ptr[K355_MMAP_SELF_3];
  } else if (fw_version == 0x370) {
    // 3.70
    kernel_base = &((uint8_t *)__readmsr(0xC0000082))[-K370_XFAST_SYSCALL];
    kernel_ptr = (uint8_t *)kernel_base;
    got_prison0 = (void **)&kernel_ptr[K370_PRISON_0];
    got_rootvnode = (void **)&kernel_ptr[K370_ROOTVNODE];

    mmap_patch_1 = &kernel_ptr[K370_MMAP_SELF_1];
    mmap_patch_2 = &kernel_ptr[K370_MMAP_SELF_2];
    mmap_patch_3 = &kernel_ptr[K370_MMAP_SELF_3];
  } else if (fw_version == 0x400) {
    // 4.00 and 4.01
    kernel_base = &((uint8_t *)__readmsr(0xC0000082))[-K400_XFAST_SYSCALL];
    kernel_ptr = (uint8_t *)kernel_base;
    got_prison0 = (void **)&kernel_ptr[K400_PRISON_0];
    got_rootvnode = (void **)&kernel_ptr[K400_ROOTVNODE];

    mmap_patch_1 = &kernel_ptr[K400_MMAP_SELF_1];
    mmap_patch_2 = &kernel_ptr[K400_MMAP_SELF_2];
    mmap_patch_3 = &kernel_ptr[K400_MMAP_SELF_3];
  } else if (fw_version == 0x405) {
    // 4.05
    kernel_base = &((uint8_t *)__readmsr(0xC0000082))[-K405_XFAST_SYSCALL];
    kernel_ptr = (uint8_t *)kernel_base;
    got_prison0 = (void **)&kernel_ptr[K405_PRISON_0];
    got_rootvnode = (void **)&kernel_ptr[K405_ROOTVNODE];

    mmap_patch_1 = &kernel_ptr[K405_MMAP_SELF_1];
    mmap_patch_2 = &kernel_ptr[K405_MMAP_SELF_2];
    mmap_patch_3 = &kernel_ptr[K405_MMAP_SELF_3];
  } else if (fw_version == 0x406) {
    // 4.06
    kernel_base = &((uint8_t *)__readmsr(0xC0000082))[-K406_XFAST_SYSCALL];
    kernel_ptr = (uint8_t *)kernel_base;
    got_prison0 = (void **)&kernel_ptr[K406_PRISON_0];
    got_rootvnode = (void **)&kernel_ptr[K406_ROOTVNODE];

    mmap_patch_1 = &kernel_ptr[K406_MMAP_SELF_1];
    mmap_patch_2 = &kernel_ptr[K406_MMAP_SELF_2];
    mmap_patch_3 = &kernel_ptr[K406_MMAP_SELF_3];
  } else if (fw_version == 0x407) {
    // 4.07
    kernel_base = &((uint8_t *)__readmsr(0xC0000082))[-K407_XFAST_SYSCALL];
    kernel_ptr = (uint8_t *)kernel_base;
    got_prison0 = (void **)&kernel_ptr[K407_PRISON_0];
    got_rootvnode = (void **)&kernel_ptr[K407_ROOTVNODE];

    mmap_patch_1 = &kernel_ptr[K407_MMAP_SELF_1];
    mmap_patch_2 = &kernel_ptr[K407_MMAP_SELF_2];
    mmap_patch_3 = &kernel_ptr[K407_MMAP_SELF_3];
  } else if (fw_version == 0x450) {
    // 4.50 and 4.55
    kernel_base = &((uint8_t *)__readmsr(0xC0000082))[-K450_XFAST_SYSCALL];
    kernel_ptr = (uint8_t *)kernel_base;
    got_prison0 = (void **)&kernel_ptr[K450_PRISON_0];
    got_rootvnode = (void **)&kernel_ptr[K450_ROOTVNODE];

    mmap_patch_1 = &kernel_ptr[K450_MMAP_SELF_1];
    mmap_patch_2 = &kernel_ptr[K450_MMAP_SELF_2];
    mmap_patch_3 = &kernel_ptr[K450_MMAP_SELF_3];
  } else if (fw_version == 0x470) {
    // 4.70
    kernel_base = &((uint8_t *)__readmsr(0xC0000082))[-K470_XFAST_SYSCALL];
    kernel_ptr = (uint8_t *)kernel_base;
    got_prison0 = (void **)&kernel_ptr[K470_PRISON_0];
    got_rootvnode = (void **)&kernel_ptr[K470_ROOTVNODE];

    mmap_patch_1 = &kernel_ptr[K470_MMAP_SELF_1];
    mmap_patch_2 = &kernel_ptr[K470_MMAP_SELF_2];
    mmap_patch_3 = &kernel_ptr[K470_MMAP_SELF_3];
  } else if (fw_version == 0x471) {
    // 4.71, 4.72, 4.73, and 4.74
    kernel_base = &((uint8_t *)__readmsr(0xC0000082))[-K471_XFAST_SYSCALL];
    kernel_ptr = (uint8_t *)kernel_base;
    got_prison0 = (void **)&kernel_ptr[K471_PRISON_0];
    got_rootvnode = (void **)&kernel_ptr[K471_ROOTVNODE];

    mmap_patch_1 = &kernel_ptr[K471_MMAP_SELF_1];
    mmap_patch_2 = &kernel_ptr[K471_MMAP_SELF_2];
    mmap_patch_3 = &kernel_ptr[K471_MMAP_SELF_3];
  } else if (fw_version == 0x500) {
    // 5.00 and 5.01
    kernel_base = &((uint8_t *)__readmsr(0xC0000082))[-K501_XFAST_SYSCALL];
    kernel_ptr = (uint8_t *)kernel_base;
    got_prison0 = (void **)&kernel_ptr[K500_PRISON_0];
    got_rootvnode = (void **)&kernel_ptr[K500_ROOTVNODE];

    mmap_patch_1 = &kernel_ptr[K500_MMAP_SELF_1];
    mmap_patch_2 = &kernel_ptr[K500_MMAP_SELF_2];
    mmap_patch_3 = &kernel_ptr[K500_MMAP_SELF_3];
  } else if (fw_version == 0x503) {
    // 5.03
    kernel_base = &((uint8_t *)__readmsr(0xC0000082))[-K503_XFAST_SYSCALL];
    kernel_ptr = (uint8_t *)kernel_base;
    got_prison0 = (void **)&kernel_ptr[K503_PRISON_0];
    got_rootvnode = (void **)&kernel_ptr[K503_ROOTVNODE];

    mmap_patch_1 = &kernel_ptr[K503_MMAP_SELF_1];
    mmap_patch_2 = &kernel_ptr[K503_MMAP_SELF_2];
    mmap_patch_3 = &kernel_ptr[K503_MMAP_SELF_3];
  } else if (fw_version == 0x505) {
    // 5.05 and 5.07
    kernel_base = &((uint8_t *)__readmsr(0xC0000082))[-K505_XFAST_SYSCALL];
    kernel_ptr = (uint8_t *)kernel_base;
    got_prison0 = (void **)&kernel_ptr[K505_PRISON_0];
    got_rootvnode = (void **)&kernel_ptr[K505_ROOTVNODE];

    mmap_patch_1 = &kernel_ptr[K505_MMAP_SELF_1];
    mmap_patch_2 = &kernel_ptr[K505_MMAP_SELF_2];
    mmap_patch_3 = &kernel_ptr[K505_MMAP_SELF_3];
  } else if (fw_version == 0x550) {
    // 5.50
    kernel_base = &((uint8_t *)__readmsr(0xC0000082))[-K550_XFAST_SYSCALL];
    kernel_ptr = (uint8_t *)kernel_base;
    got_prison0 = (void **)&kernel_ptr[K550_PRISON_0];
    got_rootvnode = (void **)&kernel_ptr[K550_ROOTVNODE];

    mmap_patch_1 = &kernel_ptr[K550_MMAP_SELF_1];
    mmap_patch_2 = &kernel_ptr[K550_MMAP_SELF_2];
    mmap_patch_3 = &kernel_ptr[K550_MMAP_SELF_3];
  } else if (fw_version == 0x553) {
    // 5.53
    kernel_base = &((uint8_t *)__readmsr(0xC0000082))[-K553_XFAST_SYSCALL];
    kernel_ptr = (uint8_t *)kernel_base;
    got_prison0 = (void **)&kernel_ptr[K553_PRISON_0];
    got_rootvnode = (void **)&kernel_ptr[K553_ROOTVNODE];

    mmap_patch_1 = &kernel_ptr[K553_MMAP_SELF_1];
    mmap_patch_2 = &kernel_ptr[K553_MMAP_SELF_2];
    mmap_patch_3 = &kernel_ptr[K553_MMAP_SELF_3];
  } else if (fw_version == 0x555) {
    // 5.55 and 5.56
    kernel_base = &((uint8_t *)__readmsr(0xC0000082))[-K555_XFAST_SYSCALL];
    kernel_ptr = (uint8_t *)kernel_base;
    got_prison0 = (void **)&kernel_ptr[K555_PRISON_0];
    got_rootvnode = (void **)&kernel_ptr[K555_ROOTVNODE];

    mmap_patch_1 = &kernel_ptr[K555_MMAP_SELF_1];
    mmap_patch_2 = &kernel_ptr[K555_MMAP_SELF_2];
    mmap_patch_3 = &kernel_ptr[K555_MMAP_SELF_3];
  } else if (fw_version == 0x600) {
    // 6.00 and 6.02
    kernel_base = &((uint8_t *)__readmsr(0xC0000082))[-K600_XFAST_SYSCALL];
    kernel_ptr = (uint8_t *)kernel_base;
    got_prison0 = (void **)&kernel_ptr[K600_PRISON_0];
    got_rootvnode = (void **)&kernel_ptr[K600_ROOTVNODE];

    mmap_patch_1 = &kernel_ptr[K600_MMAP_SELF_1];
    mmap_patch_2 = &kernel_ptr[K600_MMAP_SELF_2];
    mmap_patch_3 = &kernel_ptr[K600_MMAP_SELF_3];
  } else if (fw_version == 0x620) {
    // 6.20
    kernel_base = &((uint8_t *)__readmsr(0xC0000082))[-K620_XFAST_SYSCALL];
    kernel_ptr = (uint8_t *)kernel_base;
    got_prison0 = (void **)&kernel_ptr[K620_PRISON_0];
    got_rootvnode = (void **)&kernel_ptr[K620_ROOTVNODE];

    mmap_patch_1 = &kernel_ptr[K620_MMAP_SELF_1];
    mmap_patch_2 = &kernel_ptr[K620_MMAP_SELF_2];
    mmap_patch_3 = &kernel_ptr[K620_MMAP_SELF_3];
  } else if (fw_version == 0x670) {
    // 6.70, 6.71, and 6.72
    kernel_base = &((uint8_t *)__readmsr(0xC0000082))[-K670_XFAST_SYSCALL];
    kernel_ptr = (uint8_t *)kernel_base;
    got_prison0 = (void **)&kernel_ptr[K670_PRISON_0];
    got_rootvnode = (void **)&kernel_ptr[K670_ROOTVNODE];

    mmap_patch_1 = &kernel_ptr[K670_MMAP_SELF_1];
    mmap_patch_2 = &kernel_ptr[K670_MMAP_SELF_2];
    mmap_patch_3 = &kernel_ptr[K670_MMAP_SELF_3];
  } else if (fw_version == 0x700) {
    // 7.00, 7.01, 7.02
    kernel_base = &((uint8_t *)__readmsr(0xC0000082))[-K700_XFAST_SYSCALL];
    kernel_ptr = (uint8_t *)kernel_base;
    got_prison0 = (void **)&kernel_ptr[K700_PRISON_0];
    got_rootvnode = (void **)&kernel_ptr[K700_ROOTVNODE];

    mmap_patch_1 = &kernel_ptr[K700_MMAP_SELF_1];
    mmap_patch_2 = &kernel_ptr[K700_MMAP_SELF_2];
    mmap_patch_3 = &kernel_ptr[K700_MMAP_SELF_3];
  } else {
    return -1;
  }

  cred->cr_uid = 0;
  cred->cr_ruid = 0;
  cred->cr_rgid = 0;
  cred->cr_groups[0] = 0;

  cred->cr_prison = *got_prison0;
  fd->fd_rdir = fd->fd_jdir = *got_rootvnode;

  void *td_ucred = *(void **)(((char *)td) + 304);

  uint64_t *sonyCred = (uint64_t *)(((char *)td_ucred) + 96);
  *sonyCred = 0xffffffffffffffff;

  uint64_t *sceProcessAuthorityId = (uint64_t *)(((char *)td_ucred) + 88);
  *sceProcessAuthorityId = 0x3801000000000013;

  uint64_t *sceProcCap = (uint64_t *)(((char *)td_ucred) + 104);
  *sceProcCap = 0xffffffffffffffff;

  uint64_t cr0 = readCr0();
  writeCr0(cr0 & ~X86_CR0_WP);

  kmem = (uint8_t *)mmap_patch_1;
  kmem[0] = 0xB8;
  kmem[1] = 0x01;
  kmem[2] = 0x00;
  kmem[3] = 0x00;
  kmem[4] = 0x00;
  kmem[5] = 0xC3;

  kmem = (uint8_t *)mmap_patch_2;
  kmem[0] = 0xB8;
  kmem[1] = 0x01;
  kmem[2] = 0x00;
  kmem[3] = 0x00;
  kmem[4] = 0x00;
  kmem[5] = 0xC3;

  kmem = (uint8_t *)mmap_patch_3;
  kmem[0] = 0x31;
  kmem[1] = 0xC0;
  kmem[2] = 0x90;
  kmem[3] = 0x90;
  kmem[4] = 0x90;

  writeCr0(cr0);

  return 0;
}

uint64_t get_fw_version(void) {
  uint64_t fw_version = 0x666;
  uint64_t *fw_version_ptr = mmap(NULL, 8, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  struct kpayload_get_fw_version_info kpayload_get_fw_version_info;
  kpayload_get_fw_version_info.uaddr = (uint64_t)fw_version_ptr;
  kexec(&kpayload_get_fw_version, &kpayload_get_fw_version_info);
  memcpy(&fw_version, fw_version_ptr, 8);
  munmap(fw_version_ptr, 8);

  return fw_version;
}

int jailbreak(uint64_t fw_version) {
  struct kpayload_jailbreak_info kpayload_jailbreak_info;
  kpayload_jailbreak_info.fw_version = fw_version;
  kexec(&kpayload_jailbreak, &kpayload_jailbreak_info);

  return 0;
}
