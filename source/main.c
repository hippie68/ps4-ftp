#include "ps4.h"

#include "ftps4.h"

#define FTP_PORT 1337

int run;
int decrypt;

void custom_MTPROC(ftps4_client_info_t *client) {
  int result = mkdir("/mnt/proc", 0777);
  if (result < 0 && (*__error()) != 17) {
    ftps4_ext_client_send_ctrl_msg(client, "Failed to create /mnt/proc!" FTPS4_EOL);
    goto fail;
  }

  result = mount("procfs", "/mnt/proc", 0, NULL);
  if (result < 0) {
    ftps4_ext_client_send_ctrl_msg(client, "Failed to mount procfs!" FTPS4_EOL);
    goto fail;
  }

  ftps4_ext_client_send_ctrl_msg(client, "200 Mount success." FTPS4_EOL);
  return;

fail:
  ftps4_ext_client_send_ctrl_msg(client, "550 Could not mount!" FTPS4_EOL);
  return;
}

void custom_MTRW(ftps4_client_info_t *client) {
  if (mount_large_fs("/dev/da0x0.crypt", "/preinst", "exfatfs", "511", MNT_UPDATE) < 0) {
    goto fail;
  }
  if (mount_large_fs("/dev/da0x1.crypt", "/preinst2", "exfatfs", "511", MNT_UPDATE) < 0) {
    goto fail;
  }
  if (mount_large_fs("/dev/da0x4.crypt", "/system", "exfatfs", "511", MNT_UPDATE) < 0) {
    goto fail;
  }
  if (mount_large_fs("/dev/da0x5.crypt", "/system_ex", "exfatfs", "511", MNT_UPDATE) < 0) {
    goto fail;
  }
  /*
  if (mount_large_fs("/dev/da0x9.crypt", "/system_data", "exfatfs", "511", MNT_UPDATE) < 0) {
    goto fail;
  }
  if (mount_large_fs("/dev/md0", "/", "exfatfs", "511", MNT_UPDATE) < 0) {
    goto fail;
  }
  if (mount_large_fs("/dev/md0.crypt", "/", "exfatfs", "511", MNT_UPDATE) < 0) {
    goto fail;
  }
  */

  ftps4_ext_client_send_ctrl_msg(client, "200 Mount success." FTPS4_EOL);
  return;

fail:
  ftps4_ext_client_send_ctrl_msg(client, "550 Could not mount!" FTPS4_EOL);
}

void custom_DECRYPT(ftps4_client_info_t *client) {
  if (decrypt == 0) {
    ftps4_ext_client_send_ctrl_msg(client, "200 SELF decryption enabled..." FTPS4_EOL);
    decrypt = 1;
  } else {
    ftps4_ext_client_send_ctrl_msg(client, "200 SELF decryption disabled..." FTPS4_EOL);
    decrypt = 0;
  }
}

static void custom_RETR(ftps4_client_info_t *client) {
  char dest_path[PATH_MAX];
  ftps4_gen_ftp_fullpath(client, dest_path, sizeof(dest_path));
  if (is_self(dest_path) && decrypt == 1) {
    decrypt_and_dump_self(dest_path, "/user/temp.self");
    ftps4_send_file(client, "/user/temp.self");
    unlink("/user/temp.self");
  } else {
    ftps4_send_file(client, dest_path);
  }
}

void custom_SHUTDOWN(ftps4_client_info_t *client) {
  ftps4_ext_client_send_ctrl_msg(client, "200 Shutting down..." FTPS4_EOL);
  run = 0;
}

int get_ip_address(char *ip_address) {
  int ret;
  SceNetCtlInfo info;

  ret = sceNetCtlInit();
  if (ret >= 0) {
    ret = sceNetCtlGetInfo(SCE_NET_CTL_INFO_IP_ADDRESS, &info);
    if (ret >= 0) {
      memcpy(ip_address, info.ip_address, sizeof(info.ip_address));
      sceNetCtlTerm();

      return ret;
    }
  }

  return -1;
}

int _main(struct thread *td) {
  UNUSED(td);

  char ip_address[SCE_NET_CTL_IPV4_ADDR_STR_LEN] = {0};
  run = 1;
  decrypt = 0;

  initKernel();
  initLibc();
  initNetwork();
  initPthread();

  jailbreak();
  mmap_patch();

  initSysUtil();

  printf_notification("Running FTP server");

  int ret = get_ip_address(ip_address);
  if (ret >= 0) {
    ftps4_init(ip_address, FTP_PORT);
    ftps4_ext_add_command("MTPROC", custom_MTPROC);
    ftps4_ext_add_command("DECRYPT", custom_DECRYPT);
    ftps4_ext_del_command("RETR");
    ftps4_ext_add_command("RETR", custom_RETR);
    ftps4_ext_add_command("SHUTDOWN", custom_SHUTDOWN);
    ftps4_ext_add_command("MTRW", custom_MTRW);

    printf_notification("Listening on\nIP:     %s\nPort: %i", ip_address, FTP_PORT);

    while (run) {
      sceKernelSleep(5);
    }

    ftps4_fini();
  } else {
    printf_notification("Unable to get IP address");
  }

  return 0;
}
