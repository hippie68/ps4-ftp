//#define DEBUG_SOCKET
#define DEBUG_IP "192.168.2.2"
#define DEBUG_PORT 9023

#include "ps4.h"

#include "ftps4.h"

#define FTP_PORT 1337

int run;
int decrypt;
int kill_switch;

void custom_MTPROC(ftps4_client_info_t *client) {
  int result = mkdir("/mnt/proc", 0777);
  if (result >= 0 || (*__error()) == 17) {
    result = mount("procfs", "/mnt/proc", 0, NULL);
    if (result >= 0) {
      ftps4_ext_client_send_ctrl_msg(client, "200 Mount success." FTPS4_EOL);
      return;
    } else {
      ftps4_ext_client_send_ctrl_msg(client, "Failed to mount procfs!" FTPS4_EOL);
    }
  } else {
    ftps4_ext_client_send_ctrl_msg(client, "Failed to create /mnt/proc!" FTPS4_EOL);
  }

  ftps4_ext_client_send_ctrl_msg(client, "550 Could not mount!" FTPS4_EOL);
  return;
}

void custom_MTRW(ftps4_client_info_t *client) {
  if (mount_large_fs("/dev/md0", "/", "exfatfs", "511", MNT_UPDATE) < 0) {
    goto fail;
  }
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
  /* These fail to mount...
  // mount_large_fs("/dev/da0x9.crypt", "/system_data", "exfatfs", "511", MNT_UPDATE)
  // mount_large_fs("/dev/md0.crypt", "/", "exfatfs", "511", MNT_UPDATE)
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
  char dest_path[PATH_MAX] = {0};
  ftps4_gen_ftp_fullpath(client, dest_path, sizeof(dest_path));

  if (decrypt && is_self(dest_path)) {
    // Create unique temporary file to allow simultaneous decryptions
    char temp_path[PATH_MAX];
    sprintf(temp_path, "/user/temp/ftp_temp_file_%d", client->ctrl_sockfd);
    while (file_exists(temp_path) && strlen(temp_path) + 1 < PATH_MAX) {
      strcat(temp_path, "_");
    }

    decrypt_and_dump_self(dest_path, temp_path);
    ftps4_send_file(client, temp_path);
    unlink(temp_path);
  } else {
    ftps4_send_file(client, dest_path);
  }
}

static void custom_SIZE(ftps4_client_info_t *client) {
  struct stat s;
  char path[PATH_MAX];
  char cmd[64];

  // Get the filename to retrieve its size
  ftps4_gen_ftp_fullpath(client, path, sizeof(path));

  // Check if the file exists
  if (stat(path, &s) < 0) {
    ftps4_ext_client_send_ctrl_msg(client, "550 The file does not exist." FTPS4_EOL);
    return;
  }

  // If file is a SELF, decrypt it to retrieve the correct file size
  if (decrypt && is_self(path)) {
    char temp_path[PATH_MAX];
    sprintf(temp_path, "/user/temp/ftp_temp_file_%d", client->ctrl_sockfd);
    while (file_exists(temp_path) && strlen(temp_path) + 1 < PATH_MAX) {
      strcat(temp_path, "_");
    }
    decrypt_and_dump_self(path, temp_path);
    stat(temp_path, &s);
    unlink(temp_path);
  }

  // Send the size of the file
  sprintf(cmd, "213 %lld" FTPS4_EOL, s.st_size);
  ftps4_ext_client_send_ctrl_msg(client, cmd);
}

void custom_KILL(ftps4_client_info_t *client) {
  ftps4_ext_client_send_ctrl_msg(client, "200 Killing downloads..." FTPS4_EOL);
  kill_switch = 1;
}

void custom_SHUTDOWN(ftps4_client_info_t *client) {
  ftps4_ext_client_send_ctrl_msg(client, "200 Shutting down..." FTPS4_EOL);
  run = 0;
}

int get_ip_address(char *ip_address) {
  int ret;
  SceNetCtlInfo info;
  memset_s(&info, sizeof(SceNetCtlInfo), 0, sizeof(SceNetCtlInfo));

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

#ifdef DEBUG_SOCKET
  DEBUG_SOCK = SckConnect(DEBUG_IP, DEBUG_PORT);
#endif

  jailbreak();
  mmap_patch();

  initSysUtil();

  printf_notification("Running FTP server");

  int ret = get_ip_address(ip_address);
  if (ret >= 0) {
    ftps4_init(ip_address, FTP_PORT); // Server will set "run" to 0 on binding error
    ftps4_ext_add_command("MTPROC", custom_MTPROC);
    ftps4_ext_add_command("DECRYPT", custom_DECRYPT);
    ftps4_ext_del_command("RETR");
    ftps4_ext_add_command("RETR", custom_RETR);
    ftps4_ext_add_command("SHUTDOWN", custom_SHUTDOWN);
    ftps4_ext_del_command("SIZE");
    ftps4_ext_add_command("SIZE", custom_SIZE);
    ftps4_ext_add_command("MTRW", custom_MTRW);
    ftps4_ext_add_command("KILL", custom_KILL);

    // Give the server some time to possibly change "run"
    sceKernelSleep(5);
    if (run) {
      printf_notification("Listening on\nIP:     %s\nPort: %i", ip_address, FTP_PORT);
    }

    while (run) {
      sceKernelSleep(5);
    }

    ftps4_fini();
  } else {
    printf_notification("Unable to get IP address");
  }

  printf_notification("Shutting down FTP server...");

#ifdef DEBUG_SOCKET
  printf_debug("Closing socket...\n");
  SckClose(DEBUG_SOCK);
#endif

  return 0;
}
