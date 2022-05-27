#ifndef CONFIG_DTP_H
#define CONFIG_DTP_H

#include <stdio.h>
#include <sys/time.h>

__uint64_t get_current_usec() {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return tv.tv_sec * 1000000 + tv.tv_usec;
}

typedef struct dtp_config {
  int deadline;
  int priority;
  int size;
  float send_time_gap;
} dtp_config;

struct dtp_config *parse_dtp_config(const char *filename, int *number) {
  FILE *fd = NULL;

  int deadline;
  int priority;
  int size;
  float send_time_gap;

  int cfgs_len = 0;
  static int max_cfgs_len = 40000;
  dtp_config *cfgs = malloc(max_cfgs_len * sizeof(dtp_config));

  fd = fopen(filename, "r");
  if (fd == NULL) {
    fprintf(stderr, "Failed to open %s\n", filename);
    free(cfgs);
    *number = 0;
    return NULL;
  }

  while (fscanf(fd, "%f %d %d %d", &send_time_gap, &deadline, &size,
                &priority) == 4) {
    cfgs[cfgs_len].deadline = deadline;
    cfgs[cfgs_len].priority = priority;
    cfgs[cfgs_len].size = size;
    cfgs[cfgs_len].send_time_gap = send_time_gap;
    cfgs_len++;
    if (cfgs_len >= max_cfgs_len) {
      break;
    }
  }

  printf("%d configs loaded\n", cfgs_len);

  *number = cfgs_len;
  fclose(fd);

  return cfgs;
}

#endif