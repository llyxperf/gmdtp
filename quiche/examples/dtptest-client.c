#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <errno.h>
#include <fcntl.h>

#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <ev.h>

#include "dtp_config.h"
#include "log_helper.h"
#include <quiche.h>

#include <argp.h>
#include <string.h>
#include <time.h>

/***** Argp configs *****/

const char *argp_program_version = "dtptest-client 0.1";
static char doc[] = "dtptest-client -- a simple DTP test client";
static char args_doc[] = "SERVER_IP PORT";

static struct argp_option options[] = {
    {"log", 'l', "FILE", 0, "Log to FILE instead of stderr"},
    {"out", 'o', "FILE", 0, "Write received data to FILE"},
    {"verbose", 'v', "LEVEL", 0, "Print verbose debug messages"},
    {"color", 'c', 0, 0, "Colorize log messages"},
    {"diffserv", 'd', 0, 0, "Enable DiffServ"},
    {"quic", 'q', 0, 0, "Use QUIC instead of DTP"},
    {0}};

struct arguments {
  FILE *log_file;
  FILE *out_file;
  char *server_ip;
  char *server_port;
};

static bool DIFFSERV_ENABLE = false;
static bool QUIC_ENABLE = false;

static struct arguments args;

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
  struct arguments *arguments = state->input;
  switch (key) {
  case 'l':
    arguments->log_file = fopen(arg, "w+");
    break;
  case 'o':
    arguments->out_file = fopen(arg, "w+");
    break;
  case 'v':
    LOG_LEVEL = arg ? atoi(arg) : 3;
    break;
  case 'c':
    LOG_COLOR = 1;
    break;
  case 'd':
    DIFFSERV_ENABLE = true;
    break;
  case 'q':
    QUIC_ENABLE = true;
    break;
  case ARGP_KEY_ARG:
    switch (state->arg_num) {
    case 0: {
      arguments->server_ip = arg;
      break;
    }
    case 1: {
      arguments->server_port = arg;
      break;
    }
    default:
      argp_usage(state);
      break;
    }
    break;
  case ARGP_KEY_END:
    if (state->arg_num < 2)
      argp_usage(state);
    break;
  default:
    return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

static struct argp argp = {options, parse_opt, args_doc, doc};

#undef HELPER_LOG
#undef HELPER_OUT
#define HELPER_LOG args.log_file
#define HELPER_OUT args.out_file

/***** DTP QUIC configs *****/

#define LOCAL_CONN_ID_LEN 16

#define MAX_DATAGRAM_SIZE 1350

#define MAX_BLOCK_SIZE 10000000

uint64_t total_bytes = 0;
uint64_t total_udp_bytes = 0;
uint64_t started_at = 0;
uint64_t ended_at = 0;

struct conn_io {
  ev_timer timer;
  ev_timer pacer;

  int sock;
  int ai_family;

  quiche_conn *conn;
};

/***** utilites *****/

static void debug_log(const char *line, void *argp) { log_error("%s", line); }

void set_tos(int ai_family, int sock, int tos) {
  if (!DIFFSERV_ENABLE)
    return;

  switch (ai_family) {
  case AF_INET:
    if (setsockopt(sock, IPPROTO_IP, IP_TOS, &tos, sizeof(tos)) < 0) {
      log_error("failed to set TOS %s", strerror(errno));
    }
    break;
  case AF_INET6:
    if (setsockopt(sock, IPPROTO_IPV6, IPV6_TCLASS, &tos, sizeof(tos)) < 0) {
      log_error("failed to set TOS %s", strerror(errno));
    }
    break;

  default:
    break;
  }
}

/***** callbacks *****/

static void flush_egress(struct ev_loop *loop, struct conn_io *conn_io) {
  static uint8_t out[MAX_DATAGRAM_SIZE];

  quiche_send_info send_info;

  while (1) {
    ssize_t written =
        quiche_conn_send(conn_io->conn, out, sizeof(out), &send_info);

    if (written == QUICHE_ERR_DONE) {
      log_debug("done writing");
      break;
    }

    if (written < 0) {
      log_error("failed to create packet: %zd", written);
      return;
    }

    set_tos(conn_io->ai_family, conn_io->sock, send_info.diffserv << 2);
    ssize_t sent = sendto(conn_io->sock, out, written, 0,
                          (struct sockaddr *)&send_info.to, send_info.to_len);

    if (sent != written) {
      log_error("failed to send %s", strerror(errno));
      return;
    }

    log_debug("sent %zd bytes", sent);
  }

  double t = quiche_conn_timeout_as_nanos(conn_io->conn) / 1e9f;
  if (t != 0) {
    conn_io->timer.repeat = t;
    ev_timer_again(loop, &conn_io->timer);
  }

  // struct timespec now = {0, 0};
  // clock_gettime(CLOCK_REALTIME, &now);

  // double repeat = (send_info.at.tv_sec - now.tv_sec) +
  //                 (send_info.at.tv_nsec - now.tv_nsec) / 1e9f;
  // conn_io->pacer.repeat = repeat > 0 ? repeat : 0.001;
  conn_io->pacer.repeat = 0.0001;
  ev_timer_again(loop, &conn_io->pacer);
}

static void pacer_cb(struct ev_loop *loop, ev_timer *pacer, int revents) {
  // log_debug("flush egress pace triggered");
  struct conn_io *conn_io = pacer->data;
  flush_egress(loop, conn_io);
}

static void recv_cb(EV_P_ ev_io *w, int revents) {
  // static bool req_sent = false;

  struct conn_io *conn_io = w->data;

  static uint8_t buf[MAX_BLOCK_SIZE];

  while (1) {
    struct sockaddr_storage peer_addr;
    socklen_t peer_addr_len = sizeof(peer_addr);
    memset(&peer_addr, 0, peer_addr_len);

    ssize_t read = recvfrom(conn_io->sock, buf, sizeof(buf), 0,
                            (struct sockaddr *)&peer_addr, &peer_addr_len);

    if (read < 0) {
      if ((errno == EWOULDBLOCK) || (errno == EAGAIN)) {
        log_debug("recv would block");
        break;
      }

      log_error("failed to read %s", strerror(errno));
      return;
    }

    total_udp_bytes += read;

    quiche_recv_info recv_info = {
        (struct sockaddr *)&peer_addr,

        peer_addr_len,
    };

    ssize_t done = quiche_conn_recv(conn_io->conn, buf, read, &recv_info);

    if (done < 0) {
      log_error("failed to process packet %ld", done);
      continue;
    }

    log_debug("recv %zd bytes", done);
  }

  log_debug("done reading");

  if (quiche_conn_is_closed(conn_io->conn)) {
    log_info("connection closed");

    quiche_stats stats;

    quiche_conn_stats(conn_io->conn, &stats);

    log_info("connection closed, recv=%zu sent=%zu lost=%zu rtt=%" PRIu64
             "ns total_bytes=%zu total_udb_bytes=%zu total_time=%zu",
             stats.recv, stats.sent, stats.lost, stats.rtt, total_bytes,
             total_udp_bytes, ended_at - started_at);
    fflush(NULL);

    ev_break(EV_A_ EVBREAK_ONE);
    return;
  }

  // if (quiche_conn_is_established(conn_io->conn) && !req_sent) {
  //   const uint8_t *app_proto;
  //   size_t app_proto_len;

  //   quiche_conn_application_proto(conn_io->conn, &app_proto, &app_proto_len);

  //   log_info("connection established: %.*s", (int)app_proto_len, app_proto);

  //   const static uint8_t r[] = "GET /index.html\r\n";
  //   if (quiche_conn_stream_send(conn_io->conn, 4, r, sizeof(r), true) < 0) {
  //     log_error("failed to send HTTP request\n");
  //     return;
  //   }

  //   log_debug("sent HTTP request\n");

  //   req_sent = true;
  // }

  if (quiche_conn_is_established(conn_io->conn)) {
    uint64_t s = 0;

    quiche_stream_iter *readable = quiche_conn_readable(conn_io->conn);

    while (quiche_stream_iter_next(readable, &s)) {
      log_debug("stream %" PRIu64 " is readable", s);

      bool fin = false;
      ssize_t recv_len =
          quiche_conn_stream_recv(conn_io->conn, s, buf, sizeof(buf), &fin);
      if (recv_len < 0) {
        log_debug("recv_len %ld", recv_len);
        break;
      }
      total_bytes += recv_len;

      if (fin) {
        ended_at = get_current_usec();
        uint64_t bct = quiche_conn_bct(conn_io->conn, s);
        quiche_block block_info;
        quiche_conn_block_info(conn_io->conn, s, &block_info);

        dump_file("%ld,%ld,%ld,%ld,%ld,%ld\n", s, bct, block_info.size,
                  block_info.priority, block_info.deadline,
                  ended_at - started_at);
      }
    }

    quiche_stream_iter_free(readable);
  }

  flush_egress(loop, conn_io);
}

static void timeout_cb(EV_P_ ev_timer *w, int revents) {
  struct conn_io *conn_io = w->data;
  quiche_conn_on_timeout(conn_io->conn);

  log_debug("timeout");

  flush_egress(loop, conn_io);

  if (quiche_conn_is_closed(conn_io->conn)) {
    quiche_stats stats;

    quiche_conn_stats(conn_io->conn, &stats);

    log_info("connection closed, recv=%zu sent=%zu lost=%zu rtt=%" PRIu64
             "ns total_bytes=%zu total_udb_bytes=%zu total_time=%zu",
             stats.recv, stats.sent, stats.lost, stats.rtt, total_bytes,
             total_udp_bytes, ended_at - started_at);
    fflush(NULL);

    ev_break(EV_A_ EVBREAK_ONE);
    return;
  }
}

int main(int argc, char *argv[]) {
  args.out_file = stdout;
  args.log_file = stdout;
  argp_parse(&argp, argc, argv, 0, 0, &args);
  log_info("SERVER_IP:PORT %s:%s", args.server_ip, args.server_port);

  const struct addrinfo hints = {.ai_family = AF_UNSPEC,
                                 .ai_socktype = SOCK_DGRAM,
                                 .ai_protocol = IPPROTO_UDP};

  quiche_enable_debug_logging(debug_log, NULL);

  struct addrinfo *server;
  int err = getaddrinfo(args.server_ip, args.server_port, &hints, &server);
  if (err != 0) {
    log_error("getaddrinfo: %s", gai_strerror(err));
    return -1;
  }

  int sock =
      socket(server->ai_family, server->ai_socktype, server->ai_protocol);
  if (sock < 0) {
    log_error("create socket");
    return -1;
  }

  if (fcntl(sock, F_SETFL, O_NONBLOCK) < 0) {
    log_error("fcntl");
    return -1;
  }

  quiche_config *config = quiche_config_new(0xbabababa);
  if (config == NULL) {
    log_error("failed to create config");
    return -1;
  }

  quiche_config_set_application_protos(
      config,
      (uint8_t *)"\x0ahq-interop\x05hq-29\x05hq-28\x05hq-27\x08http/0.9", 38);

  quiche_config_set_max_idle_timeout(config, 5000);
  quiche_config_set_max_recv_udp_payload_size(config, MAX_DATAGRAM_SIZE);
  quiche_config_set_max_send_udp_payload_size(config, MAX_DATAGRAM_SIZE);
  quiche_config_set_initial_max_data(config, 1000000000);
  quiche_config_set_initial_max_stream_data_bidi_local(config, 10000000);
  quiche_config_set_initial_max_stream_data_bidi_remote(config, 10000000);
  quiche_config_set_initial_max_stream_data_uni(config, 1000000);
  quiche_config_set_initial_max_streams_bidi(config, 40000);
  quiche_config_set_initial_max_streams_uni(config, 40000);
  quiche_config_set_disable_active_migration(config, true);

  if (getenv("SSLKEYLOGFILE")) {
    quiche_config_log_keys(config);
  }

  uint8_t scid[LOCAL_CONN_ID_LEN];
  int rng = open("/dev/urandom", O_RDONLY);
  if (rng < 0) {
    log_error("failed to open /dev/urandom %s", strerror(errno));
    return -1;
  }

  ssize_t rand_len = read(rng, &scid, sizeof(scid));
  if (rand_len < 0) {
    log_error("failed to create connection ID %s", strerror(errno));
    return -1;
  }

  quiche_conn *conn =
      quiche_connect(args.server_ip, (const uint8_t *)scid, sizeof(scid),
                     server->ai_addr, server->ai_addrlen, config);

  if (conn == NULL) {
    log_error("failed to create connection");
    return -1;
  }

  dump_file("block_id,bct,size,priority,deadline,duration\n");
  started_at = get_current_usec();

  struct conn_io *conn_io = malloc(sizeof(*conn_io));
  if (conn_io == NULL) {
    log_error("failed to allocate connection IO");
    return -1;
  }

  conn_io->sock = sock;
  conn_io->ai_family = server->ai_family;
  conn_io->conn = conn;

  ev_io watcher;

  struct ev_loop *loop = ev_default_loop(0);

  ev_io_init(&watcher, recv_cb, conn_io->sock, EV_READ);
  ev_io_start(loop, &watcher);
  watcher.data = conn_io;

  ev_init(&conn_io->timer, timeout_cb);
  conn_io->timer.data = conn_io;

  ev_init(&conn_io->pacer, pacer_cb);
  conn_io->pacer.data = conn_io;

  flush_egress(loop, conn_io);

  ev_loop(loop, 0);

  freeaddrinfo(server);

  quiche_conn_free(conn);

  quiche_config_free(config);

  return 0;
}