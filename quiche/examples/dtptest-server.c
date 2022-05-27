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
#include <uthash.h>

#include "dtp_config.h"
#include "log_helper.h"
#include <quiche.h>

#include <argp.h>
#include <string.h>
#include <time.h>

/***** Argp configs *****/

const char *argp_program_version = "dtptest-server 0.1";
static char doc[] = "dtptest-server -- a simple DTP test server";
static char args_doc[] = "SERVER_IP PORT DTP_TRACE_FILE";

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
  char *dtp_trace_file;
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
    }
    case 2:
      arguments->dtp_trace_file = arg;
      break;
    default:
      argp_usage(state);
      break;
    }
    break;
  case ARGP_KEY_END:
    if (state->arg_num < 3)
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

#define MAX_TOKEN_LEN                                                          \
  sizeof("quiche") - 1 + sizeof(struct sockaddr_storage) +                     \
      QUICHE_MAX_CONN_ID_LEN

struct connections {
  int sock;
  int ai_family;

  struct conn_io *h;
};

struct conn_io {
  ev_timer timer;
  ev_timer sender;
  ev_timer pacer;
  int send_round;

  int sock;

  uint8_t cid[LOCAL_CONN_ID_LEN];

  quiche_conn *conn;

  struct sockaddr_storage peer_addr;
  socklen_t peer_addr_len;

  dtp_config *cfgs;
  int cfg_len;

  UT_hash_handle hh;
};

static quiche_config *config = NULL;

static struct connections *conns = NULL;

/***** utilites *****/

static void mint_token(const uint8_t *dcid, size_t dcid_len,
                       struct sockaddr_storage *addr, socklen_t addr_len,
                       uint8_t *token, size_t *token_len) {
  memcpy(token, "quiche", sizeof("quiche") - 1);
  memcpy(token + sizeof("quiche") - 1, addr, addr_len);
  memcpy(token + sizeof("quiche") - 1 + addr_len, dcid, dcid_len);

  *token_len = sizeof("quiche") - 1 + addr_len + dcid_len;
}

static bool validate_token(const uint8_t *token, size_t token_len,
                           struct sockaddr_storage *addr, socklen_t addr_len,
                           uint8_t *odcid, size_t *odcid_len) {
  if ((token_len < sizeof("quiche") - 1) ||
      memcmp(token, "quiche", sizeof("quiche") - 1)) {
    return false;
  }

  token += sizeof("quiche") - 1;
  token_len -= sizeof("quiche") - 1;

  if ((token_len < addr_len) || memcmp(token, addr, addr_len)) {
    return false;
  }

  token += addr_len;
  token_len -= addr_len;

  if (*odcid_len < token_len) {
    return false;
  }

  memcpy(odcid, token, token_len);
  *odcid_len = token_len;

  return true;
}

static uint8_t *gen_cid(uint8_t *cid, size_t cid_len) {
  int rng = open("/dev/urandom", O_RDONLY);
  if (rng < 0) {
    log_error("failed to open /dev/urandom %s", strerror(errno));
    return NULL;
  }

  ssize_t rand_len = read(rng, cid, cid_len);
  if (rand_len < 0) {
    log_error("failed to create connection ID %s", strerror(errno));
    return NULL;
  }

  return cid;
}

static void debug_log(const char *line, void *argp) { log_info("%s", line); }

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

static void timeout_cb(struct ev_loop *loop, ev_timer *w, int revents);
static void sender_cb(struct ev_loop *loop, ev_timer *w, int revents);
static void pacer_cb(struct ev_loop *loop, ev_timer *pacer, int revents);

static struct conn_io *create_conn(uint8_t *scid, size_t scid_len,
                                   uint8_t *odcid, size_t odcid_len,
                                   struct sockaddr_storage *peer_addr,
                                   socklen_t peer_addr_len) {
  struct conn_io *conn_io = calloc(1, sizeof(*conn_io));
  if (conn_io == NULL) {
    log_error("failed to allocate connection IO");
    return NULL;
  }

  if (scid_len != LOCAL_CONN_ID_LEN) {
    log_error("failed, scid length too short");
  }

  memcpy(conn_io->cid, scid, LOCAL_CONN_ID_LEN);

  quiche_conn *conn =
      quiche_accept(conn_io->cid, LOCAL_CONN_ID_LEN, odcid, odcid_len,
                    (struct sockaddr *)peer_addr, peer_addr_len, config);

  if (conn == NULL) {
    log_error("failed to create connection");
    return NULL;
  }

  conn_io->sock = conns->sock;
  conn_io->conn = conn;

  memcpy(&conn_io->peer_addr, peer_addr, peer_addr_len);
  conn_io->peer_addr_len = peer_addr_len;

  dtp_config *cfgs = parse_dtp_config(args.dtp_trace_file, &conn_io->cfg_len);
  if (!cfgs || conn_io->cfg_len <= 0) {
    log_error("failed to parse dtp config");
    return NULL;
  }
  conn_io->cfgs = cfgs;
  conn_io->send_round = -1;

  ev_init(&conn_io->timer, timeout_cb);
  conn_io->timer.data = conn_io;

  ev_init(&conn_io->sender, sender_cb);
  conn_io->sender.data = conn_io;

  ev_init(&conn_io->pacer, pacer_cb);
  conn_io->pacer.data = conn_io;

  HASH_ADD(hh, conns->h, cid, LOCAL_CONN_ID_LEN, conn_io);

  log_info("new connection");

  return conn_io;
}

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

    set_tos(conn_io->peer_addr.ss_family, conn_io->sock,
            send_info.diffserv << 2);
    ssize_t sent = sendto(conn_io->sock, out, written, 0,
                          (struct sockaddr *)&send_info.to, send_info.to_len);

    if (sent != written) {
      log_error("failed to send %s", strerror(errno));
      return;
    }

    log_debug("sent %zd bytes", sent);
  }

  double t = quiche_conn_timeout_as_nanos(conn_io->conn) / 1e9f;
  conn_io->timer.repeat = t;
  ev_timer_again(loop, &conn_io->timer);

  // struct timespec now = {0, 0};
  // clock_gettime(CLOCK_REALTIME, &now);

  // double repeat = (send_info.at.tv_sec - now.tv_sec) +
  //                         (send_info.at.tv_nsec - now.tv_nsec) / 1e9f;
  // conn_io->pacer.repeat = repeat > 0 ? repeat : 0.001;
  conn_io->pacer.repeat = 0.0001;
  ev_timer_again(loop, &conn_io->pacer);
}

static void pacer_cb(struct ev_loop *loop, ev_timer *pacer, int revents) {
  // log_debug("flush egress pace triggered");
  struct conn_io *conn_io = pacer->data;
  flush_egress(loop, conn_io);
}

static void sender_cb(struct ev_loop *loop, ev_timer *w, int revents) {
  struct conn_io *conn_io = w->data;

  if (quiche_conn_is_established(conn_io->conn)) {
    float send_time_gap = conn_io->cfgs[conn_io->send_round].send_time_gap;
    static uint8_t buf[MAX_BLOCK_SIZE];

    quiche_block block = {
        .size = conn_io->cfgs[conn_io->send_round].size,
        .priority = conn_io->cfgs[conn_io->send_round].priority,
        .deadline = conn_io->cfgs[conn_io->send_round].deadline,
    };

    int stream_id = 4 * (conn_io->send_round + 1) + 1;
    log_info("send stream %d", stream_id);
    ssize_t sent = 0;
    if (QUIC_ENABLE) {
      sent = quiche_conn_stream_send(conn_io->conn, stream_id, buf,
                                             block.size, true);
    } else {
      sent = quiche_conn_block_send(conn_io->conn, stream_id, buf,
                                            block.size, true, &block);
    }

    if (sent != block.size) {
      log_debug("failed to send block %d completely: sent %zd",
                conn_io->send_round, sent);
    }

    conn_io->send_round++;
    if (conn_io->send_round >= conn_io->cfg_len) {
      ev_timer_stop(loop, &conn_io->sender);
    } else {
      conn_io->sender.repeat = send_time_gap;
      ev_timer_again(loop, &conn_io->sender);
    }
  }

  flush_egress(loop, conn_io);
}

static void recv_cb(struct ev_loop *loop, ev_io *w, int revents) {
  struct conn_io *tmp, *conn_io = NULL;

  static uint8_t buf[MAX_BLOCK_SIZE];
  static uint8_t out[MAX_DATAGRAM_SIZE];

  while (1) {
    struct sockaddr_storage peer_addr;
    socklen_t peer_addr_len = sizeof(peer_addr);
    memset(&peer_addr, 0, peer_addr_len);

    ssize_t read = recvfrom(conns->sock, buf, sizeof(buf), 0,
                            (struct sockaddr *)&peer_addr, &peer_addr_len);

    if (read < 0) {
      if ((errno == EWOULDBLOCK) || (errno == EAGAIN)) {
        log_debug("recv would block");
        break;
      }

      log_error("failed to read %s", strerror(errno));
      return;
    }

    uint8_t type;
    uint32_t version;

    uint8_t scid[QUICHE_MAX_CONN_ID_LEN];
    size_t scid_len = sizeof(scid);

    uint8_t dcid[QUICHE_MAX_CONN_ID_LEN];
    size_t dcid_len = sizeof(dcid);

    uint8_t odcid[QUICHE_MAX_CONN_ID_LEN];
    size_t odcid_len = sizeof(odcid);

    uint8_t token[MAX_TOKEN_LEN];
    size_t token_len = sizeof(token);

    int rc =
        quiche_header_info(buf, read, LOCAL_CONN_ID_LEN, &version, &type, scid,
                           &scid_len, dcid, &dcid_len, token, &token_len);
    if (rc < 0) {
      log_error("failed to parse header: %d", rc);
      continue;
    }

    HASH_FIND(hh, conns->h, dcid, dcid_len, conn_io);

    if (conn_io == NULL) {
      if (!quiche_version_is_supported(version)) {
        log_debug("version negotiation");

        ssize_t written = quiche_negotiate_version(scid, scid_len, dcid,
                                                   dcid_len, out, sizeof(out));

        if (written < 0) {
          log_error("failed to create vneg packet: %zd", written);
          continue;
        }

        set_tos(conns->ai_family, conns->sock, 5 << 5);
        ssize_t sent = sendto(conns->sock, out, written, 0,
                              (struct sockaddr *)&peer_addr, peer_addr_len);
        if (sent != written) {
          log_error("failed to send %s", strerror(errno));
          continue;
        }

        log_debug("sent %zd bytes", sent);
        continue;
      }

      if (token_len == 0) {
        log_debug("stateless retry");

        mint_token(dcid, dcid_len, &peer_addr, peer_addr_len, token,
                   &token_len);

        uint8_t new_cid[LOCAL_CONN_ID_LEN];

        if (gen_cid(new_cid, LOCAL_CONN_ID_LEN) == NULL) {
          continue;
        }

        ssize_t written = quiche_retry(scid, scid_len, dcid, dcid_len, new_cid,
                                       LOCAL_CONN_ID_LEN, token, token_len,
                                       version, out, sizeof(out));

        if (written < 0) {
          log_error("failed to create retry packet: %zd", written);
          continue;
        }

        set_tos(conns->ai_family, conns->sock, 5 << 5);
        ssize_t sent = sendto(conns->sock, out, written, 0,
                              (struct sockaddr *)&peer_addr, peer_addr_len);
        if (sent != written) {
          log_error("failed to send %s", strerror(errno));
          continue;
        }

        log_debug("sent %zd bytes", sent);
        continue;
      }

      if (!validate_token(token, token_len, &peer_addr, peer_addr_len, odcid,
                          &odcid_len)) {
        log_error("invalid address validation token");
        continue;
      }

      conn_io = create_conn(dcid, dcid_len, odcid, odcid_len, &peer_addr,
                            peer_addr_len);

      if (conn_io == NULL) {
        continue;
      }
    }

    quiche_recv_info recv_info = {
        (struct sockaddr *)&peer_addr,

        peer_addr_len,
    };

    ssize_t done = quiche_conn_recv(conn_io->conn, buf, read, &recv_info);

    if (done < 0) {
      log_error("failed to process packet: %zd", done);
      continue;
    }

    log_debug("recv %zd bytes", done);

    if (quiche_conn_is_established(conn_io->conn)) {
      if (conn_io->send_round == -1) {
        conn_io->send_round = 0;
        conn_io->sender.repeat = conn_io->cfgs[0].send_time_gap;
        ev_timer_again(loop, &conn_io->sender);
      }

      uint64_t s = 0;

      quiche_stream_iter *readable = quiche_conn_readable(conn_io->conn);

      while (quiche_stream_iter_next(readable, &s)) {
        log_debug("stream %" PRIu64 " is readable", s);

        bool fin = false;
        ssize_t recv_len =
            quiche_conn_stream_recv(conn_io->conn, s, buf, sizeof(buf), &fin);
        if (recv_len < 0) {
          break;
        }
      }

      quiche_stream_iter_free(readable);
    }
  }

  HASH_ITER(hh, conns->h, conn_io, tmp) {
    flush_egress(loop, conn_io);

    if (quiche_conn_is_closed(conn_io->conn)) {
      quiche_stats stats;

      quiche_conn_stats(conn_io->conn, &stats);
      dump_info("connection closed, recv=%zu sent=%zu lost=%zu rtt=%" PRIu64
                "ns cwnd=%zu\n",
                stats.recv, stats.sent, stats.lost, stats.rtt, stats.cwnd);
      fflush(NULL);

      HASH_DELETE(hh, conns->h, conn_io);

      ev_timer_stop(loop, &conn_io->timer);
      ev_timer_stop(loop, &conn_io->sender);
      ev_timer_stop(loop, &conn_io->pacer);
      quiche_conn_free(conn_io->conn);
      free(conn_io);
    }
  }
}

static void timeout_cb(EV_P_ ev_timer *w, int revents) {
  struct conn_io *conn_io = w->data;
  quiche_conn_on_timeout(conn_io->conn);

  log_debug("timeout");

  flush_egress(loop, conn_io);

  if (quiche_conn_is_closed(conn_io->conn)) {
    quiche_stats stats;

    quiche_conn_stats(conn_io->conn, &stats);
    dump_info("connection closed, recv=%zu sent=%zu lost=%zu rtt=%" PRIu64
              "ns cwnd=%zu\n",
              stats.recv, stats.sent, stats.lost, stats.rtt, stats.cwnd);
    fflush(NULL);

    HASH_DELETE(hh, conns->h, conn_io);

    ev_timer_stop(loop, &conn_io->timer);
    ev_timer_stop(loop, &conn_io->sender);
    ev_timer_stop(loop, &conn_io->pacer);
    quiche_conn_free(conn_io->conn);
    free(conn_io->cfgs);
    free(conn_io);

    return;
  }
}

int main(int argc, char *argv[]) {
  args.out_file = stdout;
  args.log_file = stdout;
  argp_parse(&argp, argc, argv, 0, 0, &args);
  log_info("SERVER_IP:PORT %s:%s DTP_TRACE_FILE %s", args.server_ip,
           args.server_port, args.dtp_trace_file);

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

  if (bind(sock, server->ai_addr, server->ai_addrlen) < 0) {
    log_error("bind %s", strerror(errno));
    return -1;
  }

  config = quiche_config_new(QUICHE_PROTOCOL_VERSION);
  if (config == NULL) {
    log_error("quiche_config_new");
    return -1;
  }

  quiche_config_load_cert_chain_from_pem_file(config, "./cert.crt");
  quiche_config_load_priv_key_from_pem_file(config, "./cert.key");

  quiche_config_set_application_protos(
      config,
      (uint8_t *)"\x0ahq-interop\x05hq-29\x05hq-28\x05hq-27\x08http/0.9", 38);

  quiche_config_set_max_idle_timeout(config, 5000);
  quiche_config_set_max_recv_udp_payload_size(config, MAX_DATAGRAM_SIZE);
  quiche_config_set_max_send_udp_payload_size(config, MAX_DATAGRAM_SIZE);
  quiche_config_set_initial_max_data(config, 1000000000);
  quiche_config_set_initial_max_stream_data_uni(config, 10000000);
  quiche_config_set_initial_max_streams_uni(config, 40000);
  quiche_config_set_initial_max_stream_data_bidi_local(config, 10000000);
  quiche_config_set_initial_max_stream_data_bidi_remote(config, 10000000);
  quiche_config_set_initial_max_streams_bidi(config, 40000);
  quiche_config_set_cc_algorithm(config, QUICHE_CC_RENO);

  struct connections c;
  c.sock = sock;
  c.ai_family = server->ai_family;
  c.h = NULL;

  conns = &c;

  ev_io watcher;

  struct ev_loop *loop = ev_default_loop(0);

  ev_io_init(&watcher, recv_cb, sock, EV_READ);
  ev_io_start(loop, &watcher);
  watcher.data = &c;

  ev_loop(loop, 0);

  freeaddrinfo(server);

  quiche_config_free(config);

  return 0;
}