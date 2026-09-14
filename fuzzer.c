#include "fuzzer.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <poll.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "coverbridge/covbridge.h"

#define TCP_FLAG 0x01
#define MULTIPACKET_FLAG 0x02
#define WAIT_FOR_RESPONSE_FLAG 0x04
#define RAW_TCP_FLAG 0x08
#define TSIG_FLAG 0x10
#define MAX_PACKET_COUNT 64
#define MAX_UDP_PACKET_SIZE 65507
#define RAW_CHUNK_DELAY_US 1000
#define PROCESS_TIMEOUT_MS 1000
#define MULTIPACKET_TIMEOUT_MS 3000
#define FUZZ_RESPONSE_TIMEOUT_MS 20
#define RESPONSE_TIMEOUT_MS 20
#define STARTUP_RESPONSE_TIMEOUT_MS 500
#define SOCKET_TIMEOUT_MS 100
#define COVERBRIDGE_LAYOUT UINT64_C(0x4e534446555a5a01)
#define TSIG_MAC_SIZE 32
#define TSIG_FUDGE 300

static const uint8_t tsig_key_name[] = {8, 'f', 'u', 'z', 'z', '-',
                                        'k', 'e', 'y', 0};
static const uint8_t tsig_algorithm[] = {11, 'h', 'm', 'a', 'c', '-', 's',
                                         'h', 'a', '2', '5', '6', 0};
static const uint8_t tsig_secret[] = "0123456789abcdef0123456789abcdef";

static const char *target_ip = "127.0.0.1";
static const char *target_ip6 = "::1";
static int target_port = FUZZ_PORT;
static int fuzzer_started = 0;
struct worker_sync {
  _Atomic uint64_t packets_processed;
  _Atomic int parked;
  sem_t release;
};
static struct worker_sync *worker_sync;
static int worker_barrier_mode;
static int worker_is_child_process;
static cb_snapshot coverage_snapshot;
static uint64_t coverage_run;
static int coverage_initialized;
static int coverage_reported;

int LLVMFuzzerRunDriver(int *argc, char ***argv,
                        int (*callback)(const uint8_t *, size_t));
static int waitForResponse(int sockfd, int timeout_ms, int use_tcp);

void fuzzerPacketProcessed(void) {
  if (worker_sync) {
    if (worker_barrier_mode) {
      atomic_store_explicit(&worker_sync->parked, 1, memory_order_release);
    }
    atomic_fetch_add_explicit(&worker_sync->packets_processed, 1,
                              memory_order_release);
    fuzzerWorkerWait();
  }
}

static uint64_t processedPacketCount(void) {
  if (!worker_sync) {
    return 0;
  }
  return atomic_load_explicit(&worker_sync->packets_processed,
                              memory_order_acquire);
}

void fuzzerWorkerWait(void) {
  int result;

  if (!worker_barrier_mode || !worker_sync) {
    return;
  }
  cb_producer_enable();
  atomic_store_explicit(&worker_sync->parked, 1, memory_order_release);
  do {
    result = sem_wait(&worker_sync->release);
  } while (result == -1 && errno == EINTR);
  if (result == -1) {
    _exit(1);
  }
  atomic_store_explicit(&worker_sync->parked, 0, memory_order_release);
}

static void releaseWorker(void) {
  struct timespec pause = {0, 1000000L};
  int attempt;

  if (!worker_barrier_mode) {
    return;
  }
  for (attempt = 0; attempt < PROCESS_TIMEOUT_MS; attempt++) {
    if (atomic_load_explicit(&worker_sync->parked, memory_order_acquire)) {
      if (sem_post(&worker_sync->release) == -1) {
        perror("fuzzer worker release");
        abort();
      }
      return;
    }
    nanosleep(&pause, NULL);
  }
  fprintf(stderr, "fuzzer worker did not park\n");
  abort();
}

static int waitForPacketProcessed(uint64_t previous_count) {
  struct timespec started;
  struct timespec pause = {0, 1000000L};

  clock_gettime(CLOCK_MONOTONIC, &started);
  while (processedPacketCount() == previous_count) {
    struct timespec now;
    int64_t elapsed;

    nanosleep(&pause, NULL);
    clock_gettime(CLOCK_MONOTONIC, &now);
    elapsed = (now.tv_sec - started.tv_sec) * 1000;
    elapsed += (now.tv_nsec - started.tv_nsec) / 1000000;
    if (elapsed >= PROCESS_TIMEOUT_MS) {
      return -1;
    }
  }
  return 0;
}

int fuzzerInitialize(void) {
  if (getenv("NSD_FUZZ_DISABLE") ||
      (!getenv("NSD_FUZZ_COVERBRIDGE") &&
       !getenv("NSD_FUZZ_SINGLE_PROCESS"))) {
    return 0;
  }
  worker_sync = mmap(NULL, sizeof(*worker_sync), PROT_READ | PROT_WRITE,
                     MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (worker_sync == MAP_FAILED) {
    worker_sync = NULL;
    return -1;
  }
  worker_barrier_mode = 1;
  worker_is_child_process = getenv("NSD_FUZZ_COVERBRIDGE") &&
                            !getenv("NSD_FUZZ_SINGLE_PROCESS");
  atomic_init(&worker_sync->packets_processed, 0);
  atomic_init(&worker_sync->parked, 0);
  if (sem_init(&worker_sync->release, worker_is_child_process, 0) == -1) {
    return -1;
  }
  if (!worker_is_child_process) {
    cb_producer_enable();
  }
  if (cb_init(COVERBRIDGE_LAYOUT) == -1) {
    return -1;
  }
  coverage_initialized = 1;
  fprintf(stderr, "CoverBridge: %u shared coverage sites\n", cb_slots());
  return 0;
}

static void coverageBegin(void) {
  cb_libfuzzer_clear();
  if (cb_begin(++coverage_run) == -1) {
    perror("CoverBridge begin");
    abort();
  }
}

static void coverageEnd(void) {
  uint32_t active = 0;

  if (worker_barrier_mode &&
      !atomic_load_explicit(&worker_sync->parked, memory_order_acquire)) {
    fprintf(stderr, "fuzzer worker was not parked at coverage boundary\n");
    abort();
  }
  if (cb_end(&coverage_snapshot) == -1 ||
      cb_libfuzzer_import(&coverage_snapshot, 0) == -1) {
    perror("CoverBridge import");
    abort();
  }
  if (!coverage_reported) {
    for (uint32_t i = 0; i < coverage_snapshot.nslots; i++) {
      if (coverage_snapshot.counts[i]) {
        active++;
      }
    }
    if (active) {
      fprintf(stderr, "CoverBridge: imported %u active worker sites\n", active);
      coverage_reported = 1;
    }
  }
}

static int connectTarget(int use_tcp) {
  struct timeval timeout;
  int use_ipv6 = getenv("NSD_FUZZ_IPV6") != NULL;
  int family = use_ipv6 ? AF_INET6 : AF_INET;
  int socket_type = use_tcp ? SOCK_STREAM : SOCK_DGRAM;
  int sockfd = socket(family, socket_type, 0);
  int one = 1;

  if (sockfd == -1) {
    return -1;
  }

  timeout.tv_sec = SOCKET_TIMEOUT_MS / 1000;
  timeout.tv_usec = (SOCKET_TIMEOUT_MS % 1000) * 1000;
  setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
  setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  if (use_tcp) {
    setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
  }

  if (use_ipv6) {
    struct sockaddr_in6 target;

    memset(&target, 0, sizeof(target));
    target.sin6_family = AF_INET6;
    target.sin6_port = htons(target_port);
    inet_pton(AF_INET6, target_ip6, &target.sin6_addr);
    if (connect(sockfd, (struct sockaddr *)&target, sizeof(target)) == -1) {
      close(sockfd);
      return -1;
    }
  } else {
    struct sockaddr_in target;

    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    target.sin_port = htons(target_port);
    inet_pton(AF_INET, target_ip, &target.sin_addr);
    if (connect(sockfd, (struct sockaddr *)&target, sizeof(target)) == -1) {
      close(sockfd);
      return -1;
    }
  }
  return sockfd;
}

static int sendAll(int sockfd, const uint8_t *data, size_t size) {
  size_t sent = 0;

  while (sent < size) {
    ssize_t result = send(sockfd, data + sent, size - sent, MSG_NOSIGNAL);
    if (result > 0) {
      sent += (size_t)result;
    } else if (result == -1 && errno == EINTR) {
      continue;
    } else {
      return -1;
    }
  }
  return 0;
}

static void writeU16(uint8_t *data, uint16_t value) {
  data[0] = (uint8_t)(value >> 8);
  data[1] = (uint8_t)value;
}

static void writeU32(uint8_t *data, uint32_t value) {
  data[0] = (uint8_t)(value >> 24);
  data[1] = (uint8_t)(value >> 16);
  data[2] = (uint8_t)(value >> 8);
  data[3] = (uint8_t)value;
}

static void writeU48(uint8_t *data, uint64_t value) {
  data[0] = (uint8_t)(value >> 40);
  data[1] = (uint8_t)(value >> 32);
  data[2] = (uint8_t)(value >> 24);
  data[3] = (uint8_t)(value >> 16);
  data[4] = (uint8_t)(value >> 8);
  data[5] = (uint8_t)value;
}

static int signTsigPacket(const uint8_t *packet, size_t packet_size,
                          size_t maximum_size, uint8_t **signed_packet,
                          size_t *signed_size) {
  const size_t variables_size = sizeof(tsig_key_name) + 2 + 4 +
                                sizeof(tsig_algorithm) + 6 + 2 + 2 + 2;
  const size_t rdata_size =
      sizeof(tsig_algorithm) + 6 + 2 + 2 + TSIG_MAC_SIZE + 2 + 2 + 2;
  const size_t record_size = sizeof(tsig_key_name) + 2 + 2 + 4 + 2 + rdata_size;
  uint8_t timestamp[6];
  uint8_t mac[TSIG_MAC_SIZE];
  unsigned int mac_size = 0;
  uint8_t *mac_input;
  uint8_t *output;
  uint16_t additional;
  size_t offset;

  *signed_packet = NULL;
  *signed_size = packet_size;
  if (packet_size < 12 || record_size > maximum_size ||
      packet_size > maximum_size - record_size) {
    return 0;
  }
  additional = ((uint16_t)packet[10] << 8) | packet[11];
  if (additional == UINT16_MAX) {
    return 0;
  }

  mac_input = malloc(packet_size + variables_size);
  output = malloc(packet_size + record_size);
  if (!mac_input || !output) {
    free(mac_input);
    free(output);
    return 0;
  }

  writeU48(timestamp, (uint64_t)time(NULL));
  memcpy(mac_input, packet, packet_size);
  offset = packet_size;
  memcpy(mac_input + offset, tsig_key_name, sizeof(tsig_key_name));
  offset += sizeof(tsig_key_name);
  writeU16(mac_input + offset, 255);
  offset += 2;
  writeU32(mac_input + offset, 0);
  offset += 4;
  memcpy(mac_input + offset, tsig_algorithm, sizeof(tsig_algorithm));
  offset += sizeof(tsig_algorithm);
  memcpy(mac_input + offset, timestamp, sizeof(timestamp));
  offset += sizeof(timestamp);
  writeU16(mac_input + offset, TSIG_FUDGE);
  offset += 2;
  writeU16(mac_input + offset, 0);
  offset += 2;
  writeU16(mac_input + offset, 0);
  offset += 2;

  if (!HMAC(EVP_sha256(), tsig_secret, sizeof(tsig_secret) - 1, mac_input,
            offset, mac, &mac_size) ||
      mac_size != TSIG_MAC_SIZE) {
    free(mac_input);
    free(output);
    return 0;
  }
  free(mac_input);

  memcpy(output, packet, packet_size);
  writeU16(output + 10, additional + 1);
  offset = packet_size;
  memcpy(output + offset, tsig_key_name, sizeof(tsig_key_name));
  offset += sizeof(tsig_key_name);
  writeU16(output + offset, 250);
  offset += 2;
  writeU16(output + offset, 255);
  offset += 2;
  writeU32(output + offset, 0);
  offset += 4;
  writeU16(output + offset, (uint16_t)rdata_size);
  offset += 2;
  memcpy(output + offset, tsig_algorithm, sizeof(tsig_algorithm));
  offset += sizeof(tsig_algorithm);
  memcpy(output + offset, timestamp, sizeof(timestamp));
  offset += sizeof(timestamp);
  writeU16(output + offset, TSIG_FUDGE);
  offset += 2;
  writeU16(output + offset, TSIG_MAC_SIZE);
  offset += 2;
  memcpy(output + offset, mac, sizeof(mac));
  offset += sizeof(mac);
  output[offset++] = packet[0];
  output[offset++] = packet[1];
  writeU16(output + offset, 0);
  offset += 2;
  writeU16(output + offset, 0);
  offset += 2;

  *signed_packet = output;
  *signed_size = offset;
  return 1;
}

static int sendPacket(int sockfd, const uint8_t *data, size_t size,
                      int use_tcp, int use_tsig) {
  uint8_t *signed_packet = NULL;
  size_t maximum_size = use_tcp ? 65535 : MAX_UDP_PACKET_SIZE;
  uint8_t length[2];
  uint64_t previous_count;
  int result;

  if (use_tsig && signTsigPacket(data, size, maximum_size, &signed_packet,
                                 &size)) {
    data = signed_packet;
  }
  if (size > 65535) {
    free(signed_packet);
    return -1;
  }
  if (!use_tcp && size > MAX_UDP_PACKET_SIZE) {
    size = MAX_UDP_PACKET_SIZE;
  }
  previous_count = processedPacketCount();
  if (!use_tcp) {
    releaseWorker();
    result = send(sockfd, data, size, MSG_NOSIGNAL) == (ssize_t)size ? 0 : -1;
    if (result == 0 && waitForPacketProcessed(previous_count) == -1) {
      result = -1;
    }
    free(signed_packet);
    return result;
  }

  length[0] = (uint8_t)(size >> 8);
  length[1] = (uint8_t)size;
  if (sendAll(sockfd, length, sizeof(length)) == -1) {
    free(signed_packet);
    return -1;
  }
  result = sendAll(sockfd, data, size);
  free(signed_packet);
  return result;
}

static int receiveAll(int sockfd, uint8_t *data, size_t size) {
  size_t received = 0;

  while (received < size) {
    ssize_t result = recv(sockfd, data + received, size - received, 0);
    if (result > 0) {
      received += (size_t)result;
    } else if (result == -1 && errno == EINTR) {
      continue;
    } else {
      return -1;
    }
  }
  return 0;
}

static int waitForResponse(int sockfd, int timeout_ms, int use_tcp) {
  struct pollfd event = {.fd = sockfd, .events = POLLIN};
  uint8_t response[4096];
  uint8_t length[2];
  size_t response_size;
  int result;

  do {
    result = poll(&event, 1, timeout_ms);
  } while (result == -1 && errno == EINTR);

  if (result <= 0) {
    return -1;
  }
  if (use_tcp) {
    if (receiveAll(sockfd, length, sizeof(length)) == -1) {
      return -1;
    }
    response_size = ((size_t)length[0] << 8) | length[1];
    while (response_size > 0) {
      size_t chunk = response_size < sizeof(response) ? response_size
                                                      : sizeof(response);
      if (receiveAll(sockfd, response, chunk) == -1) {
        return -1;
      }
      response_size -= chunk;
    }
    return 0;
  }
  return recv(sockfd, response, sizeof(response), 0) > 0 ? 0 : -1;
}

static int sendMultipacketData(int sockfd, const uint8_t *data, size_t size,
                               int use_tcp, int wait_for_response,
                               int use_tsig) {
  struct timespec started;
  size_t offset = 0;
  size_t packet_count = 0;

  clock_gettime(CLOCK_MONOTONIC, &started);
  while (offset < size && packet_count < MAX_PACKET_COUNT) {
    struct timespec now;
    size_t packet_size;

    clock_gettime(CLOCK_MONOTONIC, &now);
    if ((now.tv_sec - started.tv_sec) * 1000 +
            (now.tv_nsec - started.tv_nsec) / 1000000 >=
        MULTIPACKET_TIMEOUT_MS) {
      break;
    }

    if (size - offset < 2) {
      break;
    }
    packet_size = ((size_t)data[offset] << 8) | data[offset + 1];
    offset += 2;
    if (packet_size > size - offset) {
      break;
    }
    if (sendPacket(sockfd, data + offset, packet_size, use_tcp, use_tsig) ==
        -1) {
      return -1;
    }
    offset += packet_size;
    packet_count++;

    if (offset < size) {
      if (wait_for_response) {
        waitForResponse(sockfd, RESPONSE_TIMEOUT_MS, use_tcp);
      }
    }
  }
  return packet_count > 0 ? 0 : 1;
}

static int sendRawTcpData(int sockfd, const uint8_t *data, size_t size) {
  return sendAll(sockfd, data, size);
}

static int sendRawTcpChunks(int sockfd, const uint8_t *data, size_t size) {
  size_t offset = 0;
  size_t chunk_count = 0;

  while (offset < size && chunk_count < MAX_PACKET_COUNT) {
    size_t chunk_size;

    if (size - offset < 2) {
      break;
    }
    chunk_size = ((size_t)data[offset] << 8) | data[offset + 1];
    offset += 2;
    if (chunk_size > size - offset) {
      break;
    }
    if (sendAll(sockfd, data + offset, chunk_size) == -1) {
      return -1;
    }
    offset += chunk_size;
    chunk_count++;
    if (offset < size) {
      usleep(RAW_CHUNK_DELAY_US);
    }
  }
  return chunk_count > 0 ? 0 : 1;
}

static void drainTcpConnection(int sockfd) {
  struct timespec started;
  uint8_t response[4096];

  clock_gettime(CLOCK_MONOTONIC, &started);
  while (1) {
    struct pollfd event = {.fd = sockfd, .events = POLLIN};
    struct timespec now;
    int64_t elapsed;
    int result;

    do {
      result = poll(&event, 1, RESPONSE_TIMEOUT_MS);
    } while (result == -1 && errno == EINTR);
    if (result > 0) {
      ssize_t received = recv(sockfd, response, sizeof(response), 0);
      if (received == 0) {
        return;
      }
      if (received < 0 && errno != EINTR) {
        return;
      }
    }
    clock_gettime(CLOCK_MONOTONIC, &now);
    elapsed = (now.tv_sec - started.tv_sec) * 1000;
    elapsed += (now.tv_nsec - started.tv_nsec) / 1000000;
    if (elapsed >= PROCESS_TIMEOUT_MS) {
      return;
    }
  }
}

int fuzzServer(const uint8_t *data, size_t size) {
  const uint8_t *payload;
  size_t payload_size;
  uint8_t flags;
  int sockfd;
  int send_result;
  int use_tcp;
  int use_multipacket;
  int raw_tcp;
  int use_tsig;
  uint64_t previous_count = 0;

  coverageBegin();
  if (size < 2) {
    goto done;
  }

  flags = data[0];
  payload = data + 1;
  payload_size = size - 1;
  use_tcp = flags & TCP_FLAG;
  use_multipacket = flags & MULTIPACKET_FLAG;
  raw_tcp = use_tcp && (flags & RAW_TCP_FLAG);
  use_tsig = !raw_tcp && (flags & TSIG_FLAG);

  if (!use_multipacket && payload_size > 65535) {
    payload_size = 65535;
  }

  sockfd = connectTarget(use_tcp);
  if (sockfd == -1) {
    goto done;
  }
  if (use_tcp) {
    previous_count = processedPacketCount();
    releaseWorker();
  }

  if (raw_tcp && use_multipacket) {
    send_result = sendRawTcpChunks(sockfd, payload, payload_size);
    if (send_result == 1) {
      sendRawTcpData(sockfd, payload, payload_size);
    }
  } else if (raw_tcp) {
    sendRawTcpData(sockfd, payload, payload_size);
  } else if (use_multipacket) {
    send_result = sendMultipacketData(sockfd, payload, payload_size, use_tcp,
                                      flags & WAIT_FOR_RESPONSE_FLAG,
                                      use_tsig);
    if (send_result == 1) {
      if (payload_size > 65535) {
        payload_size = 65535;
      }
      sendPacket(sockfd, payload, payload_size, use_tcp, use_tsig);
    }
  } else {
    sendPacket(sockfd, payload, payload_size, use_tcp, use_tsig);
  }

  if (use_tcp) {
    shutdown(sockfd, SHUT_WR);
    drainTcpConnection(sockfd);
  } else {
    waitForResponse(sockfd, FUZZ_RESPONSE_TIMEOUT_MS, 0);
  }
  close(sockfd);
  if (use_tcp && waitForPacketProcessed(previous_count) == -1) {
    fprintf(stderr, "timed out waiting for TCP worker completion\n");
    abort();
  }
done:
  coverageEnd();
  return 0;
}

static int targetReady(void) {
  static const uint8_t query[] = {0x12, 0x34, 0x01, 0x00, 0x00, 0x01,
                                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                  0x00, 0x00, 0x02, 0x00, 0x01};
  int sockfd = connectTarget(0);
  int ready = 0;

  if (sockfd != -1) {
    if (sendPacket(sockfd, query, sizeof(query), 0, 0) == 0 &&
        waitForResponse(sockfd, STARTUP_RESPONSE_TIMEOUT_MS, 0) == 0) {
      ready = 1;
    }
    close(sockfd);
  }
  return ready;
}

static void *launchFuzzerThread(void *unused) {
  char *args[10];
  char **args_pointer = args;
  int args_size = 0;
  int attempt = 0;

  (void)unused;
  while (!targetReady()) {
    if (++attempt % 10 == 0) {
      fprintf(stderr, "Waiting for NSD on port %d\n", target_port);
    }
    sleep(1);
  }

  args[args_size++] = "nsd-fuzzer";
  args[args_size++] = "FuzzingCorpusDirectory";
  args[args_size++] = "-max_len=131072";
  args[args_size++] = "-len_control=20";
  args[args_size++] = "-detect_leaks=0";
  args[args_size++] = "-dict=FuzzingDictionary";
  args[args_size++] = "-artifact_prefix=FuzzingArtifactDirectory/";
  args[args_size++] = "-timeout=5";
  args[args_size] = NULL;

  LLVMFuzzerRunDriver(&args_size, &args_pointer, fuzzServer);
  return NULL;
}

void launchFuzzer(void) {
  pthread_t thread;
  int result;

  if (getenv("NSD_FUZZ_DISABLE")) {
    return;
  }
  result = pthread_create(&thread, NULL, launchFuzzerThread, NULL);
  if (result != 0) {
    fprintf(stderr, "could not start fuzzer thread: %s\n", strerror(result));
    abort();
  }
  fuzzer_started = 1;
  pthread_detach(thread);
}

void fuzzerShutdown(void) {
  if (fuzzer_started) {
    _exit(0);
  }
  if (coverage_initialized) {
    cb_snapshot_free(&coverage_snapshot);
  }
}
