/*
 * Detection lab - variant B test program ("lab canary").
 *
 * A deliberately harmless program that performs three real, observable Linux actions so an
 * EDR/SIEM (Sysmon for Linux shipped to OpenSearch) can be exercised against polymorphic
 * persistence + beaconing behaviour, then exits:
 *
 *   1. it runs                 -> process-create        (Sysmon event 1)
 *   2. it writes a user systemd -> file-create           (Sysmon event 11)
 *      unit that *would* relaunch   of a persistence unit under ~/.config/systemd/user,
 *      it, ExecStart = its own      the executable path being under /tmp
 *      /tmp path
 *   3. it connects a few times  -> network-connection    (Sysmon event 3)
 *      to one lab sink address      (the "beacon")
 *
 * It installs nothing, ENABLES no unit (the file is written, not activated), starts no daemon,
 * touches no real data, holds no secret and never forks a payload. The isolated VM is reverted to
 * a clean snapshot after every run, so even the written file does not survive.
 *
 * Polymorphism: every deployed copy is this same program with a different 32-byte marker (the
 * lab_slot below, after a fixed magic). Copy 1 keeps the marker all-zero (a deterministic,
 * reproducible SHA-256 the known-hash rule pins); copies 2..N get a fresh random marker, so each
 * has a new SHA-256 and a new file name. Behaviour is identical - that is the whole point.
 *
 * Usage: lab-canary <sink-ip> <sink-port> <beacons> <interval-ms>
 *   beacons at a steady interval satisfy the 5+/15-min beaconing rule.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <libgen.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/*
 * The polymorphism slot: a fixed 16-byte magic the variant builder searches for, followed by 32
 * marker bytes it overwrites per copy. Initialised with a non-zero magic so the whole slot lands
 * in an in-file section (not .bss), and marked "used" + volatile so it is never optimised away.
 * Copy 1 is exactly this image: magic + 32 zero bytes.
 */
__attribute__((used))
volatile unsigned char lab_slot[48] = {
    'L', 'A', 'B', 'C', 'A', 'N', 'A', 'R', 'Y', 'M', 'A', 'R', 'K', '0', '1', ':',
    /* 32 marker bytes, all zero in copy 1 */
};

/* mkdir -p for a directory path (best effort; the run is harmless either way). */
static void mkdirs(const char *path) {
    char tmp[512];
    size_t n = strlen(path);
    if (n >= sizeof tmp) return;
    memcpy(tmp, path, n + 1);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0700);
            *p = '/';
        }
    }
    mkdir(tmp, 0700);
}

/* The absolute path of this running image (expected to be under /tmp for the lab). */
static int self_path(char *out, size_t cap) {
    ssize_t n = readlink("/proc/self/exe", out, cap - 1);
    if (n < 0) return -1;
    out[n] = '\0';
    return 0;
}

/*
 * Write a user systemd unit that would relaunch this binary. The file-create under the systemd
 * user-unit directory, by a process whose executable is under /tmp, is the persistence signal.
 * The unit is NOT enabled or started.
 */
static int write_persistence(const char *self, const char *stem) {
    const char *home = getenv("HOME");
    if (!home || !*home) home = "/root";
    char dir[512];
    snprintf(dir, sizeof dir, "%s/.config/systemd/user", home);
    mkdirs(dir);
    char path[512];
    snprintf(path, sizeof path, "%s/%s.service", dir, stem);
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    fprintf(f,
            "[Unit]\n"
            "Description=lab canary (detection-lab test persistence; not enabled)\n\n"
            "[Service]\n"
            "Type=oneshot\n"
            "ExecStart=%s\n\n"
            "[Install]\n"
            "WantedBy=default.target\n",
            self);
    fclose(f);
    fputs(path, stdout);
    fputc('\n', stdout);
    return 0;
}

/* One beacon: a short TCP connect to the lab sink, then close. Errors are ignored - the connect
 * attempt itself is the observable network-connection. */
static void beacon_once(const char *ip, int port) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return;
    struct timeval tv = {.tv_sec = 2, .tv_usec = 0};
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons((unsigned short)port);
    if (inet_pton(AF_INET, ip, &a.sin_addr) == 1) {
        connect(s, (struct sockaddr *)&a, sizeof a);
    }
    close(s);
}

static void sleep_ms(long ms) {
    struct timespec ts = {.tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
}

int main(int argc, char **argv) {
    if (argc != 5) {
        fprintf(stderr, "usage: %s <sink-ip> <sink-port> <beacons> <interval-ms>\n", argv[0]);
        return 2;
    }
    const char *ip = argv[1];
    int port = atoi(argv[2]);
    int beacons = atoi(argv[3]);
    long interval = atol(argv[4]);
    if (port <= 0 || port > 65535 || beacons < 0) {
        fprintf(stderr, "bad arguments\n");
        return 2;
    }

    /* The unit file is named after this copy's own file name (polymorphic per copy). */
    char self[512];
    if (self_path(self, sizeof self) != 0) {
        fprintf(stderr, "cannot read /proc/self/exe: %s\n", strerror(errno));
        return 1;
    }
    char selfcopy[512];
    snprintf(selfcopy, sizeof selfcopy, "%s", self);
    char *base = basename(selfcopy);
    char stem[256];
    snprintf(stem, sizeof stem, "%s", base);
    char *dot = strrchr(stem, '.');
    if (dot) *dot = '\0';

    write_persistence(self, stem);

    for (int i = 0; i < beacons; i++) {
        beacon_once(ip, port);
        if (i + 1 < beacons) sleep_ms(interval);
    }
    return 0;
}
