/* Kernel enforcement for the fixture runner. Policies are trusted TSV files.
 * No text parsing or observer decision occurs after the child starts.
 * Require Landlock ABI >= 4; never silently run without enforcement.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/landlock.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <grp.h>

#ifndef LANDLOCK_ACCESS_FS_TRUNCATE
#define LANDLOCK_ACCESS_FS_TRUNCATE (1ULL << 14)
#endif
#ifndef LANDLOCK_ACCESS_NET_BIND_TCP
#define LANDLOCK_ACCESS_NET_BIND_TCP (1ULL << 0)
#define LANDLOCK_ACCESS_NET_CONNECT_TCP (1ULL << 1)
#define LANDLOCK_RULE_NET_PORT 2
struct landlock_net_port_attr { uint64_t allowed_access; uint64_t port; };
#endif

/* Use our own ABI-4 struct so this builds with older distribution headers. */
struct ruleset_v4 { uint64_t handled_access_fs; uint64_t handled_access_net; };

static void die(const char *message) { perror(message); exit(125); }

static uint64_t read_rights = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
static uint64_t write_rights = LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_TRUNCATE |
    LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |
    LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG |
    LANDLOCK_ACCESS_FS_MAKE_SYM | LANDLOCK_ACCESS_FS_MAKE_FIFO |
    LANDLOCK_ACCESS_FS_MAKE_SOCK | LANDLOCK_ACCESS_FS_REFER;

static void add_path(int fd, const char *path, uint64_t access) {
    int object = open(path, O_PATH | O_CLOEXEC);
    if (object < 0) die(path);
    struct stat st;
    if (fstat(object, &st)) die("fstat");
    if (!S_ISDIR(st.st_mode))
        access &= LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE |
                  LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_TRUNCATE;
    struct landlock_path_beneath_attr rule = {.allowed_access = access, .parent_fd = object};
    if (syscall(SYS_landlock_add_rule, fd, LANDLOCK_RULE_PATH_BENEATH, &rule, 0)) die("add path rule");
    close(object);
}

/* Fixed safety filter, not a learned syscall allowlist. Docker adds its default
 * seccomp policy too. Only TCP and Unix stream sockets are available to workers.
 */
static void filter(void) {
#if defined(__aarch64__)
#define HOST_ARCH AUDIT_ARCH_AARCH64
#elif defined(__x86_64__)
#define HOST_ARCH AUDIT_ARCH_X86_64
#else
#error Unsupported architecture
#endif
#define BLOCK(nr) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM)
    struct sock_filter instructions[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, HOST_ARCH, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BLOCK(SYS_ptrace), BLOCK(SYS_process_vm_writev), BLOCK(SYS_process_vm_readv),
        BLOCK(SYS_bpf), BLOCK(SYS_mount), BLOCK(SYS_umount2), BLOCK(SYS_setns),
        BLOCK(SYS_unshare), BLOCK(SYS_keyctl),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_socket, 0, 9),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_UNIX, 3, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_INET, 2, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_INET6, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[1])),
        BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0xf),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SOCK_STREAM, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {.len = sizeof(instructions) / sizeof(instructions[0]), .filter = instructions};
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program)) die("seccomp");
}

int main(int argc, char **argv) {
    int abi = syscall(SYS_landlock_create_ruleset, NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (argc == 2 && !strcmp(argv[1], "--probe")) {
        printf("{\"landlock_abi\":%d,\"supported\":%s}\n", abi, abi >= 4 ? "true" : "false");
        return abi >= 4 ? 0 : 125;
    }
    if (argc < 5 || strcmp(argv[3], "--")) {
        fprintf(stderr, "usage: sandbox POLICY enforce|baseline -- COMMAND [ARGS...]\n"); return 125;
    }
    int enforce = !strcmp(argv[2], "enforce");
    if (!enforce && strcmp(argv[2], "baseline")) return 125;
    if (enforce && abi < 4) { fprintf(stderr, "Landlock ABI >= 4 required\n"); return 125; }
    int fd = -1;
    if (enforce) {
        struct ruleset_v4 attr = {.handled_access_fs = read_rights | write_rights | LANDLOCK_ACCESS_FS_EXECUTE |
            LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_BLOCK,
            .handled_access_net = LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP};
        fd = syscall(SYS_landlock_create_ruleset, &attr, sizeof(attr), 0);
        if (fd < 0) die("create ruleset");
        FILE *policy = fopen(argv[1], "r");
        if (!policy) die("open policy");
        char *line = NULL; size_t size = 0;
        while (getline(&line, &size, policy) > 0) {
            line[strcspn(line, "\n")] = 0;
            char *path = strchr(line, '\t');
            if (!path) { fprintf(stderr, "Invalid policy line\n"); return 125; }
            *path++ = 0;
            if (!strcmp(line, "connect")) {
                char *end; unsigned long port = strtoul(path, &end, 10);
                if (*end || !port || port > 65535) return 125;
                struct landlock_net_port_attr rule = {.allowed_access = LANDLOCK_ACCESS_NET_CONNECT_TCP, .port = port};
                if (syscall(SYS_landlock_add_rule, fd, LANDLOCK_RULE_NET_PORT, &rule, 0)) die("add port rule");
            } else if (!strcmp(line, "read")) add_path(fd, path, read_rights);
            else if (!strcmp(line, "list")) add_path(fd, path, LANDLOCK_ACCESS_FS_READ_DIR);
            else if (!strcmp(line, "write")) add_path(fd, path, write_rights);
            else if (!strcmp(line, "exec")) add_path(fd, path, LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE);
            else return 125;
        }
        free(line); fclose(policy);
    }
    /* The controller and trace files remain root-owned and outside /workspace. */
    if (geteuid() == 0 && (setgroups(0, NULL) || setgid(1000) || setuid(1000))) die("drop identity");
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) die("no_new_privs");
    if (enforce) {
        if (syscall(SYS_landlock_restrict_self, fd, 0)) die("restrict self");
        close(fd);
    }
    filter();
    if (chdir("/workspace")) die("workspace");
    execvp(argv[4], &argv[4]);
    die("exec command");
}
