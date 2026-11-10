// Lists and reads a file over SFTP (libssh2) or SMB (libsmb2), the libraries
// Switch file browsers and media players use, so they can run through the
// interpose shim against peer1 (the e2e "files" service).
//
//   files-probe sftp|smb <ip>
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <libssh2.h>
#include <libssh2_sftp.h>
#include <smb2/smb2.h>
#include <smb2/libsmb2.h>

#define EXPECT "hello over the tailnet\n"

// Non-blocking, like the apps' event loops: libssh2 returns EAGAIN and the
// caller polls the socket.
static int wait_socket(int fd, LIBSSH2_SESSION *s) {
    struct pollfd p = {fd, 0, 0};
    int dir = libssh2_session_block_directions(s);
    if (dir & LIBSSH2_SESSION_BLOCK_INBOUND) p.events |= POLLIN;
    if (dir & LIBSSH2_SESSION_BLOCK_OUTBOUND) p.events |= POLLOUT;
    return poll(&p, 1, 10000);
}

#define RETRY(call) ({ __typeof__(call) _r; while ((_r = (call)) == LIBSSH2_ERROR_EAGAIN) wait_socket(fd, s); _r; })

static int sftp(const char *ip) {
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_port = htons(22);
    inet_pton(AF_INET, ip, &a.sin_addr);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0 || connect(fd, (struct sockaddr *)&a, sizeof a) != 0) {
        perror("sftp: connect");
        return 1;
    }
    libssh2_init(0);
    LIBSSH2_SESSION *s = libssh2_session_init();
    libssh2_session_set_blocking(s, 0);
    int rc;
    if ((rc = RETRY(libssh2_session_handshake(s, fd))) != 0) {
        fprintf(stderr, "sftp: handshake failed: %d\n", rc);
        return 1;
    }
    if ((rc = RETRY(libssh2_userauth_password(s, "tsnx", "tsnx"))) != 0) {
        fprintf(stderr, "sftp: login failed: %d\n", rc);
        return 1;
    }
    LIBSSH2_SFTP *sf;
    while (!(sf = libssh2_sftp_init(s)) && libssh2_session_last_errno(s) == LIBSSH2_ERROR_EAGAIN) wait_socket(fd, s);
    if (!sf) {
        fprintf(stderr, "sftp: init failed: %d\n", libssh2_session_last_errno(s));
        return 1;
    }
    LIBSSH2_SFTP_HANDLE *h;
    while (!(h = libssh2_sftp_open(sf, "/srv/share/hello.txt", LIBSSH2_FXF_READ, 0)) &&
           libssh2_session_last_errno(s) == LIBSSH2_ERROR_EAGAIN)
        wait_socket(fd, s);
    if (!h) {
        fprintf(stderr, "sftp: open failed: %d\n", libssh2_session_last_errno(s));
        return 1;
    }
    char buf[256];
    ssize_t n = RETRY(libssh2_sftp_read(h, buf, sizeof buf - 1));
    if (n != (ssize_t)strlen(EXPECT) || memcmp(buf, EXPECT, (size_t)n) != 0) {
        fprintf(stderr, "sftp: read %zd bytes, not the file\n", n);
        return 1;
    }
    RETRY(libssh2_sftp_close(h));
    RETRY(libssh2_sftp_shutdown(sf));
    RETRY(libssh2_session_disconnect(s, "bye"));
    libssh2_session_free(s);
    close(fd);
    printf("sftp: read hello.txt\n");
    return 0;
}

static int smb(const char *ip) {
    struct smb2_context *c = smb2_init_context();
    smb2_set_user(c, "tsnx");
    smb2_set_password(c, "tsnx");
    smb2_set_security_mode(c, SMB2_NEGOTIATE_SIGNING_ENABLED);
    smb2_set_authentication(c, 1);  // SMB2_SEC_NTLMSSP (not in the public headers)
    if (smb2_connect_share(c, ip, "share", "tsnx") < 0) {
        fprintf(stderr, "smb: connect failed: %s\n", smb2_get_error(c));
        return 1;
    }
    struct smb2dir *d = smb2_opendir(c, "");
    if (!d) {
        fprintf(stderr, "smb: opendir failed: %s\n", smb2_get_error(c));
        return 1;
    }
    int found = 0;
    for (struct smb2dirent *e; (e = smb2_readdir(c, d));) found |= strcmp(e->name, "hello.txt") == 0;
    smb2_closedir(c, d);
    struct smb2fh *f = smb2_open(c, "hello.txt", O_RDONLY);
    char buf[256];
    int n = f ? smb2_read(c, f, (uint8_t *)buf, sizeof buf - 1) : -1;
    if (!found || n != (int)strlen(EXPECT) || memcmp(buf, EXPECT, (size_t)n) != 0) {
        fprintf(stderr, "smb: listed %d, read %d: %s\n", found, n, smb2_get_error(c));
        return 1;
    }
    smb2_close(c, f);
    smb2_disconnect_share(c);
    smb2_destroy_context(c);
    printf("smb: listed and read hello.txt\n");
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s sftp|smb <ip>\n", argv[0]);
        return 2;
    }
    setvbuf(stdout, NULL, _IONBF, 0);
    return strcmp(argv[1], "sftp") == 0 ? sftp(argv[2]) : smb(argv[2]);
}
