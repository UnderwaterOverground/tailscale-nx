// tailscale-nx MITM test: runs the socket-virtualization suite
// (native/interpose/vsock_test.c) as ordinary homebrew, so its plain BSD
// socket calls go through the sysmodule's bsd:u MITM. Output goes to nxlink.
//
//   nxlink -s mitm-test.nro <tailnet peer ip> [<non-tailnet ip:port>]
//
// The peer needs TCP+UDP echo on port 7 (tools/echo-server.py).
#include <stdio.h>
#include <switch.h>

#define main vsock_test_main
#include "vsock_test.c"
#undef main

int main(int argc, char **argv) {
    socketInitializeDefault();
    nxlinkStdio();
    printf("tailscale-nx MITM test\n");
    int rc = 2;
    if (argc >= 2) {
        rc = vsock_test_main(argc, argv);
    } else {
        printf("usage: nxlink -s mitm-test.nro <tailnet peer ip> [<ip:port>]\n");
    }
    printf("exit %d\n", rc);
    socketExit();
    return rc;
}
