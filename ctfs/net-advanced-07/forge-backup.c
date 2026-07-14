/*
 * forge-backup — "ops convenience tool" installed SUID-root on the Forge box.
 *
 * It backs up the web root by shelling out to tar. The bug: it calls `tar` by
 * NAME, not by absolute path, while running as root. Any user who can execute
 * it can prepend a directory to $PATH containing a malicious `tar` and have it
 * run as root. This is the classic SUID + PATH-hijack priv-esc.
 *
 * (setuid(0)/setgid(0) up front so /bin/sh under system() doesn't drop privs.)
 */
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    setgid(0);
    setuid(0);
    system("tar -czf /var/backups/forge.tar.gz -C /var/www forge 2>/dev/null");
    return 0;
}
