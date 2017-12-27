#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>

#include <openssl/evp.h>
#include "openbsd-compat/openssl-compat.h"

#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <time.h>

#include "xmalloc.h"
#include "ssh.h"
#include "log.h"
#include "sshkey.h"
#include "sshbuf.h"
#include "authfd.h"
#include "authfile.h"
#include "pathnames.h"
#include "misc.h"
#include "ssherr.h"
#include "digest.h"


/* argv0 */
extern char *__progname;

static char *default_files[] = {
#ifdef WITH_OPENSSL
        _PATH_SSH_CLIENT_ID_RSA,
        _PATH_SSH_CLIENT_ID_DSA,
#ifdef OPENSSL_HAS_ECC
        _PATH_SSH_CLIENT_ID_ECDSA,
#endif
#endif /*WITH_OPENSSL */
        _PATH_SSH_CLIENT_ID_ED25519,
        NULL,
};

/* Hash algorithm to use for fingerprints. */
int fingerprint_hash = SSH_FP_HASH_DEFAULT;

static int
check_signature(char *filename, char* certpath)
{
        char *ca_comment = NULL;
        char valid_interval[64], *ca_fp = NULL, *signin_ca_fp = NULL;
        char *cert_comment = NULL;
        struct sshkey *public_ca, *cert = NULL;
        int r, ret = -1;

        if ((r = sshkey_load_public(filename, &public_ca, &ca_comment)) != 0)
        {
                fprintf(stderr, "Bad key file %s: %s\n", filename, ssh_err(r));
                return -1;
        }
        if ((r = sshkey_load_public(certpath, &cert, &cert_comment)) != 0)
        {
                fprintf(stderr, "Bad certificate file %s: %s\n", certpath, ssh_err(r));
                return -2;
        }
        if ((r = sshkey_is_cert(cert)) == 0)
        {
                fprintf(stderr, "File %s is not a certificate\n", certpath);
                return -3;
        }
        // here begin real check
        ca_fp = sshkey_fingerprint(public_ca, fingerprint_hash, SSH_FP_DEFAULT);
        signin_ca_fp = sshkey_fingerprint(cert->cert->signature_key, fingerprint_hash, SSH_FP_DEFAULT);
        // fingerprint is good enough to
        // distinguish different ca
        if ((r = strcmp(ca_fp, signin_ca_fp)) != 0)
        {
                fprintf(stdout, "CA fingerprint does not match\n");
                fprintf(stdout, "Signin  CA: %s\n", signin_ca_fp);
                fprintf(stdout, "Current CA: %s\n", ca_fp);
                return -4;
        }

        struct sshkey_cert *meta = cert->cert;
        sshkey_format_cert_validity(meta, valid_interval, sizeof(valid_interval));

        // check expiration
        u_int64_t now = (u_int64_t) time(NULL);
        if (meta->valid_after > now )
        {
                fprintf(stdout, "Not valid\n");
                fprintf(stdout, "Validity interval %s\n", valid_interval);
                return -5;
        }
        if (meta->valid_before < now)
        {
                fprintf(stdout, "Expired\n");
                fprintf(stdout, "Validity interval %s\n", valid_interval);
                return -6;
        }

        sshkey_free(cert);
        sshkey_free(public_ca);
        return EXIT_SUCCESS;
}

static void
usage(void)
{
        fprintf(stderr,
                "       usage: ssh-keycheck ca_key certificate\n");
        exit(1);
}

int
main(int argc, char *argv[])
{
        if (argc != 3) usage();
        return check_signature(argv[1], argv[2]);
}
