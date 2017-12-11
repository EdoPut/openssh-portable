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
        char *key_fp = NULL , *ca_fp = NULL, *signin_ca_fp = NULL;
        char *cert_comment = NULL;
        struct sshkey *public_ca, *cert = NULL;
        int r, ret = -1;

        if ((r = sshkey_load_public(filename, &public_ca, &ca_comment)) != 0)
        {
                printf("Bad key file %s: %s\n", filename, ssh_err(r));
                return -1;
        }
        if ((r = sshkey_load_public(certpath, &cert, &cert_comment)) != 0)
        {
                printf("Bad certificate file %s: %s\n", certpath, ssh_err(r));
                return -2;
        }
        if ((r = sshkey_is_cert(cert)) != 0)
        {
                printf("File %s is not a certificate: %s\n", certpath, ssh_err(r));
                return -3;
        }
        // here begin real check
        ca_fp = sshkey_fingerprint(public_ca, fingerprint_hash, SSH_FP_DEFAULT);
        signin_ca_fp = sshkey_fingerprint(cert->cert->signature_key, fingerprint_hash, SSH_FP_DEFAULT);
        // fingerprint is good enough to
        // distinguish different ca
        if ((r = strcmp(ca_fp, signin_ca_fp)) != 0)
        {
                printf("CA fingerprint does not match\n");
                printf("Signin  CA: %s\n", signin_ca_fp);
                printf("Current CA: %s\n", ca_fp);
                return -4;
        }

        struct sshkey_cert *meta = cert->cert;

        // check expiration
        u_int64_t now = (u_int64_t) time(NULL);
        if (meta->valid_after > now )
        {
                printf("Not yet valid\n");
                return -5;
        }
        if (meta->valid_before < now)
        {
                printf("Expired\n");
                return -6;
        }

        sshkey_free(cert);
        sshkey_free(public_ca);
        return EXIT_SUCCESS;
}

int
main(int argc, char *argv[])
{
        return check_signature(argv[1], argv[2]);
}
