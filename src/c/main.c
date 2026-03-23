#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/file.h>

#include "sha256.h"
#include "lm_ots.h"
#include "lms.h"
#include "utils.h"
#include "bundle.h"

static void usage(const char *prog) {
    fprintf(stderr,
"Usage:\n"
"  %s keygen <bundle.lms>\n"
"  %s sign   <bundle.lms> <message.bin> <sig.bin>\n"
"  %s verify <bundle.lms> <sig.bin> <message.bin>\n"
"  %s info   <bundle.lms>\n\n",
        prog, prog, prog, prog);
    exit(1);
}

static void get_timestamp(char *buf, size_t bufsize) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    strftime(buf, bufsize, "%Y%m%d_%H%M%S", t);
}

int main(int argc, char **argv) {
    if (argc < 2) usage(argv[0]);

    const char *cmd = argv[1];

    // =========================================================
    // KEYGEN
    // =========================================================
    if (strcmp(cmd, "keygen") == 0) {
        if (argc != 3) usage(argv[0]);
        const char *bundle_path = argv[2];

        uint8_t I[16];
        uint8_t seed[32];

        if (secure_random(I, 16) != 0 || secure_random(seed, 32) != 0) {
            fprintf(stderr, "Random generation failed, aborting.\n");
            return 1;
        }

        uint8_t pub[20 + N];
        uint8_t tree[2 * LMS_LEAVES][N];

        if (lms_keygen(I, seed, pub, tree) != 0) {
            fprintf(stderr, "Key generation failed\n");
            return 1;
        }

        LMS_Bundle b = {0};
        memcpy(b.I, I, 16);
        b.next_q = 0;
        memcpy(b.pub, pub, 20 + N);
        b.has_seed = 1;
        memcpy(b.seed, seed, 32);
        b.has_last_sig = 0;

        // Optional: persist tree for speedup (Step 4d)
        b.has_tree = 1;
        memcpy(b.tree, tree, sizeof(tree));

        if (bundle_write(bundle_path, &b) != 0) {
            fprintf(stderr, "Failed to write bundle: %s\n", bundle_path);
            return 1;
        }

        char ts[32];
        get_timestamp(ts, sizeof ts);

        printf("Key bundle created: %s\n", bundle_path);
        printf("  created:       %s\n", ts);
        printf("  next q:        0 / %d\n", LMS_LEAVES);

        return 0;
    }

    // =========================================================
    // SIGN
    // =========================================================
    if (strcmp(cmd, "sign") == 0) {
        if (argc != 5) usage(argv[0]);

        const char *bundle_path = argv[2];
        const char *msg_path    = argv[3];
        const char *sig_path    = argv[4];

        LMS_Bundle b = {0};

        // Open file for locking
        int fd = open(bundle_path, O_RDWR);
        if (fd < 0) {
            perror("open failed");
            return 1;
        }

        if (flock(fd, LOCK_EX) != 0) {
            perror("flock failed");
            close(fd);
            return 1;
        }

        // Read bundle
        if (bundle_read(bundle_path, &b) != 0) {
            fprintf(stderr, "Failed to read bundle\n");
            flock(fd, LOCK_UN);
            close(fd);
            return 1;
        }

        if (!b.has_seed) {
            fprintf(stderr, "Bundle does not contain a seed\n");
            flock(fd, LOCK_UN);
            close(fd);
            return 1;
        }

        if (b.next_q >= LMS_LEAVES) {
            fprintf(stderr, "No OTS keys left (q = %u)\n", b.next_q);
            flock(fd, LOCK_UN);
            close(fd);
            return 1;
        }

        // Reserve q
        uint32_t q = b.next_q;
        b.next_q++;

        if (bundle_write(bundle_path, &b) != 0) {
            fprintf(stderr, "Failed to update bundle\n");
            flock(fd, LOCK_UN);
            close(fd);
            return 1;
        }

        printf("Reserved q = %u\n", q);

        flock(fd, LOCK_UN);
        close(fd);

        // Read message
        uint8_t *msg = NULL;
        size_t msglen;

        if (read_file(msg_path, &msg, &msglen) != 0) {
            fprintf(stderr, "Failed to read message\n");
            return 1;
        }

        // Build tree for signing (always recompute to ensure correct signature)
        uint8_t tree[2 * LMS_LEAVES][N];
        lms_build_tree(b.I, b.seed, tree);

        uint8_t sig[SIG_BYTES];

        if (lms_sign(b.I, q, b.seed, tree, msg, msglen, sig) != 0) {
            fprintf(stderr, "Signing failed\n");
            free(msg);
            return 1;
        }

        free(msg);

        // Write signature
        if (write_file(sig_path, sig, SIG_BYTES) != 0) {
            fprintf(stderr, "Failed to write signature\n");
            return 1;
        }

        // Update bundle with last signature 
        if (bundle_read(bundle_path, &b) != 0) {
            fprintf(stderr, "Failed to re-read bundle\n");
            return 1;
        }

        b.has_last_sig = 1;
        memcpy(b.last_sig, sig, SIG_BYTES);

        if (bundle_write(bundle_path, &b) != 0) {
            fprintf(stderr, "Failed to write final bundle\n");
            return 1;
        }

        printf("Signature created (q = %u) -> %s\n", q, sig_path);
        printf("Bundle updated: %s\n", bundle_path);

        return 0;
    }

    // =========================================================
    // VERIFY
    // =========================================================
    if (strcmp(cmd, "verify") == 0) {
        if (argc != 5) usage(argv[0]);

        const char *bundle_path = argv[2];
        const char *sig_path    = argv[3];
        const char *msg_path    = argv[4];

        LMS_Bundle b = {0};

        if (bundle_read(bundle_path, &b) != 0) {
            fprintf(stderr, "Failed to read bundle: %s\n", bundle_path);
            return 1;
        }

        uint8_t *sig = NULL, *msg = NULL;
        size_t siglen, msglen;

        if (read_file(sig_path, &sig, &siglen) != 0 || siglen != SIG_BYTES) {
            fprintf(stderr, "Invalid signature file\n");
            return 1;
        }

        if (read_file(msg_path, &msg, &msglen) != 0) {
            fprintf(stderr, "Failed to read message\n");
            free(sig);
            return 1;
        }

        int ok = lms_verify(b.pub, msg, msglen, sig);

        free(sig);
        free(msg);

        if (ok == 0) {
            printf("Signature is valid\n");
            return 0;
        } else {
            printf("Signature is INVALID\n");
            return 10;
        }
    }

    // =========================================================
    // INFO
    // =========================================================
    if (strcmp(cmd, "info") == 0) {
        if (argc != 3) usage(argv[0]);

        const char *bundle_path = argv[2];

        LMS_Bundle b = {0};

        if (bundle_read(bundle_path, &b) != 0) {
            fprintf(stderr, "Failed to read bundle: %s\n", bundle_path);
            return 1;
        }

        printf("Bundle info: %s\n", bundle_path);
        printf("  Identifier:     ");
        for (int i = 0; i < 16; i++) printf("%02x", b.I[i]);
        printf("\n");
        printf("  Next q:         %u (max %d)\n", b.next_q, LMS_LEAVES);
        printf("  Seed present:   %s\n", b.has_seed ? "yes" : "no");
        printf("  Last signature: %s\n", b.has_last_sig ? "yes" : "no");
        printf("  Tree stored:    %s\n", b.has_tree ? "yes" : "no");

        return 0;
    }

    usage(argv[0]);
    return 1;
}
