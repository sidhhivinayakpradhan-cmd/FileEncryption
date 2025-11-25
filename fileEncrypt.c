#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#define BUFSIZE 8192
#define MAGIC 0x46454E43u /* 'FENC' */

static uint64_t fnv1a64(const char *s) {
    uint64_t hash = 14695981039346656037ULL;
    for (size_t i=0;i<strlen(s);++i) {
        hash ^= (unsigned char)s[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

/* xorshift64* */
static uint64_t xorshift64star(uint64_t *state) {
    uint64_t x = *state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    *state = x;
    return x * 2685821657736338717ULL;
}

/* CRC32 (IEEE 802.3) */
static uint32_t crc32_table[256];
static void init_crc32(void) {
    uint32_t poly = 0xEDB88320u;
    for (int i=0;i<256;++i) {
        uint32_t crc = i;
        for (int j=0;j<8;++j) {
            if (crc & 1) crc = (crc >> 1) ^ poly;
            else crc >>= 1;
        }
        crc32_table[i] = crc;
    }
}
static uint32_t crc32_calc(const unsigned char *buf, size_t len, uint32_t prev) {
    uint32_t crc = ~prev;
    for (size_t i=0;i<len;++i) {
        crc = (crc >> 8) ^ crc32_table[(crc ^ buf[i]) & 0xFFu];
    }
    return ~crc;
}

/* header: [magic:uint32][iv:uint64][crc:uint32] */
#pragma pack(push,1)
struct header {
    uint32_t magic;
    uint64_t iv;
    uint32_t crc;
};
#pragma pack(pop)

static void read_password(char *buf, size_t bufsz, const char *prompt) {
    printf("%s", prompt);
    if (!fgets(buf, (int)bufsz, stdin)) { buf[0]=0; return; }
    size_t len=strlen(buf);
    if (len>0 && buf[len-1]=='\n') buf[len-1]=0;
}

/* process: mode 'e' or 'd' */
int process_file(const char *inpath, const char *outpath, const char *password, char mode) {
    FILE *fin = fopen(inpath, mode=='e'?"rb":"rb");
    if (!fin) { fprintf(stderr,"Error: cannot open input '%s'\n", inpath); return 1; }
    FILE *fout = fopen(outpath, "wb");
    if (!fout) { fprintf(stderr,"Error: cannot open output '%s'\n", outpath); fclose(fin); return 2; }

    if (mode == 'e') {
        /* compute CRC32 of whole input first */
        uint32_t crc = 0;
        unsigned char buf[BUFSIZE];
        size_t r;
        rewind(fin);
        crc = crc32_calc((const unsigned char*)"", 0, 0); /* init */
        while ((r=fread(buf,1,BUFSIZE,fin))>0) {
            crc = crc32_calc(buf, r, crc);
        }
        /* prepare header */
        struct header h;
        h.magic = MAGIC;
        /* generate IV using time() and some rand() */
        uint64_t iv = ((uint64_t)time(NULL) << 32) ^ ((uint64_t)rand() << 1) ^ (uint64_t)(crc);
        h.iv = iv;
        h.crc = crc;
        /* write header */
        if (fwrite(&h, sizeof(h), 1, fout) != 1) { fprintf(stderr,"Write header failed\n"); fclose(fin); fclose(fout); return 3; }

        /* seed PRNG with password-derived hash + iv */
        char keybuf[512];
        snprintf(keybuf, sizeof(keybuf), "%s%llu", password, (unsigned long long)iv);
        uint64_t state = fnv1a64(keybuf);
        /* encrypt and write */
        rewind(fin);
        size_t total = 0;
        while ((r=fread(buf,1,BUFSIZE,fin))>0) {
            for (size_t i=0;i<r;++i) {
                unsigned char ks = (unsigned char)(xorshift64star(&state) & 0xFFu);
                buf[i] ^= ks;
            }
            if (fwrite(buf,1,r,fout)!=r) { fprintf(stderr,"Write failed\n"); fclose(fin); fclose(fout); return 4; }
            total += r;
            printf("\rEncrypted %zu bytes...", total);
            fflush(stdout);
        }
        printf("\nEncryption finished. Output: %s\n", outpath);
    } else {
        /* Decryption mode: read header */
        struct header h;
        if (fread(&h, sizeof(h), 1, fin) != 1) { fprintf(stderr,"Error: failed to read header (file too short)\n"); fclose(fin); fclose(fout); return 5; }
        if (h.magic != MAGIC) { fprintf(stderr,"Error: invalid file format (magic mismatch)\n"); fclose(fin); fclose(fout); return 6; }
        uint64_t iv = h.iv;
        uint32_t expected_crc = h.crc;

        /* seed PRNG same way */
        char keybuf[512];
        snprintf(keybuf, sizeof(keybuf), "%s%llu", password, (unsigned long long)iv);
        uint64_t state = fnv1a64(keybuf);

        /* decrypt and compute CRC */
        unsigned char buf[BUFSIZE];
        size_t r;
        uint32_t crc = crc32_calc((const unsigned char*)"", 0, 0);
        size_t total = 0;
        while ((r=fread(buf,1,BUFSIZE,fin))>0) {
            for (size_t i=0;i<r;++i) {
                unsigned char ks = (unsigned char)(xorshift64star(&state) & 0xFFu);
                buf[i] ^= ks;
            }
            /* update crc with decrypted bytes */
            crc = crc32_calc(buf, r, crc);
            if (fwrite(buf,1,r,fout)!=r) { fprintf(stderr,"Write failed\n"); fclose(fin); fclose(fout); return 7; }
            total += r;
            printf("\rDecrypted %zu bytes...", total);
            fflush(stdout);
        }
        printf("\nDecryption finished. Output: %s\n", outpath);
        if (crc != expected_crc) {
            fprintf(stderr, "Warning: CRC mismatch (password may be wrong or file corrupted). Expected: 0x%08X, Got: 0x%08X\n", expected_crc, crc);
            /* still return success code but warn */
        } else {
            printf("Integrity check passed (CRC32 OK).\n");
        }
    }

    fclose(fin);
    fclose(fout);
    return 0;
}

void print_menu(void) {
    printf("========================================\n");
    printf("  Simple File Encryptor (Improved Demo)\n");
    printf("========================================\n");
    printf("1) Encrypt a file\n");
    printf("2) Decrypt a file\n");
    printf("3) Exit\n");
    printf("Enter choice: ");
}

int main(int argc, char *argv[]) {
    srand((unsigned int)time(NULL));
    init_crc32();

    /* If called with args, act as non-interactive */
    if (argc == 4) {
        char password[256];
        read_password(password, sizeof(password), "Enter password: ");
        char mode = argv[1][0];
        if (mode!='e' && mode!='d') { fprintf(stderr,"Mode must be 'e' or 'd'\n"); return 1; }
        return process_file(argv[2], argv[3], password, mode);
    }

    while (1) {
        print_menu();
        int ch = getchar();
        int c;
        while ((c = getchar()) != '\n' && c != EOF); /* flush */
        if (ch == '1') {
            char in[512], out[512], pwd[256];
            printf("Input file: ");
            if (!fgets(in, sizeof(in), stdin)) break;
            if (in[strlen(in)-1]=='\n') in[strlen(in)-1]=0;
            printf("Output file: ");
            if (!fgets(out, sizeof(out), stdin)) break;
            if (out[strlen(out)-1]=='\n') out[strlen(out)-1]=0;
            read_password(pwd, sizeof(pwd), "Enter password: ");
            process_file(in, out, pwd, 'e');
        } else if (ch == '2') {
            char in[512], out[512], pwd[256];
            printf("Input file: ");
            if (!fgets(in, sizeof(in), stdin)) break;
            if (in[strlen(in)-1]=='\n') in[strlen(in)-1]=0;
            printf("Output file: ");
            if (!fgets(out, sizeof(out), stdin)) break;
            if (out[strlen(out)-1]=='\n') out[strlen(out)-1]=0;
            read_password(pwd, sizeof(pwd), "Enter password: ");
            process_file(in, out, pwd, 'd');
        } else if (ch == '3') {
            printf("Goodbye.\n");
            break;
        } else {
            printf("Invalid choice.\n");
        }
    }

    return 0;
}
