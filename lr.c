#include <errno.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

char* lr_strdup(char *s) {
    size_t len = strlen(s) + 1;
    char *buf = sodium_malloc(len);

    if (!buf) {
        return NULL;
    }

    memcpy(buf, s, len);
    return buf;
}

// TODO(adaboville): get rid of getpass(2)
char* lr_getpass(char *prompt) {
    char *pwd = getpass(prompt);

    if (!pwd) {
        return NULL;
    }

    return lr_strdup(pwd);
}

int lr_kdf(unsigned char *key, unsigned char keylen, char *pwd, unsigned char *salt) {
    return crypto_pwhash(
            key,
            keylen,
            pwd,
            strlen(pwd),
            salt,
            crypto_pwhash_OPSLIMIT_SENSITIVE,
            crypto_pwhash_MEMLIMIT_SENSITIVE,
            crypto_pwhash_ALG_DEFAULT);
}

int lr_encrypt(char *file) {
    struct stat st;

    if (stat(file, &st) != 0) {
        fprintf(stderr, "stat(\"%s\"): %s\n", file, strerror(errno));
        return 4;
    }

    char *first_pwd = lr_getpass("Please enter your password: ");

    if (!first_pwd) {
        fprintf(stderr, "Couldn't read password.\n");
        return 5;
    }

    char *second_pwd = lr_getpass("Please repeat your password: ");

    if (!second_pwd) {
        fprintf(stderr, "Couldn't read password.\n");
        sodium_free(first_pwd);
        return 6;
    }

    if (strlen(first_pwd) != strlen(second_pwd) || sodium_memcmp(first_pwd, second_pwd, strlen(first_pwd)) != 0) {
        fprintf(stderr, "The passwords didn't match.\n");
        sodium_free(first_pwd);
        sodium_free(second_pwd);
        return 7;
    }

    // from now on first_pwd is the only password
    sodium_free(second_pwd);

    FILE *fp = fopen(file, "rb");

    if (!fp) {
        fprintf(stderr, "Couldn't open %s: %s\n", file, strerror(errno));
        sodium_free(first_pwd);
        return 8;
    }

    unsigned char *buffer = sodium_malloc(st.st_size);

    if (!buffer) {
        fprintf(stderr, "Couldn't allocate memory.\n");
        sodium_free(first_pwd);
        return 9;
    }

    if (fread(buffer, sizeof (char), st.st_size, fp) != (size_t)st.st_size) {
        fprintf(stderr, "Couldn't read the whole file.\n");
        sodium_free(first_pwd);
        sodium_free(buffer);
        return 10;
    }

    if (fclose(fp) != 0) {
        fprintf(stderr, "Couldn't close %s: %s", file, strerror(errno));
        sodium_free(first_pwd);
        sodium_free(buffer);
        return 11;
    }

    // key derivation!
    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char key[crypto_aead_aes256gcm_KEYBYTES];

    randombytes_buf(salt, sizeof salt);

    if (lr_kdf(key, sizeof key, first_pwd, salt) != 0) {
        fprintf(stderr, "Couldn't derive a key.\n");
        sodium_free(first_pwd);
        sodium_free(buffer);
        return 12;
    }
    sodium_free(first_pwd);

    // encryption!
    unsigned char nonce[crypto_aead_aes256gcm_NPUBBYTES];
    randombytes_buf(nonce, sizeof nonce);
    unsigned char *ciphertext = sodium_allocarray(st.st_size + crypto_aead_aes256gcm_ABYTES, sizeof (unsigned char));
    unsigned long long ciphertext_len;

    crypto_aead_aes256gcm_encrypt(
            ciphertext,
            &ciphertext_len,
            buffer,
            st.st_size,
            NULL,
            0,
            NULL,
            nonce,
            key);
    if (fwrite(salt, sizeof salt, 1, stdout) != 1) {
        sodium_free(buffer);
        sodium_free(ciphertext);
        fprintf(stderr, "Couldn't write the whole encrypted file. Encrypted file is corrupted.\n");
        return 14;
    }
    if (fwrite(nonce, sizeof nonce, 1, stdout) != 1) {
        sodium_free(buffer);
        sodium_free(ciphertext);
        fprintf(stderr, "Couldn't write the whole encrypted file. Encrypted file is corrupted.\n");
        return 15;
    }
    if (fwrite(ciphertext, sizeof (char), ciphertext_len, stdout) != ciphertext_len) {
        sodium_free(buffer);
        sodium_free(ciphertext);
        fprintf(stderr, "Couldn't write the whole encrypted file. Encrypted file is corrupted.\n");
        return 16;
    }

    sodium_free(buffer);
    sodium_free(ciphertext);
    return 0;
}

int lr_decrypt(char *file) {
    struct stat st;

    if (stat(file, &st) != 0) {
        fprintf(stderr, "stat(\"%s\"): %s\n", file, strerror(errno));
        return 4;
    }

    char *pwd = lr_getpass("Please enter your password: ");

    if (!pwd) {
        fprintf(stderr, "Couldn't read password.\n");
        return 5;
    }

    FILE *fp = fopen(file, "rb");

    if (!fp) {
        fprintf(stderr, "Couldn't open %s: %s\n", file, strerror(errno));
        sodium_free(pwd);
        return 8;
    }

    unsigned char *buffer = sodium_malloc(st.st_size);

    if (!buffer) {
        fprintf(stderr, "Couldn't allocate memory.\n");
        sodium_free(pwd);
        return 9;
    }

    if (fread(buffer, sizeof (char), st.st_size, fp) != (size_t)st.st_size) {
        fprintf(stderr, "Couldn't read the whole file.\n");
        sodium_free(pwd);
        sodium_free(buffer);
        return 10;
    }

    if (fclose(fp) != 0) {
        fprintf(stderr, "Couldn't close %s: %s", file, strerror(errno));
        sodium_free(pwd);
        sodium_free(buffer);
        return 11;
    }

    // key derivation!
    unsigned char *salt = buffer;
    unsigned char key[crypto_aead_aes256gcm_KEYBYTES];

    if (lr_kdf(key, sizeof key, pwd, salt) != 0) {
        fprintf(stderr, "Couldn't derive a key.\n");
        sodium_free(pwd);
        sodium_free(buffer);
        return 12;
    }
    sodium_free(pwd);

    // decryption!
    unsigned char *nonce = buffer + crypto_pwhash_SALTBYTES;
    unsigned char *decrypted = sodium_allocarray(st.st_size - crypto_pwhash_SALTBYTES - crypto_aead_aes256gcm_NPUBBYTES, sizeof (unsigned char));
    unsigned long long decrypted_len;

    if (crypto_aead_aes256gcm_decrypt(
            decrypted,
            &decrypted_len,
            NULL,
            buffer + crypto_pwhash_SALTBYTES + crypto_aead_aes256gcm_NPUBBYTES,
            st.st_size - crypto_pwhash_SALTBYTES - crypto_aead_aes256gcm_NPUBBYTES,
            NULL,
            0,
            nonce,
            key) == -1) {
        sodium_free(buffer);
        sodium_free(decrypted);
        fprintf(stderr, "Couldn't decrypt. Password might be wrong, or message might have been tampered with.\n");
        return 17;
    }

    if (fwrite(decrypted, sizeof (char), decrypted_len, stdout) != decrypted_len) {
        sodium_free(buffer);
        sodium_free(decrypted);
        fprintf(stderr, "Couldn't write the whole decrypted file. Decrypted file is incomplete.\n");
        return 16;
    }

    sodium_free(buffer);
    sodium_free(decrypted);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "./lr encrypt file\n");
        fprintf(stderr, "./lr decrypt file\n");
        return 1;
    }

    if (sodium_init() == -1) {
        fprintf(stderr, "libsodium failed to initialize.\n");
        return 3;
    }

    if (crypto_aead_aes256gcm_is_available() == 0) {
        fprintf(stderr, "aes256gcm isn't available.\n");
        return 13;
    }

    if (strcmp(argv[1], "encrypt") == 0) {
        return lr_encrypt(argv[2]);
    } else if (strcmp(argv[1], "decrypt") == 0) {
        return lr_decrypt(argv[2]);
    } else {
        fprintf(stderr, "%s isn't a valid operation.\n", argv[1]);
        return 2;
    }
}
