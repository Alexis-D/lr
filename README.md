# `lr`: last-resort

`lr` is an encryption utility, that uses the
[Argon2i](https://en.wikipedia.org/wiki/Argon2) for key derivation, and
AES256-GCM for encryption. This was mostly written as an exercise in using
[libsodium](https://download.libsodium.org/doc/) and showing that one
shouldn't implement its own crypto. Despite being a very simple utility that
only supports encryption/decryption it still is ~300LOC given all the
error-handling. That's a lot of room for coding mistakes that would render
secrets, well, not so secret. As a result you shouldn't be using this to store
your secrets (see <https://github.com/Alexis-D/lr/issues/1> for at least one
way in which the code in this repo was broken).

## Building/usage

```
$ make
gcc lr.c -lsodium -o lr -Wall -Wextra -pedantic
$ ./lr encrypt lr.c >encrypted
Please enter your password:
Please repeat your password:
$ ./lr decrypt encrypted >decrypted
Please enter your password:
$ md5sum lr.c decrypted
1fbb70eb23c0d60a96ba0a7319002247  lr.c
1fbb70eb23c0d60a96ba0a7319002247  decrypted
$
```

## Dependencies

Known to work with libsodium 1.0.11.
