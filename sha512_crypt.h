#ifndef SHA512_CRYPT_H
#define SHA512_CRYPT_H

void hash_password_sha512(const char *password, char *outputBuffer);
char* get_hashed_password(const char *password);
void free_hashed_password(char *hashed_password);

#endif // SHA512_CRYPT_H
