#include <openssl/evp.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "sha512_crypt.h"

void hash_password_sha512(const char *password, char *outputBuffer)
{
  unsigned char hash[EVP_MAX_MD_SIZE];
  unsigned int hash_len;
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();

  if (mdctx == NULL)
  {
    return;
  }

  EVP_DigestInit_ex(mdctx, EVP_sha512(), NULL);
  EVP_DigestUpdate(mdctx, password, strlen(password));
  EVP_DigestFinal_ex(mdctx, hash, &hash_len);
  EVP_MD_CTX_free(mdctx);

  for (unsigned int i = 0; i < hash_len; i++)
  {
    sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
  }
  outputBuffer[hash_len * 2] = 0;
}

char *get_hashed_password(const char *password)
{
  char *hashed_password = malloc(EVP_MAX_MD_SIZE * 2 + 1);
  if (hashed_password == NULL)
  {
    return NULL;
  }
  hash_password_sha512(password, hashed_password);
  return hashed_password;
}

void free_hashed_password(char *hashed_password)
{
  free(hashed_password);
}
