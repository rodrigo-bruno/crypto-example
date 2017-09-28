#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>

#include <kcapi.h>

// Note: all sizes in number of bytes.
#define AUTH_TAG_SZ 16
#define KEY_BYTE_SZ 16
#define DATA_SZ 16

#define DEBUG 1

uint8_t *key   = NULL;
uint8_t *iv    = NULL;
uint8_t *data  = NULL;

void print_buffer(char* name, uint8_t *buf, unsigned int sz) {
    int i = 0;
    uint8_t *aux = buf;
    for (; i < sz; i++) {
        printf("[buffer %s] %02x\n", name, *aux++);
    }
}

void debug_print(char* tag, char* msg)
{
#ifdef DEBUG
  printf("[%s] %s\n", tag, msg);
#endif
}

int main(void)
{
  int ret;
  struct kcapi_handle *handle = NULL;
  struct timeval t0,t1;

  // Setup crypto (part 1).
  ret = kcapi_aead_init(&handle, "gcm(aes)", 0);
  if (ret) {
    perror("Cannot setup kcapi handle");
    return -1;
  }

  // Alloc and setup memory.
  key = calloc(sizeof(uint8_t), KEY_BYTE_SZ);
  if (!key) {
    perror("Failed to calloc key");
    return -1;
  }
  ret = posix_memalign((void**)&data, sysconf(_SC_PAGESIZE), sizeof(uint8_t) * (DATA_SZ + AUTH_TAG_SZ));
  if (ret) {
    perror("Failed to calloc data");
    return -1;
  }
  bzero(data, sizeof(uint8_t) * (DATA_SZ + AUTH_TAG_SZ));
  ret = kcapi_cipher_ivsize(handle);
  if (!ret) {
    perror("Failed to get iv size");
    return -1;
  }
  iv = calloc(sizeof(uint8_t), ret);
  if (!iv) {
    perror("Failed to calloc iv");
    return -1;
  }
  
  // Setup crypto (part 2).
  ret = kcapi_aead_setkey(handle, key, KEY_BYTE_SZ);
  if (ret) {
    perror("Failed to setup key");
    return -1;
  }
  ret = kcapi_aead_settaglen(handle, AUTH_TAG_SZ);
  if (ret) {
    perror("Failed to set tag length");
    return -1;
  }
  kcapi_aead_setassoclen(handle, 0);

#ifdef DEBUG
  print_buffer("Data", data, DATA_SZ);
  print_buffer("Auth", data + DATA_SZ, AUTH_TAG_SZ);
  print_buffer("IV",   iv,  kcapi_cipher_ivsize(handle));
  print_buffer("Key",  key, KEY_BYTE_SZ);

#endif

  // Runs encryption.
  debug_print("<rbruno-aead>", "Encryption...");
  gettimeofday(&t0, NULL); 
  ret = kcapi_aead_encrypt(
        handle, data, DATA_SZ, iv, data, DATA_SZ + AUTH_TAG_SZ, KCAPI_ACCESS_HEURISTIC);
  if (ret < 0) {
    perror("Failed to encrypt data");
    return -1;
  }
  gettimeofday(&t1, NULL); 
  printf("<rbruno-aead> Encryption...Done (%lu microseconds)!\n",
      (uint64_t) (t1.tv_sec - t0.tv_sec)*1000000 + (t1.tv_usec - t0.tv_usec));

#ifdef DEBUG
  print_buffer("Data", data, DATA_SZ);
  print_buffer("Auth", data + DATA_SZ, AUTH_TAG_SZ);
  print_buffer("IV",   iv,  kcapi_cipher_ivsize(handle));
  print_buffer("Key",  key, KEY_BYTE_SZ);

#endif

  // Runs decryption.
  debug_print("<rbruno-aead>", "Decryption...");
  gettimeofday(&t0, NULL); 
  ret = kcapi_aead_decrypt(
        handle, data, DATA_SZ + AUTH_TAG_SZ, iv, data, DATA_SZ, KCAPI_ACCESS_HEURISTIC);
  if (ret < 0) {
    perror("Failed to decrypt data");
    return -1;
  }
  gettimeofday(&t1, NULL); 
  printf("<rbruno-aead> Decryption...Done (%lu microseconds)!\n",
      (uint64_t) (t1.tv_sec - t0.tv_sec)*1000000 + (t1.tv_usec - t0.tv_usec));


#ifdef DEBUG
  print_buffer("Data", data, DATA_SZ);
  print_buffer("Auth", data + DATA_SZ, AUTH_TAG_SZ);
  print_buffer("IV",   iv,  kcapi_cipher_ivsize(handle));
  print_buffer("Key",  key, KEY_BYTE_SZ);
#endif

  // Free crypto.
  kcapi_aead_destroy(handle);
  free(data),
  free(iv);
  free(key);
  return 0;
}
