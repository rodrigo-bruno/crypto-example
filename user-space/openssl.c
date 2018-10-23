#include <stdint.h>
#include <openssl/evp.h>

// Note: all sizes in number of bytes.
#define AUTH_TAG_SZ 16
#define KEY_BYTE_SZ 16
#define IV_SZ 12
#define DATA_SZ 16

#define DEBUG 1

uint8_t *key   = NULL;
uint8_t *tag   = NULL;
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


void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}
int encrypt(
  unsigned char *plaintext, 
  int plaintext_len, 
  unsigned char *aad,
  int aad_len, 
  unsigned char *key, 
  unsigned char *iv,
  unsigned char *ciphertext, 
  unsigned char *tag)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int ciphertext_len;


  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  /* Initialise the encryption operation. */
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
    handleErrors();

  /* Set IV length if default 12 bytes (96 bits) is not appropriate */
  if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL))
    handleErrors();

  /* Initialise key and IV */
  if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) handleErrors();

  /* Provide any AAD data. This can be called zero or more times as
   * required
   */
//  if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
//    handleErrors();

  /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();
  ciphertext_len = len;

  /* Finalise the encryption. Normally ciphertext bytes may be written at
   * this stage, but this does not occur in GCM mode
   */
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
  ciphertext_len += len;

  /* Get the tag */
  if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
    handleErrors();

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

int main(void)
{
  printf("OLA");

  // Alloc and setup memory.
  data = calloc(sizeof(uint8_t), (DATA_SZ + AUTH_TAG_SZ + KEY_BYTE_SZ + IV_SZ));
  if (!data) {
    perror("Failed to calloc data");
    return -1;
  }
  tag = data + DATA_SZ;
  key = tag + AUTH_TAG_SZ;
  iv = key + KEY_BYTE_SZ;  

  encrypt(data, DATA_SZ, NULL, 0, key, iv, data, tag);

#ifdef DEBUG
  print_buffer("Data", data, DATA_SZ);
  print_buffer("Auth", tag,  AUTH_TAG_SZ);
  print_buffer("IV",   iv,   IV_SZ);
  print_buffer("Key",  key,  KEY_BYTE_SZ);
#endif

}
