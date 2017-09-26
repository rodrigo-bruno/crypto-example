#include <linux/module.h>
#include <linux/scatterlist.h>
#include <crypto/aead.h>

#define DEBUG 1

// Note: all sizes in number of bytes.
#define AUTH_TAG_SZ 16
#define ASSOC_DATA_SZ 0
#define KEY_BYTE_SZ 16
#define DATA_SZ 64

u8 *key   = NULL;
u8 *iv    = NULL;
u8 *data  = NULL;
u8 *atag  = NULL;

int aes_gcm_encrypt(struct crypto_aead *tfm, 
                    u8 *iv, 
                    u8 *data, 
                    size_t data_len, 
                    u8 *atag)
{
    struct scatterlist sg[3];
    struct aead_request *aead_req;
    int reqsize = sizeof(*aead_req) + crypto_aead_reqsize(tfm);

    aead_req = kzalloc(reqsize, GFP_ATOMIC);
    if (!aead_req)
        return -ENOMEM;

    sg_init_table(sg, 3);
    sg_set_buf(&sg[0], NULL,  0); // Note: not using associated data.
    sg_set_buf(&sg[1], data,  data_len);
    sg_set_buf(&sg[2], atag,   AUTH_TAG_SZ);

    aead_request_set_tfm(   aead_req, tfm);
    aead_request_set_crypt( aead_req, sg, sg, data_len, iv);
    aead_request_set_ad(    aead_req, sg[0].length);

    crypto_aead_encrypt(aead_req);
    kzfree(aead_req);
    return 0;
}

int aes_gcm_decrypt(struct crypto_aead *tfm, 
                    u8 *iv, 
		    u8 *data, 
                    size_t data_len, 
                    u8 *atag)
{
    struct scatterlist sg[3];
    struct aead_request *aead_req;
    int reqsize = sizeof(*aead_req) + crypto_aead_reqsize(tfm);
    int err;

    if (data_len == 0)
        return -EINVAL;

    aead_req = kzalloc(reqsize, GFP_ATOMIC);
    if (!aead_req)
        return -ENOMEM;

    sg_init_table(sg, 3);
    sg_set_buf(&sg[0], NULL,  0); // Note: not using associated data.
    sg_set_buf(&sg[1], data,  data_len);
    sg_set_buf(&sg[2], atag,   AUTH_TAG_SZ);
    
    aead_request_set_tfm(aead_req, tfm);
    aead_request_set_crypt(aead_req, sg, sg, data_len + AUTH_TAG_SZ, iv);
    aead_request_set_ad(aead_req, sg[0].length);

    err = crypto_aead_decrypt(aead_req);
    kzfree(aead_req);

    // TODO - check for -EBADMSG
    return err;
}

struct crypto_aead *aes_gcm_key_setup_encrypt(u8 **key,
					      unsigned int key_len,
                                              u8 **iv)
{
      struct crypto_aead *tfm;
      int err;

      // Setup key.
      *key = kzalloc(KEY_BYTE_SZ, GFP_ATOMIC);
      if (!key)
        return ERR_PTR(-ENOMEM);

      // TODO - understand out options wrt to 2nd and 3rd arguments.
      // Setup handle.
      tfm = crypto_alloc_aead("gcm(aes)", 0, CRYPTO_ALG_ASYNC);
      if (IS_ERR(tfm)) {
          return tfm;
      }

      // Set key.
      err = crypto_aead_setkey(tfm, *key, key_len);
      if (err)
          goto free_aead;

      // Set auth tag key size.
      err = crypto_aead_setauthsize(tfm, AUTH_TAG_SZ);
      if (err)
          goto free_aead;

      // Setup initialisation vector.  
      *iv = kzalloc(crypto_aead_ivsize(tfm), GFP_ATOMIC);
      if (!iv) {
        err = -ENOMEM;
        goto free_aead;
      }

      return tfm;

free_aead:
    crypto_free_aead(tfm);
    return ERR_PTR(err);
}

void aes_gcm_key_free(struct crypto_aead *tfm)
{
    crypto_free_aead(tfm);
}


void debug_print(char* tag, char* msg)
{
#ifdef DEBUG
    printk(KERN_INFO "[%s] %s\n", tag, msg);
#endif
}

void print_buffer(char* name, u8 *buf, unsigned int sz) {
    int i = 0;
    u8 *aux = buf;
    for (; i < sz; i++) {
        printk(KERN_INFO "<rbruno> [print %s] %02x\n", name, *aux++);
    }
}

int init_module(void)
{
  int ret;
  struct crypto_aead *tfm;

  debug_print("<rbruno-aead>", "init_module() called");

  // Setup crypto.
  tfm = aes_gcm_key_setup_encrypt(&key, KEY_BYTE_SZ, &iv);
  if (IS_ERR(tfm)) {
    debug_print("<rbruno-aead>", "failed to setup crypto");
    return -1; // TODO - have a better value!
  }

  // Setup authentication tag.
  atag = kzalloc(AUTH_TAG_SZ, GFP_ATOMIC);
  if (!atag) {
    return ENOMEM;
  }

  // Setup data.
  data = kzalloc(DATA_SZ, GFP_ATOMIC);
  if (!data) {
    return ENOMEM;
  }

#ifdef DEBUG
  print_buffer("Data", data, DATA_SZ);
  print_buffer("Auth", atag, AUTH_TAG_SZ);
#endif

  // Runs encryption.
  debug_print("<rbruno-aead>", "Encryption...");
  ret = aes_gcm_encrypt(tfm, iv, data, DATA_SZ, atag);
  if (ret) {
    debug_print("<rbruno-aead>", "failed encrypt");
  }
  debug_print("<rbruno-aead>", "Encryption...Done!");
 
#ifdef DEBUG 
  print_buffer("Data", data, DATA_SZ);
  print_buffer("Auth", atag, AUTH_TAG_SZ);
#endif
 
  // Runs decryption.
  debug_print("<rbruno-aead>", "Decryption...");
  ret = aes_gcm_decrypt(tfm, iv, data, DATA_SZ, atag);
  if (ret) {
    debug_print("<rbruno-aead>", "failed decrypt");
  }
  debug_print("<rbruno-aead>", "Decryption...Done!");

#ifdef DEBUG 
  print_buffer("Data", data, DATA_SZ);
  print_buffer("Auth", atag, AUTH_TAG_SZ);
#endif

  // Free crypto. 
  aes_gcm_key_free(tfm);

  return 0;
}

void cleanup_module(void)
{
  debug_print("<rbruno-aead>", "cleanup_module() called");
}

MODULE_LICENSE("GPL");
