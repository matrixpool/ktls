#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/crypto.h>
#include <linux/err.h>
#include <linux/scatterlist.h>
#include <crypto/hash.h>
#include <crypto/skcipher.h>


#define SM4_BLOCK_SIZE  32
#define HMAC_KEY_SIZE   32

static int __init hmac_sm4_init(void)
{
    struct crypto_ahash *tfm;
    struct ahash_request *req;
    struct scatterlist sg;

    uint8_t data[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x17, 0x01, 0x01, 0x00, 0x11, 
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 
        0x61,
    };
    uint8_t key[] = {
        0x34, 0xd1, 0x8b, 0x85, 0xdf, 0xa7, 0x15, 0xdb, 
        0xb9, 0x93, 0x2d, 0x16, 0x7e, 0x6f, 0xa3, 0xc4, 
        0xdb, 0xe8, 0x4b, 0x73, 0xa1, 0x7b, 0x37, 0x92, 
        0x91, 0x98, 0xa5, 0x65, 0x2b, 0x59, 0x4b, 0xe3, 
    };

    unsigned int data_len = sizeof(data);
    unsigned char result[SM4_BLOCK_SIZE];
    int ret;

    // Allocate transformation context
    tfm = crypto_alloc_ahash("hmac(sm3)", 0, 0);
    if (IS_ERR(tfm)) {
        pr_err("Failed to allocate transformation context\n");
        return PTR_ERR(tfm);
    }

    // Allocate request
    req = ahash_request_alloc(tfm, GFP_KERNEL);
    if (!req) {
        pr_err("Failed to allocate request\n");
        ret = -ENOMEM;
        goto out_free_tfm;
    }

    // Set the HMAC key
    ret = crypto_ahash_setkey(tfm, key, HMAC_KEY_SIZE);
    if (ret) {
        pr_err("Failed to set key: %d\n", ret);
        goto out_free_req;
    }

    // Set up scatterlist
    sg_init_one(&sg, data, data_len);

    // Set the data to be hashed
    ahash_request_set_crypt(req, &sg, result, data_len);

    // Perform hashing
    ret = crypto_ahash_digest(req);
    if (ret) {
        pr_err("Failed to compute digest: %d\n", ret);
        goto out_free_req;
    }

    // Print the result
    pr_info("HMAC-SM4 result: ");
    for (int i = 0; i < SM4_BLOCK_SIZE; i++)
        pr_cont("%02x", result[i]);
    pr_cont("\n");

out_free_req:
    ahash_request_free(req);
out_free_tfm:
    crypto_free_ahash(tfm);
    return ret;
}

static void __exit hmac_sm4_exit(void)
{
    pr_info("HMAC-SM4 module exit\n");
}

module_init(hmac_sm4_init);
module_exit(hmac_sm4_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("HMAC-SM4 Example");
MODULE_AUTHOR("Your Name");
