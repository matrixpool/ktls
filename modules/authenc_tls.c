// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Authenctls: Simple AEAD wrapper for TLS1.2, derived from authenc.c
 *
 * Copyright (c) 2024 Fu Yong <matrixpool@163.com>
 */

#include <crypto/internal/aead.h>
#include <crypto/internal/hash.h>
#include <crypto/internal/skcipher.h>
#include <crypto/authenc.h>
#include <crypto/null.h>
#include <crypto/scatterwalk.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/rtnetlink.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

struct authenc_tls_instance_ctx {
	struct crypto_ahash_spawn auth;
	struct crypto_skcipher_spawn enc;
	unsigned int reqoff;
};

struct crypto_authenc_tls_ctx {
	struct crypto_ahash *auth;
	struct crypto_skcipher *enc;
	struct crypto_sync_skcipher *null;
};

struct authenc_tls_request_ctx {
	struct scatterlist *nsg;
	struct scatterlist src[2];
	struct scatterlist dst[2];
	char tail[];
};

// static int get_sg_length(struct scatterlist *sg){
// 	int length = 0, i = 0;
// 	while(sg){
// 		length += sg->length;
// 		if(sg_is_chain(sg)){
// 			printk("sg %i is chain\n", i);
// 		}
// 		if(sg_is_last(sg)){
// 			printk("sg %i is end\n", i);
// 		}
// 		printk("length:%d offset: %d page_link: 0x%lx\n", sg->length, sg->offset, sg->page_link);
// 		sg = sg_next(sg);
// 		i++;
// 	}

// 	return length;
// }

// static void print_sg(struct scatterlist *sg, char *title){
// 	struct scatterlist *s = sg;
// 	while(s){
// 		print_hex_dump(KERN_INFO, title, 2, 16,
// 			1, sg_virt(s), s->length, 1);
// 		s = sg_next(s);
// 	}
// }

static void authenc_tls_request_complete(struct aead_request *req, int err)
{
	if (err != -EINPROGRESS)
		aead_request_complete(req, err);
}

int crypto_authenc_tls_extractkeys(struct crypto_authenc_keys *keys, const u8 *key,
			       unsigned int keylen)
{
	struct rtattr *rta = (struct rtattr *)key;
	struct crypto_authenc_key_param *param;

	if (!RTA_OK(rta, keylen))
		return -EINVAL;
	if (rta->rta_type != CRYPTO_AUTHENC_KEYA_PARAM)
		return -EINVAL;

	/*
	 * RTA_OK() didn't align the rtattr's payload when validating that it
	 * fits in the buffer.  Yet, the keys should start on the next 4-byte
	 * aligned boundary.  To avoid confusion, require that the rtattr
	 * payload be exactly the param struct, which has a 4-byte aligned size.
	 */
	if (RTA_PAYLOAD(rta) != sizeof(*param))
		return -EINVAL;
	BUILD_BUG_ON(sizeof(*param) % RTA_ALIGNTO);

	param = RTA_DATA(rta);
	keys->enckeylen = be32_to_cpu(param->enckeylen);

	key += rta->rta_len;
	keylen -= rta->rta_len;

	if (keylen < keys->enckeylen)
		return -EINVAL;

	keys->authkeylen = keylen - keys->enckeylen;
	keys->authkey = key;
	keys->enckey = key + keys->authkeylen;

	return 0;
}
EXPORT_SYMBOL_GPL(crypto_authenc_tls_extractkeys);

static int crypto_authenc_tls_setkey(struct crypto_aead *authenc, const u8 *key,
				 unsigned int keylen)
{
	struct crypto_authenc_tls_ctx *ctx = crypto_aead_ctx(authenc);
	struct crypto_ahash *auth = ctx->auth;
	struct crypto_skcipher *enc = ctx->enc;
	struct crypto_authenc_keys keys;
	int err = -EINVAL;

	if (crypto_authenc_tls_extractkeys(&keys, key, keylen) != 0)
		goto out;

	crypto_ahash_clear_flags(auth, CRYPTO_TFM_REQ_MASK);
	crypto_ahash_set_flags(auth, crypto_aead_get_flags(authenc) &
				    CRYPTO_TFM_REQ_MASK);
	err = crypto_ahash_setkey(auth, keys.authkey, keys.authkeylen);
	if (err)
		goto out;
	
	crypto_skcipher_clear_flags(enc, CRYPTO_TFM_REQ_MASK);
	crypto_skcipher_set_flags(enc, crypto_aead_get_flags(authenc) &
				       CRYPTO_TFM_REQ_MASK);
	err = crypto_skcipher_setkey(enc, keys.enckey, keys.enckeylen);
out:
	memzero_explicit(&keys, sizeof(keys));
	return err;
}

static void crypto_authenc_tls_encrypt_data_done(void *data, int err)
{
	struct aead_request *req = data;
	struct authenc_tls_request_ctx *areq_ctx = aead_request_ctx(req);
	if (err)
		goto out;

out:
	kfree(areq_ctx->nsg);
	authenc_tls_request_complete(req, err);
}


static int crypto_authenc_tls_copy_assoc(struct aead_request *req)
{
	struct crypto_aead *authenc = crypto_aead_reqtfm(req);
	struct crypto_authenc_tls_ctx *ctx = crypto_aead_ctx(authenc);
	SYNC_SKCIPHER_REQUEST_ON_STACK(skreq, ctx->null);

	skcipher_request_set_sync_tfm(skreq, ctx->null);
	skcipher_request_set_callback(skreq, aead_request_flags(req),
				      NULL, NULL);
	skcipher_request_set_crypt(skreq, req->src, req->dst, req->assoclen,
				   NULL);

	return crypto_skcipher_encrypt(skreq);
}


static int crypto_authenc_tls_encrypt_padding(struct aead_request *req){
	struct crypto_aead *authenc = crypto_aead_reqtfm(req);
	unsigned int blocksize = crypto_aead_blocksize(authenc);
	unsigned int lastblock_size = req->cryptlen % blocksize;
	unsigned int padding_bytes = blocksize - lastblock_size;
	u8 padding[32] = {0};

	if(padding_bytes == 0)
		padding_bytes += blocksize;

	memset(padding, padding_bytes - 1, padding_bytes);

	scatterwalk_map_and_copy(padding, req->src, req->cryptlen + req->assoclen,
				 padding_bytes, 1);

	return padding_bytes;
}

static int crypto_authenc_tls_encrypt_data(struct aead_request *req, unsigned int flags)
{
	struct crypto_aead *authenc = crypto_aead_reqtfm(req);
	struct aead_instance *inst = aead_alg_instance(authenc);
	struct crypto_authenc_tls_ctx *ctx = crypto_aead_ctx(authenc);
	struct authenc_tls_instance_ctx *ictx = aead_instance_ctx(inst);
	struct crypto_skcipher *enc = ctx->enc;
	struct authenc_tls_request_ctx *areq_ctx = aead_request_ctx(req);
	struct skcipher_request *skreq = (void *)(areq_ctx->tail + ictx->reqoff);
	struct scatterlist *src, *dst;
	int err;

	/* add padding */
	req->cryptlen += crypto_authenc_tls_encrypt_padding(req);
	// print_sg(req->dst, "PLAINTEXT");

	src = scatterwalk_ffwd(areq_ctx->src, req->src, req->assoclen);
	dst = src;

	if (req->src != req->dst) {
		err = crypto_authenc_tls_copy_assoc(req);
		if (err)
			return err;

		dst = scatterwalk_ffwd(areq_ctx->dst, req->dst, req->assoclen);
	}

	skcipher_request_set_tfm(skreq, enc);
	skcipher_request_set_callback(skreq, aead_request_flags(req),
				crypto_authenc_tls_encrypt_data_done, req);
	skcipher_request_set_crypt(skreq, src, dst, req->cryptlen, req->iv);

	err = crypto_skcipher_encrypt(skreq);
	if (err)
		return err;

	kfree(areq_ctx->nsg);

	// print_sg(req->dst, "CIPHERTEXT");

	return 0;
}

static void authenc_tls_genicv_ahash_done(void *data, int err)
{
	struct aead_request *req = data;
	struct crypto_aead *authenc = crypto_aead_reqtfm(req);
	struct aead_instance *inst = aead_alg_instance(authenc);
	struct authenc_tls_instance_ctx *ictx = aead_instance_ctx(inst);
	struct authenc_tls_request_ctx *areq_ctx = aead_request_ctx(req);
	struct ahash_request *ahreq = (void *)(areq_ctx->tail + ictx->reqoff);

	if (err)
		goto out;

	scatterwalk_map_and_copy(ahreq->result, req->src,
				 req->assoclen + req->cryptlen,
				 crypto_aead_authsize(authenc), 1);
	req->cryptlen += crypto_aead_authsize(authenc);
	
out:
	crypto_authenc_tls_encrypt_data(req, aead_request_flags(req));
}

static void authenc_tls_extend_src_sg(struct aead_request *req, u8 *buf, int buflen){
	struct authenc_tls_request_ctx *areq_ctx = aead_request_ctx(req);
	int nents = sg_nents(req->src) + 1;
	struct scatterlist *sg = req->src;

	areq_ctx->nsg = kmalloc_array(nents, sizeof(struct scatterlist), GFP_KERNEL);
	sg_init_table(areq_ctx->nsg, nents);

	for(int i = 0; i < nents - 1; i++){
		memcpy(&areq_ctx->nsg[i], sg, sizeof(struct scatterlist));
		sg = sg_next(sg);
	}
	sg_unmark_end(&areq_ctx->nsg[nents - 2]);

	sg_set_buf(&areq_ctx->nsg[nents - 1], buf, buflen);
	
	req->src = areq_ctx->nsg;
}

static int crypto_authenc_tls_encrypt(struct aead_request *req)
{
	struct crypto_aead *authenc = crypto_aead_reqtfm(req);
	struct aead_instance *inst = aead_alg_instance(authenc);
	struct crypto_authenc_tls_ctx *ctx = crypto_aead_ctx(authenc);
	struct authenc_tls_instance_ctx *ictx = aead_instance_ctx(inst);
	struct crypto_ahash *auth = ctx->auth;
	struct authenc_tls_request_ctx *areq_ctx = aead_request_ctx(req);
	struct ahash_request *ahreq = (void *)(areq_ctx->tail + ictx->reqoff);
	u8 *hash = areq_ctx->tail;
	int err;

	hash = (u8 *)ALIGN((unsigned long)hash + crypto_ahash_alignmask(auth),
			   crypto_ahash_alignmask(auth) + 1);

	/* extend src scatterlist to add tag and padding data */
	authenc_tls_extend_src_sg(req, hash , crypto_aead_authsize(authenc) + 
		crypto_aead_blocksize(authenc));

	ahash_request_set_tfm(ahreq, auth);
	ahash_request_set_crypt(ahreq, req->src, hash,
				req->assoclen + req->cryptlen);
	ahash_request_set_callback(ahreq, aead_request_flags(req),
				   authenc_tls_genicv_ahash_done, req);

	err = crypto_ahash_digest(ahreq);
	if (err)
		return err;
	
	// scatterwalk_map_and_copy(hash, req->src, req->assoclen + req->cryptlen,
	// 			 crypto_aead_authsize(authenc), 1);
	req->cryptlen += crypto_aead_authsize(authenc);

	return crypto_authenc_tls_encrypt_data(req, aead_request_flags(req));
}

static void authenc_tls_verify_ahash_tail_done(void *data, int err)
{
	struct aead_request *req = data;
	struct crypto_aead *authenc = crypto_aead_reqtfm(req);
	unsigned int authsize = crypto_aead_authsize(authenc);
	struct aead_instance *inst = aead_alg_instance(authenc);
	struct authenc_tls_instance_ctx *ictx = aead_instance_ctx(inst);
	struct crypto_authenc_tls_ctx *ctx = crypto_aead_ctx(authenc);
	struct crypto_ahash *auth = ctx->auth;
	struct authenc_tls_request_ctx *areq_ctx = aead_request_ctx(req);
	struct ahash_request *ahreq = (void *)(areq_ctx->tail + ictx->reqoff);
	u8 *ihash = ahreq->result, *hash;

	ihash = (u8 *)ALIGN((unsigned long)ihash + crypto_ahash_alignmask(auth),
			   crypto_ahash_alignmask(auth) + 1);

 	hash = ihash + authsize;

	if(err)
		goto out;
	
	if (crypto_memneq(hash, ihash, authsize))
		authenc_tls_request_complete(req, -EBADMSG);

out:
	authenc_tls_request_complete(req, err);
}

static int crypto_authenc_tls_verify_ahash_tail(struct aead_request *req,
				       unsigned int flags)
{
	struct crypto_aead *authenc = crypto_aead_reqtfm(req);
	unsigned int authsize = crypto_aead_authsize(authenc);
	struct aead_instance *inst = aead_alg_instance(authenc);
	struct crypto_authenc_tls_ctx *ctx = crypto_aead_ctx(authenc);
	struct authenc_tls_instance_ctx *ictx = aead_instance_ctx(inst);
	struct crypto_ahash *auth = ctx->auth;
	struct authenc_tls_request_ctx *areq_ctx = aead_request_ctx(req);
	struct ahash_request *ahreq = (void *)(areq_ctx->tail + ictx->reqoff);
	unsigned char padding_length;
	unsigned int plain_length;
	u8 *ihash = areq_ctx->tail, *hash;
	int err;

	ihash = (u8 *)ALIGN((unsigned long)ihash + crypto_ahash_alignmask(auth),
			   crypto_ahash_alignmask(auth) + 1);
 	hash = ihash + authsize;

	/* get padding length */
	scatterwalk_map_and_copy(&padding_length, req->dst, req->assoclen + req->cryptlen - 1, 1, 0);
	padding_length += 1;
	plain_length = req->cryptlen - authsize - padding_length;

	/**
	 * TLS CBC encryption mode involves encrypting after padding, it is not possible to
	 * obtain the plaintext length in advance during decryption.
	 *  */ 
	scatterwalk_map_and_copy(&plain_length, req->dst, req->assoclen - 1, 1, 1);

	/* origin hash */
	scatterwalk_map_and_copy(ihash, req->dst, req->assoclen + plain_length, authsize, 0);

	ahash_request_set_tfm(ahreq, auth);
	ahash_request_set_crypt(ahreq, req->dst, hash,
				req->assoclen + plain_length);

	ahash_request_set_callback(ahreq, aead_request_flags(req),
				      authenc_tls_verify_ahash_tail_done, req);

	err = crypto_ahash_digest(ahreq);
	if(err)
		return err;

	if (crypto_memneq(hash, ihash, authsize))
		return -EBADMSG;

	/* tell caller the plaintext length */
	req->cryptlen = plain_length;

	// print_sg(req->dst, "PLAIN");
	// printk("%p\n", ihash);
	// print_hex_dump(KERN_INFO, "HASH", 2, 16,
	// 		1, ihash, 64, 1);

	return 0;
}

static void authenc_tls_decrypt_data_done(void *data, int err)
{
	struct aead_request *req = data;

	if (err)
		goto out;

out:
	crypto_authenc_tls_verify_ahash_tail(req, err);
}


static int crypto_authenc_tls_decrypt(struct aead_request *req)
{
	struct crypto_aead *authenc = crypto_aead_reqtfm(req);
	struct aead_instance *inst = aead_alg_instance(authenc);
	struct crypto_authenc_tls_ctx *ctx = crypto_aead_ctx(authenc);
	struct authenc_tls_instance_ctx *ictx = aead_instance_ctx(inst);
	struct authenc_tls_request_ctx *areq_ctx = aead_request_ctx(req);
	struct skcipher_request *skreq = (void *)(areq_ctx->tail +
						  ictx->reqoff);
	struct scatterlist *src, *dst;
	int err;

	src = scatterwalk_ffwd(areq_ctx->src, req->src, req->assoclen);
	dst = src;

	if (req->src != req->dst) {
		err = crypto_authenc_tls_copy_assoc(req);
		if (err)
			return err;

		dst = scatterwalk_ffwd(areq_ctx->dst, req->dst, req->assoclen);
	}

	skcipher_request_set_tfm(skreq, ctx->enc);
	skcipher_request_set_callback(skreq, aead_request_flags(req),
				    authenc_tls_decrypt_data_done, req);
	skcipher_request_set_crypt(skreq, src, dst,
				   req->cryptlen, req->iv);

	err = crypto_skcipher_decrypt(skreq);
	if (err)
		return err;

	return crypto_authenc_tls_verify_ahash_tail(req, aead_request_flags(req));
}

static int crypto_authenc_tls_init_tfm(struct crypto_aead *tfm)
{
	struct aead_instance *inst = aead_alg_instance(tfm);
	struct authenc_tls_instance_ctx *ictx = aead_instance_ctx(inst);
	struct crypto_authenc_tls_ctx *ctx = crypto_aead_ctx(tfm);
	struct crypto_ahash *auth;
	struct crypto_skcipher *enc;
	struct crypto_sync_skcipher *null;
	int err;

	auth = crypto_spawn_ahash(&ictx->auth);
	if (IS_ERR(auth))
		return PTR_ERR(auth);

	enc = crypto_spawn_skcipher(&ictx->enc);
	err = PTR_ERR(enc);
	if (IS_ERR(enc))
		goto err_free_ahash;

	null = crypto_get_default_null_skcipher();
	err = PTR_ERR(null);
	if (IS_ERR(null))
		goto err_free_skcipher;

	ctx->auth = auth;
	ctx->enc = enc;
	ctx->null = null;

	crypto_aead_set_reqsize(
		tfm,
		sizeof(struct authenc_tls_request_ctx) +
		ictx->reqoff +
		max_t(unsigned int,
		      crypto_ahash_reqsize(auth) +
		      sizeof(struct ahash_request),
		      sizeof(struct skcipher_request) +
		      crypto_skcipher_reqsize(enc)));

	return 0;

err_free_skcipher:
	crypto_free_skcipher(enc);
err_free_ahash:
	crypto_free_ahash(auth);
	return err;
}

static void crypto_authenc_tls_exit_tfm(struct crypto_aead *tfm)
{
	struct crypto_authenc_tls_ctx *ctx = crypto_aead_ctx(tfm);

	crypto_free_ahash(ctx->auth);
	crypto_free_skcipher(ctx->enc);
	crypto_put_default_null_skcipher();
}

static void crypto_authenc_tls_free(struct aead_instance *inst)
{
	struct authenc_tls_instance_ctx *ctx = aead_instance_ctx(inst);

	crypto_drop_skcipher(&ctx->enc);
	crypto_drop_ahash(&ctx->auth);
	kfree(inst);
}

static int crypto_authenc_tls_create(struct crypto_template *tmpl,
				 struct rtattr **tb)
{
	u32 mask;
	struct aead_instance *inst;
	struct authenc_tls_instance_ctx *ctx;
	struct hash_alg_common *auth;
	struct crypto_alg *auth_base;
	struct skcipher_alg *enc;
	int err;

	err = crypto_check_attr_type(tb, CRYPTO_ALG_TYPE_AEAD, &mask);
	if (err)
		return err;

	inst = kzalloc(sizeof(*inst) + sizeof(*ctx), GFP_KERNEL);
	if (!inst)
		return -ENOMEM;
	ctx = aead_instance_ctx(inst);

	err = crypto_grab_ahash(&ctx->auth, aead_crypto_instance(inst),
				crypto_attr_alg_name(tb[1]), 0, mask);
	if (err)
		goto err_free_inst;
	auth = crypto_spawn_ahash_alg(&ctx->auth);
	auth_base = &auth->base;

	err = crypto_grab_skcipher(&ctx->enc, aead_crypto_instance(inst),
				   crypto_attr_alg_name(tb[2]), 0, mask);
	if (err)
		goto err_free_inst;
	enc = crypto_spawn_skcipher_alg(&ctx->enc);

	ctx->reqoff = ALIGN(2 * auth->digestsize + auth_base->cra_alignmask,
			    auth_base->cra_alignmask + 1);

	err = -ENAMETOOLONG;
	if (snprintf(inst->alg.base.cra_name, CRYPTO_MAX_ALG_NAME,
		     "authenctls(%s,%s)", auth_base->cra_name,
		     enc->base.cra_name) >=
	    CRYPTO_MAX_ALG_NAME)
		goto err_free_inst;

	if (snprintf(inst->alg.base.cra_driver_name, CRYPTO_MAX_ALG_NAME,
		     "authenctls(%s,%s)", auth_base->cra_driver_name,
		     enc->base.cra_driver_name) >= CRYPTO_MAX_ALG_NAME)
		goto err_free_inst;

	inst->alg.base.cra_priority = enc->base.cra_priority * 10 +
				      auth_base->cra_priority;
	inst->alg.base.cra_blocksize = enc->base.cra_blocksize;
	inst->alg.base.cra_alignmask = auth_base->cra_alignmask |
				       enc->base.cra_alignmask;
	inst->alg.base.cra_ctxsize = sizeof(struct crypto_authenc_tls_ctx);

	inst->alg.ivsize = crypto_skcipher_alg_ivsize(enc);
	inst->alg.chunksize = crypto_skcipher_alg_chunksize(enc);
	inst->alg.maxauthsize = auth->digestsize;

	inst->alg.init = crypto_authenc_tls_init_tfm;
	inst->alg.exit = crypto_authenc_tls_exit_tfm;

	inst->alg.setkey = crypto_authenc_tls_setkey;
	inst->alg.encrypt = crypto_authenc_tls_encrypt;
	inst->alg.decrypt = crypto_authenc_tls_decrypt;

	inst->free = crypto_authenc_tls_free;

	err = aead_register_instance(tmpl, inst);
	if (err) {
err_free_inst:
		crypto_authenc_tls_free(inst);
	}
	return err;
}

static struct crypto_template crypto_authenc_tls_tmpl = {
	.name = "authenctls",
	.create = crypto_authenc_tls_create,
	.module = THIS_MODULE,
};

static int __init crypto_authenc_tls_module_init(void)
{
	return crypto_register_template(&crypto_authenc_tls_tmpl);
}

static void __exit crypto_authenc_tls_module_exit(void)
{
	crypto_unregister_template(&crypto_authenc_tls_tmpl);
}

subsys_initcall(crypto_authenc_tls_module_init);
module_exit(crypto_authenc_tls_module_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Simple AEAD wrapper for TLS1.1");
MODULE_ALIAS_CRYPTO("authenctls");
