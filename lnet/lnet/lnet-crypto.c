// SPDX-License-Identifier: GPL-2.0

/* Copyright 2012 Xyratex Technology Limited
 *
 * Copyright (c) 2012, 2014, Intel Corporation.
 */

#include <crypto/hash.h>
#include <linux/scatterlist.h>
#include <linux/pagemap.h>
#include <linux/libcfs/libcfs.h>
#include <lnet/lnet_crypto.h>
#include "adler.h"

#ifndef HAVE_CRYPTO_HASH_HELPERS
static inline const char *crypto_ahash_alg_name(struct crypto_ahash *tfm)
{
	return crypto_tfm_alg_name(crypto_ahash_tfm(tfm));
}

static inline const char *crypto_ahash_driver_name(struct crypto_ahash *tfm)
{
	return crypto_tfm_alg_driver_name(crypto_ahash_tfm(tfm));
}
#endif

/**
 *  Array of hash algorithm speed in MByte per second
 */
int cfs_crypto_hash_speeds[CFS_HASH_ALG_MAX];
EXPORT_SYMBOL(cfs_crypto_hash_speeds);

/**
 * Initialize the state descriptor for the specified hash algorithm.
 *
 * An internal routine to allocate the hash-specific state in \a hdesc for
 * use with cfs_crypto_hash_digest() to compute the hash of a single message,
 * though possibly in multiple chunks.  The descriptor internal state should
 * be freed with cfs_crypto_hash_final().
 *
 * \param[in]  hash_alg	hash algorithm id (CFS_HASH_ALG_*)
 * \param[out] type	pointer to the hash description in hash_types[] array
 * \param[in,out] req	ahash request to be initialized
 * \param[in]  key	initial hash value/state, NULL to use default value
 * \param[in]  key_len	length of \a key
 *
 * \retval		0 on success
 * \retval		negative errno on failure
 */
static int cfs_crypto_hash_alloc(enum cfs_crypto_hash_alg hash_alg,
				 const struct cfs_crypto_hash_type **type,
				 struct ahash_request **req,
				 unsigned char *key,
				 unsigned int key_len)
{
	struct crypto_ahash *tfm;
	int err = 0;

	*type = cfs_crypto_hash_type(hash_alg);
	if (!*type) {
		CWARN("Unsupported hash algorithm id = %d, max id is %d\n",
		      hash_alg, CFS_HASH_ALG_MAX);
		return -EINVAL;
	}

	/* Keys are only supported for the hmac version */
	if (key && key_len > 0) {
		char *algo_name;

		algo_name = kasprintf(GFP_KERNEL, "hmac(%s)",
				      (*type)->cht_name);
		if (!algo_name)
			return -ENOMEM;

		tfm = crypto_alloc_ahash(algo_name, 0, CRYPTO_ALG_ASYNC);
		kfree(algo_name);
	} else {
		tfm = crypto_alloc_ahash((*type)->cht_name, 0,
					 CRYPTO_ALG_ASYNC);
	}
	if (IS_ERR(tfm)) {
		CDEBUG_LIMIT(PTR_ERR(tfm) == -ENOMEM ? D_ERROR : D_INFO,
			     "Failed to alloc crypto hash %s: rc = %d\n",
			     (*type)->cht_name, (int)PTR_ERR(tfm));
		return PTR_ERR(tfm);
	}

	*req = ahash_request_alloc(tfm, GFP_KERNEL);
	if (!*req) {
		CDEBUG(D_INFO, "Failed to alloc ahash_request for %s\n",
		       (*type)->cht_name);
		GOTO(out_free_tfm, err = -ENOMEM);
	}

	ahash_request_set_callback(*req, 0, NULL, NULL);

	if (key)
		err = crypto_ahash_setkey(tfm, key, key_len);
	else if ((*type)->cht_key != 0)
		err = crypto_ahash_setkey(tfm,
					 (unsigned char *)&((*type)->cht_key),
					 (*type)->cht_size);
	if (err)
		GOTO(out_free_req, err);

	CDEBUG(D_INFO, "Using crypto hash: %s (%s) speed %d MB/s\n",
	       crypto_ahash_alg_name(tfm), crypto_ahash_driver_name(tfm),
	       cfs_crypto_hash_speeds[hash_alg]);

	err = crypto_ahash_init(*req);
	if (err) {
out_free_req:
		ahash_request_free(*req);
out_free_tfm:
		crypto_free_ahash(tfm);
	}
	return err;
}

/**
 * Calculate hash digest for the passed buffer.
 *
 * This should be used when computing the hash on a single contiguous buffer.
 * It combines the hash initialization, computation, and cleanup.
 *
 * \param[in] hash_alg	id of hash algorithm (CFS_HASH_ALG_*)
 * \param[in] buf	data buffer on which to compute hash
 * \param[in] buf_len	length of \a buf in bytes
 * \param[in] key	initial value/state for algorithm, if \a key = NULL
 *			use default initial value
 * \param[in] key_len	length of \a key in bytes
 * \param[out] hash	pointer to computed hash value, if \a hash = NULL then
 *			\a hash_len is to digest size in bytes, retval -ENOSPC
 * \param[in,out] hash_len size of \a hash buffer
 *
 * \retval -EINVAL       \a buf, \a buf_len, \a hash_len, \a hash_alg invalid
 * \retval -ENOENT       \a hash_alg is unsupported
 * \retval -ENOSPC       \a hash is NULL, or \a hash_len less than digest size
 * \retval		0 for success
 * \retval		negative errno for other errors from lower layers.
 */
int cfs_crypto_hash_digest(enum cfs_crypto_hash_alg hash_alg,
			   const void *buf, unsigned int buf_len,
			   unsigned char *key, unsigned int key_len,
			   unsigned char *hash, unsigned int *hash_len)
{
	struct scatterlist	sl;
	struct ahash_request *req;
	int			err;
	const struct cfs_crypto_hash_type	*type;

	if (!buf || buf_len == 0 || !hash_len)
		return -EINVAL;

	err = cfs_crypto_hash_alloc(hash_alg, &type, &req, key, key_len);
	if (err != 0)
		return err;

	if (!hash || *hash_len < type->cht_size) {
		*hash_len = type->cht_size;
		crypto_free_ahash(crypto_ahash_reqtfm(req));
		ahash_request_free(req);
		return -ENOSPC;
	}
	sg_init_one(&sl, (void *)buf, buf_len);

	ahash_request_set_crypt(req, &sl, hash, sl.length);
	err = crypto_ahash_digest(req);
	crypto_free_ahash(crypto_ahash_reqtfm(req));
	ahash_request_free(req);

	return err;
}
EXPORT_SYMBOL(cfs_crypto_hash_digest);

/**
 * Allocate and initialize desriptor for hash algorithm.
 *
 * This should be used to initialize a hash descriptor for multiple calls
 * to a single hash function when computing the hash across multiple
 * separate buffers or pages using cfs_crypto_hash_update{,_page}().
 *
 * The hash descriptor should be freed with cfs_crypto_hash_final().
 *
 * \param[in] hash_alg	algorithm id (CFS_HASH_ALG_*)
 * \param[in] key	initial value/state for algorithm, if \a key = NULL
 *			use default initial value
 * \param[in] key_len	length of \a key in bytes
 *
 * \retval		pointer to ahash request
 * \retval		ERR_PTR(errno) in case of error
 */
struct ahash_request *
	cfs_crypto_hash_init(enum cfs_crypto_hash_alg hash_alg,
			     unsigned char *key, unsigned int key_len)
{
	struct ahash_request *req;
	int					err;
	const struct cfs_crypto_hash_type       *type;

	err = cfs_crypto_hash_alloc(hash_alg, &type, &req, key, key_len);
	if (err)
		return ERR_PTR(err);
	return req;
}
EXPORT_SYMBOL(cfs_crypto_hash_init);

/**
 * Update hash digest computed on data within the given \a page
 *
 * \param[in] req	ahash request
 * \param[in] page	data page on which to compute the hash
 * \param[in] offset	offset within \a page at which to start hash
 * \param[in] len	length of data on which to compute hash
 *
 * \retval		0 for success
 * \retval		negative errno on failure
 */
int cfs_crypto_hash_update_page(struct ahash_request *req,
				struct page *page, unsigned int offset,
				unsigned int len)
{
	struct scatterlist sl;

	sg_init_table(&sl, 1);
	sg_set_page(&sl, page, len, offset & ~PAGE_MASK);

	ahash_request_set_crypt(req, &sl, NULL, sl.length);
	return crypto_ahash_update(req);
}
EXPORT_SYMBOL(cfs_crypto_hash_update_page);

/**
 * Update hash digest computed on the specified data
 *
 * \param[in] req	ahash request
 * \param[in] buf	data buffer on which to compute the hash
 * \param[in] buf_len	length of \buf on which to compute hash
 *
 * \retval		0 for success
 * \retval		negative errno on failure
 */
int cfs_crypto_hash_update(struct ahash_request *req,
			   const void *buf, unsigned int buf_len)
{
	struct scatterlist sl;

	sg_init_one(&sl, (void *)buf, buf_len);

	ahash_request_set_crypt(req, &sl, NULL, sl.length);
	return crypto_ahash_update(req);
}
EXPORT_SYMBOL(cfs_crypto_hash_update);

/**
 * Finish hash calculation, copy hash digest to buffer, clean up hash descriptor
 *
 * \param[in]	req		ahash request
 * \param[out]	hash		pointer to hash buffer to store hash digest
 * \param[in,out] hash_len	pointer to hash buffer size, if \a hash == NULL
 *				or hash_len == NULL only free \a hdesc instead
 *				of computing the hash
 *
 * \retval		0 for success
 * \retval		-EOVERFLOW if hash_len is too small for the hash digest
 * \retval		negative errno for other errors from lower layers
 */
int cfs_crypto_hash_final(struct ahash_request *req,
			  unsigned char *hash, unsigned int *hash_len)
{
	int size = crypto_ahash_digestsize(crypto_ahash_reqtfm(req));
	int err;

	if (!hash || !hash_len) {
		err = 0;
		goto free;
	}
	if (*hash_len < size) {
		err = -EOVERFLOW;
		goto free;
	}

	ahash_request_set_crypt(req, NULL, hash, 0);
	err = crypto_ahash_final(req);
	if (err == 0)
		*hash_len = size;
free:
	crypto_free_ahash(crypto_ahash_reqtfm(req));
	ahash_request_free(req);

	return err;
}
EXPORT_SYMBOL(cfs_crypto_hash_final);

/**
 * Compute the speed of specified hash function
 *
 * Run a speed test on the given hash algorithm on buffer using a 1MB buffer
 * size.  This is a reasonable buffer size for Lustre RPCs, even if the actual
 * RPC size is larger or smaller.
 *
 * The speed is stored internally in the cfs_crypto_hash_speeds[] array, and
 * is available through the cfs_crypto_hash_speed() function.
 *
 * This function needs to stay the same as obd_t10_performance_test() so that
 * the speeds are comparable.
 *
 * \param[in] hash_alg	hash algorithm id (CFS_HASH_ALG_*)
 * \param[in] buf	data buffer on which to compute the hash
 * \param[in] buf_len	length of \buf on which to compute hash
 */
static void cfs_crypto_performance_test(enum cfs_crypto_hash_alg hash_alg)
{
	int			buf_len = max(PAGE_SIZE, 1048576UL);
	void			*buf;
	unsigned long		start, end;
	int			err = 0;
	unsigned long		bcount;
	struct page		*page;
	unsigned char		hash[CFS_CRYPTO_HASH_DIGESTSIZE_MAX];
	unsigned int		hash_len = sizeof(hash);

	page = alloc_page(GFP_KERNEL);
	if (page == NULL) {
		err = -ENOMEM;
		goto out_err;
	}

	buf = kmap_local_page(page);
	memset(buf, 0xAD, PAGE_SIZE);
	kunmap_local(buf);

	for (start = jiffies, end = start + cfs_time_seconds(1) / 4,
	     bcount = 0; time_before(jiffies, end) && err == 0; bcount++) {
		struct ahash_request *req;
		int i;

		req = cfs_crypto_hash_init(hash_alg, NULL, 0);
		if (IS_ERR(req)) {
			err = PTR_ERR(req);
			break;
		}

		for (i = 0; i < buf_len / PAGE_SIZE; i++) {
			err = cfs_crypto_hash_update_page(req, page, 0,
							  PAGE_SIZE);
			if (err != 0)
				break;
		}

		err = cfs_crypto_hash_final(req, hash, &hash_len);
		if (err != 0)
			break;
	}
	end = jiffies;
	__free_page(page);
out_err:
	if (err != 0) {
		cfs_crypto_hash_speeds[hash_alg] = err;
		CDEBUG(D_INFO, "Crypto hash algorithm %s test error: rc = %d\n",
		       cfs_crypto_hash_name(hash_alg), err);
	} else {
		unsigned long   tmp;

		tmp = ((bcount * buf_len / jiffies_to_msecs(end - start)) *
		       1000) / (1024 * 1024);
		cfs_crypto_hash_speeds[hash_alg] = (int)tmp;
		CDEBUG(D_CONFIG, "Crypto hash algorithm %s speed = %d MB/s\n",
		       cfs_crypto_hash_name(hash_alg),
		       cfs_crypto_hash_speeds[hash_alg]);
	}
}

/**
 * hash speed in Mbytes per second for valid hash algorithm
 *
 * Return the performance of the specified \a hash_alg that was
 * computed using cfs_crypto_performance_test().  If the performance
 * has not yet been computed, do that when it is first requested.
 * That avoids computing the speed when it is not actually needed.
 * To avoid competing threads computing the checksum speed at the
 * same time, only compute a single checksum speed at one time.
 *
 * \param[in] hash_alg	hash algorithm id (CFS_HASH_ALG_*)
 *
 * \retval		positive speed of the hash function in MB/s
 * \retval		-ENOENT if \a hash_alg is unsupported
 * \retval		negative errno if \a hash_alg speed is unavailable
 */
int cfs_crypto_hash_speed(enum cfs_crypto_hash_alg hash_alg)
{
	if (hash_alg < CFS_HASH_ALG_MAX) {
		if (unlikely(cfs_crypto_hash_speeds[hash_alg] == 0)) {
			static DEFINE_MUTEX(crypto_hash_speed_mutex);

			mutex_lock(&crypto_hash_speed_mutex);
			if (cfs_crypto_hash_speeds[hash_alg] == 0)
				cfs_crypto_performance_test(hash_alg);
			mutex_unlock(&crypto_hash_speed_mutex);
		}
		return cfs_crypto_hash_speeds[hash_alg];
	}

	return -ENOENT;
}
EXPORT_SYMBOL(cfs_crypto_hash_speed);

/**
 * Run the performance test for all hash algorithms.
 *
 * Run the cfs_crypto_performance_test() benchmark for some of the available
 * hash functions at module load time.  This can't be reliably done at runtime
 * since the CPUs may be under load from thousands of connecting clients when
 * the first client connects and the checksum speeds are needed.
 *
 * Since the setup cost and computation speed of various hash algorithms is
 * a function of the buffer size (and possibly internal contention of offload
 * engines), this speed only represents an estimate of the actual speed under
 * actual usage, but is reasonable for comparing available algorithms.
 *
 * The actual speeds are available via cfs_crypto_hash_speed() for later
 * comparison.
 *
 * \retval		0 on success
 * \retval		-ENOMEM if no memory is available for test buffer
 */
static int cfs_crypto_test_hashes(void)
{
	enum cfs_crypto_hash_alg hash_alg;

	for (hash_alg = 1; hash_alg < CFS_HASH_ALG_SPEED_MAX; hash_alg++)
		cfs_crypto_performance_test(hash_alg);

	return 0;
}

static int adler32;

/**
 * Register available hash functions
 *
 * \retval		0
 */
int cfs_crypto_register(void)
{
	request_module("crc32c");

	if (cfs_crypto_adler32_register() == 0)
		adler32 = 1;

	/* check all algorithms and do performance test */
	cfs_crypto_test_hashes();

	return 0;
}

/**
 * Unregister previously registered hash functions
 */
void cfs_crypto_unregister(void)
{
	if (adler32)
		cfs_crypto_adler32_unregister();
	adler32 = 0;
}
