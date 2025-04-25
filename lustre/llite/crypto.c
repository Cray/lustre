// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2019, 2020, Whamcloud.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#include "llite_internal.h"

#ifdef HAVE_LUSTRE_CRYPTO

static int ll_get_context(struct inode *inode, void *ctx, size_t len)
{
	int rc;

	/* Get enc context xattr directly instead of going through the VFS,
	 * as there is no xattr handler for "encryption.".
	 */
	rc = ll_xattr_list(inode, xattr_for_enc(inode),
			   XATTR_ENCRYPTION_T, ctx, len, OBD_MD_FLXATTR);

	/* used as encryption unit size */
	if (S_ISREG(inode->i_mode))
		inode->i_blkbits = LUSTRE_ENCRYPTION_BLOCKBITS;
	return rc;
}

int ll_set_encflags(struct inode *inode, void *encctx, __u32 encctxlen,
		    bool preload)
{
	unsigned int ext_flags;
	int rc = 0;

	/* used as encryption unit size */
	if (S_ISREG(inode->i_mode))
		inode->i_blkbits = LUSTRE_ENCRYPTION_BLOCKBITS;
	ext_flags = ll_inode2ext_flags(inode) | LUSTRE_ENCRYPT_FL;
	ll_update_inode_flags(inode, ext_flags);

	if (encctx && encctxlen)
		rc = ll_xattr_cache_insert(inode,
					   xattr_for_enc(inode),
					   encctx, encctxlen);
	if (rc)
		return rc;

	return preload ? llcrypt_prepare_readdir(inode) : 0;
}

/* ll_set_context has 2 distinct behaviors, depending on the value of inode
 * parameter:
 * - inode is NULL:
 *   passed fs_data is a struct md_op_data *. We need to store enc ctx in
 *   op_data, so that it will be sent along to the server with the request that
 *   the caller is preparing, thus saving a setxattr request.
 * - inode is not NULL:
 *   normal case, letting proceed with setxattr operation.
 *   This use case should only be used when explicitly setting a new encryption
 *   policy on an existing, empty directory.
 */
static int ll_set_context(struct inode *inode, const void *ctx, size_t len,
			  void *fs_data)
{
	struct ptlrpc_request *req = NULL;
	int rc;

	if (inode == NULL) {
		struct md_op_data *op_data = (struct md_op_data *)fs_data;

		if (!op_data)
			return -EINVAL;

		OBD_ALLOC(op_data->op_file_encctx, len);
		if (op_data->op_file_encctx == NULL)
			return -ENOMEM;
		op_data->op_file_encctx_size = len;
		memcpy(op_data->op_file_encctx, ctx, len);
		return 0;
	}

	/* Encrypting the root directory is not allowed */
	if (is_root_inode(inode))
		return -EPERM;

	/* Send setxattr request to lower layers directly instead of going
	 * through the VFS, as there is no xattr handler for "encryption.".
	 */
	rc = md_setxattr(ll_i2mdexp(inode), ll_inode2fid(inode), OBD_MD_FLXATTR,
			 xattr_for_enc(inode), ctx, len, XATTR_CREATE,
			 ll_i2suppgid(inode), ll_i2projid(inode), &req);

	if (rc)
		return rc;
	ptlrpc_req_put(req);

	return ll_set_encflags(inode, (void *)ctx, len, false);
}

/**
 * ll_file_open_encrypt() - overlay to llcrypt_file_open
 * @inode: the inode being opened
 * @filp: the struct file being set up
 *
 * This overlay function is necessary to handle encrypted file open without
 * the key. We allow this access pattern to applications that know what they
 * are doing, by using the specific flag O_CIPHERTEXT.
 * This flag is only compatible with O_DIRECT IOs, to make sure ciphertext
 * data is wiped from page cache once IOs are finished.
 *
 * Return:
 * * %0 - On success
 * * %-ERRNO: On Failure
 */
int ll_file_open_encrypt(struct inode *inode, struct file *filp)
{
	int rc;

	rc = llcrypt_file_open(inode, filp);
	if (likely(rc != -ENOKEY))
		return rc;

	if (rc == -ENOKEY &&
	    (filp->f_flags & O_CIPHERTEXT) == O_CIPHERTEXT &&
	    filp->f_flags & O_DIRECT)
		/* allow open with O_CIPHERTEXT flag when we have O_DIRECT */
		rc = 0;

	return rc;
}

#ifdef HAVE_FSCRYPT_DUMMY_CONTEXT_ENABLED
bool ll_sb_has_test_dummy_encryption(struct super_block *sb)
{
	struct ll_sb_info *sbi = s2lsi(sb)->lsi_llsbi;

	return sbi ?
	       unlikely(test_bit(LL_SBI_TEST_DUMMY_ENCRYPTION, sbi->ll_flags)) :
	       false;
}

static bool ll_dummy_context(struct inode *inode)
{
	return ll_sb_has_test_dummy_encryption(inode->i_sb);
}
#else
static const union llcrypt_policy *
ll_get_dummy_policy(struct super_block *sb)
{
	struct lustre_sb_info *lsi = s2lsi(sb);

#ifdef HAVE_FSCRYPT_DUMMY_POLICY
	return lsi ? lsi->lsi_dummy_enc_policy.policy : NULL;
#else
	return lsi ? lsi->lsi_dummy_enc_policy.ctx : NULL;
#endif
}

bool ll_sb_has_test_dummy_encryption(struct super_block *sb)
{
	return ll_get_dummy_policy(sb) != NULL;
}
#endif

bool ll_sbi_has_encrypt(struct ll_sb_info *sbi)
{
	return test_bit(LL_SBI_ENCRYPT, sbi->ll_flags);
}

void ll_sbi_set_encrypt(struct ll_sb_info *sbi, bool set)
{
	if (set) {
		set_bit(LL_SBI_ENCRYPT, sbi->ll_flags);
	} else {
		clear_bit(LL_SBI_ENCRYPT, sbi->ll_flags);
		clear_bit(LL_SBI_TEST_DUMMY_ENCRYPTION, sbi->ll_flags);
	}
}

bool ll_sbi_has_name_encrypt(struct ll_sb_info *sbi)
{
	return test_bit(LL_SBI_ENCRYPT_NAME, sbi->ll_flags);
}

void ll_sbi_set_name_encrypt(struct ll_sb_info *sbi, bool set)
{
	if (set)
		set_bit(LL_SBI_ENCRYPT_NAME, sbi->ll_flags);
	else
		clear_bit(LL_SBI_ENCRYPT_NAME, sbi->ll_flags);
}

static bool ll_empty_dir(struct inode *inode)
{
	/* used by llcrypt_ioctl_set_policy(), because a policy can only be set
	 * on an empty dir.
	 */
	/* Here we choose to return true, meaning we always call .set_context.
	 * Then we rely on server side, with mdd_fix_attr() that calls
	 * mdd_dir_is_empty() when setting encryption flag on directory.
	 */
	return true;
}

static int ll_digest_long_name(struct inode *dir, struct llcrypt_name *fname,
			       struct lu_fid *fid, int digested)
{
	int rc = 0;

	if (digested) {
		/* Without the key, for long names user should have struct
		 * ll_digest_filename representation of the dentry instead of
		 * the name. So make sure it is valid, return fid and put
		 * excerpt of cipher text name in disk_name.
		 */
		struct ll_digest_filename *digest;

		if (fname->crypto_buf.len < sizeof(struct ll_digest_filename)) {
			rc = -EINVAL;
			goto out_free;
		}
		digest = (struct ll_digest_filename *)fname->disk_name.name;
		*fid = digest->ldf_fid;
		if (!fid_is_sane(fid) && !fid_is_zero(fid)) {
			rc = -EINVAL;
			goto out_free;
		}
		fname->disk_name.name = digest->ldf_excerpt;
		fname->disk_name.len = sizeof(digest->ldf_excerpt);
	}
	if (IS_ENCRYPTED(dir) &&
	    !name_is_dot_or_dotdot(fname->disk_name.name,
				   fname->disk_name.len)) {
		int presented_len = critical_chars(fname->disk_name.name,
						   fname->disk_name.len);
		char *buf;

		buf = kmalloc(presented_len + 1, GFP_NOFS);
		if (!buf) {
			rc = -ENOMEM;
			goto out_free;
		}

		if (presented_len == fname->disk_name.len)
			memcpy(buf, fname->disk_name.name, presented_len);
		else
			critical_encode(fname->disk_name.name,
					fname->disk_name.len, buf);
		buf[presented_len] = '\0';
		kfree(fname->crypto_buf.name);
		fname->crypto_buf.name = buf;
		fname->crypto_buf.len = presented_len;
		fname->disk_name.name = fname->crypto_buf.name;
		fname->disk_name.len = fname->crypto_buf.len;
	}
out_free:
	if (rc < 0)
		llcrypt_free_filename(fname);

	return rc;
}

/**
 * ll_prepare_lookup() - overlay to llcrypt_prepare_lookup
 * @dir: the directory that will be searched
 * @de: the dentry contain the user-provided filename being searched for
 * @fname: the filename information to be filled in
 * @fid: fid retrieved from user-provided filename
 *
 * This overlay function is necessary to properly encode @fname after
 * encryption, as it will be sent over the wire.
 * This overlay function is also necessary to handle the case of operations
 * carried out without the key. Normally llcrypt makes use of digested names in
 * that case. Having a digested name works for local file systems that can call
 * llcrypt_match_name(), but Lustre server side is not aware of encryption.
 * FID and name hash can then easily be extracted and put into the
 * requests sent to servers.
 *
 *  Return:
 * * %0: Success (filename prepared correctly for the lookup operation)
 * * %-ERRNO: Failure
 */
int ll_prepare_lookup(struct inode *dir, struct dentry *de,
		      struct llcrypt_name *fname, struct lu_fid *fid)
{
	struct qstr iname = QSTR_INIT(de->d_name.name, de->d_name.len);
	int digested = 0;
	int rc;

	if (fid && IS_ENCRYPTED(dir) && llcrypt_policy_has_filename_enc(dir) &&
	    !llcrypt_has_encryption_key(dir)) {
		struct lustre_sb_info *lsi = s2lsi(dir->i_sb);

		if ((!(lsi->lsi_flags & LSI_FILENAME_ENC_B64_OLD_CLI) &&
		     iname.name[0] == LLCRYPT_DIGESTED_CHAR) ||
		    ((lsi->lsi_flags & LSI_FILENAME_ENC_B64_OLD_CLI) &&
		     iname.name[0] == LLCRYPT_DIGESTED_CHAR_OLD))
			digested = 1;
	}

	iname.name += digested;
	iname.len -= digested;

	if (fid) {
		fid->f_seq = 0;
		fid->f_oid = 0;
		fid->f_ver = 0;
	}
	if (unlikely(filename_is_volatile(iname.name,
					  iname.len, NULL))) {
		/* keep volatile name as-is, matters for server side */
		memset(fname, 0, sizeof(struct llcrypt_name));
		fname->disk_name.name = (unsigned char *)iname.name;
		fname->disk_name.len = iname.len;
		rc = 0;
	} else {
		 /* We should use ll_prepare_lookup() but Lustre handles the
		  * digested form its own way, incompatible with llcrypt's
		  * digested form.
		  */
		rc = llcrypt_setup_filename(dir, &iname, 1, fname);
		if ((rc == 0 || rc == -ENOENT) &&
#if defined(HAVE_FSCRYPT_NOKEY_NAME) && !defined(CONFIG_LL_ENCRYPTION)
		    fname->is_nokey_name) {
#else
		    fname->is_ciphertext_name) {
#endif
			spin_lock(&de->d_lock);
			de->d_flags |= DCACHE_NOKEY_NAME;
			spin_unlock(&de->d_lock);
		}
	}
	if (rc == -ENOENT) {
		if (((is_root_inode(dir) &&
		     iname.len == strlen(dot_fscrypt_name) &&
		     strncmp(iname.name, dot_fscrypt_name, iname.len) == 0) ||
		     (!llcrypt_has_encryption_key(dir) &&
		      unlikely(filename_is_volatile(iname.name,
						    iname.len, NULL))))) {
			/* In case of subdir mount of an encrypted directory,
			 * we allow lookup of /.fscrypt directory.
			 */
			/* For purpose of migration or mirroring without enc key
			 * we allow lookup of volatile file without enc context.
			 */
			memset(fname, 0, sizeof(struct llcrypt_name));
			fname->disk_name.name = (unsigned char *)iname.name;
			fname->disk_name.len = iname.len;
			rc = 0;
		} else if (!llcrypt_has_encryption_key(dir)) {
			rc = -ENOKEY;
		}
	}
	if (rc)
		return rc;

	return ll_digest_long_name(dir, fname, fid, digested);
}

/**
 * ll_setup_filename() - overlay to llcrypt_setup_filename
 * @dir: the directory that will be searched
 * @iname: the user-provided filename being searched for
 * @lookup: 1 if we're allowed to proceed without the key because it's
 *	->lookup() or we're finding the dir_entry for deletion; 0 if we cannot
 *	proceed without the key because we're going to create the dir_entry.
 * @fname: the filename information to be filled in
 * @fid: fid retrieved from user-provided filename
 *
 * This overlay function is necessary to properly encode @fname after
 * encryption, as it will be sent over the wire.
 * This overlay function is also necessary to handle the case of operations
 * carried out without the key. Normally llcrypt makes use of digested names in
 * that case. Having a digested name works for local file systems that can call
 * llcrypt_match_name(), but Lustre server side is not aware of encryption.
 * So for keyless @lookup operations on long names, for Lustre we choose to
 * present to users the encoded struct ll_digest_filename, instead of a digested
 * name. FID and name hash can then easily be extracted and put into the
 * requests sent to servers.
 *
 *  Return:
 * * %0: Success
 * * %-ERRNO: On Failure
 */
int ll_setup_filename(struct inode *dir, const struct qstr *iname,
		      int lookup, struct llcrypt_name *fname,
		      struct lu_fid *fid)
{
	int digested = 0;
	struct qstr dname;
	int rc;

	if (fid && IS_ENCRYPTED(dir) && llcrypt_policy_has_filename_enc(dir) &&
	    !llcrypt_has_encryption_key(dir)) {
		struct lustre_sb_info *lsi = s2lsi(dir->i_sb);

		if ((!(lsi->lsi_flags & LSI_FILENAME_ENC_B64_OLD_CLI) &&
		     iname->name[0] == LLCRYPT_DIGESTED_CHAR) ||
		    ((lsi->lsi_flags & LSI_FILENAME_ENC_B64_OLD_CLI) &&
		     iname->name[0] == LLCRYPT_DIGESTED_CHAR_OLD))
			digested = 1;
	}

	dname.name = iname->name + digested;
	dname.len = iname->len - digested;

	if (fid) {
		fid->f_seq = 0;
		fid->f_oid = 0;
		fid->f_ver = 0;
	}
	if (unlikely(filename_is_volatile(iname->name,
					  iname->len, NULL))) {
		/* keep volatile name as-is, matters for server side */
		memset(fname, 0, sizeof(struct llcrypt_name));
		fname->disk_name.name = (unsigned char *)iname->name;
		fname->disk_name.len = iname->len;
		rc = 0;
	} else {
		rc = llcrypt_setup_filename(dir, &dname, lookup, fname);
	}
	if (rc == -ENOENT && lookup) {
		if (((is_root_inode(dir) &&
		     iname->len == strlen(dot_fscrypt_name) &&
		     strncmp(iname->name, dot_fscrypt_name, iname->len) == 0) ||
		     (!llcrypt_has_encryption_key(dir) &&
		      unlikely(filename_is_volatile(iname->name,
						    iname->len, NULL))))) {
			/* In case of subdir mount of an encrypted directory,
			 * we allow lookup of /.fscrypt directory.
			 */
			/* For purpose of migration or mirroring without enc key
			 * we allow lookup of volatile file without enc context.
			 */
			memset(fname, 0, sizeof(struct llcrypt_name));
			fname->disk_name.name = (unsigned char *)iname->name;
			fname->disk_name.len = iname->len;
			rc = 0;
		} else if (!llcrypt_has_encryption_key(dir)) {
			rc = -ENOKEY;
		}
	}
	if (rc)
		return rc;

	return ll_digest_long_name(dir, fname, fid, digested);
}

/**
 * ll_get_symlink() - overlay to llcrypt_get_symlink()
 * @inode: the symlink inode
 * @caddr: the on-disk contents of the symlink
 * @max_size: size of @caddr buffer
 * @done: if successful, will be set up to free the returned target if needed
 *
 * This overlay function is necessary to properly encode for presentation the
 * symlink target when the encryption key is not available, in a way that is
 * compatible with the overlay function ll_setup_filename(), so that further
 * readlink without the encryption key works properly.
 *
 *  Return:
 * * %Valid pointer: Success
 * * %error pointer: On Failure
 */
const char *ll_get_symlink(struct inode *inode, const void *caddr,
			   unsigned int max_size,
			   struct delayed_call *done)
{
	struct llcrypt_str lltr = LLTR_INIT(NULL, 0);
	struct llcrypt_str de_name;
	struct lu_fid fid;
	int rc;

	rc = llcrypt_prepare_readdir(inode);
	if (rc)
		return ERR_PTR(rc);

	/* If enc key is available, just call llcrypt function. */
	if (llcrypt_has_encryption_key(inode))
		return llcrypt_get_symlink(inode, caddr, max_size, done);

	/* When enc key is not available, we need to build an encoded name to
	 * userspace that can later be decoded by ll_setup_filename().
	 */
	rc = llcrypt_fname_alloc_buffer(inode, NAME_MAX + 1, &lltr);
	if (rc < 0)
		return ERR_PTR(rc);

	fid_zero(&fid);
	de_name.name = (char *)caddr;
	de_name.len = max_size;
	rc = ll_fname_disk_to_usr(inode, 0, 0, &de_name, &lltr, &fid);
	if (rc) {
		llcrypt_fname_free_buffer(&lltr);
		return ERR_PTR(rc);
	}
	lltr.name[lltr.len] = '\0';

	set_delayed_call(done, kfree_link, lltr.name);
	return lltr.name;
}

/**
 * ll_fname_disk_to_usr() - overlay to llcrypt_fname_disk_to_usr
 * @inode: the inode to convert name
 * @hash: major hash for inode
 * @minor_hash: minor hash for inode
 * @iname: the user-provided filename needing conversion
 * @oname: the filename information to be filled in
 * @fid: the user-provided fid for filename
 *
 * The caller must have allocated sufficient memory for the @oname string.
 *
 * This overlay function is necessary to properly decode @iname before
 * decryption, as it comes from the wire.
 * This overlay function is also necessary to handle the case of operations
 * carried out without the key. Normally llcrypt makes use of digested names in
 * that case. Having a digested name works for local file systems that can call
 * llcrypt_match_name(), but Lustre server side is not aware of encryption.
 * So for keyless @lookup operations on long names, for Lustre we choose to
 * present to users the encoded struct ll_digest_filename, instead of a digested
 * name. FID and name hash can then easily be extracted and put into the
 * requests sent to servers.
 *
 *  Return:
 * * %0: Success
 * * %-ERRNO: On Failure
 */
int ll_fname_disk_to_usr(struct inode *inode,
			 u32 hash, u32 minor_hash,
			 struct llcrypt_str *iname, struct llcrypt_str *oname,
			 struct lu_fid *fid)
{
	struct llcrypt_str lltr = LLTR_INIT(iname->name, iname->len);
	struct ll_digest_filename digest;
	int digested = 0;
	char *buf = NULL;
	int rc;

	if (IS_ENCRYPTED(inode)) {
		if (!name_is_dot_or_dotdot(lltr.name, lltr.len) &&
		    strnchr(lltr.name, lltr.len, '=')) {
			/* Only proceed to critical decode if
			 * iname contains espace char '='.
			 */
			int len = lltr.len;

			buf = kmalloc(len, GFP_NOFS);
			if (!buf)
				return -ENOMEM;

			len = critical_decode(lltr.name, len, buf);
			lltr.name = buf;
			lltr.len = len;
		}
		if (lltr.len > LL_CRYPTO_BLOCK_SIZE * 2 &&
		    !llcrypt_has_encryption_key(inode) &&
		    llcrypt_policy_has_filename_enc(inode)) {
			struct lustre_sb_info *lsi = s2lsi(inode->i_sb);

			digested = 1;
			/* Without the key for long names, set the dentry name
			 * to the representing struct ll_digest_filename. It
			 * will be encoded by llcrypt for display, and will
			 * enable further lookup requests.
			 */
			if (!fid)
				GOTO(out_buf, rc = -EINVAL);
			digest.ldf_fid = *fid;
			memcpy(digest.ldf_excerpt,
			       LLCRYPT_EXTRACT_DIGEST(lltr.name, lltr.len),
			       sizeof(digest.ldf_excerpt));

			lltr.name = (char *)&digest;
			lltr.len = sizeof(digest);

			if (!(lsi->lsi_flags & LSI_FILENAME_ENC_B64_OLD_CLI))
				oname->name[0] = LLCRYPT_DIGESTED_CHAR;
			else
				oname->name[0] = LLCRYPT_DIGESTED_CHAR_OLD;
			oname->name = oname->name + 1;
			oname->len--;
		}
	}

	rc = llcrypt_fname_disk_to_usr(inode, hash, minor_hash, &lltr, oname);

	oname->name = oname->name - digested;
	oname->len = oname->len + digested;

out_buf:
	kfree(buf);
	return rc;
}

#if !defined(HAVE_FSCRYPT_D_REVALIDATE) || defined(CONFIG_LL_ENCRYPTION)
/* Copied from llcrypt_d_revalidate, as it is not exported */
/*
 * Validate dentries in encrypted directories to make sure we aren't potentially
 * caching stale dentries after a key has been added.
 */
int llcrypt_d_revalidate(struct dentry *dentry, unsigned int flags)
{
	struct dentry *dir;
	int err;
	int valid;

	/*
	 * Plaintext names are always valid, since llcrypt doesn't support
	 * reverting to ciphertext names without evicting the directory's inode
	 * -- which implies eviction of the dentries in the directory.
	 */
	if (!llcrypt_is_nokey_name(dentry))
		return 1;

	/*
	 * Ciphertext name; valid if the directory's key is still unavailable.
	 *
	 * Although llcrypt forbids rename() on ciphertext names, we still must
	 * use dget_parent() here rather than use ->d_parent directly.  That's
	 * because a corrupted fs image may contain directory hard links, which
	 * the VFS handles by moving the directory's dentry tree in the dcache
	 * each time ->lookup() finds the directory and it already has a dentry
	 * elsewhere.  Thus ->d_parent can be changing, and we must safely grab
	 * a reference to some ->d_parent to prevent it from being freed.
	 */

	if (flags & LOOKUP_RCU)
		return -ECHILD;

	dir = dget_parent(dentry);
	err = llcrypt_prepare_readdir(d_inode(dir));
	valid = !ll_has_encryption_key(d_inode(dir));
	dput(dir);

	if (err < 0)
		return err;

	return valid;
}
#endif /* !HAVE_FSCRYPT_D_REVALIDATE || CONFIG_LL_ENCRYPTION */

const struct llcrypt_operations lustre_cryptops = {
	.key_prefix		= "lustre:",
	.get_context		= ll_get_context,
	.set_context		= ll_set_context,
#ifdef HAVE_FSCRYPT_DUMMY_CONTEXT_ENABLED
	.dummy_context		= ll_dummy_context,
#else
#ifdef HAVE_FSCRYPT_DUMMY_POLICY
	.get_dummy_policy	= ll_get_dummy_policy,
#else
	.get_dummy_context	= ll_get_dummy_policy,
#endif
#endif /* !HAVE_FSCRYPT_DUMMY_CONTEXT_ENABLED */
	.empty_dir		= ll_empty_dir,
	.max_namelen		= NAME_MAX,
};
#else /* !HAVE_LUSTRE_CRYPTO */
int ll_set_encflags(struct inode *inode, void *encctx, __u32 encctxlen,
		    bool preload)
{
	return 0;
}

int ll_file_open_encrypt(struct inode *inode, struct file *filp)
{
	return llcrypt_file_open(inode, filp);
}

void llcrypt_free_ctx(void *encctx, __u32 size)
{
}

bool ll_sb_has_test_dummy_encryption(struct super_block *sb)
{
	return false;
}

bool ll_sbi_has_encrypt(struct ll_sb_info *sbi)
{
	return false;
}

void ll_sbi_set_encrypt(struct ll_sb_info *sbi, bool set)
{
}

bool ll_sbi_has_name_encrypt(struct ll_sb_info *sbi)
{
	return false;
}

void ll_sbi_set_name_encrypt(struct ll_sb_info *sbi, bool set)
{
}

int ll_prepare_lookup(struct inode *dir, struct dentry *de,
		      struct llcrypt_name *fname, struct lu_fid *fid)
{
	const struct qstr *iname = &de->d_name;

	if (fid) {
		fid->f_seq = 0;
		fid->f_oid = 0;
		fid->f_ver = 0;
	}

	return llcrypt_setup_filename(dir, iname, 1, fname);
}

int ll_setup_filename(struct inode *dir, const struct qstr *iname,
		      int lookup, struct llcrypt_name *fname,
		      struct lu_fid *fid)
{
	if (fid) {
		fid->f_seq = 0;
		fid->f_oid = 0;
		fid->f_ver = 0;
	}

	return llcrypt_setup_filename(dir, iname, lookup, fname);
}

int ll_fname_disk_to_usr(struct inode *inode,
			 u32 hash, u32 minor_hash,
			 struct llcrypt_str *iname, struct llcrypt_str *oname,
			 struct lu_fid *fid)
{
	return llcrypt_fname_disk_to_usr(inode, hash, minor_hash, iname, oname);
}

int llcrypt_d_revalidate(struct dentry *dentry, unsigned int flags)
{
	return 1;
}
#endif

