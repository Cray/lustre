// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015, Trustees of Indiana University
 *
 * Copyright (c) 2016, Intel Corporation.
 *
 * Author: Jeremy Filizetti <jfilizet@iu.edu>
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <linux/lustre/lustre_user.h>

#include "sk_utils.h"
#include "err_util.h"

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

/* One week default expiration */
#define SK_DEFAULT_EXPIRE 604800
/* But only one day in FIPS mode */
#define SK_DEFAULT_EXPIRE_FIPS 86400
#define SK_DEFAULT_SK_KEYLEN 256
#define SK_DEFAULT_PRIME_BITS 2048
#define SK_DEFAULT_NODEMAP "default"

static int fips_mode;

static void usage(FILE *fp, char *program)
{
	int i;

	fprintf(fp, "Usage %s [OPTIONS] {-l|-m|-r|-w} <keyfile>\n", program);
	fprintf(fp, "-l|--load       <keyfile>	Load key from file into user's "
		"session keyring\n");
	fprintf(fp, "-m|--modify     <keyfile>	Modify keyfile's attributes\n");
	fprintf(fp, "-r|--read       <keyfile>	Show keyfile's attributes\n");
	fprintf(fp, "-w|--write      <keyfile>	Generate keyfile\n\n");
	fprintf(fp, "Modify/Write Options:\n");
	fprintf(fp, "-c|--crypt      <num>	Cipher for encryption "
		"(Default: AES Counter mode)\n");
	for (i = 1; i < ARRAY_SIZE(sk_crypt_algs); i++)
		fprintf(fp, "                        %s\n",
			sk_crypt_algs[i].sct_name);
	fprintf(fp, "-i|--hmac       <num>	Hash algorithm for integrity "
		"(Default: SHA256)\n");
	for (i = 1; i < ARRAY_SIZE(sk_hmac_algs); i++)
		fprintf(fp, "                        %s\n",
			sk_hmac_algs[i].sht_name);
	fprintf(fp, "-e|--expire     <num>	Seconds before contexts from "
		"key expire (Default: %d seconds (%.3g days))\n",
		SK_DEFAULT_EXPIRE, (double)SK_DEFAULT_EXPIRE / 3600 / 24);
	fprintf(fp, "-f|--fsname     <name>	File system name for key\n");
	fprintf(fp, "-g|--mgsnids    <nids>	Comma seperated list of MGS "
		"NIDs.  Only required when mgssec is used (Default: \"\")\n");
	fprintf(fp, "-n|--nodemap    <name>	Nodemap name for key "
		"(Default: \"%s\")\n", SK_DEFAULT_NODEMAP);
	fprintf(fp, "-p|--prime-bits <len>	Prime length (p) for DHKE in "
		"bits (Default: %d)\n", SK_DEFAULT_PRIME_BITS);
	fprintf(fp, "-t|--type       <type>	Key type (mgs, server, "
		"client)\n");
	fprintf(fp, "-k|--key-bits   <len>	Shared key length in bits "
		"(Default: %d)\n", SK_DEFAULT_SK_KEYLEN);
	fprintf(fp, "-d|--data       <file>	Key data source for new keys "
		"(Default: /dev/random)\n");
	fprintf(fp, "                        Not a seed value. "
		"This is the actual key value.\n\n");
	fprintf(fp, "Other Options:\n");
	fprintf(fp, "-v|--verbose           Increase verbosity for errors\n");
	exit(EXIT_FAILURE);
}

static ssize_t get_key_data(char *src, void *buffer, size_t bits)
{
	char *ptr = buffer;
	size_t remain;
	ssize_t rc;
	int fd;

	/* convert bits to minimum number of bytes */
	remain = (bits + 7) / 8;

	printf("Reading random data for shared key from '%s'\n", src);
	fd = open(src, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "error: opening '%s': %s\n", src,
			strerror(errno));
		return -errno;
	}

	while (remain > 0) {
		rc = read(fd, ptr, remain);
		if (rc < 0) {
			if (errno == EINTR)
				continue;
			fprintf(stderr, "error: reading from '%s': %s\n", src,
				strerror(errno));
			rc = -errno;
			goto out;

		} else if (rc == 0) {
			fprintf(stderr,
				"error: key source too short for %zd-bit key\n",
				bits);
			rc = -ENODATA;
			goto out;
		}
		ptr += rc;
		remain -= rc;
	}
	rc = 0;

out:
	close(fd);
	return rc;
}

static int write_config_file(char *output_file,
			     struct sk_keyfile_config *config, bool overwrite)
{
	size_t rc;
	int fd;
	int flags = O_WRONLY | O_CREAT;

	if (!overwrite)
		flags |= O_EXCL;

	sk_config_cpu_to_disk(config);

	fd = open(output_file, flags, 0400);
	if (fd < 0) {
		fprintf(stderr, "error: opening '%s': %s\n", output_file,
			strerror(errno));
		return -errno;
	}

	rc = write(fd, config, sizeof(*config));
	if (rc < 0) {
		fprintf(stderr, "error: writing to '%s': %s\n", output_file,
			strerror(errno));
		rc = -errno;
	} else if (rc != sizeof(*config)) {
		fprintf(stderr, "error: short write to '%s'\n", output_file);
		rc = -ENOSPC;

	} else {
		rc = 0;
	}

	close(fd);
	return rc;
}

static int print_config(char *filename)
{
	struct sk_keyfile_config *config;
	int i;

	config = sk_read_file(filename);
	if (!config)
		return EXIT_FAILURE;

	if (sk_validate_config(config)) {
		fprintf(stderr, "error: key configuration failed validation\n");
		free(config);
		return EXIT_FAILURE;
	}

	printf("Version:        %u\n", config->skc_version);
	printf("Type:          ");
	if (config->skc_type & SK_TYPE_MGS)
		printf(" mgs");
	if (config->skc_type & SK_TYPE_SERVER)
		printf(" server");
	if (config->skc_type & SK_TYPE_CLIENT)
		printf(" client");
	printf("\n");
	printf("HMAC alg:       %s\n", sk_hmac2name(config->skc_hmac_alg));
	printf("Crypto alg:     %s\n", sk_crypt2name(config->skc_crypt_alg));
	printf("Ctx Expiration: %u seconds\n", config->skc_expire);
	printf("Shared keylen:  %u bits\n", config->skc_shared_keylen);
	printf("Prime length:   %u bits\n", config->skc_prime_bits);
	printf("File system:    %s\n", config->skc_fsname);
	printf("MGS NIDs:      ");
	for (i = 0; i < MAX_MGSNIDS; i++) {
		if (config->skc_mgsnids[i] == LNET_NID_ANY)
			continue;
		printf(" %s", libcfs_nid2str(config->skc_mgsnids[i]));
	}
	printf("\n");
	printf("Nodemap name:   %s\n", config->skc_nodemap);
	printf("Shared key:\n");
	print_hex(0, config->skc_shared_key, config->skc_shared_keylen / 8);

	/* Don't print empty keys */
	for (i = 0; i < SK_MAX_P_BYTES; i++)
		if (config->skc_p[i] != 0)
			break;

	if (i != SK_MAX_P_BYTES) {
		printf("Prime (p):\n");
		print_hex(0, config->skc_p, config->skc_prime_bits / 8);
	}

	free(config);
	return EXIT_SUCCESS;
}

static int parse_mgsnids(char *mgsnids, struct sk_keyfile_config *config)
{
	lnet_nid_t nid;
	char *ptr;
	char *sep;
	char *end;
	int rc = 0;
	int i;

	/* replace all old values */
	for (i = 0; i < MAX_MGSNIDS; i++)
		config->skc_mgsnids[i] = LNET_NID_ANY;

	i = 0;
	end = mgsnids + strlen(mgsnids);
	ptr = mgsnids;
	while (ptr < end && i < MAX_MGSNIDS) {
		sep = strstr(ptr, ",");
		if (sep != NULL)
			*sep = '\0';

		nid = libcfs_str2nid(ptr);
		if (nid == LNET_NID_ANY) {
			fprintf(stderr, "error: invalid MGS NID: %s\n", ptr);
			rc = -EINVAL;
			break;
		}

		config->skc_mgsnids[i++] = nid;
		ptr += strlen(ptr) + 1;
	}

	if (i == MAX_MGSNIDS) {
		fprintf(stderr, "error: more than %u MGS NIDs provided\n", i);
		rc = -E2BIG;
	}

	return rc;
}

#if !defined(HAVE_OPENSSL_EVP_PKEY) && OPENSSL_VERSION_NUMBER >= 0x10100000L
static inline int __fetch_ssk_prime(struct sk_keyfile_config *config)
{
	const BIGNUM *p;
	DH *dh = NULL;
	int primenid;
	int rc = -1;

	primenid = sk_primebits2primenid(config->skc_prime_bits);
	dh = DH_new_by_nid(primenid);
	if (!dh) {
		fprintf(stderr, "error: dh cannot be init\n");
		goto prime_end;
	}

	p = DH_get0_p(dh);
	if (!p) {
		fprintf(stderr, "error: cannot get p from dh\n");
		goto prime_end;
	}

	if (BN_num_bytes(p) > SK_MAX_P_BYTES) {
		fprintf(stderr,
			"error: requested length %d exceeds maximum %d\n",
			BN_num_bytes(p), SK_MAX_P_BYTES * 8);
		goto prime_end;
	}

	if (BN_bn2bin(p, config->skc_p) != BN_num_bytes(p)) {
		fprintf(stderr, "error: convert BIGNUM p to binary failed\n");
		goto prime_end;
	}

	rc = 0;

prime_end:
	if (rc)
		fprintf(stderr,
			"error: fetching SSK prime failed: %s\n",
			ERR_error_string(ERR_get_error(), NULL));
	DH_free(dh);
	return rc;
}
#endif

static inline int __gen_ssk_prime(struct sk_keyfile_config *config)
{
	int rc = -1;
	const char *primename;
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *dh = NULL;
	BIGNUM *p;

	if (fips_mode) {
		primename = sk_primebits2name(config->skc_prime_bits);
		if (!primename) {
			fprintf(stderr,
				"error: prime len %d not supported in FIPS mode\n",
				config->skc_prime_bits);
			return rc;
		}
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
		fprintf(stdout,
			"FIPS mode, using well-known prime %s\n", primename);
#ifndef HAVE_OPENSSL_EVP_PKEY
		return __fetch_ssk_prime(config);
#endif
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */
	}

	ctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
	if (!ctx || EVP_PKEY_paramgen_init(ctx) != 1) {
		fprintf(stderr, "error: ctx cannot be init\n");
		goto prime_end;
	}

	if (EVP_PKEY_CTX_set_dh_paramgen_prime_len(ctx,
						 config->skc_prime_bits) <= 0 ||
	    EVP_PKEY_CTX_set_dh_paramgen_generator(ctx, SK_GENERATOR) <= 0) {
		fprintf(stderr, "error: cannot set prime or generator\n");
		goto prime_end;
	}

	if (EVP_PKEY_paramgen(ctx, &dh) != 1) {
		fprintf(stderr, "error: cannot generate DH parameters\n");
		goto prime_end;
	}

	if (!EVP_PKEY_get_bn_param(dh, OSSL_PKEY_PARAM_FFC_P, &p)) {
		fprintf(stderr, "error: cannot get p from dh\n");
		goto prime_end;
	}

	if (BN_num_bytes(p) > SK_MAX_P_BYTES) {
		fprintf(stderr,
			"error: cannot generate DH parameters: requested length %d exceeds maximum %d\n",
			config->skc_prime_bits, SK_MAX_P_BYTES * 8);
		goto prime_end;
	}
	if (BN_bn2bin(p, config->skc_p) != BN_num_bytes(p)) {
		fprintf(stderr,
			"error: convert BIGNUM p to binary failed\n");
		goto prime_end;
	}

	rc = 0;

prime_end:
	if (rc)
		fprintf(stderr,
			"error: generating SSK prime failed: %s\n",
			ERR_error_string(ERR_get_error(), NULL));
	EVP_PKEY_free(dh);
	EVP_PKEY_CTX_free(ctx);
	return rc;
}

int main(int argc, char **argv)
{
	struct sk_keyfile_config *config;
	char *datafile = NULL;
	char *input = NULL;
	char *load = NULL;
	char *modify = NULL;
	char *output = NULL;
	char *mgsnids = NULL;
	char *nodemap = NULL;
	char *fsname = NULL;
	char *tmp;
	char *tmp2;
	int crypt = SK_CRYPT_EMPTY;
	int hmac = SK_HMAC_EMPTY;
	int expire = -1;
	int shared_keylen = -1;
	int prime_bits = -1;
	int verbose = 0;
	int i;
	int opt;
	enum sk_key_type type = SK_TYPE_INVALID;
	bool generate_prime = false;

	static struct option long_opts[] = {
	{ .name = "crypt",	.has_arg = required_argument, .val = 'c'},
	{ .name = "data",	.has_arg = required_argument, .val = 'd'},
	{ .name = "expire",	.has_arg = required_argument, .val = 'e'},
	{ .name = "fsname",	.has_arg = required_argument, .val = 'f'},
	{ .name = "mgsnids",	.has_arg = required_argument, .val = 'g'},
	{ .name = "help",	.has_arg = no_argument,	      .val = 'h'},
	{ .name = "hmac",	.has_arg = required_argument, .val = 'i'},
	{ .name = "integrity",	.has_arg = required_argument, .val = 'i'},
	{ .name = "key-bits",	.has_arg = required_argument, .val = 'k'},
	{ .name = "shared",	.has_arg = required_argument, .val = 'k'},
	{ .name = "load",	.has_arg = required_argument, .val = 'l'},
	{ .name = "modify",	.has_arg = required_argument, .val = 'm'},
	{ .name = "nodemap",	.has_arg = required_argument, .val = 'n'},
	{ .name = "prime-bits",	.has_arg = required_argument, .val = 'p'},
	{ .name = "read",	.has_arg = required_argument, .val = 'r'},
	{ .name = "type",	.has_arg = required_argument, .val = 't'},
	{ .name = "verbose",	.has_arg = no_argument,	      .val = 'v'},
	{ .name = "write",	.has_arg = required_argument, .val = 'w'},
	{ .name = NULL, } };

	while ((opt = getopt_long(argc, argv,
				  "c:d:e:f:g:hi:l:m:n:p:r:s:k:t:w:v", long_opts,
				  NULL)) != EOF) {
		switch (opt) {
		case 'c':
			crypt = sk_name2crypt(optarg);
			break;
		case 'd':
			datafile = optarg;
			break;
		case 'e':
			expire = atoi(optarg);
			if (expire < 60)
				fprintf(stderr, "warning: using a %us key "
					"expiration may cause issues during "
					"key renegotiation\n", expire);
			break;
		case 'f':
			fsname = optarg;
			if (strlen(fsname) > MTI_NAME_MAXLEN) {
				fprintf(stderr,
					"error: file system name longer than "
					"%u characters\n", MTI_NAME_MAXLEN);
				return EXIT_FAILURE;
			}
			break;
		case 'g':
			mgsnids = optarg;
			break;
		case 'h':
			usage(stdout, argv[0]);
			break;
		case 'i':
			hmac = sk_name2hmac(optarg);
			break;
		case 'k':
			shared_keylen = atoi(optarg);
			break;
		case 'l':
			load = optarg;
			break;
		case 'm':
			modify = optarg;
			break;
		case 'n':
			nodemap = optarg;
			if (strlen(nodemap) > LUSTRE_NODEMAP_NAME_LENGTH) {
				fprintf(stderr,
					"error: nodemap name longer than "
					"%u characters\n",
					LUSTRE_NODEMAP_NAME_LENGTH);
				return EXIT_FAILURE;
			}
			break;
		case 'p':
			prime_bits = atoi(optarg);
			if (prime_bits <= 0) {
				fprintf(stderr,
					"error: invalid prime length: '%s'\n",
					optarg);
				return EXIT_FAILURE;
			}
			break;
		case 'r':
			input = optarg;
			break;
		case 't':
			tmp2 = strdup(optarg);
			if (!tmp2) {
				fprintf(stderr,
					"error: failed to allocate type\n");
				return EXIT_FAILURE;
			}
			tmp = strsep(&tmp2, ",");
			while (tmp != NULL) {
				if (strcasecmp(tmp, "server") == 0) {
					type |= SK_TYPE_SERVER;
				} else if (strcasecmp(tmp, "mgs") == 0) {
					type |= SK_TYPE_MGS;
				} else if (strcasecmp(tmp, "client") == 0) {
					type |= SK_TYPE_CLIENT;
				} else {
					fprintf(stderr,
						"error: invalid type '%s', "
						"must be mgs, server, or client"
						"\n", optarg);
					return EXIT_FAILURE;
				}
				tmp = strsep(&tmp2, ",");
			}
			free(tmp2);
			break;
		case 'v':
			verbose++;
			break;
		case 'w':
			output = optarg;
			break;
		default:
			fprintf(stderr, "error: unknown option: '%c'\n", opt);
			return EXIT_FAILURE;
			break;
		}
	}

	if (optind != argc) {
		fprintf(stderr,
			"error: extraneous arguments provided, check usage\n");
		return EXIT_FAILURE;
	}

	if (!input && !output && !load && !modify) {
		usage(stderr, argv[0]);
		return EXIT_FAILURE;
	}

	/* init gss logger for foreground (no syslog) which prints to stderr */
	initerr(NULL, verbose, 1);

	fips_mode = FIPS_mode();

	if (input)
		return print_config(input);

	if (load) {
		if (sk_load_keyfile(load))
			return EXIT_FAILURE;
		return EXIT_SUCCESS;
	}

	if (crypt == SK_CRYPT_INVALID) {
		fprintf(stderr, "error: invalid crypt algorithm specified\n");
		return EXIT_FAILURE;
	}
	if (hmac == SK_HMAC_INVALID) {
		fprintf(stderr, "error: invalid HMAC algorithm specified\n");
		return EXIT_FAILURE;
	}

	if (modify && datafile) {
		fprintf(stderr,
			"error: data file option not valid in key modify\n");
		return EXIT_FAILURE;
	}

	if (modify) {
		config = sk_read_file(modify);
		if (!config)
			return EXIT_FAILURE;

		if (type != SK_TYPE_INVALID) {
			/* generate key when adding client type */
			if (!(config->skc_type & SK_TYPE_CLIENT) &&
			    type & SK_TYPE_CLIENT)
				generate_prime = true;
			else if (!(type & SK_TYPE_CLIENT))
				memset(config->skc_p, 0, SK_MAX_P_BYTES);

			config->skc_type = type;
		}
		if (prime_bits != -1) {
			memset(config->skc_p, 0, SK_MAX_P_BYTES);
			if (config->skc_prime_bits != prime_bits &&
			    config->skc_type & SK_TYPE_CLIENT)
				generate_prime = true;
		}
	} else {
		/* write mode for a new key */
		if (!fsname && !mgsnids) {
			fprintf(stderr,
				"error: missing --fsname or --mgsnids\n");
			return EXIT_FAILURE;
		}

		config = calloc(1, sizeof(*config));
		if (!config)
			return EXIT_FAILURE;

		/* Set the defaults for new key */
		config->skc_version = SK_CONF_VERSION;
		config->skc_expire = fips_mode ?
			SK_DEFAULT_EXPIRE_FIPS : SK_DEFAULT_EXPIRE;
		config->skc_shared_keylen = SK_DEFAULT_SK_KEYLEN;
		config->skc_prime_bits = SK_DEFAULT_PRIME_BITS;
		config->skc_crypt_alg = SK_CRYPT_AES256_CTR;
		config->skc_hmac_alg = SK_HMAC_SHA256;
		for (i = 0; i < MAX_MGSNIDS; i++)
			config->skc_mgsnids[i] = LNET_NID_ANY;

		if (type == SK_TYPE_INVALID) {
			fprintf(stderr, "error: no type specified for key\n");
			goto error;
		}
		config->skc_type = type;
		generate_prime = type & SK_TYPE_CLIENT;

		/* SK_DEFAULT_NODEMAP is made to fit in skc_nodemap */
		strcpy(config->skc_nodemap, SK_DEFAULT_NODEMAP);

		if (!datafile)
			datafile = "/dev/random";
	}

	if (crypt != SK_CRYPT_EMPTY)
		config->skc_crypt_alg = crypt;
	if (hmac != SK_HMAC_EMPTY)
		config->skc_hmac_alg = hmac;
	if (expire != -1)
		config->skc_expire = expire;
	if (fips_mode && config->skc_expire > SK_DEFAULT_EXPIRE_FIPS)
		fprintf(stderr,
			"warning: using a %us key expiration greater than %us is not recommended in FIPS mode\n",
			config->skc_expire, SK_DEFAULT_EXPIRE_FIPS);
	if (shared_keylen != -1)
		config->skc_shared_keylen = shared_keylen;
	if (prime_bits != -1) {
#ifdef HAVE_OPENSSL_EVP_PKEY
		/* #define DH_MIN_MODULUS_BITS 512, not exported by OpenSSL */
		if (prime_bits < 512) {
			fprintf(stderr,
				"error: prime length must be at least 512\n");
			return EXIT_FAILURE;
		}
#endif
		config->skc_prime_bits = prime_bits;
	}
	if (fsname)
		/* fsname string length was checked when parsing
		 * command-line options
		 */
		strcpy(config->skc_fsname, fsname);
	if (nodemap)
		/* nodemap string length was checked when parsing
		 * command-line options
		 */
		strcpy(config->skc_nodemap, nodemap);
	if (mgsnids && parse_mgsnids(mgsnids, config))
		goto error;
	if (sk_validate_config(config)) {
		fprintf(stderr, "error: key configuration failed validation\n");
		goto error;
	}

	if (datafile && get_key_data(datafile, config->skc_shared_key,
				     config->skc_shared_keylen)) {
		fprintf(stderr, "error: failure getting key data from '%s'\n",
			datafile);
		goto error;
	}

	if (generate_prime) {
		printf("Generating DH parameters, this can take a while...\n");
		if (__gen_ssk_prime(config))
			goto error;
	}

	if (write_config_file(modify ?: output, config, modify))
		goto error;

	return EXIT_SUCCESS;

error:
	free(config);
	return EXIT_FAILURE;
}
