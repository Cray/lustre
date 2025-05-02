// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#define DEBUG_SUBSYSTEM S_SEC

#include <libcfs/libcfs.h>
#include <linux/crypto.h>
#include <linux/key.h>

#include <obd.h>
#include <obd_class.h>
#include <obd_support.h>
#include <lustre_net.h>
#include <lustre_import.h>
#include <lustre_log.h>
#include <lustre_disk.h>
#include <lustre_dlm.h>
#include <uapi/linux/lustre/lustre_param.h>
#include <lustre_sec.h>

#include "ptlrpc_internal.h"

const char *sptlrpc_part2name(enum lustre_sec_part part)
{
	switch (part) {
	case LUSTRE_SP_CLI:
		return "cli";
	case LUSTRE_SP_MDT:
		return "mdt";
	case LUSTRE_SP_OST:
		return "ost";
	case LUSTRE_SP_MGC:
		return "mgc";
	case LUSTRE_SP_MGS:
		return "mgs";
	case LUSTRE_SP_ANY:
		return "any";
	default:
		return "err";
	}
}
EXPORT_SYMBOL(sptlrpc_part2name);

enum lustre_sec_part sptlrpc_target_sec_part(struct obd_device *obd)
{
	const char *type = obd->obd_type->typ_name;

	if (!strcmp(type, LUSTRE_MDT_NAME))
		return LUSTRE_SP_MDT;
	if (!strcmp(type, LUSTRE_OST_NAME))
		return LUSTRE_SP_OST;
	if (!strcmp(type, LUSTRE_MGS_NAME))
		return LUSTRE_SP_MGS;

	CERROR("unknown target %p(%s)\n", obd, type);
	return LUSTRE_SP_ANY;
}

/* user supplied flavor string parsing */

/* format: <base_flavor>[-<bulk_type:alg_spec>] */
int sptlrpc_parse_flavor(const char *str, struct sptlrpc_flavor *flvr)
{
	char            buf[32];
	char           *bulk, *alg;

	memset(flvr, 0, sizeof(*flvr));

	if (str == NULL || str[0] == '\0') {
		flvr->sf_rpc = SPTLRPC_FLVR_INVALID;
		return 0;
	}

	strscpy(buf, str, sizeof(buf));

	bulk = strchr(buf, '-');
	if (bulk)
		*bulk++ = '\0';

	flvr->sf_rpc = sptlrpc_name2flavor_base(buf);
	if (flvr->sf_rpc == SPTLRPC_FLVR_INVALID)
		goto err_out;

	/* currently only base flavor "plain" can have bulk specification.  */
	if (flvr->sf_rpc == SPTLRPC_FLVR_PLAIN) {
		flvr->u_bulk.hash.hash_alg = BULK_HASH_ALG_ADLER32;
		if (bulk) {
			/* format: plain-hash:<hash_alg> */
			alg = strchr(bulk, ':');
			if (alg == NULL)
				goto err_out;
			*alg++ = '\0';

			if (strcmp(bulk, "hash"))
				goto err_out;

			flvr->u_bulk.hash.hash_alg = sptlrpc_get_hash_alg(alg);
			if (flvr->u_bulk.hash.hash_alg >= BULK_HASH_ALG_MAX)
				goto err_out;
		}

		if (flvr->u_bulk.hash.hash_alg == BULK_HASH_ALG_NULL)
			flvr_set_bulk_svc(&flvr->sf_rpc, SPTLRPC_BULK_SVC_NULL);
		else
			flvr_set_bulk_svc(&flvr->sf_rpc, SPTLRPC_BULK_SVC_INTG);
	} else {
		if (bulk)
			goto err_out;
	}

	flvr->sf_flags = 0;
	return 0;

err_out:
	CERROR("invalid flavor string: %s\n", str);
	return -EINVAL;
}
EXPORT_SYMBOL(sptlrpc_parse_flavor);

/* configure rules */

static void get_default_flavor(struct sptlrpc_flavor *sf)
{
	memset(sf, 0, sizeof(*sf));

	sf->sf_rpc = SPTLRPC_FLVR_NULL;
	sf->sf_flags = 0;
}

static void sptlrpc_rule_init(struct sptlrpc_rule *rule)
{
	rule->sr_netid = LNET_NET_ANY;
	rule->sr_from = LUSTRE_SP_ANY;
	rule->sr_to = LUSTRE_SP_ANY;
	rule->sr_padding = 0;

	get_default_flavor(&rule->sr_flvr);
}

/* format: network[.direction]=flavor */
int sptlrpc_parse_rule(char *param, struct sptlrpc_rule *rule)
{
	char *flavor, *dir;
	int rc;

	sptlrpc_rule_init(rule);

	flavor = strchr(param, '=');
	if (flavor == NULL) {
		CERROR("invalid param, no '='\n");
		RETURN(-EINVAL);
	}
	*flavor++ = '\0';

	dir = strchr(param, '.');
	if (dir)
		*dir++ = '\0';

	/* 1.1 network */
	if (strcmp(param, "default")) {
		rule->sr_netid = libcfs_str2net(param);
		if (rule->sr_netid == LNET_NET_ANY) {
			CERROR("invalid network name: %s\n", param);
			RETURN(-EINVAL);
		}
	}

	/* 1.2 direction */
	if (dir) {
		if (!strcmp(dir, "mdt2ost")) {
			rule->sr_from = LUSTRE_SP_MDT;
			rule->sr_to = LUSTRE_SP_OST;
		} else if (!strcmp(dir, "mdt2mdt")) {
			rule->sr_from = LUSTRE_SP_MDT;
			rule->sr_to = LUSTRE_SP_MDT;
		} else if (!strcmp(dir, "cli2ost")) {
			rule->sr_from = LUSTRE_SP_CLI;
			rule->sr_to = LUSTRE_SP_OST;
		} else if (!strcmp(dir, "cli2mdt")) {
			rule->sr_from = LUSTRE_SP_CLI;
			rule->sr_to = LUSTRE_SP_MDT;
		} else {
			CERROR("invalid rule dir segment: %s\n", dir);
			RETURN(-EINVAL);
		}
	}

	/* 2.1 flavor */
	rc = sptlrpc_parse_flavor(flavor, &rule->sr_flvr);
	if (rc)
		RETURN(-EINVAL);

	RETURN(0);
}
EXPORT_SYMBOL(sptlrpc_parse_rule);

void sptlrpc_rule_set_free(struct sptlrpc_rule_set *rset)
{
	LASSERT(rset->srs_nslot ||
		(rset->srs_nrule == 0 && rset->srs_rules == NULL));

	if (rset->srs_nslot) {
		OBD_FREE_PTR_ARRAY(rset->srs_rules, rset->srs_nslot);
		sptlrpc_rule_set_init(rset);
	}
}
EXPORT_SYMBOL(sptlrpc_rule_set_free);

/* return 0 if the rule set could accomodate one more rule.  */
int sptlrpc_rule_set_expand(struct sptlrpc_rule_set *rset)
{
	struct sptlrpc_rule *rules;
	int nslot;

	might_sleep();

	if (rset->srs_nrule < rset->srs_nslot)
		return 0;

	nslot = rset->srs_nslot + 8;

	/* better use realloc() if available */
	OBD_ALLOC_PTR_ARRAY(rules, nslot);
	if (rules == NULL)
		return -ENOMEM;

	if (rset->srs_nrule) {
		LASSERT(rset->srs_nslot && rset->srs_rules);
		memcpy(rules, rset->srs_rules,
		       rset->srs_nrule * sizeof(*rset->srs_rules));

		OBD_FREE_PTR_ARRAY(rset->srs_rules, rset->srs_nslot);
	}

	rset->srs_rules = rules;
	rset->srs_nslot = nslot;
	return 0;
}

static inline int rule_spec_dir(struct sptlrpc_rule *rule)
{
	return (rule->sr_from != LUSTRE_SP_ANY ||
		rule->sr_to != LUSTRE_SP_ANY);
}
static inline int rule_spec_net(struct sptlrpc_rule *rule)
{
	return (rule->sr_netid != LNET_NET_ANY);
}
static inline int rule_match_dir(struct sptlrpc_rule *r1,
				 struct sptlrpc_rule *r2)
{
	return (r1->sr_from == r2->sr_from && r1->sr_to == r2->sr_to);
}
static inline int rule_match_net(struct sptlrpc_rule *r1,
				 struct sptlrpc_rule *r2)
{
	return (r1->sr_netid == r2->sr_netid);
}

/*
 * merge @rule into @rset.
 * the @rset slots might be expanded.
 */
int sptlrpc_rule_set_merge(struct sptlrpc_rule_set *rset,
			   struct sptlrpc_rule *rule)
{
	struct sptlrpc_rule      *p = rset->srs_rules;
	int                       spec_dir, spec_net;
	int                       rc, n, match = 0;

	might_sleep();

	spec_net = rule_spec_net(rule);
	spec_dir = rule_spec_dir(rule);

	for (n = 0; n < rset->srs_nrule; n++) {
		p = &rset->srs_rules[n];

		/* test network match, if failed:
		 * - spec rule: skip rules which is also spec rule match, until
		 *   we hit a wild rule, which means no more chance
		 * - wild rule: skip until reach the one which is also wild
		 *   and matches
		 */
		if (!rule_match_net(p, rule)) {
			if (spec_net) {
				if (rule_spec_net(p))
					continue;
				else
					break;
			} else {
				continue;
			}
		}

		/* test dir match, same logic as net matching */
		if (!rule_match_dir(p, rule)) {
			if (spec_dir) {
				if (rule_spec_dir(p))
					continue;
				else
					break;
			} else {
				continue;
			}
		}

		/* find a match */
		match = 1;
		break;
	}

	if (match) {
		LASSERT(n >= 0 && n < rset->srs_nrule);

		if (rule->sr_flvr.sf_rpc == SPTLRPC_FLVR_INVALID) {
			/* remove this rule */
			if (n < rset->srs_nrule - 1)
				memmove(&rset->srs_rules[n],
					&rset->srs_rules[n + 1],
					(rset->srs_nrule - n - 1) *
					sizeof(*rule));
			rset->srs_nrule--;
		} else {
			/* override the rule */
			memcpy(&rset->srs_rules[n], rule, sizeof(*rule));
		}
	} else {
		LASSERT(n >= 0 && n <= rset->srs_nrule);

		if (rule->sr_flvr.sf_rpc != SPTLRPC_FLVR_INVALID) {
			rc = sptlrpc_rule_set_expand(rset);
			if (rc)
				return rc;

			if (n < rset->srs_nrule)
				memmove(&rset->srs_rules[n + 1],
					&rset->srs_rules[n],
					(rset->srs_nrule - n) * sizeof(*rule));
			memcpy(&rset->srs_rules[n], rule, sizeof(*rule));
			rset->srs_nrule++;
		} else {
			CDEBUG(D_CONFIG, "ignore the unmatched deletion\n");
		}
	}

	return 0;
}
EXPORT_SYMBOL(sptlrpc_rule_set_merge);

/**
 * sptlrpc_rule_set_choose() - given from/to/nid, determine a matching flavor
 * in ruleset.
 * @rset: pointer to rule set to be searched
 * @from: where request is coming (client, MDT, OST)
 * @to: where request is going
 * @nid: pointer to lnet_nid (network identifier)
 * @sf: Choosen flavor is stored [out]
 *
 * return 1 if a match found, otherwise return 0.
 */
int sptlrpc_rule_set_choose(struct sptlrpc_rule_set *rset,
			    enum lustre_sec_part from,
			    enum lustre_sec_part to,
			    struct lnet_nid *nid,
			    struct sptlrpc_flavor *sf)
{
	struct sptlrpc_rule *r;
	int n;

	if (nid_is_lo0(nid))
		/* do not enforce any sec flavor on loopback connection */
		return 0;

	for (n = 0; n < rset->srs_nrule; n++) {
		r = &rset->srs_rules[n];

		if (!LNET_NID_IS_ANY(nid) &&
		    r->sr_netid != LNET_NET_ANY &&
		    __be16_to_cpu(nid->nid_num) != r->sr_netid)
			continue;

		if (from != LUSTRE_SP_ANY && r->sr_from != LUSTRE_SP_ANY &&
		    from != r->sr_from)
			continue;

		if (to != LUSTRE_SP_ANY && r->sr_to != LUSTRE_SP_ANY &&
		    to != r->sr_to)
			continue;

		*sf = r->sr_flvr;
		return 1;
	}

	return 0;
}

void sptlrpc_rule_set_dump(struct sptlrpc_rule_set *rset)
{
	struct sptlrpc_rule *r;
	int     n;

	for (n = 0; n < rset->srs_nrule; n++) {
		r = &rset->srs_rules[n];
		CDEBUG(D_SEC, "<%02d> from %x to %x, net %x, rpc %x\n", n,
		       r->sr_from, r->sr_to, r->sr_netid, r->sr_flvr.sf_rpc);
	}
}

static int sptlrpc_rule_set_extract(struct sptlrpc_rule_set *gen,
				    struct sptlrpc_rule_set *tgt,
				    enum lustre_sec_part from,
				    enum lustre_sec_part to,
				    struct sptlrpc_rule_set *rset)
{
	struct sptlrpc_rule_set *src[2] = { gen, tgt };
	struct sptlrpc_rule     *rule;
	int                      i, n, rc;

	might_sleep();

	/* merge general rules firstly, then target-specific rules */
	for (i = 0; i < 2; i++) {
		if (src[i] == NULL)
			continue;

		for (n = 0; n < src[i]->srs_nrule; n++) {
			rule = &src[i]->srs_rules[n];

			if (from != LUSTRE_SP_ANY &&
			    rule->sr_from != LUSTRE_SP_ANY &&
			    rule->sr_from != from)
				continue;
			if (to != LUSTRE_SP_ANY &&
			    rule->sr_to != LUSTRE_SP_ANY &&
			    rule->sr_to != to)
				continue;

			rc = sptlrpc_rule_set_merge(rset, rule);
			if (rc) {
				CERROR("can't merge: %d\n", rc);
				return rc;
			}
		}
	}

	return 0;
}

/* sptlrpc configuration support  */

struct sptlrpc_conf_tgt {
	struct list_head              sct_list;
	char                    sct_name[MAX_OBD_NAME];
	struct sptlrpc_rule_set sct_rset;
};

struct sptlrpc_conf {
	struct list_head	sc_list;
	char			sc_fsname[MTI_NAME_MAXLEN];
	unsigned int		sc_modified;	/* modified during updating */
	unsigned int		sc_updated:1,	/* updated copy from MGS */
				sc_local:1;	/* local copy from target */
	struct sptlrpc_rule_set	sc_rset;	/* fs general rules */
	struct list_head	sc_tgts;	/* target-specific rules */
};

static struct mutex sptlrpc_conf_lock;
static LIST_HEAD(sptlrpc_confs);

static void sptlrpc_conf_free_rsets(struct sptlrpc_conf *conf)
{
	struct sptlrpc_conf_tgt *conf_tgt, *conf_tgt_next;

	sptlrpc_rule_set_free(&conf->sc_rset);

	list_for_each_entry_safe(conf_tgt, conf_tgt_next,
				 &conf->sc_tgts, sct_list) {
		sptlrpc_rule_set_free(&conf_tgt->sct_rset);
		list_del(&conf_tgt->sct_list);
		OBD_FREE_PTR(conf_tgt);
	}
	LASSERT(list_empty(&conf->sc_tgts));

	conf->sc_updated = 0;
	conf->sc_local = 0;
}

static void sptlrpc_conf_free(struct sptlrpc_conf *conf)
{
	CDEBUG(D_SEC, "free sptlrpc conf %s\n", conf->sc_fsname);

	sptlrpc_conf_free_rsets(conf);
	list_del(&conf->sc_list);
	OBD_FREE_PTR(conf);
}

static
struct sptlrpc_conf_tgt *sptlrpc_conf_get_tgt(struct sptlrpc_conf *conf,
					      const char *name,
					      int create)
{
	struct sptlrpc_conf_tgt *conf_tgt;

	list_for_each_entry(conf_tgt, &conf->sc_tgts, sct_list) {
		if (strcmp(conf_tgt->sct_name, name) == 0)
			return conf_tgt;
	}

	if (!create)
		return NULL;

	OBD_ALLOC_PTR(conf_tgt);
	if (conf_tgt) {
		strscpy(conf_tgt->sct_name, name, sizeof(conf_tgt->sct_name));
		sptlrpc_rule_set_init(&conf_tgt->sct_rset);
		list_add(&conf_tgt->sct_list, &conf->sc_tgts);
	}

	return conf_tgt;
}

static
struct sptlrpc_conf *sptlrpc_conf_get(const char *fsname,
				      int create)
{
	struct sptlrpc_conf *conf;

	list_for_each_entry(conf, &sptlrpc_confs, sc_list) {
		if (strcmp(conf->sc_fsname, fsname) == 0)
			return conf;
	}

	if (!create)
		return NULL;

	OBD_ALLOC_PTR(conf);
	if (conf == NULL)
		return NULL;
	if (strscpy(conf->sc_fsname, fsname, sizeof(conf->sc_fsname)) < 0) {
		OBD_FREE_PTR(conf);
		return NULL;
	}
	sptlrpc_rule_set_init(&conf->sc_rset);
	INIT_LIST_HEAD(&conf->sc_tgts);
	list_add(&conf->sc_list, &sptlrpc_confs);

	CDEBUG(D_SEC, "create sptlrpc conf %s\n", conf->sc_fsname);
	return conf;
}

/* caller must hold conf_lock already. */
static int sptlrpc_conf_merge_rule(struct sptlrpc_conf *conf,
				   const char *target,
				   struct sptlrpc_rule *rule)
{
	struct sptlrpc_conf_tgt  *conf_tgt;
	struct sptlrpc_rule_set  *rule_set;

	/* fsname == target means general rules for the whole fs */
	if (strcmp(conf->sc_fsname, target) == 0) {
		rule_set = &conf->sc_rset;
	} else {
		conf_tgt = sptlrpc_conf_get_tgt(conf, target, 1);
		if (conf_tgt) {
			rule_set = &conf_tgt->sct_rset;
		} else {
			CERROR("out of memory, can't merge rule!\n");
			return -ENOMEM;
		}
	}

	return sptlrpc_rule_set_merge(rule_set, rule);
}

/*
 * process one LCFG_SPTLRPC_CONF record. if @conf is NULL, we
 * find one through the target name in the record inside conf_lock;
 * otherwise means caller already hold conf_lock.
 */
static int __sptlrpc_process_config(char *target, const char *fsname,
				    struct sptlrpc_rule *rule,
				    struct sptlrpc_conf *conf)
{
	int rc;

	ENTRY;
	if (!conf) {
		if (!fsname)
			return -ENODEV;

		mutex_lock(&sptlrpc_conf_lock);
		conf = sptlrpc_conf_get(fsname, 0);
		if (!conf) {
			CERROR("can't find conf\n");
			rc = -ENOMEM;
		} else {
			rc = sptlrpc_conf_merge_rule(conf, target, rule);
		}
		mutex_unlock(&sptlrpc_conf_lock);
	} else {
		LASSERT(mutex_is_locked(&sptlrpc_conf_lock));
		rc = sptlrpc_conf_merge_rule(conf, target, rule);
	}

	if (!rc)
		conf->sc_modified++;

	RETURN(rc);
}

/**
 * sptlrpc_process_config() - process a config record related to the sec policy
 * @lcfg: pointer to struct lustre_cfg (config record)
 *
 * Return:
 * * %0 on success
 * * %negative on failure
 */
int sptlrpc_process_config(struct lustre_cfg *lcfg)
{
	char fsname[MTI_NAME_MAXLEN];
	struct sptlrpc_rule rule;
	char *target, *param;
	int rc;

	print_lustre_cfg(lcfg);

	target = lustre_cfg_string(lcfg, 1);
	if (!target) {
		CERROR("missing target name\n");
		return -EINVAL;
	}

	param = lustre_cfg_string(lcfg, 2);
	if (!param) {
		CERROR("missing parameter\n");
		return -EINVAL;
	}

	/* parse rule to make sure the format is correct */
	if (strncmp(param, PARAM_SRPC_FLVR,
		    sizeof(PARAM_SRPC_FLVR) - 1) != 0) {
		CERROR("Invalid sptlrpc parameter: %s\n", param);
		return -EINVAL;
	}
	param += sizeof(PARAM_SRPC_FLVR) - 1;

	CDEBUG(D_SEC, "processing rule: %s.%s\n", target, param);

	/*
	 * Three types of targets exist for sptlrpc using conf_param
	 * 1.	'_mgs' which targets mgc srpc settings. Treat it as
	 *	as a special file system name.
	 * 2.	target is a device which can be fsname-MDTXXXX or
	 *	fsname-OSTXXXX. This can be verified by the function
	 *	server_name2fsname.
	 * 3.	If both above conditions are not meet then the target
	 *	is a actual filesystem.
	 */
	if (server_name2fsname(target, fsname, NULL))
		strscpy(fsname, target, sizeof(fsname));

	rc = sptlrpc_parse_rule(param, &rule);
	if (rc)
		return rc;

	return __sptlrpc_process_config(target, fsname, &rule, NULL);
}
EXPORT_SYMBOL(sptlrpc_process_config);

static int logname2fsname(const char *logname, char *buf, int buflen)
{
	char   *ptr;
	int     len;

	ptr = strrchr(logname, '-');
	if (ptr == NULL || strcmp(ptr, "-sptlrpc")) {
		CERROR("%s is not a sptlrpc config log\n", logname);
		return -EINVAL;
	}

	len = min((int) (ptr - logname), buflen - 1);

	memcpy(buf, logname, len);
	buf[len] = '\0';
	return 0;
}

void sptlrpc_conf_log_update_begin(const char *logname)
{
	struct sptlrpc_conf *conf;
	char                 fsname[16];

	if (logname2fsname(logname, fsname, sizeof(fsname)))
		return;

	mutex_lock(&sptlrpc_conf_lock);

	conf = sptlrpc_conf_get(fsname, 0);
	if (conf) {
		if (conf->sc_local) {
			LASSERT(conf->sc_updated == 0);
			sptlrpc_conf_free_rsets(conf);
		}
		conf->sc_modified = 0;
	}

	mutex_unlock(&sptlrpc_conf_lock);
}
EXPORT_SYMBOL(sptlrpc_conf_log_update_begin);

/* mark a config log has been updated */
void sptlrpc_conf_log_update_end(const char *logname)
{
	struct sptlrpc_conf *conf;
	char                 fsname[16];

	if (logname2fsname(logname, fsname, sizeof(fsname)))
		return;

	mutex_lock(&sptlrpc_conf_lock);

	conf = sptlrpc_conf_get(fsname, 0);
	if (conf) {
		/* if original state is not updated, make sure the
		 * modified counter > 0 to enforce updating local copy.
		 */
		if (conf->sc_updated == 0)
			conf->sc_modified++;

		conf->sc_updated = 1;
	}

	mutex_unlock(&sptlrpc_conf_lock);
}
EXPORT_SYMBOL(sptlrpc_conf_log_update_end);

void sptlrpc_conf_log_start(const char *logname)
{
	char                 fsname[16];

	if (logname2fsname(logname, fsname, sizeof(fsname)))
		return;

	mutex_lock(&sptlrpc_conf_lock);
	sptlrpc_conf_get(fsname, 1);
	mutex_unlock(&sptlrpc_conf_lock);
}
EXPORT_SYMBOL(sptlrpc_conf_log_start);

void sptlrpc_conf_log_stop(const char *logname)
{
	struct sptlrpc_conf *conf;
	char                 fsname[16];

	if (logname2fsname(logname, fsname, sizeof(fsname)))
		return;

	mutex_lock(&sptlrpc_conf_lock);
	conf = sptlrpc_conf_get(fsname, 0);
	if (conf)
		sptlrpc_conf_free(conf);
	mutex_unlock(&sptlrpc_conf_lock);
}
EXPORT_SYMBOL(sptlrpc_conf_log_stop);

static inline void flavor_set_flags(struct sptlrpc_flavor *sf,
				    enum lustre_sec_part from,
				    enum lustre_sec_part to,
				    unsigned int fl_udesc)
{
	/* null flavor doesn't need to set any flavor, and in fact
	 * we'd better not do that because everybody share a single sec.
	 */
	if (sf->sf_rpc == SPTLRPC_FLVR_NULL)
		return;

	if (from == LUSTRE_SP_MDT) {
		/* MDT->MDT; MDT->OST */
		sf->sf_flags |= PTLRPC_SEC_FL_ROOTONLY;
	} else if (from == LUSTRE_SP_CLI && to == LUSTRE_SP_OST) {
		/* CLI->OST */
		sf->sf_flags |= PTLRPC_SEC_FL_ROOTONLY | PTLRPC_SEC_FL_BULK;
	} else if (from == LUSTRE_SP_CLI && to == LUSTRE_SP_MDT) {
		/* CLI->MDT */
		if (fl_udesc && sf->sf_rpc != SPTLRPC_FLVR_NULL)
			sf->sf_flags |= PTLRPC_SEC_FL_UDESC;
	}

	/* Some flavors use a single uid (0) context */
	if (flvr_is_rootonly(sf->sf_rpc))
		sf->sf_flags |= PTLRPC_SEC_FL_ROOTONLY;

	/* User descriptor might need to be cleared */
	if (flvr_allows_user_desc(sf->sf_rpc) == 0)
		sf->sf_flags &= ~PTLRPC_SEC_FL_UDESC;
}

void sptlrpc_conf_choose_flavor(enum lustre_sec_part from,
				enum lustre_sec_part to,
				struct obd_uuid *target,
				struct lnet_nid *nid,
				struct sptlrpc_flavor *sf)
{
	struct sptlrpc_conf     *conf;
	struct sptlrpc_conf_tgt *conf_tgt;
	char                     name[MTI_NAME_MAXLEN];
	int                      len, rc = 0;

	obd_uuid2fsname(name, target->uuid, sizeof(name));

	mutex_lock(&sptlrpc_conf_lock);

	conf = sptlrpc_conf_get(name, 0);
	if (conf == NULL)
		goto out;

	/* convert uuid name (supposed end with _UUID) to target name */
	len = strlen(target->uuid);
	LASSERT(len > 5);
	memcpy(name, target->uuid, len - 5);
	name[len - 5] = '\0';

	conf_tgt = sptlrpc_conf_get_tgt(conf, name, 0);
	if (conf_tgt) {
		rc = sptlrpc_rule_set_choose(&conf_tgt->sct_rset,
					     from, to, nid, sf);
		if (rc)
			goto out;
	}

	rc = sptlrpc_rule_set_choose(&conf->sc_rset, from, to,
				     nid, sf);
out:
	mutex_unlock(&sptlrpc_conf_lock);

	if (rc == 0)
		get_default_flavor(sf);

	flavor_set_flags(sf, from, to, 1);
}

/*
 * called by target devices, determine the expected flavor from
 * certain peer (from, nid).
 */
void sptlrpc_target_choose_flavor(struct sptlrpc_rule_set *rset,
				  enum lustre_sec_part from,
				  struct lnet_nid *nid,
				  struct sptlrpc_flavor *sf)
{
	if (sptlrpc_rule_set_choose(rset, from, LUSTRE_SP_ANY, nid, sf) == 0)
		get_default_flavor(sf);
}

#define SEC_ADAPT_DELAY         (10)

/**
 * sptlrpc_conf_client_adapt() - notify the sptlrpc config has changed
 * @obd: pointer to obd device (client side, OSC/MDC)
 *
 * called by client devices, notify the sptlrpc config has changed and
 * do import_sec_adapt later.
 */
void sptlrpc_conf_client_adapt(struct obd_device *obd)
{
	struct obd_import  *imp;
	int rc;

	ENTRY;

	LASSERT(strcmp(obd->obd_type->typ_name, LUSTRE_MDC_NAME) == 0 ||
		strcmp(obd->obd_type->typ_name, LUSTRE_OSC_NAME) == 0 ||
		strcmp(obd->obd_type->typ_name, LUSTRE_OSP_NAME) == 0 ||
		strcmp(obd->obd_type->typ_name, LUSTRE_LWP_NAME) == 0);
	CDEBUG(D_SEC, "obd %s\n", obd->u.cli.cl_target_uuid.uuid);

	/* serialize with connect/disconnect import */
	with_imp_locked_nested(obd, imp, rc, OBD_CLI_SEM_MDCOSC) {
		write_lock(&imp->imp_sec_lock);
		if (imp->imp_sec)
			imp->imp_sec_expire = ktime_get_real_seconds() +
				SEC_ADAPT_DELAY;
		write_unlock(&imp->imp_sec_lock);
	}

	EXIT;
}
EXPORT_SYMBOL(sptlrpc_conf_client_adapt);

/*
 * called by target devices, extract sptlrpc rules which applies to
 * this target, to be used for future rpc flavor checking.
 */
int sptlrpc_conf_target_get_rules(struct obd_device *obd,
				  struct sptlrpc_rule_set *rset)
{
	struct sptlrpc_conf *conf;
	struct sptlrpc_conf_tgt *conf_tgt;
	enum lustre_sec_part sp_dst;
	char fsname[MTI_NAME_MAXLEN];
	int rc = 0;

	ENTRY;

	if (strcmp(obd->obd_type->typ_name, LUSTRE_MDT_NAME) == 0) {
		sp_dst = LUSTRE_SP_MDT;
	} else if (strcmp(obd->obd_type->typ_name, LUSTRE_OST_NAME) == 0) {
		sp_dst = LUSTRE_SP_OST;
	} else {
		CERROR("unexpected obd type %s\n", obd->obd_type->typ_name);
		RETURN(-EINVAL);
	}

	obd_uuid2fsname(fsname, obd->obd_uuid.uuid, sizeof(fsname));

	mutex_lock(&sptlrpc_conf_lock);
	conf = sptlrpc_conf_get(fsname, 0);
	if (conf == NULL) {
		CERROR("missing sptlrpc config log\n");
		rc = -EFAULT;
	} else {
		/* extract rule set for this target */
		conf_tgt = sptlrpc_conf_get_tgt(conf, obd->obd_name, 0);

		rc = sptlrpc_rule_set_extract(&conf->sc_rset,
				      conf_tgt ? &conf_tgt->sct_rset : NULL,
				      LUSTRE_SP_ANY, sp_dst, rset);
	}
	mutex_unlock(&sptlrpc_conf_lock);

	RETURN(rc);
}

int  sptlrpc_conf_init(void)
{
	mutex_init(&sptlrpc_conf_lock);
	return 0;
}

void sptlrpc_conf_fini(void)
{
	struct sptlrpc_conf  *conf, *conf_next;

	mutex_lock(&sptlrpc_conf_lock);
	list_for_each_entry_safe(conf, conf_next, &sptlrpc_confs, sc_list)
		sptlrpc_conf_free(conf);
	LASSERT(list_empty(&sptlrpc_confs));
	mutex_unlock(&sptlrpc_conf_lock);
}
