/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/utils/lctl.c
 *
 * Author: Peter J. Braam <braam@clusterfs.com>
 * Author: Phil Schwan <phil@clusterfs.com>
 * Author: Robert Read <rread@clusterfs.com>
 */

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <libcfs/util/parser.h>
#include <linux/lnet/lnetctl.h>
#include "obdctl.h"
#include <linux/lustre/lustre_ver.h>
#include <lustre/lustreapi.h>
#include "lctl_thread.h"

#define JT_SUBCMD(name)						\
static int jt_##name(int argc, char **argv)			\
{								\
	char cmd[PATH_MAX];					\
	int rc = 0;						\
								\
	setlinebuf(stdout);					\
								\
	snprintf(cmd, sizeof(cmd), "%s %s",			\
		 program_invocation_short_name, argv[0]);	\
	program_invocation_short_name = cmd;			\
	rc = cfs_parser(argc, argv, name##_cmdlist);		\
								\
	return rc < 0 ? -rc : rc;				\
}

/**
 * command_t pcc_cmdlist - lctl pcc commands.
 */
command_t pcc_cmdlist[] = {
	{ .pc_name = "add", .pc_func = jt_pcc_add,
	  .pc_help = "Add a PCC backend to a client.\n"
		"usage: lctl pcc add <mntpath> <pccpath> [--param|-p <param>]\n"
		"\tmntpath: Lustre mount point.\n"
		"\tpccpath: Path of the PCC backend.\n"
		"\tparam:   Setting parameters for PCC backend.\n" },
	{ .pc_name = "del", .pc_func = jt_pcc_del,
	  .pc_help = "Delete the specified PCC backend on a client.\n"
		"usage: lctl pcc del <mntpath> <pccpath>\n" },
	{ .pc_name = "clear", .pc_func = jt_pcc_clear,
	  .pc_help = "Remove all PCC backend on a client.\n"
		"usage: lctl pcc clear <mntpath>\n" },
	{ .pc_name = "list", .pc_func = jt_pcc_list,
	  .pc_help = "List all PCC backends on a client.\n"
		"usage: lctl pcc list <mntpath>\n" },
	{ .pc_help = NULL }
};
JT_SUBCMD(pcc);

/**
 * command_t changelog_cmdlist - lctl changelog commands.
 */
command_t changelog_cmdlist[] = {
	{.pc_name = "register", .pc_func = jt_changelog_register,
	 .pc_help = "register a new persistent changelog user, returns id\n"
	 "usage: {--device MDTNAME} changelog register [--help|-h]\n"
	 "					       [--mask|-m MASK]\n"
	 "					       [--nameonly|-n]\n"
	 "					       [--user|-u USERNAME]"},
	{.pc_name = "deregister", .pc_func = jt_changelog_deregister,
	 .pc_help = "deregister an existing changelog user\n"
	 "usage: {--device MDTNAME} changelog deregister [ID|clID]\n"
	 "						 [--help|-h]\n"
	 "						 [--user|-u USERNAME]"},
	{.pc_help = NULL }
};
JT_SUBCMD(changelog);

/**
 * command_t net_drop_cmdlist - lctl net_drop commands.
 */
command_t net_drop_cmdlist[] = {
	{.pc_name = "add", .pc_func = jt_ptl_drop_add,
	 .pc_help = "Add LNet drop rule\n"
	 "usage: net_drop add {-s | --source NID}\n"
	 "		      {-d | --dest NID}\n"
	 "		      {{-r | --rate DROP_RATE} | {-i | --interval SECONDS}}\n"
	 "		      [-p | --portal PORTAL...]\n"
	 "		      [-m | --message {PUT|ACK|GET|REPLY...}]\n"
	 "		      [-e | --health_error]"},
	{.pc_name = "del", .pc_func = jt_ptl_drop_del,
	 .pc_help = "remove LNet drop rule\n"
	 "usage: net_drop del {-a | --all} |\n"
	 "		      {{-s | --source NID} {-d | --dest NID}}"},
	{.pc_name = "reset", .pc_func = jt_ptl_drop_reset,
	 .pc_help = "reset drop rule stats\n"
	 "usage: net_drop reset"},
	{.pc_name = "list", .pc_func = jt_ptl_drop_list,
	 .pc_help = "list LNet drop rules\n"
	 "usage: net_drop list"},
	{ .pc_help = NULL }
};
JT_SUBCMD(net_drop);

/**
 * command_t net_delay_cmdlist - lctl net_delay commands.
 */
command_t net_delay_cmdlist[] = {
	{.pc_name = "add", .pc_func = jt_ptl_delay_add,
	 .pc_help = "Add LNet delay rule\n"
	 "usage: net_delay add {-s | --source NID}\n"
	 "		       {-d | --dest NID}\n"
	 "		       {{-r | --rate DELAY_RATE} | {-i | --interval SECONDS}}\n"
	 "		       {-l | --latency SECONDS>\n"
	 "		       [-p | --portal PORTAL...]\n"
	 "		       [-m | --message {PUT|ACK|GET|REPLY...}]"},
	{.pc_name = "del", .pc_func = jt_ptl_delay_del,
	 .pc_help = "remove LNet delay rule\n"
	 "usage: net_delay del {-a | --all} |\n"
	 "		       {{-s | --source NID} {-d | --dest NID}}"},
	{.pc_name = "reset", .pc_func = jt_ptl_delay_reset,
	 .pc_help = "reset delay rule stats\n"
	 "usage: net_delay reset"},
	{.pc_name = "list", .pc_func = jt_ptl_delay_list,
	 .pc_help = "list LNet delay rules\n"
	 "usage: net_delay list"},
	{.pc_help = NULL }
};
JT_SUBCMD(net_delay);

/**
 * command_t nodemap_cmdlist - lctl nodemap commands.
 */
command_t nodemap_cmdlist[] = {
	{.pc_name = "activate", .pc_func = jt_nodemap_activate,
	 .pc_help = "activate nodemap idmapping functions\n"
	 "usage: nodemap activate {0|1}"},
	{.pc_name = "add", .pc_func = jt_nodemap_add,
	 .pc_help = "add a new nodemap\n"
	 "usage: nodemap add [-d|--dynamic] [-p|--parent PARENT_NAME] --name NODEMAP_NAME"},
	{.pc_name = "del", .pc_func = jt_nodemap_del,
	 .pc_help = "remove a nodemap\n"
	 "usage: nodemap del --name NODEMAP_NAME"},
	{.pc_name = "add_range", .pc_func = jt_nodemap_add_range,
	 .pc_help = "add a nid range to a nodemap\n"
	 "usage: nodemap add_range --name NODEMAP_NAME --range NID_RANGE"},
	{.pc_name = "del_range", .pc_func = jt_nodemap_del_range,
	 .pc_help = "delete a nid range from a nodemap\n"
	 "usage: nodemap del_range --name NODEMAP_NAME --range NID_RANGE"},
	{.pc_name = "modify", .pc_func = jt_nodemap_modify,
	 .pc_help = "modify a nodemap parameters\n"
	 "usage: nodemap modify --name NODEMAP_NAME --property PROPERTY\n"
	 "			--value VALUE"},
	{.pc_name = "add_offset", .pc_func = jt_nodemap_add_offset,
	 .pc_help = "add an offset for UID/GID/PROJID mappings\n"
	 "usage: nodemap_add_offset --name NODEMAP_NAME --offset OFFSET\n"
	 "			    --limit LIMIT"},
	{.pc_name = "del_offset", .pc_func = jt_nodemap_del_offset,
	 .pc_help = "delete an offset for UID/GID/PROJID mappings\n"
	 "usage: nodemap_del_offset --name NODEMAP_NAME"},
	{.pc_name = "add_idmap", .pc_func = jt_nodemap_add_idmap,
	 .pc_help = "add a UID or GID mapping to a nodemap\n"
	 "usage: nodemap add_idmap --name NAME --idtype {uid|gid|projid}\n"
	 "			   --idmap CLIENTID:FSID"},
	{.pc_name = "del_idmap", .pc_func = jt_nodemap_del_idmap,
	 .pc_help = "delete a UID or GID mapping from a nodemap\n"
	 "usage: nodemap del_idmap --name NAME --idtype {uid|gid|projid}\n"
	 "			   --idmap CLIENTID:FSID"},
	{.pc_name = "set_fileset", .pc_func = jt_nodemap_set_fileset,
	 .pc_help = "set a fileset on a nodemap\n"
	 "usage: nodemap set_fileset --name NODEMAP_NAME --fileset FILESET"},
	{.pc_name = "set_sepol", .pc_func = jt_nodemap_set_sepol,
	 .pc_help = "set SELinux policy info on a nodemap\n"
	 "usage: nodemap set_sepol --name NODEMAP_NAME --sepol SEPOL"},
	{.pc_name = "test_nid", .pc_func = jt_nodemap_test_nid,
	 .pc_help = "test a nid for nodemap membership\n"
	 "usage: nodemap test_nid --nid NID"},
	{.pc_name = "test_id", .pc_func = jt_nodemap_test_id,
	 .pc_help = "test a nodemap id pair for mapping\n"
	 "usage: nodemap test_id --nid NID --idtype {uid|gid|projid} --id ID"},
	{.pc_name = "info", .pc_func = jt_nodemap_info,
	 .pc_help = "print nodemap information\n"
	 "usage: nodemap info {list|nodemap_name|all}"},
	{.pc_help = NULL }
};
JT_SUBCMD(nodemap);

#ifdef HAVE_SERVER_SUPPORT
/**
 * command_t barrier_cmdlist - lctl barrier commands.
 */
command_t barrier_cmdlist[] = {
	{ .pc_name = "freeze", .pc_func = jt_barrier_freeze,
	  .pc_help = "freeze write barrier on MDTs\n"
	 "usage: barrier freeze FSNAME [TIMEOUT_SECONDS]"},
	{ .pc_name = "thaw", .pc_func = jt_barrier_thaw,
	  .pc_help = "thaw write barrier on MDTs\n"
	 "usage: barrier thaw FSNAME"},
	{ .pc_name = "stat", .pc_func = jt_barrier_stat,
	  .pc_help = "query write barrier status on MDTs\n"
	 "usage: barrier stat [--state|-s] [--timeout|-t] FSNAME"},
	{ .pc_name = "rescan", .pc_func = jt_barrier_rescan,
	  .pc_help =
	 "rescan the system to filter out inactive MDT(s) for barrier\n"
	 "usage: barrier rescan FSNAME [TIMEOUT_SECONDS]"},
	{ .pc_help = NULL }
};
JT_SUBCMD(barrier);

/**
 * command_t snaptshot_cmdlist - lctl snapshot commands.
 */
command_t snapshot_cmdlist[] = {
	{ .pc_name = "create", .pc_func = jt_snapshot_create,
	  .pc_help = "create the snapshot\n"
	 "usage: snapshot create [-b | --barrier [on | off]]\n"
	 "			 [-c | --comment COMMENT]\n"
	 "			 {-F | --fsname FSNAME}\n"
	 "			 [-h | --help] {-n | --name SSNAME}\n"
	 "			 [-r | --rsh REMOTE_SHELL]\n"
	 "			 [-t | --timeout TIMEOUT]"},
	{.pc_name = "destroy", .pc_func = jt_snapshot_destroy,
	 .pc_help = "destroy the snapshot\n"
	 "usage: snapshot destroy [-f | --force]\n"
	 "			  {-F | --fsname FSNAME} [-h | --help]\n"
	 "			  {-n | --name SSNAME}\n"
	 "			  [-r | --rsh REMOTE_SHELL]"},
	{.pc_name = "modify", .pc_func = jt_snapshot_modify,
	 .pc_help = "modify the snapshot\n"
	 "usage: snapshot modify [-c | --comment COMMENT]\n"
	 "			 {-F | --fsname FSNAME} [-h | --help]\n"
	 "			 {-n | --name SSNAME} [-N | --new NEW_SSNAME]\n"
	 "			 [-r | --rsh REMOTE_SHELL]"},
	{.pc_name = "list", .pc_func = jt_snapshot_list,
	 .pc_help = "query the snapshot(s)\n"
	 "usage: snapshot list [-d | --detail]\n"
	 "		       {-F | --fsname FSNAME} [-h | --help]\n"
	 "		       [-n | --name SSNAME] [-r | --rsh REMOTE_SHELL]"},
	{.pc_name = "mount", .pc_func = jt_snapshot_mount,
	 .pc_help = "mount the snapshot\n"
	 "usage: snapshot mount {-F | --fsname FSNAME} [-h | --help]\n"
	 "			{-n | --name SSNAME}\n"
	 "			[-r | --rsh REMOTE_SHELL]"},
	{.pc_name = "umount", .pc_func = jt_snapshot_umount,
	 .pc_help = "umount the snapshot\n"
	 "usage: snapshot umount {-F | --fsname FSNAME} [-h | --help]\n"
	 "			 {-n | --name SSNAME}\n"
	 "			 [-r | --rsh REMOTE_SHELL]"},
	{.pc_help = NULL }
};
JT_SUBCMD(snapshot);

/**
 * command_t llog_cmdlist - lctl llog commands.
 */
command_t llog_cmdlist[] = {
	{ .pc_name = "catlist", .pc_func = jt_llog_catlist,
	  .pc_help = "list Lustre configuration log files\n"
	 "usage: llog catlist"},
	{ .pc_name = "info", .pc_func = jt_llog_info,
	  .pc_help = "print log header information\n"
	 "usage: llog info {LOGNAME|FID}"},
	{ .pc_name = "print", .pc_func = jt_llog_print,
	  .pc_help = "print the content of a configuration log\n"
	 "usage: llog print {LOGNAME|FID} [--start INDEX] [--end INDEX]\n"
	 "		    [--raw]"},
	{ .pc_name = "cancel", .pc_func = jt_llog_cancel,
	  .pc_help = "cancel one record in specified log.\n"
	 "usage:llog cancel {LOGNAME|FID} --log_idx INDEX"},
	{ .pc_name = "check", .pc_func = jt_llog_check,
	  .pc_help = "verify that log content is valid.\n"
	 "usage: llog_check {LOGNAME|FID} [--start INDEX] [--end INDEX]\n"
	 "       check all records from index 1 by default."},
	{ .pc_name = "remove", .pc_func = jt_llog_check,
	  .pc_help = "remove one log and erase it from disk.\n"
	 "usage: llog remove {LOGNAME|FID} [--log_id ID]"},
	{ .pc_help = NULL }
};
JT_SUBCMD(llog);

/**
 * command_t lfsck_cmdlist - lctl lfsck commands.
 */
command_t lfsck_cmdlist[] = {
	{ .pc_name = "start", .pc_func = jt_lfsck_start,
	  .pc_help = "Start online Lustre File System Check.\n"
	 "usage: lfsck start [--device|-M {MDT,OST}_DEVICE]\n"
	 "		     [--all|-A] [--create-ostobj|-c [on | off]]\n"
	 "		     [--create-mdtobj|-C [on | off]]\n"
	 "		     [--delay-create-ostobj|-d [on | off]]\n"
	 "		     [--error|-e {continue | abort}] [--help|-h]\n"
	 "		     [--dryrun|-n [on | off]] [--orphan|-o]\n"
	 "		     [--reset|-r] [--speed|-s SPEED_LIMIT]\n"
	 "		     [--type|-t {all|default|scrub|layout|namespace}]\n"
	 "		     [--window-size|-w SIZE]"},
	{ .pc_name = "stop", .pc_func = jt_lfsck_stop,
	  .pc_help = "Stop online Lustre File System Check.\n"
	 "usage: lfsck stop [--device|-M {MDT,OST}_DEVICE]\n"
	 "		    [--all|-A] [--help|-h]"},
	{ .pc_name = "query", .pc_func = jt_lfsck_query,
	  .pc_help = "Get Lustre File System Check global status.\n"
	 "usage: lfsck query [--device|-M MDT_DEVICE] [--help|-h]\n"
	 "		     [--type|-t {all|default|scrub|layout|namespace}]\n"
	 "		     [--wait|-w]"},
	{ .pc_help = NULL }
};
JT_SUBCMD(lfsck);
#endif

command_t cmdlist[] = {
	/* Metacommands */
	{"===== metacommands =======", NULL, 0, "metacommands"},
	{"--device", jt_opt_device, 0,
	 "run <command> after connecting to device <devno>\n"
	 "--device <devno> <command [args ...]>"},

	/* User interface commands */
	{"======== control =========", NULL, 0, "control commands"},
	{"lustre_build_version", jt_get_version, 0,
	 "print version of Lustre modules\n"
	 "usage: lustre_build_version"},

	/* Network configuration commands */
	{"===== network config =====", NULL, 0, "network config"},
	{"--net", jt_opt_net, 0, "run <command> after selecting network <net>\n"
	 "usage: --net <tcp/o2ib/...> <command>"},
	{"network", jt_ptl_network, 0, "configure LNET\n"
	 "usage: network [Network] <up|down> [-l]\n"
	 "  -l: Override existing, else it will create new\n"},
	{"net", jt_ptl_network, 0, "configure LNET\n"
	 "usage: net [Network] <up|down> [-l]\n"
	 "  -l: Override existing, else it will create new\n"},
	{"list_nids", jt_ptl_list_nids, 0, "list local NIDs\n"
	 "usage: list_nids [all]"},
	{"which_nid", jt_ptl_which_nid, 0, "choose a NID\n"
	 "usage: which_nid NID [NID...]"},
	{"replace_nids", jt_replace_nids, 0,
	 "replace primary NIDs for device (clients/servers must be unmounted)\n"
	 "usage: replace_nids <DEVICE> <NID1>[,NID2,NID3:NID4,NID5:NID6]"},
	{"interface_list", jt_ptl_print_interfaces, 0,
	 "print network interface entries\n"
	 "usage: interface_list"},
	{"peer_list", jt_ptl_print_peers, 0, "print peer LNet NIDs\n"
	 "usage: peer_list"},
	{"conn_list", jt_ptl_print_connections, 0,
	 "print all the remote LNet connections\n"
	 "usage: conn_list"},
	{"route_list", jt_ptl_print_routes, 0,
	 "print the LNet routing table, same as 'show_route'\n"
	 "usage: route_list"},
	{"show_route", jt_ptl_print_routes, 0,
	 "print the LNet routing table, same as 'route_list'\n"
	 "usage: show_route"},
	{"ping", jt_ptl_ping, 0, "Check LNET connectivity\n"
	 "usage: ping nid [timeout [pid]]"},

	{"net_drop_add", jt_ptl_drop_add, 0, "Add LNet drop rule\n"
	 "usage: net_drop_add {-s | --source NID}\n"
	 "		      {-d | --dest NID}\n"
	 "		      {{-r | --rate DROP_RATE} | {-i | --interval SECONDS}}\n"
	 "		      [-p | --portal PORTAL...]\n"
	 "		      [-m | --message {PUT|ACK|GET|REPLY...}]\n"
	 "		      [-e | --health_error]"},
	{"net_drop_del", jt_ptl_drop_del, 0, "remove LNet drop rule\n"
	 "usage: net_drop_del {-a | --all} |\n"
	 "		      {{-s | --source NID} {-d | --dest NID}}"},
	{"net_drop_reset", jt_ptl_drop_reset, 0, "reset drop rule stats\n"
	 "usage: net_drop_reset"},
	{"net_drop_list", jt_ptl_drop_list, 0, "list LNet drop rules\n"
	 "usage: net_drop_list"},
	{"net_drop", jt_net_drop, net_drop_cmdlist, ""},

	{"net_delay_add", jt_ptl_delay_add, 0, "Add LNet delay rule\n"
	 "usage: net_delay_add {-s | --source NID}\n"
	 "		       {-d | --dest NID}\n"
	 "		       {{-r | --rate DELAY_RATE} | {-i | --interval SECONDS}}\n"
	 "		       {-l | --latency SECONDS>\n"
	 "		       [-p | --portal PORTAL...]\n"
	 "		       [-m | --message {PUT|ACK|GET|REPLY...}]"},
	{"net_delay_del", jt_ptl_delay_del, 0, "remove LNet delay rule\n"
	 "usage: net_delay_del {-a | --all} |\n"
	 "		       {{-s | --source NID} {-d | --dest NID}}"},
	{"net_delay_reset", jt_ptl_delay_reset, 0, "reset delay rule stats\n"
	 "usage: net_delay_reset"},
	{"net_delay_list", jt_ptl_delay_list, 0, "list LNet delay rules\n"
	 "usage: net_delay_list"},
	{"net_delay", jt_net_delay, net_delay_cmdlist, ""},

	/* Device selection commands */
	{"==== obd device selection ====", NULL, 0, "device selection"},
	{"device", jt_obd_device, 0,
	 "set current device to <name|devno>\n"
	 "usage: device <%name|$name|devno>"},
	{"cfg_device", jt_obd_device, 0,
	 "set current device to <name>, same as 'device'\n"
	 "usage: cfg_device <name>"},
	{"device_list", jt_device_list, 0, "show all devices\n"
	 "usage: device_list [--target|-t] [--yaml|-y]"},
	{"dl", jt_device_list, 0, "show all devices, same as 'device_list'\n"
	 "usage: dl [--target|-t] [--yaml|-y]"},

	/* Device operations */
	{"==== obd device operations ====", NULL, 0, "device operations"},
	{"activate", jt_obd_activate, 0, "activate an import\n"},
	{"deactivate", jt_obd_deactivate, 0, "deactivate an import. "
	 "This command should be used on failed OSC devices in an MDT LOV.\n"},
	{"abort_recovery", jt_obd_abort_recovery, 0,
	 "abort recovery on a restarting MDT or OST device\n"},
	{"abort_recovery_mdt", jt_obd_abort_recovery_mdt, 0,
	 "abort recovery between MDTs\n"},
	{"recover", jt_obd_recover, 0,
	 "try to restore a lost connection immediately\n"
	 "usage: recover [MDC/OSC device]"},
#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(3, 0, 53, 0)
	{"conf_param", jt_lcfg_confparam, 0,
	 "set a permanent config parameter.\n"
	 "This command must be run on the MGS node\n"
	 "usage: conf_param [-d] <target.keyword=val>\n"
	 "  -d  Delete the permanent setting from the configuration."},
#endif
	{"get_param", jt_lcfg_getparam, 0, "get the Lustre or LNET parameter\n"
	 "usage: get_param [--classify|-F] [--header|-H] [--links|-l]\n"
	 "		   [--no-links|-L] [--no-name|-n] [--only-name|-N]\n"
	 "		   [--readable|-r] [--recursive|-R]\n"
	 "		   [--tunable|-t] [--writable|-w] [--yaml|-y]\n"
	 "		   <param_path1 param_path2 ...>\n"
	 "Get the value of Lustre or LNET parameter from the specified path.\n"
	 "The path can contain shell-style filename patterns.\n"},
	{"set_param", jt_lcfg_setparam, 0, "set the Lustre or LNET parameter\n"
	 "usage: set_param [--client|-C[FSNAME]] [--delete|-d] [--file|-F]\n"
	 "		   [--no-name|-n] [--permanent|-P]"
#ifdef HAVE_LIBPTHREAD
	 " [--thread|-t[THREAD_COUNT]]"
#endif
	 "\n"
	 "		   PARAM1=VALUE1 [PARAM2=VALUE2 ...]\n"
	 "Set the value of the Lustre or LNET parameter at the specified path.\n"},
	{"apply_yaml", jt_lcfg_applyyaml, 0, "set/config the Lustre or LNET "
	 "parameters using configuration from a YAML file.\n"
	 "usage: apply_yaml file\n"},
	{"list_param", jt_lcfg_listparam, 0,
	 "list the Lustre or LNET parameter name\n"
	 "usage: list_param [--dir-only|-D] [--classify|-F] [--links|-l]\n"
	 "		    [--no-links|-L] [--path|-p] [--readable|-r]\n"
	 "		    [--recursive|-R] [--tunable|-t] [--writable|-w]\n"
	 "		    <param_path1 param_path2 ...>\n"
	 "List the name of Lustre or LNet parameter from the specified path.\n"},
	{"del_ost", jt_del_ost, 0, "permanently delete OST records\n"
	 "usage: del_ost [--dryrun] --target <$fsname-OSTxxxx>\n"
	 "Cancel the config records for a specific OST to forget about it.\n"},

	/* Debug commands */
	{"==== debugging control ====", NULL, 0, "debug"},
	{"debug_daemon", jt_dbg_debug_daemon, 0,
	 "debug daemon control and dump to a file\n"
	 "usage: debug_daemon {start file [#MB]|stop}"},
	{"debug_kernel", jt_dbg_debug_kernel, 0,
	 "get debug buffer and dump to a file, same as 'dk'\n"
	 "usage: debug_kernel [file] [raw]"},
	{"dk", jt_dbg_debug_kernel, 0,
	 "get debug buffer and dump to a file, same as 'debug_kernel'\n"
	 "usage: dk [file] [raw]"},
	{"debug_file", jt_dbg_debug_file, 0,
	 "convert a binary debug file dumped by the kernel to ASCII text\n"
	 "usage: debug_file <input> [output]"},
	{"df", jt_dbg_debug_file, 0,
	 "read debug log from input convert to ASCII, same as 'debug_file'\n"
	 "usage: df <input> [output]"},
	{"clear", jt_dbg_clear_debug_buf, 0, "clear kernel debug buffer\n"
	 "usage: clear"},
	{"mark", jt_dbg_mark_debug_buf, 0,
	 "insert marker text in kernel debug buffer\n"
	 "usage: mark <text>"},
	{"filter", jt_dbg_filter, 0, "filter message type\n"
	 "usage: filter <subsystem id/debug mask>"},
	{"show", jt_dbg_show, 0, "Show specific type of messages\n"
	 "usage: show <subsystem id/debug mask>"},
	{"debug_list", jt_dbg_list, 0, "list subsystem and debug types\n"
	 "usage: debug_list <subs/types>"},
	{"modules", jt_dbg_modules, 0,
	 "provide gdb-friendly module information\n"
	 "usage: modules <path>"},

	/* Pool commands */
	{"===  Pools ==", NULL, 0, "pool management"},
	{"pool_new", jt_pool_cmd, 0,
	 "add a new pool\n"
	 "usage: pool_new [-n|--nowait] <fsname>.<poolname>"},
	{"pool_add", jt_pool_cmd, 0,
	 "add the named OSTs to the pool\n"
	 "usage: pool_add [-n|--nowait] <fsname>.<poolname> <ostname indexed list>"},
	{"pool_remove", jt_pool_cmd, 0,
	 "remove the named OST from the pool\n"
	 "usage: pool_remove [-n|--nowait] <fsname>.<poolname> <ostname indexed list>"},
	{"pool_destroy", jt_pool_cmd, 0,
	 "destroy a pool\n"
	 "usage: pool_destroy [-n|--nowait] <fsname>.<poolname>"},
	{"pool_list", jt_pool_cmd, 0,
	 "list pools and pools members\n"
	 "usage: pool_list  <fsname>[.<poolname>] | <pathname>"},

#ifdef HAVE_SERVER_SUPPORT
	/* Barrier commands */
	{"===  Barrier ==", NULL, 0, "barrier management"},
	{"barrier_freeze", jt_barrier_freeze, 0,
	 "freeze write barrier on MDTs\n"
	 "usage: barrier_freeze FSNAME [TIMEOUT_SECONDS]"},
	{"barrier_thaw", jt_barrier_thaw, 0,
	 "thaw write barrier on MDTs\n"
	 "usage: barrier_thaw FSNAME"},
	{"barrier_stat", jt_barrier_stat, 0,
	 "query write barrier status on MDTs\n"
	 "usage: barrier_stat [--state|-s] [--timeout|-t] FSNAME"},
	{"barrier_rescan", jt_barrier_rescan, 0,
	 "rescan the system to filter out inactive MDT(s) for barrier\n"
	 "usage: barrier_rescan FSNAME [TIMEOUT_SECONDS]"},
	{"barrier", jt_barrier, barrier_cmdlist, ""},

	/* Snapshot commands */
	{"===  Snapshot ==", NULL, 0, "Snapshot management"},
	{"snapshot_create", jt_snapshot_create, 0,
	 "create the snapshot\n"
	 "usage: snapshot_create [-b | --barrier [on | off]]\n"
	 "			 [-c | --comment COMMENT]\n"
	 "			 {-F | --fsname FSNAME}\n"
	 "			 [-h | --help] {-n | --name SSNAME}\n"
	 "			 [-r | --rsh REMOTE_SHELL]\n"
	 "			 [-t | --timeout TIMEOUT]"},
	{"snapshot_destroy", jt_snapshot_destroy, 0,
	 "destroy the snapshot\n"
	 "usage: snapshot_destroy [-f | --force]\n"
	 "			  {-F | --fsname FSNAME} [-h | --help]\n"
	 "			  {-n | --name SSNAME}\n"
	 "			  [-r | --rsh REMOTE_SHELL]"},
	{"snapshot_modify", jt_snapshot_modify, 0,
	 "modify the snapshot\n"
	 "usage: snapshot_modify [-c | --comment COMMENT]\n"
	 "			 {-F | --fsname FSNAME} [-h | --help]\n"
	 "			 {-n | --name SSNAME} [-N | --new NEW_SSNAME]\n"
	 "			 [-r | --rsh REMOTE_SHELL]"},
	{"snapshot_list", jt_snapshot_list, 0,
	 "query the snapshot(s)\n"
	 "usage: snapshot_list [-d | --detail]\n"
	 "		       {-F | --fsname FSNAME} [-h | --help]\n"
	 "		       [-n | --name SSNAME] [-r | --rsh REMOTE_SHELL]"},
	{"snapshot_mount", jt_snapshot_mount, 0,
	 "mount the snapshot\n"
	 "usage: snapshot_mount {-F | --fsname FSNAME} [-h | --help]\n"
	 "			{-n | --name SSNAME}\n"
	 "			[-r | --rsh REMOTE_SHELL]"},
	{"snapshot_umount", jt_snapshot_umount, 0,
	 "umount the snapshot\n"
	 "usage: snapshot_umount {-F | --fsname FSNAME} [-h | --help]\n"
	 "			 {-n | --name SSNAME}\n"
	 "			 [-r | --rsh REMOTE_SHELL]"},
	{"snapshot", jt_snapshot, snapshot_cmdlist, ""},
#endif /* HAVE_SERVER_SUPPORT */
	/* Nodemap commands */
	{"=== Nodemap ===", NULL, 0, "nodemap management"},
	{"nodemap_activate", jt_nodemap_activate, 0,
	 "activate nodemap idmapping functions\n"
	 "usage: nodemap_activate {0|1}"},
	{"nodemap_add", jt_nodemap_add, 0,
	 "add a new nodemap\n"
	 "usage: nodemap_add [-d|--dynamic] [-p|--parent PARENT_NAME] --name NODEMAP_NAME"},
	{"nodemap_del", jt_nodemap_del, 0,
	 "remove a nodemap\n"
	 "usage: nodemap_del --name NODEMAP_NAME"},
	{"nodemap_add_range", jt_nodemap_add_range, 0,
	 "add a nid range to a nodemap\n"
	 "usage: nodemap_add_range --name NODEMAP_NAME --range NID_RANGE"},
	{"nodemap_del_range", jt_nodemap_del_range, 0,
	 "delete a nid range from a nodemap\n"
	 "usage: nodemap_del_range --name NODEMAP_NAME --range NID_RANGE"},
	{"nodemap_modify", jt_nodemap_modify, 0,
	 "modify a nodemap property\n"
	 "usage: nodemap_modify --name NODEMAP_NAME --property PROPERTY_NAME{=VALUE| --value VALUE}\n"
	 "valid properties: admin trusted map_mode squash_uid squash_gid squash_projid deny_unknown audit_mode forbid_encryption readonly_mount rbac deny_mount child_raise_privileges"},
	{"nodemap_add_offset", jt_nodemap_add_offset, 0,
	 "add an offset for UID/GID/PROJID mappings\n"
	 "usage: nodemap_add_offset --name NODEMAP_NAME --offset OFFSET --limit LIMIT\n"},
	{"nodemap_del_offset", jt_nodemap_del_offset, 0,
	 "delete an offset for UID/GID/PROJID mappings\n"
	 "usage: nodemap_del_offset --name NODEMAP_NAME\n"},
	{"nodemap_add_idmap", jt_nodemap_add_idmap, 0,
	 "add a UID or GID mapping to a nodemap\n"
	 "usage: nodemap_add_idmap --name NODEMAP_NAME --idtype {uid|gid|projid} --idmap CLIENTID:FSID"},
	{"nodemap_del_idmap", jt_nodemap_del_idmap, 0,
	 "delete a UID or GID mapping from a nodemap\n"
	 "usage: nodemap_del_idmap --name NODEMAP_NAME --idtype {uid|gid|projid} --idmap CLIENTID:FSID"},
	{"nodemap_set_fileset", jt_nodemap_set_fileset, 0,
	 "set a fileset on a nodemap\n"
	 "usage: nodemap_set_fileset --name NODEMAP_NAME --fileset FILESET"},
	{"nodemap_set_sepol", jt_nodemap_set_sepol, 0,
	 "set SELinux policy info on a nodemap\n"
	 "usage: nodemap_set_sepol --name NODEMAP_NAME --sepol SEPOL"},
	{"nodemap_test_nid", jt_nodemap_test_nid, 0,
	 "test a nid for nodemap membership\n"
	 "usage: nodemap_test_nid --nid NID"},
	{"nodemap_test_id", jt_nodemap_test_id, 0,
	 "test a nodemap id pair for mapping\n"
	 "Usage: nodemap_test_id --nid NID --idtype ID_TYPE --id ID"},
	{"nodemap_info", jt_nodemap_info, 0,
	 "print nodemap information\n"
	 "Usage: nodemap_info [list|nodemap_name|all]"},
	{"nodemap", jt_nodemap, nodemap_cmdlist, ""},

	/* Changelog commands */
	{"===  Changelogs ==", NULL, 0, "changelog user management"},
	{"changelog_register", jt_changelog_register, 0,
	 "register a new persistent changelog user, returns id\n"
	 "usage: {--device MDTNAME} changelog_register [--help|-h]\n"
	 "					       [--mask|-m MASK]\n"
	 "					       [--nameonly|-n]\n"
	 "					       [--user|-u USERNAME]"},
	{"changelog_deregister", jt_changelog_deregister, 0,
	 "deregister an existing changelog user\n"
	 "usage: {--device MDTNAME} changelog_deregister [ID|clID]\n"
	 "						 [--help|-h]\n"
	 "						 [--user|-u USERNAME]"},
	{"changelog", jt_changelog, changelog_cmdlist, ""},

	/* Persistent Client Cache (PCC) commands */
	{"=== Persistent Client Cache ===", NULL, 0, "PCC user management"},
	{"pcc", jt_pcc, pcc_cmdlist,
	 "lctl commands used to interact with PCC features:\n"
	 "lctl pcc add    - add a PCC backend to a client\n"
	 "lctl pcc del    - delete a PCC backend on a client\n"
	 "lctl pcc clear  - remove all PCC backends on a client\n"
	 "lctl pcc list   - list all PCC backends on a client\n"},

	/* Device configuration commands */
	{"== device setup (these are not normally used post 1.4) ==",
		NULL, 0, "device config"},
	{"attach", jt_lcfg_attach, 0,
	 "set the type, name, and uuid of the current device\n"
	 "usage: attach type name uuid"},
	{"detach", jt_obd_detach, 0,
	 "remove driver (and name and uuid) from current device\n"
	 "usage: detach"},
	{"setup", jt_lcfg_setup, 0,
	 "type specific device configuration information\n"
	 "usage: setup <args...>"},
	{"cleanup", jt_obd_cleanup, 0, "cleanup previously setup device\n"
	 "usage: cleanup [force | failover]"},

#ifdef HAVE_SERVER_SUPPORT
	/* LFSCK commands */
	{"==== LFSCK ====", NULL, 0, "LFSCK"},
	{"lfsck_start", jt_lfsck_start, 0, "start LFSCK\n"
	 "usage: lfsck_start [--device|-M [MDT,OST]_device]\n"
	 "		     [--all|-A] [--create-ostobj|-c [on | off]]\n"
	 "		     [--create-mdtobj|-C [on | off]]\n"
	 "		     [--delay-create-ostobj|-d [on | off]]\n"
	 "		     [--error|-e {continue | abort}] [--help|-h]\n"
	 "		     [--dryrun|-n [on | off]] [--orphan|-o]\n"
	 "		     [--reset|-r] [--speed|-s speed_limit]\n"
	 "		     [--type|-t lfsck_type[,lfsck_type...]]\n"
	 "		     [--window-size|-w size]"},
	{"lfsck_stop", jt_lfsck_stop, 0, "stop lfsck(s)\n"
	 "usage: lfsck_stop [--device|-M [MDT,OST]_device]\n"
	 "		    [--all|-A] [--help|-h]"},
	{"lfsck_query", jt_lfsck_query, 0, "check lfsck(s) status\n"
	 "usage: lfsck_query [--device|-M MDT_device] [--help|-h]\n"
	 "		     [--type|-t lfsck_type[,lfsck_type...]]\n"
	 "		     [--wait|-w]"},
	{"lfsck", jt_lfsck, lfsck_cmdlist, ""},

	/* Llog operations */
	{"==== LLOG ====", NULL, 0, "LLOG"},
	{"llog_catlist", jt_llog_catlist, 0,
	 "list all catalog files on current device. If current device is not\n"
	 "set, MGS device is used by default.\n"
	 "usage: llog_catlist"},
	{"llog_info", jt_llog_info, 0,
	 "print log header information.\n"
	 "usage: llog_info {LOGNAME|FID}"},
	{"llog_print", jt_llog_print, 0,
	 "print all effective log records by default, or within given range.\n"
	 "With --raw option skipped records are printed as well.\n"
	 "usage: llog_print {LOGNAME|FID} [--start INDEX] [--end INDEX]\n"
	 "		    [--raw]"},
	{"llog_cancel", jt_llog_cancel, 0,
	 "cancel one record in specified log.\n"
	 "usage:llog_cancel {LOGNAME|FID} --log_idx INDEX"},
	{"llog_check", jt_llog_check, 0,
	 "verify that log content is valid.\n"
	 "usage: llog_check {LOGNAME|FID} [--start INDEX] [--end INDEX]\n"
	 "       check all records from index 1 by default."},
	{"llog_remove", jt_llog_remove, 0,
	 "remove one log from catalog or plain log, erase it from disk.\n"
	 "usage: llog_remove {LOGNAME|FID} [--log_id ID]"},
	{"llog", jt_llog, llog_cmdlist, ""},

	{"lcfg_clear", jt_lcfg_clear, 0,
	 "drop unused config llog records for a device or filesystem.\n"
	 "clients and servers must be unmounted during this operation.\n"
	 "usage: clear_conf {FSNAME|DEVNAME}"},
	{"clear_conf", jt_lcfg_clear, 0, "alias for 'lcfg_clear'\n"},
	{"lcfg_fork", jt_lcfg_fork, 0,
	 "copy configuration logs for named filesystem with given name\n"
	 "usage: fork_lcfg FSNAME NEWNAME"},
	{"fork_lcfg", jt_lcfg_fork, 0, "alias for 'lcfg_fork'\n"},
	{"lcfg_erase", jt_lcfg_erase, 0,
	 "permanently erase configuration logs for the named filesystem\n"
	 "usage: erase_lcfg FSNAME"},
	{"erase_lcfg", jt_lcfg_erase, 0, "alias for 'lcfg_erase'\n"},
#endif /* HAVE_SERVER_SUPPORT */

	{"==== obsolete (DANGEROUS) ====", NULL, 0, "obsolete (DANGEROUS)"},
	/* network operations */
	{"add_interface", jt_ptl_add_interface, 0, "add interface entry\n"
	 "usage: add_interface ip [netmask]"},
	{"del_interface", jt_ptl_del_interface, 0, "del interface entry\n"
	 "usage: del_interface [ip]"},
	{"add_route", jt_ptl_add_route, 0,
	 "add an entry to the LNet routing table\n"
	 "usage: add_route <gateway> [<hops> [<priority>]]"},
	{"del_route", jt_ptl_del_route, 0,
	 "delete route via gateway to targets from the LNet routing table\n"
	 "usage: del_route <gateway> [<target>] [<target>]"},
	{"set_route", jt_ptl_notify_router, 0,
	 "enable/disable routes via gateway in the LNet routing table\n"
	 "usage: set_route <gateway> <up/down> [<time>]"},

	/* Test only commands */
	{"==== testing (DANGEROUS) ====", NULL, 0, "testing (DANGEROUS)"},
	{"--threads", jt_opt_threads, 0,
	 "run <threads> separate instances of <command> on device <devno>\n"
	 "--threads <threads> <verbose> <devno> <command [args ...]>"},
	{"lookup", jt_obd_mdc_lookup, 0, "report file mode info\n"
	 "usage: lookup <directory> <file>"},
	{"readonly", jt_obd_set_readonly, 0,
	 "disable writes to the underlying device\n"},
#ifdef HAVE_SERVER_SUPPORT
	{"notransno", jt_obd_no_transno, 0,
	 "disable sending of committed-transno updates\n"},
#endif
	{"add_uuid", jt_lcfg_add_uuid, 0, "associate a UUID with a NID\n"
	 "usage: add_uuid <uuid> <nid>"},
	{"del_uuid", jt_lcfg_del_uuid, 0, "delete a UUID association\n"
	 "usage: del_uuid <uuid>"},
	{"add_peer", jt_ptl_add_peer, 0, "add an peer entry\n"
	 "usage: add_peer <nid> <host> <port>"},
	{"del_peer", jt_ptl_del_peer, 0, "remove an peer entry\n"
	 "usage: del_peer [<nid>] [<ipaddr|pid>]"},
	{"add_conn ", jt_lcfg_add_conn, 0,
	 "usage: add_conn <conn_uuid> [priority]\n"},
	{"del_conn ", jt_lcfg_del_conn, 0,
	 "usage: del_conn <conn_uuid>"},
	{"disconnect", jt_ptl_disconnect, 0, "disconnect from a remote NID\n"
	 "usage: disconnect [<nid>]"},
	{"push", jt_ptl_push_connection, 0, "flush connection to a remote NID\n"
	 "usage: push [<nid>]"},
	{"mynid", jt_ptl_mynid, 0, "inform the LND of the local NID. "
	 "The NID defaults to hostname for TCP networks.\n"
	 "usage: mynid [<nid>]"},
	{"fail", jt_ptl_fail_nid, 0, "fail/restore network communications\n"
	 "Omitting the count means indefinitely, 0 means restore, "
	 "otherwise fail 'count' messages.\n"
	 "usage: fail nid|_all_ [count]"},

	/* Test commands for echo client */
	{"test_create", jt_obd_test_create, 0,
	 "create files on MDT by echo client\n"
	 "usage: test_create [-d parent_basedir] <-D parent_count> "
	 "[-b child_base_id] <-c stripe_count> <-n count> <-t time>\n"},
	{"test_mkdir", jt_obd_test_mkdir, 0,
	 "mkdir on MDT by echo client\n"
	 "usage: test_mkdir [-d parent_basedir] <-D parent_count>"
	 "[-b child_base_id] [-n count] <-t time>\n"},
	{"test_destroy", jt_obd_test_destroy, 0,
	 "Destroy files on MDT by echo client\n"
	 "usage: test_destroy [-d parent_basedir] <-D parent_count>"
	 "[-b child_base_id] [-n count] <-t time>\n"},
	{"test_rmdir", jt_obd_test_rmdir, 0,
	 "rmdir on MDT by echo client\n"
	 "usage: test_rmdir [-d parent_basedir] <-D parent_count>"
	 "[-b child_base_id] [-n count] <-t time>\n"},
	{"test_lookup", jt_obd_test_lookup, 0,
	 "lookup files on MDT by echo client\n"
	 "usage: test_lookup [-d parent_basedir] <-D parent_count>"
	 "[-b child_base_id] [-n count] <-t time>\n"},
	{"test_setxattr", jt_obd_test_setxattr, 0,
	 "Set EA for files/directory on MDT by echo client\n"
	 "usage: test_setxattr [-d parent_baseid] <-D parent_count>"
	 "[-b child_base_id] [-n count] <-t time>\n"},
	{"test_md_getattr", jt_obd_test_md_getattr, 0,
	 "getattr files on MDT by echo client\n"
	 "usage: test_md_getattr [-d parent_basedir] <-D parent_count>"
	 "[-b child_base_id] [-n count] <-t time>\n"},
	{"getattr", jt_obd_getattr, 0,
	 "get attribute for OST object <objid>\n"
	 "usage: getattr <objid>"},
	{"setattr", jt_obd_setattr, 0,
	 "set mode attribute for OST object <objid>\n"
	 "usage: setattr <objid> <mode>"},
	{"create", jt_obd_create, 0,
	 "create <num> OST objects (with <mode>)\n"
	 "usage: create [num [mode [verbose [lsm data]]]]"},
	{"destroy", jt_obd_destroy, 0,
	 "destroy OST object <objid> [num [verbose]]\n"
	 "usage: destroy <num> objects, starting at objid <objid>"},
	{"test_getattr", jt_obd_test_getattr, 0,
	 "do <num> getattrs (on OST object <objid> (objid+1 on each thread))\n"
	 "usage: test_getattr <num> [verbose [[t]objid]]"},
	{"test_setattr", jt_obd_test_setattr, 0,
	 "do <num> setattrs (on OST object <objid> (objid+1 on each thread))\n"
	 "usage: test_setattr <num> [verbose [[t]objid]]"},
	{"test_brw", jt_obd_test_brw, 0,
	 "do <num> bulk read/writes (<npages> per I/O, on OST object <objid>)\n"
	 "usage: test_brw [t]<num> [write [verbose [npages [[t]objid]]]]"},
	{"getobjversion", jt_get_obj_version, 0,
	 "get the version of an object on servers\n"
	 "usage: getobjversion <fid>\n"
	 "	 getobjversion -i <id> -g <group>"},
	{ 0, 0, 0, NULL }
};

static int lctl_main(int argc, char **argv)
{
	int rc;

	setlinebuf(stdout);

	if (ptl_initialize(argc, argv) < 0)
		exit(1);
	if (obd_initialize(argc, argv) < 0)
		exit(2);
	if (dbg_initialize(argc, argv) < 0)
		exit(3);

	llapi_set_command_name(argv[1]);
	rc = cfs_parser(argc, argv, cmdlist);
	llapi_clear_command_name();
	obd_finalize(argc, argv);

	return rc < 0 ? -rc : rc;
}

int main(int argc, char **argv)
{
	return lctl_main(argc, argv);
}
