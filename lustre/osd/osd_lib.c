// SPDX-License-Identifier: GPL-2.0

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Shared helpers for the O/<seq>/d<N>/<oid> object directory layout.
 *
 * Several OSDs store OST objects in a local filesystem namespace
 * under O/<seq>/d<N>/ and cache the dentries of those directories in
 * struct osd_obj_map / struct osd_obj_seq (see lustre/include/osd.h).
 * The routines that manage that in-memory state are kept here so
 * they need not be duplicated in each OSD. There is no separate
 * module: each OSD includes this file through a small wrapper and
 * links its own copy, which keeps the OSDs independently loadable.
 */

#include <linux/types.h>
#include <linux/fs.h>

#include <obd_support.h>
#include <osd.h>

/**
 * Free an OSD sequence structure and its associated directories.
 *
 * @osd_seq: The sequence structure to free
 */
void osd_obj_seq_free(struct osd_obj_seq *osd_seq)
{
	int j;

	if (osd_seq->oos_dirs) {
		for (j = 0; j < osd_seq->oos_subdir_count; j++) {
			if (osd_seq->oos_dirs[j])
				dput(osd_seq->oos_dirs[j]);
		}
		OBD_FREE_PTR_ARRAY(osd_seq->oos_dirs,
				   osd_seq->oos_subdir_count);
	}

	if (osd_seq->oos_root)
		dput(osd_seq->oos_root);

	OBD_FREE_PTR(osd_seq);
}

/**
 * Free an OST object map and every sequence cached in it.
 *
 * @map: The object map to clean up
 */
void osd_obj_map_free(struct osd_obj_map *map)
{
	struct osd_obj_seq *osd_seq;
	struct osd_obj_seq *tmp;

	ENTRY;

	if (map == NULL)
		return;

	write_lock(&map->om_seq_list_lock);
	list_for_each_entry_safe(osd_seq, tmp, &map->om_seq_list,
				 oos_seq_list) {
		list_del_init(&osd_seq->oos_seq_list);
		write_unlock(&map->om_seq_list_lock);
		osd_obj_seq_free(osd_seq);
		write_lock(&map->om_seq_list_lock);
	}
	write_unlock(&map->om_seq_list_lock);
	if (map->om_root)
		dput(map->om_root);
	OBD_FREE_PTR(map);
	EXIT;
}

/**
 * Find a sequence in the object map (caller must hold lock).
 *
 * @map: The object map to search
 * @seq: The sequence number to find
 *
 * Return: The sequence structure if found, NULL otherwise
 */
struct osd_obj_seq *osd_obj_seq_find_locked(struct osd_obj_map *map, u64 seq)
{
	struct osd_obj_seq *osd_seq;

	list_for_each_entry(osd_seq, &map->om_seq_list, oos_seq_list) {
		if (osd_seq->oos_seq == seq)
			return osd_seq;
	}
	return NULL;
}

/**
 * Find a sequence in the object map (with locking).
 *
 * @map: The object map to search
 * @seq: The sequence number to find
 *
 * Return: The sequence structure if found, NULL otherwise
 */
struct osd_obj_seq *osd_obj_seq_find(struct osd_obj_map *map, u64 seq)
{
	struct osd_obj_seq *osd_seq;

	read_lock(&map->om_seq_list_lock);
	osd_seq = osd_obj_seq_find_locked(map, seq);
	read_unlock(&map->om_seq_list_lock);
	return osd_seq;
}

/**
 * Generate the sequence directory name.
 *
 * Use %llu for legacy OST sequences, but use %llx for new
 * sequences names, so that the O/{seq}/dN/{oid} more closely
 * follows the DFID/PFID format. This makes it easier to map from
 * debug messages to objects in the future, and the legacy space
 * of FID_SEQ_OST_MDT0 will be unused in the future.
 *
 * @seq_name: Output buffer for the sequence name
 * @name_size: Size of the output buffer
 * @seq: The sequence number
 */
void osd_obj_seq_name(char *seq_name, size_t name_size, u64 seq)
{
	snprintf(seq_name, name_size,
		 (fid_seq_is_rsvd(seq) ||
		  fid_seq_is_mdt0(seq)) ? "%llu" : "%llx",
		 fid_seq_is_idif(seq) ? 0 : seq);
}
