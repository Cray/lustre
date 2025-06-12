/* SPDX-License-Identifier: LGPL-2.1+ WITH Linux-syscall-note */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#ifndef _LUSTRE_VER_H_
#define _LUSTRE_VER_H_

/*
 * LUSTRE_VERSION_STRING
 *
 * Note that some files may seem to include this header unnecessarily.
 * If the file uses LUSTRE_VERSION_STRING, it is likely doing the include
 * for compatibility with the Lustre code in the Linux kernel.
 * In the Linux kernel, they are likely hard coding LUSTRE_VERSION_STRING
 * right here in this file.  The out-of-kernel Lustre code generates
 * LUSTRE_VERSION_STRING in autoconf with AC_DEFINE.
 */

#define OBD_OCD_VERSION(major, minor, patch, fix)			\
	(((major) << 24) + ((minor) << 16) + ((patch) << 8) + (fix))

#define OBD_OCD_VERSION_MAJOR(version)	((int)((version) >> 24) & 255)
#define OBD_OCD_VERSION_MINOR(version)	((int)((version) >> 16) & 255)
#define OBD_OCD_VERSION_PATCH(version)	((int)((version) >>  8) & 255)
#define OBD_OCD_VERSION_FIX(version)	((int)((version) >>  0) & 255)

#define LUSTRE_VERSION_CODE						\
	OBD_OCD_VERSION(LUSTRE_MAJOR, LUSTRE_MINOR, LUSTRE_PATCH, LUSTRE_FIX)

/* If lustre version of client and servers it connects to differs by more
 * than this amount, client would issue a warning.
 * (set in lustre/autoconf/lustre-version.ac)
 */
#define LUSTRE_VERSION_OFFSET_WARN OBD_OCD_VERSION(0, 4, 50, 0)

#endif
