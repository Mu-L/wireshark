/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef SYNTAX_TREE_H
#define SYNTAX_TREE_H

#include <glib.h>
#include "cppmagic.h"

/** @file
 */

typedef enum {
	STTYPE_UNINITIALIZED,
	STTYPE_TEST,
	STTYPE_UNPARSED,
	STTYPE_STRING,
	STTYPE_CHARCONST,
	STTYPE_FIELD,
	STTYPE_FVALUE,
	STTYPE_INTEGER,
	STTYPE_RANGE,
	STTYPE_FUNCTION,
	STTYPE_SET,
	STTYPE_PCRE,
	STTYPE_NUM_TYPES
} sttype_id_t;

typedef gpointer        (*STTypeNewFunc)(gpointer);
typedef gpointer        (*STTypeDupFunc)(gconstpointer);
typedef void            (*STTypeFreeFunc)(gpointer);


/* Type information */
typedef struct {
	sttype_id_t		id;
	const char		*name;
	STTypeNewFunc		func_new;
	STTypeFreeFunc		func_free;
	STTypeDupFunc		func_dup;
} sttype_t;

/** Node (type instance) information */
typedef struct {
	guint32		magic;
	sttype_t	*type;

	/* This could be made an enum, but I haven't
	 * set aside to time to do so. */
	gpointer	data;
	gint32		value;
	gboolean	inside_brackets;
	const char	*deprecated_token;
} stnode_t;

/* These are the sttype_t registration function prototypes. */
void sttype_register_function(void);
void sttype_register_integer(void);
void sttype_register_pointer(void);
void sttype_register_range(void);
void sttype_register_set(void);
void sttype_register_string(void);
void sttype_register_test(void);

void
sttype_init(void);

void
sttype_cleanup(void);

void
sttype_register(sttype_t *type);

stnode_t*
stnode_new(sttype_id_t type_id, gpointer data);

void
stnode_set_bracket(stnode_t *node, gboolean bracket);

stnode_t*
stnode_dup(const stnode_t *org);

void
stnode_init(stnode_t *node, sttype_id_t type_id, gpointer data);

void
stnode_init_int(stnode_t *node, sttype_id_t type_id, gint32 value);

void
stnode_free(stnode_t *node);

const char*
stnode_type_name(stnode_t *node);

sttype_id_t
stnode_type_id(stnode_t *node);

gpointer
stnode_data(stnode_t *node);

gpointer
stnode_steal_data(stnode_t *node);

gint32
stnode_value(stnode_t *node);

const char *
stnode_deprecated(stnode_t *node);

#define assert_magic(obj, mnum) \
	g_assert_true((obj)); \
	if ((obj)->magic != (mnum)) { \
		g_print("\nMagic num is 0x%08x, but should be 0x%08x", \
			(obj)->magic, (mnum)); \
			g_assert_true((obj)->magic == (mnum)); \
	}

#ifdef WS_DEBUG
#define ws_assert_magic(obj, mnum) assert_magic(obj, mnum)
#else
#define ws_assert_magic(obj, mnum)
#endif

#define STTYPE_ACCESSOR(ret,type,attr,magicnum) \
	ret \
	CONCAT(CONCAT(CONCAT(sttype_,type),_),attr) (stnode_t *node) \
{\
	CONCAT(type,_t)	*value; \
	value = (CONCAT(type,_t) *)stnode_data(node);\
	ws_assert_magic(value, magicnum); \
	return value->attr; \
}

#define STTYPE_ACCESSOR_PROTOTYPE(ret,type,attr) \
	ret \
	CONCAT(CONCAT(CONCAT(sttype_,type),_),attr) (stnode_t *node);


#endif
