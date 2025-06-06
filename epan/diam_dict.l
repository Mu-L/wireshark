%top {
/* Include this before everything else, for various large-file definitions */
#include "config.h"
#include <wireshark.h>
}

/*
 * We want a reentrant scanner.
 */
%option reentrant

/*
 * We don't use input, so don't generate code for it.
 */
%option noinput

/*
 * We don't use unput, so don't generate code for it.
 */
%option nounput

/*
 * We don't read interactively from the terminal.
 */
%option never-interactive

/*
 * The language we're scanning is case-insensitive.
 */
%option caseless

/*
 * We use start condition stacks.
 */
%option stack

/*
 * We want to stop processing when we get to the end of the input.
 */
%option noyywrap

/*
 * The type for the state we keep for a scanner.
 */
%option extra-type="DiamDict_scanner_state_t *"

/*
 * Prefix scanner routines with "DiamDict_" rather than "yy", so this scanner
 * can coexist with other scanners.
 */
%option prefix="DiamDict_"

/*
 * We have to override the memory allocators so that we don't get
 * "unused argument" warnings from the yyscanner argument (which
 * we don't use, as we have a global memory allocator).
 *
 * We provide, as macros, our own versions of the routines generated by Flex,
 * which just call malloc()/realloc()/free() (as the Flex versions do),
 * discarding the extra argument.
 */
%option noyyalloc
%option noyyrealloc
%option noyyfree

%{
	/*
	 ** diam_dict.h
	 ** Diameter Dictionary Import Routines
	 **
	 ** (c) 2007, Luis E. Garcia Ontanon <luis@ontanon.org>
	 **
	 ** SPDX-License-Identifier: LGPL-2.0-or-later
	 **
	 ** See draft-frascone-xml-dictionary for the syntax of the
	 ** dictionary.
	 */

#include <glib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include "diam_dict.h"
#include <epan/to_str.h>
#include <wsutil/file_util.h>

/*
 * Disable diagnostics in the code generated by Flex.
 */
DIAG_OFF_FLEX()

typedef struct entity_t {
	char* name;
	char* file;
	struct entity_t* next;
} entity_t;

#define ATTR_UINT(cont) do { D(("attr_uint " #cont "\t" )); yyextra->attr_uint = &(cont); yy_push_state(GET_UINT_ATTR, yyscanner); } while(0)
#define ATTR_STR(cont) do { D(("attr_str " #cont "\t" )); yyextra->attr_str = &(cont); yy_push_state(GET_ATTR, yyscanner); } while(0)
#define IGNORE() do { D(("ignore: %s\t",yytext)); yy_push_state(IGNORE_ATTR, yyscanner); } while(0)

#define D(args) ddict_debug args

#define MAX_INCLUDE_DEPTH 10
#define YY_INPUT(buf,result,max_size) { result = yyextra->current_yyinput(buf,max_size,yyscanner); }
#define YY_USER_INIT { \
	DiamDict_scanner_state_t *scanner_state = DiamDict_get_extra(yyscanner); \
	BEGIN(scanner_state->start_state); \
}
#define ECHO
#define APPEND(txt,len) append_to_buffer(txt,len,yyextra)

typedef struct {
	const char* sys_dir;

	char* write_ptr;
	char* read_ptr;

	char* strbuf;
	unsigned size_strbuf;
	unsigned len_strbuf;

	ddict_t* dict;

	ddict_application_t* appl;
	ddict_avp_t* avp;
	ddict_enum_t* enumitem;
	ddict_gavp_t* gavp;
	ddict_typedefn_t* typedefn;
	ddict_cmd_t* cmd;
	ddict_vendor_t* vnd;
	ddict_xmlpi_t* xmlpi;

	ddict_application_t* last_appl;
	ddict_avp_t* last_avp;
	ddict_enum_t* last_enumitem;
	ddict_gavp_t* last_gavp;
	ddict_typedefn_t* last_typedefn;
	ddict_cmd_t* last_cmd;
	ddict_vendor_t* last_vnd;
	ddict_xmlpi_t* last_xmlpi;

	entity_t *ents;

	char** attr_str;
	unsigned* attr_uint;

	size_t (*current_yyinput)(char*,size_t,yyscan_t);
	int (*current_close)(FILE *fh);

	YY_BUFFER_STATE include_stack[MAX_INCLUDE_DEPTH];
	int include_stack_ptr;

	int start_state;
} DiamDict_scanner_state_t;

static void ddict_debug(const char* fmt, ...) G_GNUC_PRINTF(1, 2);
static void append_to_buffer(const char* txt, unsigned len, DiamDict_scanner_state_t *statep);
static FILE* ddict_open(const char*, const char*);

/*
 * Sleazy hack to suppress compiler warnings in yy_fatal_error().
 */
#define YY_EXIT_FAILURE ((void)yyscanner, 2)

/*
 * Macros for the allocators, to discard the extra argument.
 */
#define DiamDict_alloc(size, yyscanner)		(void *)malloc(size)
#define DiamDict_realloc(ptr, size, yyscanner)	(void *)realloc((char *)(ptr), (size))
#define DiamDict_free(ptr, yyscanner)		free((char *)ptr)

%}


xmlpi_start [[:blank:] \r\n]*<\?[[:blank:] \r\n]*
xmlpi_end [[:blank:] \r\n]*\?>[[:blank:] \r\n]*
xmlpi_key_attr [[:blank:] \r\n]*key[[:blank:] \r\n]*=[[:blank:] \r\n]*\042
xmlpi_value_attr [[:blank:] \r\n]*value[[:blank:] \r\n]*=[[:blank:] \r\n]*\042

comment_start [[:blank:] \r\n]*<!--[[:blank:] \r\n]*
comment_end [[:blank:] \r\n]*-->[[:blank:] \r\n]*
open_tag [[:blank:] \r\n]*<[[:blank:] \r\n]*
end_tag [[:blank:] \r\n]*\/>[[:blank:] \r\n]*
close_tag [[:blank:] \r\n]*>[[:blank:] \r\n]*
open_closetag [[:blank:] \r\n]*<\/[[:blank:] \r\n]*
equals [[:blank:] \r\n]*=[[:blank:] \r\n]*
whitespace [[:blank:] \r\n]*
dquoted \042[^\042]*\042

doctype [[:blank:] \r\n]*<!DOCTYPE[^\[]*\[[[:blank:] \r\n]*
doctype_end [[:blank:] \r\n]*\][[:blank:] \r\n]*>[[:blank:] \r\n]*

start_entity [[:blank:] \r\n]*<\!ENTITY[[:blank:] \r\n]*
system [[:blank:] \r\n]*SYSTEM[[:blank:] \r\n]*\042
entityname [a-z0-9-]+
ndquot [^\042]+
end_entity \042[[:blank:] \r\n]*>[[:blank:] \r\n]*

entity \&[a-z0-9-]+;

any .




stop >
stop_end \/>
dquot \042
number [-]?[0-9]*

dictionary_start <dictionary>
dictionary_end <\/dictionary>

base_start <base[^>*]*>
base_end <\/base>

application_start <application
application_end<\/application>

command_start <command
command_end<\/command>

typedefn_start <typedefn

avp_start <avp
avp_end <\/avp>

type_start <type
enum_start <enum

grouped_start <grouped>
grouped_end <\/grouped>

vendor_start <vendor
vendor_end<\/vendor>

gavp_start <gavp

ignored_attr [a-z0-9-]+=
ignored_quoted \042[^\042]*\042

name_attr name=\042
id_attr id=\042
code_attr code=\042
vendor_attr vendor-id=\042
typename_attr type-name=\042
typeparent_attr type-parent=\042
description_attr description=\042



%S LOADING LOADING_COMMENT LOADING_XMLPI ENTITY GET_SYSTEM GET_FILE END_ENTITY
%S GET_ATTR GET_UINT_ATTR END_ATTR OUTSIDE IN_DICT IN_APPL IN_AVP APPL_ATTRS IGNORE_ATTR
%S TYPE_ATTRS GAVP_ATTRS ENUM_ATTRS AVP_ATTRS VENDOR_ATTRS COMMAND_ATTRS TYPEDEFN_ATTRS
%S XMLPI_ATTRS XMLPI_GETKEY XMLPI_GETVAL XMLPI_ENDATTR
%%
<LOADING>{doctype} ;
<LOADING>{doctype_end} ;

<LOADING>{comment_start} BEGIN LOADING_COMMENT;
<LOADING_COMMENT>. ;
<LOADING_COMMENT>{comment_end} BEGIN LOADING;

<LOADING>{xmlpi_start} BEGIN LOADING_XMLPI;
<LOADING_XMLPI>{whitespace} ;
<LOADING_XMLPI>{entityname} {
	yyextra->xmlpi = g_new(ddict_xmlpi_t,1);
	yyextra->xmlpi->name = g_strdup(yytext);
	yyextra->xmlpi->key = NULL;
	yyextra->xmlpi->value = NULL;
	yyextra->xmlpi->next = NULL;

	if (!yyextra->dict->xmlpis)
		yyextra->last_xmlpi = yyextra->dict->xmlpis = yyextra->xmlpi;
	else
		yyextra->last_xmlpi = yyextra->last_xmlpi->next = yyextra->xmlpi;

	BEGIN XMLPI_ATTRS;
}

<XMLPI_ATTRS>{xmlpi_key_attr} BEGIN XMLPI_GETKEY;
<XMLPI_GETKEY>{ndquot} { yyextra->xmlpi->key = g_strdup(yytext); BEGIN XMLPI_ATTRS; }

<XMLPI_ATTRS>{xmlpi_value_attr} BEGIN XMLPI_GETVAL;
<XMLPI_GETVAL>{ndquot} { yyextra->xmlpi->value = g_strdup(yytext); BEGIN XMLPI_ATTRS; }

<XMLPI_ATTRS>.
<XMLPI_ATTRS>{xmlpi_end} BEGIN LOADING;


<LOADING>{start_entity} BEGIN ENTITY;
<ENTITY>{entityname} {
	entity_t* e = g_new(entity_t,1);
	e->name = g_strdup(yytext);
	e->next = yyextra->ents;
	yyextra->ents = e;
	BEGIN GET_SYSTEM;
	};
<GET_SYSTEM>{system} BEGIN GET_FILE;
<GET_FILE>{ndquot} {
		yyextra->ents->file = g_strdup(yytext);
		BEGIN END_ENTITY;
	}
<END_ENTITY>{end_entity} BEGIN LOADING;

<LOADING>{open_tag} APPEND("<",1);

<LOADING>{close_tag} APPEND(">",1);

<LOADING>{end_tag} APPEND("/>",2);

<LOADING>{open_closetag} APPEND("</",2);

<LOADING>{whitespace} APPEND(" ",1);

<LOADING>{dquoted} APPEND(yytext, (unsigned) yyleng);

<LOADING>{equals} APPEND("=",1);

<LOADING>{any} APPEND(yytext, (unsigned) yyleng);

<LOADING>{entity} {
	char* p = ++yytext;
	entity_t* e;

	while(*p != ';') p++;

	*p = '\0';

	D(("looking for entity: %s\n",yytext));

	if ( yyextra->include_stack_ptr >= MAX_INCLUDE_DEPTH ) {
		fprintf(stderr, "included files nested to deeply\n");
		yyterminate();
	}

	for (e = yyextra->ents; e; e = e->next) {
		if (strcmp(e->name,yytext) == 0) {
			yyin = ddict_open(yyextra->sys_dir,e->file);
			D(("entity: %s filename: %s yyin: %p\n",e->name,e->file,(void*)yyin));
			if (!yyin) {
				if (errno)
					fprintf(stderr, "Could not open file: '%s', error: %s\n", e->file, g_strerror(errno) );
				else
					fprintf(stderr, "Could not open file: '%s', error unknown (errno == 0)\n", e->file );
				yyterminate();
			} else {
				yyextra->include_stack[yyextra->include_stack_ptr++] = YY_CURRENT_BUFFER;
				yy_switch_to_buffer(yy_create_buffer(yyin, YY_BUF_SIZE, yyscanner), yyscanner);
				BEGIN LOADING;
			}
			break;
		}
	}

	if (!e) {
		fprintf(stderr, "Could not find entity: '%s'\n", yytext );
		yyterminate();
	}

}

<<EOF>> {
	if (!yyin) yyterminate();

	yyextra->current_close(yyin);
	D(("closing: %p %i\n",(void*)yyin,yyextra->include_stack_ptr));

	if ( --yyextra->include_stack_ptr < 0 ) {
		D(("DONE READING\n"));
		yyin = NULL;
		yyterminate();
	} else {
		yy_delete_buffer( YY_CURRENT_BUFFER, yyscanner);
		yy_switch_to_buffer(yyextra->include_stack[yyextra->include_stack_ptr], yyscanner);
		BEGIN LOADING;
	}
}


<GET_ATTR>{ndquot} {
	*(yyextra->attr_str) = g_strdup(yytext);
	D(("%s\n",yytext));
	yyextra->attr_str = NULL;
	BEGIN END_ATTR;
}

<GET_UINT_ATTR>{number} {
	*(yyextra->attr_uint) = (unsigned) strtoul(yytext,NULL,10);
	D(("%s\n",yytext););
	yyextra->attr_uint = NULL;
	BEGIN END_ATTR;
}

<END_ATTR>{dquot} {	yy_pop_state(yyscanner); }

<IGNORE_ATTR>. {
	/* XXX: should go?*/
	D(("{%s}",yytext));
}

<IGNORE_ATTR>{ignored_quoted} {
	D(("=>%s<=\n",yytext));
	yy_pop_state(yyscanner);
}

<OUTSIDE>{dictionary_start} {
	D(("dictionary_start\n"));

	BEGIN IN_DICT;
}

<IN_DICT>{base_start} {
	D(("base_start\n"));
	BEGIN IN_APPL;
}

<IN_DICT>{application_start} {
	D(("application_start\n"));

	yyextra->appl = g_new(ddict_application_t,1);
	yyextra->appl->name = NULL;
	yyextra->appl->code = 0;
	yyextra->appl->next = NULL;

	if (!yyextra->dict->applications)
		yyextra->last_appl = yyextra->dict->applications = yyextra->appl;
	else
		yyextra->last_appl = yyextra->last_appl->next = yyextra->appl;

	BEGIN APPL_ATTRS;
}

<APPL_ATTRS>{name_attr} { ATTR_STR(yyextra->appl->name); }
<APPL_ATTRS>{id_attr} { ATTR_UINT(yyextra->appl->code); }

<APPL_ATTRS>{stop} BEGIN IN_APPL;
<APPL_ATTRS>{stop_end} BEGIN IN_DICT;

<IN_APPL>{command_end}			;

<IN_APPL>{command_start}		{
	D(("command_start\n"));

	yyextra->cmd = g_new(ddict_cmd_t,1);
	yyextra->cmd->name = NULL;
	yyextra->cmd->vendor = NULL;
	yyextra->cmd->code = 0;
	yyextra->cmd->next = NULL;

	if (!yyextra->dict->cmds)
		yyextra->last_cmd = yyextra->dict->cmds = yyextra->cmd;
	else
		yyextra->last_cmd = yyextra->last_cmd->next = yyextra->cmd;

	BEGIN COMMAND_ATTRS;
}

<COMMAND_ATTRS>{name_attr}		{ ATTR_STR(yyextra->cmd->name); }
<COMMAND_ATTRS>{vendor_attr}		{ ATTR_STR(yyextra->cmd->vendor); }
<COMMAND_ATTRS>{code_attr}		{ ATTR_UINT(yyextra->cmd->code); }
<COMMAND_ATTRS>{stop}			|
<COMMAND_ATTRS>{stop_end}		{ BEGIN IN_APPL; }

<IN_DICT>{vendor_start} {
	D(("vendor_start\n"));

	yyextra->vnd = g_new(ddict_vendor_t,1);
	yyextra->vnd->name = NULL;
	yyextra->vnd->code = 0;
	yyextra->vnd->next = NULL;

	if (!yyextra->dict->vendors)
		yyextra->last_vnd = yyextra->dict->vendors = yyextra->vnd;
	else
		yyextra->last_vnd = yyextra->last_vnd->next = yyextra->vnd;

	BEGIN VENDOR_ATTRS;
}

<VENDOR_ATTRS>{name_attr}		{ ATTR_STR(yyextra->vnd->desc); }
<VENDOR_ATTRS>{vendor_attr}		{ ATTR_STR(yyextra->vnd->name); }
<VENDOR_ATTRS>{code_attr}		{ ATTR_UINT(yyextra->vnd->code); }
<VENDOR_ATTRS>{stop}			{ BEGIN IN_APPL; }
<VENDOR_ATTRS>{stop_end}		{ BEGIN IN_DICT; }

<IN_APPL>{typedefn_start} {
	D(("typedefn_start\n"));

	yyextra->typedefn = g_new(ddict_typedefn_t,1);
	yyextra->typedefn->name = NULL;
	yyextra->typedefn->parent = NULL;
	yyextra->typedefn->next = NULL;

	if (!yyextra->dict->typedefns)
		yyextra->last_typedefn = yyextra->dict->typedefns = yyextra->typedefn;
	else
		yyextra->last_typedefn = yyextra->last_typedefn->next = yyextra->typedefn;

	BEGIN TYPEDEFN_ATTRS;
}

<TYPEDEFN_ATTRS>{typename_attr}		{ ATTR_STR(yyextra->typedefn->name); }
<TYPEDEFN_ATTRS>{typeparent_attr}	{ ATTR_STR(yyextra->typedefn->parent); }
<TYPEDEFN_ATTRS>{stop}			|
<TYPEDEFN_ATTRS>{stop_end}		{ BEGIN IN_APPL; }


<IN_APPL>{avp_start}	{
	D(("avp_start\n"));

	yyextra->avp = g_new(ddict_avp_t,1);
	yyextra->avp->name = NULL;
	yyextra->avp->description = NULL;
	yyextra->avp->vendor = NULL;
	yyextra->avp->code = 0;
	yyextra->avp->type = NULL;
	yyextra->avp->enums = NULL;
	yyextra->avp->gavps = NULL;
	yyextra->avp->next = NULL;

	if (! yyextra->dict->avps )
		yyextra->last_avp = yyextra->dict->avps = yyextra->avp;
	else
		yyextra->last_avp = yyextra->last_avp->next = yyextra->avp;

	BEGIN AVP_ATTRS;
}

<AVP_ATTRS>{name_attr}			{ ATTR_STR(yyextra->avp->name); }
<AVP_ATTRS>{description_attr}		{ ATTR_STR(yyextra->avp->description); }
<AVP_ATTRS>{vendor_attr}		{ ATTR_STR(yyextra->avp->vendor); }
<AVP_ATTRS>{code_attr}			{ ATTR_UINT(yyextra->avp->code); }
<AVP_ATTRS>{stop}			{ BEGIN IN_AVP;  }
<AVP_ATTRS>{stop_end}			{ BEGIN IN_APPL; }


<IN_AVP>{grouped_start} { yyextra->avp->type = g_strdup("Grouped"); };
<IN_AVP>{grouped_end} ;

<IN_AVP>{type_start} { BEGIN TYPE_ATTRS; }
<TYPE_ATTRS>{typename_attr}			{ ATTR_STR(yyextra->avp->type); }

<IN_AVP>{gavp_start} {
	D(("gavp_start\n"));

	yyextra->gavp = g_new(ddict_gavp_t,1);
	yyextra->gavp->name = NULL;
	yyextra->gavp->code = 0;
	yyextra->gavp->next = NULL;

	if (!yyextra->avp->gavps)
		yyextra->last_gavp = yyextra->avp->gavps = yyextra->gavp;
	else
		yyextra->last_gavp = yyextra->last_gavp->next = yyextra->gavp;

	BEGIN GAVP_ATTRS;
}


<GAVP_ATTRS>{name_attr}			{ ATTR_STR(yyextra->gavp->name); }


<IN_AVP>{enum_start} {
	D(("enum_start\n"));

	yyextra->enumitem = g_new(ddict_enum_t,1);
	yyextra->enumitem->name = NULL;
	yyextra->enumitem->code = 0;
	yyextra->enumitem->next = NULL;

	if (!yyextra->avp->enums)
		yyextra->last_enumitem = yyextra->avp->enums = yyextra->enumitem;
	else
		yyextra->last_enumitem = yyextra->last_enumitem->next = yyextra->enumitem;

	BEGIN ENUM_ATTRS;
}


<ENUM_ATTRS>{name_attr}			{ ATTR_STR(yyextra->enumitem->name); }
<ENUM_ATTRS>{code_attr}			{ ATTR_UINT(yyextra->enumitem->code); }

<TYPE_ATTRS,GAVP_ATTRS,ENUM_ATTRS>{stop}		{ BEGIN IN_AVP; }
<TYPE_ATTRS,GAVP_ATTRS,ENUM_ATTRS>{stop_end}		{ BEGIN IN_AVP; }

<IN_AVP>{avp_end} { D(("avp_end\n")); BEGIN IN_APPL; }

<IN_APPL>{application_end} {
	D(("application_end\n")); BEGIN IN_DICT;
}
<IN_APPL>{stop_end} {
	D(("application_stop_end\n")); BEGIN IN_DICT;
}
<IN_APPL>{vendor_end} {
	D(("vendor_end\n")); BEGIN IN_DICT;
}
<IN_APPL>{base_end} {
	D(("base_end\n")); BEGIN IN_DICT;
}

<IN_DICT>{dictionary_end} {
	yyterminate();
}

<AVP_ATTRS,ENUM_ATTRS,GAVP_ATTRS,TYPE_ATTRS,TYPEDEFN_ATTRS,VENDOR_ATTRS,APPL_ATTRS,COMMAND_ATTRS>{ignored_attr} IGNORE();

<OUTSIDE>. ;

%%

/*
 * Turn diagnostics back on, so we check the code that we've written.
 */
DIAG_ON_FLEX()

static int debugging  = 0;

static void ddict_debug(const char* fmt, ...) {
	va_list ap;

	va_start(ap, fmt);
	if (debugging) vfprintf(stderr, fmt, ap);
	va_end(ap);

	fflush(stderr);
}

/*
 * Sleazy hack to avoid unused function warnings for yy_top_state.
 */
extern void ddict_unused(yyscan_t yyscanner);

void
ddict_unused(yyscan_t yyscanner)
{
	yy_top_state(yyscanner);
}

static void
append_to_buffer(const char* txt, unsigned len, DiamDict_scanner_state_t *statep)
{

	if (statep->strbuf == NULL) {
		statep->strbuf = (char*)g_malloc(statep->size_strbuf);
		statep->read_ptr = statep->strbuf;
		statep->write_ptr = statep->strbuf;
	}

	if (statep->len_strbuf + len >= statep->size_strbuf) {
		statep->strbuf = (char*)g_realloc(statep->strbuf,statep->size_strbuf *= 2);
		statep->read_ptr = statep->strbuf;
	}

	statep->write_ptr = statep->strbuf + statep->len_strbuf;
	memcpy(statep->write_ptr, txt, len + 1);
	statep->len_strbuf += len;
}

static size_t
file_input(char* buf, size_t max, yyscan_t scanner)
{
	FILE *in = yyget_in(scanner);
	size_t read_cnt;

	read_cnt = fread(buf,1,max,in);

	if ( read_cnt == max ) {
		return max;
	} else if (read_cnt > 0) {
		return read_cnt;
	} else {
		return YY_NULL;
	}
}


static size_t
string_input(char* buf, size_t max, yyscan_t scanner)
{
	DiamDict_scanner_state_t *statep = yyget_extra(scanner);

	if (statep->read_ptr >= statep->write_ptr ) {
		return YY_NULL;
	} else if ( statep->read_ptr + max > statep->write_ptr ) {
		max = statep->write_ptr - statep->read_ptr;
	}

	memcpy(buf,statep->read_ptr,max);
	statep->read_ptr += max;

	return max;
}

/*
 * If we're reading from a string, yyin is set to stdin, and we don't
 * want to close that.
 */
static int
string_close(FILE *fh _U_)
{
	return 0;
}

static FILE *
ddict_open(const char* system_directory, const char* filename)
{
	FILE* fh;
	char* fname;
	if (system_directory) {
		fname = ws_strdup_printf("%s" G_DIR_SEPARATOR_S "%s",
		    system_directory,filename);
	} else {
		fname = g_strdup(filename);
	}

	fh = ws_fopen(fname,"r");

	D(("fname: %s fh: %p\n",fname,(void*)fh));

	g_free(fname);


	return fh;
}

ddict_t *
ddict_scan(const char* system_directory, const char* filename, int dbg)
{
	DiamDict_scanner_state_t state;
	FILE *in;
	yyscan_t scanner;

	debugging = dbg;

	state.sys_dir = system_directory;

	state.write_ptr = NULL;
	state.read_ptr = NULL;

	state.strbuf = NULL;
	state.size_strbuf = 8192;
	state.len_strbuf = 0;

	state.dict = g_new(ddict_t,1);
	state.dict->applications = NULL;
	state.dict->vendors = NULL;
	state.dict->cmds = NULL;
	state.dict->typedefns = NULL;
	state.dict->avps = NULL;
	state.dict->xmlpis = NULL;

	state.appl = NULL;
	state.avp = NULL;
	state.enumitem = NULL;
	state.gavp = NULL;
	state.typedefn = NULL;
	state.cmd = NULL;
	state.vnd = NULL;
	state.xmlpi = NULL;

	state.last_appl = NULL;
	state.last_avp = NULL;
	state.last_enumitem = NULL;
	state.last_gavp = NULL;
	state.last_typedefn = NULL;
	state.last_cmd = NULL;
	state.last_vnd = NULL;
	state.last_xmlpi = NULL;

	state.ents = NULL;

	state.attr_str = NULL;
	state.attr_uint = NULL;

	/*
	 * Pass 1.
	 *
	 * Reads the file, does some work, and stores a modified version
	 * of the file contents in memory.
	 */
	state.current_yyinput = file_input;
	state.current_close = fclose;
	state.include_stack_ptr = 0;

	in = ddict_open(system_directory,filename);

	if (in == NULL) {
		D(("unable to open %s: %s\n", filename, g_strerror(errno)));
		g_free(state.dict);
		return NULL;
	}

	if (DiamDict_lex_init(&scanner) != 0) {
		/* Note: cannot be reached since memory allocation failure terminates early */
		D(("Can't initialize scanner: %s\n", g_strerror(errno)));
		fclose(in);
		g_free(state.dict);
		return NULL;
	}

	DiamDict_set_in(in, scanner);

	/* Associate the state with the scanner */
	DiamDict_set_extra(&state, scanner);

	state.start_state = LOADING;
	DiamDict_lex(scanner);

	DiamDict_lex_destroy(scanner);
	/*
	 * XXX - can the lexical analyzer terminate without closing
	 * all open input files?
	 */

	D(("\n---------------\n%s\n------- %u -------\n",state.strbuf,state.len_strbuf));

	/*
	 * Pass 2.
	 *
	 * Reads the modified version of the file contents and does the
	 * rest of the work.
	 */
	state.current_yyinput = string_input;
	state.current_close = string_close;

	if (DiamDict_lex_init(&scanner) != 0) {
		/* Note: cannot be reached since memory allocation failure terminates early */
		D(("Can't initialize scanner: %s\n", g_strerror(errno)));
		g_free(state.dict);
		g_free(state.strbuf);
		return NULL;
	}

	/* Associate the state with the scanner */
	DiamDict_set_extra(&state, scanner);

	state.start_state = OUTSIDE;
	DiamDict_lex(scanner);

	DiamDict_lex_destroy(scanner);
	{
		entity_t *e, *en;

		for (e = state.ents; e; e = en) {
			en = e->next;
			g_free(e->name);
			g_free(e->file);
			g_free(e);
		}
	}
	g_free(state.strbuf);

	return state.dict;
}

void
ddict_free(ddict_t* d)
{
	ddict_application_t *p, *pn;
	ddict_vendor_t *v, *vn;
	ddict_cmd_t *c, *cn;
	ddict_typedefn_t *t, *tn;
	ddict_avp_t *a, *an;
	ddict_xmlpi_t *x, *xn;

#define FREE_NAMEANDOBJ(n) do { g_free(n->name); g_free(n); } while(0)

	for (p = d->applications; p; p = pn ) {
		pn = p->next;
		FREE_NAMEANDOBJ(p);
	}

	for (v = d->vendors; v; v = vn) {
		vn = v->next;
		g_free(v->desc);
		FREE_NAMEANDOBJ(v);
	}

	for (c = d->cmds; c; c = cn ) {
		cn = c->next;
		g_free(c->vendor);
		FREE_NAMEANDOBJ(c);
	}

	for (t = d->typedefns; t; t = tn) {
		tn = t->next;
		g_free(t->parent);
		FREE_NAMEANDOBJ(t);
	}

	for (a = d->avps; a; a = an) {
		ddict_gavp_t* g, *gn;
		ddict_enum_t* e, *en;
		an = a->next;

		for (g = a->gavps; g; g = gn) {
			gn = g->next;
			FREE_NAMEANDOBJ(g);
		}

		for (e = a->enums; e; e = en) {
			en = e->next;
			FREE_NAMEANDOBJ(e);
		}

		g_free(a->vendor);
		g_free(a->type);
		g_free(a->description);
		FREE_NAMEANDOBJ(a);
	}

	for (x = d->xmlpis; x; x = xn) {
		xn = x->next;
		g_free(x->key);
		g_free(x->value);
		FREE_NAMEANDOBJ(x);
	}

	g_free(d);
}

void
ddict_print(FILE* fh, ddict_t* d)
{
	ddict_application_t* p;
	ddict_vendor_t* v;
	ddict_cmd_t* c;
	ddict_typedefn_t* t;
	ddict_avp_t* a;


	for (p = d->applications; p; p = p->next) {
		fprintf(fh,"Application: %s[%u]:\n",
				p->name ? p->name : "-",
				p->code);
	}

	for (v = d->vendors; v; v = v->next) {
		fprintf(fh,"Vendor: %s[%u]:\n",
				v->name ? v->name : "-",
				v->code);
	}

	for (c = d->cmds; c; c = c->next) {
		fprintf(fh,"Command: %s[%u] \n",
				c->name ? c->name : "-",
				c->code);
	}

	for (t = d->typedefns; t; t = t->next) {
		fprintf(fh,"Type: %s -> %s \n",
				t->name ? t->name : "-",
				t->parent ? t->parent : "" );
	}

	for (a = d->avps; a; a = a->next) {
		ddict_gavp_t* g;
		ddict_enum_t* e;
		fprintf(fh,"AVP: %s[%u:%s] %s %s\n",
				a->name ? a->name : "-",
				a->code,
				a->vendor ? a->vendor : "None",
				a->type ? a->type : "-",
				a->description ? a->description : "");

		for (g = a->gavps; g; g = g->next) {
			fprintf(fh,"\tGAVP: %s\n",
					g->name ? g->name : "-" );
		}

		for (e = a->enums; e; e = e->next) {
			fprintf(fh,"\tEnum: %s[%u]\n",
					e->name ? e->name : "-",
					e->code);
		}
	}
}

#ifdef TEST_DIAM_DICT_STANDALONE
int
main(int argc, char** argv)
{
	ddict_t* d;
	char* dname = NULL;
	char* fname;
	int i = 1;

	switch (argc) {
		case 3:
			dname = argv[i++];
		case 2:
			fname = argv[i];
			break;
		default:
			fprintf(stderr,"%s: usage [dictionary_dir] dictionary_filename\n",argv[0]);
			return 1;
	}

	d = ddict_scan(dname,fname,1);
	if (d == NULL) {
		fprintf(stderr, "Can't open dictionary\n");
		return 2;
	}

	ddict_print(stdout, d);

	return 0;
}
#endif
