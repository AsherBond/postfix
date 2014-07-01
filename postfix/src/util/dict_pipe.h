#ifndef _DICT_PIPE_H_INCLUDED_
#define _DICT_PIPE_H_INCLUDED_

/*++
/* NAME
/*	dict_pipe 3h
/* SUMMARY
/*	dictionary manager interface for pipelined tables
/* SYNOPSIS
/*	#include <dict_pipe.h>
/* DESCRIPTION
/* .nf

 /*
  * Utility library.
  */
#include <dict.h>

 /*
  * External interface.
  */
#define DICT_TYPE_PIPE	"pipemap"

#ifdef SNAPSHOT
#define DICT_TYPE_PIPE_LEGACY	"pipeline"
#endif

extern DICT *dict_pipe_open(const char *, int, int);

/* LICENSE
/* .ad
/* .fi
/*	The Secure Mailer license must be distributed with this software.
/* AUTHOR(S)
/*	Wietse Venema
/*	IBM T.J. Watson Research
/*	P.O. Box 704
/*	Yorktown Heights, NY 10598, USA
/*--*/

#endif
