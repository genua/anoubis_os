# $FreeBSD: src/lib/libc/posix1e/Makefile.inc,v 1.19 2006/07/07 14:02:17 rwatson Exp $

.PATH: ${.CURDIR}/posix1e

SRCS+=	extattr.c

MAN+=	extattr.3

MLINKS+=extattr.3 extattr_namespace_to_string.3	\
	extattr.3 extattr_string_to_namespace.3
