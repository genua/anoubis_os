PROG=		extattr_link
TOP=		${.CURDIR}/..
FAKEMNT=	${TOP}/fakemount

run-regress-${PROG}:
	ln -sf ${TMPFILE} ${TMPLINK}
	./${PROG} ${TMPFILE} ${TMPLINK}

regress:
	(cd ${TOP} && exec ${MAKE} mount)
	@(cd ${.CURDIR} && \
	    exec ${MAKE} TMPFILE=`mktemp ${FAKEMNT}/extattr.XXXXXXXX` \
	    TMPLINK=`mktemp -u ${FAKEMNT}/extattr.XXXXXXXX` run-regress-${PROG})
	(cd ${TOP} && exec ${MAKE} unmount)

clean:
	(cd ${TOP} && exec ${MAKE} unmount)
	rm -f ${PROG} ${OBJS}

.include <bsd.regress.mk>
