PROG=		extattr_limit
TOP=		${.CURDIR}/..
TESTS?=		2048 4096 4096 4096 2048 8192 4096 8192 8192 8192 2048 16384  \
		4096 16384 8192 16384 16384 16384 4096 32768 8192 32768 16384 \
		32768 32768 32768
FAKEMNT=	${TOP}/fakemount

run-regress-${PROG}:
	./${PROG} /dev/rsvnd0c ${TMPFILE}

regress:
.for FSIZE BSIZE in ${TESTS}
	(cd ${TOP} && exec ${MAKE} FSIZE=${FSIZE} BSIZE=${BSIZE} mount)
	@(cd ${.CURDIR} && \
	    exec ${MAKE} TMPFILE=`mktemp ${FAKEMNT}/extattr.XXXXXXXX` \
	    run-regress-${PROG})
	(cd ${TOP} && exec ${MAKE} unmount)
.endfor

clean:
	(cd ${TOP} && exec ${MAKE} unmount)
	rm -f ${PROG} ${OBJS}

.include <bsd.regress.mk>
