TOP=			${.CURDIR}/..
FAKEMNT=		${TOP}/fakemount

run-regress:
	sh ${.CURDIR}/acl_groupdir.sh ${TMPDIR} |\
	    diff -u - ${.CURDIR}/acl_groupdir.out

regress:
	(cd ${TOP} && exec ${MAKE} mount)
	@(cd ${.CURDIR} && \
	    exec ${MAKE} TMPDIR=`mktemp -d ${FAKEMNT}/acl.XXXXXXXX` run-regress)
	(cd ${TOP} && exec ${MAKE} unmount)

clean:
	(cd ${TOP} && exec ${MAKE} unmount)
	rm -f ${PROG} ${OBJS}

.include <bsd.regress.mk>
