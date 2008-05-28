TOP=			${.CURDIR}/..
FAKEMNT=		${TOP}/fakemount

run-regress:
	sh ${.CURDIR}/acl_groupfile.sh ${FAKEMNT} |\
	    diff -u - ${.CURDIR}/acl_groupfile.out

regress:
	(cd ${TOP} && exec ${MAKE} mount)
	@(cd ${.CURDIR} && exec ${MAKE} run-regress)
	(cd ${TOP} && exec ${MAKE} unmount)

clean:
	(cd ${TOP} && exec ${MAKE} unmount)
	rm -f ${PROG} ${OBJS}

.include <bsd.regress.mk>
