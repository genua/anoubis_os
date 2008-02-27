PROG=	open

run-regress-${PROG}:	${PROG}
			dd if=/dev/zero of=${.CURDIR}/fakeobj bs=512 count=4k
			vnconfig svnd0 ${.CURDIR}/fakeobj
			newfs -O 2 /dev/rsvnd0c
			tunefs -a set /dev/rsvnd0c
			mount /dev/svnd0c /mnt
			./${PROG}
			umount /mnt
			vnconfig -u svnd0
			rm -f ${.CURDIR}/fakeobj

.include <bsd.regress.mk>
