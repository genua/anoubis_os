FSIZE?=		2048
BSIZE?=		16384
COUNT?=		128
VND?=		vnd0

mount:
	sh ${.CURDIR}/setup.sh
	dd if=/dev/zero of=${.CURDIR}/fakedisk bs=${BSIZE} count=${COUNT}
	mkdir ${.CURDIR}/fakemount
	vnconfig s${VND} ${.CURDIR}/fakedisk
	newfs -f ${FSIZE} -b ${BSIZE} -O 2 /dev/rs${VND}c
	tunefs -a set /dev/rs${VND}c
	mount /dev/s${VND}c ${.CURDIR}/fakemount

unmount:
	-umount ${.CURDIR}/fakemount
	-vnconfig -u s${VND}
	-rm -rf ${.CURDIR}/fakedisk ${.CURDIR}/fakemount
	sh ${.CURDIR}/cleanup.sh

SUBDIR=	acl_groupdir acl_groupfile acl_userdir acl_userfile

.include <bsd.subdir.mk>
