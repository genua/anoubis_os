FSIZE?=		2048
BSIZE?=		16384
COUNT?=		128
VND?=		vnd0

mount:
	dd if=/dev/zero of=${.CURDIR}/fakedisk bs=${BSIZE} count=${COUNT}
	mkdir ${.CURDIR}/fakemount
	vnconfig s${VND} ${.CURDIR}/fakedisk
	newfs -f ${FSIZE} -b ${BSIZE} -O 2 /dev/rs${VND}c
	mount /dev/s${VND}c ${.CURDIR}/fakemount

unmount:
	-umount ${.CURDIR}/fakemount
	-vnconfig -u s${VND}
	-rm -rf ${.CURDIR}/fakedisk ${.CURDIR}/fakemount

SUBDIR= extattr_limit extattr_link extattr_priv extattr_stat extattr_truncate

.include <bsd.subdir.mk>
