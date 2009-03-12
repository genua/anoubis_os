#	$OpenBSD: deraadt $

SUBDIR= ramdisk_cd cdfs cdfs-emu

.if	make(obj) || make(cleandir) || make(clean)
SUBDIR+= iso
.endif

unconfig:
	cd ramdisk_cd; ${MAKE} unconfig

.include <bsd.subdir.mk>
