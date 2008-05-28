# Copyright (c) 2008 GeNUA mbH <info@genua.de>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
# This test asserts that permissions are correctly enforced when members of
# two distinct groups (composed of two users each) try to access a directory.
# For every <user(1/4), group1(1/2), perm1(1/7), group2(1/2), perm2(1/7)>
# combination possible, the followings steps are performed:
#
# (1) Try to inspect the contents of a directory (requires *READ* access).
# (2) Change the working directory (requires *EXEC* access in destination).
# (3) Move a directory (requires *WRITE* access).
#
# All tests are checked for success and failure when expected, in a total of
# 4 (users) * 2^2 (groups) * 7^2 (permissions) = 784 individual tests.

ALPHA="0 1 2 3"
BETA="0 1"
GAMMA="0 1"
MODES="r rw rx rwx w wx x"
RUN=0
FAILED=0

assert() {
	local beta=`expr $2 / 2`
	local gamma=`expr $2 % 2`
	local result="OK"

	if [ $7 -eq 0 ]; then
		case ${permb[$beta]}${permg[$gamma]} in
		*r*)
			;;
		*)
			echo "Inappropriate read access granted!"
			result="FAILED"
			;;
		esac
	else
		case ${permb[$beta]}${permg[$gamma]} in
		*r*)
			echo "Inappropriate read access denial!"
			result="FAILED"
			;;
		*)
			;;
		esac
	fi
	if [ $8 -eq 0 ]; then
		case ${permb[$beta]}${permg[$gamma]} in
		*w*)
			;;
		*)
			echo "Inappropriate write access granted!"
			result="FAILED"
			;;
		esac
	else
		case ${permb[$beta]}${permg[$gamma]} in
		*w*)
			echo "Inappropriate write access denial!"
			result="FAILED"
			;;
		*)
			;;
		esac
	fi
	if [ $9 -eq 0 ]; then
		case ${permb[$beta]}${permg[$gamma]} in
		*x*)
			;;
		*)
			echo "Inappropriate execution access granted!"
			result="FAILED"
			;;
		esac
	else
		case ${permb[$beta]}${permg[$gamma]} in
		*x*)
			echo "Inappropriate execution access denial!"
			result="FAILED"
			;;
		*)
			;;
		esac
	fi
	echo "$1(_alpha$2, _beta$3, _gamma$4, $5, $6) -> ($7, $8, $9) $result"
	if [ $result = "FAILED" ]; then
		FAILED=`expr $FAILED + 1`
	fi
}

test() {
	local dir1=`mktemp -d -p $WRKDIR`
	local dir2=`mktemp -d -p $WRKDIR`
	local r w x

	chown _alpha$1 $WRKDIR $dir2
	setfacl -m g:_beta$2:$4,g:_gamma$3:$5 $dir1

	sudo -u _alpha$1 ls $dir1 2>/dev/null
	r=$?
	sudo -u _alpha$1 sh -c "cd $dir1" 2>/dev/null
	x=$?
	# Note: There is a difference in behaviour between OpenBSD and Linux
	# regarding the renaming of directories. Linux does *not* require
	# write permission if the directory is being moved within a given
	# 'parent' directory, while OpenBSD does.
	sudo -u _alpha$1 mv $dir1 $dir2 2>/dev/null
	w=$?

	assert acl_groupdir $1 $2 $3 $4 $5 $r $w $x
	rm -rf $dir1 $dir2
	RUN=`expr $RUN + 1`
}

if [ -z $1 ]; then
	echo "Please specify a work directory as a first argument."
	exit 1
fi

WRKDIR=$1
echo Starting tests...

for beta in $BETA; do
	for mode in $MODES; do
		permb[$beta]=$mode
		for gamma in $GAMMA; do
			for mode in $MODES; do
				permg[$gamma]=$mode
				for alpha in $ALPHA; do
					test $alpha $beta $gamma \
					  ${permb[$beta]} ${permg[$gamma]}
				done
			done
			permg[$gamma]=""
		done
	done
	permb[$beta]=""
done

echo $RUN tests run, $FAILED failed
