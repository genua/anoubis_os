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
# This test asserts that permissions are correctly enforced when four distinct
# users try to access a file. For every <user1(1/4), perm1(1/7), ...,
# user4(1/4), perm4(1/4)> combination possible, the followings steps are
# performed:
#
# (1) Try to read from the file.
# (2) Try to execute the file.
# (3) Try to write to the file.
#
# All tests are checked for success and failure when expected, in a total of
# 4 (users) * 7^4 (permissions) = 9604 individual tests.

ALPHA="0 1 2 3"
MODES="r rw rx rwx w wx x"
RUN=0
FAILED=0

assert() {
	local result="OK"
	if [ $7 -eq 0 ]; then
		if [ ${perm[$2]} = "w" ] || [ ${perm[$2]} = "wx" ] ||
		   [ ${perm[$2]} = "x" ]; then
			echo "Inappropriate read access granted!"
			result="FAILED"
		fi
	else
		if [ ${perm[$2]} = "r" ] || [ ${perm[$2]} = "rw" ] ||
		   [ ${perm[$2]} = "rx" ] || [ ${perm[$2]} = "rwx" ]; then
			echo "Inappropriate read access denial!"
			result="FAILED"
		fi
	fi
	if [ $8 -eq 0 ]; then
		if [ ${perm[$2]} = "r" ] || [ ${perm[$2]} = "rx" ] ||
		   [ ${perm[$2]} = "x" ]; then
			echo "Inappropriate write access granted!"
			result="FAILED"
		fi
	else
		if [ ${perm[$2]} = "w" ] || [ ${perm[$2]} = "rw" ] ||
		   [ ${perm[$2]} = "wx" ] || [ ${perm[$2]} = "rwx" ]; then
			echo "Inappropriate write access denial!"
			result="FAILED"
		fi
	fi
	if [ $9 -eq 0 ]; then
		if [ ${perm[$2]} != "rx" ] && [ ${perm[$2]} != "rwx" ]; then
			echo "Inappropriate execution access granted!"
			result="FAILED"
		fi
	else
		if [ ${perm[$2]} = "rx" ] && [ ${perm[$2]} = "rwx" ]; then
			echo "Inappropriate execution access denial!"
			result="FAILED"
		fi
	fi
	echo "$1(_alpha$2, $3, $4, $5, $6) -> ($7, $8, $9) $result"
	if [ $result = "FAILED" ]; then
		FAILED=`expr $FAILED + 1`
	fi
}

test() {
	local file=`mktemp -p $WRKDIR`
	local r w x

	setfacl -m \
	  u:_alpha0:$2,u:_alpha1:$3,u:_alpha2:$4,u:_alpha3:$5 $file 2>/dev/null

	sudo -u _alpha$1 cat $file 2>/dev/null
	r=$?
	sudo -u _alpha$1 $file 2>/dev/null
	x=$?
	sudo -u _alpha$1 sh -c "echo 1 > $file" 2>/dev/null
	w=$?

	assert acl_userfile $1 $2 $3 $4 $5 $r $w $x
	rm -rf $dir $file
	RUN=`expr $RUN + 1`
}

if [ -z $1 ]; then
	echo "Please specify a work directory as a first argument."
	exit 1
fi

WRKDIR=$1
echo Starting tests...

for mode in $MODES; do
	perm[0]=$mode
	for mode in $MODES; do
		perm[1]=$mode
		for mode in $MODES; do
			perm[2]=$mode
			for mode in $MODES; do
				perm[3]=$mode
				for alpha in $ALPHA; do
					test $alpha ${perm[0]} ${perm[1]} \
					  ${perm[2]} ${perm[3]}
				done
			done
		done
	done
done

echo $RUN tests run, $FAILED failed
