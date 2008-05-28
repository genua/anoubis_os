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
# This script populates the host system with groups and users needed by the ACL
# regression tests. In case of error, partial modifications are reverted.

# Subroutines (have to come first).

addgroup() {
	local group=$1$2
	getent group $group >/dev/null
	if [ $? -eq 2 ]; then
		groupadd $group
		if [ $? -eq 0 ]; then
			echo "Added group '$group'."
			set -A added_groups ${added_groups[@]} $group
		else
			echo "Error adding group '$group'."
			revert
		fi
	fi
}

adduser() {
	local home="/var/empty"
	local shell="/sbin/nologin"
	local user=$1$2
	useradd -c "$user acl test user" -d $home -s $shell -g =uid $user
	if [ $? -eq 0 ]; then
		echo "Added user '$user'."
		set -A added_users ${added_users[@]} $user
	else
		echo "Error adding user '$user'."
		revert
	fi
}

revert() {
	echo Reverting...
	for user in ${added_users[@]}; do
		userdel $user
		if [ $? -eq 0 ]; then
			echo "Removed user '$user'."
		else
			echo "Error removing user '$user'."
		fi
	done
	for group in ${added_groups[@]}; do
		groupdel $group
		if [ $? -eq 0 ]; then
			echo "Removed group '$group'."
		else
			echo "Error removing group '$group'."
		fi
	done
	exit 1
}

# End of subroutines.

set -A added_users
set -A added_groups

echo Setting up groups and users...

for group in _beta0 _beta1 _gamma0 _gamma1; do
	getent group $group >/dev/null
	if [ $? -eq 0 ]; then
		echo "Error, group '$group' already exists."
		exit 1 # Nothing to revert at this point.
	fi
done

for alpha in 0 1 2 3; do
	beta=`expr $alpha / 2`
	gamma=`expr $alpha % 2`
	adduser _alpha $alpha
	addgroup _beta $beta
	addgroup _gamma $gamma
	usermod -G _beta$beta,_gamma$gamma _alpha$alpha
	if [ $? -eq 0 ]; then
		echo -n "Inserted user '_alpha$alpha' in groups "
		echo "'_beta$beta' and '_gamma$gamma'."
	else
		echo -n "Error inserting user $alpha$alpha in groups "
		echo "'_beta$beta' and '_gamma$gamma'."
	fi
done

exit 0
