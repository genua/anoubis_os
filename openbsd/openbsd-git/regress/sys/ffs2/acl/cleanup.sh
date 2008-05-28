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
# This script ensures that all groups and users created for the ACL regression
# test suite are correctly removed from the host system.

echo Cleaning up groups and users...

# Remove '_beta' groups.
for n in 0 1; do
	match=`getent group _beta$n | cut -d : -f 4`
	pattern="_alpha"`expr $n + $n`",_alpha"`expr $n + $n + 1`
	if [ "$match" == "$pattern" ]; then
		groupdel _beta$n
		if [ $? -eq 0 ]; then
			echo "Removed group '_beta$n'."
		else
			echo "Error removing group '_beta$n'."
		fi
	fi
done

# Remove '_gamma' groups.
for n in 0 1; do
	match=`getent group _gamma$n | cut -d : -f 4`
	pattern="_alpha"`expr $n`",_alpha"`expr $n + 2`
	if [ "$match" == "$pattern" ]; then
		groupdel _gamma$n
		if [ $? -eq 0 ]; then
			echo "Removed group '_gamma$n'."
		else
			echo "Error removing group '_gamma$n'."
		fi
	fi
done

# Remove '_alpha' users.
for n in 0 1 2 3; do
	match=`getent passwd _alpha$n | cut -d : -f 5`
	pattern="_alpha$n acl test user"
	if [ "$match" == "$pattern" ]; then
		userdel _alpha$n
		if [ $? -eq 0 ]; then
			echo "Removed user '_alpha$n'."
		else
			echo "Error removing user '_alpha$n'."
		fi
	fi
done
