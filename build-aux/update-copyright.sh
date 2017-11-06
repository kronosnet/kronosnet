#!/bin/bash
#
# Copyright (C) 2017 Red Hat, Inc.  All rights reserved.
#
# Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
#
# This software licensed under GPL-2.0+, LGPL-2.0+
#

# script to update copyright dates across the tree

input=$(grep -ril -e "Copyright.*Red Hat" |grep -v .swp)
for i in $input; do
	startdate=$(git log "$i" | grep ^Date: | tail -n 1 | awk '{print $6}')
	enddate=$(git log "$i" | grep ^Date: | head -n 1 | awk '{print $6}')
	if [ "$startdate" != "$enddate" ]; then
		sed -i -e 's#Copyright (C).*Red Hat#Copyright (C) '$startdate'-'$enddate' Red Hat#g' $i
	else
		sed -i -e 's#Copyright (C).*Red Hat#Copyright (C) '$startdate' Red Hat#g' $i
	fi
done

input=$(find . -type f |grep -v ".git")
for i in $input; do
	if [ -z "$(grep -i "Copyright" $i)" ]; then
		echo "WARNING: $i appears to be missing Copyright information"
	fi
done
