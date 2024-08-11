# Copyright (C) 2007-2012 Red Hat
# see file 'COPYING' for use and warranty information
#
# policygentool is a tool for the initial generation of SELinux policy
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of the GNU General Public License as
#    published by the Free Software Foundation; either version 2 of
#    the License, or (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
#                                        02111-1307  USA
#
#
########################### var_log Template File #############################

########################### Type Enforcement File #############################
te_types="""
type random_device_t;
"""

te_rules="""
dev_read_rand(random_test_t)
"""

########################### Interface File #############################
if_rules="""\
########################################
## <summary>
##	Read from random number generator
##	devices (e.g., /dev/random).
## </summary>
## <desc>
##	<p>
##	Allow the specified domain to read from random number
##	generator devices (e.g., /dev/random).  Typically this is
##	used in situations when a cryptographically secure random
##	number is needed.
##	</p>
##	<p>
##	Related interface:
##	</p>
##	<ul>
##		<li>dev_read_urand()</li>
##	</ul>
## </desc>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
## <infoflow type="read" weight="10"/>
#
interface(`TEMPLATETYPE_read_rand',`
	gen_require(`
		type TEMPLATETYPE_t, random_device_t;
	')

	read_chr_files_pattern($1, TEMPLATETYPE_t, random_device_t)
')

########################################
## <summary>
##	Do not audit attempts to read from random
##	number generator devices (e.g., /dev/random)
## </summary>
## <param name="domain">
##	<summary>
##	Domain to not audit.
##	</summary>
## </param>
#
interface(`TEMPLATETYPE_dontaudit_read_rand',`
	gen_require(`
		type random_device_t;
	')

	dontaudit $1 random_device_t:chr_file { getattr read };
')

########################################
## <summary>
##	Do not audit attempts to append to random
##	number generator devices (e.g., /dev/random)
## </summary>
## <param name="domain">
##	<summary>
##	Domain to not audit.
##	</summary>
## </param>
#
interface(`TEMPLATETYPE_dontaudit_append_rand',`
	gen_require(`
		type random_device_t;
	')

	dontaudit $1 random_device_t:chr_file append_chr_file_perms;
')

########################################
## <summary>
##	Write to the random device (e.g., /dev/random). This adds
##	entropy used to generate the random data read from the
##	random device.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`TEMPLATETYPE_write_rand',`
	gen_require(`
		type TEMPLATETYPE_t, random_device_t;
	')

	write_chr_files_pattern($1, TEMPLATETYPE_t, random_device_t)
')

########################################
## <summary>
##  Create the random device (/dev/random).
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`TEMPLATETYPE_create_rand_dev',`
	gen_require(`
		type TEMPLATETYPE_t, random_device_t;
	')

	create_chr_files_pattern($1, TEMPLATETYPE_t, random_device_t)
')

"""

if_admin_types="""
		type TEMPLATETYPE_log_t;"""

if_admin_rules="""
	logging_search_logs($1)
	admin_pattern($1, TEMPLATETYPE_log_t)
"""

########################### File Context ##################################
fc_file="""\
FILENAME		--	gen_context(system_u:object_r:random_device_t,s0)
"""

fc_dir="""\
FILENAME(/.*)?		gen_context(system_u:object_r:random_device_t,s0)
"""
