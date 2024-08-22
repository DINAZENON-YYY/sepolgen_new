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
attribute device_node;
attribute memory_raw_read;
attribute memory_raw_write;
attribute devices_unconfined_type;

type device_t;
type memory_device_t;
dev_node(memory_device_t)

neverallow ~{ memory_raw_read devices_unconfined_type } memory_device_t:{ chr_file blk_file } read;
neverallow ~{ memory_raw_write devices_unconfined_type } memory_device_t:{ chr_file blk_file } { append write };

type misc_device_t;
dev_node(misc_device_t)
"""

te_rules="""
allow device_node device_t:filesystem associate;

fs_associate(device_node)
fs_associate_tmpfs(device_node)

files_associate_tmp(device_node)
"""

########################### Interface File #############################
if_rules="""\
########################################
## <summary>
##	dontaudit getattr raw memory devices (e.g. /dev/mem).
## </summary>
## <param name="domain">
##	<summary>
##	Domain to not audit.
##	</summary>
## </param>
#
interface(`dev_dontaudit_getattr_memory_dev',`
	gen_require(`
		type memory_device_t;
	')

	dontaudit $1 memory_device_t:chr_file getattr;
')

########################################
## <summary>
##	Read raw memory devices (e.g. /dev/mem).
##	This is extremely dangerous as it can bypass the
##	SELinux protections, and should only be used by trusted
##	domains.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`dev_read_raw_memory',`
	gen_require(`
		type device_t, memory_device_t;
		attribute memory_raw_read;
	')

	read_chr_files_pattern($1, device_t, memory_device_t)

	allow $1 self:capability sys_rawio;
	typeattribute $1 memory_raw_read;
')

########################################
## <summary>
##	Read raw memory devices (e.g. /dev/mem) if a tunable is set.
##	This is extremely dangerous as it can bypass the
##	SELinux protections, and should only be used by trusted
##	domains.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
## <param name="tunable">
##	<summary>
##	Tunable to depend on
##	</summary>
## </param>
#
interface(`dev_read_raw_memory_cond',`
	gen_require(`
		type device_t, memory_device_t;
		attribute memory_raw_read;
	')

	typeattribute $1 memory_raw_read;
	tunable_policy(`$2', `
		read_chr_files_pattern($1, device_t, memory_device_t)
		allow $1 self:capability sys_rawio;
	')
')

########################################
## <summary>
##	Do not audit attempts to read raw memory devices
##	(e.g. /dev/mem).
##	This is extremely dangerous as it can bypass the
##	SELinux protections, and should only be used by trusted
##	domains.
## </summary>
## <param name="domain">
##	<summary>
##	Domain to not audit.
##	</summary>
## </param>
#
interface(`dev_dontaudit_read_raw_memory',`
	gen_require(`
		type memory_device_t;
	')

	dontaudit $1 memory_device_t:chr_file read_chr_file_perms;
')

########################################
## <summary>
##	Write raw memory devices (e.g. /dev/mem).
##	This is extremely dangerous as it can bypass the
##	SELinux protections, and should only be used by trusted
##	domains.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`dev_write_raw_memory',`
	gen_require(`
		type device_t, memory_device_t;
		attribute memory_raw_write;
	')

	write_chr_files_pattern($1, device_t, memory_device_t)

	allow $1 self:capability sys_rawio;
	typeattribute $1 memory_raw_write;
')

########################################
## <summary>
##	Write raw memory devices (e.g. /dev/mem) if a tunable is set.
##	This is extremely dangerous as it can bypass the
##	SELinux protections, and should only be used by trusted
##	domains.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
## <param name="tunable">
##	<summary>
##	Tunable to depend on
##	</summary>
## </param>
#
interface(`dev_write_raw_memory_cond',`
	gen_require(`
		type device_t, memory_device_t;
		attribute memory_raw_write;
	')

	typeattribute $1 memory_raw_write;
	tunable_policy(`$2', `
		write_chr_files_pattern($1, device_t, memory_device_t)
		allow $1 self:capability sys_rawio;
	')
')

########################################
## <summary>
##	Read and execute raw memory devices (e.g. /dev/mem).
##	This is extremely dangerous as it can bypass the
##	SELinux protections, and should only be used by trusted
##	domains.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`dev_rx_raw_memory',`
	gen_require(`
		type memory_device_t;
	')

	dev_read_raw_memory($1)
	allow $1 memory_device_t:chr_file { map execute };
')

########################################
## <summary>
##	Write and execute raw memory devices (e.g. /dev/mem).
##	This is extremely dangerous as it can bypass the
##	SELinux protections, and should only be used by trusted
##	domains.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`dev_wx_raw_memory',`
	gen_require(`
		type memory_device_t;
	')

	dev_write_raw_memory($1)
	allow $1 memory_device_t:chr_file { map execute };
')

########################################
## <summary>
##	Write and execute raw memory devices (e.g. /dev/mem) if a tunable is set.
##	This is extremely dangerous as it can bypass the
##	SELinux protections, and should only be used by trusted
##	domains.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
## <param name="tunable">
##	<summary>
##	Tunable to depend on
##	</summary>
## </param>
#
interface(`dev_wx_raw_memory_cond',`
	gen_require(`
		type memory_device_t;
		attribute memory_raw_write;
	')

	typeattribute $1 memory_raw_write;
	dev_write_raw_memory_cond($1, $2)
	tunable_policy(`$2', `
		allow $1 memory_device_t:chr_file { map execute };
	')
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
FILENAME		--	gen_context(system_u:object_r:memory_device_t,s0)
"""

fc_dir="""\
FILENAME(/.*)?		gen_context(system_u:object_r:memory_device_t,s0)
"""
