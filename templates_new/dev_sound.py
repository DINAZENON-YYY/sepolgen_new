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
type sound_device_t;
"""

te_rules="""
allow TEMPLATETYPE_t sound_device_t:chr_file { ioctl map open read write };
alsa_read_lib(TEMPLATETYPE_t)
alsa_read_rw_config(TEMPLATETYPE_t)
auth_read_passwd_file(TEMPLATETYPE_t)
gnome_list_home_config(TEMPLATETYPE_t)
"""

########################### Interface File #############################
if_rules="""\
########################################
## <summary>
##	Get the attributes of the sound devices.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`TEMPLATETYPE_getattr_sound_dev',`
	gen_require(`
		type TEMPLATETYPE_t, sound_device_t;
	')

	getattr_chr_files_pattern($1, TEMPLATETYPE_t, sound_device_t)
')

########################################
## <summary>
##	Set the attributes of the sound devices.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`TEMPLATETYPE_setattr_sound_dev',`
	gen_require(`
		type TEMPLATETYPE_t, sound_device_t;
	')

	setattr_chr_files_pattern($1, TEMPLATETYPE_t, sound_device_t)
')

########################################
## <summary>
##	Read the sound devices.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`TEMPLATETYPE_read_sound',`
	gen_require(`
		type TEMPLATETYPE_t, sound_device_t;
	')

	read_chr_files_pattern($1, TEMPLATETYPE_t, sound_device_t)
	allow $1 sound_device_t:chr_file map;
')

########################################
## <summary>
##	Write the sound devices.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`TEMPLATETYPE_write_sound',`
	gen_require(`
		type TEMPLATETYPE_t, sound_device_t;
	')

	write_chr_files_pattern($1, TEMPLATETYPE_t, sound_device_t)
	allow $1 sound_device_t:chr_file map;
')

########################################
## <summary>
##	Read the sound mixer devices.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`TEMPLATETYPE_read_sound_mixer',`
	gen_require(`
		type TEMPLATETYPE_t, sound_device_t;
	')

	read_chr_files_pattern($1, TEMPLATETYPE_t, sound_device_t)
	allow $1 sound_device_t:chr_file map;
')

########################################
## <summary>
##	Write the sound mixer devices.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`TEMPLATETYPE_write_sound_mixer',`
	gen_require(`
		type TEMPLATETYPE_t, sound_device_t;
	')

	write_chr_files_pattern($1, TEMPLATETYPE_t, sound_device_t)
	allow $1 sound_device_t:chr_file map;
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
FILENAME		--	gen_context(system_u:object_r:sound_device_t,s0)
"""

fc_dir="""\
FILENAME(/.*)?		gen_context(system_u:object_r:sound_device_t,s0)
"""
