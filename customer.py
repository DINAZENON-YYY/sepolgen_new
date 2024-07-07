
########################### tmp Template File #############################
te_types="""
type SEMPLATETYPE;
files_type(SEMPLATETYPE)
"""

te_rules="""
manage_dirs_pattern(TEMPLATETYPE_t, SEMPLATETYPE, SEMPLATETYPE)
manage_files_pattern(TEMPLATETYPE_t, SEMPLATETYPE, SEMPLATETYPE)
manage_lnk_files_pattern(TEMPLATETYPE_t, SEMPLATETYPE, SEMPLATETYPE)
"""

########################### Interface File #############################
if_rules="""
########################################
## <summary>
##	Search TEMPLATETYPE rw directories.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`TEMPLATETYPE_search_rw_dir',`
	gen_require(`
		type SEMPLATETYPE;
	')

	allow $1 SEMPLATETYPE:dir search_dir_perms;
	files_search_rw($1)
')

########################################
## <summary>
##	Read TEMPLATETYPE rw files.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`TEMPLATETYPE_read_rw_files',`
	gen_require(`
		type SEMPLATETYPE;
	')

	read_files_pattern($1, SEMPLATETYPE, SEMPLATETYPE)
	allow $1 SEMPLATETYPE:dir list_dir_perms;
	files_search_rw($1)
')

########################################
## <summary>
##	Manage TEMPLATETYPE rw files.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`TEMPLATETYPE_manage_rw_files',`
	gen_require(`
		type SEMPLATETYPE;
	')

	manage_files_pattern($1, SEMPLATETYPE, SEMPLATETYPE)
')

########################################
## <summary>
##	Create, read, write, and delete
##	TEMPLATETYPE rw dirs.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`TEMPLATETYPE_manage_rw_dirs',`
	gen_require(`
		type SEMPLATETYPE;
	')

	manage_dirs_pattern($1, SEMPLATETYPE, SEMPLATETYPE)
')

"""

te_stream_rules="""
manage_sock_files_pattern(TEMPLATETYPE_t, SEMPLATETYPE, SEMPLATETYPE)
"""

if_stream_rules="""\
########################################
## <summary>
##	Connect to TEMPLATETYPE over a unix stream socket.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`TEMPLATETYPE_stream_connect',`
	gen_require(`
		type TEMPLATETYPE_t, SEMPLATETYPE;
	')

	stream_connect_pattern($1, SEMPLATETYPE, SEMPLATETYPE, SEMPLATETYPE)
')
"""

if_admin_types="""
		type SEMPLATETYPE;"""

if_admin_rules="""
	files_search_etc($1)
	admin_pattern($1, SEMPLATETYPE)
"""

########################### File Context ##################################
fc_file="""
FILENAME		--	gen_context(system_u:object_r:FILETYPE,s0)
"""

fc_sock_file="""\
FILENAME        -s  gen_context(system_u:object_r:TEMPLATETYPE_etc_rw_t,s0)
"""

fc_dir="""
FILENAME(/.*)?		gen_context(system_u:object_r:FILETYPE,s0)
"""
