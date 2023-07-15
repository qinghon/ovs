# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2021 VMware, Inc.

# ovsdb/_server.ovsschema.inc
ovsdb__server_ovsschema_inc = custom_target(
    '_server.ovsschema.inc',
    input : meson.project_source_root() + '/ovsdb/_server.ovsschema',
    output : '_server.ovsschema.inc',
    command : [
        prog_python,
        meson.project_source_root() + '/build-aux/text2c',
    ],
    feed : true,
    capture : true ,
    env : python_env,
)

ovsdb_ovsdb_server5 = custom_target(
    'ovsdb_ovsdb_server_5',
    output : 'ovsdb-server.5',
    command : [
        prog_python,
        meson.project_source_root() + '/ovsdb/ovsdb-doc',
        '--version=' + as_version,
        meson.project_source_root() + '/ovsdb/_server.ovsschema',
        meson.project_source_root() + '/ovsdb/_server.xml',
    ],
    capture : true ,
    env : python_env,
    install: true,
    install_dir: 'share/man/man5',
)

ovsdb_local_config_5 = custom_target(
    'ovsdb_local_config_5',
    output : 'ovsdb.local-config.5',
    command : [
        prog_python,
        meson.project_source_root() + '/ovsdb/ovsdb-doc',
        '--version=' + as_version,
        meson.project_source_root() + '/ovsdb/local-config.ovsschema',
        meson.project_source_root() + '/ovsdb/local-config.xml',
    ],
    capture : true ,
    env : python_env,
    install: true,
    install_dir: 'share/man/man5',
)

sources = files(
	'column.c',
	'condition.c',
	'execution.c',
	'file.c',
	'jsonrpc-server.c',
	'log.c',
	'mutation.c',
	'ovsdb.c',
	'monitor.c',
	'query.c',
	'raft.c',
	'raft-private.c',
	'raft-rpc.c',
	'rbac.c',
	'replication.c',
	'relay.c',
	'row.c',
	'server.c',
	'storage.c',
	'table.c',
	'trigger.c',
	'transaction.c',
	'transaction-forward.c',
	'ovsdb-util.c',
)

deps = []

mapfile = meson.project_build_root() + '/ovsdb.map'
vflag = '-Wl,-Map,@0@'.format(mapfile)
ovsdb = library(
  'ovsdb', sources,
  dependencies : deps,
  include_directories : global_inc,
  link_args : ['-Wl,--no-undefined', vflag],
  link_depends : mapfile,
  link_with: [openvswitch],
  version : as_version,
  soversion : as_soversion,
  install: true,
)


sources = files(
    'ovsdb-tool.c',
)
exdeps = [global_exdeps]
exldflags = []
if have_dpdk
    exdeps += libdpdk
    exldflags += libdpdk_ldflags
endif
if build_machine.system() == 'linux'
    exdeps += m_dep
endif

deps = [exdeps]

executable('ovsdb-tool', sources,
    dependencies : deps,
    include_directories : global_inc,
    link_args : ['-Wl,--no-undefined'] + exldflags,
    link_with : [ ovsdb, openvswitch ],
    install : true,
    install_dir:  'bin',
)

sources = files(
    'ovsdb-client.c',
)

deps = [exdeps]

executable('ovsdb-client', sources,
    dependencies : deps,
    include_directories : global_inc,
    link_args : ['-Wl,--no-undefined'] + exldflags,
    link_with : [ ovsdb, openvswitch ],
    install : true,
    install_dir:  'bin',
)

sources = files(
    'ovsdb-server.c',
)

sources += [
    ovsdb__server_ovsschema_inc,
]

deps = [exdeps]

executable('ovsdb-server', sources,
    dependencies : deps,
    include_directories : global_inc,
    link_args : ['-Wl,--no-undefined'] + exldflags,
    link_with : [ ovsdb, openvswitch ],
    install : true,
    install_dir:  'sbin',
)
pkg.generate(ovsdb)

man_pages = files(['ovsdb-idlc.1'])
man_pages += configure_file(input: 'ovsdb-client.1.in', output : 'ovsdb-client.1', configuration : conf_dir)
man_pages += configure_file(input: 'ovsdb-server.1.in', output : 'ovsdb-server.1', configuration : conf_dir)
man_pages += configure_file(input: 'ovsdb-tool.1.in', output : 'ovsdb-tool.1', configuration : conf_dir)
install_data(sources: 'local-config.ovsschema', install_dir : 'share/openvswitch')
install_man(man_pages)