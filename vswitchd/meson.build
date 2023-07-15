# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2021 VMware, Inc.


vswitchd_ovs_vswitchd_conf_db_5 = custom_target(
    'vswitchd_ovs_vswitchd_conf_db_5',
    output : 'ovs-vswitchd.conf.db.5',
    command : [
        prog_python,
        meson.project_source_root() + '/ovsdb/ovsdb-doc',
        '--version=' + as_version,
        meson.project_source_root() + '/vswitchd/vswitch.ovsschema',
        meson.project_source_root() + '/vswitchd/vswitch.xml',
    ],
    capture : true ,
    env : python_env,
    install: true,
    install_dir: 'share/man/man5',
)


sources = files(
    'bridge.c',
    'ovs-vswitchd.c',
    'system-stats.c',
    #'xenserver.c',
)

sources += [
	include_odp_netlink_h,
]

sources += lib_vswitch_idl_h
exdeps = [thread_dep, global_exdeps]
exldflags = []
if have_dpdk
    exdeps += libdpdk
    exldflags += libdpdk_ldflags
endif

deps = [exdeps]

if build_machine.system() == 'linux'
    deps += m_dep
endif

executable('ovs-vswitchd', sources,
  dependencies : deps,
  include_directories : global_inc,
  link_args : ['-Wl,--no-undefined'] + exldflags,
  link_with : [ openvswitch, ofproto, sflow ],
  install : true,
  install_dir:  'sbin',
)
install_data(sources: 'vswitch.ovsschema', install_dir : 'share/openvswitch')

man_pages = []

man_filein = [
    'ovs-vswitchd.8.in',
]
foreach f:man_filein
    man_pages += configure_file(input: f, output : f.replace('.in', ''), configuration : conf_dir)
endforeach
install_man(man_pages)
