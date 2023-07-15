# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2021 VMware, Inc.

vtep_vtep_idl_c = custom_target(
    'vtep-idl.c',
#    input : meson.project_source_root() + '/vtep/vtep-idl.ovsidl',
    input : vtep_vtep_idl_ovsidl,
    output : 'vtep-idl.c',
    command : [
        prog_python,
        meson.project_source_root() + '/ovsdb/ovsdb-idlc.in',
        'c-idl-source',
        '@INPUT@',
    ],
    capture : true,
    env : python_env,
)

vtep_vtep_idl_h = custom_target(
    'vtep-idl.h',
#    input : meson.project_source_root() + '/vtep/vtep-idl.ovsidl',
    input : vtep_vtep_idl_ovsidl,
    output : 'vtep-idl.h',
    command : [
        prog_python,
        meson.project_source_root() + '/ovsdb/ovsdb-idlc.in',
        'c-idl-header',
        '@INPUT@',
    ],
    capture : true,
    env : python_env,
)

man_vtep_5 = custom_target(
    'man_vtep_5',
    output : 'vtep.5',
    command : [
        prog_python,
        meson.project_source_root() + '/ovsdb/ovsdb-doc',
        '--version=' + as_version,
        meson.project_source_root() + '/vtep/vtep.ovsschema',
        meson.project_source_root() + '/vtep/vtep.xml',
    ],
    capture : true ,
    env : python_env,
    install: true,
    install_dir: 'share/man/man5',
)


#sources = files(
#    'vtep-idl.c',
#)
sources = [
    vtep_vtep_idl_c,
    vtep_vtep_idl_h,
]

deps = []

mapfile = meson.project_build_root() + '/vtep.map'
vflag = '-Wl,-Map,@0@'.format(mapfile)
vtep = library(
  'vtep', sources,
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
    'vtep-ctl.c',
)

sources += [
    vtep_vtep_idl_h,
]

deps = [global_exdeps]
if build_machine.system() == 'linux'
    deps += m_dep
endif

executable('vtep-ctl', sources,
    dependencies : deps,
    include_directories : global_inc,
    link_args : ['-Wl,--no-undefined', '-Wl,--allow-multiple-definition'],
    link_with : [ vtep, openvswitch ],
    install: true,
)
install_data(sources: 'vtep.ovsschema', install_dir : 'share/openvswitch')
configure_file(input: 'ovs-vtep.in', output : 'ovs-vtep', configuration : conf_dir, install_dir: 'share/openvswitch/scripts')

man_pages = []

man_filein = [
    'vtep-ctl.8.in',
]
foreach f:man_filein
    man_pages += configure_file(input: f, output : f.replace('.in', ''), configuration : conf_dir)
endforeach
install_man(man_pages)