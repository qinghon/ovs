# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2021 VMware, Inc.

include_odp_netlink_h = custom_target(
    'odp-netlink.h',
    input : meson.project_source_root() + '/include/linux/openvswitch.h',
    output : 'odp-netlink.h',
    command : [
        prog_python,
        meson.project_source_root() + '/build-aux/extract-odp-netlink-h.py',
        '@INPUT@',
    ],
    capture : true,
    env : python_env,
)

include_odp_netlink_macros_h = custom_target(
    'odp-netlink-macros.h',
    input : include_odp_netlink_h,
    output : 'odp-netlink-macros.h',
    command : [
        prog_python,
        meson.project_source_root() + '/build-aux/extract-odp-netlink-macros-h.py',
        '@INPUT@',
    ],
    capture : true,
    env : python_env,
)


headers_str = run_command('python3', '-c', '''import pathlib
headers = pathlib.Path("").rglob("*.h")
for f in headers:
    print(f)
''',
    check: true)
inst_headers = headers_str.stdout().strip().split('\n')

_noinst_headers = []

dirs = ['linux',
    #'openflow',
    'openvswitch',
    #'sparse',
    'windows']

foreach d : dirs
    noinst_hdr = []
    subdir(d)
    foreach f: noinst_hdr
        _noinst_headers += join_paths(d, f)
    endforeach
endforeach


_inst_headers = []
foreach x : inst_headers
    if x not in _noinst_headers
        _inst_headers += x
    endif
endforeach


inst_headers = _inst_headers
install_headers(inst_headers,
    preserve_path: true,
)