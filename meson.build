# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2021 VMware, Inc.

# Meson Newer Version Justification
# Version 0.56.0: enables 'project_build_root' for 'meson' object
# Version 0.57.0: enables use of 'env' in 'custom_target'
# Version 0.59.0: enables use of 'feed' in 'custom_target'

project('openvswitch', 'C', 'cpp',
        version: '3.1.90',
        license: 'Apache2.0',
        default_options: [
                          'buildtype=release',
                          'default_library=static',
                          'warning_level=2',
                         ],
        meson_version: '>= 0.63.0'
)

fs = import('fs')
pkg = import('pkgconfig')

as_version = meson.project_version()
ver_arr = as_version.split('.')

as_current_version  = ver_arr[0]
as_revision_version = ver_arr[1]
as_age_version      = ver_arr[2]

as_soversion = '0'
conf_soversion = configuration_data()
conf_soversion.set('SOVERSION', as_soversion)

cc = meson.get_compiler('c')

prog_python = import('python').find_installation('python3')

python_env = environment()
python_env.set('PYTHONPATH', meson.project_source_root() + '/python')
# Prevent creation of *.pyc files in 'python/build/__pycache__' directory
python_env.set('PYTHONDONTWRITEBYTECODE', 'yes')

conf_dir = configuration_data()
conf_dir.set('LOGDIR', '/var/log/openvswitch')
conf_dir.set('RUNDIR', '/var/run/openvswitch')
conf_dir.set('DBDIR', get_option('sysconfdir') + '/openvswitch')
conf_dir.set('bindir', get_option('bindir'))
conf_dir.set('sbindir', get_option('sbindir'))
conf_dir.set('sysconfdir', get_option('sysconfdir'))
conf_dir.set('pkgdatadir', get_option('datadir') + '/openvswitch')
conf_dir.set('VERSION', '"' + as_version + '"')
conf_dir.set('PYTHON3', prog_python.full_path())
conf_dir.set('PKIDIR', get_option('localstatedir') + '/lib/openvswitch/pki')

cdata = configuration_data()
global_exdeps = []

if build_machine.system() == 'linux'
    m_dep = cc.find_library('m', required : true)
    thread_dep = dependency('threads', required : true)
    cdata.set('_GNU_SOURCE', 1)
endif

if build_machine.system() == 'windows'
    if get_option('with-pthread') == 'optval'
        error('"with-pthread" is a required option on Windows')
    endif
    win_pthread_path = get_option('with-pthread')
    win_pthread_dirs = [
        win_pthread_path,
    ]
    # Some may place DLL and LIB files under 'lib' subfolder
    if fs.is_dir(win_pthread_path + '\lib')
        win_pthread_dirs += win_pthread_path + '\lib'
    endif
    thread_dep = cc.find_library(
        'pthreadVC3',
        dirs : win_pthread_dirs,
        required : true,
    )
    windows_libs = [
        'Ws2_32', # Resolve symbols for Winsock
        'WbemUuid',
        'Shlwapi',
        'Iphlpapi',
    ]
    windows_deps = []
    foreach w : windows_libs
        windows_deps += cc.find_library(
            w,
            required : true,
        )
    endforeach
endif

cxx = meson.get_compiler('cpp')
cdata.set('HAVE_CXX11', 1)


crypto_dep = dependency('openssl', required: false, fallback: ['openssl', 'openssl_dep'])
if crypto_dep.found()
    cdata.set('HAVE_OPENSSL', 1)
    global_exdeps += crypto_dep
endif

have_dpdk = false

if get_option('with-dpdk') != 'disable'
    have_dpdk = true
    libdpdk_static = get_option('with-dpdk') == 'static'
    libdpdk = dependency('libdpdk', required : true, static: libdpdk_static )
    cdata.set('DPDK_NETDEV', 1)
    cdata.set('HAVE_RTE_CONFIG_H', 1)
    if libdpdk_static
        libdpdk_ldflags = ['-Wl,--allow-multiple-definition']
    else
        libdpdk_ldflags = []
    endif
    vhost_numa = cc.compiles('#include <rte_config.h>\nint main(){return RTE_LIBRTE_VHOST_NUMA;}', dependencies: [libdpdk] , name: 'numa')
    dpdk_huge = cc.compiles('#include <rte_config.h>\nint main(){return RTE_EAL_NUMA_AWARE_HUGEPAGES;}', dependencies: [libdpdk], name: 'dpdk hugepages')
    if  vhost_numa and dpdk_huge
        cdata.set('VHOST_NUMA', 1)
    endif

endif

check_headers = [
  ['HAVE_BITS_FLOATN_COMMON_H', 'bits/floatn/common.h'],
  ['HAVE_DLFCN_H', 'dlfcn.h'],
  ['HAVE_INTTYPES_H', 'inttypes.h'],
  ['HAVE_LIBUNWIND_H', 'libunwind.h'],
  ['HAVE_LINUX_IF_ETHER_H', 'linux/if_ether.h'],
  ['HAVE_LINUX_NET_NAMESPACE_H', 'linux/net_namespace.h'],
  ['HAVE_LINUX_PERF_EVENT_H', 'linux/perf_event.h'],
  ['HAVE_LINUX_TYPES_H', 'linux/types.h'],
  ['HAVE_MEMORY_H', 'memory.h'],
  ['HAVE_MNTENT_H', 'mntent.h'],
  ['HAVE_NET_IF_MIB_H', 'net/if_mib.h'],
  ['HAVE_NETLINK', 'linux/netlink.h'],
  ['HAVE_RTE_CONFIG_H', 'rte_config.h'],
  ['HAVE_STDATOMIC_H', 'stdatomic.h'],
  ['HAVE_STDINT_H', 'stdint.h'],
  ['HAVE_STDIO_H', 'stdio.h'],
  ['HAVE_STDLIB_H', 'stdlib.h'],
  ['HAVE_STRINGS_H', 'strings.h'],
  ['HAVE_STRING_H', 'string.h'],
  ['HAVE_SYS_STATVFS_H', 'sys/statvfs.h'],
  ['HAVE_SYS_STAT_H', 'sys/stat.h'],
  ['HAVE_SYS_TYPES_H', 'sys/types.h'],
  ['HAVE_UNISTD_H', 'unistd.h'],
  ['HAVE_VALGRIND_VALGRIND_H', 'valgrind/valgrind.h'],
]

foreach h : check_headers
  if cc.has_header(h.get(1))
    cdata.set(h.get(0), 1)
  endif
endforeach

check_functions = [
# check token ['HAVE_AF_XDP']
# check token ['HAVE_ATOMIC']
  ['HAVE_BACKTRACE', 'backtrace', '#include <execinfo.h>', [] ],
  ['HAVE_CLOCK_GETTIME', 'clock_gettime', '#include<time.h>', []],
  ['HAVE_DECL_MALLOC_TRIM', 'malloc_trim', '#include <malloc.h>', []],
# check token ['HAVE_DECL_RTE_EAL_NUMA_AWARE_HUGEPAGES']
# check token ['HAVE_DECL_RTE_LIBRTE_VHOST_NUMA']
  ['HAVE_DECL_STRERROR_R', 'strerror_r', '#include <string.h>', [] ],
# check token ['HAVE_DECL_SYS_SIGLIST']
# check token ['HAVE_GCC4_ATOMICS']
  ['HAVE_GETLOADAVG', 'getloadavg', '#include<stdlib.h>', []],
  ['HAVE_GETMNTENT_R', 'getmntent_r', '#include<mntent.h>', []],
# check token ['HAVE_GLIBC_PTHREAD_SETNAME_NP']
# check token ['HAVE_IF_DL']
# check token ['HAVE_LIBCAPNG']
# check token ['HAVE_LIBSOCKET']
['HAVE_MLOCKALL', 'mlockall', '#include <sys/mman.h>', []],
# check token ['HAVE_NETBSD_PTHREAD_SETNAME_NP']
# check token ['HAVE_NETLINK']
# check token ['HAVE_NLA_BITFIELD32']
# check token ['HAVE_OPENSSL']
  ['HAVE_POSIX_MEMALIGN', 'posix_memalign', '#include<stdlib.h>', []],
# check token ['HAVE_PRAGMA_MESSAGE']
  ['HAVE_PTHREAD_SET_NAME_NP', 'pthread_set_name_np', '#include<pthread.h>', []],
  ['HAVE_PTHREAD_SPIN_LOCK', 'pthread_spin_lock', '#include <pthread.h>', []],
  ['HAVE_SENDMMSG', 'sendmmsg', '#include<sys/socket.h>', ['-D_GNU_SOURCE']],
  ['HAVE_STATVFS', 'statvfs', '#include<sys/statvfs.h>', []],
  ['HAVE_STRERROR_R', 'strerror_r', '#include<string.h>', []],
  ['HAVE_STRNLEN', 'strnlen', '#include<string.h>', []],
# check token ['HAVE_STRTOK_R_BUG']
# check token ['HAVE_STRUCT_IFREQ_IFR_FLAGSHIGH']
# check token ['HAVE_STRUCT_SOCKADDR_IN6_SIN6_SCOPE_ID']
# check token ['HAVE_STRUCT_STAT_ST_MTIMENSEC']
# check token ['HAVE_STRUCT_STAT_ST_MTIM_TV_NSEC']
# check token ['HAVE_STRUCT_TCF_T_FIRSTUSE']
# check token ['HAVE_STRUCT_TIMESPEC']
# check token ['HAVE_TCA_MPLS_TTL']
# check token ['HAVE_TCA_PEDIT_KEY_EX_HDR_TYPE_UDP']
# check token ['HAVE_TCA_POLICE_PKTRATE64']
# check token ['HAVE_TCA_SKBEDIT_FLAGS']
# check token ['HAVE_TCA_TUNNEL_KEY_ENC_TTL']
# check token ['HAVE_TCA_VLAN_PUSH_VLAN_PRIORITY']
# check token ['HAVE_VIRTIO_TYPES']
# check token ['HAVE_XDP_NEED_WAKEUP']
# check token ['HAVE___THREAD']
]

foreach f : check_functions
  if cc.has_function(f.get(1), prefix : f.get(2), args : f.get(3))
    cdata.set(f.get(0), 1)
  endif

endforeach

check_structs = [
  ['HAVE_NLA_BITFIELD32', 'value', 'struct nla_bitfield32', '#include<linux/netlink.h>', []],
  ['HAVE_STRUCT_MMSGHDR_MSG_LEN', 'msg_len', 'struct mmsghdr', '#include<sys/socket.h>', ['-D_GNU_SOURCE']],
  ['HAVE_STRUCT_SOCKADDR_IN6_SIN6_SCOPE_ID', 'sin6_scope_id', 'struct sockaddr_in6', '#include <netinet/in.h>', ['-D_GNU_SOURCE']],
  ['HAVE_STRUCT_STAT_ST_MTIM_TV_NSEC', 'st_mtim.tv_nsec', 'struct stat', '#include <sys/stat.h>', ['-D_GNU_SOURCE']],
  ['HAVE_STRUCT_TCF_T_FIRSTUSE', 'firstuse', 'struct tcf_t', '#include <linux/pkt_cls.h>', ['-D_GNU_SOURCE']],
]

foreach s : check_structs
  if cc.has_member(s.get(2), s.get(1), prefix : s.get(3), args : s.get(4))
    cdata.set(s.get(0), 1)
  endif
endforeach

check_librarys = [
    ['HAVE_LIBCAPNG', 'libcap-ng'],
    ['HAVE_UNWIND' , 'libunwind'],
    ['HAVE_UNBOUND', 'libunbound'],
]
foreach l : check_librarys
    if l.get(1) in get_option('disable-libs').split(',')
        continue
    endif
    lib = dependency(l.get(1), required : false)
    if lib.found()
        cdata.set(l.get(0), 1)
        global_exdeps += lib
    endif
endforeach

check_compiles = [
    {'def': 'HAVE_THREAD_LOCAL','args': { 'code': '#include <threads.h> static thread_local int var; int main() { return var; }', 'name':'thread_local check'} },
    {'def': 'HAVE___THREAD', 'args': { 'code': '#include <threads.h> static __thread int var; int main() { return var; }', 'name': '__thread check'}},
    {'def': 'HAVE_PRAGMA_MESSAGE', 'args': { 'code': '_Pragma("message(\"Checking for pragma message\")")', 'name': '_Pragma check'}},
    {'def': 'HAVE_SCTP_CONNTRACK_HEARTBEATS', 'args':{ 'code': '''#include <linux/netfilter/nfnetlink.h>
                             #include <linux/netfilter/nfnetlink_conntrack.h>
                             #include <linux/netfilter/nf_conntrack_common.h>
                             #include <linux/netfilter/nf_conntrack_sctp.h>
                             int main(){int x = SCTP_CONNTRACK_HEARTBEAT_SENT; return x;}''', 'name': 'sctp check'}} ,
    {'def': 'HAVE_GLIBC_PTHREAD_SETNAME_NP', 'args': { 'code': '#include <pthread.h>\nint main(){pthread_setname_np(pthread_self(), "name");}', 'name': 'glibc pthread_setname_np', 'args': ['-Werror=implicit-function-declaration', '-D_GNU_SOURCE']}},
    {'def': 'HAVE_NETBSD_PTHREAD_SETNAME_NP', 'args': {'code': '#include <pthread.h>\nint main(){pthread_setname_np(pthread_self(), "%s", "name");}', 'name': 'netbsd pthread_setname_np', 'args': ['-Werror=implicit-function-declaration']}},
    {'def': 'OPENSSL_SUPPORTS_SNI', 'args': { 'code': '#include <openssl/ssl.h>\nint main(){return SSL_set_tlsext_host_name(NULL, "name");}', 'name': 'openssl sni', 'args': ['-Werror=implicit-function-declaration']}},
    {'def': 'HAVE_VIRTIO_TYPES', 'args': { 'code': '#include <linux/virtio_types.h>\nint main(){__virtio16 x =  0; return x;}', 'name': 'virtio types'}},
    {'def': 'HAVE_TCA_POLICE_PKTRATE64', 'args': { 'code': '#include <linux/pkt_cls.h>\nint main(){int x = TCA_POLICE_PKTRATE64; return x;}', 'name': 'linux TCA_POLICE_PKTRATE64'}},
    {'def': 'HAVE_TCA_MPLS_TTL', 'args': { 'code': '#include <linux/tc_act/tc_mpls.h>\nint main(){int x = TCA_MPLS_TTL; return x;}', 'name': 'linux TCA_MPLS_TTL'}},
    {'def': 'HAVE_TCA_PEDIT_KEY_EX_HDR_TYPE_UDP', 'args': { 'code': '#include <linux/tc_act/tc_pedit.h>\nint main(){int x = TCA_PEDIT_KEY_EX_HDR_TYPE_UDP; return x;}', 'name': 'linux TCA_PEDIT_KEY_EX_HDR_TYPE_UDP'}},
    {'def': 'HAVE_TCA_SKBEDIT_FLAGS', 'args': { 'code': '#include <linux/tc_act/tc_skbedit.h>\nint main(){int x = TCA_SKBEDIT_FLAGS; return x;}', 'name': 'linux TCA_SKBEDIT_FLAGS'}},
    {'def': 'HAVE_TCA_STATS_PKT64', 'args': { 'code': '#include <linux/gen_stats.h>\nint main(){int x = TCA_STATS_PKT64; return x;}', 'name': 'linux TCA_STATS_PKT64'}},
    {'def': 'HAVE_TCA_TUNNEL_KEY_ENC_TTL', 'args': { 'code': '#include <linux/tc_act/tc_tunnel_key.h>\nint main(){ int x = TCA_TUNNEL_KEY_ENC_TTL; return x;}', 'name': 'linux TCA_TUNNEL_KEY_ENC_TTL'}},
    {'def': 'HAVE_TCA_VLAN_PUSH_VLAN_PRIORITY', 'args': { 'code': '#include <linux/tc_act/tc_vlan.h>\nint main(){ int x = TCA_VLAN_PUSH_VLAN_PRIORITY; return x;}', 'name': 'linux TCA_VLAN_PUSH_VLAN_PRIORITY'}},
]

foreach c : check_compiles

    result = cc.compiles(c['args']['code'],
                         name: c['args'].get('name', []),
                         args: c['args'].get('args', []),
                         dependencies:   c['args'].get('dep', []),
                         )

    if result
        cdata.set(c['def'], 1)
    endif
endforeach

cdata.set('PACKAGE_STRING', '"' + meson.project_name() + ' ' + as_version + '"')
cdata.set('VERSION', '"' + as_version + '"')
cdata.set('sbindir', get_option('sbindir'))

if build_machine.system() == 'windows'
	cdata.set('WIN32', 1)
endif

configure_file(input : 'config.h.meson',
  output : 'config.h',
  configuration : cdata)

header_files = [
    ['lib', 'string.h'],
    ['lib', 'stdio.h'],
]

conf_headers = configuration_data()
conf_headers.set('INCLUDE_NEXT', 'include_next')
conf_headers.set_quoted('NEXT_STDIO_H', 'stdio.h')
conf_headers.set_quoted('NEXT_STRING_H', 'string.h')

foreach h : header_files
    configure_file(
        input : h.get(0) + '/' + h.get(1) + '.in',
        output : h.get(1),
        configuration : conf_headers,
        install_dir: 'include/lib'
    )
endforeach


map_files = [
    ['lib', 'sflow.map'],
    ['lib', 'openvswitch.map'],
    ['ovsdb', 'ovsdb.map'],
    ['ofproto', 'ofproto.map'],
    ['vtep', 'vtep.map'],
]

foreach m : map_files
    configure_file(
        input : m.get(0) + '/' + m.get(1) + '.in',
        output : m.get(1),
        configuration : conf_soversion,
    )
endforeach

ovs_lib_version = '0'
ovs_lib_revision = '0'
ovs_lib_age = '0'

conf_version = configuration_data()
conf_version.set('PACKAGE_STRING', meson.project_name() + ' ' + as_version)
conf_version.set('PACKAGE_VERSION', as_version)
conf_version.set('LT_CURRENT', ovs_lib_version)
conf_version.set('LT_REVISION', ovs_lib_revision)
conf_version.set('LT_AGE', ovs_lib_age)

subdir('include')

# MSR: this is temporary hard-coded
# though values are taken from the 'config.log'
# however, most of it should be coming from
# supplied options and have default values
cin_processing = configuration_data()
cin_processing.set('BANNER', '/* -*- mode: c; buffer-read-only: t -*- */') # this a temporary hack and may break backwards compatability with autotools
cin_processing.set('srcdir', meson.project_source_root())
cin_processing.set_quoted('LOGDIR', '/var/log/openvswitch')
cin_processing.set_quoted('RUNDIR', '/var/run/openvswitch')
cin_processing.set_quoted('DBDIR', '/etc/openvswitch')
cin_processing.set_quoted('bindir', '/bin')
cin_processing.set_quoted('sysconfdir', '/etc')
cin_processing.set_quoted('pkgdatadir', '/usr/share/openvswitch')


subdir('python/ovs')

c_in_files = [
    ['lib', 'dirs.c'],
]

foreach cin : c_in_files
    configure_file(
        input : cin.get(0) + '/' + cin.get(1) + '.in.meson',
        output : cin.get(1),
        configuration : cin_processing,
    )
endforeach

global_inc = include_directories(
    '.',
    'include',
    'lib',
)

if build_machine.system() == 'windows'
    global_inc = include_directories(
		'.',
		'include',
		'lib',
		'include/windows',
		'datapath-windows/include',
		win_pthread_path,
	)
    # Some may place header files under 'include' subfolder
    if fs.is_dir(win_pthread_path + '\include')
        global_inc += win_pthread_path + '\include'
    endif
endif

global_libs = []


add_project_arguments('-Wstrict-prototypes', language : 'c')
add_project_arguments(
    '-Wno-sign-compare',
    '-Wpointer-arith',
    '-Wformat',
    '-Wformat-security',
    '-Wswitch-enum',
    '-Wunused-parameter',
    '-Wbad-function-cast',
    '-Wcast-align',
    '-Wstrict-prototypes',
    '-Wold-style-definition',
    '-Wmissing-prototypes',
    '-Wmissing-field-initializers',
    '-fno-strict-aliasing',
    '-Wswitch-bool',
    '-Wlogical-not-parentheses',
    '-Wsizeof-array-argument',
    '-Wshift-negative-value',
    '-Wshadow',
    language : 'c',
)
check_options_argumens = [
    '-Wno-null-pointer-arithmetic',
    '-Warray-bounds-pointer-arithmetic',
    '-Qunused-arguments',
]

foreach a : check_options_argumens
    if cc.has_argument(a)
        add_project_arguments(a, language : 'c')
    endif
endforeach

install_prefix = '/usr/local/'

lib_ovsdb_server_idl_ovsidl = custom_target(
    'ovsdb-server-idl.ovsidl',
    input : [
        meson.project_source_root() + '/ovsdb/_server.ovsschema',
        meson.project_source_root() + '/lib/ovsdb-server-idl.ann',
    ],
    output : 'ovsdb-server-idl.ovsidl',
    command : [
        prog_python,
        meson.project_source_root() + '/ovsdb/ovsdb-idlc.in',
        'annotate',
        '@INPUT0@',
        '@INPUT1@',
    ],
    capture : true,
    env : python_env,
)

lib_vswitch_idl_ovsidl = custom_target(
    'vswitch-idl.ovsidl',
    input : [
        meson.project_source_root() + '/vswitchd/vswitch.ovsschema',
        meson.project_source_root() + '/lib/vswitch-idl.ann',
    ],
    output : 'vswitch-idl.ovsidl',
    command : [
        prog_python,
        meson.project_source_root() + '/ovsdb/ovsdb-idlc.in',
        'annotate',
        '@INPUT0@',
        '@INPUT1@',
    ],
    capture : true,
    env : python_env,
)

vtep_vtep_idl_ovsidl = custom_target(
    'vtep-idl.ovsidl',
    input : [
        meson.project_source_root() + '/vtep/vtep.ovsschema',
        meson.project_source_root() + '/vtep/vtep-idl.ann',
    ],
    output : 'vtep-idl.ovsidl',
    command : [
        prog_python,
        meson.project_source_root() + '/ovsdb/ovsdb-idlc.in',
        'annotate',
        '@INPUT0@',
        '@INPUT1@',
    ],
    capture : true,
    env : python_env,
)

subdir('lib')
subdir('ofproto')
subdir('utilities')
subdir('vtep')
subdir('vswitchd')
subdir('ovsdb')
#subdir('datapath')
subdir('python')
subdir('tests')
subdir('Documentation')
configure_file(input: 'ipsec/ovs-monitor-ipsec.in', output : 'ovs-monitor-ipsec', configuration : conf_dir, install_dir: 'share/openvswitch/scripts')
