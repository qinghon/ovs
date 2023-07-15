# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2021 VMware, Inc.

sources = files(
    'ovs-appctl.c',
)
exdeps = [global_exdeps]
exldflags = []
if have_dpdk
    exdeps += libdpdk
    exldflags += libdpdk_ldflags
endif
deps = [exdeps]

if build_machine.system() == 'linux'
    deps += m_dep
endif

executable('ovs-appctl', sources,
  dependencies : deps,
  include_directories : global_inc,
  link_args : ['-Wl,--no-undefined', ] + exldflags,
  link_with : openvswitch,
  install : true,
  install_dir:  'bin',
)

sources = files(
    'ovs-testcontroller.c',
)



executable('ovs-testcontroller', sources,
  dependencies : deps,
  include_directories : global_inc,
  link_args : ['-Wl,--no-undefined'] + exldflags,
  link_with : openvswitch,
  install : true,
  install_dir:  'bin',
)

sources = files(
    'ovs-dpctl.c',
)

sources += [
	include_odp_netlink_h,
]

executable('ovs-dpctl', sources,
  dependencies : deps,
  include_directories : global_inc,
  link_args : ['-Wl,--no-undefined'] + exldflags,
  link_with : openvswitch,
  install : true,
  install_dir:  'bin',
)

sources = files(
    'ovs-ofctl.c',
)

sources += [
	include_odp_netlink_h,
]

executable('ovs-ofctl', sources,
  dependencies : deps,
  include_directories : global_inc,
  link_args : ['-Wl,--no-undefined'] + exldflags,
  link_with : [ openvswitch, ofproto ],
  install : true,
  install_dir:  'bin',
)

sources = files(
    'ovs-vsctl.c',
)

sources += lib_vswitch_idl_h

executable('ovs-vsctl', sources,
  dependencies : deps,
  include_directories : global_inc,
  link_args : ['-Wl,--no-undefined', ] + exldflags,
  link_with : openvswitch,
  install : true,
  install_dir:  'bin',
)

configure_file(input : 'ovs-parse-backtrace.in',
  output : 'ovs-parse-backtrace',
  configuration : conf_dir,
  install_dir: 'bin'
  )

conf_pki = configuration_data()
conf_pki.merge_from(conf_dir)

configure_file(input: 'ovs-pki.in', output : 'ovs-pki', configuration : conf_pki, install_dir: 'bin')


configure_file(input: 'ovs-vlan-test.in', output : 'ovs-vlan-test', configuration : conf_dir, install_dir: 'bin')
configure_file(input: 'ovs-tcpundump.in', output : 'ovs-tcpundump', configuration : conf_dir, install_dir: 'bin')
configure_file(input: 'ovs-tcpdump.in', output : 'ovs-tcpdump', configuration : conf_dir, install_dir: 'bin')
configure_file(input: 'ovs-pcap.in', output : 'ovs-pcap', configuration : conf_dir, install_dir: 'bin')
configure_file(input: 'bugtool/ovs-bugtool.in', output : 'ovs-bugtool', configuration : conf_dir, install_dir: 'sbin')
configure_file(input: 'ovs-lib.in', output : 'ovs-lib', configuration : conf_dir, install_dir: 'share/openvswitch/scripts')
configure_file(input: 'ovs-ctl.in', output : 'ovs-ctl', configuration : conf_dir, install_dir: 'share/openvswitch/scripts')
configure_file(input: 'ovs-check-dead-ifs.in', output : 'ovs-check-dead-ifs', configuration : conf_dir, install_dir: 'share/openvswitch/scripts')
configure_file(input: 'ovs-kmod-ctl.in', output : 'ovs-kmod-ctl', configuration : conf_dir, install_dir: 'share/openvswitch/scripts')
configure_file(input: 'ovs-dpctl-top.in', output : 'ovs-dpctl-top', configuration : conf_dir, install_dir: 'bin')
configure_file(input: 'ovs-l3ping.in', output : 'ovs-l3ping', configuration : conf_dir, install_dir: 'bin')
configure_file(input: 'ovs-test.in', output : 'ovs-test', configuration : conf_dir, install_dir: 'bin')

install_data(sources: 'ovs-appctl-bashcomp.bash', install_dir : '/etc/bash_completion.d')
install_data(sources: 'ovs-vsctl-bashcomp.bash', install_dir : '/etc/bash_completion.d')
install_data(sources: 'ovs-docker', install_dir : 'bin')
install_data(sources: 'ovs-save', install_dir : 'share/openvswitch/scripts')
install_subdir('bugtool/plugins', install_dir : 'share/openvswitch/bugtool-plugins', strip_directory : true)
install_data('bugtool/ovs-bugtool-daemons-ver', install_dir : 'share/openvswitch/scripts')
install_data('bugtool/ovs-bugtool-fdb-show', install_dir : 'share/openvswitch/scripts')
install_data('bugtool/ovs-bugtool-get-dpdk-nic-numa', install_dir : 'share/openvswitch/scripts')
install_data('bugtool/ovs-bugtool-get-port-stats', install_dir : 'share/openvswitch/scripts')
install_data('bugtool/ovs-bugtool-ovs-appctl-dpif', install_dir : 'share/openvswitch/scripts')
install_data('bugtool/ovs-bugtool-ovs-bridge-datapath-type', install_dir : 'share/openvswitch/scripts')
install_data('bugtool/ovs-bugtool-ovs-ofctl-loop-over-bridges', install_dir : 'share/openvswitch/scripts')
install_data('bugtool/ovs-bugtool-ovs-vswitchd-threads-affinity', install_dir : 'share/openvswitch/scripts')
install_data('bugtool/ovs-bugtool-qos-configs', install_dir : 'share/openvswitch/scripts')
install_data('bugtool/ovs-bugtool-tc-class-show', install_dir : 'share/openvswitch/scripts')

man_pages = files(['ovs-kmod-ctl.8'])

man_filein = [
    'ovs-dpctl.8.in',
    'ovs-dpctl-top.8.in',
    'ovs-ofctl.8.in',
    'ovs-testcontroller.8.in',
    'ovs-vsctl.8.in',
    'ovs-pcap.1.in',
]
foreach f:man_filein
    man_pages += configure_file(input: f, output : f.replace('.in', ''), configuration : conf_dir)
endforeach
man_pages += configure_file(input: 'bugtool/ovs-bugtool.8.in', output : 'ovs-bugtool.8', configuration : conf_dir)
install_man(man_pages)

usdt_script = [
'usdt-scripts/bridge_loop.bt',
'usdt-scripts/dpif_nl_exec_monitor.py',
'usdt-scripts/reval_monitor.py',
'usdt-scripts/upcall_cost.py',
'usdt-scripts/upcall_monitor.py',
]

install_data(usdt_script, install_dir: 'share/openvswitch/scripts/usdt')
