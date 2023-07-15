if get_option('disable-doc')
    subdir_done()
endif

man_files_ = [
    'ovs-actions.7',
    'ovs-appctl.8',
    'ovs-ctl.8',
    'ovs-l3ping.8',
    'ovs-parse-backtrace.8',
    'ovs-pki.8',
    'ovs-sim.1',
    'ovs-tcpdump.8',
    'ovs-tcpundump.1',
    'ovs-test.8',
    'ovs-vlan-test.8',
    'ovsdb-server.7',
    'ovsdb.5',
    'ovsdb.7',
]
man_file_ins_dir = []

man_files = []
man_files_rst = []

foreach f:man_files_
    man_file_ins_dir += ['man']
    man_files_rst += join_paths('ref', f+'.rst')
    man_files += join_paths(meson.current_build_dir(), 'man', f)
endforeach

sphinx = find_program('sphinx-build-3', required : false)
if not sphinx.found()
    sphinx = find_program('sphinx-build', required : not get_option('disable-doc'))
endif

if sphinx.found()
    custom_target('documentation-html',
        command: [sphinx, '-b', 'html', '-W', '-n', meson.current_source_dir(), '@OUTPUT@'],
        output: 'html',
        install: true,
        install_dir: '/usr/share/doc/openvswitch-doc'
    )
    custom_target('documentation-man',
        command: [sphinx, '-b', 'man', '-W', '-n', meson.current_source_dir(), '@OUTPUT@'],
        output: 'man',
        install: true,
        install_dir: 'share',
    )

endif
