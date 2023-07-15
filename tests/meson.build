
test_idltest_ovsidl = custom_target(
    'test_idltest_ovsidl',
    output : 'idltest.ovsidl',
    input: [ 'idltest.ovsschema', 'idltest.ann'],
    command : [
        prog_python,
        meson.project_source_root() + '/ovsdb/ovsdb-idlc.in',
        #'-C', meson.project_source_root(),
        'annotate',
        '@INPUT0@',
        '@INPUT1@'
    ],
    capture : true ,
    env : python_env,
)

tests_idltest_c = custom_target(
    'tests_idltest_c',
    output : 'idltest.c',
    input: test_idltest_ovsidl,
    command : [
        prog_python,
        meson.project_source_root() + '/ovsdb/ovsdb-idlc.in',
        'c-idl-source',
        '@INPUT@',
    ],
    depends: [test_idltest_ovsidl],
    capture : true ,
    env : python_env,
)
tests_idltest_h = custom_target(
    'tests_idltest_h',
    output : 'idltest.h',
    input: test_idltest_ovsidl,
    command : [
        prog_python,
        meson.project_source_root() + '/ovsdb/ovsdb-idlc.in',
        'c-idl-header',
        '@INPUT@',
    ],
    depends: [test_idltest_ovsidl],
    capture : true ,
    env : python_env,
)

sources = files(
    'ovstest.c',
    'test-aa.c',
    'test-aes128.c',
    'test-atomic.c',
    'test-barrier.c',
    'test-bitmap.c',
    'test-bundle.c',
    'test-byte-order.c',
    'test-ccmap.c',
    'test-classifier.c',
    'test-cmap.c',
    'test-conntrack.c',
    'test-csum.c',
    'test-flows.c',
    'test-hash.c',
    'test-heap.c',
    'test-hindex.c',
    'test-hmap.c',
    'test-id-fpool.c',
    'test-json.c',
    'test-jsonrpc.c',
    'test-list.c',
    'test-lockfile.c',
    'test-mpsc-queue.c',
    'test-multipath.c',
    'test-netflow.c',
    'test-odp.c',
    'test-ofpbuf.c',
    'test-packets.c',
    'test-random.c',
    'test-rcu.c',
    'test-rculist.c',
    'test-reconnect.c',
    'test-rstp.c',
    'test-sflow.c',
    'test-sha1.c',
    'test-skiplist.c',
    'test-stopwatch.c',
    'test-stp.c',
    'test-unixctl.c',
    'test-util.c',
    'test-uuid.c',
    'test-uuidset.c',
    'test-vconn.c',
)
if build_machine.system() != 'windows'
    sources += files('test-unix-socket.c',)
endif
if build_machine.system() == 'linux'
    sources += files('test-netlink-conntrack.c', 'test-netlink-policy.c')
endif

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

executable('ovstest',
  sources + [tests_idltest_h, tests_idltest_c],
  dependencies : deps,
  include_directories : global_inc,
  link_args : ['-Wl,--no-undefined'] + exldflags,
  link_with : [ openvswitch, ofproto, sflow , ovsdb],
)

sources = files('test-lib.c')
executable('test-lib',
  sources + [tests_idltest_h, tests_idltest_c],
  dependencies : deps,
  include_directories : global_inc,
  link_args : ['-Wl,--no-undefined'] + exldflags,
  link_with : [ openvswitch],
)

sources = files('test-ovsdb.c')
executable('test_ovsdb',
  sources + [tests_idltest_h, tests_idltest_c],
  dependencies : deps,
  include_directories : global_inc,
  link_args : ['-Wl,--no-undefined'] + exldflags,
  link_with : [ openvswitch, ovsdb],
)

executable('test_stream',
  files('test-stream.c'),
  dependencies : deps,
  include_directories : global_inc,
  link_args : ['-Wl,--no-undefined'] + exldflags,
  link_with : [ openvswitch],
)
test_strtok_r = executable('test_strtok_r',
  files('test-strtok_r.c'),
  dependencies : deps,
  include_directories : global_inc,
  link_args : ['-Wl,--no-undefined'] + exldflags,
)
test_props = executable('test_props',
  files('test-type-props.c'),
  dependencies : deps,
  include_directories : global_inc,
  link_args : ['-Wl,--no-undefined'] + exldflags,
)


# test case
test('type props', test_props)

envdata = environment()
python_paths = [meson.current_build_dir(), join_paths(meson.project_source_root(), 'python')]
exec_paths = [meson.current_build_dir(), meson.current_source_dir()]
envdata.append('SRC_DIR', meson.current_source_dir())
envdata.append('PYTHONPATH', python_paths)
envdata.append('PATH', exec_paths)
envdata.append('TESTS_BUILDDIR', meson.current_build_dir())

test_suites = [
    'test_strtok_r.py',
    'test_library.py',
]

foreach suite:test_suites
    test(
      'python unittests_' + suite,
      prog_python,
      args: ['-m', 'unittest', 'discover',
      '-s', join_paths(meson.project_source_root(), 'tests')] + ['-p' , suite],
      env: envdata,
      timeout: 300,
    )
endforeach
