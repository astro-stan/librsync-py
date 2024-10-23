project('librsync_py', 'c',
    version : '0.1.0',
    license: ['AGPL-3.0'],
    license_files: ['LICENSE'],
    meson_version: '>=1.4.0',
    subproject_dir: 'vendor',
    default_options : [
        'prefix=' + meson.current_build_dir(),
        'c_std=c99',
        'werror=true',
        # Do not respect the `limited_api` arg of the
        # `extension_module` call by default
        'python.allow_limited_api=false',
    ]
)

librsync_cmake_defines = {
    'BUILD_RDIFF': 'OFF', # Do not build the `rdiff` target
    'BUILD_SHARED_LIBS':'OFF',
    'CMAKE_POSITION_INDEPENDENT_CODE': 'ON',
    'CMAKE_C_FLAGS_RELEASE': '-O' + get_option('optimization'),
    'CMAKE_C_FLAGS_DEBUG': '-O' + get_option('optimization'),
}

if get_option('debug') == true
    librsync_cmake_defines += {'CMAKE_BUILD_TYPE': 'Debug'}
else
    librsync_cmake_defines += {'CMAKE_BUILD_TYPE': 'Release'}
endif

librsync_cmake_defines_list = []
# Aggregate defines
foreach name, value: librsync_cmake_defines
    librsync_cmake_defines_list += ['-D' + name + '=' + value]
endforeach

# A set of defines to pass to the preprocessor when generating the librsync_py C ext
# code with CFFI. These are used to fool the preprocessor that certain system
# headers have already been included and preprocessed (when in fact they haven't).
#
# The goal is to reduce the unrelevant noise present in the outputted headers
# coming from the expansion of system includes in the source librsync headers.
# Otherwise `pycparser` can get confused and fail.
librsync_pyext_preproccessing_c_args = [
     # Define so that `LIBRSYNC_EXPORT` gets defined as an empty macro
     # inside `librsync_export.h`. This is needed when preprocessing with
     # pycparser, as it doesn't currently support `__attribute__` directives.
    '-DLIBRSYNC_STATIC_DEFINE',

    '-D_STDIO_H', # Define for stdio.h on gcc
    '-D_STDIO_H_', # Define for stdio.h on Xcode clang

    # '-D_TIME_H', # Define for time.h on gcc
    # '-D_TIME_H_', # Define for time.h on Xcode clang

    '-D_GCC_WRAP_STDINT_H', # Define for stdint.h on mingw64
    '-D__CLANG_STDINT_H', # Define for stdint.h on Xcode clang
]

librsync_py_pyext_name = '_@0@'.format(meson.project_name())

c_compiler = meson.get_compiler('c')
echo = find_program('echo', required: true)
python = import('python').find_installation(pure: false)
header_cleaner_script = files('header_cleaner.py')
# ffi_generator_script = files('ffi_generator.py')

cmake = import('cmake')
librsync_options = cmake.subproject_options()
librsync_options.add_cmake_defines(librsync_cmake_defines)
librsync_proj = cmake.subproject(
    'librsync',
    options: librsync_options,
)
# message(librsync_proj.target_list())
librsync_dep = librsync_proj.dependency('rsync')

librsync_inc_dir = meson.current_source_dir() / 'vendor' / 'librsync' / 'src'

header_pp_config = {
    'librsync_pp.h': {
        'source_header': librsync_inc_dir / 'librsync.h',
        'clean_script_args': [
            '--allowlist', 'librsync.h', 'time_t.h', 'types.h'
        ]
    },
    'job_pp.h': {
        'source_header': librsync_inc_dir / 'job.h',
        'clean_script_args': [
            '--allowlist', 'job.h'
        ]
    },
    'sumset_pp.h': {
        'source_header': librsync_inc_dir / 'sumset.h',
        'clean_script_args': [
            '--allowlist', 'sumset.h'
        ]
    },
}

foreach header_pp_name, config: header_pp_config
    # Preprocess header
    header_pp = configure_file(
        command: [
            c_compiler,
            '-I@0@'.format(librsync_inc_dir),
            '-E',
            librsync_pyext_preproccessing_c_args,
            librsync_cmake_defines_list,
            config['source_header'],
        ],
        capture: true,
        output: header_pp_name
    )

    # Clean header
    header_pp = configure_file(
        command: [
            python,
            header_cleaner_script,
            '@INPUT@',
            config['clean_script_args']
        ],
        input: [header_pp],
        output: header_pp_name,
    )
endforeach

# # Preprocess librsync.h
# librsync_h_pp = configure_file(
#     command: [
#         c_compiler,
#         '-I@0@'.format(librsync_inc_dir),
#         '-E',
#         librsync_pyext_preproccessing_c_args,
#         librsync_header,
#     ],
#     capture: true,
#     output: 'librsync_pp.h',
# )

# # Preprocess job.h
# librsync_job_h_pp = configure_file(
#     command: [
#         c_compiler,
#         '-I@0@'.format(librsync_inc_dir),
#         '-E',
#         librsync_pyext_preproccessing_c_args,
#         librsync_job_header,
#     ],
#     output: 'job_pp.h',
#     capture: true,
# )

# # Preprocess sumset.h
# librsync_sumset_h_pp = configure_file(
#     command: [
#         c_compiler,
#         '-I@0@'.format(librsync_inc_dir),
#         '-E',
#         librsync_pyext_preproccessing_c_args,
#         librsync_sumset_header,
#     ],
#     output: 'sumset_pp.h',
#     capture: true,
# )

# # Clean preprocessed librsync_pp.h
# librsync_py_src = configure_file(
#     command: [
#         python,
#         header_cleaner_script,
#         '@INPUT@',
#         '--allowlist',
#         'librsync.h',
#         'time_t.h',
#         'types.h',
#     ],
#     input: [librsync_h_pp],
#     output: 'librsync_pp.h',
# )

# # Generate the pyext interface using CFFI
# librsync_py_src = configure_file(
#     command: [
#         python,
#         ffi_generator_script,
#         '--update-files',
#         '--module-name',
#         librsync_py_pyext_name,
#         '@INPUT@',
#         '--header-allowlist',
#         'sumset.h',
#         'job.h',
#         '@0@:librsync.h'.format(librsync_h_pp),
#         '@0@:time.h'.format(librsync_h_pp),
#     ],
#     input: [librsync_h_pp, librsync_job_h_pp, librsync_sumset_h_pp],
#     output: '@0@.c'.format(librsync_py_pyext_name)
# )

# # Compile the pyext
# python.extension_module(
#     librsync_py_pyext_name,
#     librsync_py_src,
#     dependencies: [
#         librsync_dep,
#     ],
#     subdir: meson.project_name(),
#     install: true,
#     # CFFI uses the limited API when possible.
#     # The exact rules for when this happens are a little muddy and depend
#     # on both python and C preprocessor logic.
#     # Define what the minimum supported limited API version is here, but toggle
#     # whether it should be respected or ignored via the `python.allow_limited_api`
#     # option.
#     #
#     # CFFI docs state 3.5+, but this module targets 3.8+.
#     limited_api: '3.8',
# )

# python.install_sources(
#     files([
#         'src' / 'librsync_py'/ '__init__.py'
#     ]),
#     subdir: meson.project_name(),
# )
