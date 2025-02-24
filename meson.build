project('librsync_py', 'c',
    version : '0.1.0', # Keep in sync with the version in pyproject.toml
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

c_compiler = meson.get_compiler('c')
cmake = import('cmake')
python = import('python').find_installation(pure: false)
# Script used to clean the preprocessed librsync headers
header_cleaner_script = files('header_cleaner.py')
# Script used to generate the pyext FFI interface
ffi_generator_script = files('ffi_generator.py')
# The path to the librsync include dir
librsync_inc_dir = meson.current_source_dir() / 'vendor' / 'librsync' / 'src'

librsync_py_pyext_name = '_@0@'.format(meson.project_name())
librsync_py_pyext_c_name = '@0@.c'.format(librsync_py_pyext_name)
librsync_py_pyext_h_name = '@0@.h'.format(librsync_py_pyext_name)
time_t_size_tester_c_name = 'time_t_size_tester.c'
time_t_size_tester_bin_name = 'time_t_size_tester'

# C_args to pass to cmake when building librsync
librsync_cmake_defines = {
    'BUILD_RDIFF': 'OFF', # Do not build the `rdiff` target
    'BUILD_SHARED_LIBS':'OFF',
    'CMAKE_POSITION_INDEPENDENT_CODE': 'ON',
     # When compiling with MingGW-W64, `-Wformat` raises a compiler error
     # when printing a `size_t` type, even though the correct format specifier
     # is used (`%Iu`) by librsync. Normally disabling this flag to ignore the
     # error is bad, but in this case it _should_ be okay because:
     # - It is likely a false-positive (MS C runtime supports printing `size_t`:
     #   https://learn.microsoft.com/en-us/cpp/c-runtime-library/format-specification-syntax-printf-and-wprintf-functions?view=msvc-170#size-prefixes-for-printf-and-wprintf-format-type-specifiers)
     # - The relevant code is not used by the Python FFI wrapper functions
    'CMAKE_C_FLAGS_RELEASE': '-O' + get_option('optimization') + ' -Wno-format',
    'CMAKE_C_FLAGS_DEBUG': '-O' + get_option('optimization') + ' -Wno-format',
}
if get_option('debug') == true
    librsync_cmake_defines += {'CMAKE_BUILD_TYPE': 'Debug'}
else
    librsync_cmake_defines += {'CMAKE_BUILD_TYPE': 'Release'}
endif

# A list of extra C headers to pass the the CFFI generator script
extra_cffi_header_definitions = files([
    'src' / meson.project_name() / '_pyext' / '_librsync_py_extra.h'
])

# A set of defines to pass to the preprocessor when preprocessing the librsync
# headers. These are used to fool the preprocessor that certain system
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
]

# The headers to be used when generating the Pyext FFI
# Editing this may require editing the header_pp_config variable
librsync_pyext_headers = [
    'librsync.h',
    'job.h',
    'sumset.h'
]

# Generate the time_t size tester
time_t_size_tester_c = configure_file(
    command: [
        python,
        '-c',
        'from pathlib import Path; Path("""@0@""").write_text("""@1@""")'.format(
            time_t_size_tester_c_name,
            '''#include <stdio.h>
               #include <time.h>
               int main()
               {
                    printf("%u", (unsigned int)sizeof(time_t));
                    return 0;
               }'''
        )
    ],
    output: time_t_size_tester_c_name,
)

# Compile the time_t size tester
time_t_size_tester_bin = configure_file(
    command: [
        c_compiler,
        '-o',
        time_t_size_tester_bin_name,
        time_t_size_tester_c
    ],
    output: time_t_size_tester_bin_name,
)

# Compute time_t size
computed_time_t_size = run_command(time_t_size_tester_bin, check: true).stdout().strip()

# Generate the pyext header
librsync_py_h = configure_file(
    command: [
        python,
        '-c',
        'from pathlib import Path; Path("""@0@""").write_text("""@1@""")'.format(
            librsync_py_pyext_h_name,
            '#include "' + '"\n#include "'.join(librsync_pyext_headers) + '\"'
        )
    ],
    output: librsync_py_pyext_h_name,
)

# Configuration for the preprocessing of the headers
# Editing this may require editing librsync_pyext_headers
header_pp_config = {
    '_librsync_py_pp.h': {
        'source_header': librsync_py_h.full_path(),
        'clean_script_args': [
            '--header-allowlist',
                # system headers
                'stdint.h',
                'bits/types.h',
                # librsync headers
                'librsync.h',
                'sumset.h',
                'job.h',
                'hashtable.h',
                'checksum.h',
                'mdfour.h',
                'rollsum.h',
                'rabinkarp.h',

            '--line-allowlist',
                'sumset.h:35:86',
                'hashtable.h:128:147',
                'checksum.h:35:62',
                'rollsum.h:36:40',
                'rabinkarp.h:56:60',

            '--substitutions',
                ':__extension__:'
        ],
    },
}

librsync_options = cmake.subproject_options()
librsync_options.add_cmake_defines(librsync_cmake_defines)
librsync_proj = cmake.subproject(
    'librsync',
    options: librsync_options,
)
# message(librsync_proj.target_list())
librsync_dep = librsync_proj.dependency('rsync')

# Build the cmake defines dict as a list
librsync_cmake_defines_as_list = []
foreach name, value: librsync_cmake_defines
    librsync_cmake_defines_as_list += ['-D' + name + '=' + value]
endforeach

# The preprocessed header objects
header_pp_list = []

foreach header_pp_name, config: header_pp_config
    # Preprocess header
    header_pp = configure_file(
        command: [
            c_compiler,
            '-I@0@'.format(librsync_inc_dir),
            '-E',
            librsync_pyext_preproccessing_c_args,
            librsync_cmake_defines_as_list,
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

    header_pp_list += [header_pp]
endforeach

# Generate the pyext interface using CFFI
librsync_py_c = configure_file(
    command: [
        python,
        ffi_generator_script,
        '--define-time-t',
        '--time-t-sizeof-hint',
        computed_time_t_size,
        '--module-name',
        librsync_py_pyext_name,
        '--module-header',
        librsync_py_h.full_path(),
        '@INPUT@',
        extra_cffi_header_definitions,
    ],
    input: header_pp_list,
    output: '@0@.c'.format(librsync_py_pyext_name)
)

# Compile the pyext
python.extension_module(
    librsync_py_pyext_name,
    librsync_py_c,
    dependencies: [
        librsync_dep,
    ],
    subdir: meson.project_name(),
    install: true,
    # CFFI uses the limited API when possible.
    # The exact rules for when this happens are a little muddy and depend
    # on both python and C preprocessor logic.
    # Define what the minimum supported limited API version is here, but toggle
    # whether it should be respected or ignored via the `python.allow_limited_api`
    # option.
    #
    # CFFI docs state 3.5+, but this module targets 3.8+.
    limited_api: '3.8',
)

python.install_sources(
    files([
        'src' / meson.project_name() / '__init__.py',
        'src' / meson.project_name() / 'common.py',
        'src' / meson.project_name() / 'exceptions.py',
        'src' / meson.project_name() / 'stats.py',
        'src' / meson.project_name() / 'stream.py',
        'src' / meson.project_name() / 'whole.py',
    ]),
    subdir: meson.project_name(),
)

python.install_sources(
    files([
        'src' / meson.project_name() / '_internals' / '__init__.py',
        'src' / meson.project_name() / '_internals' / 'wrappers.py',
    ]),
    subdir: meson.project_name() / '_internals',
)
