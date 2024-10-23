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
python = import('python').find_installation(pure: false)
cmake = import('cmake')

librsync_py_pyext_name = '_@0@'.format(meson.project_name())
librsync_py_pyext_c_name = '@0@.c'.format(librsync_py_pyext_name)
librsync_py_pyext_h_name = '@0@.h'.format(librsync_py_pyext_name)

librsync_cmake_defines = {
    'NDEBUG': '1',
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

# Script used to clean the preprocessed librsync headers
header_cleaner_script = files('header_cleaner.py')
# Script used to generate the Pyext FFI interface
ffi_generator_script = files('ffi_generator.py')
# The path to the librsync include dir
librsync_inc_dir = meson.current_source_dir() / 'vendor' / 'librsync' / 'src'

# The headers to be used when generating the Pyext FFI
librsync_pyext_headers = [
    'librsync.h',
    'job.h',
    'sumset.h'
]

# Create the pyext header
librsync_py_h = configure_file(
    command: [
        python,
        '-c',
        'from pathlib import Path; Path("""@0@""").write_text("""@1@""")'.format(
            librsync_py_pyext_h_name,
            '#include "' + '"\n#include "'.join(librsync_pyext_headers) + '\"'
        )
    ],
    output: librsync_py_pyext_h_name
)

# Configuration for the preprocessing of the headers
header_pp_config = {
    '_librsync_py_pp.h': {
        'source_header': librsync_py_h.full_path(),
        'clean_script_args': [
            '--header-allowlist',
                # System headers
                'time_t.h',
                'types.h',
                'stdbool.h',
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

        ]
    }
    # 'librsync_pp.h': {
    #     'source_header': librsync_inc_dir / 'librsync.h',
    #     'clean_script_args': [
    #         '--header-allowlist', 'librsync.h', 'time_t.h', 'types.h'
    #     ]
    # },
    # 'sumset_pp.h': {
    #     'source_header': librsync_inc_dir / 'sumset.h',
    #     'clean_script_args': [
    #         '--header-allowlist', 'sumset.h', 'hashtable.h', 'checksum.h', 'stdbool.h'
    #     ]
    # },
    # 'job_pp.h': {
    #     'source_header': librsync_inc_dir / 'job.h',
    #     'clean_script_args': [
    #         '--header-allowlist', 'job.h', 'mdfour.h'
    #     ]
    # },
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
        '--module-name',
        librsync_py_pyext_name,
        '--module-header',
        librsync_py_h.full_path(),
        '@INPUT@',
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
        'src' / 'librsync_py'/ '__init__.py'
    ]),
    subdir: meson.project_name(),
)
