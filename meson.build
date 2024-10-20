project('librsync', 'c',
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

librsync_defines = {
    'BUILD_RDIFF': 'OFF',
}

pyitc_pyext_name = '_@0@'.format(meson.project_name())

c_compiler = meson.get_compiler('c')
python = import('python').find_installation(pure: false)

cmake = import('cmake')
librsync_options = cmake.subproject_options()
librsync_options.add_cmake_defines(librsync_defines)
librsync_proj = cmake.subproject(
    'librsync',
    options: librsync_options,
)
