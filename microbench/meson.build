# Copyright 2025 University of California, Riverside
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

project('palladium-ingress', ['cpp', 'c'],
  license: 'Apache-2.0',
  default_options: ['warning_level=3', 'optimization=3', 'buildtype=release'],
  meson_version: '>= 0.61.2'
)

# test if we are on DPU or Host
dependency_doca = dependency('doca-common', required: false)
if dependency_doca.found()
  doca_found = true
  doca_inc = '/opt/mellanox/doca/include'
  c_compiler = meson.get_compiler('c')
  if c_compiler.has_header_symbol(doca_inc + '/doca_build_config.h', 'DOCA_ARCH_DPU', dependencies: dependency_doca)
      is_dpu = true
  else
      is_dpu = false
  endif
  is_host = not is_dpu
  message('DOCA is found')
  if is_dpu
    message('We are on DPU')
  else
    message('We are on Host')
  endif
else
  doca_found = false
  message('DOCA is not found!!')
endif



# Disable compiler warnings
add_project_arguments(['-Wno-unused-parameter', '-Wno-sign-compare', '-Wno-pointer-arith'], language: 'c')
add_project_arguments(['-std=c++20'], language: 'cpp')
#add_project_arguments('-Wno-error=sign-compare', language: 'c')


# Check for deps
libconfig_dep = dependency('libconfig', required: true)
glib_dep = dependency('glib-2.0', required: true)
ibverbs_dep = dependency('libibverbs', required: true)

inc_dirs = include_directories('../RDMA_lib/include', '../DOCA_lib/include')

root_dir = meson.project_source_root()

# Define compiler and linker flags
cflags = ['-MMD', '-MP', '-O3', '-Wall', '-Werror', '-DLOG_USE_COLOR']
ldflags = ['-L/usr/lib64']
ldlibs = ['-lm', '-pthread', '-luuid']

# Compile DOCA_lib
doca_dir = root_dir + '/../DOCA_lib'
doca_build_dir = doca_dir + '/build'
doca_incdir = include_directories('../DOCA_lib/include')

doca_dep = declare_dependency(
  include_directories: doca_incdir,
  link_args: ['-L' + root_dir + '/../DOCA_lib', '-lDOCA_lib', ]
  )
build_doca = custom_target(
    'build_DOCA',
    output: 'DOCA',       # File(s) produced by the script
    command: ['meson', 'setup', doca_build_dir, doca_dir, '&&', 'ninja', '-C', doca_build_dir, '-v'],  # Command to execute the script
    build_by_default: true        # Ensure it runs by default
)
build_doca_dep = declare_dependency(
  sources: build_doca
  )

doca_cpp_binary = [
  ['rdma_server', ['./rdma_server.cpp' ]],
]

doca_cflags = [
	'-Wno-missing-braces',
	'-Wno-missing-field-initializers',
    '-Wno-pedantic',
    '-Wno-unused-function',
    '-Wno-deprecated-declarations',
    '-D DOCA_ALLOW_EXPERIMENTAL_API',
]

if doca_found
  doca_argp_dep = dependency('doca-argp', required: true)
  doca_comch_dep = dependency('doca-comch', required: true)
  doca_rdma_dep = dependency('doca-rdma', required: true)
  doca_common = dependency('doca-common', required: true)
  doca_dma_dep = dependency('doca-dma', required: true)

  foreach bin : doca_cpp_binary
    executable(bin[0],
      sources: bin[1],
      include_directories: inc_dirs,
      cpp_args: cflags + doca_cflags,
      link_args: ldflags + ldlibs,
      dependencies: [libconfig_dep, glib_dep, ibverbs_dep, doca_dep, build_doca_dep, doca_common, doca_rdma_dep, doca_argp_dep, doca_comch_dep, doca_dma_dep],
      install: false
    )
  endforeach
endif
  
