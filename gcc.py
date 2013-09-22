#!/usr/bin/python

import os
import subprocess
import sys

gcc = '$KASAN_GCC_PATH/gcc'

def should_instrument(filename):
  if filename.startswith('arch/x86/mm/asan/test'):
    return True

  if filename.startswith('arch/x86/mm/asan'):
    return False #loop?
  if filename.startswith('mm/slab'):
    return False #slab.c slab_common.c
  if filename.startswith('arch/x86/vdso'):
    return False #user-space

  if filename.startswith('arch/x86/realmode'):
    return False
  if filename.startswith('arch/x86/boot'):
    return False

  return True

args = sys.argv[1:]
args = [arg for arg in args if arg != '-Wa,--allow-incbin']

files = [arg for arg in args if arg[0] != '-' and arg[0] != '@']
if len(files) > 0:
  filename = files[-1]
  #sys.stderr.write(str(filename) + '\n')
  if should_instrument(filename):
    args.append('-fsanitize=thread')

gcc_args = [gcc] + args
subprocess.call(gcc_args)
