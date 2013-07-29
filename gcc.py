#!/usr/bin/python

import os
import subprocess
import sys

gcc = '../gcc/install/bin/gcc'

def should_exclude(filename):
  if filename.startswith('arch/x86/mm/asan/error'):
    return False
#  return True

  if filename.startswith('arch'):
    return True
  if filename.startswith('drivers'):
    return True
    # a- b- c- d+ v.+
  if filename.startswith('fs'):
    return True
  if filename.startswith('net'):
    return True
  if filename.startswith('security'):
    return True

  if filename.startswith('mm/slab'):
    # slab_common.c slab.c
    return True
  return False

args = sys.argv[1:]

files = [arg for arg in args if arg[0] != '-' and arg[0] != '@']
if len(files) > 0:
  filename = files[-1]
  #sys.stderr.write(str(filename) + '\n')

new_args = []
for arg in args:
  if arg == '-fsanitize=thread' and should_exclude(filename):
    continue
  new_args.append(arg)

gcc_args = [gcc] + new_args
subprocess.call(gcc_args)
