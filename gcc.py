#!/usr/bin/python

import os
import subprocess
import sys

gcc = '../gcc/install/bin/gcc'

def should_exclude(filename):
  if filename.startswith('arch/x86/mm/asan/error'):
    return False
  if filename.startswith('arch/x86/mm/asan'):
    return True #loop?
  if filename.startswith('mm/slab'):
    return True #slab.c slab_common.c
  if filename.startswith('fs/dcache.c'):
    return True #dentry_string_cmp()
  if filename.startswith('net/ipv4/fib_trie.c'):
    return True #leaf_walk_rcu()
  if filename.startswith('arch/x86/vdso'):
    return True #asan_dummies? (not ssh'able)

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
