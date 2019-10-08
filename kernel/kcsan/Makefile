# SPDX-License-Identifier: GPL-2.0
KCSAN_SANITIZE := n
KCOV_INSTRUMENT := n

CFLAGS_REMOVE_kcsan.o = $(CC_FLAGS_FTRACE)
CFLAGS_REMOVE_core.o = $(CC_FLAGS_FTRACE)
CFLAGS_REMOVE_atomic.o = $(CC_FLAGS_FTRACE)
CFLAGS_REMOVE_info.o = $(CC_FLAGS_FTRACE)

CFLAGS_kcsan.o = $(call cc-option, -fno-conserve-stack -fno-stack-protector)
CFLAGS_core.o = $(call cc-option, -fno-conserve-stack -fno-stack-protector)
CFLAGS_atomic.o = $(call cc-option, -fno-conserve-stack -fno-stack-protector)
CFLAGS_info.o = $(call cc-option, -fno-conserve-stack -fno-stack-protector)

obj-y := kcsan.o core.o atomic.o info.o report.o
