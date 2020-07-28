# SPDX-License-Identifier: GPL-2.0

obj-$(CONFIG_KFENCE) := core.o report.o

CFLAGS_kfence-test.o := -g -fno-omit-frame-pointer -fno-optimize-sibling-calls
obj-$(CONFIG_KFENCE_TEST) += kfence-test.o
