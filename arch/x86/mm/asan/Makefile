obj-y := asan.o report.o stats.o tests.o

CFLAGS_REMOVE_asan.o = -pg -O0 -O1 -O2 -fsanitize=kernel-address
CFLAGS_REMOVE_report.o = -fsanitize=kernel-address
CFLAGS_REMOVE_stats.o = -fsanitize=kernel-address
CFLAGS_asan.o = -O3
