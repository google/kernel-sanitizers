obj-y := asan.o report.o stats.o tests.o quarantine.o

CFLAGS_REMOVE_asan.o = -pg -O0 -O1 -O2
KASAN_SANITIZE_asan.o = n
KASAN_SANITIZE_report.o = n
KASAN_SANITIZE_stats.o = n
KASAN_SANITIZE_quarantine.o = n
CFLAGS_asan.o = -O3
