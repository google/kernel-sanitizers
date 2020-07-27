// SPDX-License-Identifier: GPL-2.0
/*
 * Test cases for KFENCE memory safety error detector. Since the interface with
 * which KFENCE's reports are obtained is via the console, this is the output we
 * should verify. For each test case checks the presence (or absence) of
 * generated reports. Relies on 'console' tracepoint to capture reports as they
 * appear in the kernel log.
 *
 * Copyright (C) 2020, Google LLC.
 * Author: Alexander Potapenko <glider@google.com>
 *         Marco Elver <elver@google.com>
 */

#include <kunit/test.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/kfence.h>
#include <linux/mm.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/tracepoint.h>
#include <trace/events/printk.h>

#include "kfence.h"

/* Report as observed from console. */
static struct {
	spinlock_t lock;
	int nlines;
	char lines[2][512];
} observed = {
	.lock = __SPIN_LOCK_UNLOCKED(observed.lock),
};

/* Probe for console output: obtains observed lines of interest. */
static void probe_console(void *ignore, const char *buf, size_t len)
{
	unsigned long flags;
	int nlines;

	spin_lock_irqsave(&observed.lock, flags);
	nlines = observed.nlines;

	if (strnstr(buf, "BUG: KFENCE: ", len) && strnstr(buf, "test_", len)) {
		/*
		 * KFENCE report and related to the test.
		 *
		 * The provided @buf is not NUL-terminated; copy no more than
		 * @len bytes and let strscpy() add the missing NUL-terminator.
		 */
		strscpy(observed.lines[0], buf, min(len + 1, sizeof(observed.lines[0])));
		nlines = 1;
	} else if (nlines == 1 && (strnstr(buf, "at 0x", len) || strnstr(buf, "of 0x", len))) {
		strscpy(observed.lines[nlines++], buf, min(len + 1, sizeof(observed.lines[0])));
	}

	WRITE_ONCE(observed.nlines, nlines); /* Publish new nlines. */
	spin_unlock_irqrestore(&observed.lock, flags);
}

/* Check if a report related to the test exists. */
static bool report_available(void)
{
	return READ_ONCE(observed.nlines) == ARRAY_SIZE(observed.lines);
}

/* Information we expect in a report. */
struct expect_report {
	enum kfence_error_type type; /* The type or error. */
	void *fn; /* Function pointer to expected function where access occurred. */
	char *addr; /* Address at which the bad access occurred. */
};

/* Check observed report matches information in @r. */
static bool report_matches(const struct expect_report *r)
{
	bool ret = false;
	unsigned long flags;
	typeof(observed.lines) expect;
	const char *end;
	char *cur;

	/* Doubled-checked locking. */
	if (!report_available())
		return false;

	/* Generate expected report contents. */

	/* Title */
	cur = expect[0];
	end = &expect[0][sizeof(expect[0]) - 1];
	switch (r->type) {
	case KFENCE_ERROR_OOB:
		cur += scnprintf(cur, end - cur, "BUG: KFENCE: out-of-bounds");
		break;
	case KFENCE_ERROR_UAF:
		cur += scnprintf(cur, end - cur, "BUG: KFENCE: use-after-free");
		break;
	case KFENCE_ERROR_CORRUPTION:
		cur += scnprintf(cur, end - cur, "BUG: KFENCE: memory corruption");
		break;
	case KFENCE_ERROR_INVALID:
		cur += scnprintf(cur, end - cur, "BUG: KFENCE: invalid access");
		break;
	case KFENCE_ERROR_INVALID_FREE:
		cur += scnprintf(cur, end - cur, "BUG: KFENCE: invalid free");
		break;
	}

	scnprintf(cur, end - cur, " in %pS", r->fn);
	/* The exact offset won't match, remove it; also strip module name. */
	cur = strchr(expect[0], '+');
	if (cur)
		*cur = '\0';

	/* Access information */
	cur = expect[1];
	end = &expect[1][sizeof(expect[1]) - 1];

	switch (r->type) {
	case KFENCE_ERROR_OOB:
		cur += scnprintf(cur, end - cur, "Out-of-bounds access at");
		break;
	case KFENCE_ERROR_UAF:
		cur += scnprintf(cur, end - cur, "Use-after-free access at");
		break;
	case KFENCE_ERROR_CORRUPTION:
		cur += scnprintf(cur, end - cur, "Detected corrupted memory at");
		break;
	case KFENCE_ERROR_INVALID:
		cur += scnprintf(cur, end - cur, "Invalid access at");
		break;
	case KFENCE_ERROR_INVALID_FREE:
		cur += scnprintf(cur, end - cur, "Invalid free of");
		break;
	}

	cur += scnprintf(cur, end - cur, " 0x" PTR_FMT, (void *)r->addr);

	spin_lock_irqsave(&observed.lock, flags);
	if (!report_available())
		goto out; /* A new report is being captured. */

	/* Finally match expected output to what we actually observed. */
	ret = strstr(observed.lines[0], expect[0]) && strstr(observed.lines[1], expect[1]);
out:
	spin_unlock_irqrestore(&observed.lock, flags);
	return ret;
}

/* ===== Test cases ===== */

#define TEST_PRIV_WANT_MEMCACHE ((void *)1)

/* Cache used by tests; if NULL, allocate from kmalloc instead. */
static struct kmem_cache *test_cache;

static size_t setup_test_cache(struct kunit *test, size_t size, void (*ctor)(void *))
{
	if (test->priv != TEST_PRIV_WANT_MEMCACHE)
		return size;

	kunit_info(test, "%s: size=%zu, ctor=%ps\n", __func__, size, ctor);

	/*
	 * Use SLAB_NOLEAKTRACE to prevent merging with existing caches. Any
	 * other flag in SLAB_NEVER_MERGE (except SLAB_TYPESAFE_BY_RCU, which
	 * disables KFENCE) also works. Use SLAB_ACCOUNT to allocate via memcg,
	 * if enabled.
	 */
	test_cache = kmem_cache_create("test", size, 1, SLAB_NOLEAKTRACE | SLAB_ACCOUNT, ctor);
	KUNIT_ASSERT_TRUE_MSG(test, test_cache, "could not create cache");

	return size;
}

static void test_cache_destroy(void)
{
	if (!test_cache)
		return;

	kmem_cache_destroy(test_cache);
	test_cache = NULL;
}

/* Must always inline to match stack trace against caller. */
static __always_inline void test_free(void *ptr)
{
	if (test_cache)
		kmem_cache_free(test_cache, ptr);
	else
		kfree(ptr);
}

/*
 * If this should be a KFENCE allocation, and on which side the allocation and
 * the closest guard page should be.
 */
enum allocation_policy {
	ALLOCATE_ANY, /* KFENCE, any side. */
	ALLOCATE_LEFT, /* KFENCE, left side of page. */
	ALLOCATE_RIGHT, /* KFENCE, right side of page. */
	ALLOCATE_NONE, /* No KFENCE allocation. */
};

/*
 * Try to get a guarded allocation from KFENCE. Uses either kmalloc() or the
 * current test_cache if set up.
 */
static void *test_alloc(struct kunit *test, size_t size, gfp_t gfp, enum allocation_policy policy)
{
	void *alloc;
	unsigned long timeout;
	const char *policy_name;

	switch (policy) {
	case ALLOCATE_ANY:
		policy_name = "any";
		break;
	case ALLOCATE_LEFT:
		policy_name = "left";
		break;
	case ALLOCATE_RIGHT:
		policy_name = "right";
		break;
	case ALLOCATE_NONE:
		policy_name = "none";
		break;
	}

	kunit_info(test, "%s: size=%zu, gfp=%x, policy=%s, cache=%i\n", __func__, size, gfp,
		   policy_name, !!test_cache);

	/*
	 * 100x the sample rate should be more than enough to ensure we get a
	 * KFENCE allocation eventually.
	 */
	timeout = jiffies + msecs_to_jiffies(100 * CONFIG_KFENCE_SAMPLE_RATE);
	do {
		if (test_cache)
			alloc = kmem_cache_alloc(test_cache, gfp);
		else
			alloc = kmalloc(size, gfp);

		if (is_kfence_addr(alloc)) {
			if (policy == ALLOCATE_ANY)
				return alloc;
			if (policy == ALLOCATE_LEFT && IS_ALIGNED((unsigned long)alloc, PAGE_SIZE))
				return alloc;
			if (policy == ALLOCATE_RIGHT &&
			    !IS_ALIGNED((unsigned long)alloc, PAGE_SIZE))
				return alloc;
		} else if (policy == ALLOCATE_NONE)
			return alloc;

		test_free(alloc);
	} while (jiffies < timeout);

	KUNIT_ASSERT_TRUE_MSG(test, false, "failed to allocate from KFENCE");
	return NULL; /* Unreachable. */
}

static void test_out_of_bounds_read(struct kunit *test)
{
	const size_t size = 32;
	struct expect_report expect = {
		.type = KFENCE_ERROR_OOB,
		.fn = test_out_of_bounds_read,
	};
	char *buf;

	setup_test_cache(test, size, NULL);

	/* Test both sides. */

	buf = test_alloc(test, size, GFP_KERNEL, ALLOCATE_LEFT);
	expect.addr = buf - 1;
	READ_ONCE(*expect.addr);
	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
	test_free(buf);

	buf = test_alloc(test, size, GFP_KERNEL, ALLOCATE_RIGHT);
	expect.addr = buf + size;
	READ_ONCE(*expect.addr);
	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
	test_free(buf);
}

static void test_use_after_free_read(struct kunit *test)
{
	const size_t size = 32;
	struct expect_report expect = {
		.type = KFENCE_ERROR_UAF,
		.fn = test_use_after_free_read,
	};

	setup_test_cache(test, size, NULL);
	expect.addr = test_alloc(test, size, GFP_KERNEL, ALLOCATE_ANY);
	test_free(expect.addr);
	READ_ONCE(*expect.addr);
	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
}

static void test_double_free(struct kunit *test)
{
	const size_t size = 32;
	struct expect_report expect = {
		.type = KFENCE_ERROR_INVALID_FREE,
		.fn = test_double_free,
	};

	setup_test_cache(test, size, NULL);
	expect.addr = test_alloc(test, size, GFP_KERNEL, ALLOCATE_ANY);
	test_free(expect.addr);
	test_free(expect.addr); /* Double-free. */
	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
}

/*
 * KFENCE is unable to detect an OOB if the allocation's alignment requirements
 * leave a gap between the object and the guard page. Specifically, an
 * allocation of e.g. 73 bytes is aligned on 8 and 128 bytes for SLUB or SLAB
 * respectively. Therefore it is impossible for the allocated object to adhere
 * to either of the page boundaries.
 *
 * However, we test that an access to memory beyond the gap result in KFENCE
 * detecting an OOB access.
 */
static void test_kmalloc_aligned_oob_read(struct kunit *test)
{
	const size_t size = 73;
	const size_t align = kmalloc_caches[kmalloc_type(GFP_KERNEL)][kmalloc_index(size)]->align;
	struct expect_report expect = {
		.type = KFENCE_ERROR_OOB,
		.fn = test_kmalloc_aligned_oob_read,
	};
	char *buf;

	buf = test_alloc(test, size, GFP_KERNEL, ALLOCATE_RIGHT);

	/*
	 * The object is offset to the right, so there won't be an OOB to the
	 * left of it.
	 */
	READ_ONCE(*(buf - 1));
	KUNIT_EXPECT_FALSE(test, report_available());

	/*
	 * @buf must be aligned on @align, therefore buf + size belongs to the
	 * same page -> no OOB.
	 */
	READ_ONCE(*(buf + size));
	KUNIT_EXPECT_FALSE(test, report_available());

	/* Overflowing by @align bytes will result in an OOB. */
	expect.addr = buf + size + align;
	READ_ONCE(*expect.addr);
	KUNIT_EXPECT_TRUE(test, report_matches(&expect));

	test_free(buf);
}

static void test_kmalloc_aligned_oob_write(struct kunit *test)
{
	const size_t size = 73;
	struct expect_report expect = {
		.type = KFENCE_ERROR_CORRUPTION,
		.fn = test_kmalloc_aligned_oob_write,
	};
	char *buf;

	buf = test_alloc(test, size, GFP_KERNEL, ALLOCATE_RIGHT);
	/*
	 * The object is offset to the right, so we won't get a page
	 * fault immediately after it.
	 */
	expect.addr = buf + size;
	WRITE_ONCE(*expect.addr, READ_ONCE(*expect.addr) + 1);
	KUNIT_EXPECT_FALSE(test, report_available());
	test_free(buf);
	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
}

/* Test cache shrinking and destroying with KFENCE. */
static void test_shrink_memcache(struct kunit *test)
{
	const size_t size = 32;
	void *buf;

	setup_test_cache(test, size, NULL);
	KUNIT_EXPECT_TRUE(test, test_cache);
	buf = test_alloc(test, size, GFP_KERNEL, ALLOCATE_ANY);
	kmem_cache_shrink(test_cache);
	test_free(buf);

	KUNIT_EXPECT_FALSE(test, report_available());
}

static void ctor_set_x(void *obj)
{
	/* Every object has at least 8 bytes. */
	memset(obj, 'x', 8);
}

/* Ensure that SL*B does not modify KFENCE objects on bulk free. */
static void test_free_bulk(struct kunit *test)
{
	int iter;

	for (iter = 0; iter < 5; iter++) {
		const size_t size = setup_test_cache(test, 8 + prandom_u32_max(300),
						     (iter & 1) ? ctor_set_x : NULL);
		void *objects[] = {
			test_alloc(test, size, GFP_KERNEL, ALLOCATE_RIGHT),
			test_alloc(test, size, GFP_KERNEL, ALLOCATE_NONE),
			test_alloc(test, size, GFP_KERNEL, ALLOCATE_LEFT),
			test_alloc(test, size, GFP_KERNEL, ALLOCATE_NONE),
			test_alloc(test, size, GFP_KERNEL, ALLOCATE_NONE),
		};

		kmem_cache_free_bulk(test_cache, ARRAY_SIZE(objects), objects);
		KUNIT_ASSERT_FALSE(test, report_available());
		test_cache_destroy();
	}
}

/* Ensure that constructors work properly. */
static void test_memcache_ctor(struct kunit *test)
{
	const int size = 32;
	char *buf;
	int i;

	setup_test_cache(test, size, ctor_set_x);
	buf = test_alloc(test, size, GFP_KERNEL, ALLOCATE_ANY);

	for (i = 0; i < 8; i++)
		KUNIT_EXPECT_EQ(test, buf[i], (char)'x');

	test_free(buf);

	KUNIT_EXPECT_FALSE(test, report_available());
}

/* Test that memory is zeroed if requested. */
static void test_gfpzero(struct kunit *test)
{
	const int size = PAGE_SIZE; /* PAGE_SIZE so we can use ALLOCATE_ANY. */
	char *buf1, *buf2;
	int i;

	if (CONFIG_KFENCE_SAMPLE_RATE > 100) {
		kunit_warn(test, "skipping ... would take too long\n");
		return;
	}

	setup_test_cache(test, size, NULL);
	buf1 = test_alloc(test, size, GFP_KERNEL, ALLOCATE_ANY);
	for (i = 0; i < size; i++)
		buf1[i] = i + 1;
	test_free(buf1);

	/* Try to get same address again -- this can take a while. */
	for (i = 0;; i++) {
		buf2 = test_alloc(test, size, GFP_KERNEL | __GFP_ZERO, ALLOCATE_ANY);
		if (buf1 == buf2)
			break;
		test_free(buf2);

		if (i == CONFIG_KFENCE_NUM_OBJECTS) {
			kunit_warn(test, "giving up ... cannot get same object back\n");
			return;
		}
	}

	for (i = 0; i < size; i++)
		KUNIT_EXPECT_EQ(test, buf2[i], (char)0);

	test_free(buf2);

	KUNIT_EXPECT_FALSE(test, report_available());
}

static void test_invalid_access(struct kunit *test)
{
	const struct expect_report expect = {
		.type = KFENCE_ERROR_INVALID,
		.fn = test_invalid_access,
		.addr = &__kfence_pool[10],
	};

	READ_ONCE(__kfence_pool[10]);
	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
}

/*
 * KUnit does not provide a way to provide arguments to tests, and we encode
 * additional info in the name. Set up 2 tests per test case, one using the
 * default allocator, and another using a custom memcache (suffix '-memcache').
 */
// clang-format off
// TODO: fix formatting for v1
#define KFENCE_KUNIT_CASE(test_name)                                           \
	{ .run_case = test_name, .name = #test_name },                         \
	{ .run_case = test_name, .name = #test_name "-memcache" }
// clang-format on

static struct kunit_case kfence_test_cases[] = {
	KFENCE_KUNIT_CASE(test_out_of_bounds_read),
	KFENCE_KUNIT_CASE(test_use_after_free_read),
	KFENCE_KUNIT_CASE(test_double_free),
	KFENCE_KUNIT_CASE(test_free_bulk),
	KUNIT_CASE(test_kmalloc_aligned_oob_read),
	KUNIT_CASE(test_kmalloc_aligned_oob_write),
	KUNIT_CASE(test_shrink_memcache),
	KUNIT_CASE(test_memcache_ctor),
	KUNIT_CASE(test_invalid_access),
	KUNIT_CASE(test_gfpzero),
	{},
};

/* ===== End test cases ===== */

static int test_init(struct kunit *test)
{
	unsigned long flags;
	int i;

	spin_lock_irqsave(&observed.lock, flags);
	for (i = 0; i < ARRAY_SIZE(observed.lines); i++)
		observed.lines[i][0] = '\0';
	observed.nlines = 0;
	spin_unlock_irqrestore(&observed.lock, flags);

	/* Any test with 'memcache' in its name will want a memcache. */
	if (strstr(test->name, "memcache"))
		test->priv = TEST_PRIV_WANT_MEMCACHE;
	else
		test->priv = NULL;

	return 0;
}

static void test_exit(struct kunit *test)
{
	test_cache_destroy();
}

static struct kunit_suite kfence_test_suite = {
	.name = "kfence-test",
	.test_cases = kfence_test_cases,
	.init = test_init,
	.exit = test_exit,
};
static struct kunit_suite *kfence_test_suites[] = { &kfence_test_suite, NULL };

static void register_tracepoints(struct tracepoint *tp, void *ignore)
{
	check_trace_callback_type_console(probe_console);
	if (!strcmp(tp->name, "console"))
		WARN_ON(tracepoint_probe_register(tp, probe_console, NULL));
}

static void unregister_tracepoints(struct tracepoint *tp, void *ignore)
{
	if (!strcmp(tp->name, "console"))
		tracepoint_probe_unregister(tp, probe_console, NULL);
}

/*
 * We only want to do tracepoints setup and teardown once, therefore we have to
 * customize the init and exit functions and cannot rely on kunit_test_suite().
 */
static int __init kfence_test_init(void)
{
	/*
	 * Because we want to be able to build the test as a module, we need to
	 * iterate through all known tracepoints, since the static registration
	 * won't work here.
	 */
	for_each_kernel_tracepoint(register_tracepoints, NULL);
	return __kunit_test_suites_init(kfence_test_suites);
}

static void kfence_test_exit(void)
{
	__kunit_test_suites_exit(kfence_test_suites);
	for_each_kernel_tracepoint(unregister_tracepoints, NULL);
	tracepoint_synchronize_unregister();
}

late_initcall(kfence_test_init);
module_exit(kfence_test_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>");
