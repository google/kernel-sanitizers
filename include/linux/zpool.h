/*
 * zpool memory storage api
 *
 * Copyright (C) 2014 Dan Streetman
 *
 * This is a common frontend for the zbud and zsmalloc memory
 * storage pool implementations.  Typically, this is used to
 * store compressed memory.
 */

#ifndef _ZPOOL_H_
#define _ZPOOL_H_

struct zpool;

struct zpool_ops {
	int (*evict)(struct zpool *pool, unsigned long handle);
};

/*
 * Control how a handle is mapped.  It will be ignored if the
 * implementation does not support it.  Its use is optional.
 * Note that this does not refer to memory protection, it
 * refers to how the memory will be copied in/out if copying
 * is necessary during mapping; read-write is the safest as
 * it copies the existing memory in on map, and copies the
 * changed memory back out on unmap.  Write-only does not copy
 * in the memory and should only be used for initialization.
 * If in doubt, use ZPOOL_MM_DEFAULT which is read-write.
 */
enum zpool_mapmode {
	ZPOOL_MM_RW, /* normal read-write mapping */
	ZPOOL_MM_RO, /* read-only (no copy-out at unmap time) */
	ZPOOL_MM_WO, /* write-only (no copy-in at map time) */

	ZPOOL_MM_DEFAULT = ZPOOL_MM_RW
};

/**
 * zpool_create_pool() - Create a new zpool
 * @type	The type of the zpool to create (e.g. zbud, zsmalloc)
 * @flags	What GFP flags should be used when the zpool allocates memory.
 * @ops		The optional ops callback.
 *
 * This creates a new zpool of the specified type.  The zpool will use the
 * given flags when allocating any memory.  If the ops param is NULL, then
 * the created zpool will not be shrinkable.
 *
 * Returns: New zpool on success, NULL on failure.
 */
struct zpool *zpool_create_pool(char *type, gfp_t flags,
			struct zpool_ops *ops);

/**
 * zpool_get_type() - Get the type of the zpool
 * @pool	The zpool to check
 *
 * This returns the type of the pool.
 *
 * Returns: The type of zpool.
 */
char *zpool_get_type(struct zpool *pool);

/**
 * zpool_destroy_pool() - Destroy a zpool
 * @pool	The zpool to destroy.
 *
 * This destroys an existing zpool.  The zpool should not be in use.
 */
void zpool_destroy_pool(struct zpool *pool);

/**
 * zpool_malloc() - Allocate memory
 * @pool	The zpool to allocate from.
 * @size	The amount of memory to allocate.
 * @handle	Pointer to the handle to set
 *
 * This allocates the requested amount of memory from the pool.
 * The provided @handle will be set to the allocated object handle.
 *
 * Returns: 0 on success, negative value on error.
 */
int zpool_malloc(struct zpool *pool, size_t size, unsigned long *handle);

/**
 * zpool_free() - Free previously allocated memory
 * @pool	The zpool that allocated the memory.
 * @handle	The handle to the memory to free.
 *
 * This frees previously allocated memory.  This does not guarantee
 * that the pool will actually free memory, only that the memory
 * in the pool will become available for use by the pool.
 */
void zpool_free(struct zpool *pool, unsigned long handle);

/**
 * zpool_shrink() - Shrink the pool size
 * @pool	The zpool to shrink.
 * @pages	The number of pages to shrink the pool.
 * @reclaimed	The number of pages successfully evicted.
 *
 * This attempts to shrink the actual memory size of the pool
 * by evicting currently used handle(s).  If the pool was
 * created with no zpool_ops, or the evict call fails for any
 * of the handles, this will fail.  If non-NULL, the @reclaimed
 * parameter will be set to the number of pages reclaimed,
 * which may be more than the number of pages requested.
 *
 * Returns: 0 on success, negative value on error/failure.
 */
int zpool_shrink(struct zpool *pool, unsigned int pages,
			unsigned int *reclaimed);

/**
 * zpool_map_handle() - Map a previously allocated handle into memory
 * @pool	The zpool that the handle was allocated from
 * @handle	The handle to map
 * @mm	How the memory should be mapped
 *
 * This maps a previously allocated handle into memory.  The @mm
 * param indicates to the implementation how the memory will be
 * used, i.e. read-only, write-only, read-write.  If the
 * implementation does not support it, the memory will be treated
 * as read-write.
 *
 * This may hold locks, disable interrupts, and/or preemption,
 * and the zpool_unmap_handle() must be called to undo those
 * actions.  The code that uses the mapped handle should complete
 * its operatons on the mapped handle memory quickly and unmap
 * as soon as possible.  Multiple handles should not be mapped
 * concurrently on a cpu.
 *
 * Returns: A pointer to the handle's mapped memory area.
 */
void *zpool_map_handle(struct zpool *pool, unsigned long handle,
			enum zpool_mapmode mm);

/**
 * zpool_unmap_handle() - Unmap a previously mapped handle
 * @pool	The zpool that the handle was allocated from
 * @handle	The handle to unmap
 *
 * This unmaps a previously mapped handle.  Any locks or other
 * actions that the implementation took in zpool_map_handle()
 * will be undone here.  The memory area returned from
 * zpool_map_handle() should no longer be used after this.
 */
void zpool_unmap_handle(struct zpool *pool, unsigned long handle);

/**
 * zpool_get_total_size() - The total size of the pool
 * @pool	The zpool to check
 *
 * This returns the total size in bytes of the pool.
 *
 * Returns: Total size of the zpool in bytes.
 */
u64 zpool_get_total_size(struct zpool *pool);


/**
 * struct zpool_driver - driver implementation for zpool
 * @type:	name of the driver.
 * @list:	entry in the list of zpool drivers.
 * @create:	create a new pool.
 * @destroy:	destroy a pool.
 * @malloc:	allocate mem from a pool.
 * @free:	free mem from a pool.
 * @shrink:	shrink the pool.
 * @map:	map a handle.
 * @unmap:	unmap a handle.
 * @total_size:	get total size of a pool.
 *
 * This is created by a zpool implementation and registered
 * with zpool.
 */
struct zpool_driver {
	char *type;
	struct module *owner;
	struct list_head list;

	void *(*create)(gfp_t gfp, struct zpool_ops *ops);
	void (*destroy)(void *pool);

	int (*malloc)(void *pool, size_t size, unsigned long *handle);
	void (*free)(void *pool, unsigned long handle);

	int (*shrink)(void *pool, unsigned int pages,
				unsigned int *reclaimed);

	void *(*map)(void *pool, unsigned long handle,
				enum zpool_mapmode mm);
	void (*unmap)(void *pool, unsigned long handle);

	u64 (*total_size)(void *pool);
};

/**
 * zpool_register_driver() - register a zpool implementation.
 * @driver:	driver to register
 */
void zpool_register_driver(struct zpool_driver *driver);

/**
 * zpool_unregister_driver() - unregister a zpool implementation.
 * @driver:	driver to unregister.
 *
 * Module usage counting is used to prevent using a driver
 * while/after unloading.  Please only call unregister from
 * module exit function.
 */
void zpool_unregister_driver(struct zpool_driver *driver);

/**
 * zpool_evict() - evict callback from a zpool implementation.
 * @pool:	pool to evict from.
 * @handle:	handle to evict.
 *
 * This can be used by zpool implementations to call the
 * user's evict zpool_ops struct evict callback.
 */
int zpool_evict(void *pool, unsigned long handle);

#endif
