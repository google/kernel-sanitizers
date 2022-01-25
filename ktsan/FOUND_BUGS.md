KTSAN: Found bugs
=================

* [data-race in ipc_obtain_object_check](https://groups.google.com/forum/#!topic/ktsan/xJQC-7sJqbk) | 4.2 | [Fixed](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=b9a532277938798b53178d5a66af6e2915cb27cf), [CVE](https://security-tracker.debian.org/tracker/CVE-2015-7613)
* [data-race on mnt.mnt_flags](https://groups.google.com/forum/#!topic/ktsan/qrOegr4iT1I) | 4.2 |
* [data-race in jbd2_journal_set_features](https://groups.google.com/forum/#!topic/ktsan/Z3kKosmh9rQ) | 4.2 |
* [data-race between __scsi_init_queue/ata_sg_setup](https://groups.google.com/forum/#!topic/ktsan/B-DpQCmwcCA) | 4.2 |
* [data-race in rhashtable_rehash_one](https://groups.google.com/forum/#!topic/ktsan/8RfL0z-qXm4)| 4.2 | Fixed
* [data-race on inode->i_flctx](https://groups.google.com/forum/#!topic/ktsan/6sIFuuwhkIk) | 4.2 | Fixed
* [data-race in timer_stats_account_timer](https://groups.google.com/forum/#!topic/ktsan/vzvHLp3rU0A) | 4.2 | Fixed
* [data-race on sk_buff after re-cloning](https://groups.google.com/forum/#!topic/ktsan/YoU0yX2wQJU) | 4.2 |
* [data-race in put_pid](https://groups.google.com/forum/#!topic/ktsan/tXIh3nO8aP0) | 4.2 |
* [data-race in llist_del_first](https://groups.google.com/d/msg/ktsan/_-4Vce9D1Wg/3aiMeSaFAAAJ) | 4.2 | Fixed
* [e1000: fix data race between tx_ring->next_to_clean](https://groups.google.com/forum/#!topic/ktsan/x2cxkPKoqZo) | 4.2 | Fixed
* [input: fix data race __ps2_command](https://lkml.org/lkml/2015/9/7/283) | 4.2 |
* [data-race in __tty_buffer_request_room](http://www.spinics.net/lists/kernel/msg2070018.html) | 4.2 | Fixed
* [data-race in tty_buffer_flush](http://www.spinics.net/lists/kernel/msg2070036.html) | 4.2 | Fixed
* [data-race in mlock/rmap](http://www.spinics.net/lists/kernel/msg2070002.html) | 4.2 | Confirmed
* [data-race in ext4_writepages](http://www.spinics.net/lists/kernel/msg2068255.html) | 4.2 |
* [__inode_add_bytes/ext4_mark_iloc_dirty](https://lkml.org/lkml/2015/8/31/405) | 4.2 | Confirmed
* [release_tty/flush_to_ldisc](https://lkml.org/lkml/2015/8/28/386) | 4.2.0-rc2 | Fixed
* [generic_fillattr/generic_update_time/shmem_mknod](https://lkml.org/lkml/2015/8/28/400) | 4.2.0-rc2 |
* [data-race in uart_ioctl](https://lkml.org/lkml/2015/8/25/358) | 4.2.0-rc2 | Confirmed, WONTFIX
* [data-race in SyS_swapon](http://www.spinics.net/lists/linux-mm/msg92677.html) | 4.2.0-rc2 | Fixed
* [data-race in psmouse_interrupt](https://lkml.org/lkml/2015/7/22/293) | 4.2.0-rc2 | Confirmed, WONTFIX?
