Found Bugs
==========

Over the years KASAN has found thousands of issues in the Linux kernel so maintaining a full list is pointless.
This page contains links to some old bugs found with KASAN back in the days when it was being developed.
Just for historical purposes.

## Old Bugs

Description  | Links | Status
------------ | ----- | ------
Out-of-bounds read in net/ipv4 | [kernel.org](http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=aab515d7c32a34300312416c50314e755ea6f765) | Fixed
Out-of-bounds in sd_revalidate_disk (drivers/scsi/sd.c) | [spinics.net](http://www.spinics.net/lists/linux-scsi/msg68519.html) [kernel.org](http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=984f1733fcee3fbc78d47e26c5096921c5d9946a) | Fixed
Use-after-free in aio_migratepage | [kernel.org](http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=5e9ae2e5da0beb93f8557fc92a8f4fbc05ea448f) [code.google.com](https://code.google.com/p/address-sanitizer/wiki/AddressSanitizerForKernelReports) | Fixed
Out-of-bounds in ip6_finish_output2 | [spinics.net](http://www.spinics.net/lists/netdev/msg250734.html) [seclists.org](http://seclists.org/oss-sec/2013/q3/683) [kernel.org](http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=2811ebac2521ceac84f2bdae402455baa6a7fb47) | Fixed
Out-of-bounds in ftrace_regex_release (kernel/trace/ftrace.c) | [spinics.net](http://www.spinics.net/lists/kernel/msg1612400.html) [lkml.org](https://lkml.org/lkml/2013/10/20/126) | Fixed
Use-after-free in ext4_mb_new_blocks |  [permalink.gmane.org](http://permalink.gmane.org/gmane.comp.file-systems.ext4/40353) [permalink.gmane.org](http://permalink.gmane.org/gmane.comp.file-systems.ext4/41108) | Fixed
Race (use-after-free) in ip4_datagram_release_cb | [spinics.net](http://www.spinics.net/lists/netdev/msg285419.html) [kernel.org](http://git.kernel.org/cgit/linux/kernel/git/stable/linux-stable.git/commit/?id=9709674e68646cee5a24e3000b3558d25412203a) | Fixed
Use-after-free in __put_anon_vma | [lkml.org](https://lkml.org/lkml/2014/6/6/186) | Confirmed
Out-of-bounds read in __d_lookup_rcu (fs/dcache.c) | [code.google.com](https://code.google.com/p/address-sanitizer/wiki/AddressSanitizerForKernelReports) [lkml.org](http://lkml.org/lkml/2013/10/3/493) | Confirmed
Out-of-bounds in get_wchan (arch/x86/kernel/process_64.c) | [lkml.org](http://lkml.org/lkml/2013/9/3/286) [spinics.net](http://www.spinics.net/lists/kernel/msg1596173.html) | Confirmed
Stack-out-of-bounds in idr_for_each | [lkml.org](https://lkml.org/lkml/2014/6/23/516) | Confirmed
Out-of-bounds memory write in fs/ecryptfs/crypto.c | [lkml.org](https://lkml.org/lkml/2014/11/21/230) | Confirmed
Use-after-free in drivers/net/ethernet/intel/e1000 | [permalink.gmane.org](http://permalink.gmane.org/gmane.linux.drivers.e1000.devel/12441) | Not confirmed
Use-after-free in ____call_usermodehelper (kernel/kmod.c) | [lkml.org](http://www.lkml.org/lkml/2013/8/21/431) | Not confirmed
Use-after-free in SyS_remap_file_pages | [lkml.org](https://lkml.org/lkml/2013/9/17/30) | Not confirmed
Use-after-free in ata_qc_issue (drivers/ata/libata-core.c) | [spinics.net](http://www.spinics.net/lists/linux-ide/msg46213.html) | Not confirmed
Racy use-after-free in list_del_event | [lkml.org](https://lkml.org/lkml/2014/6/18/318) | Not confirmed

Description  | Links | Status
------------ | ----- | ------
drm/i915: Fix command parser table validator | [cgit.freedesktop.org](http://cgit.freedesktop.org/drm-intel/commit/?id=8453580cb8834dedffda86bcb64f13befc90eb03) | Fixed
iwlwifi: out-of-bounds access in iwl_init_sband_channel | [lkml.org](https://lkml.org/lkml/2015/8/14/114) | Fixed
sched: memory corruption on completing completions / out of bounds on stack in do_raw_spin_unlock | [lkml.org](https://lkml.org/lkml/2015/2/4/761) [article.gmane.org] (http://article.gmane.org/gmane.linux.kernel/1883900) | Fixed
net: raw socket accessing invalid memory / out of bounds on stack in memcpy_fromiovec | [lkml.org](https://lkml.org/lkml/2015/1/23/689) | Not confirmed
mm: compaction: buffer overflow in isolate_migratepages_range | [lkml.org](https://lkml.org/lkml/2014/8/9/162) | Confirmed
out of bounds access in i915_cmd_parser_init_ring | [lkml.org](https://lkml.org/lkml/2015/8/13/814) | Fixed
out of bounds access in hash_net4_add_cidr | [spinics.net](http://www.spinics.net/lists/netfilter-devel/msg37751.html) [spinics.net](http://www.spinics.net/lists/netdev/msg342000.html) | Fixed
null-ptr-deref in __rds_conn_create| [lkml.org](https://lkml.org/lkml/2015/9/8/455) | Fixed
out of bounds on stack in iov_iter_advance | [lkml.org](https://lkml.org/lkml/2015/8/12/598) | Confirmed
use after free in dio_bio_complet | [redhat.com](https://www.redhat.com/archives/dm-devel/2015-August/msg00070.html) | Fixed
null-ptr-deref in mincore_page/shmem_mapping | [lkml.org](https://lkml.org/lkml/2015/2/23/105) | Fixed
out of bounds in gic_raise_softirq/gic_compute_target_list | [infradead.org](http://lists.infradead.org/pipermail/linux-arm-kernel/2015-March/328588.html) | Fixed
out of bounds in trace_event_enum_update | [lkml.org](https://lkml.org/lkml/2015/4/17/717) | Fixed
use-after-free in mlxsw_sx_port_xmit | [ozlabs.org](https://patchwork.ozlabs.org/patch/504719/) | Fixed
use after free in page_cache_async_readahead | [lkml.org](http://article.gmane.org/gmane.linux.kernel/2030866) [spinics.net](http://www.spinics.net/lists/linux-mm/msg94012.html) | Fixed
Use-after-free in kobject_put (scsi_host_dev_release) | [lkml.org](https://lkml.org/lkml/2015/9/11/228) | No response
Out-of-bounds in crc16 (ext4_group_desc_csum) | [lkml.org](https://lkml.org/lkml/2015/9/11/334) | No response
User-memory-access in ext4_orphan_del | [lkml.org](https://lkml.org/lkml/2015/9/17/359) | No response
out of bounds on stack in csum_partial_copy_fromiovecend | [spinics.net](http://www.spinics.net/lists/netdev/msg343998.html) | Not confirmed
NULL ptr deref in handle_mm_fault | [spinics.net](http://www.spinics.net/lists/linux-mm/msg94663.html) | Not confirmed
use-after-free in shrink_page_list | [lkml.org](https://lkml.org/lkml/2015/10/7/539) | TODO

### More bugs found by external users

  * Look [here](https://www.google.com/?gws_rd=ssl#q=site%3Alkml.org+%22Memory+state+around+the+buggy+address%22+%22Sasha+Levin%22) and [here](https://www.google.com/?gws_rd=ssl#q=site%3Alkml.org+%22Memory+state+around+the+buggy+address%22)
