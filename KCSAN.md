Kernel Concurrency Sanitizer (KCSAN)
====================================

The Kernel Concurrency Sanitizer (KCSAN) is a watchpoint based dynamic race detector for the Linux kernel. More details can be found in [Documentation/dev-tools/kcsan.rst](https://www.kernel.org/doc/html/latest/dev-tools/kcsan.html).

The latest stable version of KCSAN is in [mainline](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/log/kernel/kcsan).

The LWN article series "Concurrency bugs should fear the big bad data-race detector" discuss KCSAN in more detail:

* https://lwn.net/Articles/816850/
* https://lwn.net/Articles/816854/

Talks:

* [Linux Plumbers Conference 2020](/kcsan/LPC2020-KCSAN.pdf)

Continuous Testing & Fuzzing
----------------------------

We have a [public syzbot instance](https://syzkaller.appspot.com/upstream?manager=ci2-upstream-kcsan-gce). Reports will appear on the dashboard after internal review, to keep the volume of bugs manageable (which gives us a chance to carefully react to KCSAN reports while best practices are still evolving).

Upstream Fixes of Data Races found by KCSAN
-------------------------------------------

This is a non-exhaustive list of some fixes for data races found by KCSAN.
Last updated: Aug 23, 2021.

* [perf: Fix data race between pin_count increment/decrement](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=6c605f8371159432ec61cbb1488dcf7ad24ad19a)
* [io_uring: fix data race to avoid potential NULL-deref](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=b16ef427adf31fb4f6522458d37b3fe21d6d03b8)
* [timers: Move clearing of base::timer_running under base:: Lock](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=bb7262b295472eb6858b5c49893954794027cd84)
* [net: igmp: fix data-race in igmp_ifc_timer_expire()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=4a2b285e7e103d4d6c6ed3e5052a0ff74a5d7f15)
* [udp: annotate data races around unix_sk(sk)->gso_size](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=18a419bad63b7f68a1979e28459782518e7b6bbe)
* [net: annotate data race around sk_ll_usec](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=0dbffbb5335a1e3aa6855e4ee317e25e669dd302)
* [net/af_unix: fix a data-race in unix_dgram_sendmsg / unix_release_sock](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=a494bd642d9120648b06bb7d28ce6d05f55a7819)
* [net/packet: annotate accesses to po->ifindex](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=e032f7c9c7cefffcfb79b9fc16c53011d2d9d11f)
* [net/packet: annotate accesses to po->bind](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=c7d2ef5dd4b03ed0ee1d13bc0c55f9cf62d49bd6)
* [inet: annotate date races around sk->sk_txhash](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=b71eaed8c04f72a919a9c44e83e4ee254e69e7f3)
* [net: annotate data race in sock_error()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f13ef10059ccf5f4ed201cd050176df62ec25bb8)
* [inet: annotate data race in inet_send_prepare() and inet_dgram_connect()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=dcd01eeac14486b56a790f5cce9b823440ba5b34)
* [bpf_lru_list: Read double-checked variable once without lock](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=6df8fb83301d68ea0a0c0e1cbcc790fcc333ed12)
* [ALSA: rawmidi: Access runtime->avail always in spinlock](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=88a06d6fd6b369d88cec46c62db3e2604a2f50d5)
* [ALSA: seq: Use bool for snd_seq_queue internal flags](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=4ebd47037027c4beae99680bff3b20fdee5d7c1e)
* [mm/page_counter: fix various data races at memsw](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=6e4bd50f3888fa8fea8bc66a0ad4ad5f1c862961)
* [fat: don't allow to mount if the FAT length == 0](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=b1b65750b8db67834482f758fc385bfa7560d228) | [lkml](https://lkml.kernel.org/r/0000000000000cfff005a26226ce@google.com)
* [rcu: Add *_ONCE() and data_race() to rcu_node ->exp_tasks plus locking](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=314eeb43e5f22856b281c91c966e51e5782a3498)
* [tcp: annotate sk->sk_rcvbuf lockless reads](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=ebb3b78db7bf842270a46fd4fe7cc45c78fa5ed6)
* [ALSA: seq: Avoid concurrent access to queue flags](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=bb51e669fa49feb5904f452b2991b240ef31bc97) | [syzbot](https://syzkaller.appspot.com/bug?id=7f6dc75cdfdaa26c6ba5c170063af241807683f6) 
* [ALSA: seq: Fix concurrent access to queue current tick/time](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=dc7497795e014d84699c3b8809ed6df35352dd74)
* [mm: annotate a data race in page_zonenum()](https://lore.kernel.org/patchwork/patch/1194300/)
* [mm/mempool: fix a data race in mempool_free()](https://lore.kernel.org/patchwork/patch/1192684/)
* [ext4: fix a data race in EXT4_I(inode)->i_disksize](https://lore.kernel.org/patchwork/patch/1190562/)
* [rcutorture: Annotation lockless accesses to rcu_torture_current](https://lore.kernel.org/patchwork/patch/1195006/)
* [rcutorture: Add READ_ONCE() to rcu_torture_count and rcu_torture_batch](https://lore.kernel.org/patchwork/patch/1195005/)
* [rcutorture: Fix stray access to rcu_fwd_cb_nodelay](https://lore.kernel.org/patchwork/patch/1195004/)
* [rcutorture: Fix rcu_torture_one_read()/rcu_torture_writer() data race](https://lore.kernel.org/patchwork/patch/1195003/)
* [srcu: Add READ_ONCE() to srcu_struct ->srcu_gp_seq load](https://lore.kernel.org/patchwork/patch/1194990/)
* [srcu: Fix process_srcu()/srcu_batches_completed() datarace](https://lore.kernel.org/patchwork/patch/1194989/)
* [srcu: Fix __call_srcu()/srcu_get_delay() datarace](https://lore.kernel.org/patchwork/patch/1194988/)
* [srcu: Fix __call_srcu()/process_srcu() datarace](https://lore.kernel.org/patchwork/patch/1194987/)
* [rcu-tasks: *_ONCE() for rcu_tasks_cbs_head](https://lore.kernel.org/patchwork/patch/1194983/)
* [rcu: Add WRITE_ONCE() to rcu_state ->gp_start](https://lore.kernel.org/patchwork/patch/1194955/)
* [rcu: Add *_ONCE() to rcu_node ->boost_kthread_status](https://lore.kernel.org/patchwork/patch/1194952/)
* [rcu: Add *_ONCE() to rcu_data ->rcu_forced_tick](https://lore.kernel.org/patchwork/patch/1194951/)
* [rcu: Add READ_ONCE() to rcu_data ->gpwrap](https://lore.kernel.org/patchwork/patch/1194950/)
* [rcu: *_ONCE() for grace-period progress indicators](https://lore.kernel.org/patchwork/patch/1194948/)
* [rcu: Add READ_ONCE() to rcu_segcblist ->tails](https://lore.kernel.org/patchwork/patch/1194947/)
* [rcu: Add WRITE_ONCE() to rcu_node ->qsmaskinitnext](https://lore.kernel.org/patchwork/patch/1194945/)
* [locking/rtmutex: rcu: Add WRITE_ONCE() to rt_mutex ->owner](https://lore.kernel.org/patchwork/patch/1194946/)
* [rcu: Add WRITE_ONCE() to rcu_state ->gp_req_activity](https://lore.kernel.org/patchwork/patch/1194944/)
* [rcu: Add READ_ONCE() to rcu_node ->gp_seq](https://lore.kernel.org/patchwork/patch/1194943/)
* [rcu: Add WRITE_ONCE to rcu_node ->exp_seq_rq store](https://lore.kernel.org/patchwork/patch/1194942/)
* [rcu: Add WRITE_ONCE() to rcu_node ->qsmask update](https://lore.kernel.org/patchwork/patch/1194941/)
* [rcu: Fix exp_funnel_lock()/rcu_exp_wait_wake() datarace](https://lore.kernel.org/patchwork/patch/1194939/)
* [skbuff: fix a data race in skb_queue_len()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=86b18aaa2b5b5bb48e609cd591b3d2d0fdbe0442)
* [debugobjects: Fix various data races](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=35fd7a637c42bb54ba4608f4d40ae6e55fc88781)
* [tick/sched: Annotate lockless access to last_jiffies_update](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=de95a991bb72e009f47e0c4bbc90fc5f594588d5)
* [rcu: Use WRITE_ONCE() for assignments to ->pprev for hlist_nulls](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=860c8802ace14c646864795e057349c9fb2d60ad)
* [rcu: Avoid data-race in rcu_gp_fqs_check_wake()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=6935c3983b246d5fbfebd3b891c825e65c118f2d)
* [tomoyo: Use atomic_t for statistics counter](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=a8772fad0172aeae339144598b809fd8d4823331)
* [locking/spinlock/debug: Fix various data races](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=1a365e822372ba24c9da0822bc583894f6f3d821)
* [vfs: mark pipes and sockets as stream-like file descriptors](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=d8e464ecc17b4444e9a3e148a9748c4828c6328c)
* [sctp: cache netns in sctp_ep_common](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=312434617cb16be5166316cf9d08ba760b1042a1)
* [tun: fix data-race in gro_normal_list()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=c39e342a050a4425348e6fe7f75827c0a1a7ebc5)
* [tcp: fix data-race in tcp_recvmsg()](http://lkml.kernel.org/r/20191106205933.149697-1-edumazet@google.com)
* [net: introduce u64_stats_t](http://lkml.kernel.org/r/20191108002722.129055-1-edumazet@google.com)
* [inetpeer: fix data-race in inet_putpeer / inet_putpeer](http://lkml.kernel.org/r/20191107183042.6286-1-edumazet@google.com)
* [list: add hlist_unhashed_lockless()](http://lkml.kernel.org/r/20191107193738.195914-1-edumazet@google.com)
* [hrtimer: Annotate lockless access to timer->state](https://lore.kernel.org/lkml/20191106174804.74723-1-edumazet@google.com/)
* [ipv6: fixes rt6_probe() and fib6_nh->last_probe init](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=1bef4c223b8588cf50433bdc2c6953d82949b3b3) | [lkml](https://lore.kernel.org/netdev/20191107024509.87121-1-edumazet@google.com/)
* [net: silence data-races on sk_backlog.tail](https://lore.kernel.org/netdev/20191106180411.113080-1-edumazet@google.com/)
* [net: various KCSAN inspired fixes](https://lore.kernel.org/netdev/20191105221154.232754-1-edumazet@google.com/)
* [rcu: Use READ_ONCE() for ->expmask in rcu_read_unlock_special()](http://lkml.kernel.org/r/20191104162652.GC20975@paulmck-ThinkPad-P72)
* [srcu: Apply *_ONCE() to ->srcu_last_gp_end](http://lkml.kernel.org/r/20191104161152.GB20975@paulmck-ThinkPad-P72)
* [mm: vmscan: memcontrol: remove mem_cgroup_select_victim_node()](http://lkml.kernel.org/r/20191030204232.139424-1-shakeelb@google.com) | [report](http://lkml.kernel.org/r/20191029005405.201986-1-shakeelb@google.com)
* [net: annotate lockless accesses to sk->sk_napi_id](http://lkml.kernel.org/r/20191029175444.83564-1-edumazet@google.com)
* [udp: fix data-race in udp_set_dev_scratch()](http://lkml.kernel.org/r/20191024184331.28920-1-edumazet@google.com)
* [net: avoid KCSAN splats](https://lore.kernel.org/netdev/20191024054452.81661-1-edumazet@google.com/)
* [proc: fix inode uid/gid writeback race](http://lkml.kernel.org/r/20191020173010.GA14744@avx2)
* [netfilter: conntrack: avoid possible false sharing](https://lore.kernel.org/netdev/20191009212451.0522979f@cakuba.netronome.com/T/)
* [tun: remove possible false sharing in tun_flow_update()](http://lkml.kernel.org/r/20191009162002.19360-1-edumazet@google.com)
* [tcp: address KCSAN reports in tcp_poll() (part I)](https://lore.kernel.org/netdev/20191011031746.16220-1-edumazet@google.com/)
* [rcu: Fix data-race due to atomic_t copy-by-value](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=6cf539a87a61a4fbc43f625267dbcbcf283872ed) | [lkml](https://lore.kernel.org/lkml/20191009155743.202142-1-elver@google.com/)
* [rcu: avoid data-race in rcu_gp_fqs_check_wake()](https://lore.kernel.org/lkml/20191009212154.24709-1-edumazet@google.com/)
* [rcu: exp: Avoid race on lockless rcu_node::expmask loop](https://lore.kernel.org/lkml/20191008025056.GA2701514@tardis/)
* [stop_machine: avoid potential race behaviour](https://lore.kernel.org/lkml/20191007104536.27276-1-mark.rutland@arm.com/)
* [taskstats: fix data-race](https://lore.kernel.org/lkml/20191009114809.8643-1-christian.brauner@ubuntu.com/) | [report](https://lore.kernel.org/lkml/0000000000009b403005942237bf@google.com/)
