Symbolizer
==========

To simplify reading kernel reports, you can use the [symbolizer script](/tools/symbolizer.py).
It appends fileline information to each stack trace frame in the kernel log.
The script requires access to the vmlinux and kernel modules binaries built with `CONFIG_DEBUG_INFO`.

```
$ cat report
...
[  107.327411]  [<ffffffff8110424c>] call_usermodehelper_freeinfo+0x2c/0x30
[  107.328668]  [<ffffffff811049d5>] call_usermodehelper_exec+0xa5/0x1c0
[  107.329816]  [<ffffffff811052b0>] call_usermodehelper+0x40/0x60
[  107.330987]  [<ffffffff8146c15e>] kobject_uevent_env+0x5ee/0x620
[  107.332035]  [<ffffffff8146c19b>] kobject_uevent+0xb/0x10
[  107.333108]  [<ffffffff8173bd7f>] net_rx_queue_update_kobjects+0xaf/0x150
...
```

```
$ cat report | ./symbolizer.py --linux=path/to/kernel/ --strip=path/to/kernel/
...
 [<ffffffff8110424c>] call_usermodehelper_freeinfo+0x2c/0x30 kernel/kmod.c:265
 [<ffffffff811049d5>] call_usermodehelper_exec+0xa5/0x1c0 kernel/kmod.c:612
 [<ffffffff811052b0>] call_usermodehelper+0x40/0x60 kernel/kmod.c:642
 [<ffffffff8146c15e>] kobject_uevent_env+0x5ee/0x620 lib/kobject_uevent.c:311
 [<ffffffff8146c19b>] kobject_uevent+0xb/0x10 lib/kobject_uevent.c:333
 [<     inlined    >] net_rx_queue_update_kobjects+0xaf/0x150 rx_queue_add_kobject net/core/net-sysfs.c:771
 [<ffffffff8173bd7f>] net_rx_queue_update_kobjects+0xaf/0x150 net/core/net-sysfs.c:786
...
```

The script supports using multiple `--linux` and `--strip` arguments.

As an alternative, you can use [syz-symbolize](https://github.com/google/syzkaller/blob/master/tools/syz-symbolize/symbolize.go) (part of [syzkaller](https://github.com/google/syzkaller)).
