# KernelAddressSanitizer (KASAN)

**Note**: this repo doesn't host any KASAN code anymore as it's now in the mainline kernel.

KernelAddressSanitizer (KASAN) is a dynamic memory error detector for the Linux kernel that allows to find use-after-free and out-of-bounds bugs.

KASAN is available in the mainline Linux kernel starting from version `4.0` and can be enabled with `CONFIG_KASAN=y`.

See more details in [KASAN documentation](https://www.kernel.org/doc/html/latest/dev-tools/kasan.html).

For questions use KASAN mailing list [kasan-dev@googlegroups.com](https://groups.google.com/forum/#!forum/kasan-dev).
You can subscribe to it either with a Google account or by sending an email to kasan-dev+subscribe@googlegroups.com.

Issues in KASAN itself can be reported on [KASAN bug tracker](https://bugzilla.kernel.org/buglist.cgi?component=Sanitizers&product=Memory%20Management&resolution=---).

To simplify reading KASAN reports you can use our [symbolizer script](https://github.com/google/sanitizers/blob/master/address-sanitizer/tools/kasan_symbolize.py):

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
$ cat report | ./kasan_symbolize.py --linux=path/to/kernel/ --strip=path/to/kernel/
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
