Kernel Thread Sanitizer (KTSAN)
===============================

This page is about the KTSAN happens-before Linux kernel data-race detector. The project is currently on-hold.

For an alternative approach using watchpoints, see [Kernel Concurrency Sanitizer (KCSAN)](/KCSAN.md).

## Overview

KTSAN is a a dynamic data-race error detector for the Linux kernel. It is related in its approach to user-space [Thread Sanitizer (TSAN)](https://clang.llvm.org/docs/ThreadSanitizer.html). The latest version (which tracks upstream stable releases) can be found in the [ktsan](https://github.com/google/kasan/tree/ktsan) branch.

More extensive documentation can be found in [Documentation](https://github.com/google/kasan/blob/ktsan/Documentation/ktsan.txt) (currently somewhat outdated).

The original prototype, which was written for Linux kernel version 4.2 can be found under the tag [ktsan_v4.2-with-fixes](https://github.com/google/kasan/releases/tag/ktsan_v4.2-with-fixes) (includes various fixes for found data-races).

A list of some of the found bugs is available [here](/KTSAN/FOUND_BUGS.md).

To symbolize reports, use [syz-symbolize](https://github.com/google/syzkaller/blob/master/tools/syz-symbolize/symbolize.go) (part of [syzkaller](https://github.com/google/syzkaller)) or [symbolizer.py](/tools/symbolizer.py).

## Building And Running

Build kernel with ktsan:
``` bash
git clone https://github.com/google/kasan.git ktsan
cd ktsan/
make defconfig
make kvmconfig
scripts/config -e KTSAN -e SLAB -d SLUB -e DEBUG_INFO
yes '' | make oldconfig
make -j64 LOCALVERSION=-tsan
```

Install QEMU:
``` bash
sudo apt-get install kvm qemu-kvm
```

Create a minimal Debian-wheezy image:
``` bash
# Enable promptless ssh to the machine for root with RSA keys
mkdir debian-stable
sudo debootstrap --include=openssh-server stable debian-stable
sudo sed -i '/^root/ { s/:x:/::/ }' debian-stable/etc/passwd
sudo mkdir debian-stable/root/.ssh/
mkdir ssh
ssh-keygen -f ssh/id_rsa -t rsa -N ''
cat ssh/id_rsa.pub | sudo tee debian-stable/root/.ssh/authorized_keys

# Download and install trinity
sudo chroot debian-stable /bin/bash -c "apt-get update; apt-get -y install curl tar gcc make sysbench time"
sudo chroot debian-stable /bin/bash -c "mkdir -p ~; cd ~/; wget https://github.com/kernelslacker/trinity/archive/v1.9.tar.gz -O trinity-1.9.tar.gz; tar -xf trinity-1.9.tar.gz"
sudo chroot debian-stable /bin/bash -c "cd ~/trinity-1.9 ; ./configure ; make -j16 ; make install"

# Build and install perf
cp -r $KTSAN debian-stable/tmp/
sudo chroot debian-stable /bin/bash -c "apt-get install -y flex bison python-dev libelf-dev libunwind7-dev libaudit-dev libslang2-dev libperl-dev binutils-dev liblzma-dev libnuma-dev"
sudo chroot debian-stable /bin/bash -c "cd /tmp/ktsan/tools/perf/; make"
sudo chroot debian-stable /bin/bash -c "cp /tmp/ktsan/tools/perf/perf /usr/bin/"
rm -r debian-stable/tmp/ktsan

# Install other packages you might need
sudo chroot debian-stable /bin/bash -c "apt-get install -y git vim screen usbutils"

# Build a disk image 
sudo virt-make-fs --format=qcow2 --size=+200M debian-stable rootfs.img
```

Make a copy of the original image (the image file will be modified by QEMU):
``` bash
cp rootfs.img rootfs-dirty.img
```

Run QEMU:
``` bash
qemu-system-x86_64 \
  -drive file=rootfs-dirty.img,index=0 \
  -m 20G -smp 4 \
  -net user,hostfwd=tcp::10022-:22 -net nic \
  -nographic \
  -kernel arch/x86/boot/bzImage -append "console=ttyS0 root=/dev/sda rw debug earlyprintk=serial slub_debug=QUZ"\
  -enable-kvm -cpu host

# Note: on CentOS: -net nic,vlan=0,model=e1000
```

To stop QEMU press Ctrl+A then X

To run Trinity:
``` bash
ssh -i ssh/id_rsa -p 10022 -o "StrictHostKeyChecking no" root@localhost "trinity --dangerous -q -m -C 16"
```

## Implementation

KTSAN adapts the data-race detection algorithm of user-space [ThreadSanitizer](https://github.com/google/sanitizers/wiki/ThreadSanitizerAlgorithm) (version 2, don't confuse with [version 1](https://static.googleusercontent.com/media/research.google.com/en//pubs/archive/35604.pdf)) to the Linux kernel.

Some details can be found [here](https://docs.google.com/presentation/d/1OsihHNut6E26ACTnT-GplQrdJuByRPNqUmN0HkqurIM/edit?usp=sharing) or (in Russian) [here](http://w27001.vdi.mipt.ru/wp/wp-content/uploads/2017/03/%D0%9A%D0%9E%D0%9D%D0%9E%D0%92%D0%90%D0%9B%D0%9E%D0%92-%D0%90%D0%9D%D0%94%D0%A0%D0%95%D0%99.-%D0%90%D0%92%D0%A2%D0%9E%D0%9C%D0%90%D0%A2%D0%98%D0%A7%D0%95%D0%A1%D0%9A%D0%98%D0%99-%D0%9F%D0%9E%D0%98%D0%A1%D0%9A-%D0%A1%D0%9E%D0%A1%D0%A2%D0%9E%D0%AF%D0%9D%D0%98%D0%99-%D0%93%D0%9E%D0%9D%D0%9E%D0%9A-%D0%92-%D0%AF%D0%94%D0%A0%D0%95-%D0%9E%D0%A1-LINUX.pdf).

## Future Implementation Ideas

* Make some internal structures per CPU instead of per thread (VC cache, what else?). VCs themselves stay per thread.

* Monitor some kernel thread scheduler events (thread execution started/stopped on CPU).

* Disable interrupts during TSAN events (kernel scheduler events, synchronization events) (CLI, STI).

* Use 4 bytes per slot: 1 for thread id, 2 for clock, 1 for everything else (flags, ...).

* Different threads might have the same thread id (only 256 different values available).

* When clock overflows it is possible to change thread id and connect "old" and "new" threads with a happens-before relation.

* Find races in both kmalloc and vmalloc ranges.

* Use two-level shadow memory mapping scheme for now.

* Do a flush when we run out of clocks. The flush might work as follows. There is a global epoch variable which is increased during each flush. Each thread have a local epoch variable. When a thread is starting it will flush itself if the thread local epoch is less than the global one.
