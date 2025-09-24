{ config, lib, pkgs, ... }:
{
  # Security
	security = {
    # Auditing
    auditd.enable = true;
    audit.enable = true;
    audit.rules = [
      # Log all program executions on 64-bit architecture
      "-a exit,always -F arch=b64 -S execve"
      "-a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime,stime -k time-change"
      "-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change"
      "-w /etc/localtime -p wa -k time-change"
      "-w /etc/group -p wa -k identity"
      "-w /etc/passwd -p wa -k identity"
      "-w /etc/gshadow -p wa -k identity"
      "-w /etc/shadow -p wa -k identity"
      "-w /etc/security/opasswd -p wa -k identity"
      "-a exit,always -F arch=b32 -S sethostname,setdomainname -k system-locale"
      "-a exit,always -F arch=b64 -S sethostname,setdomainname -k system-locale"
      "-w /etc/issue -p wa -k system-locale"
      "-w /etc/issue.net -p wa -k system-locale"
      "-w /etc/hosts -p wa -k system-locale"
      "-w /etc/sysconfig/network -p wa -k system-locale"
      "-w /etc/selinux/ -p wa -k MAC-policy"
      "-w /etc/apparmor/ -p wa -k MAC-policy"
      "-w /etc/apparmor.d/ -p wa -k MAC-policy"
      "-w /var/log/faillog -p wa -k logins"
      "-w /var/log/lastlog -p wa -k logins"
      "-w /var/run/faillock -p wa -k logins"
      "-w /var/run/utmp -p wa -k session"
      "-w /var/log/btmp -p wa -k session"
      "-w /var/log/wtmp -p wa -k session"
      "-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng"
      "-a always,exit -S all -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=-1 -F key=perm_chng"
      "-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng"
      "-a always,exit -F arch=b32 -C euid!=uid -F auid!=unset -S execve -k user_emulation"
      "-a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve -k user_emulation"
      "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod"
      "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod"
      "-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=500 - F auid!=4294967295 -k perm_mod"
      "-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=500 - F auid!=4294967295 -k perm_mod"
      "-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod"
      "-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod"
      "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access"
      "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access"
      "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access"
      "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access"
      "-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=unset -k priv_cmd"
      "-a always,exit -F arch=b32 -S mount -F auid>=500 -F auid!=4294967295 -k export"
      "-a always,exit -F arch=b64 -S mount -F auid>=500 -F auid!=4294967295 -k export"
      "-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=unset -k usermod"
      "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete"
      "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete"
      "-w /etc/sudoers -p wa -k scope"
      "-w /etc/sudoers.d -p wa -k scope"
      "-w /etc/sudoers -p wa -k actions"
      "-w /var/log/sudo.log -p wa -k sudo_log_file"
      "-w /sbin/insmod -p x -k modules"
      "-w /sbin/rmmod -p x -k modules"
      "-w /sbin/modprobe -p x -k modules"
      "-a always,exit -F arch=b64 -S init_module,finit_module,delete_module,create_module,query_module -F auid>=1000 -F auid!=unset -k kernel_modules"
      "-a always,exit -F path=/usr/bin/kmod -F perm=x -F auid>=1000 -F auid!=unset - k kernel_modules"
      "-a always,exit -S init_module -S delete_module -k modules"
      "-a always,exit -F arch=b64 -S mount -F auid>=500 -F auid!=4294967295 -k mounts"
      "-a always,exit -F arch=b32 -S mount -F auid>=500 -F auid!=4294967295 -k mounts"
      "space_left_action = single"
      "action_mail_acct = email"
      "admin_space_left_action = single" 
      "disk_full_action = single"
      "disk_error_action = single"
      "max_log_file = 8"
      "max_log_file_action = keep_logs"
    ];
    # Kernel modules
    protectKernelImage = true;
    lockKernelModules = false; # this breaks iptables, wireguard, and virtd
    # force-enable the Page Table Isolation (PTI) Linux kernel feature
    forcePageTableIsolation = true;
    # User namespaces are required for sandboxing.
    # this means you cannot set `"user.max_user_namespaces" = 0;` in sysctl
    allowUserNamespaces = true;
    # Disable unprivileged user namespaces, unless containers are enabled
    unprivilegedUsernsClone = config.virtualisation.containers.enable;
    allowSimultaneousMultithreading = true;
  };
  # Services
  services.dbus.implementation = "broker";
  security.sudo.execWheelOnly = true;
  # Systemd
  systemd.services.systemd-journald = {
    serviceConfig = {
      UMask = 0077;
      PrivateNetwork = true;
      ProtectHostname = true;
      ProtectKernelModules = true;
    };
  }; 
  systemd.services.systemd-rfkill = {
    serviceConfig = {
      ProtectSystem = "strict";
      ProtectHome = true;
      ProtectKernelTunables = true;
      ProtectKernelModules = true;
      ProtectControlGroups = true;
      ProtectClock = true;
      ProtectProc = "invisible";
      ProcSubset = "pid";
      PrivateTmp = true;
      MemoryDenyWriteExecute = true;
      NoNewPrivileges = true;
      LockPersonality = true;
      RestrictRealtime = true;
      SystemCallArchitectures = "native";
      UMask = "0077";
      IPAddressDeny = "any";
    };
  };
  # Sysctl
  boot.kernel.sysctl = {
    "fs.suid_dumpable" = 0;
    # prevent pointer leaks
    "kernel.kptr_restrict" = 2;
    # restrict kernel log to CAP_SYSLOG capability
    "kernel.dmesg_restrict" = 1;
    # Note: certian container runtimes or browser sandboxes might rely on the following
    # restrict eBPF to the CAP_BPF capability
    "kernel.unprivileged_bpf_disabled" = 1;
    # should be enabled along with bpf above
    "net.core.bpf_jit_harden" = 2;
    # restrict loading TTY line disciplines to the CAP_SYS_MODULE
    "dev.tty.ldisk_autoload" = 0;
    # prevent exploit of use-after-free flaws
    "vm.unprivileged_userfaultfd" = 0;
    # kexec is used to boot another kernel during runtime and can be abused
    "kernel.kexec_load_disabled" = 1;
    # Kernel self-protection
    # SysRq exposes a lot of potentially dangerous debugging functionality to unprivileged users
    # 4 makes it so a user can only use the secure attention key. A value of 0 would disable completely
    "kernel.sysrq" = 4;
    # disable unprivileged user namespaces, Note: Docker, NH, and other apps may need this
    # "kernel.unprivileged_userns_clone" = 0; # commented out because it makes NH and other programs fail
    # restrict all usage of performance events to the CAP_PERFMON capability
    "kernel.perf_event_paranoid" = 3;
    # Network
    # protect against SYN flood attacks (denial of service attack)
    "net.ipv4.tcp_syncookies" = 1;
    # protection against TIME-WAIT assassination
    "net.ipv4.tcp_rfc1337" = 1;
    # enable source validation of packets received (prevents IP spoofing)
    "net.ipv4.conf.default.rp_filter" = 1;
    "net.ipv4.conf.all.rp_filter" = 1;
    "net.ipv4.conf.all.accept_redirects" = 0;
    "net.ipv4.conf.default.accept_redirects" = 0;
    "net.ipv4.conf.all.secure_redirects" = 0;
    "net.ipv4.conf.default.secure_redirects" = 0;
    # Protect against IP spoofing
    "net.ipv6.conf.all.accept_redirects" = 0;
    "net.ipv6.conf.default.accept_redirects" = 0;
    "net.ipv4.conf.all.send_redirects" = 0;
    "net.ipv4.conf.default.send_redirects" = 0;
    # prevent man-in-the-middle attacks
    "net.ipv4.icmp_echo_ignore_all" = 1;
    # ignore ICMP request, helps avoid Smurf attacks
    "net.ipv4.conf.all.forwarding" = 0;
    "net.ipv4.conf.default.accept_source_route" = 0;
    "net.ipv4.conf.all.accept_source_route" = 0;
    "net.ipv6.conf.all.accept_source_route" = 0;
    "net.ipv6.conf.default.accept_source_route" = 0;
    # Reverse path filtering causes the kernel to do source validation of
    "net.ipv6.conf.all.forwarding" = 0;
    "net.ipv6.conf.all.accept_ra" = 0;
    "net.ipv6.conf.default.accept_ra" = 0;
    ## TCP hardening
    # Prevent bogus ICMP errors from filling up logs.
    "net.ipv4.icmp_ignore_bogus_error_responses" = 1;
    # Disable TCP SACK
    "net.ipv4.tcp_sack" = 0;
    "net.ipv4.tcp_dsack" = 0;
    "net.ipv4.tcp_fack" = 0;
    # Userspace
    # restrict usage of ptrace
    "kernel.yama.ptrace_scope" = 2;
    # ASLR memory protection (64-bit systems)
    "vm.mmap_rnd_bits" = 32;
    "vm.mmap_rnd_compat_bits" = 16;
    # only permit symlinks to be followed when outside of a world-writable sticky directory
    "fs.protected_symlinks" = 1;
    "fs.protected_hardlinks" = 1;
    # Prevent creating files in potentially attacker-controlled environments
    "fs.protected_fifos" = 2;
    "fs.protected_regular" = 2;
    # Randomize memory
    "kernel.randomize_va_space" = 2;
    # Exec Shield (Stack protection)
    "kernel.exec-shield" = 1;
    ## TCP optimization
    # TCP Fast Open is a TCP extension that reduces network latency by packing
    # data in the sender’s initial TCP SYN. Setting 3 = enable TCP Fast Open for
    # both incoming and outgoing connections:
    "net.ipv4.tcp_fastopen" = 3;
    # Bufferbloat mitigations + slight improvement in throughput & latency
    "net.ipv4.tcp_congestion_control" = "bbr";
    "net.core.default_qdisc" = "cake";
  };
  boot.kernelParams = [
    # Enable audit
    "audit=1"
    # Serial
    "console=tty1"
    "console=ttyS0,115200n8"
    "console=ttyS1,115200n8"
    # make it harder to influence slab cache layout
    "slab_nomerge"
    # enables zeroing of memory during allocation and free time
    # helps mitigate use-after-free vulnerabilaties
    "init_on_alloc=1"
    "init_on_free=1"
    # randomizes page allocator freelist, improving security by
    # making page allocations less predictable
    "page_alloc.shuffel=1"
    # enables Kernel Page Table Isolation, which mitigates Meltdown and
    # prevents some KASLR bypasses
    "pti=on"
    # randomizes the kernel stack offset on each syscall
    # making attacks that rely on a deterministic stack layout difficult
    "randomize_kstack_offset=on"
    # disables vsyscalls, they've been replaced with vDSO
    "vsyscall=none"
    # disables debugfs, which exposes sensitive info about the kernel
    "debugfs=off"
    # certain exploits cause an "oops", this makes the kernel panic if an "oops" occurs
    "oops=panic"
    # only alows kernel modules that have been signed with a valid key to be loaded
    # making it harder to load malicious kernel modules
    # can make VirtualBox or Nvidia drivers unusable
    "module.sig_enforce=1"
    # prevents user space code excalation
    "lockdown=confidentiality"
    # "rd.udev.log_level=3"
    # "udev.log_priority=3"
  ];
  boot.blacklistedKernelModules = [
    # Obscure networking protocols
    "dccp"   # Datagram Congestion Control Protocol
    "sctp"  # Stream Control Transmission Protocol
    "rds"  # Reliable Datagram Sockets
    "tipc"  # Transparent Inter-Process Communication
    "n-hdlc" # High-level Data Link Control
    "ax25"  # Amateur X.25
    "netrom"  # NetRom
    "x25"     # X.25
    "rose"
    "decnet"
    "econet"
    "af_802154"  # IEEE 802.15.4
    "ipx"  # Internetwork Packet Exchange
    "appletalk"
    "psnap"  # SubnetworkAccess Protocol
    "p8023"  # Novell raw IEE 802.3
    "p8022"  # IEE 802.3
    "can"   # Controller Area Network
    "atm"
    # Various rare filesystems
    "cramfs"
    "freevxfs"
    "jffs2"
    "hfs"
    "hfsplus"
    "udf"
    # "squashfs"  # compressed read-only file system used for Live CDs
    # "cifs"  # cmb (Common Internet File System)
    # "nfs"  # Network File System
    # "nfsv3"
    # "nfsv4"
    # "ksmbd"  # SMB3 Kernel Server
    # "gfs2"  # Global File System 2
    # vivid driver is only useful for testing purposes and has been the
    # cause of privilege escalation vulnerabilities
    # "vivid"
  ];
  config = {
    services = {
      fail2ban = {
        enable = true;
        maxretry = 5;
        bantime = "1h";
        # ignoreIP = [
        # "172.16.0.0/12"
        # "192.168.0.0/16"
        # "2601:881:8100:8de0:31e6:ac52:b5be:462a"
        # "matrix.org"
        # "app.element.io" # don't ratelimit matrix users
        # ];

        bantime-increment = {
          enable = true; # Enable increment of bantime after each violation
          multipliers = "1 2 4 8 16 32 64 128 256";
          maxtime = "168h"; # Do not ban for more than 1 week
          overalljails = true; # Calculate the bantime based on all the violations
        };
      };
      openssh = {
        enable = true;
        settings = {
          PasswordAuthentication = false;
          PermitEmptyPasswords = false;
          PermitTunnel = false;
          UseDns = false;
          KbdInteractiveAuthentication = false;
          X11Forwarding = config.services.xserver.enable;
          MaxAuthTries = 3;
          MaxSessions = 2;
          ClientAliveInterval = 300;
          ClientAliveCountMax = 0;
          AllowUsers = ["your-user"];
          TCPKeepAlive = false;
          AllowTcpForwarding = false;
          AllowAgentForwarding = false;
          LogLevel = "VERBOSE";
          PermitRootLogin = "no";
          KexAlgorithms = [
            # Key Exchange Algorithms in priority order
            "curve25519-sha256@libssh.org"
            "ecdh-sha2-nistp521"
            "ecdh-sha2-nistp384"
            "ecdh-sha2-nistp256"
            "diffie-hellman-group-exchange-sha256"
          ];
          Ciphers = [
            # stream cipher alternative to aes256, proven to be resilient
            # Very fast on basically anything
            "chacha20-poly1305@openssh.com"
            # industry standard, fast if you have AES-NI hardware
            "aes256-gcm@openssh.com"
            "aes128-gcm@openssh.com"
            "aes256-ctr"
            "aes192-ctr"
            "aes128-ctr"
          ];
          Macs = [
            # Combines the SHA-512 hash func with a secret key to create a MAC
            "hmac-sha2-512-etm@openssh.com"
            "hmac-sha2-256-etm@openssh.com"
            "umac-128-etm@openssh.com"
            "hmac-sha2-512"
            "hmac-sha2-256"
            "umac-128@openssh.com"
          ];
        };
        # These keys will be generated for you
        hostKeys = [
          {
            path = "/etc/ssh/ssh_host_ed25519_key";
            type = "ed25519";
          }
        ];
      };
    };
  };
}