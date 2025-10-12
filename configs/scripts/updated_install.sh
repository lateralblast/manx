#!/run/current-system/sw/bin/bash
export PATH="/run/wrappers/bin:/root/.nix-profile/bin:/nix/profile/bin:/root/.local/state/nix/profile/bin:/etc/profiles/per-user/root/bin:/nix/var/nix/profiles/default/bin:/run/current-system/sw/bin"

# Set general environment
declare -A ai

ai['swap']="true"                                           # ai : Use swap
ai['lvm']="false"                                             # ai : Use LVM
ai['zsh']="true"                                             # ai : Use zsh
ai['dhcp']="true"                                           # ai : Use DHCP
ai['bridge']="false"                                       # ai : Use Bridge
ai['sshserver']="true"                                 # ai : Enable SSH server
ai['bridgenic']="br0"                                 # ai : Bridge Network Interface
ai['reboot']="true"                                       # ai : Reboot after install
ai['poweroff']="false"                                   # ai : Power off after install
ai['attended']="false"                                   # ai : Attended install
ai['nixinstall']="true"                               # ai : Run NixOS install
ai['rootfs']="zfs"                                       # ai : Root filesystem
ai['bootfs']="vfat"                                       # ai : Boot filesystem
ai['rootdisk']="first"                                   # ai : Root disk
ai['mbrpart']="1"                                     # ai : MBR partition
ai['rootpart']="2"                                   # ai : Root partition
ai['efipart']="3"                                     # ai : UEFI partition
ai['bootpart']="3"                                    # ai : Boot partition
ai['swappart']="4"                                   # ai : Swap partition
ai['swapsize']="2G"                                   # ai : Swap size
ai['rootsize']="100%FREE"                                   # ai : Root size
ai['bootsize']="512M"                                   # ai : Boot size
ai['rootpool']="rpool"                                   # ai : Root pool
ai['swapvolname']="swap"                             # ai : Swap volume name
ai['bootvolname']="boot"                             # ai : Boot volume name
ai['rootvolname']="nixos"                             # ai : Root volume name
ai['installdir']="/mnt"                               # ai : Install directory
ai['mbrpartname']=""                             # ai : MBR partition name
ai['locale']="en_AU.UTF-8"                                       # ai : Locale
ai['devnodes']="/dev/disk/by-uuid"                                   # ai : Device nodes
ai['logdir']="/var/log"                                       # ai : Log directory
ai['logfile']="/var/log/install.log"                                     # ai : Log file
ai['timezone']="Australia/Melbourne"                                   # ai : Timezone
ai['usershell']="zsh"                                 # ai : User shell
ai['username']="nixos"                                   # ai : Username
ai['extragroups']="wheel"                             # ai : User extra groups
ai['usergecos']="Admin"                                 # ai : User GECOS
ai['normaluser']="true"                               # ai : Normal user
ai['sudocommand']="ALL"                             # ai : Sudo command
ai['sudooptions']="NOPASSWD"                             # ai : Sudo options
ai['rootpassword']="nixos"                           # ai : Root password
ai['rootcrypt']=$( mkpasswd --method=sha-512 "${ai['rootpassword']}" )  # ai : Root crypt
ai['userpassword']="nixos"                           # ai : User password
ai['usercrypt']=$( mkpasswd --method=sha-512 "${ai['userpassword']}" )  # ai : User crypt
ai['stateversion']="25.05"                           # ai : State version
ai['hostname']="nixos"                                   # ai : Hostname
ai['hostid']=$( head -c 8 /etc/machine-id )                              # ai : HostID
ai['nixdir']="${ai['installdir']}/etc/nixos"                             # ai : Nix directory
ai['nixcfg']="${ai['nixdir']}/configuration.nix"                         # ai : Nix configuration
ai['hwcfg']="${ai['nixdir']}/hardware-configuration.nix"                 # ai : Nix hardware configuration
ai['zfsoptions']="-O mountpoint=none -O atime=off -O compression=lz4 -O xattr=sa -O acltype=posixacl -o ashift=12"                               # ai : ZFS filesystem options
ai['availmods']="ahci ehci_pci megaraid_sas sdhci_pci sd_mod sr_mod usbhid usb_storage virtio_blk virtio_pci xhci_pci"                                 # ai : Available modules
ai['initmods']=""                                   # ai : Initrd modules
ai['bootmods']=""                                   # ai : Boot modules
ai['experimental-features']="nix-command flakes"         # ai : Experimental Features
ai['unfree']="false"                                       # ai : Non free software
ai['gfxmode']="auto"                                     # ai : Graphics Mode
ai['gfxpayload']="text"                               # ai : Graphics Payload
ai['nic']="first"                                             # ai : Network Interface
ai['dns']="8.8.8.8"                                             # ai : DNS Server
ai['ip']=""                                               # ai : IP Address
ai['gateway']=""                                     # ai : Gateway Address
ai['cidr']="24"                                           # ai : CIDR
ai['sshkey']="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJvM+S0BZ+l3rJVvwMFNQGD/e1MJwB5LAwhsfMXhE/iR spindler@Richards-MacBook-Pro.local"                                       # ai : SSH key
ai['oneshot']="true"                                     # ai : Oneshot
ai['kernelparams']="audit=1 slab_nomerge init_on_alloc=1 init_on_free=1 page_alloc.shuffel=1 pti=on randomize_kstack_offset=on vsyscall=none debugfs=off oops=panic module.sig_enforce=1 lockdown=confidentiality rd.udev.log_level=3 udev.log_priority=3  console=tty1  console=ttyS0,115200no8 "                           # ai : Kernel Parameters
ai['grubextraconfig']=" serial --speed=115200 --unit=0 --word=8 --parity=no --stop=1 --port=0x02f8  terminal_input serial  terminal_output serial "                     # ai : Extra grub configuration
ai['journaldextraconfig']="SystemMaxUse=500M SystemMaxFileSize=50M"             # ai : Extra journald configuration
ai['journaldupload']="false"                       # ai : Journald upload
ai['imports']="<nixpkgs/nixos/modules/system/boot/loader/grub/grub.nix> <nixpkgs/nixos/modules/system/boot/kernel.nix>"                                     # ai : Nix configuration imports
ai['hwimports']=""                                 # ai : Nix hardware configuration imports
ai['kernel']=""                                       # ai : Kernel
ai['passwordauthentication']="false"       # ai : SSH Password Authentication
ai['permitemptypasswords']="false"           # ai : SSH Permit Empty Password
ai['kbdinteractive']="false"                       # ai : SSH Keyboard Interactive Authentication
ai['usedns']="false"                                       # ai : SSH Use DNS
ai['x11forwarding']="false"                         # ai : SSH X11 Forwarding
ai['maxauthtries']="3"                           # ai : SSH Max Authentication Tries
ai['maxsessions']="2"                             # ai : SSH Max Sessions
ai['permittunnel']="false"                           # ai : SSH Permit Tunnel
ai['allowusers']="nixos"                               # ai : SSH Allowed Users
ai['loglevel']="VERBOSE"                                   # ai : SSH Log Level
ai['clientaliveinterval']="300"             # ai : SSH Client Alive Interval
ai['clientalivecountmax']="0"             # ai : SSH Client Alive Max Count
ai['allowtcpforwarding']="false"               # ai : SSH Allow TCP Forwarding
ai['allowagentforwarding']="false"           # ai : SSH Allow Agent Forwarding
ai['permitrootlogin']="no"                     # ai : SSH Permit Root Login
ai['hostkeyspath']="/etc/ssh/ssh_host_ed25519_key"                           # ai : SSH Host Key Path
ai['hostkeystype']="ed25519"                           # ai : SSH Host Key Type
ai['kexalgorithms']="curve25519-sha256@libssh.org ecdh-sha2-nistp521 ecdh-sha2-nistp384 ecdh-sha2-nistp256 diffie-hellman-group-exchange-sha256"                         # ai : SSH Key Exchange Algorithms
ai['ciphers']="chacha20-poly1305@openssh.com aes256-gcm@openssh.com aes128-gcm@openssh.com aes256-ctr aes192-ctr aes128-ctr"                                     # ai : SSH Ciphers
ai['macs']="hmac-sha2-512-etm@openssh.com hmac-sha2-256-etm@openssh.com umac-128-etm@openssh.com hmac-sha2-512 hmac-sha2-256 umac-128@openssh.com"                                           # ai : SSH MACs
ai['isomount']="/iso"                                   # ai : ISO mount
ai['prefix']="ai"                                       # ai : Prefix
ai['targetarch']="arm64"                               # ai : Target Architecture
ai['systempackages']="aide ansible btop curl dmidecode efibootmgr ethtool file fwupd git kernel-hardening-checker lsb-release lsof lshw lynis nmap pciutils ripgrep rclone tmux usbutils vim wget"                       # ai : System Packages
ai['blacklist']="dccp sctp rds tipc n-hdlc ax25 netrom x25 rose decnet econet af_802154 ipx appletalk psnap p8023 p8022 can atm cramfs freevxfs jffs2 hfs hfsplus udf"                                 # ai : Blacklist Modules
ai['sysctl']="    \"kernel.exec-shield\" = 1;
    \"net.ipv4.tcp_rfc1337\" = 1;
    \"net.ipv6.conf.all.forwarding\" = 0;
    \"net.ipv4.conf.all.accept_redirects\" = 0;
    \"net.ipv4.conf.all.secure_redirects\" = 0;
    \"kernel.dmesg_restrict\" = 1;
    \"kernel.randomize_va_space\" = 2;
    \"net.ipv4.conf.default.secure_redirects\" = 0;
    \"net.ipv4.conf.all.rp_filter\" = 1;
    \"net.ipv6.conf.default.accept_ra\" = 0;
    \"net.ipv4.conf.default.accept_source_route\" = 0;
    \"net.ipv4.icmp_ignore_bogus_error_responses\" = 1;
    \"fs.protected_hardlinks\" = 1;
    \"kernel.yama.ptrace_scope\" = 2;
    \"dev.tty.ldisk_autoload\" = 0;
    \"kernel.unprivileged_bpf_disabled\" = 1;
    \"net.ipv4.conf.all.forwarding\" = 0;
    \"fs.suid_dumpable\" = 0;
    \"vm.mmap_rnd_compat_bits\" = 16;
    \"net.ipv6.conf.all.accept_ra\" = 0;
    \"net.ipv4.conf.default.rp_filter\" = 1;
    \"fs.protected_regular\" = 2;
    \"net.ipv4.conf.all.accept_source_route\" = 0;
    \"net.ipv4.tcp_dsack\" = 0;
    \"vm.unprivileged_userfaultfd\" = 0;
    \"net.ipv4.conf.all.send_redirects\" = 0;
    \"fs.protected_fifos\" = 2;
    \"net.ipv4.tcp_fack\" = 0;
    \"net.ipv4.tcp_syncookies\" = 1;
    \"net.ipv4.icmp_echo_ignore_all\" = 1;
    \"kernel.perf_event_paranoid\" = 3;
    \"net.core.default_qdisc\" = \"cake\";
    \"net.ipv4.tcp_sack\" = 0;
    \"net.ipv4.conf.default.send_redirects\" = 0;
    \"net.ipv4.conf.default.accept_redirects\" = 0;
    \"net.ipv4.tcp_congestion_control\" = \"bbr\";
    \"net.core.bpf_jit_harden\" = 2;
    \"net.ipv6.conf.all.accept_source_route\" = 0;
    \"kernel.kptr_restrict\" = 2;
    \"fs.protected_symlinks\" = 1;
    \"net.ipv6.conf.default.accept_source_route\" = 0;
    \"kernel.sysrq\" = 4;
    \"kernel.kexec_load_disabled\" = 1;
    \"net.ipv6.conf.default.accept_redirects\" = 0;
    \"vm.mmap_rnd_bits\" = 32;
    \"net.ipv4.tcp_fastopen\" = 3;
    \"net.ipv6.conf.all.accept_redirects\" = 0;
"                                       # ai : Sysctl
ai['audit']="true"                                         # ai : Audit
ai['auditrules']="      \"-a exit,always -F arch=b64 -S execve\"
      \"-a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime,stime -k time-change\"
      \"-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change\"
      \"-w /etc/localtime -p wa -k time-change\"
      \"-w /etc/group -p wa -k identity\"
      \"-w /etc/passwd -p wa -k identity\"
      \"-w /etc/gshadow -p wa -k identity\"
      \"-w /etc/shadow -p wa -k identity\"
      \"-a exit,always -F arch=b32 -S sethostname,setdomainname -k system-locale\"
      \"-a exit,always -F arch=b64 -S sethostname,setdomainname -k system-locale\"
      \"-w /etc/issue -p wa -k system-locale\"
      \"-w /etc/issue.net -p wa -k system-locale\"
      \"-w /etc/hosts -p wa -k system-locale\"
      \"-w /etc/apparmor/ -p wa -k MAC-policy\"
      \"-w /etc/apparmor.d/ -p wa -k MAC-policy\"
      \"-w /var/log/faillog -p wa -k logins\"
      \"-w /var/log/lastlog -p wa -k logins\"
      \"-w /var/run/faillock -p wa -k logins\"
      \"-w /var/run/utmp -p wa -k session\"
      \"-w /var/log/btmp -p wa -k session\"
      \"-w /var/log/wtmp -p wa -k session\"
      \"-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng\"
      \"-a always,exit -F arch=b32 -C euid!=uid -F auid!=unset -S execve -k user_emulation\"
      \"-a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve -k user_emulation\"
      \"-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod\"
      \"-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod\"
      \"-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod\"
      \"-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod\"
      \"-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access\"
      \"-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access\"
      \"-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access\"
      \"-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access\"
      \"-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=unset -k priv_cmd\"
      \"-a always,exit -F arch=b32 -S mount -F auid>=500 -F auid!=4294967295 -k export\"
      \"-a always,exit -F arch=b64 -S mount -F auid>=500 -F auid!=4294967295 -k export\"
      \"-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete\"
      \"-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete\"
      \"-w /etc/sudoers -p wa -k scope\"
      \"-w /etc/sudoers.d -p wa -k scope\"
      \"-w /etc/sudoers -p wa -k actions\"
      \"-w /var/log/sudo.log -p wa -k sudo_log_file\"
      \"-w /run/current-system/sw/bin/insmod -p x -k modules\"
      \"-w /run/current-system/sw/bin/rmmod -p x -k modules\"
      \"-w /run/current-system/sw/bin/modprobe -p x -k modules\"
      \"-a always,exit -F arch=b64 -S init_module,finit_module,delete_module,create_module,query_module -F auid>=1000 -F auid!=unset -k kernel_modules\"
      \"-a always,exit -S init_module -S delete_module -k modules\"
      \"-a always,exit -F arch=b64 -S mount -F auid>=500 -F auid!=4294967295 -k mounts\"
      \"-a always,exit -F arch=b32 -S mount -F auid>=500 -F auid!=4294967295 -k mounts\"
"                               # ai : Audit Rules
ai['fail2ban']="true"                                   # ai : Fail2ban
ai['maxretry']="5"                                   # ai : Fail2ban Max Retry
ai['bantime']="1h"                                     # ai : Fail2ban Ban Time
ai['ignoreip']="172.16.0.0/12 192.168.0.0/16"                                   # ai : Fail2ban Ignore IP
ai['bantimeincrement']="true"                   # ai : Fail2ban Ban Time Increment
ai['multipliers']="1 2 4 8 16 32 64 128 256"                             # ai : Fail2ban Multipliers
ai['maxtime']="1h"                                     # ai : Fail2ban Max Time
ai['overalljails']="true"                           # ai : Overall Jails
ai['protectkernelimage']="true"               # ai : Protect Kernel Image
ai['lockkernelmodules']="false"                 # ai : Lock Kernel Modules
ai['forcepagetableisolation']="true"     # ai : Force Page Table Isolation
ai['unprivilegedusernsclone']="config.virtualisation.containers.enable"     # ai : Unprivileged User NS Clone
ai['allowsmt']="true"                                   # ai : Allow SMT
ai['execwheelonly']="true"                         # ai : Exec Wheel Only
ai['dbusimplementation']="broker"               # ai : DBus Implementation
ai['allowusernamespaces']="true"             # ai : Allow User Namespaces
ai['systemdumask']="0077"                           # ai : Systemd umask
ai['privatenetwork']="true"                       # ai : Protect Network
ai['protecthostname']="true"                     # ai : Protect Hostname
ai['protectkernelmodules']="true"           # ai : Protect Kernel Modules
ai['protectsystem']="strict"                         # ai : Protect System
ai['protecthome']="true"                             # ai : Protect Home
ai['protectkerneltunables']="true"         # ai : Protect Kernel Tunables
ai['protectkernelmodules']="true"           # ai : Protect Kernel Modules
ai['protectcontrolgroups']="true"           # ai : Protect Control Groups
ai['protectclock']="true"                           # ai : Protect Clock
ai['protectproc']="invisible"                             # ai : Protect Proccesses
ai['procsubset']="pid"                               # ai : Process Subset
ai['privatetmp']="true"                               # ai : Private Temp
ai['memorydenywriteexecute']="true"       # ai : Memory Deny Write Execute
ai['nownewprivileges']="true"                   # ai : Now New Privileges
ai['lockpersonality']="true"                     # ai : Lock Personality
ai['restrictrealtime']="true"                   # ai : Restrict Real Time
ai['systemcallarchitectures']="native"     # ai : System Call Architectures
ai['ipaddressdeny']="any"                         # ai : IP Address Deny
ai['firewall']="true"                                   # ai : Firewall
ai['allowedtcpports']="22"                     # ai : Allowed TCP Ports
ai['allowedudpports']=""                     # ai : Allowed UDP Ports
ai['fwupd']="true"                                         # ai : Firmware Update Service
ai['logrotate']="true"                                 # ai : Log rotate
ai['processgrub']="true"                             # ai : Process grub
ai['interactiveinstall']="false"               # ai : Interactive Install
ai['scriptfile']="$0"

spacer=$'\n'

# If oneshot is disabled exit

if [ "${ai['oneshot']}" = "false" ]; then
  exit
fi

# Check we are using only one volume manager

if [ "${ai['lvm']}" = "true" ] && [ "${ai['rootfs']}" = "zfs" ]; then
  echo "Cannot use two volume managers (LVM and ZFS)"
  exit
fi

# Parse parameters

parse_parameters () {
  echo "Processing parameters"
  for param in ${!ai[@]}
  do
    echo "Setting ${param} to ${ai[${param}]}"
  done
}

# Parse grub parameters

parse_grub_parameters () {
  if [ "${ai['processgrub']}" = "true" ]; then
    echo "Processing grub parameters"
    str=$( < /proc/cmdline )
    del="ai."
    sep="${str}${del}"
    items=();
    while [[ "${sep}" ]]; do
      items+=( "${sep%%"$del"*}" );
      sep=${sep#*"$del"};
    done;
    declare -a items
    for item in "${items[@]}"; do
      if [[ ! ${item} =~ BOOT_IMAGE ]]; then
        IFS='=' read -r param value <<< ${item}
        value=${value//\"/}
        value=${value// nohibernate*/}
        value="${value%"${value##*[![:space:]]}"}"
        if [ ! "${value}" = "" ]; then
          if [ ! "${ai[${param}]}" = "${value}" ]; then
            ai[${param}]="${value}"
            echo "Setting ${param} to ${value}"
          fi
        fi
      fi
    done
  fi
}

# Set ZFS options

set_zfs_options () {
  ai['zfsoptions']="${ai['zfsoptions']} -R ${ai['installdir']}"
  echo "Setting zfsoptions to ${ai['zfsoptions']}"
}

# Set up networking

setup_networking () {
  if [ "${ai['dhcp']}" = "false" ]; then
    if [ "${ai['nic']}" = "first" ]; then
      counter=1
      ai['nic']=$( ip link | grep "state UP" | awk '{ print $2}' | head -1 | grep ^e | cut -f1 -d: )
      while [ "${ai['nic']}" = "" ]; do
        echo "Waiting for network link to come up (count=${counter})"
        sleep 5s
        ai['nic']=$( ip link | grep "state UP" | awk '{ print $2}' | head -1 | grep ^e | cut -f1 -d: )
        counter=$(( counter + 1 ))
        if [ "${counter}" = "10" ]; then
          echo "Could not find network with link up"
          ai['nic']=$( ip link | awk '{ print $2}' | head -1 | grep ^e | cut -f1 -d: )
        fi
      done
      echo "Setting nic to ${ai['nic']}"
    fi
  fi
}

# Discover first disk

discover_first_disk () {
  if [ "${ai['rootdisk']}" = "first" ]; then
    ai['rootdisk']=$( lsblk -l -o TYPE,NAME,TRAN | grep disk | grep -v usb | sort | head -1 | awk '{print $2}' )
    ai['rootdisk']="/dev/${ai['rootdisk']}"
    echo "Setting rootdisk to ${ai['rootdisk']}"
  fi
}


# Update partitions for NVMe devices

setup_nvme_partitions () {
  if [[ ${ai['rootdisk']} =~ nvme ]]; then
    ai['efipart']="1"
    ai['bootpart']="1"
    ai['swappart']="2"
    ai['rootpart']="3"
    ai['rootpart']="p${ai['rootpart']}"
    ai['efipart']="p${ai['efipart']}"
    ai['bootpart']="p${ai['efipart']}"
    ai['swappart']="p${ai['swappart']}"
    ai['devnodes']="/dev/disk/by-id"
  fi
}

# Boot modules

setup_boot_modules () {
  if [ "${ai['bootmods']}" = "" ]; then
    ai['bootmods']="kvm-intel"
  else
    ai['bootmods']="${ai['bootmods']} kvm-intel"
  fi
  echo "Setting bootmods to ${ai['bootmods']}"
}

# QEMU check

setup_hwimports () {
  qemu_check=$( cat /proc/ioports | grep QEMU )
  if [ -n "${qemu_check}" ]; then
    if [ "${ai['hwimports']}" = "" ]; then
      ai['hwimports']="(modulesPath + \"/profiles/qemu-guest.nix\")"
    else
      ai['hwimports']="${ai['hwimports']} (modulesPath + \"/profiles/qemu-guest.nix\")"
    fi
    echo "Setting hwimports to ${ai['hwimports']}"
  fi
}

# Check if BIOS or UEFI boot

check_bios_or_uefi () {
  if [ -d "/sys/firmware/efi" ]; then
    ai['biosflag']="false"
    ai['uefiflag']="true"
    ai['grubdev']="nodev"
    ai['bootvolname']="uefiboot"
  else
    ai['biosflag']="true"
    ai['uefiflag']="false"
    ai['grubdev']="${ai['rootdisk']}"
    ai['bootvolname']="biosboot"
  fi
  echo "Setting biosflag to ${ai['biosflag']}"
  echo "Setting uefiflag to ${ai['uefiflag']}"
  echo "Setting grubdev to ${ai['grubdev']}"
  echo "Setting biosvolname to ${ai['biosvolname']}"
}

# Set root partition type

setup_root_partition_type () {
  case "${ai['rootfs']}" in
    "zfs")
      ai['partflag']="BF01"
      ai['rootname']="rpool"
      ;;
    *)
      ai['partflag']="8300"
      ai['rootname']="root"
      ;;
  esac
  echo "Setting partflag to ${ai['partflag']}"
  echo "Setting rootname to ${ai['rootname']}"
}

# Wipe and set up disk

wipe_root_disk () {
  echo "Wiping ${ai['rootdisk']}"
  swapoff -a
  umount -Rl ${ai['installdir']}
  zpool destroy -f ${ai['rootpool']}
  lvremove -f ${ai['rootpool']}
  wipefs ${ai['rootdisk']}
  sgdisk --zap-all ${ai['rootdisk']}
  zpool labelclear -f ${ai['rootdisk']}
  partprobe ${ai['rootdisk']}
  sleep 5s
}

# Partition root disk

partition_root_disk () {
  echo "Partitioning ${ai['rootdisk']}"
  if [ "${ai['biosflag']}" = "true" ]; then
    sgdisk -a ${ai['mbrpart']} -n ${ai['mbrpart']}:0:+1M -t ${ai['mbrpart']}:EF02 -c ${ai['mbrpart']}:${ai['mbrvolname']} ${ai['rootdisk']}
  fi
  if [ "${ai['lvm']}" = "true" ]; then
    sgdisk -n ${ai['rootpart']}:0:0 -t ${ai['rootpart']}:${ai['partflag']} -c ${ai['rootpart']}:${ai['rootvolname']} ${ai['rootdisk']}
    pvcreate -ff ${ai['rootdisk']}${ai['rootpart']}
    vgcreate -f ${ai['rootpool']} ${ai['rootdisk']}${ai['rootpart']}
    lvcreate -y --size ${ai['bootsize']} --name ${ai['bootvolname']} ${ai['rootpool']}
    if [ "${USE_SWAP}" = "true" ]; then
      lvcreate -y --size ${ai['swapsize']} --name ${ai['swapvolname']} ${ai['rootpool']}
    fi
    lvcreate -y -l ${ai['rootsize']} --name ${ai['rootvolname']} ${ai['rootpool']}
    ai['swapvol']="/dev/${ai['rootpool']}/${ai['swapvolname']}"
    ai['bootvol']="/dev/${ai['rootpool']}/${ai['bootvolname']}"
    ai['rootvol']="/dev/${ai['rootpool']}/${ai['rootvolname']}"
    if [ "${ai[initmods]}" = "" ]; then
      ai['initmods']="\"dm-snapshot\" \"dm-raid\" \"dm-cache-default\""
    else
      ai['initmods']="${ai['initmods']} \"dm-snapshot\" \"dm-raid\" \"dm-cache-default\""
    fi
    ai['rootsearch']=$( ls -l ${ai['rootvol']} | awk '{print $11}' | cut -f2 -d/ )
    ai['bootsearch']=$( ls -l ${ai['bootvol']} | awk '{print $11}' | cut -f2 -d/ )
    ai['swapsearch']=$( ls -l ${ai['swapvol']} | awk '{print $11}' | cut -f2 -d/ )
  else
    sgdisk -n ${ai['efipart']}:2M:+${ai['bootsize']} -t ${ai['efipart']}:EF00 -c ${ai['efipart']}:${ai['bootvolname']} ${ai['rootdisk']}
    if [ "${ai['swap']}" = "true" ]; then
      sgdisk -n ${ai['swappart']}:0:+${ai['swapsize']} -t ${ai['swappart']}:8200 -c ${ai['swappart']}:${ai['swapname']} ${ai['rootdisk']}
    fi
    sgdisk -n ${ai['rootpart']}:0:0 -t ${ai['rootpart']}:${ai['partflag']} -c ${ai['rootpart']}:${ai['rootvolname']} ${ai['rootdisk']}
    ai['swapvol']="${ai['rootdisk']}${ai['swappart']}"
    ai['bootvol']="${ai['rootdisk']}${ai['bootpart']}"
    ai['rootvol']="${ai['rootdisk']}${ai['rootpart']}"
    ai['rootsuffix']=$( echo "${ai['rootdisk']}" | cut -f3 -d/  )
    ai['rootsearch']="${ai['rootsuffix']}${ai['rootpart']}"
    ai['bootsearch']="${ai['rootsuffix']}${ai['bootpart']}"
    ai['swapsearch']="${ai['rootsuffix']}${ai['swappart']}"
  fi
  partprobe ${ai['rootdisk']}
  sleep 5s
  echo "Setting rootvol to ${ai['rootvol']}"
  echo "Setting bootvol to ${ai['bootvol']}"
  echo "Setting swapvol to ${ai['swapvol']}"
  echo "Setting rootsearch to ${ai['rootsearch']}"
  echo "Setting bootsearch to ${ai['bootsearch']}"
  echo "Setting swapsearch to ${ai['swapsearch']}"
}

# Make and mount filesystems

make_and_mount_filesystems () {
  echo "Making and mounting filesystems"
  if [ "${ai['swap']}" = "true" ]; then
    mkswap -L ${ai['swapvolname']} ${ai['swapvol']}
    swapon ${ai['swapvol']}
  fi
  if [ "${ai['rootfs']}" = "zfs" ]; then
    zpool create -f ${ai['zfsoptions']} ${ai['rootpool']} ${ai['rootdisk']}${ai['rootpart']}
    for mount_name in root nix var home; do
      zfs create -o mountpoint=legacy ${ai['rootpool']}/${mount_name}
    done
    mount -t zfs ${ai['rootpool']}/root ${ai['installdir']}
    for mount_name in nix var home; do
      mkdir -p ${ai['installdir']}/${mount_name}
      mount -t ${ai['rootfs']} ${ai['rootpool']}/${mount_name} ${ai['installdir']}/${mount_name}
    done
  else
    if [ "${ai['rootfs']}" = "ext4" ]; then
      mkfs.${ai['rootfs']} -F -L ${ai['rootvolname']} ${ai['rootvol']}
    else
      mkfs.${ai['rootfs']} -f -L ${ai['rootvolname']} ${ai['rootvol']}
    fi
    mount -t ${ai['rootfs']} ${ai['rootvol']} ${ai['installdir']}
  fi
  mkfs.${ai['bootfs']} ${ai['bootvol']}
  mkdir ${ai['installdir']}/boot
  mount ${ai['bootvol']} ${ai['installdir']}/boot
  mkdir -p ${ai['nixdir']}
  rm ${ai['nixdir']}/*
  cp ${ai['isomount']}/${ai['prefix']}/*.nix ${ai['nixdir']}
  echo "Creating log directory ${ai['installdir']}${ai['logdir']}"
  mkdir -p ${ai['installdir']}/${ai['logdir']}
}

# Create configuration.nix

create_nix_configuration () {
  echo "Creating ${ai['nixcfg']}"
  tee ${ai['nixcfg']} << NIX_CFG
{ config, lib, pkgs, ... }:
{
  imports = [
    ${ai['imports']// /${spacer}    }
    ./hardware-configuration.nix
  ];
  boot.loader.systemd-boot.enable = ${ai['uefiflag']};
  boot.loader.efi.canTouchEfiVariables = ${ai['uefiflag']};
  boot.loader.grub.devices = [ "${ai['grubdev']}" ];
  boot.loader.grub.gfxmodeEfi = "${ai['gfxmode']}";
  boot.loader.grub.gfxpayloadEfi = "${ai['gfxpayload']}";
  boot.loader.grub.gfxmodeBios = "${ai['gfxmode']}";
  boot.loader.grub.gfxpayloadBios = "${ai['gfxpayload']}";
  boot.initrd.supportedFilesystems = ["${ai['rootfs']}"];
  boot.supportedFilesystems = [ "${ai['rootfs']}" ];
  boot.zfs.devNodes = "${ai['devnodes']}";
  services.lvm.boot.thin.enable = ${ai['lvm']};
NIX_CFG
  if ! [ "${ai['kernel']}" = "" ]; then
    tee -a ${ai['nixcfg']} << NIX_CFG
  boot.kernelPackages = lib.mkDefault pkgs.linuxPackages${ai['kernel']};
NIX_CFG
  fi
  tee -a ${ai['nixcfg']} << NIX_CFG
  boot.blacklistedKernelModules = [
NIX_CFG
  for item in ${ai['blacklist']}; do
  tee -a ${ai['nixcfg']} << NIX_CFG
    "${item}"
NIX_CFG
  done
  tee -a ${ai['nixcfg']} << NIX_CFG
  ];

  # Sysctl Parameters
  boot.kernel.sysctl = {
${ai['sysctl']}
  };

  # Security
  security = {
    # Auditing
    auditd.enable = ${ai['audit']};
    audit.enable = ${ai['audit']};
    audit.rules = [
${ai['auditrules']}
    ];
    protectKernelImage = ${ai['protectkernelimage']};
    lockKernelModules = ${ai['lockkernelmodules']};
    forcePageTableIsolation = ${ai['forcepagetableisolation']};
    allowUserNamespaces = ${ai['allowusernamespaces']};
    unprivilegedUsernsClone = ${ai['unprivilegedusernsclone']};
    allowSimultaneousMultithreading = ${ai['allowsmt']};
  };

  # Services security
  security.sudo.execWheelOnly = ${ai['execwheelonly']};
  services.dbus.implementation = "${ai['dbusimplementation']}";
  services.logrotate.enable = ${ai['logrotate']};
  services.journald.upload.enable = ${ai['journaldupload']};
  services.journald.extraConfig = "
NIX_CFG
  for item in  ${ai['journaldextraconfig']}; do
    tee -a ${ai['nixcfg']} << NIX_CFG
    ${item}
NIX_CFG
  done
  tee -a ${ai['nixcfg']} << NIX_CFG
  ";

  # Fwupd service
  services.fwupd.enable = ${ai['fwupd']};

  # Systemd
  systemd.services.systemd-journald = {
    serviceConfig = {
      UMask = ${ai['systemdumask']};
      PrivateNetwork = ${ai['privatenetwork']};
      ProtectHostname = ${ai['protecthostname']};
      ProtectKernelModules = ${ai['protectkernelmodules']};
    };
  };
  systemd.services.systemd-rfkill = {
    serviceConfig = {
      ProtectSystem = "${ai['protectsystem']}";
      ProtectHome = ${ai['protecthome']};
      ProtectKernelTunables = ${ai['protectkerneltunables']};
      ProtectKernelModules = ${ai['protectkernelmodules']};
      ProtectControlGroups = ${ai['protectcontrolgroups']};
      ProtectClock = ${ai['protectclock']};
      ProtectProc = "${ai['protectproc']}";
      ProcSubset = "${ai['procsubset']}";
      PrivateTmp = ${ai['privatetmp']};
      MemoryDenyWriteExecute = ${ai['memorydenywriteexecute']};
      NoNewPrivileges = ${ai['nownewprivileges']};
      LockPersonality = ${ai['lockpersonality']};
      RestrictRealtime = ${ai['restrictrealtime']};
      SystemCallArchitectures = "${ai['systemcallarchitectures']}";
      UMask = "${ai['systemdumask']}";
      IPAddressDeny = "${ai['ipaddressdeny']}";
    };
  };

  # HostID and Hostname
  networking.hostId = "${ai['hostid']}";
  networking.hostName = "${ai['hostname']}";

  # fail2ban
  services.fail2ban = {
    enable = ${ai['fail2ban']};
    maxretry = ${ai['maxretry']};
    bantime = "${ai['bantime']}";
    ignoreIP = [
NIX_CFG
  for item in ${ai['ignoreip']}; do
    tee -a ${ai['nixcfg']} << NIX_CFG
    "${item}"
NIX_CFG
  done
  tee -a ${ai['nixcfg']} << NIX_CFG
    ];
    bantime-increment = {
      enable = ${ai['bantimeincrement']};
      multipliers = "${ai['multipliers']}";
      maxtime = "${ai['maxtime']}";
      overalljails = ${ai['overalljails']};
    };
  };

  # OpenSSH
  services.openssh.enable = ${ai['sshserver']};
  services.openssh.settings.PasswordAuthentication = ${ai['passwordauthentication']};
  services.openssh.settings.PermitEmptyPasswords = ${ai['permitemptypasswords']};
  services.openssh.settings.KbdInteractiveAuthentication = ${ai['kbdinteractive']};
  services.openssh.settings.PermitTunnel = ${ai['permittunnel']};
  services.openssh.settings.UseDns = ${ai['usedns']};
  services.openssh.settings.X11Forwarding = ${ai['x11forwarding']};
  services.openssh.settings.MaxAuthTries = ${ai['maxauthtries']};
  services.openssh.settings.AllowUsers = [ "${ai['allowusers']}" ];
  services.openssh.settings.LogLevel = "${ai['loglevel']}";
  services.openssh.settings.PermitRootLogin = "${ai['permitrootlogin']}";
  services.openssh.settings.AllowTcpForwarding = ${ai['allowtcpforwarding']};
  services.openssh.settings.AllowAgentForwarding = ${ai['allowagentforwarding']};
  services.openssh.settings.ClientAliveInterval = ${ai['clientaliveinterval']};
  services.openssh.settings.ClientAliveCountMax = ${ai['clientalivecountmax']};
  services.openssh.settings.KexAlgorithms = [
NIX_CFG
  for item in ${ai['kexalgorithms']}; do
    tee -a ${ai['nixcfg']} << NIX_CFG
    "${item}"
NIX_CFG
  done
  tee -a ${ai['nixcfg']} << NIX_CFG
  ];
  services.openssh.settings.Ciphers = [
NIX_CFG
  for item in ${ai['ciphers']}; do
    tee -a ${ai['nixcfg']} << NIX_CFG
    "${item}"
NIX_CFG
  done
  tee -a ${ai['nixcfg']} << NIX_CFG
  ];
  services.openssh.settings.Macs = [
NIX_CFG
  for item in ${ai['macs']}; do
    tee -a ${ai['nixcfg']} << NIX_CFG
    "${item}"
NIX_CFG
  done
  tee -a ${ai['nixcfg']} << NIX_CFG
  ];
  services.openssh.hostKeys = [
    {
      path = "${ai['hostkeyspath']}";
      type = "${ai['hostkeystype']}";
    }
  ];

  # Firewall
  networking.firewall = {
    enable = ${ai['firewall']};
    allowedTCPPorts = [ ${ai['allowedtcpports']} ];
    allowedUDPPorts = [ ${ai['allowedudpports']} ];
  };

  # Additional Nix options
  nix.settings.experimental-features = "${ai['experimental-features']}";

  # System packages
  environment.systemPackages = with pkgs; [
    ${ai['systempackages']// /${spacer}    }
  ];
  # Allow unfree packages
  nixpkgs.config.allowUnfree = ${ai['unfree']};

  # Set your time zone.
  time.timeZone = "${ai['timezone']}";

  # Select internationalisation properties.
  i18n.defaultLocale = "${ai['locale']}";
  i18n.extraLocaleSettings = {
    LC_ADDRESS = "${ai['locale']}";
    LC_IDENTIFICATION = "${ai['locale']}";
    LC_MEASUREMENT = "${ai['locale']}";
    LC_MONETARY = "${ai['locale']}";
    LC_NAME = "${ai['locale']}";
    LC_NUMERIC = "${ai['locale']}";
    LC_PAPER = "${ai['locale']}";
    LC_TELEPHONE = "${ai['locale']}";
    LC_TIME = "${ai['locale']}";
  };

  # Define a user account.
  users.users.${ai['username']} = {
    shell = pkgs.${ai['usershell']};
    isNormalUser = ${ai['normaluser']};
    description = "${ai['usergecos']}";
    extraGroups = [ "${ai['extragroups']}" ];
    openssh.authorizedKeys.keys = [ "${ai['sshkey']}" ];
    hashedPassword = "${ai['usercrypt']}";
  };
  programs.zsh.enable = ${ai['zsh']};
  system.userActivationScripts.zshrc = "touch .zshrc";

  # Sudo configuration
  security.sudo.extraRules= [
    { users = [ "${ai['username']}" ];
      commands = [
        { command = "${ai['sudocommand']}" ;
          options= [ "${ai['sudooptions']}" ];
        }
      ];
    }
  ];

  # Networking
  networking.useDHCP = lib.mkDefault ${ai['dhcp']};
NIX_CFG
  if [ "${ai['dhcp']}" = "false" ]; then
    if [ "${ai['bridge']}" = "false" ]; then
      tee -a ${ai['nixcfg']} << NIX_CFG

  networking = {
    interfaces."${ai['nic']}".useDHCP = ${ai['dhcp']};
    interfaces."${ai['nic']}".ipv4.addresses = [{
      address = "${ai['ip']}";
      prefixLength = ${ai['cidr']};
    }];
    defaultGateway = "${ai['gateway']}";
    nameservers = [ "${ai['dns']}" ];
  };
NIX_CFG
    else
      tee -a ${ai['nixcfg']} << NIX_CFG
  networking = {
    bridges."${ai['bridgenic']}".interfaces = [ "${ai['nic']}" ];
    interfaces."${ai['bridgenic']}".useDHCP = ${ai['dhcp']};
    interfaces."${ai['nic']}".useDHCP = ${ai['dhcp']};
    interfaces."${ai['bridgenic']}".ipv4.addresses = [{
      address = "${ai['ip']}";
      prefixLength = ${ai['cidr']};
    }];
    defaultGateway = "${ai['gateway']}";
    nameservers = [ "${ai['dns']}" ];
  };
NIX_CFG
    fi
  fi
  tee -a ${ai['nixcfg']} << NIX_CFG
  users.users.root.initialHashedPassword = "${ai['rootcrypt']}";
  nixpkgs.hostPlatform = lib.mkDefault "${ai['targetarch']}-linux";
  hardware.cpu.intel.updateMicrocode = lib.mkDefault config.hardware.enableRedistributableFirmware;
  system.stateVersion = "${ai['stateversion']}";
}
NIX_CFG
}

# Get device UUIDs

get_device_uuids () {
  if [ "${ai['swap']}" = "true" ]; then
    ai['swapuuid']=$(ls -l ${ai['devnodes']} | grep ${ai['swapsearch']} | awk '{print $9}' )
    ai['swapdev']="${ai['devnodes']}/${ai['swapuuid']}"
  else
    ai['swapdev']=""
  fi
  ai['bootuuid']=$(ls -l ${ai['devnodes']} | grep ${ai['bootsearch']} | awk '{print $9}' )
  ai['bootdev']="${ai['devnodes']}/${ai['bootuuid']}"
  ai['rootuuid']=$(ls -l ${ai['devnodes']} | grep ${ai['rootsearch']} | awk '{print $9}' )
  ai['rootdev']="${ai['devnodes']}/${ai['rootuuid']}"
  echo "Setting rootuuid to ${ai['rootuuid']}"
  echo "Setting rootdev to ${ai['rootdev']}"
  echo "Setting bootuuid to ${ai['bootuuid']}"
  echo "Setting bootdev to ${ai['bootdev']}"
  echo "Setting swapuuid to ${ai['swapuuid']}"
  echo "Setting swapdev to ${ai['swapdev']}"
}

# Create hardware-configuration.nix

create_hardware_configuration () {
  echo "Creating ${ai['hwcfg']}"
  tee ${ai['hwcfg']} << HW_CFG
{ config, lib, pkgs, modulesPath, ... }:
{
  imports = [
    ${ai['hwimports']}
  ];
  boot.initrd.availableKernelModules = [
HW_CFG
  for item in ${ai['availmods']}; do
    tee -a ${ai['hwcfg']} << HW_CFG
    "${item}"
HW_CFG
  done
  tee -a ${ai['hwcfg']} << HW_CFG
  ];
  boot.initrd.kernelModules = [
HW_CFG
  for item in ${ai['initmods']}; do
    tee -a ${ai['hwcfg']} << HW_CFG
    "${item}""
HW_CFG
  done
  tee -a ${ai['hwcfg']} << HW_CFG
  ];
  boot.kernelModules = [
HW_CFG
  for item in ${ai['bootmods']}; do
    tee -a ${ai['hwcfg']} << HW_CFG
    "${item}"
HW_CFG
  done
  tee -a ${ai['hwcfg']} << HW_CFG
  ];
  boot.loader.grub.extraConfig = "
    ${ai['grubextraconfig']//  /${spacer}     }
  ";
  boot.kernelParams = [
HW_CFG
  for item in ${ai['kernelparams']}; do
    tee -a ${ai['hwcfg']} << HW_CFG
    "${item}"
HW_CFG
  done
  tee -a ${ai['hwcfg']} << HW_CFG
  ];
  boot.extraModulePackages = [ ];
HW_CFG
  if [ "${ai['rootfs']}" = "zfs" ]; then
    tee -a ${ai['hwcfg']} << HW_CFG
  fileSystems."/" = {
    device = "${ai['rootpool']}/root";
    fsType = "${ai['rootfs']}";
    neededForBoot = true;
  };
  fileSystems."/nix" = {
    device = "${ai['rootpool']}/nix";
    fsType = "${ai['rootfs']}";
  };
  fileSystems."/home" = {
    device = "${ai['rootpool']}/home";
    fsType = "${ai['rootfs']}";
  };
  fileSystems."/var" = {
    device = "${ai['rootpool']}/var";
    fsType = "${ai['rootfs']}";
  };
HW_CFG
  else
    tee -a ${ai['hwcfg']} << HW_CFG
  fileSystems."/" = {
    device = "${ai['rootdev']}";
    fsType = "${ai['rootfs']}";
    neededForBoot = true;
  };
HW_CFG
  fi
  tee -a ${ai['hwcfg']} << HW_CFG
  fileSystems."/boot" = {
    device = "${ai['bootdev']}";
    fsType = "${ai['bootfs']}";
    options = [ "fmask=0022" "dmask=0022" ];
  };
  swapDevices = [ { device = "${ai['swapdev']}"; } ];
}
HW_CFG
}

# Manual config creation command if you need it
# nixos-generate-config --root ${ai['installdir']}

# Check whether to run installer and handle appropriately

handle_installer () {
  if [ "${ai['attended']}" = "true" ]; then
    echo "To install:"
    echo "nixos-install -v --show-trace --no-root-passwd 2>&1 | tee ${ai['installdir']}${ai['logfile']}"
    echo "To unmount filesystems and reboot:"
    echo "umount -Rl ${ai['installdir']}"
    if [ "${ai['rootfs']}" = "zfs" ]; then
      echo "zpool export -a"
    fi
    echo "swapoff -a"
    echo "reboot"
    exit
  else
    nixos-install -v --show-trace --no-root-passwd 2>&1 | tee ${ai['installdir']}${ai['logfile']}
    echo "Logged to ${ai['installdir']}${ai['logfile']}"
  fi
  # Check Installation finished
  install_check=$( tail -1 "${ai['installdir']}${ai['logfile']}" | grep -c "installation finished" )
  # Exit if not finished
  if [ "${install_check}" = "0" ]; then
    echo "Installation did not finish"
    exit
  else
    umount -Rl ${ai['installdir']}
    if [ "${ai['rootfs']}" = "zfs" ]; then
      zpool export -a
    fi
    swapoff -a
  fi
  if [ "${ai['poweroff']}" = "true" ]; then
    poweroff
  fi
  if [ "${ai['reboot']}" = "true" ]; then
    reboot
  fi
}

interactive_install () {
  if [ "${ai['interactiveinstall']}" = "true" ] || [ "${ai['dointeractiveinstall']}" = "true" ]; then
    for key in ${!ai[@]}; do
      if ! [[ "${key}" =~ interactive ]]; then
        value="${ai[${key}]}"
        line=$( grep "# ai :" "${ai['scriptfile']}" | grep "'${key}'" | grep -v grep )
        if ! [ "${line}" = "" ]; then
          IFS=":" read -r header question <<< "${line}"
          question=$( echo "${question}" | sed "s/^ //g" )
          prompt="${question}? [${value}]: "
          read -r -p "${prompt}" answer
          if ! [ "${answer}" = "" ]; then
            options[${key}]="${answer}"
          fi
          if ! [ "${answer}" = "none" ]; then
            options[${key}]=""
          fi
        fi
      fi
    done
  fi
}

do_install () {
  parse_parameters
  parse_grub_parameters
  interactive_install
  set_zfs_options
  setup_networking
  discover_first_disk
  setup_nvme_partitions
  setup_boot_modules
  setup_hwimports
  check_bios_or_uefi
  setup_root_partition_type
  wipe_root_disk
  partition_root_disk
  make_and_mount_filesystems
  create_nix_configuration
  get_device_uuids
  create_hardware_configuration
  handle_installer
}

# Handle command line arguments

while test $# -gt 0; do
  case $1 in
    --install)
      do_install
      ;;
    --interactive)
      ai['dointeractiveinstall']="true"
      do_install
      ;;
    *)
      do_install
      ;;
  esac
done
