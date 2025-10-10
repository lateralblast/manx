#!/run/current-system/sw/bin/bash
export PATH="/run/wrappers/bin:/root/.nix-profile/bin:/nix/profile/bin:/root/.local/state/nix/profile/bin:/etc/profiles/per-user/root/bin:/nix/var/nix/profiles/default/bin:/run/current-system/sw/bin"

# Set general environment
declare -A ai

ai['swap']="true"
ai['lvm']="false"
ai['zsh']="true"
ai['dhcp']="true"
ai['bridge']="false"
ai['sshserver']="true"
ai['bridgenic']="br0"
ai['reboot']="true"
ai['poweroff']="false"
ai['attended']="false"
ai['nixinstall']="true"
ai['rootfs']="zfs"
ai['bootfs']="vfat"
ai['rootdisk']="first"
ai['mbrpart']="1"
ai['rootpart']="2"
ai['efipart']="3"
ai['bootpart']="3"
ai['swappart']="4"
ai['swapsize']="2G"
ai['rootsize']="100%FREE"
ai['bootsize']="512M"
ai['rootpool']="rpool"
ai['swapvolname']="swap"
ai['bootvolname']="boot"
ai['rootvolname']="nixos"
ai['installdir']="/mnt"
ai['mbrpartname']=""
ai['locale']="en_AU.UTF-8"
ai['devnodes']="/dev/disk/by-uuid"
ai['logdir']="/var/log"
ai['logfile']="/var/log/install.log"
ai['timezone']="Australia/Melbourne"
ai['usershell']="zsh"
ai['username']="nixos"
ai['extragroups']="wheel"
ai['usergecos']="Admin"
ai['normaluser']="true"
ai['sudocommand']="ALL"
ai['sudooptions']="NOPASSWD"
ai['rootpassword']="nixos"
ai['rootcrypt']=$( mkpasswd --method=sha-512 "${ai['rootpassword']}" )
ai['userpassword']="nixos"
ai['usercrypt']=$( mkpasswd --method=sha-512 "${ai['userpassword']}" )
ai['stateversion']="25.05"
ai['hostname']="nixos"
ai['hostid']=$( head -c 8 /etc/machine-id )
ai['nixdir']="${ai['installdir']}/etc/nixos"
ai['nixcfg']="${ai['nixdir']}/configuration.nix"
ai['hwcfg']="${ai['nixdir']}/hardware-configuration.nix"
ai['zfsoptions']="-O mountpoint=none -O atime=off -O compression=lz4 -O xattr=sa -O acltype=posixacl -o ashift=12"
ai['availmods']="ahci ehci_pci megaraid_sas sdhci_pci sd_mod sr_mod usbhid usb_storage virtio_blk virtio_pci xhci_pci"
ai['initmods']=""
ai['bootmods']=""
ai['experimental-features']="nix-command flakes"
ai['unfree']="false"
ai['gfxmode']="auto"
ai['gfxpayload']="text"
ai['nic']="first"
ai['dns']="8.8.8.8"
ai['ip']=""
ai['gateway']=""
ai['cidr']="24"
ai['sshkey']="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJvM+S0BZ+l3rJVvwMFNQGD/e1MJwB5LAwhsfMXhE/iR spindler@Richards-MacBook-Pro.local"
ai['oneshot']="true"
ai['kernelparams']="audit=1 slab_nomerge init_on_alloc=1 init_on_free=1 page_alloc.shuffel=1 pti=on randomize_kstack_offset=on vsyscall=none debugfs=off oops=panic module.sig_enforce=1 lockdown=confidentiality rd.udev.log_level=3 udev.log_priority=3  console=tty1  console=ttyS0,115200no8 "
ai['grubextraconfig']=" serial --speed=115200 --unit=0 --word=8 --parity=no --stop=1 --port=0x02f8  terminal_input serial  terminal_output serial "
ai['journaldextraconfig']="SystemMaxUse=500M SystemMaxFileSize=50M"
ai['journaldupload']="false"
ai['imports']="<nixpkgs/nixos/modules/system/boot/loader/grub/grub.nix> <nixpkgs/nixos/modules/system/boot/kernel.nix>"
ai['hwimports']=""
ai['kernel']=""
ai['passwordauthentication']="false"
ai['permitemptypasswords']="false"
ai['kbdinteractiveauthentication']="false"
ai['usedns']="false"
ai['x11forwarding']="false"
ai['maxauthtries']="3"
ai['maxsessions']="2"
ai['permittunnel']="false"
ai['allowusers']="nixos"
ai['loglevel']="VERBOSE"
ai['clientaliveinterval']="300"
ai['clientalivecountmax']="0"
ai['allowtcpforwarding']="false"
ai['allowagentforwarding']="false"
ai['allowedtcpports']="22"
ai['allowedudpports']=""
ai['permitrootlogin']="no"
ai['hostkeyspath']="/etc/ssh/ssh_host_ed25519_key"
ai['hostkeystype']="ed25519"
ai['kexalgorithms']="curve25519-sha256@libssh.org ecdh-sha2-nistp521 ecdh-sha2-nistp384 ecdh-sha2-nistp256 diffie-hellman-group-exchange-sha256"
ai['ciphers']="chacha20-poly1305@openssh.com aes256-gcm@openssh.com aes128-gcm@openssh.com aes256-ctr aes192-ctr aes128-ctr"
ai['macs']="hmac-sha2-512-etm@openssh.com hmac-sha2-256-etm@openssh.com umac-128-etm@openssh.com hmac-sha2-512 hmac-sha2-256 umac-128@openssh.com"
ai['isomount']="/iso"
ai['prefix']="ai"
ai['targetarch']="arm64"
ai['systempackages']="aide ansible btop curl dmidecode efibootmgr ethtool file fwupd git kernel-hardening-checker lsb-release lsof lshw lynis nmap pciutils ripgrep rclone tmux usbutils vim wget"
ai['blacklist']="dccp sctp rds tipc n-hdlc ax25 netrom x25 rose decnet econet af_802154 ipx appletalk psnap p8023 p8022 can atm cramfs freevxfs jffs2 hfs hfsplus udf"
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
"
ai['audit']="true"
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
"
ai['fail2ban']="true"
ai['maxretry']="5"
ai['bantime']="1h"
ai['ignoreip']="172.16.0.0/12 192.168.0.0/16"
ai['bantimeincrement']="true"
ai['multipliers']="1 2 4 8 16 32 64 128 256"
ai['maxtime']="1h"
ai['overalljails']="true"
ai['protectkernelimage']="true"
ai['lockkernelmodules']="false"
ai['forcepagetableisolation']="true"
ai['unprivilegedusernsclone']="config.virtualisation.containers.enable"
ai['allowsimultaneousmultithreading']="true"
ai['execwheelonly']="true"
ai['dbusimplementation']="broker"
ai['allowusernamespaces']="true"
ai['systemdumask']="0077"
ai['privatenetwork']="true"
ai['protecthostname']="true"
ai['protectkernelmodules']="true"
ai['protectsystem']="strict"
ai['protecthome']="true"
ai['protectkerneltunables']="true"
ai['protectkernelmodules']="true"
ai['protectcontrolgroups']="true"
ai['protectclock']="true"
ai['protectproc']="invisible"
ai['procsubset']="pid"
ai['privatetmp']="true"
ai['memorydenywriteexecute']="true"
ai['nownewprivileges']="true"
ai['lockpersonality']="true"
ai['restrictrealtime']="true"
ai['systemcallarchitectures']="native"
ai['ipaddressdeny']="any"
ai['firewall']="true"
ai['fwupd']="true"
ai['logrotate']="true"
ai['processgrub']="true"

spacer=$'\n'

# Parse parameters
echo "Processing parameters"
for param in ${!ai[@]}
do
  echo "Setting ${param} to ${ai[${param}]}"
done

# Parse grub parameters
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
ai['zfsoptions']="${ai['zfsoptions']} -R ${ai['installdir']}"
echo "Setting zfsoptions to ${ai['zfsoptions']}"

# If oneshot is disabled exit
if [ "${ai['oneshot']}" = "false" ]; then
  exit
fi

# Set up non DHCP environment
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

# Discover first disk
if [ "${ai['rootdisk']}" = "first" ]; then
  ai['rootdisk']=$( lsblk -l -o TYPE,NAME,TRAN | grep disk | grep -v usb | sort | head -1 | awk '{print $2}' )
  ai['rootdisk']="/dev/${ai['rootdisk']}"
  echo "Setting rootdisk to ${ai['rootdisk']}"
fi

# Update partitions for NVMe devices
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

# Check we are using only one volume manager
if [ "${ai['lvm']}" = "true" ] && [ "${ai['rootfs']}" = "zfs" ]; then
  echo "Cannot use two volume managers (LVM and ZFS)"
  exit
fi

# Boot modules
if [ "${ai['bootmods']}" = "" ]; then
  ai['bootmods']="kvm-intel"
else
  ai['bootmods']="${ai['bootmods']} kvm-intel"
fi
echo "Setting bootmods to ${ai['bootmods']}"

# QEMU check
qemu_check=$( cat /proc/ioports | grep QEMU )
if [ -n "${qemu_check}" ]; then
  if [ "${ai['hwimports']}" = "" ]; then
    ai['hwimports']="(modulesPath + \"/profiles/qemu-guest.nix\")"
  else
    ai['hwimports']="${ai['hwimports']} (modulesPath + \"/profiles/qemu-guest.nix\")"
  fi
  echo "Setting hwimports to ${ai['hwimports']}"
fi

# Check if BIOS or UEFI boot
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

# Set root partition type
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

# Wipe and set up disks
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

# Make and mount filesystems
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

# Create configuration.nix
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
    allowSimultaneousMultithreading = ${ai['allowsimultaneousmultithreading']};
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
  services.openssh.settings.KbdInteractiveAuthentication = ${ai['kbdinteractiveauthentication']};
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

# Get device UUIDs
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

# Create hardware-configuration.nix
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

# Manual config creation command if you need it
# nixos-generate-config --root ${ai['installdir']}

echo "Creating log directory ${ai['installdir']}${ai['logdir']}"
mkdir -p ${ai['installdir']}/${ai['logdir']}

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