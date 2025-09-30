#!env bash

# Name:         manx (Make Automated NixOS)
# Version:      1.2.0
# Release:      1
# License:      CC-BA (Creative Commons By Attribution)
#               http://creativecommons.org/licenses/by/4.0/legalcode
# Group:        System
# Source:       N/A
# URL:          https://github.com/lateralblast/manx
# Distribution: NixOS
# Vendor:       Linux
# Packager:     Richard Spindler <richard@lateralblast.com.au>
# Description:  A template for writing shell scripts

# Insert some shellcheck disables
# Depending on your requirements, you may want to add/remove disables
# shellcheck disable=SC2004
# shellcheck disable=SC2089
# shellcheck disable=SC2034
# shellcheck disable=SC1090
# shellcheck disable=SC2129
# shellcheck disable=SC2199
# shellcheck disable=SC2239

# Create arrays

declare -A os
declare -A vm
declare -A script
declare -A imports
declare -A options
declare -a options_list
declare -a actions_list

# Grab script information and put it into an associative array

script['args']="$*"
script['file']="$0"
script['name']="manx"
script['file']=$( realpath "${script['file']}" )
script['path']=$( dirname "${script['file']}" )
script['modulepath']="${script['path']}/modules"
script['bin']=$( basename "${script['file']}" )
script['user']=$( id -u -n )

# Function: set_defaults
#
# Set defaults

set_defaults () {
  # System kernel parameters - Security related
  options['kernelparams']=""                                                        # option : Additional kernel parameters to add to system grub commands
  kernelparams=(
    "audit=1"
    "slab_nomerge"
    "init_on_alloc=1"
    "init_on_free=1"
    "page_alloc.shuffel=1"
    "pti=on"
    "randomize_kstack_offset=on"
    "vsyscall=none"
    "debugfs=off"
    "oops=panic"
    "module.sig_enforce=1"
    "lockdown=confidentiality"
    "rd.udev.log_level=3"
    "udev.log_priority=3"
  )
  for item in "${kernelparams[@]}"; do
    options['kernelparams']+=" \\\"${item}\\\" "
  done
  # ZFS options
  options['zfsoptions']=""                                                          # option : Blacklisted kernel modules
  zfsoptions=(
    "-O mountpoint=none"
    "-O atime=off"
    "-O compression=lz4"
    "-O xattr=sa"
    "-O acltype=posixacl"
    "-o ashift=12"
  )
  for item in "${zfsoptions[@]}"; do
    options['zfsoptions']+=" ${item} "
  done
  # Packages
  options['systempackages']=""                                                      # option : System packages
  systempackages=(
    "aide"
    "ansible"
    "curl"
    "dmidecode"
    "efibootmgr"
    "file"
    "kernel-hardening-checker"
    "lsb-release"
    "lshw"
    "lynis"
    "pciutils"
    "vim"
    "wget"
  )
  for item in "${systempackages[@]}"; do
    options['systempackages']+=" ${item} "
  done
  # Blacklist
  options['blacklist']=""                                                           # option : Blacklisted kernel modules
  blacklist=(
    "dccp"
    "sctp"
    "rds"
    "tipc"
    "n-hdlc"
    "ax25"
    "netrom"
    "x25"
    "rose"
    "decnet"
    "econet"
    "af_802154"
    "ipx"
    "appletalk"
    "psnap"
    "p8023"
    "p8022"
    "can"
    "atm"
    "cramfs"
    "freevxfs"
    "jffs2"
    "hfs"
    "hfsplus"
    "udf"
  )
  for item in "${blacklist[@]}"; do
    options['blacklist']+=" \\\"${item}\\\" "
  done
  # Available kernel modules
  options['availmods']=""                                                           # option : Available kernel modules
  availmods=(
    "ahci"
    "xhci_pci"
    "virtio_pci"
    "sr_mod"
    "virtio_blk"
  )
  for item in "${availmods[@]}"; do
    options['availmods']+=" \\\"${item}\\\" "
  done
  # Kernel parameters
  options['isokernelparams']=""                                                     # option : Additional kernel parameters to add to ISO grub commands
  options['serialkernelparams']=""                                                  # option : Serial kernel params
  serialkernelparams=(
    "console=tty1"
    "console=ttyS0,115200n8"
    "console=ttyS1,115200n8"
  )
  for item in "${serialkernelparams[@]}"; do
    options['isoserialkernelparams']+=" \"${item}\" "
  done
  for item in "${serialkernelparams[@]}"; do
    options['serialkernelparams']+=" \\\"${item}\\\" "
  done
  options['serialextraargs']=""                                                     # option : Serial extra args
  serialextraargs=(
    "serial --speed=115200 --unit=0 --word=8 --parity=no --stop=1"
    "terminal_input serial"
    "terminal_output serial"
  )
  spacer=$'\n    '
  for item in "${serialextraargs[@]}"; do
    if [ "${options['serialextraargs']}" = "" ]; then
      options['serialextraargs']="${item}"
    else
      options['serialextraargs']+="${spacer}${item}"
    fi
  done
  # Imports
  options['isoimports']=""                                                          # option : ISO imports
  isoimports=(
    "<nixpkgs/nixos/modules/installer/cd-dvd/installation-cd-minimal-combined.nix>"
    "<nixpkgs/nixos/modules/installer/cd-dvd/channel.nix>"
    "<nixpkgs/nixos/modules/system/boot/loader/grub/grub.nix>"
    "<nixpkgs/nixos/modules/system/boot/kernel.nix>"
  )
  for item in "${isoimports[@]}"; do
    options['isoimports']+=" ${item} "
  done
  options['imports']=""                                                             # option : System imports
  imports=(
    "<nixpkgs/nixos/modules/system/boot/loader/grub/grub.nix>"
    "<nixpkgs/nixos/modules/system/boot/kernel.nix>"
  )
  for item in "${imports[@]}"; do
    options['imports']+=" ${item} "
  done
  # Options
  options['secure']="true"                                                          # option : Enable secure parameters
  options['sysctl']=""                                                              # option : System sysctl parameters
  options['prefix']="ai"                                                            # option : Install directory prefix
  options['verbose']="false"                                                        # option : Verbose mode
  options['testmode']="false"                                                       # option : Test mode
  options['strict']="false"                                                         # option : Strict mode
  options['dryrun']="false"                                                         # option : Dryrun mode
  options['debug']="false"                                                          # option : Debug mode
  options['force']="false"                                                          # option : Force actions
  options['mask']="false"                                                           # option : Mask identifiers
  options['yes']="false"                                                            # option : Answer yes to questions
  options['dhcp']="true"                                                            # option : DHCP network
  options['swap']="true"                                                            # option : Use swap
  options['lvm']="false"                                                            # option : Use LVM
  options['zsh']="true"                                                             # option : Enable zsh
  options['preserve']="false"                                                       # option : Preserve ISO
  options['workdir']="${HOME}/${script['name']}"                                    # option : Script work directory
  options['sshkey']=""                                                              # option : SSH key
  options['rootdisk']="first"                                                       # option : Disk
  options['nic']="first"                                                            # option : NIC
  options['zfs']="true"                                                             # option : ZFS filesystem
  options['ext4']="false"                                                           # option : EXT4 filesystem
  options['locale']="en_AU.UTF-8"                                                   # option : Locale
  options['timezone']="Australia/Melbourne"                                         # option : Timezone
  options['username']=""                                                            # option : Username
  options['userpassword']="nixos"                                                   # option : User Password
  options['usercrypt']=""                                                           # option : User Password Crypt
  options['hostname']="nixos"                                                       # option : Hostname
  options['sshkeyfile']=""                                                          # option : SSH key file
  options['bootfs']="vfat"                                                          # option : Boot filesystem
  options['rootfs']="zfs"                                                           # option : Root filesystem
  options['firmware']="bios"                                                        # option : Boot firmware type
  options['bios']="true"                                                            # option : BIOS Boot firmware
  options['uefi']="false"                                                           # option : UEFI Boot firmware
  options['isomount']="/iso"                                                        # option : ISO mount directory
  options['oneshotscript']="${options['workdir']}/${options['prefix']}/oneshot.sh"  # option : Oneshot script
  options['installscript']="${options['workdir']}/${options['prefix']}/install.sh"  # option : Install script
  options['nixisoconfig']="${options['workdir']}/iso.nix"                           # option : NixOS ISO config
  options['zfsinstall']="${options['workdir']}/${options['prefis']}/zfs.sh"         # option : ZFS install script
  options['extinstall']="${options['workdir']}/${options['prefis']}/ext4.sh"        # option : EXT4 install script
  options['runsize']="50%"                                                          # option : Run size
  options['source']="${options['workdir']}/${options['prefix']}"                    # option : Source directory for ISO additions
  options['target']="/${options['prefix']}"                                         # option : Target directory for ISO additions
  options['installdir']="/mnt"                                                      # option : Install directory
  options['nixdir']="${options['installdir']}/etc/nixos"                            # option : NixOS directory for configs
  options['nixconfig']="${options['nixdir']}/configuration.nix"                     # option : NixOS install config file
  options['nixhwconfig']="${options['nixdir']}/hardware-configuration.nix"          # option : NixOS install hardware config file
  options['nixzfsconfig']="${options['nixdir']}/zfs.nix"                            # option : NixOS install ZFS config file
  options['systemd-boot']="true"                                                    # option : systemd-boot
  options['touchefi']="true"                                                        # option : Touch EFI
  options['sshserver']="true"                                                       # option : Enable SSH server
  options['swapsize']="2G"                                                          # option : Swap partition size
  options['rootsize']="100%"                                                        # option : Root partition size
  options['rootpool']="rpool"                                                       # option : Root pool name
  options['rootpassword']="nixos"                                                   # option : Root password
  options['rootcrypt']=""                                                           # option : Root password crypt
  options['username']="nixos"                                                       # option : User Username
  options['usergecos']="nixos"                                                      # option : User GECOS
  options['usershell']="zsh"                                                        # option : User Shell
  options['normaluser']="true"                                                      # option : Normal User
  options['extragroups']="wheel"                                                    # option : Extra Groups
  options['sudousers']="${options['username']}"                                     # option : Sudo Users
  options['sudocommand']="ALL"                                                      # option : Sudo Command
  options['sudooptions']="NOPASSWD"                                                 # option : Sudo Options
  options['experimental-features']="nix-command flakes"                             # option : Experimental Features
  options['unfree']="false"                                                         # option : Allow Non Free Packages
  options['stateversion']="25.05"                                                   # option : State version
  options['unattended']="true"                                                      # option : Execute install script
  options['attended']="false"                                                       # option : Don't execute install script
  options['reboot']="true"                                                          # option : Reboot after install
  options['poweroff']="true"                                                        # option : Poweroff after install
  options['nixinstall']="true"                                                      # option : Run Nix installer on ISO
  options['gfxmode']="auto"                                                         # option : Grub graphics mode
  options['gfxpayload']="text"                                                      # option : Grub graphics payload
  options['networkmanager']="true"                                                  # option : Enable NetworkManager
  options['xserver']="false"                                                        # option : Enable Xserver
  options['keymap']="au"                                                            # option : Keymap
  options['videodriver']=""                                                         # option : Video Driver
  options['sddm']="false"                                                           # option : KDE Plasma Login Manager
  options['plasma6']="false"                                                        # option : KDE Plasma
  options['gdm']="false"                                                            # option : Gnome Login Manager
  options['gnome']="false"                                                          # option : Gnome
  options['rootkit']="false"                                                        # option : Enable rootkit protection
  options['bridge']="false"                                                         # option : Enable bridge
  options['bridgenic']="br0"                                                        # option : Bridge NIC
  options['ip']=""                                                                  # option : IP Address
  options['cidr']="24"                                                              # option : CIDR
  options['dns']="8.8.8.8"                                                          # option : DNS/Nameserver address
  options['gateway']=""                                                             # option : Gateway address
  options['standalone']="false"                                                     # option : Package all requirements on ISO
  options['rootvolname']="nixos"                                                    # option : Root volume name
  options['bootvolname']="boot"                                                     # option : Boot volume name
  options['mbrvolname']="bootcode"                                                  # option : Boot volume name
  options['swapvolname']="swap"                                                     # option : Swap volume name
  options['uefivolname']="uefi"                                                     # option : UEFI volume name
  options['homevolname']="home"                                                     # option : Home volume name
  options['nixvolname']="nix"                                                       # option : Nix volume name
  options['usrvolname']="usr"                                                       # option : Usr volume name
  options['varvolname']="var"                                                       # option : Var volume name
  options['tempdir']="/tmp"                                                         # option : Temp directory
  options['mbrpart']="1"                                                            # option : MBR partition
  options['rootpart']="2"                                                           # option : Root partition
  options['efipart']="3"                                                            # option : UEFI/Boot partition
  options['swappart']="4"                                                           # option : Swap partition
  options['devnodes']="/dev/disk/by-uuid"                                           # option : Device nodesDevice nodes
  options['logdir']="/var/log"                                                      # option : Install log dir
  options['logfile']="${options['logdir']}/install.log"                             # option : Install log file
  options['bootsize']="512M"                                                        # option : Boot partition size
  options['isoextraargs']=""                                                        # option : Additional kernel config to add to ISO grub commands
  options['extraargs']=""                                                           # option : Additional kernel config to add to system grub commands
  options['initmods']=''                                                            # option : Available system init modules
  options['bootmods']=''                                                            # option : Available system boot modules
  options['oneshot']="true"                                                         # option : Enable oneshot service
  options['serial']="true"                                                          # option : Enable serial
  options['kernel']=""                                                              # option : Kernel
  options['sshpasswordauthentication']="false"                                      # option : SSH Password Authentication
  options['firewall']="false"                                                       # option : Enable firewall
  options['allowedtcpports']="22"                                                   # option : Allowed TCP ports
  options['allowedudpports']=""                                                     # option : Allowed UDP ports
  options['import']=""                                                              # option : Import Nix config to add to system build
  options['isoimport']=""                                                           # option : Import Nix config to add to ISO build
  options['dockerarch']=$( uname -m |sed 's/x86_/amd/g' )                           # option : Docker architecture
  options['targetarch']=$( uname -m )                                               # option : Target architecture
  options['createdockeriso']="false"                                                # option : Create ISO using docker
  options['console']="false"                                                        # option : Enable console in actions
  options['suffix']=""                                                              # option : Output file suffix

  # VM defaults
  vm['name']="${script['name']}"                                                    # vm : VM name
  vm['vcpus']="2"                                                                   # vm : VM vCPUs
  vm['cpu']="host-passthrough"                                                      # vm : VM CPU
  vm['os-variant']="nixos-unknown"                                                  # vm : VM OS variant
  vm['host-device']=""                                                              # vm : VM Host-device for pass-through
  vm['graphics']="none"                                                             # vm : VM Graphics
  vm['virt-type']="kvm"                                                             # vm : VM Virtualisation type
  vm['network']="bridge=br0,model=virtio"                                           # vm : VM NIC
  vm['memory']="4G"                                                                 # vm : VM RAM
  vm['cdrom']=""                                                                    # vm : VM ISO
  vm['boot']="uefi"                                                                 # vm : VM Boot type
  vm['disk']=""                                                                     # vm : VM Disk
  vm['features']="kvm_hidden=on"                                                    # vm : VM Features
  vm['size']="20G"                                                                  # vm : VM Disk size
  vm['dir']="${options['workdir']}/vms"                                             # vm : VM Directory
  vm['noautoconsole']="true"                                                        # vm : VM Autoconsole
  vm['noreboot']="true"                                                             # vm : VM Reboot
  vm['wait']=""                                                                     # vm : VM Wait before starting
  vm['machine']="q35"                                                               # vm : VM Machine

  os['name']=$( uname -s )
  if [ "${os['name']}" = "Linux" ]; then
    lsb_check=$( command -v lsb_release )
    if [ -n "${lsb_check}" ]; then
      os['distro']=$( lsb_release -i -s 2 | sed 's/"//g' 2>&1 /dev/null )
    else
      os['distro']=$( hostnamectl | grep "Operating System" | awk '{print $3}' )
    fi
  fi
  if [ "${os['name']}" = "Darwin" ]; then
    vm['cpu']="cortex-a57"
    vm['network']="default,model=virtio"
  fi
}

set_defaults

# Function: print_message
#
# Print message

print_message () {
  message="$1"
  format="$2"
  if [ "${format}" = "verbose" ]; then
    echo "${message}"
  else
    if [[ "${format}" =~ warn ]]; then
      echo -e "Warning:\t${message}"
    else
      if [ "${options['verbose']}" = "true" ]; then
        if [[ "${format}" =~ ing$ ]]; then
          format="${format^}"
        else
          if [[ "${format}" =~ t$ ]]; then
            if [ "${format}" = "test" ]; then
              format="${format}ing"
            else
              format="${format^}ting"
            fi
          else
            if [[ "${format}" =~ e$ ]]; then
              if ! [[ "${format}" =~ otice ]]; then
                format="${format::-1}"
                format="${format^}ing"
              fi
            fi
          fi
        fi
        format="${format^}"
        length="${#format}"
        if [ "${length}" -lt 7 ]; then
          tabs="\t\t"
        else
          tabs="\t"
        fi
        echo -e "${format}:${tabs}${message}"
      fi
    fi
  fi
}

# Function: verbose_message
#
# Verbose message

verbose_message () {
  message="$1"
  print_message "${message}" "verbose"
}

# Function: warning_message
#
# Warning message

warning_message () {
  message="$1"
  print_message "${message}" "warn"
}

# Function: execute_message
#
#  Print command

execute_message () {
  message="$1"
  print_message "${message}" "execute"
}

# Function: notice_message
#
# Notice message

notice_message () {
  message="$1"
  verbose_message "${message}" "notice"
}

# Function: notice_message
#
# Information Message

information_message () {
  message="$1"
  verbose_message "${message}" "info"
}

# Load modules

if [ -d "${script['modulepath']}" ]; then
  modules=$( find "${script['modulepath']}" -name "*.sh" )
  for module in ${modules}; do
    if [[ "${script['args']}" =~ "verbose" ]]; then
     print_message "Module ${module}" "load"
    fi
    . "${module}"
  done
fi

# Function: reset_defaults
#
# Reset defaults based on command line options

reset_defaults () {
  # System sysctl parameters - Security related
  if [ "${options['secure']}" = "true" ]; then
    IFS='' read -r -d '' options['sysctl'] << SYSCTL
    "kernel.exec-shield" = 1;
    "net.ipv4.tcp_rfc1337" = 1;
    "net.ipv6.conf.all.forwarding" = 0;
    "net.ipv4.conf.all.accept_redirects" = 0;
    "net.ipv4.conf.all.secure_redirects" = 0;
    "kernel.dmesg_restrict" = 1;
    "kernel.randomize_va_space" = 2;
    "net.ipv4.conf.default.secure_redirects" = 0;
    "net.ipv4.conf.all.rp_filter" = 1;
    "net.ipv6.conf.default.accept_ra" = 0;
    "net.ipv4.conf.default.accept_source_route" = 0;
    "net.ipv4.icmp_ignore_bogus_error_responses" = 1;
    "fs.protected_hardlinks" = 1;
    "kernel.yama.ptrace_scope" = 2;
    "dev.tty.ldisk_autoload" = 0;
    "kernel.unprivileged_bpf_disabled" = 1;
    "net.ipv4.conf.all.forwarding" = 0;
    "fs.suid_dumpable" = 0;
    "vm.mmap_rnd_compat_bits" = 16;
    "net.ipv6.conf.all.accept_ra" = 0;
    "net.ipv4.conf.default.rp_filter" = 1;
    "fs.protected_regular" = 2;
    "net.ipv4.conf.all.accept_source_route" = 0;
    "net.ipv4.tcp_dsack" = 0;
    "vm.unprivileged_userfaultfd" = 0;
    "net.ipv4.conf.all.send_redirects" = 0;
    "fs.protected_fifos" = 2;
    "net.ipv4.tcp_fack" = 0;
    "net.ipv4.tcp_syncookies" = 1;
    "net.ipv4.icmp_echo_ignore_all" = 1;
    "kernel.perf_event_paranoid" = 3;
    "net.core.default_qdisc" = "cake";
    "net.ipv4.tcp_sack" = 0;
    "net.ipv4.conf.default.send_redirects" = 0;
    "net.ipv4.conf.default.accept_redirects" = 0;
    "net.ipv4.tcp_congestion_control" = "bbr";
    "net.core.bpf_jit_harden" = 2;
    "net.ipv6.conf.all.accept_source_route" = 0;
    "kernel.kptr_restrict" = 2;
    "fs.protected_symlinks" = 1;
    "net.ipv6.conf.default.accept_source_route" = 0;
    "kernel.sysrq" = 4;
    "kernel.kexec_load_disabled" = 1;
    "net.ipv6.conf.default.accept_redirects" = 0;
    "vm.mmap_rnd_bits" = 32;
    "net.ipv4.tcp_fastopen" = 3;
    "net.ipv6.conf.all.accept_redirects" = 0;
SYSCTL
    options['sysctl']="${options['sysctl']//\"/\\\"}"
  fi
  if [ "${options['debug']}" = "true" ]; then
    print_message "Enabling debug mode" "notice"
    set -x
  fi
  if [ "${options['strict']}" = "true" ]; then
    print_message "Enabling strict mode" "notice"
    set -u
  fi
  if [ "${options['dryrun']}" = "true" ]; then
    print_message "Enabling dryrun mode" "notice"
  fi
  if [ "${options['zsh']}" = "true" ]; then
    options['usershell']="zsh"
  fi
  if ! [ "${options['usershell']}" = "zsh" ]; then
    options['zsh']="false"
  fi
  if [ "${options['lvm']}" = "true" ]; then
    options['zfs']="false"
    if [ "${options["rootfs"]}" = "zfs" ]; then
      warning_message "LVM selected, root filestem cannot be ZFS, setting to EXT4"
      options['rootfs']="ext4"
    fi
  fi
  if [ "${options['zfs']}" = "true" ] || [ "${options['rootfs']}" = "zfs" ]; then
    options['zfs']='true'
    options['rootfs']='zfs'
  fi
  if [ "${options['ext4']}" = "true" ] || [ "${options['rootfs']}" = "ext4" ]; then
    options['ext4']='true'
    options['rootfs']='ext4'
  fi
  if [ "${options['bios']}" = "true" ] || [ "${options['firmware']}" = "bios" ]; then
    options['bios']='true'
    options['firmware']='bios'
  fi
  if [ "${options['uefi']}" = "true" ] || [ "${options['firmware']}" = "uefi" ]; then
    options['uefi']='true'
    options['firmware']='uefi'
  fi
  if [ "${options['serial']}" = "true" ]; then
    if [ "${options['isokernelparams']}" = "" ]; then
      options['isokernelparams']="${options['isoserialkernelparams']}"
    else
      options['isokernelparams']="${options['isokernelparams']} ${options['isoserialkernelparams']}"
    fi
    if [ "${options['kernelparams']}" = "" ]; then
      options['kernelparams']="${options['serialkernelparams']}"
    else
      options['kernelparams']="${options['kernelparams']} ${options['serialkernelparams']}"
    fi
    spacer=$'\n    '
    if [ "${options['isoextraargs']}" = "" ]; then
      options['isoextraargs']="${options['serialextraargs']}"
    else
      options['isoextraargs']="${options['isoextraargs']}${spacer}${options['serialextraargs']}"
    fi
    if [ "${options['extraargs']}" = "" ]; then
      options['extraargs']="${options['serialextraargs']}"
    else
      options['extraargs']="${options['extraargs']}${spacer}${options['serialextraargs']}"
    fi
  fi
  if [[ ${options['kernel']} =~ latest ]] && [[ ${options['kernel']} =~ hardened ]]; then
    options['kernel']="_latest_hardened"
  else
    if [[ ${options['kernel']} =~ latest ]]; then
      options['kernel']="_latest"
    else
      if [[ ${options['kernel']} =~ hardened ]]; then
        options['kernel']="_hardened"
      fi
    fi
  fi
  if ! [ "${options['import']}" = "" ]; then
    if ! [ -f "${options['import']}" ]; then
      warning_message "Nix configuration file ${options['import']} does not exist"
      do_exit
    else
      import=$( basename "${options['import']}" )
      execute_command "cp ${options['import']} ${options['source']}"
    fi
    options['imports']="${options['import']} ./${import}"
  fi
  if ! [ "${options['isoimport']}" = "" ]; then
    if ! [ -f "${options['isoimport']}" ]; then
      warning_message "Nix configuration file ${options['isoimport']} does not exist"
      do_exit
    else
      options['isoimports']="${options['isoimport']} ${import}"
    fi
  fi
}

# Function: do_exit
#
# Selective exit (don't exit when we're running in dryrun mode)

do_exit () {
  if [ "${options['dryrun']}" = "false" ]; then
    exit
  fi
}

# Function: check_value
#
# check value (make sure that command line arguments that take values have values)

check_value () {
  param="$1"
  value="$2"
  if [[ ${value} =~ ^-- ]]; then
    print_message "Value '$value' for parameter '$param' looks like a parameter" "verbose"
    echo ""
    if [ "${options['force']}" = "false" ]; then
      do_exit
    fi
  else
    if [ "${value}" = "" ]; then
      print_message "No value given for parameter $param" "verbose"
      echo ""
      if [[ "${param}" =~ "option" ]]; then
        print_options
      else
        if [[ "${param}" =~ "action" ]]; then
          print_actions
        else
          print_help
        fi
      fi
      exit
    fi
  fi
}

# Function: execute_command
#
# Execute command

execute_command () {
  command="$1"
  privilege="$2"
  if [[ "${privilege}" =~ su ]]; then
    command="sudo sh -c \"${command}\""
  fi
  if [ "${options['verbose']}" = "true" ]; then
    execute_message "${command}"
  fi
  if [ "${options['dryrun']}" = "false" ]; then
    eval "${command}"
  fi
}

# Function: print_info
#
# Print information

print_info () {
  info="$1"
  echo ""
  echo "Usage: ${script['bin']} --action(s) [action(,action)] --option(s) [option(,option)]"
  echo ""
  if [[ ${info} =~ switch ]]; then
    echo "${info}(es):"
    echo "-----------"
  else
    echo "${info}(s):"
    echo "----------"
  fi
  while read -r line; do
    if [[ "${line}" =~ .*"# ${info}".* ]]; then
      if [[ "${info}" =~ option ]]; then
        IFS=':' read -r param desc <<< "${line}"
        IFS=']' read -r param default <<< "${param}"
        IFS='[' read -r _ param <<< "${param}"
        param="${param//\'/}"
        default="${options[${param}]}"
        if [ "${param}" = "mask" ]; then
          default="false"
        else
          if [ "${options['mask']}" = "true" ]; then
            default="${default/${script['user']}/user}"
          fi
        fi
        param="${param} (default = ${default})"
      else
        IFS='#' read -r param desc <<< "${line}"
        desc="${desc/${info} :/}"
      fi
      echo "${param}"
      echo "  ${desc}"
    fi
  done < "${script['file']}"
  echo ""
}

# Function: print_help
#
# Print help/usage insformation

print_help () {
  print_info "switch"
}

# Function print_actions
#
# Print actions

print_actions () {
  print_info "action"
}

# Function: print_options
#
# Print options

print_options () {
  print_info "option"
}

# Function: print_usage
#
# Print Usage

print_usage () {
  usage="$1"
  case $usage in
    all|full)
      print_help
      print_actions
      print_options
      ;;
    help)
      print_help
      ;;
    action*)
      print_actions
      ;;
    option*)
      print_options
      ;;
    *)
      print_help
      shift
      ;;
  esac
}

# Function: print_version
#
# Print version information

print_version () {
  script['version']=$( grep '^# Version' < "$0" | awk '{print $3}' )
  echo "${script['version']}"
}

# Function: check_shellcheck
#
# Run Shellcheck

check_shellcheck () {
  bin_test=$( command -v shellcheck | grep -c shellcheck )
  if ! [ "$bin_test" = "0" ]; then
    shellcheck "${script['file']}"
  fi
}

# Do some early command line argument processing

if [ "${script['args']}" = "" ]; then
  print_help
  exit
fi

# Function: process_options
#
# Handle options

process_options () {
  option="$1"
  if [[ "${option}" =~ ^no ]] || [[ "${option}" =~ ^un ]]; then
    options["${option}"]="true"
    option="${option:2}"
    value="false"
  else
    value="true"
  fi
  options["${option}"]="${value}"
  print_message "${option} to ${value}" "set"
}

# Function: print_environment
#
# Print environment

print_environment () {
  echo "Environment (Options):"
  for option in "${!options[@]}"; do
    value="${options[${option}]}"
    echo -e "Option ${option}\tis set to ${value}"
  done
}

# Function: print_defaults
#
# Print defaults

print_defaults () {
  echo "Defaults:"
  for default in "${!options[@]}"; do
    value="${options[${default}]}"
    echo -e "Default ${default}\tis set to ${value}"
  done
}

# Function: check_nix_config
#
# Check NIX config

check_nix_config () {
  if ! [ -d "${options['workdir']}" ]; then
    execute_command "mkdir -p ${options['workdir']}"
  fi
  if ! [ -d "${options['workdir']}/ai" ]; then
    execute_command "mkdir -p ${options['workdir']}/ai"
  fi
  nix_test=$( command -v nix )
  if [ "${nix_test}" = "" ]; then
    sh <(curl --proto '=https' --tlsv1.2 -L https://nixos.org/nix/install) --no-daemon
  fi
}


# Function: get_password_crypt
#
# Get Password Crypt

get_password_crypt () {
  if ! [ "${options['userpassword']}" = "" ]; then
    if [ "${options['usercrypt']}" = "" ]; then
      if [ "${os['name']}" = "Darwin" ]; then
        options['usercrypt']=$( echo "${options['userpassword']}" | openssl passwd -6 --stdin )
      else
        options['usercrypt']=$( mkpasswd --method=sha-512 "${options['userpassword']}" )
      fi
    fi
  fi
  if ! [ "${options['rootpassword']}" = "" ]; then
    if [ "${options['rootcrypt']}" = "" ]; then
      if [ "${os['name']}" = "Darwin" ]; then
        options['rootcrypt']=$( echo "${options['rootpassword']}" | openssl passwd -6 --stdin )
      else
        options['rootcrypt']=$( mkpasswd --method=sha-512 "${options['rootpassword']}" )
      fi
    fi
  fi
}

# Function: get_ssh_key
#
# Get SSH key

get_ssh_key () {
  if [ "${options['sshkey']}" = "" ]; then
    if [ "${options['sshkeyfile']}" = "" ]; then
      information_message "Attempting to find SSH key file"
      key_file=$( find "$HOME"/.ssh -name "*.pub" |head -1 )
      if [ "${key_file}" = "" ]; then
        information_message "No SSH key file found"
        information_message "Disabling use of SSH key file"
      else
        information_message "SSH key file found: ${key_file}"
        options['sshkeyfile']="${key_file}"
        options['sshkey']=$( <"${options['sshkeyfile']}" )
      fi
    else
      if [ -f "${options['sshkeyfile']}" ]; then
        options['sshkey']=$( <"${options['sshkeyfile']}" )
      else
        warning_message "SSH key file ${options['sshkeyfile']} does not exist"
        do_exit
      fi
    fi
  fi
}

# Function: pupulate_iso_kernel_params
#
# Populate a list of extra parameters to add to grub boot command

populate_iso_kernel_params () {
  for param in oneshot attended swap lvm zsh dhcp bridge sshserver bridgenic \
    poweroff reboot nixinstall rootfs bootfs rootdisk mbrpart rootpart efipart \
    swappart kernel swapsize rootsize bootsize rootpool swapvolname rootvolname \
    bootpolname installdir mbrpartname locale devnodes logdir logfile timezone \
    usershell username extragroups usergecos normaluser sudocommand sudooptions \
    rootpassword userpassword stateversion hostname unfree gfxmode gfxpatload \
    nic dns ip gateway cidr zfsoptions systempackages imports hwimports firewall \
    sshpasswordauthentication allowedtcpports allowedudpports targetarch sshkey \
    blacklist; do
    value="${options[${param}]}"
    if ! [ "${value}" = ""  ]; then
      if [[ ${param} =~ zfsoptions|sshkey|blacklist|imports|packages ]]; then
        item="\"ai.${param}=\\\"${value}\\\"\""
      else
        item="\"ai.${param}=${value}\""
      fi
    fi 
    options['isokernelparams']+=" ${item} "
  done
}

# Function: create_nix_config
#
# Create NixOS config

create_nix_iso_config () {
  check_nix_config
  get_ssh_key
  populate_iso_kernel_params
  verbose_message "Creating ${options['nixisoconfig']}"
  if [ "${options['createdockeriso']}" = "true" ]; then
    source_dir="/root/${script['name']}/ai"
  else
    source_dir="${options['source']}"
  fi
  tee "${options['nixisoconfig']}" << NIXISOCONFIG
# ISO build config
{ config, pkgs, ... }:
{
  imports = [ ${options['isoimports']} ];

  # Add contents to ISO
  isoImage = {
    contents = [
      { source = ${source_dir} ;
        target = "${options['target']}";
      }
    ];
NIXISOCONFIG
  if [ "${options['standalone']}" = "true" ]; then
    tee -a "${options['nixisoconfig']}" << NIXISOCONFIG
    storeContents = [
      config.system.build.toplevel
    ];
    includeSystemBuildDependencies = true;
NIXISOCONFIG
  else
    tee -a "${options['nixisoconfig']}" << NIXISOCONFIG
    storeContents = with pkgs; [
      ${options['systempackages']}
    ];
NIXISOCONFIG
  fi
  tee -a "${options['nixisoconfig']}" << NIXISOCONFIG
  };

  # Set boot params
  boot.runSize = "${options['runsize']}";
  boot.loader = {
    grub = {
      gfxmodeEfi = "${options['gfxmode']}";
      gfxpayloadEfi = "${options['gfxpayload']}";
      gfxmodeBios = "${options['gfxmode']}";
      gfxpayloadBios = "${options['gfxpayload']}";
      extraConfig = "
        ${options['isoextraargs']}
      ";
      extraEntries = ''
        menuentry "Boot from next volume" {
          exit 1
        }
      '';
    };
  };
  boot.kernelParams = [ ${options['isokernelparams']} ];
#  boot.kernelPackages = pkgs.linuxPackages${options['kernel']};

  # Set your time zone
  time.timeZone = "${options['timezone']}";

  # Select internationalisation properties.
  i18n.defaultLocale = "${options['locale']}";
  i18n.extraLocaleSettings = {
    LC_ADDRESS = "${options['locale']}";
    LC_IDENTIFICATION = "${options['locale']}";
    LC_MEASUREMENT = "${options['locale']}";
    LC_MONETARY = "${options['locale']}";
    LC_NAME = "${options['locale']}";
    LC_NUMERIC = "${options['locale']}";
    LC_PAPER = "${options['locale']}";
    LC_TELEPHONE = "${options['locale']}";
    LC_TIME = "${options['locale']}";
  };

  # Firewall
  networking.firewall = {
    enable = ${options['firewall']};
    allowedTCPPorts = [ ${options['allowedtcpports']} ];
    allowedUDPPorts = [ ${options['allowedudpports']} ];
  };

  # OpenSSH
  services.openssh.enable = ${options['sshserver']};
  services.openssh.settings.PasswordAuthentication = ${options['sshpasswordauthentication']};

  # Enable SSH in the boot process.
  systemd.services.sshd.wantedBy = pkgs.lib.mkForce [ "multi-user.target" ];
  users.users.root.openssh.authorizedKeys.keys = ["${options['sshkey']}" ];

  # Based packages to include in ISO
  environment.systemPackages = with pkgs; [ ${options['systempackages']} ];

  # Additional Nix options
  nix.settings.experimental-features = "${options['experimental-features']}";

  # Allow unfree packages
  nixpkgs.config.allowUnfree = ${options['unfree']};

NIXISOCONFIG

  if [ "${options['attended']}" = "false" ]; then
    tee -a "${options['nixisoconfig']}" << NIXISOCONFIG
  # Unattended install service
  systemd.services.unattended-install = {
    description = "Unattended NixOS installation script";
    wantedBy = [ "multi-user.target" ];
    after = [ "getty.target" ];
    conflicts = [ "getty@tty1.service" ];
    serviceConfig = {
      User = "nixos";
      Type = "oneshot";
      StandardInput = "tty-force";
      RestartSec = 1200;
    };
    unitConfig = {
      OnFailure = "multi-user.target";
    };
    restartIfChanged = false;
    script = ''
      export PATH="/run/wrappers/bin:/root/.nix-profile/bin:/nix/profile/bin:/root/.local/state/nix/profile/bin:/etc/profiles/per-user/root/bin:/nix/var/nix/profiles/default/bin:/run/current-system/sw/bin"
      sudo ${options['isomount']}/${options['prefix']}/oneshot.sh
    '';
  };

NIXISOCONFIG
  fi

  tee -a "${options['nixisoconfig']}" << NIXISOCONFIG
  system.stateVersion = "${options['stateversion']}";
}
NIXISOCONFIG
}

# Function: create_oneshot_script
#
# Create oneshot script

create_oneshot_script () {
  check_nix_config
  get_ssh_key
  verbose_message "Creating ${options['oneshotscript']}"
  tee "${options['oneshotscript']}" << ONESHOT
#!/run/current-system/sw/bin/bash
set -x
export PATH="/run/wrappers/bin:/root/.nix-profile/bin:/nix/profile/bin:/root/.local/state/nix/profile/bin:/etc/profiles/per-user/root/bin:/nix/var/nix/profiles/default/bin:/run/current-system/sw/bin"
mkdir -p ${options['tempdir']}/${options['prefix']}
cp ${options['isomount']}/${options['prefix']}/*.sh ${options['tempdir']}/${options['prefix']}
chmod +x ${options['installdir']}/${options['prefix']}/*.sh
sudo ${options['tempdir']}/${options['prefix']}/install.sh
ONESHOT
  chmod +x "${options['oneshotscript']}"
}


# Function: create_install_script
#
# Create install script

create_install_script () {
  check_nix_config
  get_ssh_key
  get_password_crypt
  verbose_message "Creating ${options['installscript']}"
  tee "${options['installscript']}" << INSTALL
#!/run/current-system/sw/bin/bash
export PATH="/run/wrappers/bin:/root/.nix-profile/bin:/nix/profile/bin:/root/.local/state/nix/profile/bin:/etc/profiles/per-user/root/bin:/nix/var/nix/profiles/default/bin:/run/current-system/sw/bin"

# Set general environment
declare -A ai

ai['swap']="${options['swap']}"
ai['lvm']="${options['lvm']}"
ai['zsh']="${options['zsh']}"
ai['dhcp']="${options['dhcp']}"
ai['bridge']="${options['bridge']}"
ai['sshserver']="${options['sshserver']}"
ai['bridgenic']="${options['bridgenic']}"
ai['reboot']="${options['reboot']}"
ai['poweroff']="${options['poweroff']}"
ai['attended']="${options['attended']}"
ai['nixinstall']="${options['nixinstall']}"
ai['rootfs']="${options['rootfs']}"
ai['bootfs']="${options['bootfs']}"
ai['rootdisk']="${options['rootdisk']}"
ai['mbrpart']="${options['mbrpart']}"
ai['rootpart']="${options['rootpart']}"
ai['efipart']="${options['efipart']}"
ai['bootpart']="${options['efipart']}"
ai['swappart']="${options['swappart']}"
ai['swapsize']="${options['swapsize']}"
ai['rootsize']="${options['rootsize']}"
ai['bootsize']="${options['bootsize']}"
ai['rootpool']="${options['rootpool']}"
ai['swapvolname']="${options['swapvolname']}"
ai['bootvolname']="${options['bootvolname']}"
ai['rootvolname']="${options['rootvolname']}"
ai['installdir']="${options['installdir']}"
ai['mbrpartname']="${options['mbrpartname']}"
ai['locale']="${options['locale']}"
ai['devnodes']="${options['devnodes']}"
ai['logdir']="${options['logdir']}"
ai['logfile']="${options['logfile']}"
ai['timezone']="${options['timezone']}"
ai['usershell']="${options['usershell']}"
ai['username']="${options['username']}"
ai['extragroups']="${options['extragroups']}"
ai['usergecos']="${options['usergecos']}"
ai['normaluser']="${options['normaluser']}"
ai['sudocommand']="${options['sudocommand']}"
ai['sudooptions']="${options['sudooptions']}"
ai['rootpassword']="${options['rootpassword']}"
ai['rootcrypt']=\$( mkpasswd --method=sha-512 "\${ai['rootpassword']}" )
ai['userpassword']="${options['userpassword']}"
ai['usercrypt']=\$( mkpasswd --method=sha-512 "\${ai['userpassword']}" )
ai['stateversion']="${options['stateversion']}"
ai['hostname']="${options['hostname']}"
ai['hostid']=\$( head -c 8 /etc/machine-id )
ai['nixdir']="\${ai['installdir']}/etc/nixos"
ai['nixcfg']="\${ai['nixdir']}/configuration.nix"
ai['hwcfg']="\${ai['nixdir']}/hardware-configuration.nix"
ai['zfsoptions']="${options['zfsoptions']}"
ai['availmods']="${options['availmods']}"
ai['initmods']="${options['initmods']}"
ai['bootmods']="${options['bootmods']}"
ai['experimental-features']="${options['experimental-features']}"
ai['unfree']="${options['unfree']}"
ai['gfxmode']="${options['gfxmode']}"
ai['gfxpayload']="${options['gfxpayload']}"
ai['nic']="${options['nic']}"
ai['dns']="${options['dns']}"
ai['ip']="${options['ip']}"
ai['gateway']="${options['gateway']}"
ai['cidr']="${options['cidr']}"
ai['sshkey']="${options['sshkey']}"
ai['oneshot']="${options['oneshot']}"
ai['kernelparams']="${options['kernelparams']}"
ai['extraargs']="${options['extraargs']}"
ai['imports']="${options['imports']}"
ai['kernel']="${options['kernel']}"
ai['sshpasswordauthentication']="${options['sshpasswordauthentication']}"
ai['allowedtcpports']="${options['allowedtcpports']}"
ai['allowedudpports']="${options['allowedudpports']}"
ai['isomount']="${options['isomount']}"
ai['prefix']="${options['prefix']}"
ai['targetarch']="${options['targetarch']}"
ai['systempackages']="${options['systempackages']}"
ai['blacklist']="${options['blacklist']}"
ai['sysctl']="${options['sysctl']}"

# Parse parameters
echo "Processing parameters"
for param in \${!ai[@]}
do
  echo "Setting \${param} to \${ai[\${param}]}"
done

# Parse grub parameters
echo "Processing grub parameters"
str=\$( < /proc/cmdline )
del="ai."
sep="\${str}\${del}"
items=();
while [[ "\${sep}" ]]; do
    items+=( "\${sep%%"\$del"*}" );
    sep=\${sep#*"\$del"};
done;
declare -a items
for item in "\${items[@]}"; do
  if [[ ! \${item} =~ BOOT_IMAGE ]]; then
    IFS='=' read -r param value <<< \${item}
    value=\${value//\"/}
    value=\${value// nohibernate*/}
    value="\${value%"\${value##*[![:space:]]}"}"
    if [ ! "\${value}" = "" ]; then
      if [ ! "\${ai[\${param}]}" = "\${value}" ]; then
        ai[\${param}]="\${value}"
        echo "Setting \${param} to \${value}"
      fi
    fi
  fi
done
ai['zfsoptions']="\${ai['zfsoptions']} -R \${ai['installdir']}"
echo "Setting zfsoptions to \${ai['zfsoptions']}"

# If oneshot is disabled exit
if [ "\${ai['oneshot']}" = "false" ]; then
  exit
fi

# Set up non DHCP environment
if [ "\${ai['dhcp']}" = "false" ]; then
  if [ "\${ai['nic']}" = "first" ]; then
    ai['nic']=\$( ip link | grep "state UP" | awk '{ print \$2}' | head -1 | grep ^e | cut -f1 -d: )
    echo "Setting nic to \${ai['nic']}"
  fi
fi

# Discover first disk
if [ "\${ai['rootdisk']}" = "first" ]; then
  ai['rootdisk']=\$( lsblk -x TYPE|grep disk |sort |head -1 |awk '{print \$1}' )
  ai['rootdisk']="/dev/\${ai['rootdisk']}"
  echo "Setting rootdisk to \${ai['rootdisk']}"
fi

# Check we are using only one volume manager
if [ "\${ai['lvm']}" = "true" ] && [ "\${ai['rootfs']}" = "zfs" ]; then
  echo "Cannot use two volume managers (LVM and ZFS)"
  exit
fi

# QEMU check
qemu_check=\$( cat /proc/ioports |grep QEMU )
if [ -n "\${qemu_check}" ]; then
  if [ "\${ai['bootmods']}" = "" ]; then
    ai['bootmods']="\"kvm-intel\""
  else
    ai['bootmods']="\${ai['bootmods']} \"kvm-intel\""
  fi
  echo "Setting bootmods to \${ai['bootmods']}"
  if [ "\${ai['hwimports']}" = "" ]; then
    ai['hwimports']="(modulesPath + \"/profiles/qemu-guest.nix\")"
  else
    ai['hwimports']="\${ai['hwimports']} (modulesPath + \"/profiles/qemu-guest.nix\")"
  fi
  echo "Setting hwimports to \${ai['hwimports']}"
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
  ai['grubdev']="\${ai['rootdisk']}"
  ai['bootvolname']="biosboot"
fi
echo "Setting biosflag to \${ai['biosflag']}"
echo "Setting uefiflag to \${ai['uefiflag']}"
echo "Setting grubdev to \${ai['grubdev']}"
echo "Setting biosvolname to \${ai['biosvolname']}"

# Set root partition type
case "\${ai['rootfs']}" in
  "zfs")
    ai['partflag']="BF01"
    ai['rootname']="rpool"
    ;;
  *)
    ai['partflag']="8300"
    ai['rootname']="root"
    ;;
esac
echo "Setting partflag to \${ai['partflag']}"
echo "Setting rootname to \${ai['rootname']}"

# Wipe and set up disks
echo "Wiping \${ai['rootdisk']}"
swapoff -a
umount -Rl \${ai['installdir']}
zpool destroy -f \${ai['rootpool']}
lvremove -f \${ai['rootpool']}
wipefs \${ai['rootdisk']}
sgdisk --zap-all \${ai['rootdisk']}
zpool labelclear -f \${ai['rootdisk']}
partprobe \${ai['rootdisk']}
sleep 5s
echo "Partitioning \${ai['rootdisk']}"
if [ "\${ai['biosflag']}" = "true" ]; then
  sgdisk -a \${ai['mbrpart']} -n \${ai['mbrpart']}:0:+1M -t \${ai['mbrpart']}:EF02 -c \${ai['mbrpart']}:\${ai['mbrvolname']} \${ai['rootdisk']}
fi
if [ "\${ai['lvm']}" = "true" ]; then
  sgdisk -n \${ai['rootpart']}:0:0 -t \${ai['rootpart']}:\${ai['partflag']} -c \${ai['rootpart']}:\${ai['rootvolname']} \${ai['rootdisk']}
  pvcreate -f \${ai['rootdisk']}\${ai['rootpart']}
  vgcreate -f \${ai['rootpool']} \${ai['rootdisk']}\${ai['rootpart']}
  lvcreate -y --size \${ai['bootsize']} --name \${ai['bootvolname']} \${ai['rootpool']}
  if [ "\${USE_SWAP}" = "true" ]; then
    lvcreate -y --size \${ai['swapsize']} --name \${ai['swapvolname']} \${ai['rootpool']}
  fi
  lvcreate -y --size \${ai['rootsize']} --name \${ai['rootvolname']} \${ai['rootpool']}
  ai['swapvol']="/dev/\${ai['rootpool']}/\${ai['swapvolname']}"
  ai['bootvol']="/dev/\${ai['rootpool']}/\${ai['bootvolname']}"
  ai['rootvol']="/dev/\${ai['rootpool']}/\${ai['rootvolname']}"
  lvextend -l +100%FREE \${ai['rootvol']}
  if [ "\${ai[initmods]}" = "" ]; then
    ai['initmods']="\"dm-snapshot\" \"dm-raid\" \"dm-cache-default\""
  else
    ai['initmods']="\${ai['initmods']} \"dm-snapshot\" \"dm-raid\" \"dm-cache-default\""
  fi
  ai['rootsearch']=\$( ls -l \${ai['rootvol']} | awk '{print \$11}' |cut -f2 -d/ )
  ai['bootsearch']=\$( ls -l \${ai['bootvol']} | awk '{print \$11}' |cut -f2 -d/ )
  ai['swapsearch']=\$( ls -l \${ai['swapvol']} | awk '{print \$11}' |cut -f2 -d/ )
else
  sgdisk -n \${ai['efipart']}:2M:+\${ai['bootsize']} -t \${ai['efipart']}:EF00 -c \${ai['efipart']}:\${ai['bootvolname']} \${ai['rootdisk']}
  if [ "\${ai['swap']}" = "true" ]; then
    sgdisk -n \${ai['swappart']}:0:+\${ai['swapsize']} -t \${ai['swappart']}:8200 -c \${ai['swappart']}:\${ai['swapname']} \${ai['rootdisk']}
  fi
  sgdisk -n \${ai['rootpart']}:0:0 -t \${ai['rootpart']}:\${ai['partflag']} -c \${ai['rootpart']}:\${ai['rootvolname']} \${ai['rootdisk']}
  ai['swapvol']="\${ai['rootdisk']}\${ai['swappart']}"
  ai['bootvol']="\${ai['rootdisk']}\${ai['bootpart']}"
  ai['rootvol']="\${ai['rootdisk']}\${ai['rootpart']}"
  ai['rootsuffix']=\$( echo "\${ai['rootdisk']}" | cut -f3 -d/  )
  ai['rootsearch']="\${ai['rootsuffix']}\${ai['rootpart']}"
  ai['bootsearch']="\${ai['rootsuffix']}\${ai['bootpart']}"
  ai['swapsearch']="\${ai['rootsuffix']}\${ai['swappart']}"
fi
partprobe \${ai['rootdisk']}
sleep 5s
echo "Setting rootvol to \${ai['rootvol']}"
echo "Setting bootvol to \${ai['bootvol']}"
echo "Setting swapvol to \${ai['swapvol']}"
echo "Setting rootsearch to \${ai['rootsearch']}"
echo "Setting bootsearch to \${ai['bootsearch']}"
echo "Setting swapsearch to \${ai['swapsearch']}"

# Make and mount filesystems
echo "Making and mounting filesystems"
if [ "\${ai['swap']}" = "true" ]; then
  mkswap -L \${ai['swapvolname']} \${ai['swapvol']}
  swapon \${ai['swapvol']}
fi
if [ "\${ai['rootfs']}" = "zfs" ]; then
  zpool create -f \${ai['zfsoptions']} \${ai['rootpool']} \${ai['rootdisk']}\${ai['rootpart']}
  for mount_name in root nix var home; do
    zfs create -o mountpoint=legacy \${ai['rootpool']}/\${mount_name}
  done
  mount -t zfs \${ai['rootpool']}/root \${ai['installdir']}
  for mount_name in nix var home; do
    mkdir -p \${ai['installdir']}/\${mount_name}
    mount -t \${ai['rootfs']} \${ai['rootpool']}/\${mount_name} \${ai['installdir']}/\${mount_name}
  done
else
  if [ "\${ai['rootfs']}" = "ext4" ]; then
    mkfs.\${ai['rootfs']} -F -L \${ai['rootvolname']} \${ai['rootvol']}
  else
    mkfs.\${ai['rootfs']} -f -L \${ai['rootvolname']} \${ai['rootvol']}
  fi
  mount -t \${ai['rootfs']} \${ai['rootvol']} \${ai['installdir']}
fi
mkfs.\${ai['bootfs']} \${ai['bootvol']}
mkdir \${ai['installdir']}/boot
mount \${ai['bootvol']} \${ai['installdir']}/boot
mkdir -p \${ai['nixdir']}
rm \${ai['nixdir']}/*
cp \${ai['isomount']}/\${ai['prefix']}/*.nix \${ai['nixdir']}

# Create configuration.nix
echo "Creating \${ai['nixcfg']}"
tee \${ai['nixcfg']} << NIX_CFG
{ config, lib, pkgs, ... }:
{
  imports = [ \${ai['imports']} ./hardware-configuration.nix ];
  boot.loader.systemd-boot.enable = \${ai['uefiflag']};
  boot.loader.efi.canTouchEfiVariables = \${ai['uefiflag']};
  boot.loader.grub.devices = [ "\${ai['grubdev']}" ];
  boot.loader.grub.gfxmodeEfi = "\${ai['gfxmode']}";
  boot.loader.grub.gfxpayloadEfi = "\${ai['gfpayxload']}";
  boot.loader.grub.gfxmodeBios = "\${ai['gfxmode']}";
  boot.loader.grub.gfxpayloadBios = "\${ai['gfxpayload']}";
  boot.initrd.supportedFilesystems = ["\${ai['rootfs']}"];
  boot.supportedFilesystems = [ "\${ai['rootfs']}" ];
  boot.zfs.devNodes = "\${ai['devnodes']}";
  services.lvm.boot.thin.enable = \${ai['lvm']};
#  boot.kernelPackages = pkgs.linuxPackages\${ai['kernel']};
  boot.blacklistedKernelModules = [ \${ai['blacklist']} ];

  # Sysctl Parameters
  boot.kernel.sysctl = {
    \${ai['sysctl']}
  };


  # HostID and Hostname
  networking.hostId = "\${ai['hostid']}";
  networking.hostName = "\${ai['hostname']}";

  # Services
  services.openssh.enable = \${ai['sshserver']};
  services.openssh.settings.PasswordAuthentication = \${ai['sshpasswordauthentication']};

  # Firewall
  networking.firewall = {
    enable = \${ai['firewall']};
    allowedTCPPorts = [ \${ai['allowedtcpports']} ];
    allowedUDPPorts = [ \${ai['allowedudpports']} ];
  };

  # Additional Nix options
  nix.settings.experimental-features = "\${ai['experimental-features']}";

  # System packages
  environment.systemPackages = with pkgs; [ \${ai['systempackages']} ];

  # Allow unfree packages
  nixpkgs.config.allowUnfree = \${ai['unfree']};

  # Set your time zone.
  time.timeZone = "\${ai['timezone']}";

  # Select internationalisation properties.
  i18n.defaultLocale = "\${ai['locale']}";
  i18n.extraLocaleSettings = {
    LC_ADDRESS = "\${ai['locale']}";
    LC_IDENTIFICATION = "\${ai['locale']}";
    LC_MEASUREMENT = "\${ai['locale']}";
    LC_MONETARY = "\${ai['locale']}";
    LC_NAME = "\${ai['locale']}";
    LC_NUMERIC = "\${ai['locale']}";
    LC_PAPER = "\${ai['locale']}";
    LC_TELEPHONE = "\${ai['locale']}";
    LC_TIME = "\${ai['locale']}";
  };

  # Define a user account.
  users.users.\${ai['username']} = {
    shell = pkgs.\${ai['usershell']};
    isNormalUser = \${ai['normaluser']};
    description = "\${ai['usergecos']}";
    extraGroups = [ "\${ai['extragroups']}" ];
    openssh.authorizedKeys.keys = [ "\${ai['sshkey']}" ];
    hashedPassword = "\${ai['usercrypt']}";
  };
  programs.zsh.enable = \${ai['zsh']};

  # Sudo configuration
  security.sudo.extraRules= [
    { users = [ "\${ai['username']}" ];
      commands = [
        { command = "\${ai['sudocommand']}" ;
          options= [ "\${ai['sudooptions']}" ];
        }
      ];
    }
  ];

  # Networking
  networking.useDHCP = lib.mkDefault \${ai['dhcp']};
NIX_CFG
if [ "\${ai['dhcp']}" = "false" ]; then
  if [ "\${ai['bridge']}" = "false" ]; then
    tee -a \${ai['nixcfg']} << NIX_CFG
  networking = {
    interfaces."\${ai['nic']}".useDHCP = \${ai['dhcp']};
    interfaces."\${ai['nic']}".ipv4.addresses = [{
      address = "\${ai['ip']}";
      prefixLength = \${ai['cidr']};
    }];
    defaultGateway = "\${ai['gateway']}";
    nameservers = [ "\${ai['dns']}" ];
  };
NIX_CFG
  else
    tee -a \${ai['nixcfg']} << NIX_CFG
  networking = {
    bridges."\${ai['bridgenic']}".interfaces = [ "\${ai['nic']}" ];
    interfaces."\${bridgenic}".useDHCP = \${ai['dhcp']};
    interfaces."\${nic}".useDHCP = \${ai['dhcp']};
    interfaces."\${bridgenic}".ipv4.addresses = [{
      address = "\${ai['ip']}";
      prefixLength = \${ai['cidr']};
    }];
    defaultGateway = "\${ai['gateway']}";
    nameservers = [ "\${ai['dns']}" ];
  };
NIX_CFG
  fi
fi
tee -a \${ai['nixcfg']} << NIX_CFG
  users.users.root.initialHashedPassword = "\${ai['rootcrypt']}";
  nixpkgs.hostPlatform = lib.mkDefault "\${ai['targetarch']}-linux";
  system.stateVersion = "\${ai['stateversion']}";
}
NIX_CFG

# Get device UUIDs
if [ "\${ai['swap']}" = "true" ]; then
  ai['swapuuid']=\$(ls -l \${ai['devnodes']} |grep \${ai['swapsearch']} |awk '{print \$9}' )
  ai['swapdev']="\${ai['devnodes']}/\${ai['swapuuid']}"
else
  ai['swapdev']=""
fi
ai['bootuuid']=\$(ls -l \${ai['devnodes']} |grep \${ai['bootsearch']} |awk '{print \$9}' )
ai['bootdev']="\${ai['devnodes']}/\${ai['bootuuid']}"
ai['rootuuid']=\$(ls -l \${ai['devnodes']} |grep \${ai['rootsearch']} |awk '{print \$9}' )
ai['rootdev']="\${ai['devnodes']}/\${ai['rootuuid']}"
echo "Setting rootuuid to \${ai['rootuuid']}"
echo "Setting rootdev to \${ai['rootdev']}"
echo "Setting bootuuid to \${ai['bootuuid']}"
echo "Setting bootdev to \${ai['bootdev']}"
echo "Setting swapuuid to \${ai['swapuuid']}"
echo "Setting swapdev to \${ai['swapdev']}"

# Create hardware-configuration.nix
echo "Creating \${ai['nixcfg']}"
tee \${ai['hwcfg']} << HW_CFG
{ config, lib, pkgs, modulesPath, ... }:
{
  imports = [ \${ai['hwimports']} ];
  boot.initrd.availableKernelModules = [ \${ai['availmods']} ];
  boot.initrd.kernelModules = [ \${ai['initmods']} ];
  boot.kernelModules = [ \${ai['bootmods']} ];
  boot.kernelParams = [ \${ai['kernelparams']} ];
  boot.loader.grub.extraConfig = "
    \${ai['extraargs']}
  ";
  boot.extraModulePackages = [ ];
HW_CFG
if [ "\${ai['rootfs']}" = "zfs" ]; then
  tee -a \${ai['hwcfg']} << HW_CFG
  fileSystems."/" = {
    device = "\${ai['rootpool']}/root";
    fsType = "\${ai['rootfs']}";
    neededForBoot = true;
  };
  fileSystems."/nix" = {
    device = "\${ai['rootpool']}/nix";
    fsType = "\${ai['rootfs']}";
  };
  fileSystems."/home" = {
    device = "\${ai['rootpool']}/home";
    fsType = "\${ai['rootfs']}";
  };
  fileSystems."/var" = {
    device = "\${ai['rootpool']}/var";
    fsType = "\${ai['rootfs']}";
  };
HW_CFG
else
  tee -a \${ai['hwcfg']} << HW_CFG
  fileSystems."/" = {
    device = "\${ai['rootdev']}";
    fsType = "\${ai['rootfs']}";
    neededForBoot = true;
  };
HW_CFG
fi
tee -a \${ai['hwcfg']} << HW_CFG
  fileSystems."/boot" = {
    device = "\${ai['bootdev']}";
    fsType = "\${ai['bootfs']}";
    options = [ "fmask=0022" "dmask=0022" ];
  };
  swapDevices = [ { device = "\${ai['swapdev']}"; } ];
}
HW_CFG

# Manual config creation command if you need it
# nixos-generate-config --root \${ai['installdir']}

echo "Creating log directory \${ai['installdir']}\${ai['logdir']}"
mkdir -p \${ai['installdir']}/\${ai['logdir']}

if [ "\${ai['attended']}" = "true" ]; then
  echo "To install:"
  echo "nixos-install -v --show-trace --no-root-passwd 2>&1 |tee \${ai['installdir']}\${ai['logfile']}"
  echo "To unmount filesystems and reboot:"
  echo "umount -Rl \${ai['installdir']}"
  echo "zpool export -a"
  echo "swapoff -a"
  echo "reboot"
  exit
else
  nixos-install -v --show-trace --no-root-passwd 2>&1 |tee \${ai['installdir']}\${ai['logfile']}
  echo "Logged to \${ai['installdir']}\${ai['logfile']}"
fi

# Check Installation finished
install_check=\$( tail -1 "\${ai['installdir']}\${ai['logfile']}" | grep -c "installation finished" )

# Exit if not finished
if [ "\${install_check}" = "0" ]; then
  echo "Installation did not finish"
  exit
else
  umount -Rl \${ai['installdir']}
  zpool export -a
  swapoff -a
fi

if [ "\${ai['poweroff']}" = "true" ]; then
  poweroff
fi
if [ "\${ai['reboot']}" = "true" ]; then
  reboot
fi

INSTALL
chmod +x "${options['installscript']}"
}

# Function: get_output_file_suffix
#
# Determine output ISO file name suffix

get_output_file_suffix () {
  if [ "${options['suffix']}" = "${script['name']}" ]; then
    suffix="${script['name']}"
  else
    if [ "${options['suffix']}" = "" ]; then
      suffix="${script['name']}"
    else
      suffix="${script['name']}-${options['suffix']}"
    fi
  fi
  for param in rootdisk nic ; do
    value="${options[${param}]}"
    if ! [ "${value}" = "first" ]; then
      suffix="${suffix}-${value}"
    fi
  done
  for param in ip username; do
    value="${options[${param}]}"
    if ! [ "${value}" = "" ]; then
      suffix="${suffix}-${value}"
    fi
  done
  for param in unattended noreboot standalone lvm; do
    value="${options[${param}]}"
    if [ "${value}" = "true" ]; then
      suffix="${suffix}-${param}"
    fi
  done
  suffix="${suffix}-${options['rootfs']}.iso"
  options['suffix']="${suffix}"
}

# Function: update_output_file_name
#
# Update output ISO file name based on options

update_output_file_name () {
  if [ "${options['output']}" = "" ]; then
    output_dir="${options['workdir']}/isos"
    temp_name=$( basename -s ".iso" "${iso_file}" )
    get_output_file_suffix
    options['output']="${output_dir}/${options['suffix']}"
  fi 
}

# Function: preserve_iso
#
# Preserve ISO

preserve_iso () {
  iso_file="$1"
  update_output_file_name
  output_dir=$( dirname "${options['output']}" )
  if ! [ -d "${output_dir}" ]; then
    execute_command "mkdir -p ${output_dir}"
  fi
  if [ -f "${options['output']}" ]; then
    execute_command "rm -f ${options['output']}"
  fi
  execute_command "cp ${iso_file} ${options['output']}"
}

# Function: create_iso
#
# Create ISO

create_iso () {
  check_nix_config
  create_nix_iso_config
  create_oneshot_script
  create_install_script
  execute_command "cd ${options['workdir']} ; nix-build '<nixpkgs/nixos>' -A config.system.build.isoImage -I nixos-config=${options['nixisoconfig']} --builders ''"
#  execute_command "nixos-generate -f iso -c ${options['nixisoconfig']}"
  iso_dir="${options['workdir']}/result/iso"
  if [ -d "${iso_dir}" ]; then
    iso_file=$( find "${iso_dir}" -name "*.iso" )
    if [ "${options['preserve']}" = "true" ]; then
      preserve_iso "${iso_file}"
    fi
    verbose_message "Generated ISO: ${iso_file}"
    if [ "${options['preserve']}" = "true" ]; then
      verbose_message "Preserved ISO: ${options['output']}"
    fi
  fi
}

# Function: check_kvm_vm_exists
#
# Check KVM VM exists

check_kvm_vm_exists () {
  if [ "${os['name']}" = "Darwin" ]; then
    status=$( virsh list --all | grep "${vm['name']} " | grep -c "${vm['name']}" )
  else
    status=$( sudo virsh list --all | grep "${vm['name']}" | grep -c "${vm['name']}" )
  fi
  if [ "${status}" = "0" ]; then
    vm['exists']="false"
  else
    vm['exists']="true"
  fi
}

# Function: control_kvm_vm
#
# Control KVM VM

control_kvm_vm () {
  check_kvm_vm_exists
  case ${vm['action']} in
    start)
      action_test="Starting"
      ;;
    stop)
      action_test="Stopping"
      ;;
    console)
      action_test="Consoling to"
      ;;
  esac
  if [ "${vm['exists']}" = "true" ]; then
    if [ "${os['name']}" = "Darwin" ]; then
      vm_check=$( virsh list --all | grep "${vm['name']} " | grep -c "${vm['status']}" )
      if [ "${vm_check}" = "0" ]; then
        information_message "${actions_text} KVM VM ${vm['name']}"
        execute_command "virsh -c \"qemu:///session\" ${vm['action']} ${vm['name']} 2> /dev/null"
      fi
    else
      vm_check=$( sudo virsh list --all | grep "${vm['name']}" | grep -c "${vm['status']}" )
      if [ "${vm_check}" = "0" ]; then
        information_message "${actions_text} KVM VM ${vm['name']}"
        execute_command "sudo virsh ${vm['action']} ${vm['name']} 2> /dev/null"
      fi
    fi
  fi
}

# Function: stop_kvm_vm
#
# Stop KVM VM

stop_kvm_vm () {
  vm['action']="destroy"
  vm['status']="shut off"
  control_kvm_vm
}

# Function: start_kvm_vm
#
# Start KVM VM

start_kvm_vm () {
  vm['action']="start"
  vm['status']="running"
  control_kvm_vm
  if [ "${options['console']}" = "true" ]; then
    vm['action']="console"
    vm['status']="shut off"
    control_kvm_vm
  fi
}

# Function: delete_kvm_vm
#
# Delete a KVM VM

delete_kvm_vm () {
  check_kvm_vm_exists
  stop_kvm_vm
  if [ "${vm['exists']}" = "true" ]; then
    if [ "${os['name']}" = "Darwin" ]; then
      information_message "Deleting VM ${vm['name']}"
      execute_command "virsh -c \"qemu:///session\" undefine ${vm['name']} --nvram 2> /dev/null"
    else
      information_message "Deleting VM ${vm['name']}"
      execute_command "sudo virsh undefine ${vm['name']} --nvram 2> /dev/null"
    fi
  fi
}

# Function: add_iso_to_kvm_vm
#
# Add ISO to KVM VM

add_iso_to_kvm_vm () {
  stop_kvm_vm
  if [ "${vm['exists']}" = "true" ]; then
    if [ "${vm['cdrom']}" = "" ]; then
      add_cdrom_device
    else
      if [ -f "${vm['cdrom']}" ]; then
        set_cdrom_device
      else
        verbose_message "ISO file ${vm['cdrom']} does not exist"
        do_exit
      fi
    fi
  fi
}

# Function: set_cdrom_device
#
# Set cdrom device

set_cdrom_device () {
  stop_kvm_vm
  cdrom_device="/tmp/${vm['name']}_cdrom.xml"
  if [ "${vm['exists']}" = "true" ]; then
    tee "${cdrom_device}" << CDROM_DEVICE
    <disk type='file' device='cdrom'>
      <driver name='qemu' type='raw'/>
      <source file='${vm['cdrom']}'/>
      <target dev='sda' bus='scsi'/>
      <readonly/>
      <address type='drive' controller='0' bus='0' target='0' unit='0'/>
    </disk>
CDROM_DEVICE
    if [ -f "${cdrom_device}" ]; then
      if [ "${os['name']}" = "Darwin" ]; then
        execute_command "virsh update-device ${vm['name']} ${cdrom_device}"
      else
        execute_command "sudo virsh update-device ${vm['name']} ${cdrom_device}"
      fi
    fi
  fi
}

# Function: boot_from_iso
#
# Boot from ISO

boot_from_disk () {
  vm['cdrom']=""
  set_cdrom_device
  start_kvm_vm
}

# Function: boot_from_iso
#
# Boot from ISO

boot_from_cdrom () {
  if [ "${vm['cdrom']}" = "" ]; then
    verbose_message "No ISO file specified"
    do_exit
  else
    if ! [ -f "${vm['cdrom']}" ]; then
      verbose_message "ISO file ${vm['cdrom']} does not exist"
      do_exit
    fi
  fi
  add_iso_to_kvm_vm
  start_kvm_vm
}

# Function: console_to_kvm_vm
#
# Connect to KVM console

console_to_kvm_vm () {
  options['console']="true"
  start_kvm_vm
}

# Function: create_kvm_vm
#
# Create a KVM VM for testing an ISO

create_kvm_vm () {
  if ! [ -d "${vm['dir']}" ]; then
    execute_command "mkdir -p ${vm['dir']}"
  fi
  if [ "${vm['disk']}" = "" ]; then
    vm['size']=${vm['size']//G/}
    vm['disk']="path=${vm['dir']}/${vm['name']},size=${vm['size']}"
  fi
  if [[ ${vm['memory']} =~ G$ ]]; then
    ram="${vm['memory']}"
    ram=${ram//G/}
    ram=$(( 1024 * ${ram} ))
    vm['memory']="${ram}"
  fi
  if [ "${vm['cdrom']}" = "" ]; then
    if [ "${os['name']}" = "Darwin" ]; then
      iso_dir="${options['workdir']}/isos"
    else
      iso_dir="${options['workdir']}/result/iso"
    fi
    if [ -d "${iso_dir}" ]; then
      vm['cdrom']=$( ls -rt "${iso_dir}"/nixos*.iso |tail -1 )
    else
      warning_message "Could not find an ISO to use"
      exit
    fi
  fi
  if ! [ -f "${vm['cdrom']}" ]; then
    warning_message "File ${vm['cdrom']} does not exist"
    do_exit
  fi
  if [ "${os['name']}" = "Darwin" ]; then
    command="virt-install"
    vm['status']=$( virsh list --all | grep "${vm['name']} " | grep -c "${vm['name']}" )
  else
    command="sudo virt-install"
    vm['status']=$( sudo virsh list --all | grep "${vm['name']} " | grep -c "${vm['name']}" )
  fi
  if [ "${vm['status']}" = "0" ]; then
    if [ "${os['name']}" = "Darwin" ]; then
      for param in name vcpus cpu graphics network memory cdrom boot disk wait; do
        if ! [ "${vm[${param}]}" = "" ]; then
          value="${vm[${param}]}"
          command="${command} --${param} ${value}"
        fi
      done
    else
      for param in name machine vcpus cpu os-variant host-device graphics virt-type network memory cdrom boot disk features wait; do
        if ! [ "${vm[${param}]}" = "" ]; then
          value="${vm[${param}]}"
          command="${command} --${param} ${value}"
        fi
      done
    fi
    for param in noautoconsole noreboot; do
      value="${vm[${param}]}"
      if [ "${value}" = "true" ]; then
        command="${command} --${param}"
      fi
    done
    vm_dir="${options['workdir']}/vms"
    if ! [ -d "${vm_dir}" ]; then
      execute_command "mkdir ${vm_dir}"
    fi
    vm_file="${vm_dir}/${vm['name']}.xml"
    execute_command "${command} --print-xml 1 > ${vm_file}"
    if [ "${os['name']}" = "Darwin" ]; then
      execute_command "virsh define ${vm_file}"
    else
      execute_command "sudo virsh define ${vm_file}"
    fi
    verbose_message ""
    verbose_message "To start the VM and connect to console run the following command:"
    verbose_message ""
    if [ "${os['name']}" = "Darwin" ]; then
      verbose_message "virsh start ${vm['name']} ; virsh console ${vm['name']}"
    else
      verbose_message "sudo virsh start ${vm['name']} ; sudo virsh console ${vm['name']}"
    fi
  else
    warning_message "KVM VM ${vm['name']} already exists"
    do_exit
  fi
}

# Function: check_docker
#
# Check docker config

check_docker () {
  if ! [ -f "/.dockerenv" ]; then
    docker_test=$( command -v docker )
    if [ -z "${docker_test}" ]; then
      warning_message "Docker not installed"
      do_exit
    fi
    arch_dir="${options['workdir']}/${options['dockerarch']}"
    if ! [ -d "${arch_dir}" ]; then
      execute_command "mkdir -p ${arch_dir}"
    fi
    docker_image="${script['name']}-latest-${options['dockerarch']}"
    image_check=$( docker images | grep "^${docker_image}" | awk '{ print $1 }' )
    if ! [ "${image_check}" = "${docker_image}" ]; then
      compose_file="${arch_dir}/docker-compose.yml"
      docker_file="${arch_dir}/Dockerfile"
      tee "${compose_file}" << COMPOSE_FILE
version "3"
services:
  ${docker_image}:
    build:
      contect: .
      dockerfile: Dockerfile
    image: ${docker_image}
    container_name: ${docker_image}
    entrypoint: /run/current-system/sw/bin/bash
    working_dir: /root
    platform: linux/${options['dockerarch']}
COMPOSE_FILE
        tee "${docker_file}" << DOCKER_FILE
FROM nixos/nix
RUN nix-channel --update
DOCKER_FILE
        docker build "${arch_dir}" --tag "${docker_image}" --platform "linux/${options['dockerarch']}"
    fi
  fi
}

# Function: create_docker_iso
#
# Create ISO using docker

create_docker_iso () {
  check_nix_config
  create_nix_iso_config
  create_oneshot_script
  create_install_script
  check_docker
  get_output_file_suffix
  platform="linux/${options['dockerarch']}"
  docker_image="${script['name']}-latest-${options['dockerarch']}"
  target_dir="/root/${script['name']}"
  target_script="${target_dir}/create_docker_iso.sh"
  output_dir="${options['workdir']}/isos"
  iso_dir="${target_dir}/result/iso"
  save_dir="${target_dir}/isos"
  config_file="${target_dir}/iso.nix"
  docker_script="${options['workdir']}/create_docker_iso.sh"
  if ! [ -d "${options['workdir']}/isos" ]; then
    execute_command "mkdir ${options['workdir']}/isos"
  fi
  tee "${docker_script}" << CREATE_DOCKER_ISO
cd ${target_dir} ; nix-build '<nixpkgs/nixos>' -A config.system.build.isoImage -I nixos-config=${config_file} --builders ''
if [ -d "${iso_dir}" ]; then
  iso_file=\$( find ${iso_dir} -name "*.iso" )
  temp_name=\$( basename -s ".iso" "\${iso_file}" )
  save_file="\${temp_name}-${options['suffix']}"
  if [ -f "${save_dir}/\${save_file}" ]; then
    rm -f ${save_dir}/\${save_file}
  fi
  cp \${iso_file} ${save_dir}/\${save_file}
  output_file="${output_dir}/\${save_file}"
  echo "Source: \${iso_file}"
  echo "Output: ${save_dir}/\${save_file}"
  echo "Output: \${output_file}"
fi
CREATE_DOCKER_ISO
  execute_command "chmod +x ${docker_script}"
  command="exec docker run --privileged=true --cap-add=CAP_MKNOD --device-cgroup-rule=\"b 7:* rmw\" --platform ${platform} --mount type=bind,source=${options['workdir']},target=${target_dir} ${docker_image} bash ${target_script}"
  if [ "${options['dryrun']}" = "false" ]; then
    execute_command "${command}"
  else
    "Command: ${command}"
  fi
}

# Function: process_actions
#
# Handle actions

process_actions () {
  actions="$1"
  case $actions in
    addiso)                 # action : Add ISO to VM
      add_iso_to_kvm_vm
      exit
      ;;
    bootfromcdrom)          # action : Set boot device to CDROM and boot VM
      boot_from_cdrom
      exit
      ;;
    bootfromdisk)           # action : Set boot device to disk and boot VM
      boot_from_disk
      exit
      ;;
    createinstall*)         # action : Create install script
      create_install_script
      exit
      ;;
    checkdocker*)           # action : Check docker config
      check_docker
      exit
      ;;
    createdockeriso)        # action : Create docker ISO
      create_docker_iso
      exit
      ;;
    createiso)              # action : Create ISO
      create_iso
      exit
      ;;
    createnix*)             # action : Create NixOS ISO config
      create_nix_iso_config
      exit
      ;;
    createoneshot*)         # action : Create install script
      create_oneshot_script
      exit
      ;;
    createvm)               # action : Create install script
      create_kvm_vm
      exit
      ;;
    consolevm)              # action : Create install script
      console_to_kvm_vm
      exit
      ;;
    deletevm)               # action : Create install script
      delete_kvm_vm
      exit
      ;;
    help)                   # action : Print actions help
      print_actions
      exit
      ;;
    printenv*)              # action : Print environment
      print_environment
      exit
      ;;
    printdefaults)          # action : Print defaults
      print_defaults
      exit
      ;;
    setboot*)               # action : Print defaults
      set_boot_device
      exit
      ;;
    start*)                 # action : Start KVM VM
      start_kvm_vm
      exit
      ;;
    stop*)                  # action : Start KVM VM
      stop_kvm_vm
      exit
      ;;
    shellcheck)             # action : Shellcheck script
      check_shellcheck
      exit
      ;;
    version)                # action : Print version
      print_version
      exit
      ;;
    *)
      print_actions
      exit
      ;;
  esac
}

# Handle mask option

if [[ $@ =~ --option ]] && [[ $@ =~ mask ]] || [[ $@ =~ --mask ]]; then
  options['mask']="true"
fi

# Handle command line arguments

while test $# -gt 0; do
  case $1 in
    --action*)                      # switch : Action(s) to perform
      check_value "$1" "$2"
      actions_list+=("$2")
      shift 2
      ;;
    --addiso|--addcdrom)            # switch : Add cdrom to VM
      actions_list+=("addiso")
      shift
      ;;
    --removeiso|--removecdrom)      # switch : Remove cdrom from VM
      actions_list+=("removeiso")
      shift
      ;;
    --allowedtcpports)              # switch : Allowed TCP ports
      check_value "$1" "$2"
      options['allowedtcpports']="$2"
      shift 2
      ;;
    --allowedudpports)              # switch : Allowed UDP ports
      check_value "$1" "$2"
      options['allowedudpports']="$2"
      shift 2
      ;;
    --availmod*)                    # switch : Available system kernel modules
      check_value "$1" "$2"
      options['availmods']="$2"
      shift 2
      ;;
    --blacklist)                    # switch : Blacklist modules
      check_value "$1" "$2"
      options['blacklist']="$2"
      shift 2
      ;;
    --bootfromdisk)                 # switch : Boot VM from disk
      actions_list+=("bootfromdisk")
      shift
      ;;
    --bootfromiso|--bootfromcdrom)  # switch : Boot VM from CDROM
      actions_list+=("bootfromcdrom")
      shift
      ;;
    --bootmod*)                     # switch : Available system boot modules
      check_value "$1" "$2"
      options['bootmods']="$2"
      shift 2
      ;;
    --bootsize)                     # switch : Boot partition size
      check_value "$1" "$2"
      options['bootsize']="$2"
      shift 2
      ;;
    --bootvm|--startvm)             # switch : Boot VM
      actions_list+=("startkvmvm")
      shift
      ;;
    --stopvm)                       # switch : Stop VM
      actions_list+=("stopkvmvm")
      shift
      ;;
    --bridge)                       # switch : Enable bridge
      options['bridge']="true"
      shift
      ;;
    --bridgenic)                    # switch : Bridge NIC
      check_value "$1" "$2"
      options['bridgenic']="$2"
      options['bridge']="true"
      options['dhcp']="false"
      shift 2
      ;;
    --bootf*)                       # switch : Boot Filesystem
      check_value "$1" "$2"
      options['bootfs']="$2"
      shift 2
      ;;
    --bootvol*)                     # switch : Boot volume name
      check_value "$1" "$2"
      options['bootvolname']="$2"
      shift 2
      ;;
    --checkdocker*)                 # switch : Check docker config
      actions_list+=("checkdocker")
      shift
      ;;
    --cidr)                         # switch : CIDR
      check_value "$1" "$2"
      options['cidr']="$2"
      options['dhcp']="false"
      shift 2
      ;;
    --createinstall*)               # switch : Create install script
      actions_list+=("createinstall")
      shift
      ;;
    --createiso)                    # switch : Create ISO
      actions_list+=("createiso")
      shift
      ;;
    --createdockeriso)              # switch : Create ISO
      actions_list+=("createdockeriso")
      options['createdockeriso']="true"
      shift
      ;;
    --createnix*)                   # switch : Create NixOS ISO config
      actions_list+=("createnix")
      shift
      ;;
    --createoneshot*)               # switch : Create oneshot script
      actions_list+=("createoneshot")
      shift
      ;;
    --createvm)                     # switch : Create oneshot script
      actions_list+=("createvm")
      shift
      ;;
    --console*)                     # switch : Create oneshot script
      actions_list+=("consolevm")
      shift
      ;;
    --usercrypt|--crypt)            # switch : User Password Crypt
      check_value "$1" "$2"
      options['usercrypt']="$2"
      shift 2
      ;;
    --debug)                        # switch : Enable debug mode
      options['debug']="true"
      shift
      ;;
    --deletevm)                     # switch : Delete VM
      actions_list+=("deletevm")
      shift
      ;;
    --dhcp)                         # switch : Enable DHCP
      options['dhcp']="true"
      shift
      ;;
    --disk|rootdisk)                # switch : Root disk
      check_value "$1" "$2"
      options['rootdisk']="$2"
      shift 2
      ;;
    --dns|--nameserver)             # switch : DNS/Nameserver address
      check_value "$1" "$2"
      options['dns']="$2"
      options['dhcp']="false"
      shift 2
      ;;
    --dockerarch)                   # switch : Docker architecture
      check_value "$1" "$2"
      options['dockerarch']="$2"
      shift 2
      ;;
    --dryrun)                       # switch : Enable debug mode
      options['dryrun']="true"
      shift
      ;;
    --experimental*)                # switch : SSH key
      check_value "$1" "$2"
      options['experimental-features']="$2"
      shift 2
      ;;
    --extraargs)                    # switch : ISO Kernel extra args
      check_value "$1" "$2"
      options['extraargs']="$2"
      shift 2
      ;;
    --extragroup*)                  # switch : Extra groups
      check_value "$1" "$2"
      options['extragroups']="$2"
      shift 2
      ;;
    --firewall)                     # switch : Enable firewall
      options['firewall']="true"
      shift
      ;;
    --nofirewall)                   # switch : Disable firewall
      options['firewall']="false"
      shift
      ;;
    --firmware)                     # switch : Boot firmware type
      check_value "$1" "$2"
      options['firmware']="$2"
      shift 2
      ;;
    --force)                        # switch : Enable force mode
      options['force']="true"
      shift
      ;;
    --gateway)                      # switch : Gateway address
      check_value "$1" "$2"
      options['gateway']="$2"
      options['dhcp']="false"
      shift 2
      ;;
    --gecos|--usergecos)            # switch : GECOS field
      check_value "$1" "$2"
      options['usergecos']="$2"
      shift 2
      ;;
    --gfxmode)                      # switch : Bios text mode
      check_value "$1" "$2"
      options['gfxmode']="$2"
      shift 2
      ;;
    --gfxpayload)                   # switch : Bios text mode
      check_value "$1" "$2"
      options['gfxpayload']="$2"
      shift 2
      ;;
    --help|-h)                      # switch : Print help information
      print_help
      shift
      exit
      ;;
    --hostname)                     # switch : Hostname
      check_value "$1" "$2"
      options['hostname']="$2"
      shift 2
      ;;
    --hwimports)                    # switch : Imports for system hardware configuration
      check_value "$1" "$2"
      options['hwimports']="$2"
      shift 2
      ;;
    --import)                       # switch : Import a Nix configuration
      check_value "$1" "$2"
      options['import']="$2"
      shift 2
      ;;
    --imports)                      # switch : Imports for system configuration
      check_value "$1" "$2"
      options['imports']="$2"
      shift 2
      ;;
    --initmod*)                     # switch : Available system init modules
      check_value "$1" "$2"
      options['initmods']="$2"
      shift 2
      ;;
    --installscript)                # switch : Install script
      check_value "$1" "$2"
      options['installscript']="$2"
      shift 2
      ;;
    --installdir)                   # switch : Install directory where destination disk is mounted
      check_value "$1" "$2"
      options['installdir']="$2"
      shift 2
      ;;
    --ip)                           # switch : IP address
      check_value "$1" "$2"
      options['ip']="$2"
      options['dhcp']="false"
      shift 2
      ;;
    --isoextra*)                    # switch : ISO Kernel extra args
      check_value "$1" "$2"
      options['isoextraargs']="$2"
      shift 2
      ;;
    --isoimport)                    # switch : Import additional Nix configuration file into ISO configuration
      check_value "$1" "$2"
      options['isoimport']="$2"
      shift 2
      ;;
    --isoimports)                   # switch : NixOS imports for ISO build
      check_value "$1" "$2"
      options['isoimports']="$2"
      shift 2
      ;;
    --isokernelparam*)              # switch : Extra kernel parameters to add to ISO grub commands
      check_value "$1" "$2"
      options['isokernelparams']="$2"
      shift 2
      ;;
    --isomount)                     # switch : Install ISO mount directory
      check_value "$1" "$2"
      options['isomount']="$2"
      shift 2
      ;;
    --keymap)                       # switch : Keymap
      check_value "$1" "$2"
      options['keymap']="$2"
      shift 2
      ;;
    --kernelparam*)                 # switch : Extra kernel parameters to add to systembuild
      check_value "$1" "$2"
      options['kernelparams']="$2"
      shift 2
      ;;
    --kernel)                       # switch : Kernel
      check_value "$1" "$2"
      options['kernel']="$2"
      shift 2
      ;;
    --locale)                       # switch : Locale
      check_value "$1" "$2"
      options['locale']="$2"
      shift 2
      ;;
    --logfile)                      # switch : Locale
      check_value "$1" "$2"
      options['logfile']="$2"
      shift 2
      ;;
    --lvm)                          # switch : Enable LVM
      options['lvm']="true"
      shift
      ;;
    --mask*)                        # switch : Enable LVM
      options['mask']="true"
      shift
      ;;
    --mbrpartname)                  # switch : MBR partition name
      check_value "$1" "$2"
      options['mbrpartname']="$2"
      shift 2
      ;;
    --nic)                          # switch : NIC
      check_value "$1" "$2"
      options['nic']="$2"
      shift 2
      ;;
    --nixconfig)                    # switch : NixOS configuration file
      check_value "$1" "$2"
      options['nixconfig']="$2"
      shift 2
      ;;
    --nixdir)                       # switch : Set NixOS directory
      check_value "$1" "$2"
      options['nixdir']="$2"
      shift 2
      ;;
    --nixhwconfig)                  # switch : NixOS hardware configuration file
      check_value "$1" "$2"
      options['nixhwconfig']="$2"
      shift 2
      ;;
    --nixinstall)                   # switch : Run NixOS install script automatically on ISO
      options['nixinstall']="true"
      shift
      ;;
    --nixisoconfig)                 # switch : NixOS ISO configuration file
      check_value "$1" "$2"
      options['nixisoconfig']="$2"
      shift 2
      ;;
    --oneshot)                      # switch : Enable oneshot service
      options['oneshot']="true"
      shift
      ;;
    --nooneshot)                    # switch : Disable oneshot service
      options['oneshot']="false"
      shift
      ;;
    --option*)                      # switch : Option(s) to set
      check_value "$1" "$2"
      options_list+=("$2")
      shift 2
      ;;
    --output*|--iso)                # switch : Output file
      check_value "$1" "$2"
      options['output']="$2"
      options['preserve']="true"
      shift 2
      ;;
    --password|--userpassword)      # switch : User password
      check_value "$1" "$2"
      options['userpassword']="$2"
      shift 2
      ;;
    --sshpasswordauthentication)    # switch : Eanble SSH password authentication
      options['sshpasswordauthentication']="true"
      shift
      ;;
    --nosshpasswordauthentication)  # switch : Disable SSH password authentication
      options['sshpasswordauthentication']="false"
      shift
      ;;
    --poweroff)                     # switch : Enable poweroff after install
      options['poweroff']="true"
      shift
      ;;
    --prefix)                       # switch : Install prefix
      check_value "$1" "$2"
      options['prefix']="$2"
      shift 2
      ;;
    --preserve)                     # switch : Preserve output file
      options['preserve']="true"
      shift
      ;;
    --reboot)                       # switch : Enable reboot after install
      options['reboot']="true"
      shift
      ;;
    --rootcrypt)                    # switch : Root password crypt
      check_value "$1" "$2"
      options['rootcrypt']="$2"
      shift 2
      ;;
    --rootf*|--filesystem)          # switch : Root Filesystem
      check_value "$1" "$2"
      options['rootfs']="$2"
      shift 2
      ;;
    --rootpassword)                 # switch : Root password
      check_value "$1" "$2"
      options['rootpassword']="$2"
      shift 2
      ;;
    --rootpool)                     # switch : Root pool name
      check_value "$1" "$2"
      options['rootpool']="$2"
      shift 2
      ;;
    --rootsize)                     # switch : Root partition size
      check_value "$1" "$2"
      options['rootsize']="$2"
      shift 2
      ;;
    --rootvol*)                     # switch : Root volume name
      check_value "$1" "$2"
      options['rootvolname']="$2"
      shift 2
      ;;
    --runsize)                      # switch : Run size
      check_value "$1" "$2"
      options['runsize']="$2"
      shift 2
      ;;
    --secure)                       # switch : Enable secure parameters
      options['secure']="true"
      shift
      ;;
    --serial)                       # switch : Enable serial
      options['serial']="true"
      shift
      ;;
    --setboot*)                     # switch : Set boot device
      actions_list+=("setboot")
      shift
      ;;
    --shell|usershell)              # switch : User Shell
      check_value "$1" "$2"
      options['usershell']="$2"
      shift 2
      ;;
    --shellcheck)                   # switch : Run shellcheck
      actions_list+=("shellcheck")
      shift
      ;;
    --source)                       # switch : Source directory for ISO additions
      check_value "$1" "$2"
      options['source']="$2"
      shift 2
      ;;
    --sshkey)                       # switch : SSH key
      check_value "$1" "$2"
      options['sshkey']="$2"
      shift 2
      ;;
    --sshkeyfile)                   # switch : SSH key file
      check_value "$1" "$2"
      options['sshkeyfile']="$2"
      shift 2
      ;;
    --sshserver)                    # switch : Enable strict mode
      options['sshserver']="true"
      shift
      ;;
    --standalone)                   # switch : Create a standalone ISO
      options['standalone']="true"
      shift
      ;;
    --stateversion)                 # switch : NixOS state version
      check_value "$1" "$2"
      options['stateversion']="$2"
      shift 2
      ;;
    --strict)                       # switch : Enable strict mode
      options['strict']="true"
      shift
      ;;
    --sudocommand*)                 # switch : Sudo commands
      check_value "$1" "$2"
      options['sudocommand']="$2"
      shift 2
      ;;
    --sudooption*)                  # switch : Sudo options
      check_value "$1" "$2"
      options['sudooptions']="$2"
      shift 2
      ;;
    --sudouser*)                    # switch : Sudo users
      check_value "$1" "$2"
      options['sudousers']="$2"
      shift 2
      ;;
    --suffix|--outputsuffix)        # switch : Sudo users
      check_value "$1" "$2"
      options['suffix']="$2"
      shift 2
      ;;
    --systempackages)               # switch : NixOS state version
      check_value "$1" "$2"
      options['systempackages']="$2"
      shift 2
      ;;
    --swap)                         # switch : Enable swap
      options['swap']="true"
      shift
      ;;
    --swapsize)                     # switch : Swap partition size
      check_value "$1" "$2"
      options['swapsize']="$2"
      options['swap']="true"
      shift 2
      ;;
    --swapvol*)                     # switch : Swap volume name
      check_value "$1" "$2"
      options['swapvolname']="$2"
      options['swap']="true"
      shift 2
      ;;
    --target)                       # switch : Target directory for ISO additions
      check_value "$1" "$2"
      options['target']="$2"
      shift 2
      ;;
    --targetarch)                   # switch : Target architecture
      check_value "$1" "$2"
      options['targetarch']="$2"
      shift 2
      ;;
    --temp*)                        # switch : Target directory
      check_value "$1" "$2"
      options['tempdir']="$2"
      shift 2
      ;;
    --testmode)                     # switch : Enable swap
      options['testmode']="true"
      shift
      ;;
    --usage)                        # switch : Action to perform
      check_value "$1" "$2"
      usage="$2"
      print_usage "${usage}"
      shift 2
      exit
      ;;
    --username)                     # switch : User username
      check_value "$1" "$2"
      options['username']="$2"
      shift 2
      ;;
    --verbose)                      # switch : Enable verbose mode
      options['verbose']="true"
      shift
      ;;
    --version|-V)                   # switch : Print version information
      print_version
      exit
      ;;
    --videodriver)                  # switch : Video Driver
      check_value "$1" "$2"
      options['videodriver']="$2"
      shift 2
      ;;
    --vmautoconsole)                # switch : VM Autoconsole
      vm['noautoconsole']="false"
      shift
      ;;
    --vmboot)                       # switch : VM Boot type
      check_value "$1" "$2"
      vm['boot']="$2"
      shift 2
      ;;
    --vmcpu)                        # switch : VM CPU
      check_value "$1" "$2"
      vm['cpu']="$2"
      shift 2
      ;;
    --vmdir)                        # switch : VM Directory
      check_value "$1" "$2"
      vm['dir']="$2"
      shift 2
      ;;
    --vmfeatures)                   # switch : VM Features
      check_value "$1" "$2"
      vm['features']="$2"
      shift 2
      ;;
    --vmhostdevice)                 # switch : VM Host device
      check_value "$1" "$2"
      vm['host-device']="$2"
      shift 2
      ;;
    --vmgraphics)                   # switch : VM Graphics
      check_value "$1" "$2"
      vm['graphics']="$2"
      shift 2
      ;;
    --vmiso|--vmcdrom)              # switch : VM ISO
      check_value "$1" "$2"
      vm['cdrom']="$2"
      shift 2
      ;;
    --vmmachine)                    # switch : VM Machine
      check_value "$1" "$2"
      vm['machine']="$2"
      shift 2
      ;;
    --vmmemory)                     # switch : VM Memory
      check_value "$1" "$2"
      vm['memory']="$2"
      shift 2
      ;;
    --vmname)                       # switch : VM Name
      check_value "$1" "$2"
      vm['name']="$2"
      shift 2
      ;;
    --vmnetwork)                    # switch : VM Network
      check_value "$1" "$2"
      vm['network']="$2"
      shift 2
      ;;
    --vmnoautoconsole)              # switch : VM No autoconsole
      vm['noautoconsole']="true"
      shift
      ;;
    --vmnoreboot)                   # switch : VM Do not reboot VM after creation
      vm['noreboot']="true"
      shift
      ;;
    --vmreboot)                     # switch : VM Reboot VM after creation
      vm['noreboot']="false"
      shift
      ;;
    --vmsize)                       # switch : VM Size
      check_value "$1" "$2"
      vm['size']="$2"
      shift 2
      ;;
    --vmosvariant)                  # switch : VM OS variant
      check_value "$1" "$2"
      vm['os-variant']="$2"
      shift 2
      ;;
    --vmvirttype)                   # switch : VM Virtualisation type
      check_value "$1" "$2"
      vm['virt-type']="$2"
      shift 2
      ;;
    --vmvcpus)                      # switch : VM vCPUs
      check_value "$1" "$2"
      vm['vcpus']="$2"
      shift 2
      ;;
    --vmwait)                       # switch : VM number of seconds to wait before starting
      check_value "$1" "$2"
      vm['wait']="$2"
      shift 2
      ;;
    --workdir)                      # switch : Set script work directory
      check_value "$1" "$2"
      options['workdir']="$2"
      shift 2
      ;;
    --zfsinstall)                   # switch : ZFS install script
      check_value "$1" "$2"
      options['zfsinstall']="$2"
      shift 2
      ;;
    --zsh)                          # switch : Enable zsh
      options['zsh']="true"
      shift
      ;;
    *)
      print_help
      shift
      exit
      ;;
  esac
done

# Process options

if [ -n "${options_list[*]}" ]; then
  for list in "${options_list[@]}"; do
    if [[ "${list}" =~ "," ]]; then
      IFS="," read -r -a array <<< "${list[*]}"
      for item in "${array[@]}"; do
        process_options "${item}"
      done
    else
      process_options "${list}"
    fi
  done
fi

# Reset defaults based on switches

reset_defaults

# Process actions

if [ -n "${actions_list[*]}" ]; then
  for list in "${actions_list[@]}"; do
    if [[ "${list}" =~ "," ]]; then
      IFS="," read -r -a array <<< "${list[*]}"
      for item in "${array[@]}"; do
        process_actions "${item}"
      done
    else
      process_actions "${list}"
    fi
  done
fi
