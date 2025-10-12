#!env bash

# Name:         manx (Make Automated NixOS)
# Version:      1.6.6
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
  options['audit']="true"                                                           # option : Auditd parameters
  options['auditrules']=""                                                          # option : Auditd parameters
  options['kernelparams']=""                                                        # option : Additional kernel parameters to add to system grub commands
  # ZFS options
  options['zfsoptions']=""                                                          # option : ZFS options
  zfsoptions=(
    "-O mountpoint=none"
    "-O atime=off"
    "-O compression=lz4"
    "-O xattr=sa"
    "-O acltype=posixacl"
    "-o ashift=12"
  )
  options['zfsoptions']="${zfsoptions[@]}"
  options['isosystempackages']=""                                                   # option : ISO system packages
  isosystempackages=(
    "aide"
    "ansible"
    "btop"
    "curl"
    "dmidecode"
    "efibootmgr"
    "ethtool"
    "file"
    "fwupd"
    "git"
    "kernel-hardening-checker"
    "lsb-release"
    "lsof"
    "lshw"
    "lynis"
    "nmap"
    "pciutils"
    "ripgrep"
    "rclone"
    "tmux"
    "usbutils"
    "vim"
    "wget"
  )
  options['isosystempackages']="${isosystempackages[@]}"
  options['isostorepackages']=""                                                    # option : ISO store packages
  isostorepackages=(
    "aide"
    "ansible"
    "btop"
    "curl"
    "dmidecode"
    "efibootmgr"
    "ethtool"
    "file"
    "fwupd"
    "git"
    "kernel-hardening-checker"
    "lsb-release"
    "lsof"
    "lshw"
    "lynis"
    "nmap"
    "pciutils"
    "ripgrep"
    "rclone"
    "tmux"
    "usbutils"
    "vim"
    "wget"
  )
  options['isostorepackages']="${isostorepackages[@]}"
  options['systempackages']=""                                                      # option : System packages
  systempackages=(
    "aide"
    "ansible"
    "btop"
    "curl"
    "dmidecode"
    "efibootmgr"
    "ethtool"
    "file"
    "fwupd"
    "git"
    "kernel-hardening-checker"
    "lsb-release"
    "lsof"
    "lshw"
    "lynis"
    "nmap"
    "pciutils"
    "ripgrep"
    "rclone"
    "tmux"
    "usbutils"
    "vim"
    "wget"
  )
  options['systempackages']="${systempackages[@]}"
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
  options['blacklist']="${blacklist[@]}"
  # Available kernel modules
  options['availmods']=""                                                           # option : Available kernel modules
  availmods=(
    "ahci"
    "ehci_pci"
    "megaraid_sas"
    "sdhci_pci"
    "sd_mod"
    "sr_mod"
    "usbhid"
    "usb_storage"
    "virtio_blk"
    "virtio_pci"
    "xhci_pci"
  )
  options['availmods']="${availmods[@]}"
  # Serial parameters
  options['serialspeed']="115200"                                                   # option : Serial speed
  options['serialunit']="0"                                                         # option : Serial unit
  options['serialword']="8"                                                         # option : Serial word
  options['serialparity']="no"                                                      # option : Serial parity
  options['serialstop']="1"                                                         # option : Serial stop
  options['serialport']="0x02f8"                                                    # option : Serial port
  options['serialtty']="ttyS0"                                                      # option : Serial TTY
  # Kernel parameters
  options['isokernelparams']=""                                                     # option : Additional kernel parameters to add to ISO grub commands
  options['kernelparams']=""                                                        # option : Additional kernel parameters to add to system grub commands
  options['serialkernelparams']=""                                                  # option : Serial kernel params
  options['serialextraconfig']=""                                                   # option : Serial extra args
  # Imports
  options['isoimports']=""                                                          # option : ISO imports
  isoimports=(
    "<nixpkgs/nixos/modules/installer/cd-dvd/installation-cd-minimal-combined.nix>"
    "<nixpkgs/nixos/modules/installer/cd-dvd/channel.nix>"
    "<nixpkgs/nixos/modules/system/boot/loader/grub/grub.nix>"
    "<nixpkgs/nixos/modules/system/boot/kernel.nix>"
  )
  options['isoimports']="${isoimports[@]}"
  options['imports']=""                                                             # option : System imports
  imports=(
    "<nixpkgs/nixos/modules/system/boot/loader/grub/grub.nix>"
    "<nixpkgs/nixos/modules/system/boot/kernel.nix>"
  )
  options['imports']="${imports[@]}"
  # SSH Kex Algorithms
  options['kexalgorithms']=""                                                       # option : SSH Key Exchange Algorithms
  kexalgorithms=(
    "curve25519-sha256@libssh.org"
    "ecdh-sha2-nistp521"
    "ecdh-sha2-nistp384"
    "ecdh-sha2-nistp256"
    "diffie-hellman-group-exchange-sha256"
  )
  options['kexalgorithms']="${kexalgorithms[@]}"
  # SSH ciphers
  options['ciphers']=""                                                             # option : SSH Ciphers
  ciphers=(
    "chacha20-poly1305@openssh.com"
    "aes256-gcm@openssh.com"
    "aes128-gcm@openssh.com"
    "aes256-ctr"
    "aes192-ctr"
    "aes128-ctr"
  )
  options['ciphers']="${ciphers[@]}"
  # SSH Macs
  options['macs']=""                                                                # option : SSH Macs
  macs=(
    "hmac-sha2-512-etm@openssh.com"
    "hmac-sha2-256-etm@openssh.com"
    "umac-128-etm@openssh.com"
    "hmac-sha2-512"
    "hmac-sha2-256"
    "umac-128@openssh.com"
  )
  options['macs']="${macs[@]}"
  # fail2pan ignore IPs
  options['ignoreip']=""                                                            # option : fail2ban ignore ip
  ignoreip=(
    "172.16.0.0/12"
    "192.168.0.0/16"
  )
  options['ignoreip']="${ignoreip[@]}"
  # Journald extra config
  options['journaldextraconfig']=""                                                 # option : Journald extra config
  journaldextraconfig=(
    "SystemMaxUse=500M"
    "SystemMaxFileSize=50M"
  )
  options['journaldextraconfig']="${journaldextraconfig[@]}"
  options['journaldupload']="false"                                                 # option : Journald remote log upload
  # Options
  options['fwupd']="true"                                                           # option : Enable fwupd
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
  options['username']="nixos"                                                       # option : Username
  options['installuser']="nixos"                                                    # option : Install username
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
  options['rootsize']="100%FREE"                                                    # option : Root partition size
  options['rootpool']="rpool"                                                       # option : Root pool name
  options['rootpassword']="nixos"                                                   # option : Root password
  options['rootcrypt']=""                                                           # option : Root password crypt
  options['username']="nixos"                                                       # option : User Username
  options['usergecos']="Admin"                                                      # option : User GECOS
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
  options['isogrubextraconfig']=""                                                  # option : Additional kernel config to add to ISO grub commands
  options['grubextraconfig']=""                                                     # option : Additional kernel config to add to system grub commands
  options['initmods']=''                                                            # option : Available system init modules
  options['bootmods']=''                                                            # option : Available system boot modules
  options['oneshot']="true"                                                         # option : Enable oneshot service
  options['serial']="true"                                                          # option : Enable serial
  options['kernel']=""                                                              # option : Kernel
  options['passwordauthentication']="false"                                         # option : SSH Password Authentication
  options['permitemptypasswords']="false"                                           # option : SSH permit empty passwords
  options['permittunnel']="false"                                                   # option : SSH permit tunnel
  options['usedns']="false"                                                         # option : SSH use DNS
  options['kbdinteractive']="false"                                                 # option : SSH allow interactive kerboard authentication
  options['x11forwarding']="false"                                                  # option : SSH allow X11 forwarding
  options['maxauthtries']="3"                                                       # option : SSH max auth tries
  options['maxsessions']="2"                                                        # option : SSH max sessions
  options['clientaliveinterval']="300"                                              # option : SSH client alive interval
  options['clientalivecountmax']="0"                                                # option : SSH client alive max count
  options['firewall']="true"                                                        # option : Enable firewall
  options['allowedtcpports']="22"                                                   # option : Allowed TCP ports
  options['allowedudpports']=""                                                     # option : Allowed UDP ports
  options['allowusers']="${options['username']}"                                    # option : SSH allow user
  options['allowtcpforwarding']="false"                                             # option : SSH allow TCP forwarding
  options['allowagentforwarding']="false"                                           # option : SSH allow agent forwarding
  options['permitrootlogin']="no"                                                   # option : SSH permit root login
  options['isopermitrootlogin']="no"                                                # option : SSH permit root login for install
  options['loglevel']="VERBOSE"                                                     # option : SSH log level
  options['hostkeystype']="ed25519"                                                 # option : SSH hosts keys type
  options['hostkeyspath']="/etc/ssh/ssh_host_${options['hostkeystype']}_key"        # option : SSH hosts key type
  options['import']=""                                                              # option : Import Nix config to add to system build
  options['isoimport']=""                                                           # option : Import Nix config to add to ISO build
  options['dockerarch']=$( uname -m |sed 's/x86_/amd/g' )                           # option : Docker architecture
  options['targetarch']=$( uname -m )                                               # option : Target architecture
  options['createdockeriso']="false"                                                # option : Create ISO using docker
  options['console']="false"                                                        # option : Enable console in actions
  options['suffix']=""                                                              # option : Output file suffix
  options['fail2ban']="true"                                                        # option : Enable fail2ban
  options['maxretry']="5"                                                           # option : fail2ban max retry
  options['bantime']="1h"                                                           # option : fail2ban ban time
  options['bantimeincrement']="true"                                                # option : fail2ban ban time increment
  options['multipliers']="1 2 4 8 16 32 64 128 256"                                 # option : fail2ban ban time multipliers
  options['maxtime']="1h"                                                           # option : fail2ban max time
  options['overalljails']="true"                                                    # option : Enable fail2ban overalljails
  options['protectkernelimage']="true"                                              # option : Protect kernel image
  options['lockkernelmodules']="false"                                              # option : Lock kernel modules
  options['allowusernamespaces']="true"                                             # option : Allow user name spaces
  options['forcepagetableisolation']="true"                                         # option : Force page table isolation
  options['unprivilegedusernsclone']="config.virtualisation.containers.enable"      # option : Disable unprivileged user namespaces
  options['allowsmt']="true"                                                        # option : Allow SMT
  options['dbusimplementation']="broker"                                            # option : Dbus implementation
  options['execwheelonly']="true"                                                   # option : Sudo exec wheel only
  options['systemdumask']="0077"                                                    # option : systemd umask
  options['privatenetwork']="true"                                                  # option : systemd private network
  options['protecthostname']="true"                                                 # option : systemd protect hostname
  options['protectkernelmodules']="true"                                            # option : systemd protect kernel modules
  options['protectsystem']="strict"                                                 # option : systemd protect system
  options['protecthome']="true"                                                     # option : systemd protect home
  options['protectkerneltunables']="true"                                           # option : systemd protect kernel tunables
  options['protectcontrolgroups']="true"                                            # option : systemd protect control groups
  options['protectclock']="true"                                                    # option : systemd protect clock
  options['protectproc']="invisible"                                                # option : systemd protect proc
  options['procsubset']="pid"                                                       # option : systemd protect kernel modules
  options['privatetmp']="true"                                                      # option : systemd private tmp
  options['memorydenywriteexecute']="true"                                          # option : systemd deny write execute
  options['nownewprivileges']="true"                                                # option : systemd no new privileges
  options['lockpersonality']="true"                                                 # option : systemd lock personality
  options['restrictrealtime']="true"                                                # option : systemd restrict realtime
  options['systemcallarchitectures']="native"                                       # option : systemd system call architectures
  options['ipaddressdeny']="any"                                                    # option : systemd IP address deny
  options['usepreservediso']="false"                                                # option : Use preserved ISO
  options['processgrub']="true"                                                     # option : Process grub command line
  options['logrotate']="true"                                                       # option : Log rotate
  options['unstable']="false"                                                       # option : Enable unstable features/packages
  options['interactive']="false"                                                    # option : Interactive mode
  options['interactiveinstall']="false"                                             # option : Interactive install mode

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
  if [ "${options['unstable']}" = "true" ]; then
    options['isostorepackages']="${options['isostorepackages']} zfs_unstable"
    options['isossystempackages']="${options['isosystempackages']} zfs_unstable"
    options['systempackages']="${options['systempackages']} zfs_unstable"
  fi
  serial_console="console=${options['serialtty']},${options['serialspeed']}${options['serialparity']}${options['serialword']}"
  serialkernelparams=(
    "console=tty1"
    "${serial_console}"
  )
  for item in "${serialkernelparams[@]}"; do
    options['isoserialkernelparams']+=" \"${item}\" "
  done
  for item in "${serialkernelparams[@]}"; do
    options['serialkernelparams']+=" ${item} "
  done
  serial_params="serial"
  for param in speed unit word parity stop port; do
    item="serial${param}"
    value="${options[${item}]}"
    if ! [ "${value}" = "" ]; then
      serial_params="${serial_params} --${param}=${value}"
    fi
  done
  serialextraconfig=(
    "${serial_params}"
    "terminal_input serial"
    "terminal_output serial"
  )
  for item in "${serialextraconfig[@]}"; do
    if [ "${options['serialextraconfig']}" = "" ]; then
      options['serialextraconfig']=" ${item} "
    else
      options['serialextraconfig']+=" ${item} "
    fi
  done
  if [ "${options['attended']}" = "true" ]; then
    options['unattended']="false"
  fi
  if [ "${options['unattended']}" = "true" ]; then
    options['attended']="false"
  fi
  if [ "${options['reboot']}" = "true" ]; then
    options['poweroff']="false"
  fi
  if [ "${options['poweroff']}" = "true" ]; then
    options['reboot']="false"
  fi
  if ! [ "${options['allowusers']}" = "${options['username']}" ]; then
    options['allowusers']="${options['username']}"
  fi
  # System sysctl parameters - Security related
  if [ "${options['audit']}" = "true" ]; then
    IFS='' read -r -d '' options['auditrules'] << SYSCTL
      "-a exit,always -F arch=b64 -S execve"
      "-a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime,stime -k time-change"
      "-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change"
      "-w /etc/localtime -p wa -k time-change"
      "-w /etc/group -p wa -k identity"
      "-w /etc/passwd -p wa -k identity"
      "-w /etc/gshadow -p wa -k identity"
      "-w /etc/shadow -p wa -k identity"
      "-a exit,always -F arch=b32 -S sethostname,setdomainname -k system-locale"
      "-a exit,always -F arch=b64 -S sethostname,setdomainname -k system-locale"
      "-w /etc/issue -p wa -k system-locale"
      "-w /etc/issue.net -p wa -k system-locale"
      "-w /etc/hosts -p wa -k system-locale"
      "-w /etc/apparmor/ -p wa -k MAC-policy"
      "-w /etc/apparmor.d/ -p wa -k MAC-policy"
      "-w /var/log/faillog -p wa -k logins"
      "-w /var/log/lastlog -p wa -k logins"
      "-w /var/run/faillock -p wa -k logins"
      "-w /var/run/utmp -p wa -k session"
      "-w /var/log/btmp -p wa -k session"
      "-w /var/log/wtmp -p wa -k session"
      "-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng"
      "-a always,exit -F arch=b32 -C euid!=uid -F auid!=unset -S execve -k user_emulation"
      "-a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve -k user_emulation"
      "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod"
      "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod"
      "-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod"
      "-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod"
      "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access"
      "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access"
      "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access"
      "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access"
      "-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=unset -k priv_cmd"
      "-a always,exit -F arch=b32 -S mount -F auid>=500 -F auid!=4294967295 -k export"
      "-a always,exit -F arch=b64 -S mount -F auid>=500 -F auid!=4294967295 -k export"
      "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete"
      "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete"
      "-w /etc/sudoers -p wa -k scope"
      "-w /etc/sudoers.d -p wa -k scope"
      "-w /etc/sudoers -p wa -k actions"
      "-w /var/log/sudo.log -p wa -k sudo_log_file"
      "-w /run/current-system/sw/bin/insmod -p x -k modules"
      "-w /run/current-system/sw/bin/rmmod -p x -k modules"
      "-w /run/current-system/sw/bin/modprobe -p x -k modules"
      "-a always,exit -F arch=b64 -S init_module,finit_module,delete_module,create_module,query_module -F auid>=1000 -F auid!=unset -k kernel_modules"
      "-a always,exit -S init_module -S delete_module -k modules"
      "-a always,exit -F arch=b64 -S mount -F auid>=500 -F auid!=4294967295 -k mounts"
      "-a always,exit -F arch=b32 -S mount -F auid>=500 -F auid!=4294967295 -k mounts"
SYSCTL
    options['auditrules']="${options['auditrules']//\"/\\\"}"
  fi
  if [ "${options['secure']}" = "true" ]; then
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
    options['kernelparams']="${kernelparams[@]}"
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
  if ! [ "${options['rootfs']}" = "zfs" ]; then
    options['zfs']="false"
    if [ "${options['rootfs']}" = "btrfs" ]; then
      options['lvm']="false"
    else
      options['lvm']="true"
    fi
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
    if [ "${options['isogrubextraconfig']}" = "" ]; then
      options['isogrubextraconfig']="${options['serialextraconfig']}"
    else
      options['isogrubextraconfig']="${options['isogrubextraconfig']} ${options['serialextraconfig']}"
    fi
    if [ "${options['grubextraconfig']}" = "" ]; then
      options['grubextraconfig']="${options['serialextraconfig']}"
    else
      options['grubextraconfig']="${options['grubextraconfig']} ${options['serialextraconfig']}"
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
  if ! [ "${options['kernel']}" = "" ]; then
    if ! [[ "${options['kernel']}" =~ ^_ ]]; then
      options['kernel']="_${options['kernel']}"
    fi
    options['kernel']="${options['kernel']//\./_}"
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
      if ! [[ "${line}" =~ grep ]]; then
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
  if [[ "${option}" =~ ^no|^un|^dont ]]; then
    options["${option}"]="true"
    if [[ "${option}" =~ ^dont ]]; then
      option="${option:4}"
    else
      option="${option:2}"
    fi
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
  if [ "${os['name']}" = "Linux" ]; then
    nix_test=$( command -v nix )
    if [ "${nix_test}" = "" ]; then
      sh <(curl --proto '=https' --tlsv1.2 -L https://nixos.org/nix/install) --no-daemon
    fi
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
      key_file=$( find "$HOME"/.ssh -name "*.pub" | head -1 )
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
    rootpassword userpassword stateversion hostname unfree gfxmode gfxpayload \
    passwordauthentication allowedtcpports allowedudpports targetarch sshkey \
    permitemptypasswords permittunnel usedns kbdinteractive nic \
    dns ip gateway cidr zfsoptions systempackages firewall imports hwimports\
    allowusers permitrootlogin interactiveinstall; do
#    x11forwarding maxauthtries maxsessions clientaliveinterval allowusers \
#    clientalivecountmax allowtcpforwarding allowagentforwarding loglevel \
#    permitrootlogin hostkeyspath hostkeystype kexalgorithms ciphers macs \
#    fail2ban maxretry bantime ignoreip bantimeincrement multipliers maxtime \
#    lockkernelmodules forcepagetableisolation allowusernamespaces processgrub \
#    unprivilegedusernsclone dbusimplementation execwheelonly systemdumask \
#    privatenetwork protecthostname protectkernelmodules protectsystem \
#    protecthome protectkerneltunables protectcontrolgroups protectclock \
#    protectproc procsubset privatetmp memorydenywriteexecute nownewprivileges \
#    lockpersonality restrictrealtime systemcallarchitectures ipaddressden \
#    overalljails protectkernelimage allowsmt fwupd\
    item=""
    value="${options[${param}]}"
    if ! [ "${value}" = ""  ]; then
      if [[ "${value}" =~ " " ]]; then
        item="\"ai.${param}=\\\"${value}\\\"\""
      else
        item="\"ai.${param}=${value}\""
      fi
    else
      item="\"ai.${param}=\""
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
  spacer=$'\n'
  tee "${options['nixisoconfig']}" << NIXISOCONFIG
# ISO build config
{ config, pkgs, lib, ... }:
{
  imports = [
    ${options['isoimports']// /${spacer}    }
  ];

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
      ${options['isostorepackages']// /${spacer}      }
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
        ${options['isogrubextraconfig']//  /${spacer}         }
      ";
    };
  };
  boot.kernelParams = [ ${options['isokernelparams']// \"/${spacer}    \"}
  ];
NIXISOCONFIG
  if ! [ "${options['kernel']}" = "" ]; then
    tee -a "${options['nixisoconfig']}" << NIXISOCONFIG
  boot.kernelPackages = lib.mkDefault pkgs.linuxPackages${options['kernel']};
NIXISOCONFIG
  fi
  tee -a "${options['nixisoconfig']}" << NIXISOCONFIG

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

  # Fwupd service
  services.fwupd.enable = ${options['fwupd']};

  # OpenSSH
  services.openssh.enable = ${options['sshserver']};
  services.openssh.settings.PasswordAuthentication = ${options['passwordauthentication']};
  services.openssh.settings.PermitEmptyPasswords = ${options['permitemptypasswords']};
  services.openssh.settings.KbdInteractiveAuthentication = ${options['kbdinteractive']};
  services.openssh.settings.PermitTunnel = ${options['permittunnel']};
  services.openssh.settings.UseDns = ${options['usedns']};
  services.openssh.settings.X11Forwarding = ${options['x11forwarding']};
  services.openssh.settings.MaxAuthTries = ${options['maxauthtries']};
  services.openssh.settings.MaxSessions = ${options['maxsessions']};
  services.openssh.settings.AllowUsers = [ "${options['installuser']}" ];
  services.openssh.settings.LogLevel = "${options['loglevel']}";
  services.openssh.settings.PermitRootLogin = "${options['isopermitrootlogin']}";
  services.openssh.settings.AllowTcpForwarding = ${options['allowtcpforwarding']};
  services.openssh.settings.AllowAgentForwarding = ${options['allowagentforwarding']};
  services.openssh.settings.ClientAliveInterval = ${options['clientaliveinterval']};
  services.openssh.settings.ClientAliveCountMax = ${options['clientalivecountmax']};
  services.openssh.settings.KexAlgorithms = [
NIXISOCONFIG
  for item in ${options['kexalgorithms']}; do
    tee -a "${options['nixisoconfig']}" << NIXISOCONFIG
    "${item}"
NIXISOCONFIG
  done
  tee -a "${options['nixisoconfig']}" << NIXISOCONFIG
  ];
  services.openssh.settings.Ciphers = [
NIXISOCONFIG
  for item in ${options['ciphers']}; do
    tee -a "${options['nixisoconfig']}" << NIXISOCONFIG
    "${item}"
NIXISOCONFIG
  done
  tee -a "${options['nixisoconfig']}" << NIXISOCONFIG
  ];
  services.openssh.settings.Macs = [
NIXISOCONFIG
  for item in ${options['macs']}; do
    tee -a "${options['nixisoconfig']}" << NIXISOCONFIG
    "${item}"
NIXISOCONFIG
  done
  tee -a "${options['nixisoconfig']}" << NIXISOCONFIG
  ];

  # Networking
NIXISOCONFIG
  if ! [ "${options['nic']}" = "first" ]; then
    tee -a "${options['nixisoconfig']}" << NIXISOCONFIG
  networking.useDHCP = lib.mkDefault ${options['dhcp']};
NIXISOCONFIG
  else
    tee -a "${options['nixisoconfig']}" << NIXISOCONFIG
  networking.useDHCP = lib.mkDefault true;
NIXISOCONFIG
  fi
  if [ "${options['dhcp']}" = "false" ] && ! [ "${options['nic']}" = "first" ]; then
    if [ "${options['bridge']}" = "false" ]; then
      tee -a "${options['nixisoconfig']}" << NIXISOCONFIG
  networking = {
    interfaces."${options['nic']}".useDHCP = ${options['dhcp']};
    interfaces."${options['nic']}".ipv4.addresses = [{
      address = "${options['ip']}";
      prefixLength = ${options['cidr']};
    }];
    defaultGateway = "${options['gateway']}";
    nameservers = [ "${options['dns']}" ];
  };
NIXISOCONFIG
    else
      tee -a "${options['nixisoconfig']}" << NIXISOCONFIG
  networking = {
    bridges."${options['bridgenic']}".interfaces = [ "${options['nic']}" ];
    interfaces."${options['bridgenic']}".useDHCP = ${options['dhcp']};
    interfaces."${options['nic']}".useDHCP = ${options['dhcp']};
    interfaces."${options['bridgenic']}".ipv4.addresses = [{
      address = "${options['ip']}";
      prefixLength = ${options['cidr']};
    }];
    defaultGateway = "${options['gateway']}";
    nameservers = [ "${options['dns']}" ];
  };

NIXISOCONFIG
    fi
  fi
  if ! [ "${options['installuser']}" = "nixos" ]; then
    tee -a "${options['nixisoconfig']}" << NIXISOCONFIG
    # Define a user account.
  users.users.${options['username']} = {
    shell = pkgs.${options['usershell']};
    isNormalUser = ${options['normaluser']};
    description = "${options['usergecos']}";
    extraGroups = [ "${options['extragroups']}" ];
    openssh.authorizedKeys.keys = [ "${options['sshkey']}" ];
    hashedPassword = "${options['usercrypt']}";
  };
  programs.zsh.enable = ${options['zsh']};
  system.userActivationScripts.zshrc = "touch .zshrc";

  # Sudo configuration
  security.sudo.extraRules= [
    { users = [ "${options['username']}" ];
      commands = [
        { command = "${options['sudocommand']}" ;
          options= [ "${options['sudooptions']}" ];
        }
      ];
    }
  ];

NIXISOCONFIG
  fi
  tee -a "${options['nixisoconfig']}" << NIXISOCONFIG
  # Systemd
  systemd.services.systemd-journald = {
    serviceConfig = {
      UMask = ${options['systemdumask']};
      PrivateNetwork = ${options['privatenetwork']};
      ProtectHostname = ${options['protecthostname']};
      ProtectKernelModules = ${options['protectkernelmodules']};
    };
  }; 
  systemd.services.systemd-rfkill = {
    serviceConfig = {
      ProtectSystem = "${options['protectsystem']}";
      ProtectHome = ${options['protecthome']};
      ProtectKernelTunables = ${options['protectkerneltunables']};
      ProtectKernelModules = ${options['protectkernelmodules']};
      ProtectControlGroups = ${options['protectcontrolgroups']};
      ProtectClock = ${options['protectclock']};
      ProtectProc = "${options['protectproc']}";
      ProcSubset = "${options['procsubset']}";
      PrivateTmp = ${options['privatetmp']};
      MemoryDenyWriteExecute = ${options['memorydenywriteexecute']};
      NoNewPrivileges = ${options['nownewprivileges']};
      LockPersonality = ${options['lockpersonality']};
      RestrictRealtime = ${options['restrictrealtime']};
      SystemCallArchitectures = "${options['systemcallarchitectures']}";
      UMask = "${options['systemdumask']}";
      IPAddressDeny = "${options['ipaddressdeny']}";
    };
  };

  # Enable SSH in the boot process.
  systemd.services.sshd.wantedBy = pkgs.lib.mkForce [ "multi-user.target" ];
  users.users.root.openssh.authorizedKeys.keys = [ "${options['sshkey']}" ];
  users.users.nixos.openssh.authorizedKeys.keys = [ "${options['sshkey']}" ];

  # Based packages to include in ISO
  environment.systemPackages = with pkgs; [
    ${options['isosystempackages']// /${spacer}    }
  ];

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

ai['swap']="${options['swap']}"                                           # ai : Use swap
ai['lvm']="${options['lvm']}"                                             # ai : Use LVM
ai['zsh']="${options['zsh']}"                                             # ai : Use zsh
ai['dhcp']="${options['dhcp']}"                                           # ai : Use DHCP
ai['bridge']="${options['bridge']}"                                       # ai : Use Bridge
ai['sshserver']="${options['sshserver']}"                                 # ai : Enable SSH server
ai['bridgenic']="${options['bridgenic']}"                                 # ai : Bridge Network Interface
ai['reboot']="${options['reboot']}"                                       # ai : Reboot after install
ai['poweroff']="${options['poweroff']}"                                   # ai : Power off after install
ai['attended']="${options['attended']}"                                   # ai : Attended install
ai['nixinstall']="${options['nixinstall']}"                               # ai : Run NixOS install
ai['rootfs']="${options['rootfs']}"                                       # ai : Root filesystem
ai['bootfs']="${options['bootfs']}"                                       # ai : Boot filesystem
ai['rootdisk']="${options['rootdisk']}"                                   # ai : Root disk
ai['mbrpart']="${options['mbrpart']}"                                     # ai : MBR partition
ai['rootpart']="${options['rootpart']}"                                   # ai : Root partition
ai['efipart']="${options['efipart']}"                                     # ai : UEFI partition
ai['bootpart']="${options['efipart']}"                                    # ai : Boot partition
ai['swappart']="${options['swappart']}"                                   # ai : Swap partition
ai['swapsize']="${options['swapsize']}"                                   # ai : Swap size
ai['rootsize']="${options['rootsize']}"                                   # ai : Root size
ai['bootsize']="${options['bootsize']}"                                   # ai : Boot size
ai['rootpool']="${options['rootpool']}"                                   # ai : Root pool
ai['swapvolname']="${options['swapvolname']}"                             # ai : Swap volume name
ai['bootvolname']="${options['bootvolname']}"                             # ai : Boot volume name
ai['rootvolname']="${options['rootvolname']}"                             # ai : Root volume name
ai['installdir']="${options['installdir']}"                               # ai : Install directory
ai['mbrpartname']="${options['mbrpartname']}"                             # ai : MBR partition name
ai['locale']="${options['locale']}"                                       # ai : Locale
ai['devnodes']="${options['devnodes']}"                                   # ai : Device nodes
ai['logdir']="${options['logdir']}"                                       # ai : Log directory
ai['logfile']="${options['logfile']}"                                     # ai : Log file
ai['timezone']="${options['timezone']}"                                   # ai : Timezone
ai['usershell']="${options['usershell']}"                                 # ai : User shell
ai['username']="${options['username']}"                                   # ai : Username
ai['extragroups']="${options['extragroups']}"                             # ai : User extra groups
ai['usergecos']="${options['usergecos']}"                                 # ai : User GECOS
ai['normaluser']="${options['normaluser']}"                               # ai : Normal user
ai['sudocommand']="${options['sudocommand']}"                             # ai : Sudo command
ai['sudooptions']="${options['sudooptions']}"                             # ai : Sudo options
ai['rootpassword']="${options['rootpassword']}"                           # ai : Root password
ai['rootcrypt']=\$( mkpasswd --method=sha-512 "\${ai['rootpassword']}" )  # ai : Root crypt
ai['userpassword']="${options['userpassword']}"                           # ai : User password
ai['usercrypt']=\$( mkpasswd --method=sha-512 "\${ai['userpassword']}" )  # ai : User crypt
ai['stateversion']="${options['stateversion']}"                           # ai : State version
ai['hostname']="${options['hostname']}"                                   # ai : Hostname
ai['hostid']=\$( head -c 8 /etc/machine-id )                              # ai : HostID
ai['nixdir']="\${ai['installdir']}/etc/nixos"                             # ai : Nix directory
ai['nixcfg']="\${ai['nixdir']}/configuration.nix"                         # ai : Nix configuration
ai['hwcfg']="\${ai['nixdir']}/hardware-configuration.nix"                 # ai : Nix hardware configuration
ai['zfsoptions']="${options['zfsoptions']}"                               # ai : ZFS filesystem options
ai['availmods']="${options['availmods']}"                                 # ai : Available modules
ai['initmods']="${options['initmods']}"                                   # ai : Initrd modules
ai['bootmods']="${options['bootmods']}"                                   # ai : Boot modules
ai['experimental-features']="${options['experimental-features']}"         # ai : Experimental Features
ai['unfree']="${options['unfree']}"                                       # ai : Non free software
ai['gfxmode']="${options['gfxmode']}"                                     # ai : Graphics Mode
ai['gfxpayload']="${options['gfxpayload']}"                               # ai : Graphics Payload
ai['nic']="${options['nic']}"                                             # ai : Network Interface
ai['dns']="${options['dns']}"                                             # ai : DNS Server
ai['ip']="${options['ip']}"                                               # ai : IP Address
ai['gateway']="${options['gateway']}"                                     # ai : Gateway Address
ai['cidr']="${options['cidr']}"                                           # ai : CIDR
ai['sshkey']="${options['sshkey']}"                                       # ai : SSH key
ai['oneshot']="${options['oneshot']}"                                     # ai : Oneshot
ai['kernelparams']="${options['kernelparams']}"                           # ai : Kernel Parameters
ai['grubextraconfig']="${options['grubextraconfig']}"                     # ai : Extra grub configuration
ai['journaldextraconfig']="${options['journaldextraconfig']}"             # ai : Extra journald configuration
ai['journaldupload']="${options['journaldupload']}"                       # ai : Journald upload
ai['imports']="${options['imports']}"                                     # ai : Nix configuration imports
ai['hwimports']="${options['hwimports']}"                                 # ai : Nix hardware configuration imports
ai['kernel']="${options['kernel']}"                                       # ai : Kernel
ai['passwordauthentication']="${options['passwordauthentication']}"       # ai : SSH Password Authentication
ai['permitemptypasswords']="${options['permitemptypasswords']}"           # ai : SSH Permit Empty Password
ai['kbdinteractive']="${options['kbdinteractive']}"                       # ai : SSH Keyboard Interactive Authentication
ai['usedns']="${options['usedns']}"                                       # ai : SSH Use DNS
ai['x11forwarding']="${options['x11forwarding']}"                         # ai : SSH X11 Forwarding
ai['maxauthtries']="${options['maxauthtries']}"                           # ai : SSH Max Authentication Tries
ai['maxsessions']="${options['maxsessions']}"                             # ai : SSH Max Sessions
ai['permittunnel']="${options['permittunnel']}"                           # ai : SSH Permit Tunnel
ai['allowusers']="${options['allowusers']}"                               # ai : SSH Allowed Users
ai['loglevel']="${options['loglevel']}"                                   # ai : SSH Log Level
ai['clientaliveinterval']="${options['clientaliveinterval']}"             # ai : SSH Client Alive Interval
ai['clientalivecountmax']="${options['clientalivecountmax']}"             # ai : SSH Client Alive Max Count
ai['allowtcpforwarding']="${options['allowtcpforwarding']}"               # ai : SSH Allow TCP Forwarding
ai['allowagentforwarding']="${options['allowagentforwarding']}"           # ai : SSH Allow Agent Forwarding
ai['permitrootlogin']="${options['permitrootlogin']}"                     # ai : SSH Permit Root Login
ai['hostkeyspath']="${options['hostkeyspath']}"                           # ai : SSH Host Key Path
ai['hostkeystype']="${options['hostkeystype']}"                           # ai : SSH Host Key Type
ai['kexalgorithms']="${options['kexalgorithms']}"                         # ai : SSH Key Exchange Algorithms
ai['ciphers']="${options['ciphers']}"                                     # ai : SSH Ciphers
ai['macs']="${options['macs']}"                                           # ai : SSH MACs
ai['isomount']="${options['isomount']}"                                   # ai : ISO mount
ai['prefix']="${options['prefix']}"                                       # ai : Prefix
ai['targetarch']="${options['targetarch']}"                               # ai : Target Architecture
ai['systempackages']="${options['systempackages']}"                       # ai : System Packages
ai['blacklist']="${options['blacklist']}"                                 # ai : Blacklist Modules
ai['sysctl']="${options['sysctl']}"                                       # ai : Sysctl
ai['audit']="${options['audit']}"                                         # ai : Audit
ai['auditrules']="${options['auditrules']}"                               # ai : Audit Rules
ai['fail2ban']="${options['fail2ban']}"                                   # ai : Fail2ban
ai['maxretry']="${options['maxretry']}"                                   # ai : Fail2ban Max Retry
ai['bantime']="${options['bantime']}"                                     # ai : Fail2ban Ban Time
ai['ignoreip']="${options['ignoreip']}"                                   # ai : Fail2ban Ignore IP
ai['bantimeincrement']="${options['bantimeincrement']}"                   # ai : Fail2ban Ban Time Increment
ai['multipliers']="${options['multipliers']}"                             # ai : Fail2ban Multipliers
ai['maxtime']="${options['maxtime']}"                                     # ai : Fail2ban Max Time
ai['overalljails']="${options['overalljails']}"                           # ai : Overall Jails
ai['protectkernelimage']="${options['protectkernelimage']}"               # ai : Protect Kernel Image
ai['lockkernelmodules']="${options['lockkernelmodules']}"                 # ai : Lock Kernel Modules
ai['forcepagetableisolation']="${options['forcepagetableisolation']}"     # ai : Force Page Table Isolation
ai['unprivilegedusernsclone']="${options['unprivilegedusernsclone']}"     # ai : Unprivileged User NS Clone
ai['allowsmt']="${options['allowsmt']}"                                   # ai : Allow SMT
ai['execwheelonly']="${options['execwheelonly']}"                         # ai : Exec Wheel Only
ai['dbusimplementation']="${options['dbusimplementation']}"               # ai : DBus Implementation
ai['allowusernamespaces']="${options['allowusernamespaces']}"             # ai : Allow User Namespaces
ai['systemdumask']="${options['systemdumask']}"                           # ai : Systemd umask
ai['privatenetwork']="${options['privatenetwork']}"                       # ai : Protect Network
ai['protecthostname']="${options['protecthostname']}"                     # ai : Protect Hostname
ai['protectkernelmodules']="${options['protectkernelmodules']}"           # ai : Protect Kernel Modules
ai['protectsystem']="${options['protectsystem']}"                         # ai : Protect System
ai['protecthome']="${options['protecthome']}"                             # ai : Protect Home
ai['protectkerneltunables']="${options['protectkerneltunables']}"         # ai : Protect Kernel Tunables
ai['protectkernelmodules']="${options['protectkernelmodules']}"           # ai : Protect Kernel Modules
ai['protectcontrolgroups']="${options['protectcontrolgroups']}"           # ai : Protect Control Groups
ai['protectclock']="${options['protectclock']}"                           # ai : Protect Clock
ai['protectproc']="${options['protectproc']}"                             # ai : Protect Proccesses
ai['procsubset']="${options['procsubset']}"                               # ai : Process Subset
ai['privatetmp']="${options['privatetmp']}"                               # ai : Private Temp
ai['memorydenywriteexecute']="${options['memorydenywriteexecute']}"       # ai : Memory Deny Write Execute
ai['nownewprivileges']="${options['nownewprivileges']}"                   # ai : Now New Privileges
ai['lockpersonality']="${options['lockpersonality']}"                     # ai : Lock Personality
ai['restrictrealtime']="${options['restrictrealtime']}"                   # ai : Restrict Real Time
ai['systemcallarchitectures']="${options['systemcallarchitectures']}"     # ai : System Call Architectures
ai['ipaddressdeny']="${options['ipaddressdeny']}"                         # ai : IP Address Deny
ai['firewall']="${options['firewall']}"                                   # ai : Firewall
ai['allowedtcpports']="${options['allowedtcpports']}"                     # ai : Allowed TCP Ports
ai['allowedudpports']="${options['allowedudpports']}"                     # ai : Allowed UDP Ports
ai['fwupd']="${options['fwupd']}"                                         # ai : Firmware Update Service
ai['logrotate']="${options['logrotate']}"                                 # ai : Log rotate
ai['processgrub']="${options['processgrub']}"                             # ai : Process grub
ai['interactiveinstall']="${options['interactiveinstall']}"               # ai : Interactive Install
ai['scriptfile']="\$0"

spacer=\$'\n'

# If oneshot is disabled exit

if [ "\${ai['oneshot']}" = "false" ]; then
  exit
fi

# Check we are using only one volume manager

if [ "\${ai['lvm']}" = "true" ] && [ "\${ai['rootfs']}" = "zfs" ]; then
  echo "Cannot use two volume managers (LVM and ZFS)"
  exit
fi

# Parse parameters

parse_parameters () {
  echo "Processing parameters"
  for param in \${!ai[@]}
  do
    echo "Setting \${param} to \${ai[\${param}]}"
  done
}

# Parse grub parameters

parse_grub_parameters () {
  if [ "\${ai['processgrub']}" = "true" ]; then
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
  fi
}

# Set ZFS options

set_zfs_options () {
  ai['zfsoptions']="\${ai['zfsoptions']} -R \${ai['installdir']}"
  echo "Setting zfsoptions to \${ai['zfsoptions']}"
}

# Set up networking

setup_networking () {
  if [ "\${ai['dhcp']}" = "false" ]; then
    if [ "\${ai['nic']}" = "first" ]; then
      counter=1
      ai['nic']=\$( ip link | grep "state UP" | awk '{ print \$2}' | head -1 | grep ^e | cut -f1 -d: )
      while [ "\${ai['nic']}" = "" ]; do
        echo "Waiting for network link to come up (count=\${counter})"
        sleep 5s
        ai['nic']=\$( ip link | grep "state UP" | awk '{ print \$2}' | head -1 | grep ^e | cut -f1 -d: )
        counter=\$(( counter + 1 ))
        if [ "\${counter}" = "10" ]; then
          echo "Could not find network with link up"
          ai['nic']=\$( ip link | awk '{ print \$2}' | head -1 | grep ^e | cut -f1 -d: )
        fi
      done
      echo "Setting nic to \${ai['nic']}"
    fi
  fi
}

# Discover first disk

discover_first_disk () {
  if [ "\${ai['rootdisk']}" = "first" ]; then
    ai['rootdisk']=\$( lsblk -l -o TYPE,NAME,TRAN | grep disk | grep -v usb | sort | head -1 | awk '{print \$2}' )
    ai['rootdisk']="/dev/\${ai['rootdisk']}"
    echo "Setting rootdisk to \${ai['rootdisk']}"
  fi
}


# Update partitions for NVMe devices

setup_nvme_partitions () {
  if [[ \${ai['rootdisk']} =~ nvme ]]; then
    ai['efipart']="1"
    ai['bootpart']="1"
    ai['swappart']="2"
    ai['rootpart']="3"
    ai['rootpart']="p\${ai['rootpart']}"
    ai['efipart']="p\${ai['efipart']}"
    ai['bootpart']="p\${ai['efipart']}"
    ai['swappart']="p\${ai['swappart']}"
    ai['devnodes']="/dev/disk/by-id"
  fi
}

# Boot modules

setup_boot_modules () {
  if [ "\${ai['bootmods']}" = "" ]; then
    ai['bootmods']="kvm-intel"
  else
    ai['bootmods']="\${ai['bootmods']} kvm-intel"
  fi
  echo "Setting bootmods to \${ai['bootmods']}"
}

# QEMU check

setup_hwimports () {
  qemu_check=\$( cat /proc/ioports | grep QEMU )
  if [ -n "\${qemu_check}" ]; then
    if [ "\${ai['hwimports']}" = "" ]; then
      ai['hwimports']="(modulesPath + \"/profiles/qemu-guest.nix\")"
    else
      ai['hwimports']="\${ai['hwimports']} (modulesPath + \"/profiles/qemu-guest.nix\")"
    fi
    echo "Setting hwimports to \${ai['hwimports']}"
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
    ai['grubdev']="\${ai['rootdisk']}"
    ai['bootvolname']="biosboot"
  fi
  echo "Setting biosflag to \${ai['biosflag']}"
  echo "Setting uefiflag to \${ai['uefiflag']}"
  echo "Setting grubdev to \${ai['grubdev']}"
  echo "Setting biosvolname to \${ai['biosvolname']}"
}

# Set root partition type

setup_root_partition_type () {
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
}

# Wipe and set up disk

wipe_root_disk () {
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
}

# Partition root disk

partition_root_disk () {
  echo "Partitioning \${ai['rootdisk']}"
  if [ "\${ai['biosflag']}" = "true" ]; then
    sgdisk -a \${ai['mbrpart']} -n \${ai['mbrpart']}:0:+1M -t \${ai['mbrpart']}:EF02 -c \${ai['mbrpart']}:\${ai['mbrvolname']} \${ai['rootdisk']}
  fi
  if [ "\${ai['lvm']}" = "true" ]; then
    sgdisk -n \${ai['rootpart']}:0:0 -t \${ai['rootpart']}:\${ai['partflag']} -c \${ai['rootpart']}:\${ai['rootvolname']} \${ai['rootdisk']}
    pvcreate -ff \${ai['rootdisk']}\${ai['rootpart']}
    vgcreate -f \${ai['rootpool']} \${ai['rootdisk']}\${ai['rootpart']}
    lvcreate -y --size \${ai['bootsize']} --name \${ai['bootvolname']} \${ai['rootpool']}
    if [ "\${USE_SWAP}" = "true" ]; then
      lvcreate -y --size \${ai['swapsize']} --name \${ai['swapvolname']} \${ai['rootpool']}
    fi
    lvcreate -y -l \${ai['rootsize']} --name \${ai['rootvolname']} \${ai['rootpool']}
    ai['swapvol']="/dev/\${ai['rootpool']}/\${ai['swapvolname']}"
    ai['bootvol']="/dev/\${ai['rootpool']}/\${ai['bootvolname']}"
    ai['rootvol']="/dev/\${ai['rootpool']}/\${ai['rootvolname']}"
    if [ "\${ai[initmods]}" = "" ]; then
      ai['initmods']="\"dm-snapshot\" \"dm-raid\" \"dm-cache-default\""
    else
      ai['initmods']="\${ai['initmods']} \"dm-snapshot\" \"dm-raid\" \"dm-cache-default\""
    fi
    ai['rootsearch']=\$( ls -l \${ai['rootvol']} | awk '{print \$11}' | cut -f2 -d/ )
    ai['bootsearch']=\$( ls -l \${ai['bootvol']} | awk '{print \$11}' | cut -f2 -d/ )
    ai['swapsearch']=\$( ls -l \${ai['swapvol']} | awk '{print \$11}' | cut -f2 -d/ )
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
}

# Make and mount filesystems

make_and_mount_filesystems () {
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
  echo "Creating log directory \${ai['installdir']}\${ai['logdir']}"
  mkdir -p \${ai['installdir']}/\${ai['logdir']}
}

# Create configuration.nix

create_nix_configuration () {
  echo "Creating \${ai['nixcfg']}"
  tee \${ai['nixcfg']} << NIX_CFG
{ config, lib, pkgs, ... }:
{
  imports = [
    \${ai['imports']// /\${spacer}    }
    ./hardware-configuration.nix
  ];
  boot.loader.systemd-boot.enable = \${ai['uefiflag']};
  boot.loader.efi.canTouchEfiVariables = \${ai['uefiflag']};
  boot.loader.grub.devices = [ "\${ai['grubdev']}" ];
  boot.loader.grub.gfxmodeEfi = "\${ai['gfxmode']}";
  boot.loader.grub.gfxpayloadEfi = "\${ai['gfxpayload']}";
  boot.loader.grub.gfxmodeBios = "\${ai['gfxmode']}";
  boot.loader.grub.gfxpayloadBios = "\${ai['gfxpayload']}";
  boot.initrd.supportedFilesystems = ["\${ai['rootfs']}"];
  boot.supportedFilesystems = [ "\${ai['rootfs']}" ];
  boot.zfs.devNodes = "\${ai['devnodes']}";
  services.lvm.boot.thin.enable = \${ai['lvm']};
NIX_CFG
  if ! [ "\${ai['kernel']}" = "" ]; then
    tee -a \${ai['nixcfg']} << NIX_CFG
  boot.kernelPackages = lib.mkDefault pkgs.linuxPackages\${ai['kernel']};
NIX_CFG
  fi
  tee -a \${ai['nixcfg']} << NIX_CFG
  boot.blacklistedKernelModules = [
NIX_CFG
  for item in \${ai['blacklist']}; do
  tee -a \${ai['nixcfg']} << NIX_CFG
    "\${item}"
NIX_CFG
  done
  tee -a \${ai['nixcfg']} << NIX_CFG
  ];

  # Sysctl Parameters
  boot.kernel.sysctl = {
\${ai['sysctl']}
  };

  # Security
  security = {
    # Auditing
    auditd.enable = \${ai['audit']};
    audit.enable = \${ai['audit']};
    audit.rules = [
\${ai['auditrules']}
    ];
    protectKernelImage = \${ai['protectkernelimage']};
    lockKernelModules = \${ai['lockkernelmodules']};
    forcePageTableIsolation = \${ai['forcepagetableisolation']};
    allowUserNamespaces = \${ai['allowusernamespaces']};
    unprivilegedUsernsClone = \${ai['unprivilegedusernsclone']};
    allowSimultaneousMultithreading = \${ai['allowsmt']};
  };

  # Services security
  security.sudo.execWheelOnly = \${ai['execwheelonly']};
  services.dbus.implementation = "\${ai['dbusimplementation']}";
  services.logrotate.enable = \${ai['logrotate']};
  services.journald.upload.enable = \${ai['journaldupload']};
  services.journald.extraConfig = "
NIX_CFG
  for item in  \${ai['journaldextraconfig']}; do
    tee -a \${ai['nixcfg']} << NIX_CFG
    \${item}
NIX_CFG
  done
  tee -a \${ai['nixcfg']} << NIX_CFG
  ";

  # Fwupd service
  services.fwupd.enable = \${ai['fwupd']};

  # Systemd
  systemd.services.systemd-journald = {
    serviceConfig = {
      UMask = \${ai['systemdumask']};
      PrivateNetwork = \${ai['privatenetwork']};
      ProtectHostname = \${ai['protecthostname']};
      ProtectKernelModules = \${ai['protectkernelmodules']};
    };
  }; 
  systemd.services.systemd-rfkill = {
    serviceConfig = {
      ProtectSystem = "\${ai['protectsystem']}";
      ProtectHome = \${ai['protecthome']};
      ProtectKernelTunables = \${ai['protectkerneltunables']};
      ProtectKernelModules = \${ai['protectkernelmodules']};
      ProtectControlGroups = \${ai['protectcontrolgroups']};
      ProtectClock = \${ai['protectclock']};
      ProtectProc = "\${ai['protectproc']}";
      ProcSubset = "\${ai['procsubset']}";
      PrivateTmp = \${ai['privatetmp']};
      MemoryDenyWriteExecute = \${ai['memorydenywriteexecute']};
      NoNewPrivileges = \${ai['nownewprivileges']};
      LockPersonality = \${ai['lockpersonality']};
      RestrictRealtime = \${ai['restrictrealtime']};
      SystemCallArchitectures = "\${ai['systemcallarchitectures']}";
      UMask = "\${ai['systemdumask']}";
      IPAddressDeny = "\${ai['ipaddressdeny']}";
    };
  };

  # HostID and Hostname
  networking.hostId = "\${ai['hostid']}";
  networking.hostName = "\${ai['hostname']}";

  # fail2ban
  services.fail2ban = {
    enable = \${ai['fail2ban']};
    maxretry = \${ai['maxretry']};
    bantime = "\${ai['bantime']}";
    ignoreIP = [
NIX_CFG
  for item in \${ai['ignoreip']}; do
    tee -a \${ai['nixcfg']} << NIX_CFG
    "\${item}"
NIX_CFG
  done
  tee -a \${ai['nixcfg']} << NIX_CFG
    ];
    bantime-increment = {
      enable = \${ai['bantimeincrement']};
      multipliers = "\${ai['multipliers']}";
      maxtime = "\${ai['maxtime']}";
      overalljails = \${ai['overalljails']};
    };
  };

  # OpenSSH
  services.openssh.enable = \${ai['sshserver']};
  services.openssh.settings.PasswordAuthentication = \${ai['passwordauthentication']};
  services.openssh.settings.PermitEmptyPasswords = \${ai['permitemptypasswords']};
  services.openssh.settings.KbdInteractiveAuthentication = \${ai['kbdinteractive']};
  services.openssh.settings.PermitTunnel = \${ai['permittunnel']};
  services.openssh.settings.UseDns = \${ai['usedns']};
  services.openssh.settings.X11Forwarding = \${ai['x11forwarding']};
  services.openssh.settings.MaxAuthTries = \${ai['maxauthtries']};
  services.openssh.settings.AllowUsers = [ "\${ai['allowusers']}" ];
  services.openssh.settings.LogLevel = "\${ai['loglevel']}";
  services.openssh.settings.PermitRootLogin = "\${ai['permitrootlogin']}";
  services.openssh.settings.AllowTcpForwarding = \${ai['allowtcpforwarding']};
  services.openssh.settings.AllowAgentForwarding = \${ai['allowagentforwarding']};
  services.openssh.settings.ClientAliveInterval = \${ai['clientaliveinterval']};
  services.openssh.settings.ClientAliveCountMax = \${ai['clientalivecountmax']};
  services.openssh.settings.KexAlgorithms = [
NIX_CFG
  for item in \${ai['kexalgorithms']}; do
    tee -a \${ai['nixcfg']} << NIX_CFG
    "\${item}"
NIX_CFG
  done
  tee -a \${ai['nixcfg']} << NIX_CFG
  ];
  services.openssh.settings.Ciphers = [
NIX_CFG
  for item in \${ai['ciphers']}; do
    tee -a \${ai['nixcfg']} << NIX_CFG
    "\${item}"
NIX_CFG
  done
  tee -a \${ai['nixcfg']} << NIX_CFG
  ];
  services.openssh.settings.Macs = [
NIX_CFG
  for item in \${ai['macs']}; do
    tee -a \${ai['nixcfg']} << NIX_CFG
    "\${item}"
NIX_CFG
  done
  tee -a \${ai['nixcfg']} << NIX_CFG
  ];
  services.openssh.hostKeys = [
    {
      path = "\${ai['hostkeyspath']}";
      type = "\${ai['hostkeystype']}";
    }
  ];

  # Firewall
  networking.firewall = {
    enable = \${ai['firewall']};
    allowedTCPPorts = [ \${ai['allowedtcpports']} ];
    allowedUDPPorts = [ \${ai['allowedudpports']} ];
  };

  # Additional Nix options
  nix.settings.experimental-features = "\${ai['experimental-features']}";

  # System packages
  environment.systemPackages = with pkgs; [
    \${ai['systempackages']// /\${spacer}    }
  ];
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
  system.userActivationScripts.zshrc = "touch .zshrc";

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
    interfaces."\${ai['bridgenic']}".useDHCP = \${ai['dhcp']};
    interfaces."\${ai['nic']}".useDHCP = \${ai['dhcp']};
    interfaces."\${ai['bridgenic']}".ipv4.addresses = [{
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
  hardware.cpu.intel.updateMicrocode = lib.mkDefault config.hardware.enableRedistributableFirmware;
  system.stateVersion = "\${ai['stateversion']}";
}
NIX_CFG
}

# Get device UUIDs

get_device_uuids () {
  if [ "\${ai['swap']}" = "true" ]; then
    ai['swapuuid']=\$(ls -l \${ai['devnodes']} | grep \${ai['swapsearch']} | awk '{print \$9}' )
    ai['swapdev']="\${ai['devnodes']}/\${ai['swapuuid']}"
  else
    ai['swapdev']=""
  fi
  ai['bootuuid']=\$(ls -l \${ai['devnodes']} | grep \${ai['bootsearch']} | awk '{print \$9}' )
  ai['bootdev']="\${ai['devnodes']}/\${ai['bootuuid']}"
  ai['rootuuid']=\$(ls -l \${ai['devnodes']} | grep \${ai['rootsearch']} | awk '{print \$9}' )
  ai['rootdev']="\${ai['devnodes']}/\${ai['rootuuid']}"
  echo "Setting rootuuid to \${ai['rootuuid']}"
  echo "Setting rootdev to \${ai['rootdev']}"
  echo "Setting bootuuid to \${ai['bootuuid']}"
  echo "Setting bootdev to \${ai['bootdev']}"
  echo "Setting swapuuid to \${ai['swapuuid']}"
  echo "Setting swapdev to \${ai['swapdev']}"
}

# Create hardware-configuration.nix

create_hardware_configuration () {
  echo "Creating \${ai['hwcfg']}"
  tee \${ai['hwcfg']} << HW_CFG
{ config, lib, pkgs, modulesPath, ... }:
{
  imports = [
    \${ai['hwimports']}
  ];
  boot.initrd.availableKernelModules = [ 
HW_CFG
  for item in \${ai['availmods']}; do
    tee -a \${ai['hwcfg']} << HW_CFG
    "\${item}"
HW_CFG
  done
  tee -a \${ai['hwcfg']} << HW_CFG
  ];
  boot.initrd.kernelModules = [
HW_CFG
  for item in \${ai['initmods']}; do
    tee -a \${ai['hwcfg']} << HW_CFG
    "\${item}""
HW_CFG
  done
  tee -a \${ai['hwcfg']} << HW_CFG
  ];
  boot.kernelModules = [
HW_CFG
  for item in \${ai['bootmods']}; do
    tee -a \${ai['hwcfg']} << HW_CFG
    "\${item}"
HW_CFG
  done
  tee -a \${ai['hwcfg']} << HW_CFG
  ];
  boot.loader.grub.extraConfig = "
    \${ai['grubextraconfig']//  /\${spacer}     }
  ";
  boot.kernelParams = [
HW_CFG
  for item in \${ai['kernelparams']}; do
    tee -a \${ai['hwcfg']} << HW_CFG
    "\${item}"
HW_CFG
  done
  tee -a \${ai['hwcfg']} << HW_CFG
  ];
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
}

# Manual config creation command if you need it
# nixos-generate-config --root \${ai['installdir']}

# Check whether to run installer and handle appropriately

handle_installer () {
  if [ "\${ai['attended']}" = "true" ]; then
    echo "To install:"
    echo "nixos-install -v --show-trace --no-root-passwd 2>&1 | tee \${ai['installdir']}\${ai['logfile']}"
    echo "To unmount filesystems and reboot:"
    echo "umount -Rl \${ai['installdir']}"
    if [ "\${ai['rootfs']}" = "zfs" ]; then
      echo "zpool export -a"
    fi
    echo "swapoff -a"
    echo "reboot"
    exit
  else
    nixos-install -v --show-trace --no-root-passwd 2>&1 | tee \${ai['installdir']}\${ai['logfile']}
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
    if [ "\${ai['rootfs']}" = "zfs" ]; then
      zpool export -a
    fi
    swapoff -a
  fi
  if [ "\${ai['poweroff']}" = "true" ]; then
    poweroff
  fi
  if [ "\${ai['reboot']}" = "true" ]; then
    reboot
  fi
}

interactive_install () {
  if [ "\${ai['interactiveinstall']}" = "true" ] || [ "\${ai['dointeractiveinstall']}" = "true" ]; then 
    for key in \${!ai[@]}; do
      if ! [[ "\${key}" =~ interactive ]]; then
        value="\${ai[\${key}]}"
        line=$( grep "# ai :" "\${ai['scriptfile']}" | grep "'\${key}'" | grep -v grep )
        if ! [ "\${line}" = "" ]; then
          IFS=":" read -r header question <<< "\${line}"
          question=$( echo "\${question}" | sed "s/^ //g" )
          prompt="\${question}? [\${value}]: "
          read -r -p "\${prompt}" answer
          if ! [ "\${answer}" = "" ]; then
            options[\${key}]="\${answer}"
          fi
          if ! [ "\${answer}" = "none" ]; then
            options[\${key}]=""
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

while test \$# -gt 0; do
  case \$1 in
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
    else
      if [ "${param}" = "rootdisk" ]; then
        suffix="${suffix}-first-disk"
      else
        suffix="${suffix}-first-${param}"
      fi
    fi
  done
  for param in ip; do
    value="${options[${param}]}"
    if ! [ "${value}" = "" ]; then
      suffix="${suffix}-${value}"
    fi
  done
  for param in hostname username; do
    value="${options[${param}]}"
    if ! [ "${value}" = "nixos" ]; then
      suffix="${suffix}-${value}"
    fi
  done
  for param in bridge unattended attended poweroff nopoweroff reboot noreboot standalone lvm unstable; do
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
    if [ "${os['name']}" = "Darwin" ] || [ "${options['usepreservediso']}" = "true" ]; then
      iso_dir="${options['workdir']}/isos"
    else
      iso_dir="${options['workdir']}/result/iso"
    fi
    if [ -d "${iso_dir}" ]; then
      vm['cdrom']=$( ls -rt "${iso_dir}"/nixos*.iso | tail -1 )
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

# Function: interactive_questions
#
# Interactive Questions

interactive_questions () {
  if [ "${options['interactive']}" = "true" ]; then
    for key in ${!options[@]}; do
      if ! [[ "${key}" =~ interactive ]]; then
        value="${options[${key}]}"
        line=$( grep '# option :' "${script['file']}" | grep "\'${key}\'" )
        if ! [ "${line}" = "" ]; then
          IFS=":" read -r header question <<< "${line}"
          question=$( echo "${question}" | sed "s/^ //g" )
          if [ "${options['verbose']}" = "true" ]; then 
            prompt="${question}? [${key}] [${value}]: "
          else
            prompt="${question}? [${value}]: "
          fi
          read -r -p "${prompt}" answer
          if ! [ "${answer}" = "" ]; then
            options[${key}]="${answer}"
          fi
          if [ "${answer}" = "none" ]; then
            options[${key}]=""
          fi
        fi
      fi
    done
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
      interactive_questions
      create_install_script
      exit
      ;;
    checkdocker*)           # action : Check docker config
      check_docker
      exit
      ;;
    createdockeriso)        # action : Create docker ISO
      interactive_questions
      create_docker_iso
      exit
      ;;
    createiso)              # action : Create ISO
      interactive_questions
      create_iso
      exit
      ;;
    createnix*)             # action : Create NixOS ISO config
      interactive_questions
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
    --action*)                          # switch : Action(s) to perform
      check_value "$1" "$2"
      actions_list+=("$2")
      shift 2
      ;;
    --addiso|--addcdrom)                # switch : Add cdrom to VM
      actions_list+=("addiso")
      shift
      ;;
    --audit)                            # switch : Enable auditing
      options['audit']="true"
      shift
      ;;
    --removeiso|--removecdrom)          # switch : Remove cdrom from VM
      actions_list+=("removeiso")
      shift
      ;;
    --allowedtcpports)                  # switch : Allowed TCP ports
      check_value "$1" "$2"
      options['allowedtcpports']="$2"
      shift 2
      ;;
    --allowedudpports)                  # switch : Allowed UDP ports
      check_value "$1" "$2"
      options['allowedudpports']="$2"
      shift 2
      ;;
    --allowagentforwarding)             # switch : SSH allow agent forwarding
      options['allowagentforwarding']="true"
      shift
      ;;
    --allows*)                          # switch : SSH allow TCP forwarding
      options['allowsmt']="true"
      shift
      ;;
    --allowtcpforwarding)               # switch : SSH allow TCP forwarding
      options['allowtcpforwarding']="true"
      shift
      ;;
    --allowusers)                       # switch : SSH allow users
      check_value "$1" "$2"
      options['allowusers']="$2"
      shift 2
      ;;
    --availmod*)                        # switch : Available system kernel modules
      check_value "$1" "$2"
      options['availmods']="$2"
      shift 2
      ;;
    --bantime)                          # switch : fail2ban ban time
      check_value "$1" "$2"
      options['bantime']="$2"
      shift 2
      ;;
    --bantimeincrement)                 # switch : Enable fail2ban ban time increment
      options['bantimeincrement']="true"
      shift
      ;;
    --nobantimeincrement)               # switch : Enable fail2ban ban time increment
      options['bantimeincrement']="false"
      shift
      ;;
    --blacklist)                        # switch : Blacklist modules
      check_value "$1" "$2"
      options['blacklist']="$2"
      shift 2
      ;;
    --bootfromdisk)                     # switch : Boot VM from disk
      actions_list+=("bootfromdisk")
      shift
      ;;
    --bootfromiso|--bootfromcdrom)      # switch : Boot VM from CDROM
      actions_list+=("bootfromcdrom")
      shift
      ;;
    --bootmod*)                         # switch : Available system boot modules
      check_value "$1" "$2"
      options['bootmods']="$2"
      shift 2
      ;;
    --bootsize)                         # switch : Boot partition size
      check_value "$1" "$2"
      options['bootsize']="$2"
      shift 2
      ;;
    --bootvm|--startvm)                 # switch : Boot VM
      actions_list+=("startkvmvm")
      shift
      ;;
    --stopvm)                           # switch : Stop VM
      actions_list+=("stopkvmvm")
      shift
      ;;
    --bridge)                           # switch : Enable bridge
      options['bridge']="true"
      shift
      ;;
    --bridgenic)                        # switch : Bridge NIC
      check_value "$1" "$2"
      options['bridgenic']="$2"
      options['bridge']="true"
      options['dhcp']="false"
      shift 2
      ;;
    --bootf*)                           # switch : Boot Filesystem
      check_value "$1" "$2"
      options['bootfs']="$2"
      shift 2
      ;;
    --bootvol*)                         # switch : Boot volume name
      check_value "$1" "$2"
      options['bootvolname']="$2"
      shift 2
      ;;
    --checkdocker*)                     # switch : Check docker config
      actions_list+=("checkdocker")
      shift
      ;;
    --cidr)                             # switch : CIDR
      check_value "$1" "$2"
      options['cidr']="$2"
      options['dhcp']="false"
      shift 2
      ;;
    --ciphers)                          # switch : SSH ciphers
      check_value "$1" "$2"
      options['ciphers']="$2"
      shift 2
      ;;
    --clientaliveinterval)              # switch : SSH client alive interval
      check_value "$1" "$2"
      options['clientaliveinterval']="$2"
      shift 2
      ;;
    --clientalivecountmax)              # switch : SSH client alive count max
      check_value "$1" "$2"
      options['clientalivecountmax']="$2"
      shift 2
      ;;
    --createinstall*)                   # switch : Create install script
      actions_list+=("createinstall")
      shift
      ;;
    --createiso)                        # switch : Create ISO
      actions_list+=("createiso")
      shift
      ;;
    --createdockeriso)                  # switch : Create ISO
      actions_list+=("createdockeriso")
      options['createdockeriso']="true"
      shift
      ;;
    --createnix*)                       # switch : Create NixOS ISO config
      actions_list+=("createnix")
      shift
      ;;
    --createoneshot*)                   # switch : Create oneshot script
      actions_list+=("createoneshot")
      shift
      ;;
    --createvm)                         # switch : Create oneshot script
      actions_list+=("createvm")
      shift
      ;;
    --console*)                         # switch : Create oneshot script
      actions_list+=("consolevm")
      shift
      ;;
    --crypt|--usercrypt)                # switch : User Password Crypt
      check_value "$1" "$2"
      options['usercrypt']="$2"
      shift 2
      ;;
    --dbusimplementation)               # switch : Dbus implementation
      check_value "$1" "$2"
      options['dbusimplementation']="$2"
      shift 2
      ;;
    --debug)                            # switch : Enable debug mode
      options['debug']="true"
      shift
      ;;
    --deletevm)                         # switch : Delete VM
      actions_list+=("deletevm")
      shift
      ;;
    --dhcp)                             # switch : Enable DHCP
      options['dhcp']="true"
      shift
      ;;
    --disk|rootdisk)                    # switch : Root disk
      check_value "$1" "$2"
      options['rootdisk']="$2"
      shift 2
      ;;
    --dns|--nameserver)                 # switch : DNS/Nameserver address
      check_value "$1" "$2"
      options['dns']="$2"
      options['dhcp']="false"
      shift 2
      ;;
    --dockerarch)                       # switch : Docker architecture
      check_value "$1" "$2"
      options['dockerarch']="$2"
      shift 2
      ;;
    --dryrun)                           # switch : Enable debug mode
      options['dryrun']="true"
      shift
      ;;
    --execwheelonly)                    # switch : Sudo exec wheel only
      check_value "$1" "$2"
      options['execwheelonly']="$2"
      shift 2
      ;;
    --experimental*)                    # switch : SSH key
      check_value "$1" "$2"
      options['experimental-features']="$2"
      shift 2
      ;;
    --extragroup*)                      # switch : Extra groups
      check_value "$1" "$2"
      options['extragroups']="$2"
      shift 2
      ;;
    --fail2ban)                         # switch : Enable fail2ban
      options['fail2ban']="true"
      shift
      ;;
    --nofail2ban)                       # switch : Disable fail2ban
      options['fail2ban']="false"
      shift
      ;;
    --firewall)                         # switch : Enable firewall
      options['firewall']="true"
      shift
      ;;
    --nofirewall)                       # switch : Disable firewall
      options['firewall']="false"
      shift
      ;;
    --firmware)                         # switch : Boot firmware type
      check_value "$1" "$2"
      options['firmware']="$2"
      shift 2
      ;;
    --force)                            # switch : Enable force mode
      options['force']="true"
      shift
      ;;
    --forcepagetableisolation)          # switch : Force page table isolation
      options['forcepagetableisolation']="true"
      shift
      ;;
    --noforcepagetableisolation)        # switch : Don't force page table isolation
      options['forcepagetableisolation']="false"
      shift
      ;;
    --fwupd)                            # switch : Enable fwupd
      options['fwupd']="true"
      shift
      ;;
    --nofwupd)                          # switch : Disable fwupd
      options['fwupd']="false"
      shift
      ;;
    --gateway)                          # switch : Gateway address
      check_value "$1" "$2"
      options['gateway']="$2"
      options['dhcp']="false"
      shift 2
      ;;
    --gecos|--usergecos)                # switch : GECOS field
      check_value "$1" "$2"
      options['usergecos']="$2"
      shift 2
      ;;
    --gfxmode)                          # switch : Bios text mode
      check_value "$1" "$2"
      options['gfxmode']="$2"
      shift 2
      ;;
    --gfxpayload)                       # switch : Bios text mode
      check_value "$1" "$2"
      options['gfxpayload']="$2"
      shift 2
      ;;
    --grubextra*)                       # switch : ISO grub extra config
      check_value "$1" "$2"
      options['grubextraconfig']="$2"
      shift 2
      ;;
    --help|-h)                          # switch : Print help information
      print_help
      shift
      exit
      ;;
    --hostkeyspath)                     # switch : SSH host keys path
      check_value "$1" "$2"
      options['hostkeyspath']="$2"
      shift 2
      ;;
    --hostkeystype)                     # switch : SSH host keys type
      check_value "$1" "$2"
      options['hostkeystype']="$2"
      shift 2
      ;;
    --hostname)                         # switch : Hostname
      check_value "$1" "$2"
      options['hostname']="$2"
      shift 2
      ;;
    --hwimports)                        # switch : Imports for system hardware configuration
      check_value "$1" "$2"
      options['hwimports']="$2"
      shift 2
      ;;
    --import)                           # switch : Import a Nix configuration
      check_value "$1" "$2"
      options['import']="$2"
      shift 2
      ;;
    --imports)                          # switch : Imports for system configuration
      check_value "$1" "$2"
      options['imports']="$2"
      shift 2
      ;;
    --initmod*)                         # switch : Available system init modules
      check_value "$1" "$2"
      options['initmods']="$2"
      shift 2
      ;;
    --installscript)                    # switch : Install script
      check_value "$1" "$2"
      options['installscript']="$2"
      shift 2
      ;;
    --installdir)                       # switch : Install directory where destination disk is mounted
      check_value "$1" "$2"
      options['installdir']="$2"
      shift 2
      ;;
    --installuser*)                     # switch : Install username
      check_value "$1" "$2"
      options['installuser']="$2"
      shift 2
      ;;
    --interactive)                      # switch : Enable interactive mode
      options['interactive']="true"
      shift
      ;;
    --interactiveinstall)               # switch : Enable interactive install mode
      options['interactiveinstall']="true"
      shift
      ;;
    --nointeractive)                    # switch : Disable interactive mode
      options['interactive']="false"
      shift
      ;;
    --nointeractiveinstall)             # switch : Disable interactive install mode
      options['interactiveinstall']="false"
      shift
      ;;
    --ip)                               # switch : IP address
      check_value "$1" "$2"
      options['ip']="$2"
      options['dhcp']="false"
      shift 2
      ;;
    --ipaddressdeny)                    # switch : systemd IP address deny
      check_value "$1" "$2"
      options['ipaddressdeny']="$2"
      shift 2
      ;;
    --isogrubextra*)                    # switch : ISO grub extra config
      check_value "$1" "$2"
      options['isogrubextraconfig']="$2"
      shift 2
      ;;
    --isoimport)                        # switch : Import additional Nix configuration file into ISO configuration
      check_value "$1" "$2"
      options['isoimport']="$2"
      shift 2
      ;;
    --isoimports)                       # switch : NixOS imports for ISO build
      check_value "$1" "$2"
      options['isoimports']="$2"
      shift 2
      ;;
    --isokernelparam*)                  # switch : Extra kernel parameters to add to ISO grub commands
      check_value "$1" "$2"
      options['isokernelparams']="$2"
      shift 2
      ;;
    --isomount)                         # switch : Install ISO mount directory
      check_value "$1" "$2"
      options['isomount']="$2"
      shift 2
      ;;
    --isopermitrootlogin)               # switch : Enable SSH root login for ISO
      options['isopermitrootlogin']="yes"
      shift
      ;;
    --journaldextra*)                   # switch : System journald extra config
      check_value "$1" "$2"
      options['journaldextraconfig']="$2"
      shift 2
      ;;
    --journalupload)                    # switch : Enable remote log upload
      options['journaldupload']="true"
      shift
      ;;
    --nojournalupload)                  # switch : Disable remote log upload
      options['journaldupload']="false"
      shift
      ;;
    --kbdinteractive*)                  # switch : Enable SSH allow interactive kerboard authentication
      options['kbdinteractive']="true"
      shift
      ;;
    --nokbdinteractive*)                # switch : Disable SSH allow interactive kerboard authentication
      options['nokbdinteractive']="true"
      shift
      ;;
    --keymap)                           # switch : Keymap
      check_value "$1" "$2"
      options['keymap']="$2"
      shift 2
      ;;
    --kernelparam*)                     # switch : Extra kernel parameters to add to systembuild
      check_value "$1" "$2"
      options['kernelparams']="$2"
      shift 2
      ;;
    --kernel)                           # switch : Kernel
      check_value "$1" "$2"
      options['kernel']="$2"
      shift 2
      ;;
    --kexalgorithms)                    # switch : SSH key exchange algorithms
      check_value "$1" "$2"
      options['kexalgorithms']="$2"
      shift 2
      ;;
    --locale)                           # switch : Locale
      check_value "$1" "$2"
      options['locale']="$2"
      shift 2
      ;;
    --logfile)                          # switch : Locale
      check_value "$1" "$2"
      options['logfile']="$2"
      shift 2
      ;;
    --loglevel)                         # switch : SSH log level
      check_value "$1" "$2"
      options['loglevel']="$2"
      shift 2
      ;;
    --logrotate)                        # switch : Enable logrotate
      options['logrotate']="true"
      shift
      ;;
    --nologrotate)                      # switch : Enable logrotate
      options['logrotate']="false"
      shift
      ;;
    --lockkernelmodules)                # switch : Lock kernel modules
      options['lockkernelmodules']="true"
      shift
      ;;
    --nolockkernelmodules)              # switch : Don't lock kernel modules
      options['lockkernelmodules']="false"
      shift
      ;;
    --lockpersonality)                  # switch : Enable systemd lock personality
      options['lockpersonality']="true"
      shift
      ;;
    --nolockpersonality)                # switch : Disable systemd lock personality
      options['lockpersonality']="false"
      shift
      ;;
    --lvm)                              # switch : Enable LVM
      options['lvm']="true"
      shift
      ;;
    --macs)                             # switch : SSH macs
      check_value "$1" "$2"
      options['macs']="$2"
      shift 2
      ;;
    --mask*)                            # switch : Enable LVM
      options['mask']="true"
      shift
      ;;
    --maxauthtries)                     # switch : SSH max auth tries
      check_value "$1" "$2"
      options['maxauthtries']="$2"
      shift 2
      ;;
    --maxretry)                         # switch : fail2ban max retry
      check_value "$1" "$2"
      options['maxretry']="$2"
      shift 2
      ;;
    --maxtime)                          # switch : fail2ban bantime maximum 
      check_value "$1" "$2"
      options['maxtime']="$2"
      shift 2
      ;;
    --memorydenywriteexecute)           # switch : Enable systemd memory deny write execute
      options['memorydenywriteexecute']="true"
      shift
      ;;
    --nomemorydenywriteexecute)         # switch : Disable systemd memory deny write execute
      options['memorydenywriteexecute']="false"
      shift
      ;;
    --mbrpartname)                      # switch : MBR partition name
      check_value "$1" "$2"
      options['mbrpartname']="$2"
      shift 2
      ;;
    --multipliers)                      # switch : fail2ban ban time multipliers
      check_value "$1" "$2"
      options['multipliers']="$2"
      shift 2
      ;;
    --nic)                              # switch : NIC
      check_value "$1" "$2"
      options['nic']="$2"
      shift 2
      ;;
    --nixconfig)                        # switch : NixOS configuration file
      check_value "$1" "$2"
      options['nixconfig']="$2"
      shift 2
      ;;
    --nixdir)                           # switch : Set NixOS directory
      check_value "$1" "$2"
      options['nixdir']="$2"
      shift 2
      ;;
    --nixhwconfig)                      # switch : NixOS hardware configuration file
      check_value "$1" "$2"
      options['nixhwconfig']="$2"
      shift 2
      ;;
    --nixinstall)                       # switch : Run NixOS install script automatically on ISO
      options['nixinstall']="true"
      shift
      ;;
    --nixisoconfig)                     # switch : NixOS ISO configuration file
      check_value "$1" "$2"
      options['nixisoconfig']="$2"
      shift 2
      ;;
    --nonewprivileges)                  # switch : Enable systemd no new privileges
      options['nownewprivileges']="true"
      shift
      ;;
    --newprivileges)                    # switch : Disable systemd no new privileges
      options['nownewprivileges']="false"
      shift
      ;;
    --oneshot)                          # switch : Enable oneshot service
      options['oneshot']="true"
      shift
      ;;
    --nooneshot)                        # switch : Disable oneshot service
      options['oneshot']="false"
      shift
      ;;
    --option*)                          # switch : Option(s) to set
      check_value "$1" "$2"
      options_list+=("$2")
      shift 2
      ;;
    --output*|--iso)                    # switch : Output file
      check_value "$1" "$2"
      options['output']="$2"
      options['preserve']="true"
      shift 2
      ;;
    --overalljails)                     # switch : fail2ban bantime overalljails
      options['overalljails']="true"
      shift
      ;;
    --password|--userpassword)          # switch : User password
      check_value "$1" "$2"
      options['userpassword']="$2"
      shift 2
      ;;
    --passwordauthentication)           # switch : Enable SSH password authentication
      options['passwordauthentication']="true"
      shift
      ;;
    --nopasswordauthentication)         # switch : Disable SSH password authentication
      options['passwordauthentication']="false"
      shift
      ;;
    --permitemptypasswords)             # switch : Enable SSH empty passwords
      options['permitemptypasswords']="true"
      shift
      ;;
    --permitrootlogin)                  # switch : Enable SSH root login
      options['permitrootlogin']="yes"
      shift
      ;;
    --poweroff)                         # switch : Enable poweroff after install
      options['poweroff']="true"
      shift
      ;;
    --prefix)                           # switch : Install prefix
      check_value "$1" "$2"
      options['prefix']="$2"
      shift 2
      ;;
    --preserve)                         # switch : Preserve output file
      options['preserve']="true"
      shift
      ;;
    --privatetmp)                       # switch : Enable systemd private tmp
      options['privatetmp']="true"
      shift
      ;;
    --noprivatetmp)                     # switch : Disable systemd private tmp
      options['privatetmp']="false"
      shift
      ;;
    --privatenetwork)                   # switch : Enable systemd private network
      options['privatenetwork']="true"
      shift
      ;;
    --noprivatenetwork)                 # switch : Disable systemd private network
      options['privatenetwork']="true"
      shift
      ;;
    --processgrub*)                     # switch : Enable processing grub command line
      options['processgrub']="true"
      shift
      ;;
    --noprocessgrub*)                   # switch : Disable processing grub command line
      options['processgrub']="false"
      shift
      ;;
    --protectclock)                     # switch : Enable systemd protect clock
      options['protectclock']="true"
      shift
      ;;
    --noprotectclock)                   # switch : Disable systemd protect clock
      options['protectclock']="false"
      shift
      ;;
    --protectcontrolgroups)             # switch : Enable systemd protect control groups
      options['protectcontrolgroups']="true"
      shift
      ;;
    --noprotectcontrolgroups)           # switch : Disable systemd protect control groups
      options['protectcontrolgroups']="false"
      shift
      ;;
    --protecthome)                      # switch : Enable systemd protect home
      options['protecthome']="true"
      shift
      ;;
    --noprotecthome)                    # switch : Disable systemd protect home
      options['protecthome']="false"
      shift
      ;;
    --protecthostname)                  # switch : Enable systemd protect hostname
      options['protecthostname']="true"
      shift
      ;;
    --noprotecthostname)                # switch : Disable systemd protect hostname
      options['protecthostname']="false"
      shift
      ;;
    --protectkernelimage)               # switch : Protect kernel image
      options['protectkernelimage']="true"
      shift
      ;;
    --noprotectkernelimage)             # switch : Don't protect kernel image
      options['protectkernelimage']="false"
      shift
      ;;
    --protectkernelmodules)             # switch : Enable systemd protect kernel modules
      options['protectkernelmodules']="true"
      shift
      ;;
    --noprotectkernelmodules)           # switch : Disable systemd protect kernel modules
      options['protectkernelmodules']="false"
      shift
      ;;
    --protectkerneltunables)            # switch : Enable systemd protect kernel tunables
      options['protectkernelmodules']="true"
      shift
      ;;
    --noprotectkerneltunables)          # switch : Disable systemd protect kernel tunables
      options['protectkernelmodules']="false"
      shift
      ;;
    --protectproc)                      # switch : systemd protect proc
      check_value "$1" "$2"
      options['protectproc']="$2"
      shift 2
      ;;
    --protectsubset)                    # switch : systemd protect subset
      check_value "$1" "$2"
      options['protectsubset']="true"
      shift 2
      ;;
    --protectsystem)                    # switch : systemd protect system
      check_value "$1" "$2"
      options['protectsystem']="$2"
      shift 2
      ;;
    --reboot)                           # switch : Enable reboot after install
      options['reboot']="true"
      shift
      ;;
    --restrictrealtime)                 # switch : Enable systemd restrict realtime
      options['restrictrealtime']="true"
      shift
      ;;
    --norestrictrealtime)               # switch : Disable systemd restrict realtime
      options['restrictrealtime']="false"
      shift
      ;;
    --rootcrypt)                        # switch : Root password crypt
      check_value "$1" "$2"
      options['rootcrypt']="$2"
      shift 2
      ;;
    --rootf*|--filesystem)              # switch : Root Filesystem
      check_value "$1" "$2"
      options['rootfs']="$2"
      shift 2
      ;;
    --rootpassword)                     # switch : Root password
      check_value "$1" "$2"
      options['rootpassword']="$2"
      shift 2
      ;;
    --rootpool)                         # switch : Root pool name
      check_value "$1" "$2"
      options['rootpool']="$2"
      shift 2
      ;;
    --rootsize)                         # switch : Root partition size
      check_value "$1" "$2"
      options['rootsize']="$2"
      shift 2
      ;;
    --rootvol*)                         # switch : Root volume name
      check_value "$1" "$2"
      options['rootvolname']="$2"
      shift 2
      ;;
    --runsize)                          # switch : Run size
      check_value "$1" "$2"
      options['runsize']="$2"
      shift 2
      ;;
    --secure)                           # switch : Enable secure parameters
      options['secure']="true"
      shift
      ;;
    --serial)                           # switch : Enable serial
      options['serial']="true"
      shift
      ;;
    --serialparity)                     # switch : Serial parity
      check_value "$1" "$2"
      options['serialparity']="$2"
      shift 2
      ;;
    --serialport)                       # switch : Serial port
      check_value "$1" "$2"
      options['serialport']="$2"
      shift 2
      ;;
    --serialspeed)                      # switch : Serial speed
      check_value "$1" "$2"
      options['serialspeed']="$2"
      shift 2
      ;;
    --serialstop)                       # switch : Serial stop
      check_value "$1" "$2"
      options['serialstop']="$2"
      shift 2
      ;;
    --serialtty)                        # switch : Serial tty
      check_value "$1" "$2"
      options['serialtty']="$2"
      shift 2
      ;;
    --serialunit)                       # switch : Serial unit
      check_value "$1" "$2"
      options['serialunit']="$2"
      shift 2
      ;;
    --serialword)                       # switch : Serial stop
      check_value "$1" "$2"
      options['serialword']="$2"
      shift 2
      ;;
    --setboot*)                         # switch : Set boot device
      actions_list+=("setboot")
      shift
      ;;
    --shell|usershell)                  # switch : User Shell
      check_value "$1" "$2"
      options['usershell']="$2"
      shift 2
      ;;
    --shellcheck)                       # switch : Run shellcheck
      actions_list+=("shellcheck")
      shift
      ;;
    --source)                           # switch : Source directory for ISO additions
      check_value "$1" "$2"
      options['source']="$2"
      shift 2
      ;;
    --sshkey)                           # switch : SSH key
      check_value "$1" "$2"
      options['sshkey']="$2"
      shift 2
      ;;
    --sshkeyfile)                       # switch : SSH key file
      check_value "$1" "$2"
      options['sshkeyfile']="$2"
      shift 2
      ;;
    --sshserver)                        # switch : Enable strict mode
      options['sshserver']="true"
      shift
      ;;
    --standalone)                       # switch : Create a standalone ISO
      options['standalone']="true"
      shift
      ;;
    --stateversion)                     # switch : NixOS state version
      check_value "$1" "$2"
      options['stateversion']="$2"
      shift 2
      ;;
    --strict)                           # switch : Enable strict mode
      options['strict']="true"
      shift
      ;;
    --sudocommand*)                     # switch : Sudo commands
      check_value "$1" "$2"
      options['sudocommand']="$2"
      shift 2
      ;;
    --sudooption*)                      # switch : Sudo options
      check_value "$1" "$2"
      options['sudooptions']="$2"
      shift 2
      ;;
    --sudouser*)                        # switch : Sudo users
      check_value "$1" "$2"
      options['sudousers']="$2"
      shift 2
      ;;
    --suffix|--outputsuffix)            # switch : Sudo users
      check_value "$1" "$2"
      options['suffix']="$2"
      shift 2
      ;;
    --systemdumask)                     # switch : Systemd umask
      check_value "$1" "$2"
      options['systemdumask']="$2"
      shift 2
      ;;
    --systempackages)                   # switch : NixOS state version
      check_value "$1" "$2"
      options['systempackages']="$2"
      shift 2
      ;;
    --systemcallarchitectures)          # switch : Systemd call architectures
      check_value "$1" "$2"
      options['systemcallarchitectures']="$2"
      shift 2
      ;;
    --swap)                             # switch : Enable swap
      options['swap']="true"
      shift
      ;;
    --swapsize)                         # switch : Swap partition size
      check_value "$1" "$2"
      options['swapsize']="$2"
      options['swap']="true"
      shift 2
      ;;
    --swapvol*)                         # switch : Swap volume name
      check_value "$1" "$2"
      options['swapvolname']="$2"
      options['swap']="true"
      shift 2
      ;;
    --target)                           # switch : Target directory for ISO additions
      check_value "$1" "$2"
      options['target']="$2"
      shift 2
      ;;
    --targetarch)                       # switch : Target architecture
      check_value "$1" "$2"
      options['targetarch']="$2"
      shift 2
      ;;
    --temp*)                            # switch : Target directory
      check_value "$1" "$2"
      options['tempdir']="$2"
      shift 2
      ;;
    --testmode)                         # switch : Enable swap
      options['testmode']="true"
      shift
      ;;
    --unprivilegedusernsclone)          # switch : Disable unprivileged user namespaces
      check_value "$1" "$2"
      options['unprivilegedusernsclone']="$2"
      shift 2
      ;;
    --unstable)                         # switch : Enable unstable features
      options['unstable']="true"
      shift
      ;;
    --stable)                           # switch : Disable unstable features
      options['unstable']="false"
      shift
      ;;
    --usage)                            # switch : Action to perform
      check_value "$1" "$2"
      usage="$2"
      print_usage "${usage}"
      shift 2
      exit
      ;;
    --usedns)                           # switch : SSH use DNS
      options['use']="true"
      shift
      ;;
    --usepres*)                         # switch : Use preserved ISO
      options['usepreservediso']="true"
      shift
      ;;
    --username)                         # switch : User username
      check_value "$1" "$2"
      options['username']="$2"
      shift 2
      ;;
    --verbose)                          # switch : Enable verbose mode
      options['verbose']="true"
      shift
      ;;
    --version|-V)                       # switch : Print version information
      print_version
      exit
      ;;
    --videodriver)                      # switch : Video Driver
      check_value "$1" "$2"
      options['videodriver']="$2"
      shift 2
      ;;
    --vmautoconsole)                    # switch : VM Autoconsole
      vm['noautoconsole']="false"
      shift
      ;;
    --vmboot)                           # switch : VM Boot type
      check_value "$1" "$2"
      vm['boot']="$2"
      shift 2
      ;;
    --vmcpu)                            # switch : VM CPU
      check_value "$1" "$2"
      vm['cpu']="$2"
      shift 2
      ;;
    --vmdir)                            # switch : VM Directory
      check_value "$1" "$2"
      vm['dir']="$2"
      shift 2
      ;;
    --vmfeatures)                       # switch : VM Features
      check_value "$1" "$2"
      vm['features']="$2"
      shift 2
      ;;
    --vmhostdevice)                     # switch : VM Host device
      check_value "$1" "$2"
      vm['host-device']="$2"
      shift 2
      ;;
    --vmgraphics)                       # switch : VM Graphics
      check_value "$1" "$2"
      vm['graphics']="$2"
      shift 2
      ;;
    --vmiso|--vmcdrom)                  # switch : VM ISO
      check_value "$1" "$2"
      vm['cdrom']="$2"
      shift 2
      ;;
    --vmmachine)                        # switch : VM Machine
      check_value "$1" "$2"
      vm['machine']="$2"
      shift 2
      ;;
    --vmmemory)                         # switch : VM Memory
      check_value "$1" "$2"
      vm['memory']="$2"
      shift 2
      ;;
    --vmname)                           # switch : VM Name
      check_value "$1" "$2"
      vm['name']="$2"
      shift 2
      ;;
    --vmnetwork)                        # switch : VM Network
      check_value "$1" "$2"
      vm['network']="$2"
      shift 2
      ;;
    --vmnoautoconsole)                  # switch : VM No autoconsole
      vm['noautoconsole']="true"
      shift
      ;;
    --vmnoreboot)                       # switch : VM Do not reboot VM after creation
      vm['noreboot']="true"
      shift
      ;;
    --vmreboot)                         # switch : VM Reboot VM after creation
      vm['noreboot']="false"
      shift
      ;;
    --vmsize)                           # switch : VM Size
      check_value "$1" "$2"
      vm['size']="$2"
      shift 2
      ;;
    --vmosvariant)                      # switch : VM OS variant
      check_value "$1" "$2"
      vm['os-variant']="$2"
      shift 2
      ;;
    --vmvirttype)                       # switch : VM Virtualisation type
      check_value "$1" "$2"
      vm['virt-type']="$2"
      shift 2
      ;;
    --vmvcpus)                          # switch : VM vCPUs
      check_value "$1" "$2"
      vm['vcpus']="$2"
      shift 2
      ;;
    --vmwait)                           # switch : VM number of seconds to wait before starting
      check_value "$1" "$2"
      vm['wait']="$2"
      shift 2
      ;;
    --workdir)                          # switch : Set script work directory
      check_value "$1" "$2"
      options['workdir']="$2"
      shift 2
      ;;
    --x11forwarding)                    # switch : Enable SSH X11 forwarding
      options['x11forwarding']="true"
      shift
      ;;
    --nox11forwarding)                  # switch : Disable SSH X11 forwarding
      options['x11forwarding']="false"
      shift
      ;;
    --zfsinstall)                       # switch : ZFS install script
      check_value "$1" "$2"
      options['zfsinstall']="$2"
      shift 2
      ;;
    --zsh)                              # switch : Enable zsh
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
