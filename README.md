![Manx cat](manx.jpg)

MANX
----

Make Automated NixOS (ISO)


Version
-------

Current version: 1.2.2

License
-------

CC BY-SA: https://creativecommons.org/licenses/by-sa/4.0/

Fund me here: https://ko-fi.com/richardatlateralblast


Introduction
------------

A script to an make an automated NixOS installation.

By default this script creates an unattended install ISO
with a ZFS root filesystem.

On NixOS, this script can be run directly, e.g.:

```
./manx.sh
```

On other versions of linux of the same architecture, the script can be run under nix-shell.

```
nix-shell -p bash
bash ./manx.sh
```

Features
--------

By default the script will try to choose sensible defaults,
if options are not specified. If fully automated, then
install script runs as a systemd service on boot.

By default the script creates a minimal ISO that fetches
packages from the network if required. To create an ISO
that is standalone, use the standalone option.

This script has the following capabilities:

- Create an attended/unattended install with:
  - ZFS root install
  - EXT4 root install
  - SSH server enabled during install with keys if specified/available
- Ability to:
  - Alter install parameters by editing grub command line before booting
  - Specify:
    - Language
    - Timezone
    - Keymap
    - etc
  - Import external addition Nix configuration file
  - Add additional packages
  - Specify static IP or use DHCP
  - Configure bridge devices
  - Modify user:
    - Shell
    - Username
    - Password
    - SSH key
- Creates a subdirectory which is imported in the ISO image:
  - Contains install scripts used for install

Status
------

This script is in the early stages of development

To-do:

- Add support for pass-thru PCIe devices
- Add ability to create image in a NixOS docker container
- Add ability to run this script via nix-shell on non NixOS Linux distros

Methodology
-----------

The script follows this process:

- Creates:
  - NixOS ISO configuration with:
    - SSH enabled with key
    - Directory that contains script
    - Includes additional packages for troubleshooting/automation:
      - ansible
      - curl 
      - dmidecode 
      - efibootmgr 
      - file 
      - lsb-release 
      - lshw 
      - pciutils 
      - vim 
      - wget
  - A directory containing:
    - Oneshot install script
    - Install script
- Builds ISO that depending on options:
  - Runs a fully automated unattended install, or
  - Runs in attended mode where the install script needs to be run manually

In automated/unattended mode the install runs from a systemd oneshot service.
This service copies the install scipt into /tmp and runs it.

The parameters passed to grub can be modified in order to change the install parameters.
The install script check these parameters on start up and passes them to the installer.

For example if the root filesystem was set to ZFS, there will be the following matching grub parameter:

```
ai.rootfs=zfs
```

This parameter can modified by editing the grub boot parameter before booting.

Background
----------

A standalone version of the script that was created for testing purposed,
and then folded back into the script is located here:

[Original Standalone Install Script](configs/scripts/install.sh)

[Updated Standalone Install Script](configs/scripts/updated_install.sh)

By setting the options in the script it can be used to install one of:

- ZFS root with or without swap
- EXT4/XFS/BTRFS root with or without swap on raw or LVM partitions 

By default nix-build will create a symlink to created ISO in the work directory.

If you use the preserve option, the script will copy and rename the ISO (based on options)
into an isos directory in the work directory, e.g.

```
./manx.sh --createiso --options attended,noreboot,preserve
....
Generated ISO: /home/user/manx/result/iso/nixos-minimal-25.05.810061.d2ed99647a4b-x86_64-linux.iso
Preserved ISO: /home/user/manx/isos/nixos-minimal-25.05.810061.d2ed99647a4b-x86_64-linux-unattended-noreboot-nixos-zfs.iso
```

As previously mentioned when an automated install IOS is built,
the install script runs via a systemd oneshot service.

An example of the entry in the Nix ISO config file:

```
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
      sudo /iso/ai/oneshot.sh 
    '';
  };
```

Examples
--------

Create an attended install (requires manual running of install script) ISO with no reboot (verbose output):

```
./manx.sh --createiso --options attended,noreboot,verbose
```

Create an unattended install with defaults (ZFS root, DHCP):

```
./manx.sh --createiso
```

Create a standalone unattended install with defaults (ZFS root, DHCP):

```
./manx.sh --createiso --options standalone
```

After creating an ISO, you can test it by creating a VM:

```
./manx.sh --createvm --vmname test
```

Create an ISO using docker on MacOS:

```
./manx.sh --createdockeriso
```

Help
----

General Usage:

```
./manx.sh --help

Usage: manx.sh --action(s) [action(,action)] --option(s) [option(,option)]

switch(es):
----------
witch(es):
---------
--action*)
    Action(s) to perform
--allowedtcpports)
    Allowed TCP ports
--allowedudpports)
    Allowed UDP ports
--availmod*)
    Available system kernel modules
--bootmod*)
    Available system boot modules
--bootsize)
    Boot partition size
--bridge)
    Enable bridge
--bridgenic)
    Bridge NIC
--bootf*)
    Boot Filesystem
--bootvol*)
    Boot volume name
--checkdocker*)
    Check docker config
--cidr)
    CIDR
--createinstall*)
    Create install script
--createiso)
    Create ISO
--createdockeriso)
    Create ISO
--createnix*)
    Create NixOS ISO config
--createoneshot*)
    Create oneshot script
--createvm)
    Create oneshot script
--usercrypt|--crypt)
    User Password Crypt
--debug)
    Enable debug mode
--deletevm)
    Delete VM
--dhcp)
    Enable DHCP
--disk|rootdisk)
    Root disk
--dns|--nameserver)
    DNS/Nameserver address
--dockerarch)
    Docker architecture
--dryrun)
    Enable debug mode
--experimental*)
    SSH key
--extraargs)
    ISO Kernel extra args
--extragroup*)
    Extra groups
--firewall)
    Enable firewall
--nofirewall)
    Disable firewall
--firmware)
    Boot firmware type
--force)
    Enable force mode
--gateway)
    Gateway address
--gecos|--usergecos)
    GECOS field
--gfxmode)
    Bios text mode
--gfxpayload)
    Bios text mode
--help|-h)
    Print help information
--hostname)
    Hostname
--hwimports)
    Imports for system hardware configuration
--import)
    Import a Nix configuration
--imports)
    Imports for system configuration
--initmod*)
    Available system init modules
--install)
    Install script
--installdir)
    Install directory where destination disk is mounted
--ip)
    IP address
--isoextra*)
    ISO Kernel extra args
--isoimport)
    Import additional Nix configuration file into ISO configuration
--isoimports)
    NixOS imports for ISO build
--isokernelparam*)
    Extra kernel parameters to add to ISO grub commands
--isomount)
    Install ISO mount directory
--keymap)
    Keymap
--kernelparam*)
    Extra kernel parameters to add to systembuild
--kernel)
    Kernel
--locale)
    Locale
--logfile)
    Locale
--lvm)
    Enable LVM
--mask*)
    Enable LVM
--mbrpartname)
    MBR partition name
--nic)
    NIC
--nixconfig)
    NixOS configuration file
--nixdir)
    Set NixOS directory
--nixhwconfig)
    NixOS hardware configuration file
--nixinstall)
    Run NixOS install script automatically on ISO
--nixisoconfig)
    NixOS ISO configuration file
--oneshot)
    Enable oneshot service
--nooneshot)
    Disable oneshot service
--option*)
    Option(s) to set
--output*)
    Output file
--password|--userpassword)
    User password
--sshpasswordauthentication)
    Eanble SSH password authentication
--nosshpasswordauthentication)
    Disable SSH password authentication
--poweroff)
    Enable poweroff after install
--prefix)
    Install prefix
--preserve)
    Preserve output file
--reboot)
    Enable reboot after install
--rootcrypt)
    Root password crypt
--rootf*|--filesystem)
    Root Filesystem
--rootpassword)
    Root password
--rootpool)
    Root pool name
--rootsize)
    Root partition size
--rootvol*)
    Root volume name
--runsize)
    Run size
--serial)
    Enable serial
--shell|usershell)
    User Shell
--shellcheck)
    Run shellcheck
--source)
    Source directory for ISO additions
--sshkey)
    SSH key
--sshkeyfile)
    SSH key file
--sshserver)
    Enable strict mode
--standalone)
    Create a standalone ISO
--stateversion)
    NixOS state version
--strict)
    Enable strict mode
--sudocommand*)
    Sudo commands
--sudooption*)
    Sudo options
--sudouser*)
    Sudo users
--systempackages)
    NixOS state version
--swap)
    Enable swap
--swapsize)
    Swap partition size
--swapvol*)
    Swap volume name
--target)
    Target directory for ISO additions
--targetarch)
    Target architecture
--temp*)
    Target directory
--testmode)
    Enable swap
--usage)
    Action to perform
--username)
    User username
--verbose)
    Enable verbose mode
--version|-V)
    Print version information
--videodriver)
    Video Driver
--vmautoconsole)
    VM Autoconsole
--vmboot)
    VM Boot type
--vmcpu)
    VM CPU
--vmdir)
    VM Directory
--vmfeatures)
    VM Features
--vmhostdevice)
    VM Host device
--vmgraphics)
    VM Graphics
--vmiso|--vmcdrom)
    VM ISO
--vmmachine)
    VM Machine
--vmmemory)
    VM Memory
--vmname)
    VM Name
--vmnetwork)
    VM Network
--vmnoautoconsole)
    VM No autoconsole
--vmnoreboot)
    VM Do not reboot VM after creation
--vmreboot)
    VM Reboot VM after creation
--vmsize)
    VM Size
--vmosvariant)
    VM OS variant
--vmvirttype)
    VM Virtualisation type
--vmvcpus)
    VM vCPUs
--vmwait)
    VM number of seconds to wait before starting
--workdir)
    Set script work directory
--zfsinstall)
    ZFS install script
--zsh)
    Enable zsh
```

Options:

```
./manx.sh --usage options

Usage: manx.sh --action(s) [action(,action)] --option(s) [option(,option)]

option(s):
---------
zfsoptions (default = -O mountpoint=none -O atime=off -O compression=lz4 -O xattr=sa -O acltype=posixacl -o ashift=12)
   ZFS pool options
isoimports (default = <nixpkgs/nixos/modules/installer/cd-dvd/installation-cd-minimal-combined.nix> <nixpkgs/nixos/modules/installer/cd-dvd/channel.nix> <nixpkgs/nixos/modules/system/boot/loader/grub/grub.nix> <nixpkgs/nixos/modules/system/boot/kernel.nix>)
   ISO imports
imports (default = <nixpkgs/nixos/modules/system/boot/loader/grub/grub.nix> <nixpkgs/nixos/modules/system/boot/kernel.nix>)
   System imports
hwimports (default = )
   System hardware configuration imports
prefix (default = ai)
   Install directory prefix
verbose (default = false)
   Verbose mode
testmode (default = false)
   Test mode
strict (default = false)
   Strict mode
dryrun (default = false)
   Dryrun mode
debug (default = false)
   Debug mode
force (default = false)
   Force actions
mask (default = false)
   Mask identifiers
yes (default = false)
   Answer yes to questions
dhcp (default = true)
   DHCP network
swap (default = true)
   Use swap
lvm (default = false)
   Use LVM
zsh (default = true)
   Enable zsh
preserve (default = false)
   Preserve ISO
workdir (default = /Users/user/manx)
   Script work directory
sshkey (default = )
   SSH key
rootdisk (default = first)
   Disk
nic (default = first)
   NIC
zfs (default = true)
   ZFS filesystem
ext4 (default = false)
   EXT4 filesystem
locale (default = en_AU.UTF-8)
   Locale
timezone (default = Australia/Melbourne)
   Timezone
username (default = nixos)
   Username
userpassword (default = nixos)
   User Password
usercrypt (default = )
   User Password Crypt
hostname (default = nixos)
   Hostname
sshkeyfile (default = )
   SSH key file
bootfs (default = vfat)
   Boot filesystem
rootfs (default = zfs)
   Root filesystem
firmware (default = bios)
   Boot firmware type
bios (default = true)
   BIOS Boot firmware
uefi (default = false)
   UEFI Boot firmware
isomount (default = /iso)
   ISO mount directory
oneshot (default = true)
   Oneshot script
install (default = /Users/user/manx/ai/install.sh)
   Install script
nixisoconfig (default = /Users/user/manx/iso.nix)
   NixOS ISO config
zfsinstall (default = /Users/user/manx//zfs.sh)
   ZFS install script
extinstall (default = /Users/user/manx//ext4.sh)
   EXT4 install script
runsize (default = 50%)
   Run size
source (default = /Users/user/manx/ai)
   Source directory for ISO additions
target (default = /ai)
   Target directory for ISO additions
installdir (default = /mnt)
   Install directory
nixdir (default = /mnt/etc/nixos)
   NixOS directory for configs
nixconfig (default = /mnt/etc/nixos/configuration.nix)
   NixOS install config file
nixhwconfig (default = /mnt/etc/nixos/hardware-configuration.nix)
   NixOS install hardware config file
nixzfsconfig (default = /mnt/etc/nixos/zfs.nix)
   NixOS install ZFS config file
systemd-boot (default = true)
   systemd-boot
touchefi (default = true)
   Touch EFI
sshserver (default = true)
   Enable SSH server
swapsize (default = 2G)
   Swap partition size
rootsize (default = 100%)
   Root partition size
rootpool (default = rpool)
   Root pool name
rootpassword (default = nixos)
   Root password
rootcrypt (default = )
   Root password crypt
username (default = nixos)
   User Username
usergecos (default = nixos)
   User GECOS
usershell (default = zsh)
   User Shell
normaluser (default = true)
   Normal User
extragroups (default = wheel)
   Extra Groups
sudousers (default = nixos)
   Sudo Users
sudocommand (default = ALL)
   Sudo Command
sudooptions (default = NOPASSWD)
   Sudo Options
systempackages (default = aide ansible curl dmidecode efibootmgr file kernel-hardening-checker lsb-release lshw lynis pciutils vim wget)
   System Packages
experimental-features (default = nix-command flakes)
   Experimental Features
unfree (default = false)
   Allow Non Free Packages
stateversion (default = 25.05)
   State version
unattended (default = true)
   Execute install script
attended (default = false)
   Don't execute install script
reboot (default = true)
   Reboot after install
poweroff (default = true)
   Poweroff after install
nixinstall (default = true)
   Run Nix installer on ISO
gfxmode (default = auto)
   Grub graphics mode
gfxpayload (default = text)
   Grub graphics payload
networkmanager (default = true)
   Enable NetworkManager
xserver (default = false)
   Enable Xserver
keymap (default = au)
   Keymap
videodriver (default = )
   Video Driver
sddm (default = false)
   KDE Plasma Login Manager
plasma6 (default = false)
   KDE Plasma
gdm (default = false)
   Gnome Login Manager
gnome (default = false)
   Gnome
rootkit (default = false)
   Enable rootkit protection
bridge (default = false)
   Enable bridge
bridgenic (default = br0)
   Bridge NIC
ip (default = )
   IP Address
cidr (default = 24)
   CIDR
dns (default = 8.8.8.8)
   DNS/Nameserver address
gateway (default = )
   Gateway address
standalone (default = false)
   Package all requirements on ISO
rootvolname (default = nixos)
   Root volume name
bootvolname (default = boot)
   Boot volume name
mbrvolname (default = bootcode)
   Boot volume name
swapvolname (default = swap)
   Swap volume name
uefivolname (default = uefi)
   UEFI volume name
homevolname (default = home)
   Home volume name
nixvolname (default = nix)
   Nix volume name
usrvolname (default = usr)
   Usr volume name
varvolname (default = var)
   Var volume name
tempdir (default = /tmp)
   Temp directory
mbrpart (default = 1)
   MBR partition
rootpart (default = 2)
   Root partition
efipart (default = 3)
   UEFI/Boot partition
swappart (default = 4)
   Swap partition
devnodes (default = /dev/disk/by-uuid)
   Device nodesDevice nodes
logdir (default = /var/log)
   Install log dir
logfile (default = /var/log/install.log)
   Install log file
bootsize (default = 512M)
   Boot partition size
isokernelparams (default = )
   Additional kernel parameters to add to ISO grub commands
kernelparams (default = )
   Additional kernel parameters to add to system grub commands
isoextraargs (default = )
   Additional kernel config to add to ISO grub commands
extraargs (default = )
   Additional kernel config to add to system grub commands
availmods (default = "ahci" "xhci_pci" "virtio_pci" "sr_mod" "virtio_blk")
   Available system kernel modules
initmods (default = )
   Available system init modules
bootmods (default = )
   Available system boot modules
oneshot (default = true)
   Enable oneshot service
serial (default = true)
   Enable serial
kernel (default = )
   Kernel
sshpasswordauthentication (default = false)
   SSH Password Authentication
firewall (default = true)
   Enable firewall
allowedtcpports (default = 22)
   Allowed TCP ports
allowedudpports (default = )
   Allowed UDP ports
import (default = )
   Import Nix config to add to system build
isoimport (default = )
   Import Nix config to add to ISO build
dockerarch (default = arm64)
   Docker architecture
targetarch (default = arm64)
   Target architecture
createdockeriso (default = false)
   Create ISO using docker
```
