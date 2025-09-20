![Manx cat](manx.jpg)

MANX
----

Manage/Automate NiXOS


Version
-------

Current version: 0.5.3

License
-------

CC BY-SA: https://creativecommons.org/licenses/by-sa/4.0/

Fund me here: https://ko-fi.com/richardatlateralblast


Introduction
------------

A script to an make an automated NiXOS installation.

By default this script creates an unattended install ISO
with a ZFS root filesystem.

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
  - Specify:
    - Language
    - Timezone
    - Keymap
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

- Add install options to grub menu rather than having to create a specific ISO
  - ZFS install
  - EXT4 install
  - Attended/Unattended (e.g. manual run of install script and/or reboot)
- Add other filesystem options
- Add support for pass-thru PCIe devices

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

Help
----

General Usage:

```
./manx.sh --help

Usage: manx.sh --action(s) [action(,action)] --option(s) [option(,option)]

switch(es):
---------
--action*)              
    Action(s) to perform
--bootpool)             
    Boot pool name
--bridge)               
    Enable bridge
--bridgenic)            
    Bridge NIC
--bootvol*)             
    Boot volume name
--cidr)                 
    CIDR
--createext*)           
    Create EXT4 install script
--createinstall*)       
    Create install script
--createiso)            
    Create ISO
--createnix*)           
    Create NIX ISO config
--createzfsinstall*)    
    Create ZFS install script
--usercrypt|--crypt)    
    User Password Crypt
--debug)                
    Enable debug mode
--dryrun)               
    Enable debug mode
--disk)                 
    SSH key
--dns|--nameserver)     
    DNS/Nameserver address
--experimental*)        
    SSH key
--extragroup*)          
    Extra groups
--filesystem*)          
    Root Filesystem
--firmware)             
    Boot firmware type
--force)                
    Enable force mode
--gecos)                
    GECOS field
--help|-h)              
    Print help information
--hostname)             
    Hostname
--install)              
    Install script
--ip)                   
    IP address
--isoimports)           
    Nixos imports for ISO build
--keymap)               
    Keymap
--nic)                  
    NIC
--nixconfig)            
    Nix configuration file
--nixhwconfig)          
    Nix hardware configuration file
--nixisoconfig)         
    Nix ISO configuration file
--nixzfsconfig)         
    Nix ZFS configuration file
--nixdir)               
    Set Nix directory
--option*)              
    Option(s) to set
--password|--userpassword)  
    User password
--prefix)               
    Install prefix
--rootcrypt)            
    Root password crypt
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
--shell)                
    User Shell
--shellcheck)           
    Run shellcheck
--source)               
    Source directory
--sshkey)               
    SSH key
--sshkeyfile)           
    SSH key file
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
--swapsize)             
    Swap partition size
--swapvol*)             
    Swap volume name
--target)               
    Target directory
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
--workdir)              
    Set Nix work directory
--zfsinstall)           
    ZFS install script
```

Actions:

```
./manx.sh --usage actions

Usage: manx.sh --action(s) [action(,action)] --option(s) [option(,option)]

action(s):
---------
createinstall*)       
    Create install script
createiso)            
    Create ISO
createnix*)           
    Create Nix ISO config
createzfs*)           
    Create ZFS install script
createext*)           
    Create EXT4 install script
help)                 
    Print actions help
printenv*)            
    Print environment
printdefaults)        
    Print defaults
shellcheck)           
    Shellcheck script
version)              
    Print version
```

Options:

```
./manx.sh --usage options

Usage: manx.sh --action(s) [action(,action)] --option(s) [option(,option)]

option(s):
---------
isoimports (default = <nixpkgs/nixos/modules/installer/cd-dvd/installation-cd-minimal-combined.nix> <nixpkgs/nixos/modules/installer/cd-dvd/channel.nix>)
   - ISO imports
verbose (default = false)
   Verbose mode
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
workdir (default = /home/user/manx)
   Nix work directory
sshkey (default = )
   SSH key
disk (default = first)
   Disk
nic (default = first)
   NIC
zfs (default = false)
   ZFS filesystem
ext4 (default = true)
   EXT4 filesystem
language (default = en_AU.UTF-8)
   Language
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
filesystem (default = ext4)
   Root filesystem
firmware (default = bios)
   Boot firmware type
bios (default = true)
   BIOS Boot firmware
uefi (default = false)
   UEFI Boot firmware
install (default = /home/user/manx/ai/install.sh)
   Install script
nixisoconfig (default = /home/user/manx/iso.nix)
   Nix ISO config
zfsinstall (default = /home/user/manx/ai/zfs.sh)
   ZFS install script
extinstall (default = /home/user/manx/ai/ext4.sh)
   EXT4 install script
runsize (default = 50%)
   Run size
prefix (default = ai)
   Install directory prefix
source (default = /home/user/manx/ai)
   Source directory
target (default = /ai)
   Target directory
nixdir (default = /mnt/etc/nixos)
   NIX directory
nixconfig (default = /mnt/etc/nixos/configuration.nix)
   NIX install config file
nixhwconfig (default = /mnt/etc/nixos/hardware-configuration.nix)
   NIX install hardware config file
nixzfsconfig (default = /mnt/etc/nixos/zfs.nix)
   NIX install ZFS config file
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
bootpool (default = bpool)
   Boot pool name
rootpool (default = rpool)
   Root pool name
rootpassword (default = nixos)
   Root password
rootcrypt (default = )
   Root password crypt
username (default = nixos)
   User Username
gecos (default = nixos)
   User GECOS
shell (default = zsh)
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
systempackages (default = curl dmidecode efibootmgr file lsb-release lshw pciutils vim wget)
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
zsh (default = true)
   Enable zsh
installdir (default = /mnt)
   Install directory
rootvolname (default = nixos)
   Root volume name
bootvolname (default = boot)
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

```
