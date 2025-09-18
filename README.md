![Manx cat](manx.jpg)

MANX
----

Manage/Automate NiXOS


Version
-------

Current version: 0.4.5

License
-------

CC BY-SA: https://creativecommons.org/licenses/by-sa/4.0/

Fund me here: https://ko-fi.com/richardatlateralblast


Introduction
------------

A script to an make an automated NiXOS installation.

By default this script creates an unattended install ISO
with a ZFS root filesystem

Features
--------

This script has the following capabilities:

Status
------

This script is in the early stages of development

Help
----

General Usage:

```
./manx.sh --help

Usage: manx.sh --action(s) [action(,action)] --option(s) [option(,option)]

switch(es):
---------
--action*)              
    Action to perform
--createinstall*)       
    Create install script
--createiso)            
    Create ISO
--createnix*)           
    Create ISO
--createzfsinstall*)    
    Create ZFS install script
--debug)                
    Enable debug mode
--dryrun)               
    Enable debug mode
--experimental*)        
    SSH key
--extragroup*)          
    Extra groups
--force)                
    Enable force mode
--help|-h)              
    Print help information
--install)              
    Install script
--nixconfig)            
    Set Nix ISO configuration
--nixdir)               
    Set Nix directory
--option*)              
    Action to perform
--password)             
    User password
--prefix)               
    Install prefix
--runsize)              
    Run size
--shell)                
    User Shell
--source)               
    Source directory
--sshkey)               
    SSH key
--sshkeyfile)           
    SSH key file
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
--target)               
    Target directory
--usage)                
    Action to perform
--username)             
    User username
--verbose)              
    Enable verbos e mode
--version|-V)           
    Print version information
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
    Create ISO
createzfs*)           
    Create ZFS install script
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
nixdir (default = /home/user/nix)
   Nix work directory
sshkey (default = )
   SSH key
language (default = en_AU.UTF-8)
   Language
timezone (default = Australia/Melbourne)
   Timezone
username (default = nixos)
   Username
password (default = nixos)
   Password
sshkeyfile (default = )
   SSH key file
install (default = /home/user/nix/ai/install.sh)
   Install script
nixconfig (default = /home/user/nix/iso.nix)
   Nix ISO config
zfsinstall (default = /home/user/nix/ai/zfs.sh)
   ZFS install script
cdimage (default = <nixpkgs/nixos/modules/installer/cd-dvd/installation-cd-minimal.nix>)
   Nix installation
channel (default = <nixpkgs/nixos/modules/installer/cd-dvd/channel.nix>)
   Nix channel
runsize (default = 50%)
   Run size
prefix (default = ai)
   Install directory prefix
source (default = /home/user/nix/ai)
   Source directory
target (default = /ai)
   Target directory
systemd-boot (default = true)
   systemd-boot
touchefi (default = true)
   Touch EFI
sshserver (default = true)
   Enable SSH server
username (default = nixos)
   User Username
password (default = nixos)
   User Password
shell (default = bash)
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
systempackages (default = vim git efibootmgr zsh)
   System Packages
experimental-features (default = nix-command flakes)
   Experimental Features
unfree (default = true)
   Allow Non Free Packages
stateversion (default = 25.05)
   State version
```
