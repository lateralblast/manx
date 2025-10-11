![Manx cat](manx.jpg)

MANX
----

Make Automated NixOS (ISO)


Version
-------

Current version: 1.6.4

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

I have tried to aim for having security enabled by default.
This is to reduce the vectors of attack during and after the
OS installation.

Currently SSH and systemd security profiles have been enabled
for the boot CD and the system. SSH is enabled with only keys
by default, and SSH to the installation process is by via the
nixos account rather than the root account. Although sudo from
nixos to root does not require a password currently, but as
previously stated logging into the nixos account via SSH
requires the ISO to be built with SSH keys installed.
This can be changed by rebuilding the ISO or editing the
grub boot parameters.

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

By default if you don't specify an interface, even if you specify an IP,
the installer will use DHCP for the install phase. For the system build
phase if you haven't specified and interface it will look for the first
available interface and configure that interface with the IP specified.

If you specified an IP with an interface, then the install phase will
not use DHCP, and assign the IP to that interface for the install phase.

If you wish to have a different user to access the system during the
install phase you can use the --installuser switch, which will add that
user to the install phase and only allow that user to SSH into the
machine during the install phase. The default nixos user exists, but
you will not be able to SSH in as this user during the install phase.

By default serial console is enabled allowing console only KVM install.
By default ttyS0 is used for serial console. You may need to change this
for console redirection over IME/AMT or IPMI, for example by default
console redirection over IPMI on iDRAC etc goes via ttyS1, in which
case you will need to specify --serialtty ttyS1 as an option.

Status
------

This script is in the early stages of development

To-do:

- Add support for pass-thru PCIe devices

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
(this will create a VM with the default name and the ISO generated above)

```
./manx.sh --createvm
```

This will give you information about starting and connecting to VM, etc:

```
sudo virsh start manx ; sudo virsh console manx
```

To delete the VM created:

```
./manx.sh --deletevm
```

Create an ISO using docker on MacOS:

```
./manx.sh --createdockeriso
```

To boot from disk and connect to console:

```
./manx.sh --bootfromdisk --options console
```

Help
----

General Usage:

```
./manx.sh --help

Usage: manx.sh --action(s) [action(,action)] --option(s) [option(,option)]

switch(es):
-----------
--action*)
    Action(s) to perform
--addiso|--addcdrom)
    Add cdrom to VM
--audit)
    Enable auditing
--removeiso|--removecdrom)
    Remove cdrom from VM
--allowedtcpports)
    Allowed TCP ports
--allowedudpports)
    Allowed UDP ports
--allowagentforwarding)
    SSH allow agent forwarding
--allowsimultaneousmultithreading)
    SSH allow TCP forwarding
--allowtcpforwarding)
    SSH allow TCP forwarding
--allowusers)
    SSH allow users
--availmod*)
    Available system kernel modules
--bantime)
    fail2ban ban time
--bantimeincrement)
    Enable fail2ban ban time increment
--nobantimeincrement)
    Enable fail2ban ban time increment
--blacklist)
    Blacklist modules
--bootfromdisk)
    Boot VM from disk
--bootfromiso|--bootfromcdrom)
    Boot VM from CDROM
--bootmod*)
    Available system boot modules
--bootsize)
    Boot partition size
--bootvm|--startvm)
    Boot VM
--stopvm)
    Stop VM
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
--ciphers)
    SSH ciphers
--clientaliveinterval)
    SSH client alive interval
--clientalivecountmax)
    SSH client alive count max
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
--console*)
    Create oneshot script
--crypt|--usercrypt)
    User Password Crypt
--dbusimplementation)
    Dbus implementation
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
--execwheelonly)
    Sudo exec wheel only
--experimental*)
    SSH key
--extragroup*)
    Extra groups
--fail2ban)
    Enable fail2ban
--nofail2ban)
    Disable fail2ban
--firewall)
    Enable firewall
--nofirewall)
    Disable firewall
--firmware)
    Boot firmware type
--force)
    Enable force mode
--forcepagetableisolation)
    Force page table isolation
--noforcepagetableisolation)
    Don't force page table isolation
--fwupd)
    Enable fwupd
--nofwupd)
    Disable fwupd
--gateway)
    Gateway address
--gecos|--usergecos)
    GECOS field
--gfxmode)
    Bios text mode
--gfxpayload)
    Bios text mode
--grubextra*)
    ISO grub extra config
--help|-h)
    Print help information
--hostkeyspath)
    SSH host keys path
--hostkeystype)
    SSH host keys type
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
--installscript)
    Install script
--installdir)
    Install directory where destination disk is mounted
--installuser*)
    Install username
--interactive)
    Enable Interactive mode
--nointeractive)
    Disable Interactive mode
--ip)
    IP address
--ipaddressdeny)
    systemd IP address deny
--isogrubextra*)
    ISO grub extra config
--isoimport)
    Import additional Nix configuration file into ISO configuration
--isoimports)
    NixOS imports for ISO build
--isokernelparam*)
    Extra kernel parameters to add to ISO grub commands
--isomount)
    Install ISO mount directory
--isopermitrootlogin)
    Enable SSH root login for ISO
--journaldextra*)
    System journald extra config
--journalupload)
    Enable remote log upload
--nojournalupload)
    Disable remote log upload
--kbdinteractiveauthentication)
    Enable SSH allow interactive kerboard authentication
--nokbdinteractiveauthentication)
    Disable SSH allow interactive kerboard authentication
--keymap)
    Keymap
--kernelparam*)
    Extra kernel parameters to add to systembuild
--kernel)
    Kernel
--kexalgorithms)
    SSH key exchange algorithms
--locale)
    Locale
--logfile)
    Locale
--loglevel)
    SSH log level
--logrotate)
    Enable logrotate
--nologrotate)
    Enable logrotate
--lockkernelmodules)
    Lock kernel modules
--nolockkernelmodules)
    Don't lock kernel modules
--lockpersonality)
    Enable systemd lock personality
--nolockpersonality)
    Disable systemd lock personality
--lvm)
    Enable LVM
--macs)
    SSH macs
--mask*)
    Enable LVM
--maxauthtries)
    SSH max auth tries
--maxretry)
    fail2ban max retry
--maxtime)
    fail2ban bantime maximum
--memorydenywriteexecute)
    Enable systemd memory deny write execute
--nomemorydenywriteexecute)
    Disable systemd memory deny write execute
--mbrpartname)
    MBR partition name
--multipliers)
    fail2ban ban time multipliers
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
--nonewprivileges)
    Enable systemd no new privileges
--newprivileges)
    Disable systemd no new privileges
--oneshot)
    Enable oneshot service
--nooneshot)
    Disable oneshot service
--option*)
    Option(s) to set
--output*|--iso)
    Output file
--overalljails)
    fail2ban bantime overalljails
--password|--userpassword)
    User password
--passwordauthentication)
    Enable SSH password authentication
--nopasswordauthentication)
    Disable SSH password authentication
--permitemptypasswords)
    Enable SSH empty passwords
--permitrootlogin)
    Enable SSH root login
--poweroff)
    Enable poweroff after install
--prefix)
    Install prefix
--preserve)
    Preserve output file
--privatetmp)
    Enable systemd private tmp
--noprivatetmp)
    Disable systemd private tmp
--privatenetwork)
    Enable systemd private network
--noprivatenetwork)
    Disable systemd private network
--processgrub*)
    Enable processing grub command line
--noprocessgrub*)
    Disable processing grub command line
--protectclock)
    Enable systemd protect clock
--noprotectclock)
    Disable systemd protect clock
--protectcontrolgroups)
    Enable systemd protect control groups
--noprotectcontrolgroups)
    Disable systemd protect control groups
--protecthome)
    Enable systemd protect home
--noprotecthome)
    Disable systemd protect home
--protecthostname)
    Enable systemd protect hostname
--noprotecthostname)
    Disable systemd protect hostname
--protectkernelimage)
    Protect kernel image
--noprotectkernelimage)
    Don't protect kernel image
--protectkernelmodules)
    Enable systemd protect kernel modules
--noprotectkernelmodules)
    Disable systemd protect kernel modules
--protectkerneltunables)
    Enable systemd protect kernel tunables
--noprotectkerneltunables)
    Disable systemd protect kernel tunables
--protectproc)
    systemd protect proc
--protectsubset)
    systemd protect subset
--protectsystem)
    systemd protect system
--reboot)
    Enable reboot after install
--restrictrealtime)
    Enable systemd restrict realtime
--norestrictrealtime)
    Disable systemd restrict realtime
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
--secure)
    Enable secure parameters
--serial)
    Enable serial
--serialparity)
    Serial parity
--serialport)
    Serial port
--serialspeed)
    Serial speed
--serialstop)
    Serial stop
--serialtty)
    Serial tty
--serialunit)
    Serial unit
--serialword)
    Serial stop
--setboot*)
    Set boot device
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
--suffix|--outputsuffix)
    Sudo users
--systemdumask)
    Systemd umask
--systempackages)
    NixOS state version
--systemcallarchitectures)
    Systemd call architectures
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
--unprivilegedusernsclone)
    Disable unprivileged user namespaces
--unstable)
    Enable unstable features
--stable)
    Disable unstable features
--usage)
    Action to perform
--usedns)
    SSH use DNS
--usepres*)
    Use preserved ISO
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
--x11forwarding)
    Enable SSH X11 forwarding
--nox11forwarding)
    Disable SSH X11 forwarding
--zfsinstall)
    ZFS install script
--zsh)
    Enable zsh--action*)
    Action(s) to perform
--addiso|--addcdrom)
    Add cdrom to VM
--audit)
    Enable auditing
--removeiso|--removecdrom)
    Remove cdrom from VM
--allowedtcpports)
    Allowed TCP ports
--allowedudpports)
    Allowed UDP ports
--allowagentforwarding)
    SSH allow agent forwarding
--allowsimultaneousmultithreading)
    SSH allow TCP forwarding
--allowtcpforwarding)
    SSH allow TCP forwarding
--allowusers)
    SSH allow users
--availmod*)
    Available system kernel modules
--bantime)
    fail2ban ban time
--bantimeincrement)
    Enable fail2ban ban time increment
--nobantimeincrement)
    Enable fail2ban ban time increment
--blacklist)
    Blacklist modules
--bootfromdisk)
    Boot VM from disk
--bootfromiso|--bootfromcdrom)
    Boot VM from CDROM
--bootmod*)
    Available system boot modules
--bootsize)
    Boot partition size
--bootvm|--startvm)
    Boot VM
--stopvm)
    Stop VM
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
--ciphers)
    SSH ciphers
--clientaliveinterval)
    SSH client alive interval
--clientalivecountmax)
    SSH client alive count max
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
--console*)
    Create oneshot script
--crypt|--usercrypt)
    User Password Crypt
--dbusimplementation)
    Dbus implementation
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
--execwheelonly)
    Sudo exec wheel only
--experimental*)
    SSH key
--extragroup*)
    Extra groups
--fail2ban)
    Enable fail2ban
--nofail2ban)
    Disable fail2ban
--firewall)
    Enable firewall
--nofirewall)
    Disable firewall
--firmware)
    Boot firmware type
--force)
    Enable force mode
--forcepagetableisolation)
    Force page table isolation
--noforcepagetableisolation)
    Don't force page table isolation
--fwupd)
    Enable fwupd
--nofwupd)
    Disable fwupd
--gateway)
    Gateway address
--gecos|--usergecos)
    GECOS field
--gfxmode)
    Bios text mode
--gfxpayload)
    Bios text mode
--grubextra*)
    ISO grub extra config
--help|-h)
    Print help information
--hostkeyspath)
    SSH host keys path
--hostkeystype)
    SSH host keys type
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
--installscript)
    Install script
--installdir)
    Install directory where destination disk is mounted
--installuser*)
    Install username
--interactive)
    Enable Interactive mode
--nointeractive)
    Disable Interactive mode
--ip)
    IP address
--ipaddressdeny)
    systemd IP address deny
--isogrubextra*)
    ISO grub extra config
--isoimport)
    Import additional Nix configuration file into ISO configuration
--isoimports)
    NixOS imports for ISO build
--isokernelparam*)
    Extra kernel parameters to add to ISO grub commands
--isomount)
    Install ISO mount directory
--isopermitrootlogin)
    Enable SSH root login for ISO
--journaldextra*)
    System journald extra config
--journalupload)
    Enable remote log upload
--nojournalupload)
    Disable remote log upload
--kbdinteractiveauthentication)
    Enable SSH allow interactive kerboard authentication
--nokbdinteractiveauthentication)
    Disable SSH allow interactive kerboard authentication
--keymap)
    Keymap
--kernelparam*)
    Extra kernel parameters to add to systembuild
--kernel)
    Kernel
--kexalgorithms)
    SSH key exchange algorithms
--locale)
    Locale
--logfile)
    Locale
--loglevel)
    SSH log level
--logrotate)
    Enable logrotate
--nologrotate)
    Enable logrotate
--lockkernelmodules)
    Lock kernel modules
--nolockkernelmodules)
    Don't lock kernel modules
--lockpersonality)
    Enable systemd lock personality
--nolockpersonality)
    Disable systemd lock personality
--lvm)
    Enable LVM
--macs)
    SSH macs
--mask*)
    Enable LVM
--maxauthtries)
    SSH max auth tries
--maxretry)
    fail2ban max retry
--maxtime)
    fail2ban bantime maximum
--memorydenywriteexecute)
    Enable systemd memory deny write execute
--nomemorydenywriteexecute)
    Disable systemd memory deny write execute
--mbrpartname)
    MBR partition name
--multipliers)
    fail2ban ban time multipliers
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
--nonewprivileges)
    Enable systemd no new privileges
--newprivileges)
    Disable systemd no new privileges
--oneshot)
    Enable oneshot service
--nooneshot)
    Disable oneshot service
--option*)
    Option(s) to set
--output*|--iso)
    Output file
--overalljails)
    fail2ban bantime overalljails
--password|--userpassword)
    User password
--passwordauthentication)
    Enable SSH password authentication
--nopasswordauthentication)
    Disable SSH password authentication
--permitemptypasswords)
    Enable SSH empty passwords
--permitrootlogin)
    Enable SSH root login
--poweroff)
    Enable poweroff after install
--prefix)
    Install prefix
--preserve)
    Preserve output file
--privatetmp)
    Enable systemd private tmp
--noprivatetmp)
    Disable systemd private tmp
--privatenetwork)
    Enable systemd private network
--noprivatenetwork)
    Disable systemd private network
--processgrub*)
    Enable processing grub command line
--noprocessgrub*)
    Disable processing grub command line
--protectclock)
    Enable systemd protect clock
--noprotectclock)
    Disable systemd protect clock
--protectcontrolgroups)
    Enable systemd protect control groups
--noprotectcontrolgroups)
    Disable systemd protect control groups
--protecthome)
    Enable systemd protect home
--noprotecthome)
    Disable systemd protect home
--protecthostname)
    Enable systemd protect hostname
--noprotecthostname)
    Disable systemd protect hostname
--protectkernelimage)
    Protect kernel image
--noprotectkernelimage)
    Don't protect kernel image
--protectkernelmodules)
    Enable systemd protect kernel modules
--noprotectkernelmodules)
    Disable systemd protect kernel modules
--protectkerneltunables)
    Enable systemd protect kernel tunables
--noprotectkerneltunables)
    Disable systemd protect kernel tunables
--protectproc)
    systemd protect proc
--protectsubset)
    systemd protect subset
--protectsystem)
    systemd protect system
--reboot)
    Enable reboot after install
--restrictrealtime)
    Enable systemd restrict realtime
--norestrictrealtime)
    Disable systemd restrict realtime
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
--secure)
    Enable secure parameters
--serial)
    Enable serial
--serialparity)
    Serial parity
--serialport)
    Serial port
--serialspeed)
    Serial speed
--serialstop)
    Serial stop
--serialtty)
    Serial tty
--serialunit)
    Serial unit
--serialword)
    Serial stop
--setboot*)
    Set boot device
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
--suffix|--outputsuffix)
    Sudo users
--systemdumask)
    Systemd umask
--systempackages)
    NixOS state version
--systemcallarchitectures)
    Systemd call architectures
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
--unprivilegedusernsclone)
    Disable unprivileged user namespaces
--unstable)
    Enable unstable features
--stable)
    Disable unstable features
--usage)
    Action to perform
--usedns)
    SSH use DNS
--usepres*)
    Use preserved ISO
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
--x11forwarding)
    Enable SSH X11 forwarding
--nox11forwarding)
    Disable SSH X11 forwarding
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
audit (default = true)
   Auditd parameters
auditrules (default = )
   Auditd parameters
kernelparams (default = )
   Additional kernel parameters to add to system grub commands
zfsoptions (default = -O mountpoint=none -O atime=off -O compression=lz4 -O xattr=sa -O acltype=posixacl -o ashift=12)
   ZFS options
isosystempackages (default = aide ansible btop curl dmidecode efibootmgr ethtool file fwupd git kernel-hardening-checker lsb-release lsof lshw lynis nmap pciutils ripgrep rclone tmux usbutils vim wget)
   ISO system packages
isostorepackages (default = aide ansible btop curl dmidecode efibootmgr ethtool file fwupd git kernel-hardening-checker lsb-release lsof lshw lynis nmap pciutils ripgrep rclone tmux usbutils vim wget)
   ISO store packages
systempackages (default = aide ansible btop curl dmidecode efibootmgr ethtool file fwupd git kernel-hardening-checker lsb-release lsof lshw lynis nmap pciutils ripgrep rclone tmux usbutils vim wget)
   System packages
blacklist (default = dccp sctp rds tipc n-hdlc ax25 netrom x25 rose decnet econet af_802154 ipx appletalk psnap p8023 p8022 can atm cramfs freevxfs jffs2 hfs hfsplus udf)
   Blacklisted kernel modules
availmods (default = ahci ehci_pci megaraid_sas sdhci_pci sd_mod sr_mod usbhid usb_storage virtio_blk virtio_pci xhci_pci)
   Available kernel modules
serialspeed (default = 115200)
   Serial speed
serialunit (default = 0)
   Serial unit
serialword (default = 8)
   Serial word
serialparity (default = no)
   Serial parity
serialstop (default = 1)
   Serial stop
serialport (default = 0x02f8)
   Serial port
serialtty (default = ttyS0)
   Serial TTY
isokernelparams (default = )
   Additional kernel parameters to add to ISO grub commands
kernelparams (default = )
   Additional kernel parameters to add to system grub commands
serialkernelparams (default = )
   Serial kernel params
serialextraconfig (default = )
   Serial extra args
isoimports (default = <nixpkgs/nixos/modules/installer/cd-dvd/installation-cd-minimal-combined.nix> <nixpkgs/nixos/modules/installer/cd-dvd/channel.nix> <nixpkgs/nixos/modules/system/boot/loader/grub/grub.nix> <nixpkgs/nixos/modules/system/boot/kernel.nix>)
   ISO imports
imports (default = <nixpkgs/nixos/modules/system/boot/loader/grub/grub.nix> <nixpkgs/nixos/modules/system/boot/kernel.nix>)
   System imports
kexalgorithms (default = curve25519-sha256@libssh.org ecdh-sha2-nistp521 ecdh-sha2-nistp384 ecdh-sha2-nistp256 diffie-hellman-group-exchange-sha256)
   SSH Key Exchange Algorithms
ciphers (default = chacha20-poly1305@openssh.com aes256-gcm@openssh.com aes128-gcm@openssh.com aes256-ctr aes192-ctr aes128-ctr)
   SSH Ciphers
macs (default = hmac-sha2-512-etm@openssh.com hmac-sha2-256-etm@openssh.com umac-128-etm@openssh.com hmac-sha2-512 hmac-sha2-256 umac-128@openssh.com)
   SSH Macs
ignoreip (default = 172.16.0.0/12 192.168.0.0/16)
   fail2ban ignore ip
journaldextraconfig (default = SystemMaxUse=500M SystemMaxFileSize=50M)
   Journald extra config
journaldupload (default = false)
   Journald remote log upload
fwupd (default = true)
   Enable fwupd
secure (default = true)
   Enable secure parameters
sysctl (default = )
   System sysctl parameters
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
installuser (default = nixos)
   Install username
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
oneshotscript (default = /Users/user/manx/ai/oneshot.sh)
   Oneshot script
installscript (default = /Users/user/manx/ai/install.sh)
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
rootsize (default = 100%FREE)
   Root partition size
rootpool (default = rpool)
   Root pool name
rootpassword (default = nixos)
   Root password
rootcrypt (default = )
   Root password crypt
username (default = nixos)
   User Username
usergecos (default = Admin)
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
isogrubextraconfig (default = )
   Additional kernel config to add to ISO grub commands
grubextraconfig (default = )
   Additional kernel config to add to system grub commands
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
passwordauthentication (default = false)
   SSH Password Authentication
permitemptypasswords (default = false)
   SSH permit empty passwords
permittunnel (default = false)
   SSH permit tunnel
usedns (default = false)
   SSH use DNS
kbdinteractiveauthentication (default = false)
   SSH allow interactive kerboard authentication
x11forwarding (default = false)
   SSH allow X11 forwarding
maxauthtries (default = 3)
   SSH max auth tries
maxsessions (default = 2)
   SSH max sessions
clientaliveinterval (default = 300)
   SSH client alive interval
clientalivecountmax (default = 0)
   SSH client alive max count
firewall (default = true)
   Enable firewall
allowedtcpports (default = 22)
   Allowed TCP ports
allowedudpports (default = )
   Allowed UDP ports
allowusers (default = nixos)
   SSH allow user
allowtcpforwarding (default = false)
   SSH allow TCP forwarding
allowagentforwarding (default = false)
   SSH allow agent forwarding
permitrootlogin (default = no)
   SSH permit root login
isopermitrootlogin (default = no)
   SSH permit root login for install
loglevel (default = VERBOSE)
   SSH log level
hostkeystype (default = ed25519)
   SSH hosts keys type
hostkeyspath (default = /etc/ssh/ssh_host_ed25519_key)
   SSH hosts key type
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
console (default = false)
   Enable console in actions
suffix (default = )
   Output file suffix
fail2ban (default = true)
   Enable fail2ban
maxretry (default = 5)
   fail2ban max retry
bantime (default = 1h)
   fail2ban ban time
bantimeincrement (default = true)
   fail2ban ban time increment
multipliers (default = 1 2 4 8 16 32 64 128 256)
   fail2ban ban time multipliers
maxtime (default = 1h)
   fail2ban max time
overalljails (default = true)
   Enable fail2ban overalljails
protectkernelimage (default = true)
   Protect kernel image
lockkernelmodules (default = false)
   Lock kernel modules
allowusernamespaces (default = true)
   Allow user name spaces
forcepagetableisolation (default = true)
   Force page table isolation
unprivilegedusernsclone (default = config.virtualisation.containers.enable)
   Disable unprivileged user namespaces
allowsimultaneousmultithreading (default = true)
   Allow SMT
dbusimplementation (default = broker)
   Dbus implementation
execwheelonly (default = true)
   Sudo exec wheel only
systemdumask (default = 0077)
   systemd umask
privatenetwork (default = true)
   systemd private network
protecthostname (default = true)
   systemd protect hostname
protectkernelmodules (default = true)
   systemd protect kernel modules
protectsystem (default = strict)
   systemd protect system
protecthome (default = true)
   systemd protect home
protectkerneltunables (default = true)
   systemd protect kernel tunables
protectcontrolgroups (default = true)
   systemd protect control groups
protectclock (default = true)
   systemd protect clock
protectproc (default = invisible)
   systemd protect proc
procsubset (default = pid)
   systemd protect kernel modules
privatetmp (default = true)
   systemd private tmp
memorydenywriteexecute (default = true)
   systemd deny write execute
nownewprivileges (default = true)
   systemd no new privileges
lockpersonality (default = true)
   systemd lock personality
restrictrealtime (default = true)
   systemd restrict realtime
systemcallarchitectures (default = native)
   systemd system call architectures
ipaddressdeny (default = any)
   systemd IP address deny
usepreservediso (default = false)
   Use preserved ISO
processgrub (default = true)
   Process grub command line
logrotate (default = true)
   Log rotate
unstable (default = false)
   Enable unstable features/packages
interactive (default = false)
   Interactive mode
```
