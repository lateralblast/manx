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
ai['reboot']="false"
ai['poweroff']="true"
ai['attended']="true"
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
ai['rootsize']="100%"
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
ai['usergecos']="nixos"
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
ai['availmods']='"ahci" "xhci_pci" "virtio_pci" "sr_mod" "virtio_blk"'
ai['initmods']=''
ai['bootmods']=''
ai['experimental-features']="nix-command flakes"
ai['unfree']="false"
ai['gfxmode']="text"
ai['gfxpayload']="text"
ai['nic']="first"
ai['dns']="8.8.8.8"
ai['ip']=""
ai['gateway']=""
ai['cidr']="24"
ai['sshkey']="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICl7w06accD5PJuQYiqpGiZBAsK82W4CVibaQ0kJsYq2 spindler@nixos"

# Parse parameters
echo "Processing parameters"
for param in ${!ai[@]}
do
  echo "Setting ${param} to ${ai[${param}]}"
done

# Parse grub parameters
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
ai['zfsoptions']="${ai['zfsoptions']} -R ${ai['installdir']}"
echo "Setting zfsoptions to ${ai['zfsoptions']}"
# Set up non DHCP environment
if [ "${ai['dhcp']}" = "false" ]; then
  if [ "${ai['nic']}" = "first" ]; then
    ai['nic']=$( ip link | grep "state UP" | awk '{ print $2}' | head -1 | grep ^e | cut -f1 -d: )
    echo "Setting nic to ${ai['nic']}"
  fi
fi

# Discover first disk
if [ "${ai['rootdisk']}" = "first" ]; then
  ai['rootdisk']=$( lsblk -x TYPE|grep disk |sort |head -1 |awk '{print $1}' )
  ai['rootdisk']="/dev/${ai['rootdisk']}"
  echo "Setting rootdisk to ${ai['rootdisk']}"
fi

# Check we are using only one volume manager
if [ "${ai['lvm']}" = "true" ] && [ "${ai['rootfs']}" = "zfs" ]; then
  echo "Cannot use two volume managers (LVM and ZFS)"
  exit
fi

# QEMU check
qemu_check=$( cat /proc/ioports |grep QEMU )
if [ -n "${qemu_check}" ]; then
  if [ "${ai['bootmods']}" = "" ]; then
    ai['bootmods']="\"kvm-intel\""
  else
    ai['bootmods']="${ai['bootmods']} \"kvm-intel\""
  fi
  echo "Setting bootmods to ${ai['bootmods']}"
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
  pvcreate -f ${ai['rootdisk']}${ai['rootpart']}
  vgcreate -f ${ai['rootpool']} ${ai['rootdisk']}${ai['rootpart']}
  lvcreate -y --size ${ai['bootsize']} --name ${ai['bootvolname']} ${ai['rootpool']}
  if [ "${USE_SWAP}" = "true" ]; then
    lvcreate -y --size ${ai['swapsize']} --name ${ai['swapvolname']} ${ai['rootpool']}
  fi
  lvcreate -y --size ${ai['rootsize']} --name ${ai['rootvolname']} ${ai['rootpool']}
  ai['swapvol']="/dev/${ai['rootpool']}/${ai['swapvolname']}"
  ai['bootvol']="/dev/${ai['rootpool']}/${ai['bootvolname']}"
  ai['rootvol']="/dev/${ai['rootpool']}/${ai['rootvolname']}"
  lvextend -l +100%FREE ${ai['rootvol']} 
  if [ "${ai[initmods]}" = "" ]; then
    ai['initmods']="\"dm-snapshot\" \"dm-raid\" \"dm-cache-default\""
  else
    ai['initmods']="${ai['initmods']} \"dm-snapshot\" \"dm-raid\" \"dm-cache-default\""
  fi
  ai['rootsearch']=$( ls -l ${ai['rootvol']} | awk '{print $11}' |cut -f2 -d/ )
  ai['bootsearch']=$( ls -l ${ai['bootvol']} | awk '{print $11}' |cut -f2 -d/ )
  ai['swapsearch']=$( ls -l ${ai['swapvol']} | awk '{print $11}' |cut -f2 -d/ )
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

# Create configuration.nix
echo "Creating ${ai['nixcfg']}"
tee ${ai['nixcfg']} << NIX_CFG
{ config, lib, pkgs, ... }:
{
  imports = [ ./hardware-configuration.nix ];
  boot.loader.systemd-boot.enable = ${ai['uefiflag']};
  boot.loader.efi.canTouchEfiVariables = ${ai['uefiflag']};
  boot.loader.grub.devices = [ "${ai['grubdev']}" ];
  boot.loader.grub.gfxmodeEfi = "${ai['gfxmode']}";
  boot.loader.grub.gfxpayloadEfi = "${ai['gfpayxload']}";
  boot.loader.grub.gfxmodeBios = "${ai['gfxmode']}";
  boot.loader.grub.gfxpayloadBios = "${ai['gfxpayload']}";
  boot.initrd.supportedFilesystems = ["${ai['rootfs']}"];
  boot.supportedFilesystems = [ "${ai['rootfs']}" ];
  boot.zfs.devNodes = "${ai['devnodes']}";
  services.lvm.boot.thin.enable = ${ai['lvm']};

  # HostID and Hostname
  networking.hostId = "${ai['hostid']}";
  networking.hostName = "${ai['hostname']}";

  # Services
  services.openssh.enable = ${ai['sshserver']};

  # Additional Nix options
  nix.settings.experimental-features = "${ai['experimental-features']}";

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
    interfaces."${bridgenic}".useDHCP = ${ai['dhcp']};
    interfaces."${nic}".useDHCP = ${ai['dhcp']};
    interfaces."${bridgenic}".ipv4.addresses = [{
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
  nixpkgs.hostPlatform = lib.mkDefault "x86_64-linux";
  system.stateVersion = "${ai['stateversion']}";
}
NIX_CFG

# Get device UUIDs
if [ "${ai['swap']}" = "true" ]; then
  ai['swapuuid']=$(ls -l ${ai['devnodes']} |grep ${ai['swapsearch']} |awk '{print $9}' )
  ai['swapdev']="${ai['devnodes']}/${ai['swapuuid']}"
else
  ai['swapdev']=""
fi
ai['bootuuid']=$(ls -l ${ai['devnodes']} |grep ${ai['bootsearch']} |awk '{print $9}' )
ai['bootdev']="${ai['devnodes']}/${ai['bootuuid']}"
ai['rootuuid']=$(ls -l ${ai['devnodes']} |grep ${ai['rootsearch']} |awk '{print $9}' )
ai['rootdev']="${ai['devnodes']}/${ai['rootuuid']}"
echo "Setting rootuuid to ${ai['rootuuid']}"
echo "Setting rootdev to ${ai['rootdev']}"
echo "Setting bootuuid to ${ai['bootuuid']}"
echo "Setting bootdev to ${ai['bootdev']}"
echo "Setting swapuuid to ${ai['swapuuid']}"
echo "Setting swapdev to ${ai['swapdev']}"

# Create hardware-configuration.nix
echo "Creating ${ai['nixcfg']}"
tee ${ai['hwcfg']} << HW_CFG
{ config, lib, pkgs, modulesPath, ... }:
{
  imports = [ ${ai['hwimports']} ];
  boot.initrd.availableKernelModules = [ ${ai['availmods']} ];
  boot.initrd.kernelModules = [ ${ai['initmods']} ];
  boot.kernelModules = [ ${ai['bootmods']} ];
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
  echo "nixos-install -v --show-trace --no-root-passwd 2>&1 |tee ${ai['installdir']}${ai['logfile']}"
  echo "To unmount filesystems and reboot:"
  echo "umount -Rl ${ai['installdir']}"
  echo "zpool export -a"
  echo "swapoff -a"
  exit
else
  nixos-install -v --show-trace --no-root-passwd 2>&1 |tee ${ai['installdir']}${ai['logfile']}
  echo "Logged to ${ai['installdir']}${ai['logfile']}"
fi

umount -Rl ${ai['installdir']}
zpool export -a
swapoff -a

if [ "${ai['poweroff']}" = "true" ]; then
  poweroff
fi
if [ "${ai['reboot']}" = "true" ]; then
  reboot
fi
