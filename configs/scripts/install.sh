#!/run/current-system/sw/bin/bash

export PATH="/run/wrappers/bin:/root/.nix-profile/bin:/nix/profile/bin:/root/.local/state/nix/profile/bin:/etc/profiles/per-user/root/bin:/nix/var/nix/profiles/default/bin:/run/current-system/sw/bin"

set -x

# Set general environment
USE_SWAP="true"
USE_LVM="false"
USE_ZSH="true"
USE_DHCP="true"
USE_BRIDGE="false"
SSH_SERVER="true"
BRIDGE_DEV="br0"
DO_REBOOT="false"
DO_INSTALL="true"
ROOT_FS="zfs"
BOOT_FS="vfat"
ROOT_DISK="/dev/vda"
MBR_PART="1"
ROOT_PART="2"
EFI_PART="3"
BOOT_PART="3"
SWAP_PART="4"
SWAP_SIZE="2G"
ROOT_SIZE="8G"
BOOT_SIZE="512M"
ROOT_POOL="rpool"
SWAP_NAME="swap"
TARGET_DIR="/mnt"
MBR_NAME="bootcode"
LOCALE="en_AU.UTF-8"
DEV_NODES="/dev/disk/by-uuid"
LOG_DIR="/var/log"
LOG_FILE="${LOG_DIR}/install.log"
TIME_ZONE="Australia/Melbourne"
USER_SHELL="zsh"
USER_NAME="nixos"
USER_GROUPS="wheel"
USER_GECOS="NiXOS User"
NORMAL_FLAG="true"
SUDO_COMMAND="ALL"
SUDO_OPTIONS="NOPASSWD"
ROOT_PASSWORD="nixos"
ROOT_CRYPT=$( mkpasswd --method=sha-512 "${ROOT_PASSWORD}" )
USER_PASSWORD="nixos"
USER_CRYPT=$( mkpasswd --method=sha-512 "${USER_PASSWORD}" )
STATE_VERSION="25.05"
HOST_NAME="nixos"
HOST_ID=$( head -c 8 /etc/machine-id )
NIX_DIR="${TARGET_DIR}/etc/nixos"
NIX_CFG="${NIX_DIR}/configuration.nix"
HW_CFG="${NIX_DIR}/hardware-configuration.nix"
ZFS_OPTIONS="-O mountpoint=none -O atime=off -O compression=lz4 -O xattr=sa -O acltype=posixacl -o ashift=12 -R ${TARGET_DIR}"
AVAIL_MODS="\"ahci\" \"xhci_pci\" \"virtio_pci\" \"sr_mod\" \"virtio_blk\""
NIX_EXP=""
USE_UNFREE="false"
SYSTEM_PACKAGES="ansible curl dmidecode efibootmgr file lsb-release lshw pciutils vim wget"

# Set up non DHCP environment
NIC_DEV="first"
NIC_DNS="8.8.8.8"
NIC_IP="192.168.11.9"
NIC_GW="192.168.11.254"
NIC_CIDR="22"
if [ "${USE_DHCP}" = "false" ]; then
  if [ "${NIC_DEV}" = "first" ]; then
    NIC_DEV=$( ip link | grep "state UP" | awk '{ print $2}' | head -1 | grep ^e | cut -f1 -d: )
  fi
fi

# Discover first disk
if [ "${ROOT_DISK}" = "first" ]; then
  ROOT_DISK=$( lsblk -x TYPE|grep disk |sort |head -1 |awk '{print $1}' )
  ROOT_DISK="/dev/${ROOT_DISK}"
fi

# Check we are using only one volume manager
if [ "${USE_LVM}" = "true" ] && [ "${ROOT_FS}" = "zfs" ]; then
  echo "Cannot use two volume managers (LVM and ZFS)"
  exit
fi

# QEMU check
QEMU_CHECK=$( cat /proc/ioports |grep QEMU )
if [ -n "${QEMU_CHECK}" ]; then
  BOOT_MODS="\"kvm-intel\""
  HW_IMPORTS="(modulesPath + \"/profiles/qemu-guest.nix\")"
else
  BOOT_MODS=""
  HW_IMPORTS=""
fi

# Check if BIOS or UEFI boot
if [ -d "/sys/firmware/efi" ]; then
  BIOS_FLAG="false"
  UEFI_FLAG="true"
  GRUB_DEV="nodev"
  BOOT_NAME="uefiboot"
else
  BIOS_FLAG="true"
  UEFI_FLAG="false"
  GRUB_DEV="${ROOT_DISK}"
  BOOT_NAME="biosboot"
fi

# Set root partition type
case "${ROOT_FS}" in
  "zfs")
    PART_FLAG="BF01"
    ROOT_NAME="rpool"
    ;;
  *)
    PART_FLAG="8300"
    ROOT_NAME="root"
    ;;
esac

# Wipe and set up disks
swapoff -a
umount -Rl ${TARGET_DIR}
zpool destroy -f ${ROOT_POOL}
lvremove -f ${ROOT_POOL}
wipefs ${ROOT_DISK}
sgdisk --zap-all ${ROOT_DISK}
zpool labelclear -f ${ROOT_DISK}
partprobe ${ROOT_DISK}
sleep 2s
if [ "${BIOS_FLAG}" = "true" ]; then
  sgdisk -a ${MBR_PART} -n ${MBR_PART}:0:+1M -t ${MBR_PART}:EF02 -c ${MBR_PART}:${MBR_NAME} ${ROOT_DISK}
fi
if [ "${USE_LVM}" = "true" ]; then
  sgdisk -n ${ROOT_PART}:0:0 -t ${ROOT_PART}:${PART_FLAG} -c ${ROOT_PART}:${ROOT_NAME} ${ROOT_DISK}
  pvcreate -f ${ROOT_DISK}${ROOT_PART}
  vgcreate -f ${ROOT_POOL} ${ROOT_DISK}${ROOT_PART}
  lvcreate -y --size ${BOOT_SIZE} --name ${BOOT_NAME} ${ROOT_POOL}
  if [ "${USE_SWAP}" = "true" ]; then
    lvcreate -y --size ${SWAP_SIZE} --name ${SWAP_NAME} ${ROOT_POOL}
  fi
  lvcreate -y --size ${ROOT_SIZE} --name ${ROOT_NAME} ${ROOT_POOL}
  SWAP_VOL="/dev/${ROOT_POOL}/${SWAP_NAME}"
  BOOT_VOL="/dev/${ROOT_POOL}/${BOOT_NAME}"
  ROOT_VOL="/dev/${ROOT_POOL}/${ROOT_NAME}"
  lvextend -l +100%FREE ${ROOT_VOL} 
  INIT_MODS="\"dm-snapshot\" \"dm-raid\" \"dm-cache-default\""
  ROOT_SEARCH=$( ls -l ${ROOT_VOL} | awk '{print $11}' |cut -f2 -d/ )
  BOOT_SEARCH=$( ls -l ${BOOT_VOL} | awk '{print $11}' |cut -f2 -d/ )
  SWAP_SEARCH=$( ls -l ${SWAP_VOL} | awk '{print $11}' |cut -f2 -d/ )
else
  sgdisk -n ${EFI_PART}:2M:+${BOOT_SIZE} -t ${EFI_PART}:EF00 -c ${EFI_PART}:${BOOT_NAME} ${ROOT_DISK}
  if [ "${USE_SWAP}" = "true" ]; then
    sgdisk -n ${SWAP_PART}:0:+${SWAP_SIZE} -t ${SWAP_PART}:8200 -c ${SWAP_PART}:${SWAP_NAME} ${ROOT_DISK}
  fi
  sgdisk -n ${ROOT_PART}:0:0 -t ${ROOT_PART}:${PART_FLAG} -c ${ROOT_PART}:${ROOT_NAME} ${ROOT_DISK}
  SWAP_VOL="${ROOT_DISK}${SWAP_PART}"
  BOOT_VOL="${ROOT_DISK}${BOOT_PART}"
  ROOT_VOL="${ROOT_DISK}${ROOT_PART}"
  INIT_MODS=""
  ROOT_SUFFIX=$( echo "${ROOT_DISK}" | cut -f3 -d/  )
  ROOT_SEARCH="${ROOT_SUFFIX}${ROOT_PART}"
  BOOT_SEARCH="${ROOT_SUFFIX}${BOOT_PART}"
  SWAP_SEARCH="${ROOT_SUFFIX}${SWAP_PART}"
fi
partprobe ${ROOT_DISK}
sleep 2s

# Make and mount filesystems
if [ "${USE_SWAP}" = "true" ]; then
  mkswap -L ${SWAP_NAME} ${SWAP_VOL}
  swapon ${SWAP_VOL}
fi
if [ "${ROOT_FS}" = "zfs" ]; then
  zpool create -f ${ZFS_OPTIONS} ${ROOT_POOL} ${ROOT_DISK}${ROOT_PART}
  for DIR_NAME in root nix var home; do
    zfs create -o mountpoint=legacy ${ROOT_POOL}/${DIR_NAME}
  done
  mount -t zfs ${ROOT_POOL}/root ${TARGET_DIR}
  for DIR_NAME in nix var home; do
    mkdir -p ${TARGET_DIR}/${DIR_NAME}
    mount -t ${ROOT_FS} ${ROOT_POOL}/${DIR_NAME} ${TARGET_DIR}/${DIR_NAME}
  done
else
  if [ "${ROOT_FS}" = "ext4" ]; then
    mkfs.${ROOT_FS} -F -L ${ROOT_NAME} ${ROOT_VOL}
  else
    mkfs.${ROOT_FS} -f -L ${ROOT_NAME} ${ROOT_VOL}
  fi
  mount -t ${ROOT_FS} ${ROOT_VOL} ${TARGET_DIR}
fi
mkfs.${BOOT_FS} ${BOOT_VOL}
mkdir ${TARGET_DIR}/boot
mount ${BOOT_VOL} ${TARGET_DIR}/boot
mkdir -p ${NIX_DIR}
rm ${NIX_DIR}/*

# Create configuration.nix
tee ${NIX_CFG} << NIX_CFG
{ config, lib, pkgs, ... }:
{
  imports = [ ./hardware-configuration.nix ];
  boot.loader.systemd-boot.enable = ${UEFI_FLAG};
  boot.loader.efi.canTouchEfiVariables = ${UEFI_FLAG};
  boot.loader.grub.devices = [ "${GRUB_DEV}" ];
  boot.initrd.supportedFilesystems = ["${ROOT_FS}"];
  boot.supportedFilesystems = [ "${ROOT_FS}" ];
  boot.zfs.devNodes = "${DEV_NODES}";
  services.lvm.boot.thin.enable = ${USE_LVM};
  # HostID and Hostname
  networking.hostId = "${HOST_ID}";
  networking.hostName = "${HOST_NAME}";
  # Services
  services.openssh.enable = ${SSH_SERVER};
  # Packages to include
  environment.systemPackages = with pkgs; [ ${SYSTEM_PACKAGES} ];
  # Additional Nix options
  nix.settings.experimental-features = "${NIX_EXP}";
  # Allow unfree packages
  nixpkgs.config.allowUnfree = ${USE_UNFREE};
  # Set your time zone.
  time.timeZone = "${TIME_ZONE}";
  # Select internationalisation properties.
  i18n.defaultLocale = "${LOCALE}";
  i18n.extraLocaleSettings = {
    LC_ADDRESS = "${LOCALE}";
    LC_IDENTIFICATION = "${LOCALE}";
    LC_MEASUREMENT = "${LOCALE}";
    LC_MONETARY = "${LOCALE}";
    LC_NAME = "${LOCALE}";
    LC_NUMERIC = "${LOCALE}";
    LC_PAPER = "${LOCALE}";
    LC_TELEPHONE = "${LOCALE}";
    LC_TIME = "${LOCALE}";
  };
  # Define a user account. 
  users.users.${USER_NAME} = {
    shell = pkgs.${USER_SHELL};
    isNormalUser = ${NORMAL_FLAG};
    description = "${USER_GECOS}";
    extraGroups = [ "${USER_GROUPS}" ];
    openssh.authorizedKeys.keys = [ "${SSH_KEY}" ];
    hashedPassword = "${USER_CRYPT}";
  };
  programs.zsh.enable = ${USE_ZSH};

  # Sudo configuration
  security.sudo.extraRules= [
    { users = [ "${USER_NAME}" ];
      commands = [
        { command = "${SUDO_COMMAND}" ;
          options= [ "${SUDO_OPTIONS}" ];
        }
      ];
    }
  ];
  networking.useDHCP = lib.mkDefault ${USE_DHCP};
NIX_CFG
if [ "${USE_DHCP}" = "false" ]; then
  if [ "${USE_BRIDGE}" = "false" ]; then
    tee -a ${NIX_CFG} << NIX_CFG
  networking = {
    interfaces."${NIC_DEV}".useDHCP = ${USE_DHCP};
    interfaces."${NIC_DEV}".ipv4.addresses = [{
      address = "${NIC_IP}";
      prefixLength = ${NIC_CIDR};
    }];
    defaultGateway = "${NIC_GW}";
    nameservers = [ "${NIC_DNS}" ];
  };
NIX_CFG
  else
    tee -a ${NIX_CFG} << NIX_CFG
  networking = {
    bridges."${BRIDGE_DEV}".interfaces = [ "${NIC_DEV}" ];
    interfaces."${BRIDGE_DEV}".useDHCP = ${USE_DHCP};
    interfaces."${NIC_DEV}".useDHCP = ${USE_DHCP};
    interfaces."${BRIDGE_DEV}".ipv4.addresses = [{
      address = "${NIC_IP}";
      prefixLength = ${NIC_CIDR};
    }];
    defaultGateway = "${NIC_GW}";
    nameservers = [ "${NIC_DNS}" ];
  };    
NIX_CFG
  fi
fi
tee -a ${NIX_CFG} << NIX_CFG
  users.users.root.initialHashedPassword = "${ROOT_CRYPT}";
  nixpkgs.hostPlatform = lib.mkDefault "x86_64-linux";
  system.stateVersion = "${STATE_VERSION}";
}
NIX_CFG

# Get device UUIDs
if [ "$USE_SWAP" = "true" ]; then
  SWAP_UUID=$(ls -l ${DEV_NODES} |grep ${SWAP_SEARCH} |awk '{print $9}' )
  SWAP_DEV="${DEV_NODES}/${SWAP_UUID}"
else
  SWAP_DEV=""
fi
BOOT_UUID=$(ls -l ${DEV_NODES} |grep ${BOOT_SEARCH} |awk '{print $9}' )
BOOT_DEV="${DEV_NODES}/${BOOT_UUID}"
ROOT_UUID=$(ls -l ${DEV_NODES} |grep ${ROOT_SEARCH} |awk '{print $9}' )
ROOT_DEV="${DEV_NODES}/${ROOT_UUID}"

# Create hardware-configuration.nix
tee ${HW_CFG} << HW_CFG
{ config, lib, pkgs, modulesPath, ... }:
{
  imports = [ ${HW_IMPORTS} ];
  boot.initrd.availableKernelModules = [ ${AVAIL_MODS} ];
  boot.initrd.kernelModules = [ ${INIT_MODS} ];
  boot.kernelModules = [ ${BOOT_MODS} ];
  boot.extraModulePackages = [ ];
HW_CFG
if [ "${ROOT_FS}" = "zfs" ]; then
  tee -a ${HW_CFG} << HW_CFG
  fileSystems."/" = {
    device = "${ROOT_POOL}/root";
    fsType = "${ROOT_FS}";
    neededForBoot = true;
  };
  fileSystems."/nix" = {
    device = "${ROOT_POOL}/nix";
    fsType = "${ROOT_FS}";
  };
  fileSystems."/home" = {
    device = "${ROOT_POOL}/home";
    fsType = "${ROOT_FS}";
  };
  fileSystems."/var" = {
    device = "${ROOT_POOL}/var";
    fsType = "${ROOT_FS}";
  };
HW_CFG
else
  tee -a ${HW_CFG} << HW_CFG
  fileSystems."/" = {
    device = "${ROOT_DEV}";
    fsType = "${ROOT_FS}";
    neededForBoot = true;
  };
HW_CFG
fi
tee -a ${HW_CFG} << HW_CFG
  fileSystems."/boot" = {
    device = "${BOOT_DEV}";
    fsType = "${BOOT_FS}";
    options = [ "fmask=0022" "dmask=0022" ];
  };
  swapDevices = [ { device = "${SWAP_DEV}"; } ];
}
HW_CFG

# Manual config creation command if you need it
# nixos-generate-config --root ${TARGET_DIR}

if [ "${DO_INSTALL}" = "false" ]; then
  exit
fi

mkdir -p ${TARGET_DIR}/${LOG_DIR}

nixos-install -v --show-trace --no-root-passwd 2>&1 |tee ${TARGET_DIR}${LOG_FILE}

umount -Rl ${TARGET_DIR}
zpool export -a
swapoff -a

if [ "${DO_REBOOT}" = "true" ]; then
  reboot
fi
