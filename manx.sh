#!env bash

# Name:         manx (Manage/Automate NiXOS)
# Version:      0.2.1
# Release:      1
# License:      CC-BA (Creative Commons By Attribution)
#               http://creativecommons.org/licenses/by/4.0/legalcode
# Group:        System
# Source:       N/A
# URL:          https://github.com/lateralblast/manx
# Distribution: NiXOS
# Vendor:       Linux
# Packager:     Richard Spindler <richard@lateralblast.com.au>
# Description:  A template for writing shell scripts

# Insert some shellcheck disables
# Depending on your requirements, you may want to add/remove disables
# shellcheck disable=SC2034
# shellcheck disable=SC1090
# shellcheck disable=SC2129
# shellcheck disable=SC2239

# Create arrays

declare -A os
declare -A script
declare -A options 
declare -a options_list
declare -a actions_list

# Grab script information and put it into an associative array

script['args']="$*"
script['file']="$0"
script['name']="just"
script['file']=$( realpath "${script['file']}" )
script['path']=$( dirname "${script['file']}" )
script['modulepath']="${script['path']}/modules"
script['bin']=$( basename "${script['file']}" )
script['user']=$( id -u -n )

# Function: set_defaults
#
# Set defaults

set_defaults () {
  options['cdbase']="nixpkgs/nixos/modules/installer/cd-dvd"                # option : Nix CD base
  options['verbose']="false"                                                # option : Verbose mode
  options['strict']="false"                                                 # option : Strict mode
  options['dryrun']="false"                                                 # option : Dryrun mode
  options['debug']="false"                                                  # option : Debug mode
  options['force']="false"                                                  # option : Force actions
  options['mask']="false"                                                   # option : Mask identifiers
  options['yes']="false"                                                    # option : Answer yes to questions
  options['workdir']="${HOME}/nix"                                          # option : Nix work directory
  options['sshkey']=""                                                      # option : SSH key
  options['disk']="first"                                                   # option : Disk
  options['nic']="first"                                                    # option : NIC
  options['language']="en_AU.UTF-8"                                         # option : Language
  options['timezone']="Australia/Melbourne"                                 # option : Timezone
  options['username']=""                                                    # option : Username
  options['password']=""                                                    # option : Password
  options['sshkeyfile']=""                                                  # option : SSH key file
  options['install']="${options['workdir']}/ai/install.sh"                  # option : Install script
  options['nixisoconfig']="${options['workdir']}/iso.nix"                   # option : Nix ISO config
  options['zfsinstall']="${options['workdir']}/ai/zfs.sh"                   # option : ZFS install script
  options['cdimage']="<${options['cdbase']}/installation-cd-minimal.nix>"   # option : Nix installation
  options['channel']="<${options['cdbase']}/channel.nix>"                   # option : Nix channel 
  options['runsize']="50%"                                                  # option : Run size
  options['prefix']="ai"                                                    # option : Install directory prefix
  options['source']="${options['workdir']}/${options['prefix']}"            # option : Source directory
  options['target']="/${options['prefix']}"                                 # option : Target directory
  options['nixdir']="/mnt/etc/nixos"                                        # option : NIX directory
  options['nixconfig']="${options['nixdir']}/configuration.nix"             # option : NIX install config file
  options['nixhwconfig']="${options['nixdir']}/hardware-configuration.nix"  # option : NIX install hardware config file
  options['nixzfsconfig']="${options['nixdir']}/zfs.nix"                    # option : NIX install ZFS config file
  options['systemd-boot']="true"                                            # option : systemd-boot
  options['touchefi']="true"                                                # option : Touch EFI
  options['sshserver']="true"                                               # option : Enable SSH server
  options['swapsize']="2G"                                                  # option : Swap size
  options['bootpool']="bpool"                                               # option : Boot pool name
  options['rootpool']="rpool"                                               # option : Root pool name
  options['rootvol']="nixos"                                                # option : Root volume name
  options['rootpassword']="nixos"                                           # option : Root password
  options['rootcrypt']=""                                                   # option : Root password crypt
  options['username']="nixos"                                               # option : User Username
  options['gecos']="nixos"                                                  # option : User GECOS
  options['password']="nixos"                                               # option : User Password
  options['shell']="bash"                                                   # option : User Shell
  options['normaluser']="true"                                              # option : Normal User
  options['extragroups']="wheel"                                            # option : Extra Groups
  options['sudousers']="${options['username']}"                             # option : Sudo Users
  options['sudocommand']="ALL"                                              # option : Sudo Command
  options['sudooptions']="NOPASSWD"                                         # option : Sudo Options
  options['systempackages']="vim git efibootmgr zsh"                        # option : System Packages
  options['experimental-features']="nix-command flakes"                     # option : Experimental Features
  options['unfree']="true"                                                  # option : Allow Non Free Packages
  options['stateversion']="25.05"                                           # option : State version
  options['unattended']="true"                                              # option : Execute install script
  options['attended']="false"                                               # option : Don't execute install script
  options['reboot']="true"                                                  # option : Reboot after install
  os['name']=$( uname -s )
  if [ "${os['name']}" = "Linux" ]; then
    lsb_check=$( command -v lsb_release )
    if [ -n "${lsb_check}" ]; then 
      os['distro']=$( lsb_release -i -s 2 | sed 's/"//g' > /dev/null )
    else
      os['distro']=$( hostnamectl | grep "Operating System" | awk '{print $3}' )
    fi
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
              if [[ ! "${format}" =~ otice ]]; then
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
  if [[ "${value}" =~ "--" ]]; then
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
  else
    echo "${info}(s):"
  fi
  echo "---------"
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
  if [ ! "$bin_test" = "0" ]; then
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
  if [ ! -d "${options['workdir']}" ]; then
    execute_command "mkdir -p ${options['workdir']}"
  fi
  if [ ! -d "${options['workdir']}/ai" ]; then
    execute_command "mkdir -p ${options['workdir']}/ai"
  fi
  if [ "${os['name']}" = "Linux" ]; then
    nix_test=$( command -v nix )
    if [ -z "${nix_test}" ]; then
      if [ "${os['distro']}" = "Ubuntu" ]; then
        execute_command "apt install nix-bin" "sudo"
      fi
    fi
  else
    sh <(curl --proto '=https' --tlsv1.2 -L https://nixos.org/nix/install) --no-daemon
  fi
}

# function: get_ssh_key
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

# function: create_nix_config
#
# Create NixOS config

create_nix_iso_config () {
  check_nix_config
  get_ssh_key
  verbose_message "Creating ${options['nixisoconfig']}"
  tee "${options['nixisoconfig']}" << NIXCONFIG
# ISO build config
{ config, pkgs, ... }:
{
  imports = [
    ${options['cdimage']}
    ${options['channel']}
  ];
  # Add contents to ISO
  isoImage = {
    contents = [
      { source = ${options['source']} ;
        target = "${options['target']}";
      }
    ];
  };
  # Set boot params
  boot.runSize = "${options['runsize']}";
  # Bootloader.
  boot.loader.systemd-boot.enable = ${options['systemd-boot']};
  boot.loader.efi.canTouchEfiVariables = ${options['touchefi']};
  # Set your time zone.
  time.timeZone = "${options['timezone']}";
  # Select internationalisation properties.
  i18n.defaultLocale = "${options['language']}";
  i18n.extraLocaleSettings = {
    LC_ADDRESS = "${options['language']}";
    LC_IDENTIFICATION = "${options['language']}";
    LC_MEASUREMENT = "${options['language']}";
    LC_MONETARY = "${options['language']}";
    LC_NAME = "${options['language']}";
    LC_NUMERIC = "${options['language']}";
    LC_PAPER = "${options['language']}";
    LC_TELEPHONE = "${options['language']}";
    LC_TIME = "${options['language']}";
  };
  # OpenSSH
  services.openssh.enable = ${options['sshserver']};
  # Enable SSH in the boot process.
  systemd.services.sshd.wantedBy = pkgs.lib.mkForce [ "multi-user.target" ];
  users.users.root.openssh.authorizedKeys.keys = [
    "${options['sshkey']}"
  ];
  # Based packages to include in ISO
  environment.systemPackages = with pkgs; [ ${options['systempackages']} ];
  # Additional Nix options
  nix.settings.experimental-features = "${options['experimental-features']}";
  # Allow unfree packages
  nixpkgs.config.allowUnfree = ${options['unfree']};
NIXCONFIG
  if [ "${options['attended']}" = "false" ]; then
    tee -a "${options['nixisoconfig']}" << NIXCONFIG
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
      sudo /iso/ai/install.sh 
  '';
  };
NIXCONFIG
  fi
  tee -a "${options['nixisoconfig']}" << NIXCONFIG
  system.stateVersion = "${options['stateversion']}";
}
NIXCONFIG
}

# Function: create_install_script
#
# Create install script

create_install_script () {
  check_nix_config
  get_ssh_key
  verbose_message "Creating ${options['install']}"
  tee "${options['install']}" << INSTALL
#!/run/current-system/sw/bin/bash
set -x
export PATH="/run/wrappers/bin:/root/.nix-profile/bin:/nix/profile/bin:/root/.local/state/nix/profile/bin:/etc/profiles/per-user/root/bin:/nix/var/nix/profiles/default/bin:/run/current-system/sw/bin"
mkdir -p /mnt/${options['prefix']}
cp /iso/${options['prefix']}/*.sh /mnt/${options['prefix']}
chmod +x /mnt/${options['prefix']}/*.sh
bash /mnt/${options['prefix']}/zfs.sh
INSTALL
}

# Function: create_zfs_install_script
#
# Create ZFS install script

create_zfs_install_script () {
  check_nix_config
  get_ssh_key
  verbose_message "Creating ${options['zfsinstall']}"
  tee "${options['zfsinstall']}" << ZFSINSTALL
#!/run/current-system/sw/bin/bash
set -x
export PATH="/run/wrappers/bin:/root/.nix-profile/bin:/nix/profile/bin:/root/.local/state/nix/profile/bin:/etc/profiles/per-user/root/bin:/nix/var/nix/profiles/default/bin:/run/current-system/sw/bin"
REBOOT="${options['reboot']}"
# Declare disk(s)
ZFSINSTALL
if [ "${options['disk']}" = "first" ]; then
  tee -a "${options['zfsinstall']}" << ZFSINSTALL
FIRST_DISK=\$( lsblk -x TYPE|grep disk |sort |head -1 |awk '{print \$1}' )
DISK=( /dev/\${FIRST_DISK} )
ZFSINSTALL
else
  tee -a "${options['zfsinstall']}" << ZFSINSTALL
DISK=( ${options['disk']} )
ZFSINSTALL
fi
tee -a "${options['zfsinstall']}" << ZFSINSTALL
# Declare partitions/pools
PART_MBR="bootcode"
PART_EFI="efiboot"
PART_BOOT="${options['bootpool']}"
PART_SWAP="swap"
PART_ROOT="${options['rootpool']}"
SWAP_SIZE="${options['swapsize']}"
ZFS_BOOT="${options['bootpool']}"
ZFS_ROOT="${options['rootpool']}"
ZFS_ROOT_VOL="${options['rootvol']}"
ROOT_CRYPT="${options['rootcrypt']}"
IMPERMANENCE=0
EMPTYSNAP="SYSINIT"
# Declare config files
MAIN_CFG="${options['nixconfig']}"
HW_CFG="${options['nixhwconfig']}"
ZFS_CFG="${options['nixzfsconfig']}"
# Setup disk(s)
i=0 SWAP_DEVS=()
for d in \${DISK[*]}
do
  wipefs \${d}
  sgdisk --zap-all \${d}
  sgdisk -a1 -n1:0:+100K -t1:EF02 -c 1:\${PART_MBR}\${i} \${d}
  sgdisk -n2:1M:+1G -t2:EF00 -c 2:\${PART_EFI}\${i} \${d}
  sgdisk -n3:0:+4G -t3:BE00 -c 3:\${PART_BOOT}\${i} \${d}
  sgdisk -n4:0:+\${SWAPSIZE} -t4:8200 -c 4:\${PART_SWAP}\${i} \${d}
  SWAP_DEVS+=(\${d}4)
  sgdisk -n5:0:0 -t5:BF00 -c 5:\${PART_ROOT}\${i} \${d}

  partprobe \${d}
  sleep 5s
  mkswap -L \${PART_SWAP}fs\${i} /dev/disk/by-partlabel/\${PART_SWAP}\${i}
  swapon /dev/disk/by-partlabel/\${PART_SWAP}\${i}
  (( i++ )) || true
done
unset i d
# Create the boot pool
zpool create -f \
  -o compatibility=grub2 \
  -o ashift=12 \
  -o autotrim=on \
  -O acltype=posixacl \
  -O compression=lz4 \
  -O devices=off \
  -O normalization=formD \
  -O relatime=on \
  -O xattr=sa \
  -O mountpoint=none \
  -O checksum=sha256 \
  -R /mnt \
  \${ZFS_BOOT} \${ZFS_BOOT_VDEV} /dev/disk/by-partlabel/\${PART_BOOT}*
# Create the root pool
zpool create -f \
  -o ashift=12 \
  -o autotrim=on \
  -O acltype=posixacl \
  -O compression=zstd \
  -O dnodesize=auto -O normalization=formD \
  -O relatime=on \
  -O xattr=sa \
  -O mountpoint=none \
  -O checksum=edonr \
  -R /mnt \
  \${ZFS_ROOT} \${ZFS_ROOT_VDEV} /dev/disk/by-partlabel/\${PART_ROOT}*
# Create the boot dataset
zfs create \${ZFS_BOOT}/\${ZFS_ROOT_VOL}
# Create the root dataset
zfs create -o mountpoint=/     \${ZFS_ROOT}/\${ZFS_ROOT_VOL}
# Create datasets (subvolumes) in the root dataset
zfs create \${ZFS_ROOT}/\${ZFS_ROOT_VOL}/home
(( \$IMPERMANENCE )) && zfs create \${ZFS_ROOT}/\${ZFS_ROOT_VOL}/keep || true
zfs create -o atime=off \${ZFS_ROOT}/\${ZFS_ROOT_VOL}/nix
zfs create \${ZFS_ROOT}/\${ZFS_ROOT_VOL}/root
zfs create \${ZFS_ROOT}/\${ZFS_ROOT_VOL}/usr
zfs create \${ZFS_ROOT}/\${ZFS_ROOT_VOL}/var
# Create datasets (subvolumes) in the boot dataset
# This comes last because boot order matters
zfs create -o mountpoint=/boot \${ZFS_BOOT}/\${ZFS_ROOT_VOL}/boot
# Make empty snapshots of impermanent volumes
if (( \$IMPERMANENCE ))
then
  for i in "" /usr /var
  do
    zfs snapshot \${ZFS_ROOT}/\${ZFS_ROOT_VOL}\${i}@\${EMPTY_SNAP}
  done
fi

# Create, mount and populate the efi partitions
i=0
for d in \${DISK[*]}
do
  mkfs.vfat -n EFI /dev/disk/by-partlabel/\${PART_EFI}\${i}
  mkdir -p /mnt/boot/efis/\${PART_EFI}\${i}
  mount -t vfat /dev/disk/by-partlabel/\${PART_EFI}\${i} /mnt/boot/efis/\${PART_EFI}${i}
  (( i++ )) || true
done
unset i d
# Mount the first drive's efi partition to /mnt/boot/efi
mkdir /mnt/boot/efi
mount -t vfat /dev/disk/by-partlabel/\${PART_EFI}0 /mnt/boot/efi
# Make sure we won't trip over zpool.cache later
mkdir -p /mnt/etc/zfs/
rm -f /mnt/etc/zfs/zpool.cache
touch /mnt/etc/zfs/zpool.cache
chmod a-w /mnt/etc/zfs/zpool.cache
chattr +i /mnt/etc/zfs/zpool.cache
# Generate and edit configs
nixos-generate-config --force --root /mnt
sed -i -e "s|./hardware-configuration.nix|& ./zfs.nix|" \${MAIN_CFG}
if (( \$IMPERMANENCE ))
then
  echo '{ config, lib, pkgs, ... }:'
else
  echo '{ config, pkgs, ... }:'
fi | tee -a \${ZFS_CFG}

tee -a \${ZFS_CFG} << EOF

{
  boot.supportedFilesystems = [ "zfs" ];
  networking.hostId = "\$(head -c 8 /etc/machine-id)";
  boot.kernelPackages = config.boot.zfs.package.latestCompatibleLinuxPackages;
  boot.zfs.devNodes = "/dev/disk/by-partlabel";
EOF

if (( \$IMPERMANENCE ))
then
  tee -a \${ZFS_CFG} << EOF
  boot.initrd.postDeviceCommands = lib.mkAfter ''
    zfs rollback -r \${ZFS_ROOT}/\${ZFS_ROOT_VOL}@\${EMPTY_SNAP}
  '';
EOF
fi
# Remove boot.loader stuff, it's to be added to zfs.nix
sed -i '/boot.loader/d' \${MAIN_CFG}
# Disable xserver. Comment them without a space after the pound sign so we can
# recognize them when we edit the config later
sed -i -e 's;^  \(services.xserver\);  #\1;' \${MAIN_CFG}
# Create rest of ZFS install config
tee -a \${ZFS_CFG} << EOF
  environment.systemPackages = with pkgs; [ ${options['systempackages']} ];

  # Set your time zone.
  time.timeZone = "${options['timezone']}";
  
  # Select internationalisation properties.
  i18n.defaultLocale = "${options['language']}";
  i18n.extraLocaleSettings = {
    LC_ADDRESS = "${options['language']}";
    LC_IDENTIFICATION = "${options['language']}";
    LC_MEASUREMENT = "${options['language']}";
    LC_MONETARY = "${options['language']}";
    LC_NAME = "${options['language']}";
    LC_NUMERIC = "${options['language']}";
    LC_PAPER = "${options['language']}";
    LC_TELEPHONE = "${options['language']}";
    LC_TIME = "${options['language']}";
  };

  # OpenSSH
  services.openssh.enable = true;

  # Define a user account. 
  users.users.${options['username']} = {
    shell = pkgs.${options['shell']};
    isNormalUser = ${options['normaluser']};
    description = "${options['gecos']}";
    extraGroups = [ "${options['extragroups']}" ];
    openssh.authorizedKeys.keys = [ "${options['sshkey']}" ];
    hashedPassword = "${options['password']}";
  };
  
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

  boot.loader.efi.efiSysMountPoint = "/boot/efi";
  boot.loader.efi.canTouchEfiVariables = false;
  boot.loader.generationsDir.copyKernels = true;
  boot.loader.grub.efiInstallAsRemovable = true;
  boot.loader.grub.enable = true;
  boot.loader.grub.copyKernels = true;
  boot.loader.grub.efiSupport = true;
  boot.loader.grub.zfsSupport = true;

  boot.loader.grub.extraPrepareConfig = ''
    mkdir -p /boot/efis
    for i in  /boot/efis/*; do mount \${i} ; done

    mkdir -p /boot/efi
    mount /boot/efi
  '';

  boot.loader.grub.extraInstallCommands = ''
    ESP_MIRROR=\$(mktemp -d)
    cp -r /boot/efi/EFI \${ESP_MIRROR}
    for i in /boot/efis/*; do
      cp -r \${ESP_MIRROR}/EFI \${i}
    done
    rm -rf \${ESP_MIRROR}
  '';

  boot.loader.grub.devices = [
EOF

for d in \${DISK[*]}; do
  printf "    \"\${d}\"\n" >> \${ZFS_CFG}
done

tee -a \${ZFS_CFG} << EOF
  ];

EOF
sed -i 's|fsType = "zfs";|fsType = "zfs"; options = [ "zfsutil" "X-mount.mkdir" ];|g' \${HW_CFG}

ADDNR=\$(awk '/^  fileSystems."\/" =$/ {print NR+3}' \${HW_CFG})
if [ -n "\${ADDNR}" ]; then
  sed -i "\${ADDNR}i"' \      neededForBoot = true;' \${HW_CFG}
fi

ADDNR=\$(awk '/^  fileSystems."\/boot" =$/ {print NR+3}' \${HW_CFG})
if [ -n "\${ADDNR}" ]; then
  sed -i "\${ADDNR}i"' \      neededForBoot = true;' \${HW_CFG}
fi

if (( \$IMPERMANENCE ))
then
  # Of course we want to keep the config files after the initial
  # reboot. So, create a bind mount from /keep/etc/nixos -> /etc/nixos
  # here, and copy the files and actually mount the bind later
  ADDNR=\$(awk '/^  swapDevices =/ {print NR-1}' \${HW_CFG})
  TMPFILE=\$(mktemp)
  head -n \${ADDNR} \${HW_CFG} > \${TMPFILE}

  tee -a \${TMPFILE} << EOF
  fileSystems."/etc/nixos" =
    { device = "/keep/etc/nixos";
      fsType = "none";
      options = [ "bind" ];
    };

EOF
  ADDNR=\$(awk '/^  swapDevices =/ {print NR}' \${HW_CFG})
  tail -n +\${ADDNR} \${HW_CFG} >> \${TMPFILE}
  cat \${TMPFILE} > \${HW_CFG}
  rm -f \${TMPFILE}
  unset ADDNR TMPFILE
fi

tee -a \${ZFS_CFG} << EOF
users.users.root.initialHashedPassword = "\${ROOT_CRYPT}";

}
EOF

if (( \$IMPERMANENCE ))
then
  # This is where we copy the config files and mount the bind
  install -d -m 0755 /mnt/keep/etc
  cp -a /mnt/etc/nixos /mnt/keep/etc/
  mount -o bind /mnt/keep/etc/nixos /mnt/etc/nixos
fi

nixos-install -v --show-trace --no-root-passwd --substituters "" --root /mnt
umount -Rl /mnt
zpool export -a
swapoff -a
if [ "\${REBOOT}" = "true" ]; then
  reboot
fi
ZFSINSTALL
}

# Function: create_iso
#
# Create ISO

create_iso () {
  check_nix_config
  create_nix_iso_config
  create_install_script
  create_zfs_install_script
  execute_command "cd ${options['workdir']} ; nix-build '<nixpkgs/nixos>' -A config.system.build.isoImage -I nixos-config=${options['nixisoconfig']}"
  iso_dir="${work_dir}/result/iso"
  iso_file=$( find "${iso_dir}" -name "*.iso" )
  verbose_message "Ouput ISO: ${iso_file}"
}

# Function: process_actions
#
# Handle actions

process_actions () {
  actions="$1"
  case $actions in
    createinstall*)       # action : Create install script
      create_install_script
      exit
      ;;
    createiso)            # action : Create ISO
      create_iso
      exit
      ;;
    createnix*)           # action : Create Nix ISO config
      create_nix_iso_config
      exit
      ;;
    createzfs*)           # action : Create ZFS install script
      create_zfs_install_script
      exit
      ;;
    help)                 # action : Print actions help
      print_actions
      exit
      ;;
    printenv*)            # action : Print environment
      print_environment
      exit
      ;;
    printdefaults)        # action : Print defaults
      print_defaults
      exit
      ;;
    shellcheck)           # action : Shellcheck script
      check_shellcheck
      exit
      ;;
    version)              # action : Print version
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

if [[ $@ =~ --option ]] && [[ $@ =~ mask ]]; then
  options['mask']="true"
fi

# Handle command line arguments

while test $# -gt 0; do
  case $1 in
    --action*)              # switch : Action(s) to perform
      check_value "$1" "$2"
      actions_list+=("$2")
      shift 2
      ;;
    --bootpool)             # switch : Boot pool name
      check_value "$1" "$2"
      options['bootpool']="$2"
      shift 2
      ;;
    --createinstall*)       # switch : Create install script
      actions_list+=("createinstall")
      shift
      ;;
    --createiso)            # switch : Create ISO
      actions_list+=("createiso")
      shift
      ;;
    --createnix*)           # switch : Create ISO
      actions_list+=("createnix")
      shift
      ;;
    --createzfsinstall*)    # switch : Create ZFS install script
      actions_list+=("createzfs")
      shift
      ;;
    --debug)                # switch : Enable debug mode
      options['debug']="true"
      shift
      ;;
    --dryrun)               # switch : Enable debug mode
      options['dryrun']="true"
      shift
      ;;
    --disk)                 # switch : SSH key
      check_value "$1" "$2"
      options['disk']="$2"
      shift 2
      ;;
    --experimental*)        # switch : SSH key
      check_value "$1" "$2"
      options['experimental-features']="$2"
      shift 2
      ;;
    --extragroup*)          # switch : Extra groups
      check_value "$1" "$2"
      options['extragroups']="$2"
      shift 2
      ;;
    --force)                # switch : Enable force mode
      options['force']="true"
      shift
      ;;
    --gecos)                # switch : GECOS field
      check_value "$1" "$2"
      options['gecos']="$2"
      shift 2
      ;;
    --help|-h)              # switch : Print help information
      print_help
      shift
      exit
      ;;
    --install)              # switch : Install script
      check_value "$1" "$2"
      options['install']="$2"
      shift 2
      ;;
    --nic)                  # switch : NIC
      check_value "$1" "$2"
      options['nic']="$2"
      shift 2
      ;;
    --nixconfig)            # switch : Nix configuration file
      check_value "$1" "$2"
      options['nixconfig']="$2"
      shift 2
      ;;
    --nixhwconfig)          # switch : Nix hardware configuration file
      check_value "$1" "$2"
      options['nixhwconfig']="$2"
      shift 2
      ;;
    --nixisoconfig)         # switch : Nix ISO configuration file
      check_value "$1" "$2"
      options['nixisoconfig']="$2"
      shift 2
      ;;
    --nixzfsconfig)         # switch : Nix ZFS configuration file
      check_value "$1" "$2"
      options['nixzfsconfig']="$2"
      shift 2
      ;;
    --nixdir)               # switch : Set Nix directory
      check_value "$1" "$2"
      options['nixdir']="$2"
      shift 2
      ;;
    --option*)              # switch : Option(s) to set
      check_value "$1" "$2"
      options_list+=("$2")
      shift 2
      ;;
    --password)             # switch : User password
      check_value "$1" "$2"
      options['password']="$2"
      shift 2
      ;;
    --prefix)               # switch : Install prefix
      check_value "$1" "$2"
      options['prefix']="$2"
      shift 2
      ;;
    --rootcrypt)            # switch : Root password crypt
      check_value "$1" "$2"
      options['rootcrypt']="$2"
      shift 2
      ;;
    --rootpassword)         # switch : Root password
      check_value "$1" "$2"
      options['rootpassword']="$2"
      shift 2
      ;;
    --rootpool)             # switch : Root pool name
      check_value "$1" "$2"
      options['rootpool']="$2"
      shift 2
      ;;
    --rootvol)              # switch : Root volume name
      check_value "$1" "$2"
      options['rootvol']="$2"
      shift 2
      ;;
    --runsize)              # switch : Run size
      check_value "$1" "$2"
      options['runsize']="$2"
      shift 2
      ;;
    --shell)                # switch : User Shell
      check_value "$1" "$2"
      options['shell']="$2"
      shift 2
      ;;
    --shellcheck)           # switch : Run shellcheck
      actions_list+=("shellcheck")
      shift
      ;;
    --source)               # switch : Source directory
      check_value "$1" "$2"
      options['source']="$2"
      shift 2
      ;;
    --sshkey)               # switch : SSH key
      check_value "$1" "$2"
      options['sshkey']="$2"
      shift 2
      ;;
    --sshkeyfile)           # switch : SSH key file
      check_value "$1" "$2"
      options['sshkeyfile']="$2"
      shift 2
      ;;
    --stateversion)         # switch : NixOS state version
      check_value "$1" "$2"
      options['stateversion']="$2"
      shift 2
      ;;
    --strict)               # switch : Enable strict mode
      options['strict']="true"
      shift
      ;;
    --sudocommand*)         # switch : Sudo commands
      check_value "$1" "$2"
      options['sudocommand']="$2"
      shift 2
      ;;
    --sudooption*)          # switch : Sudo options
      check_value "$1" "$2"
      options['sudooptions']="$2"
      shift 2
      ;;
    --sudouser*)            # switch : Sudo users
      check_value "$1" "$2"
      options['sudousers']="$2"
      shift 2
      ;;
    --systempackages)       # switch : NixOS state version
      check_value "$1" "$2"
      options['systempackages']="$2"
      shift 2
      ;;
    --swapsize)             # switch : Swap size
      check_value "$1" "$2"
      options['swapsize']="$2"
      shift 2
      ;;
    --target)               # switch : Target directory
      check_value "$1" "$2"
      options['target']="$2"
      shift 2
      ;;
    --usage)                # switch : Action to perform
      check_value "$1" "$2"
      usage="$2"
      print_usage "${usage}"
      shift 2
      exit
      ;;
    --username)             # switch : User username
      check_value "$1" "$2"
      options['username']="$2"
      shift 2
      ;;
    --verbose)              # switch : Enable verbose mode
      options['verbose']="true"
      shift
      ;;
    --version|-V)           # switch : Print version information
      print_version
      exit
      ;;
    --workdir)              # switch : Set Nix work directory
      check_value "$1" "$2"
      options['workdir']="$2"
      shift 2
      ;;
    --zfsinstall)           # switch : ZFS install script
      check_value "$1" "$2"
      options['zfsinstall']="$2"
      shift 2
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
