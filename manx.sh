#!env bash

# Name:         manx (Make Automated NixOS)
# Version:      0.6.8
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
# shellcheck disable=SC2034
# shellcheck disable=SC1090
# shellcheck disable=SC2129
# shellcheck disable=SC2199
# shellcheck disable=SC2239

# Create arrays

declare -A os
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
  options['zfsoptions']="-O mountpoint=none -O atime=off -O compression=lz4 -O xattr=sa -O acltype=posixacl -o ashift=12" # option: ZFS pool options
  # Packages
  packages="ansible curl dmidecode efibootmgr file lsb-release lshw pciutils vim wget"
  # Imports
  imports['hardware']="<nixpkgs/nixos/modules/profiles/all-hardware.nix>"                                         # import : NixOS hardware profile
  imports['base']="<nixpkgs/nixos/modules/profiles/base.nix>"                                                     # import : NixOS base profile
  imports['minimal']="<nixpkgs/nixos/modules/installer/cd-dvd/installation-cd-minimal-combined.nix>"              # -l import : NixOS CD minimal profile
  imports['channel']="<nixpkgs/nixos/modules/installer/cd-dvd/channel.nix>"                                       # import : NixOS CD channel profile
  options['isoimports']="${imports['minimal']} ${imports['channel']}"                                             # option: - ISO imports
  # Options
  options['prefix']="ai"                                                      # option : Install directory prefix
  options['verbose']="false"                                                  # option : Verbose mode
  options['strict']="false"                                                   # option : Strict mode
  options['dryrun']="false"                                                   # option : Dryrun mode
  options['debug']="false"                                                    # option : Debug mode
  options['force']="false"                                                    # option : Force actions
  options['mask']="false"                                                     # option : Mask identifiers
  options['yes']="false"                                                      # option : Answer yes to questions
  options['dhcp']="true"                                                      # option : DHCP network
  options['swap']="true"                                                      # option : Use swap
  options['lvm']="false"                                                      # option : Use LVM
  options['zsh']="true"                                                       # option : Enable zsh
  options['preserve']="false"                                                 # option : Preserve ISO
  options['workdir']="${HOME}/${script['name']}"                              # option : Script work directory
  options['sshkey']=""                                                        # option : SSH key
  options['disk']="first"                                                     # option : Disk
  options['nic']="first"                                                      # option : NIC
  options['zfs']="true"                                                       # option : ZFS filesystem
  options['ext4']="false"                                                     # option : EXT4 filesystem
  options['locale']="en_AU.UTF-8"                                             # option : Locale
  options['timezone']="Australia/Melbourne"                                   # option : Timezone
  options['username']=""                                                      # option : Username
  options['userpassword']="nixos"                                             # option : User Password
  options['usercrypt']=""                                                     # option : User Password Crypt
  options['hostname']="nixos"                                                 # option : Hostname 
  options['sshkeyfile']=""                                                    # option : SSH key file
  options['bootfs']="vfat"                                                    # option : Boot filesystem
  options['rootfs']="zfs"                                                     # option : Root filesystem
  options['firmware']="bios"                                                  # option : Boot firmware type
  options['bios']="true"                                                      # option : BIOS Boot firmware
  options['uefi']="false"                                                     # option : UEFI Boot firmware
  options['isomount']="/iso"                                                  # option : ISO mount directory
  options['oneshot']="${options['workdir']}/${options['prefix']}/oneshot.sh"  # option : Oneshot script
  options['install']="${options['workdir']}/${options['prefix']}/install.sh"  # option : Install script
  options['nixisoconfig']="${options['workdir']}/iso.nix"                     # option : NixOS ISO config
  options['zfsinstall']="${options['workdir']}/${options['prefis']}/zfs.sh"   # option : ZFS install script
  options['extinstall']="${options['workdir']}/${options['prefis']}/ext4.sh"  # option : EXT4 install script
  options['runsize']="50%"                                                    # option : Run size
  options['source']="${options['workdir']}/${options['prefix']}"              # option : Source directory for ISO additions
  options['target']="/${options['prefix']}"                                   # option : Target directory for ISO additions
  options['installdir']="/mnt"                                                # option : Install directory
  options['nixdir']="${options['installdir']}/etc/nixos"                      # option : NixOS directory for configs
  options['nixconfig']="${options['nixdir']}/configuration.nix"               # option : NixOS install config file
  options['nixhwconfig']="${options['nixdir']}/hardware-configuration.nix"    # option : NixOS install hardware config file
  options['nixzfsconfig']="${options['nixdir']}/zfs.nix"                      # option : NixOS install ZFS config file
  options['systemd-boot']="true"                                              # option : systemd-boot
  options['touchefi']="true"                                                  # option : Touch EFI
  options['sshserver']="true"                                                 # option : Enable SSH server
  options['swapsize']="2G"                                                    # option : Swap partition size
  options['rootsize']="100%"                                                  # option : Root partition size
  options['rootpool']="rpool"                                                 # option : Root pool name
  options['rootpassword']="nixos"                                             # option : Root password
  options['rootcrypt']=""                                                     # option : Root password crypt
  options['username']="nixos"                                                 # option : User Username
  options['usergecos']="nixos"                                                # option : User GECOS
  options['usershell']="zsh"                                                  # option : User Shell
  options['normaluser']="true"                                                # option : Normal User
  options['extragroups']="wheel"                                              # option : Extra Groups
  options['sudousers']="${options['username']}"                               # option : Sudo Users
  options['sudocommand']="ALL"                                                # option : Sudo Command
  options['sudooptions']="NOPASSWD"                                           # option : Sudo Options
  options['systempackages']="${packages}"                                     # option : System Packages
  options['experimental-features']="nix-command flakes"                       # option : Experimental Features
  options['unfree']="false"                                                   # option : Allow Non Free Packages
  options['stateversion']="25.05"                                             # option : State version
  options['unattended']="true"                                                # option : Execute install script
  options['attended']="false"                                                 # option : Don't execute install script
  options['reboot']="true"                                                    # option : Reboot after install
  options['nixinstall']="true"                                                # option : Run Nix installer on ISO
  options['networkmanager']="true"                                            # option : Enable NetworkManager
  options['xserver']="false"                                                  # option : Enable Xserver
  options['keymap']="au"                                                      # option : Keymap
  options['videodriver']=""                                                   # option : Video Driver
  options['sddm']="false"                                                     # option : KDE Plasma Login Manager
  options['plasma6']="false"                                                  # option : KDE Plasma
  options['gdm']="false"                                                      # option : Gnome Login Manager
  options['gnome']="false"                                                    # option : Gnome
  options['rootkit']="false"                                                  # option : Enable rootkit protection
  options['bridge']="false"                                                   # option : Enable bridge
  options['bridgenic']="br0"                                                  # option : Bridge NIC
  options['ip']=""                                                            # option : IP Address
  options['cidr']="24"                                                        # option : CIDR
  options['dns']="8.8.8.8"                                                    # option : DNS/Nameserver address
  options['gateway']=""                                                       # option : Gateway address
  options['standalone']="false"                                               # option : Package all requirements on ISO
  options['rootvolname']="nixos"                                              # option : Root volume name
  options['bootvolname']="boot"                                               # option : Boot volume name
  options['mbrvolname']="bootcode"                                            # option : Boot volume name
  options['swapvolname']="swap"                                               # option : Swap volume name
  options['uefivolname']="uefi"                                               # option : UEFI volume name
  options['homevolname']="home"                                               # option : Home volume name
  options['nixvolname']="nix"                                                 # option : Nix volume name
  options['usrvolname']="usr"                                                 # option : Usr volume name
  options['varvolname']="var"                                                 # option : Var volume name
  options['tempdir']="/tmp"                                                   # option : Temp directory
  options['mbrpart']="1"                                                      # option : MBR partition
  options['rootpart']="2"                                                     # option : Root partition
  options['efipart']="3"                                                      # option : UEFI/Boot partition
  options['swappart']="4"                                                     # option : Swap partition
  options['devnodes']="/dev/disk/by-uuid"                                     # option : Device nodesDevice nodes
  options['logdir']="/var/log"                                                # option : Install log dir
  options['logfile']="${options['logdir']}/install.log"                       # option : Install log file
  options['bootsize']="512M"                                                  # option : Boot partition size
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
  if [ "${options['zsh']}" = "true" ]; then
    options['usershell']="zsh"
  fi
  if [ ! "${options['usershell']}" = "zsh" ]; then
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


# Function: get_password_crypt
#
# Get Password Crypt

get_password_crypt () {
  if [ ! "${options['userpassword']}" = "" ]; then
    if [ "${options['usercrypt']}" = "" ]; then
      options['usercrypt']=$( mkpasswd --method=sha-512 "${options['userpassword']}" )
    fi
  fi
  if [ ! "${options['rootpassword']}" = "" ]; then
    if [ "${options['rootcrypt']}" = "" ]; then
      options['rootcrypt']=$( mkpasswd --method=sha-512 "${options['rootpassword']}" )
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

# Function: create_nix_config
#
# Create NixOS config

create_nix_iso_config () {
  check_nix_config
  get_ssh_key
  verbose_message "Creating ${options['nixisoconfig']}"
  tee "${options['nixisoconfig']}" << NIXISOCONFIG
# ISO build config
{ config, pkgs, ... }:
{
  imports = [ ${options['isoimports']} ];

  # Add contents to ISO
  isoImage = {
    contents = [
      { source = ${options['source']} ;
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

  # Bootloader
  # boot.loader.systemd-boot.enable = ${options['systemd-boot']};
  # boot.loader.efi.canTouchEfiVariables = ${options['touchefi']};

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

  # OpenSSH
  services.openssh.enable = ${options['sshserver']};

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
      sudo ${options['isomount']}/${options['prefix']}/install.sh 
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
  verbose_message "Creating ${options['oneshot']}"
  tee "${options['oneshot']}" << ONESHOT
#!/run/current-system/sw/bin/bash
set -x
export PATH="/run/wrappers/bin:/root/.nix-profile/bin:/nix/profile/bin:/root/.local/state/nix/profile/bin:/etc/profiles/per-user/root/bin:/nix/var/nix/profiles/default/bin:/run/current-system/sw/bin"
mkdir -p ${options['tempdir']}/${options['prefix']}
cp ${options['isomount']}/${options['prefix']}/*.sh ${options['tempdir']}/${options['prefix']}
chmod +x ${options['installdir']}/${options['prefix']}/*.sh
sudo ${options['tempdir']}/${options['prefix']}/install.sh
ONESHOT
chmod +x "${options['oneshot']}"
}


# Function: create_install_script
#
# Create install script

create_install_script () {
  check_nix_config
  get_ssh_key
  get_password_crypt
  verbose_message "Creating ${options['install']}"
  tee "${options['install']}" << INSTALL
#!/run/current-system/sw/bin/bash
set -x
export PATH="/run/wrappers/bin:/root/.nix-profile/bin:/nix/profile/bin:/root/.local/state/nix/profile/bin:/etc/profiles/per-user/root/bin:/nix/var/nix/profiles/default/bin:/run/current-system/sw/bin"

# Set general environment
USE_SWAP="${options['swap']}"
USE_LVM="${options['lvm']}"
USE_ZSH="${options['zsh']}"
USE_DHCP="${options['dhcp']}"
USE_BRIDGE="${options['bridge']}"
SSH_SERVER="${options['sshserver']}"
BRIDGE_DEV="${options['bridgenic']}"
DO_REBOOT="${options['reboot']}"
DO_INSTALL="${options['nixinstall']}"
ROOT_FS="${options['rootfs']}"
BOOT_FS="${options['bootfs']}"
ROOT_DISK="${options['disk']}"
MBR_PART="${options['mbrpart']}"
ROOT_PART="${options['rootpart']}"
EFI_PART="${options['efipart']}"
BOOT_PART="${options['efipart']}"
SWAP_PART="${options['swappart']}"
SWAP_SIZE="${options['swapsize']}"
ROOT_SIZE="${options['rootsize']}"
BOOT_SIZE="${options['bootsize']}"
ROOT_POOL="${options['rootpool']}"
SWAP_NAME="${options['swapvolname']}"
TARGET_DIR="${options['installdir']}"
MBR_NAME="${options['mbrpartname']}"
LOCALE="${options['locale']}"
DEV_NODES="${options['devnodes']}"
LOG_DIR="${options['logdir']}"
LOG_FILE="${options['logfile']}"
TIME_ZONE="${options['timezone']}"
USER_SHELL="${options['usershell']}"
USER_NAME="${options['username']}"
USER_GROUPS="${options['extragroups']}"
USER_GECOS="${options['usergecos']}"
NORMAL_FLAG="${options['normaluser']}"
SUDO_COMMAND="${options['sudocommand']}"
SUDO_OPTIONS="${options['sudooptions']}"
ROOT_PASSWORD="${options['rootpassword']}"
ROOT_CRYPT=\$( mkpasswd --method=sha-512 "\${ROOT_PASSWORD}" )
USER_PASSWORD="${options['userpassword']}"
USER_CRYPT=\$( mkpasswd --method=sha-512 "\${USER_PASSWORD}" )
STATE_VERSION="${options['stateversion']}"
HOST_NAME="${options['hostname']}"
HOST_ID=\$( head -c 8 /etc/machine-id )
NIX_DIR="\${TARGET_DIR}/etc/nixos"
NIX_CFG="\${NIX_DIR}/configuration.nix"
HW_CFG="\${NIX_DIR}/hardware-configuration.nix"
ZFS_OPTIONS="${options['zfsoptions']} -R \${TARGET_DIR}"
AVAIL_MODS="\"ahci\" \"xhci_pci\" \"virtio_pci\" \"sr_mod\" \"virtio_blk\""
NIX_EXP=""
USE_UNFREE="${options['unfree']}"

# Set up non DHCP environment
NIC_DEV="${options['nic']}"
NIC_DNS="${options['dns']}"
NIC_IP="${options['ip']}"
NIC_GW="${options['gateway']}"
NIC_CIDR="${options['cidr']}"
if [ "\${USE_DHCP}" = "false" ]; then
  if [ "\${NIC_DEV}" = "first" ]; then
    NIC_DEV=\$( ip link | grep "state UP" | awk '{ print \$2}' | head -1 | grep ^e | cut -f1 -d: )
  fi
fi

# Discover first disk
if [ "\${ROOT_DISK}" = "first" ]; then
  ROOT_DISK=\$( lsblk -x TYPE|grep disk |sort |head -1 |awk '{print \$1}' )
  ROOT_DISK="/dev/\${ROOT_DISK}"
fi

# Check we are using only one volume manager
if [ "\${USE_LVM}" = "true" ] && [ "\${ROOT_FS}" = "zfs" ]; then
  echo "Cannot use two volume managers (LVM and ZFS)"
  exit
fi

# QEMU check
QEMU_CHECK=\$( cat /proc/ioports |grep QEMU )
if [ -n "\${QEMU_CHECK}" ]; then
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
  GRUB_DEV="\${ROOT_DISK}"
  BOOT_NAME="biosboot"
fi

# Set root partition type
case "\${ROOT_FS}" in
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
umount -Rl \${TARGET_DIR}
zpool destroy -f \${ROOT_POOL}
lvremove -f \${ROOT_POOL}
wipefs \${ROOT_DISK}
sgdisk --zap-all \${ROOT_DISK}
zpool labelclear -f \${ROOT_DISK}
partprobe \${ROOT_DISK}
sleep 2s
if [ "\${BIOS_FLAG}" = "true" ]; then
  sgdisk -a \${MBR_PART} -n \${MBR_PART}:0:+1M -t \${MBR_PART}:EF02 -c \${MBR_PART}:\${MBR_NAME} \${ROOT_DISK}
fi
if [ "\${USE_LVM}" = "true" ]; then
  sgdisk -n \${ROOT_PART}:0:0 -t \${ROOT_PART}:\${PART_FLAG} -c \${ROOT_PART}:\${ROOT_NAME} \${ROOT_DISK}
  pvcreate -f \${ROOT_DISK}\${ROOT_PART}
  vgcreate -f \${ROOT_POOL} \${ROOT_DISK}\${ROOT_PART}
  lvcreate -y --size \${BOOT_SIZE} --name \${BOOT_NAME} \${ROOT_POOL}
  if [ "\${USE_SWAP}" = "true" ]; then
    lvcreate -y --size \${SWAP_SIZE} --name \${SWAP_NAME} \${ROOT_POOL}
  fi
  lvcreate -y --size \${ROOT_SIZE} --name \${ROOT_NAME} \${ROOT_POOL}
  SWAP_VOL="/dev/\${ROOT_POOL}/\${SWAP_NAME}"
  BOOT_VOL="/dev/\${ROOT_POOL}/\${BOOT_NAME}"
  ROOT_VOL="/dev/\${ROOT_POOL}/\${ROOT_NAME}"
  lvextend -l +100%FREE \${ROOT_VOL} 
  INIT_MODS="\"dm-snapshot\" \"dm-raid\" \"dm-cache-default\""
  ROOT_SEARCH=\$( ls -l \${ROOT_VOL} | awk '{print \$11}' |cut -f2 -d/ )
  BOOT_SEARCH=\$( ls -l \${BOOT_VOL} | awk '{print \$11}' |cut -f2 -d/ )
  SWAP_SEARCH=\$( ls -l \${SWAP_VOL} | awk '{print \$11}' |cut -f2 -d/ )
else
  sgdisk -n \${EFI_PART}:2M:+\${BOOT_SIZE} -t \${EFI_PART}:EF00 -c \${EFI_PART}:\${BOOT_NAME} \${ROOT_DISK}
  if [ "\${USE_SWAP}" = "true" ]; then
    sgdisk -n \${SWAP_PART}:0:+\${SWAP_SIZE} -t \${SWAP_PART}:8200 -c \${SWAP_PART}:\${SWAP_NAME} \${ROOT_DISK}
  fi
  sgdisk -n \${ROOT_PART}:0:0 -t \${ROOT_PART}:\${PART_FLAG} -c \${ROOT_PART}:\${ROOT_NAME} \${ROOT_DISK}
  SWAP_VOL="\${ROOT_DISK}\${SWAP_PART}"
  BOOT_VOL="\${ROOT_DISK}\${BOOT_PART}"
  ROOT_VOL="\${ROOT_DISK}\${ROOT_PART}"
  INIT_MODS=""
  ROOT_SUFFIX=\$( echo "\${ROOT_DISK}" | cut -f3 -d/  )
  ROOT_SEARCH="\${ROOT_SUFFIX}\${ROOT_PART}"
  BOOT_SEARCH="\${ROOT_SUFFIX}\${BOOT_PART}"
  SWAP_SEARCH="\${ROOT_SUFFIX}\${SWAP_PART}"
fi
partprobe \${ROOT_DISK}
sleep 2s

# Make and mount filesystems
if [ "\${USE_SWAP}" = "true" ]; then
  mkswap -L \${SWAP_NAME} \${SWAP_VOL}
  swapon \${SWAP_VOL}
fi
if [ "\${ROOT_FS}" = "zfs" ]; then
  zpool create -f \${ZFS_OPTIONS} \${ROOT_POOL} \${ROOT_DISK}\${ROOT_PART}
  for DIR_NAME in root nix var home; do
    zfs create -o mountpoint=legacy \${ROOT_POOL}/\${DIR_NAME}
  done
  mount -t zfs \${ROOT_POOL}/root \${TARGET_DIR}
  for DIR_NAME in nix var home; do
    mkdir -p \${TARGET_DIR}/\${DIR_NAME}
    mount -t \${ROOT_FS} \${ROOT_POOL}/\${DIR_NAME} \${TARGET_DIR}/\${DIR_NAME}
  done
else
  if [ "\${ROOT_FS}" = "ext4" ]; then
    mkfs.\${ROOT_FS} -F -L \${ROOT_NAME} \${ROOT_VOL}
  else
    mkfs.\${ROOT_FS} -f -L \${ROOT_NAME} \${ROOT_VOL}
  fi
  mount -t \${ROOT_FS} \${ROOT_VOL} \${TARGET_DIR}
fi
mkfs.\${BOOT_FS} \${BOOT_VOL}
mkdir \${TARGET_DIR}/boot
mount \${BOOT_VOL} \${TARGET_DIR}/boot
mkdir -p \${NIX_DIR}
rm \${NIX_DIR}/*

# Create configuration.nix
tee \${NIX_CFG} << NIX_CFG
{ config, lib, pkgs, ... }:
{
  imports = [ ./hardware-configuration.nix ];
  boot.loader.systemd-boot.enable = \${UEFI_FLAG};
  boot.loader.efi.canTouchEfiVariables = \${UEFI_FLAG};
  boot.loader.grub.devices = [ "\${GRUB_DEV}" ];
  boot.initrd.supportedFilesystems = ["\${ROOT_FS}"];
  boot.supportedFilesystems = [ "\${ROOT_FS}" ];
  boot.zfs.devNodes = "\${DEV_NODES}";
  services.lvm.boot.thin.enable = \${USE_LVM};
  # HostID and Hostname
  networking.hostId = "\${HOST_ID}";
  networking.hostName = "\${HOST_NAME}";
  # Services
  services.openssh.enable = \${SSH_SERVER};
  # Additional Nix options
  nix.settings.experimental-features = "\${NIX_EXP}";
  # Allow unfree packages
  nixpkgs.config.allowUnfree = \${USE_UNFREE};
  # Set your time zone.
  time.timeZone = "\${TIME_ZONE}";
  # Select internationalisation properties.
  i18n.defaultLocale = "\${LOCALE}";
  i18n.extraLocaleSettings = {
    LC_ADDRESS = "\${LOCALE}";
    LC_IDENTIFICATION = "\${LOCALE}";
    LC_MEASUREMENT = "\${LOCALE}";
    LC_MONETARY = "\${LOCALE}";
    LC_NAME = "\${LOCALE}";
    LC_NUMERIC = "\${LOCALE}";
    LC_PAPER = "\${LOCALE}";
    LC_TELEPHONE = "\${LOCALE}";
    LC_TIME = "\${LOCALE}";
  };
  # Define a user account. 
  users.users.\${USER_NAME} = {
    shell = pkgs.\${USER_SHELL};
    isNormalUser = \${NORMAL_FLAG};
    description = "\${USER_GECOS}";
    extraGroups = [ "\${USER_GROUPS}" ];
    openssh.authorizedKeys.keys = [ "\${SSH_KEY}" ];
    hashedPassword = "\${USER_CRYPT}";
  };
  programs.zsh.enable = \${USE_ZSH};

  # Sudo configuration
  security.sudo.extraRules= [
    { users = [ "\${USER_NAME}" ];
      commands = [
        { command = "\${SUDO_COMMAND}" ;
          options= [ "\${SUDO_OPTIONS}" ];
        }
      ];
    }
  ];
  networking.useDHCP = lib.mkDefault \${USE_DHCP};
NIX_CFG
if [ "\${USE_DHCP}" = "false" ]; then
  if [ "\${USE_BRIDGE}" = "false" ]; then
    tee -a \${NIX_CFG} << NIX_CFG
  networking = {
    interfaces."\${NIC_DEV}".useDHCP = \${USE_DHCP};
    interfaces."\${NIC_DEV}".ipv4.addresses = [{
      address = "\${NIC_IP}";
      prefixLength = \${NIC_CIDR};
    }];
    defaultGateway = "\${NIC_GW}";
    nameservers = [ "\${NIC_DNS}" ];
  };
NIX_CFG
  else
    tee -a \${NIX_CFG} << NIX_CFG
  networking = {
    bridges."\${BRIDGE_DEV}".interfaces = [ "\${NIC_DEV}" ];
    interfaces."\${BRIDGE_DEV}".useDHCP = \${USE_DHCP};
    interfaces."\${NIC_DEV}".useDHCP = \${USE_DHCP};
    interfaces."\${BRIDGE_DEV}".ipv4.addresses = [{
      address = "\${NIC_IP}";
      prefixLength = \${NIC_CIDR};
    }];
    defaultGateway = "\${NIC_GW}";
    nameservers = [ "\${NIC_DNS}" ];
  };    
NIX_CFG
  fi
fi
tee -a \${NIX_CFG} << NIX_CFG
  users.users.root.initialHashedPassword = "\${ROOT_CRYPT}";
  nixpkgs.hostPlatform = lib.mkDefault "x86_64-linux";
  system.stateVersion = "\${STATE_VERSION}";
}
NIX_CFG

# Get device UUIDs
if [ "\${USE_SWAP}" = "true" ]; then
  SWAP_UUID=\$(ls -l \${DEV_NODES} |grep \${SWAP_SEARCH} |awk '{print \$9}' )
  SWAP_DEV="\${DEV_NODES}/\${SWAP_UUID}"
else
  SWAP_DEV=""
fi
BOOT_UUID=\$(ls -l \${DEV_NODES} |grep \${BOOT_SEARCH} |awk '{print \$9}' )
BOOT_DEV="\${DEV_NODES}/\${BOOT_UUID}"
ROOT_UUID=\$(ls -l \${DEV_NODES} |grep \${ROOT_SEARCH} |awk '{print \$9}' )
ROOT_DEV="\${DEV_NODES}/\${ROOT_UUID}"

# Create hardware-configuration.nix
tee \${HW_CFG} << HW_CFG
{ config, lib, pkgs, modulesPath, ... }:
{
  imports = [ \${HW_IMPORTS} ];
  boot.initrd.availableKernelModules = [ \${AVAIL_MODS} ];
  boot.initrd.kernelModules = [ \${INIT_MODS} ];
  boot.kernelModules = [ \${BOOT_MODS} ];
  boot.extraModulePackages = [ ];
HW_CFG
if [ "\${ROOT_FS}" = "zfs" ]; then
  tee -a \${HW_CFG} << HW_CFG
  fileSystems."/" = {
    device = "\${ROOT_POOL}/root";
    fsType = "\${ROOT_FS}";
    neededForBoot = true;
  };
  fileSystems."/nix" = {
    device = "\${ROOT_POOL}/nix";
    fsType = "\${ROOT_FS}";
  };
  fileSystems."/home" = {
    device = "\${ROOT_POOL}/home";
    fsType = "\${ROOT_FS}";
  };
  fileSystems."/var" = {
    device = "\${ROOT_POOL}/var";
    fsType = "\${ROOT_FS}";
  };
HW_CFG
else
  tee -a \${HW_CFG} << HW_CFG
  fileSystems."/" = {
    device = "\${ROOT_DEV}";
    fsType = "\${ROOT_FS}";
    neededForBoot = true;
  };
HW_CFG
fi
tee -a \${HW_CFG} << HW_CFG
  fileSystems."/boot" = {
    device = "\${BOOT_DEV}";
    fsType = "\${BOOT_FS}";
    options = [ "fmask=0022" "dmask=0022" ];
  };
  swapDevices = [ { device = "\${SWAP_DEV}"; } ];
}
HW_CFG

# Manual config creation command if you need it
# nixos-generate-config --root \${TARGET_DIR}

if [ "\${DO_INSTALL}" = "false" ]; then
  exit
fi

mkdir -p ${TARGET_DIR}/${LOG_DIR}

nixos-install -v --show-trace --no-root-passwd 2>&1 |tee \${TARGET_DIR}\${LOG_FILE}

umount -Rl \${TARGET_DIR}
zpool export -a
swapoff -a

if [ "\${DO_REBOOT}" = "true" ]; then
  reboot
fi

INSTALL
chmod +x "${options['install']}"
}

# Function: preserve_iso
#
# Preserve ISO

preserve_iso () {
  iso_file="$1"
  if [ "${options['output']}" = "" ]; then
    output_dir="${options['workdir']}/isos"
    temp_name=$( basename -s ".iso" "${iso_file}" )
    for param in unattended noreboot standalone lvm; do
      value="${options[${param}]}"
      if [ "${value}" = "true" ]; then
        temp_name="${temp_name}-${param}"
      fi
    done
    for param in disk nic ; do
      value="${options[${param}]}"
      if [ ! "${value}" = "first" ]; then
        temp_name="${temp_name}-${value}"
      fi
    done
    for param in ip username; do
      value="${options[${param}]}"
      if [ ! "${value}" = "" ]; then
        temp_name="${temp_name}-${value}"
      fi
    done
    temp_name="${temp_name}-${options['rootfs']}.iso"
    options['output']="${output_dir}/${temp_name}"
  fi
  output_dir=$( dirname "${options['output']}" )
  if [ ! -d "${output_dir}" ]; then
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
  iso_file=$( find "${iso_dir}" -name "*.iso" )
  if [ "${options['preserve']}" = "true" ]; then
    preserve_iso "${iso_file}"
  fi
  verbose_message "Generated ISO: ${iso_file}"
  if [ "${options['preserve']}" = "true" ]; then
    verbose_message "Preserved ISO: ${options['output']}"
  fi
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
    createnix*)           # action : Create NixOS ISO config
      create_nix_iso_config
      exit
      ;;
    createoneshot*)       # action : Create install script
      create_oneshot_script
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
    --action*)                  # switch : Action(s) to perform
      check_value "$1" "$2"
      actions_list+=("$2")
      shift 2
      ;;
    --bootsize)                 # switch : Boot partition size
      check_value "$1" "$2"
      options['bootsize']="$2"
      shift 2
      ;;
    --bridge)                   # switch : Enable bridge
      options['bridge']="true"
      shift
      ;;
    --bridgenic)                # switch : Bridge NIC
      check_value "$1" "$2"
      options['bridgenic']="$2"
      options['bridge']="true"
      options['dhcp']="false"
      shift 2
      ;;
    --bootf*)                   # switch : Boot Filesystem
      check_value "$1" "$2"
      options['bootfs']="$2"
      shift 2
      ;;
    --bootvol*)                 # switch : Boot volume name
      check_value "$1" "$2"
      options['bootvolname']="$2"
      shift 2
      ;;
    --cidr)                     # switch : CIDR
      check_value "$1" "$2"
      options['cidr']="$2"
      options['dhcp']="false"
      shift 2
      ;;
    --createinstall*)           # switch : Create install script
      actions_list+=("createinstall")
      shift
      ;;
    --createiso)                # switch : Create ISO
      actions_list+=("createiso")
      shift
      ;;
    --createnix*)               # switch : Create NixOS ISO config
      actions_list+=("createnix")
      shift
      ;;
    --createoneshot*)           # switch : Create oneshot script
      actions_list+=("createoneshot")
      shift
      ;;
    --usercrypt|--crypt)        # switch : User Password Crypt 
      check_value "$1" "$2"
      options['usercrypt']="$2"
      shift 2
      ;;
    --debug)                    # switch : Enable debug mode
      options['debug']="true"
      shift
      ;;
    --dhcp)                     # switch : Enable DHCP
      options['dhcp']="true"
      shift
      ;;
    --disk)                     # switch : SSH key
      check_value "$1" "$2"
      options['disk']="$2"
      shift 2
      ;;
    --dns|--nameserver)         # switch : DNS/Nameserver address
      check_value "$1" "$2"
      options['dns']="$2"
      options['dhcp']="false"
      shift 2
      ;;
    --dryrun)                   # switch : Enable debug mode
      options['dryrun']="true"
      shift
      ;;
    --experimental*)            # switch : SSH key
      check_value "$1" "$2"
      options['experimental-features']="$2"
      shift 2
      ;;
    --extragroup*)              # switch : Extra groups
      check_value "$1" "$2"
      options['extragroups']="$2"
      shift 2
      ;;
    --firmware)                 # switch : Boot firmware type
      check_value "$1" "$2"
      options['firmware']="$2"
      shift 2
      ;;
    --force)                    # switch : Enable force mode
      options['force']="true"
      shift
      ;;
    --gateway)                  # switch : Gateway address
      check_value "$1" "$2"
      options['gateway']="$2"
      options['dhcp']="false"
      shift 2
      ;;
    --gecos|--usergecos)        # switch : GECOS field
      check_value "$1" "$2"
      options['usergecos']="$2"
      shift 2
      ;;
    --help|-h)                  # switch : Print help information
      print_help
      shift
      exit
      ;;
    --hostname)                 # switch : Hostname
      check_value "$1" "$2"
      options['hostname']="$2"
      shift 2
      ;;
    --imports)                  # switch : Imports for system
      check_value "$1" "$2"
      options['imports']="$2"
      shift 2
      ;;
    --install)                  # switch : Install script
      check_value "$1" "$2"
      options['install']="$2"
      shift 2
      ;;
    --installdir)               # switch : Install directory where destination disk is mounted
      check_value "$1" "$2"
      options['installdir']="$2"
      shift 2
      ;;
    --ip)                       # switch : IP address
      check_value "$1" "$2"
      options['ip']="$2"
      options['dhcp']="false"
      shift 2
      ;;
    --isoimports)               # switch : NixOS imports for ISO build
      check_value "$1" "$2"
      options['isoimports']="$2"
      shift 2
      ;;
    --isomount)                 # switch : Install ISO mount directory
      check_value "$1" "$2"
      options['isomount']="$2"
      shift 2
      ;;
    --keymap)                   # switch : Keymap
      check_value "$1" "$2"
      options['keymap']="$2"
      shift 2
      ;;
    --locale)                   # switch : Locale
      check_value "$1" "$2"
      options['locale']="$2"
      shift 2
      ;;
    --logfile)                  # switch : Locale
      check_value "$1" "$2"
      options['logfile']="$2"
      shift 2
      ;;
    --lvm)                      # switch : Enable LVM
      options['lvm']="true"
      shift
      ;;
    --mbrpartname)              # switch : MBR partition name
      check_value "$1" "$2"
      options['mbrpartname']="$2"
      shift 2
      ;;
    --nic)                      # switch : NIC
      check_value "$1" "$2"
      options['nic']="$2"
      shift 2
      ;;
    --nixconfig)                # switch : NixOS configuration file
      check_value "$1" "$2"
      options['nixconfig']="$2"
      shift 2
      ;;
    --nixdir)                   # switch : Set NixOS directory
      check_value "$1" "$2"
      options['nixdir']="$2"
      shift 2
      ;;
    --nixhwconfig)              # switch : NixOS hardware configuration file
      check_value "$1" "$2"
      options['nixhwconfig']="$2"
      shift 2
      ;;
    --nixinstall)               # switch : Run NixOS install script automatically on ISO
      options['nixinstall']="true"
      shift
      ;;
    --nixisoconfig)             # switch : NixOS ISO configuration file
      check_value "$1" "$2"
      options['nixisoconfig']="$2"
      shift 2
      ;;
    --option*)                  # switch : Option(s) to set
      check_value "$1" "$2"
      options_list+=("$2")
      shift 2
      ;;
    --output*)                  # switch : Output file
      check_value "$1" "$2"
      options['output']="$2"
      options['preserve']="true"
      shift 2
      ;;
    --password|--userpassword)  # switch : User password
      check_value "$1" "$2"
      options['userpassword']="$2"
      shift 2
      ;;
    --prefix)                   # switch : Install prefix
      check_value "$1" "$2"
      options['prefix']="$2"
      shift 2
      ;;
    --preserve)                 # switch : Preserve output file
      options['preserve']="true"
      shift
      ;;
    --reboot)                   # switch : Enable reboot after install
      options['sshserver']="true"
      shift
      ;;
    --rootcrypt)                # switch : Root password crypt
      check_value "$1" "$2"
      options['rootcrypt']="$2"
      shift 2
      ;;
    --rootf*|--filesystem)      # switch : Root Filesystem
      check_value "$1" "$2"
      options['rootfs']="$2"
      shift 2
      ;;
    --rootpassword)             # switch : Root password
      check_value "$1" "$2"
      options['rootpassword']="$2"
      shift 2
      ;;
    --rootpool)                 # switch : Root pool name
      check_value "$1" "$2"
      options['rootpool']="$2"
      shift 2
      ;;
    --rootsize)                 # switch : Root partition size
      check_value "$1" "$2"
      options['rootsize']="$2"
      shift 2
      ;;
    --rootvol*)                 # switch : Root volume name
      check_value "$1" "$2"
      options['rootvolname']="$2"
      shift 2
      ;;
    --runsize)                  # switch : Run size
      check_value "$1" "$2"
      options['runsize']="$2"
      shift 2
      ;;
    --shell|usershell)          # switch : User Shell
      check_value "$1" "$2"
      options['usershell']="$2"
      shift 2
      ;;
    --shellcheck)               # switch : Run shellcheck
      actions_list+=("shellcheck")
      shift
      ;;
    --source)                   # switch : Source directory for ISO additions
      check_value "$1" "$2"
      options['source']="$2"
      shift 2
      ;;
    --sshkey)                   # switch : SSH key
      check_value "$1" "$2"
      options['sshkey']="$2"
      shift 2
      ;;
    --sshkeyfile)               # switch : SSH key file
      check_value "$1" "$2"
      options['sshkeyfile']="$2"
      shift 2
      ;;
    --sshserver)                # switch : Enable strict mode
      options['sshserver']="true"
      shift
      ;;
    --standalone)               # switch : Create a standalone ISO
      options['standalone']="true"
      shift
      ;;
    --stateversion)             # switch : NixOS state version
      check_value "$1" "$2"
      options['stateversion']="$2"
      shift 2
      ;;
    --strict)                   # switch : Enable strict mode
      options['strict']="true"
      shift
      ;;
    --sudocommand*)             # switch : Sudo commands
      check_value "$1" "$2"
      options['sudocommand']="$2"
      shift 2
      ;;
    --sudooption*)              # switch : Sudo options
      check_value "$1" "$2"
      options['sudooptions']="$2"
      shift 2
      ;;
    --sudouser*)                # switch : Sudo users
      check_value "$1" "$2"
      options['sudousers']="$2"
      shift 2
      ;;
    --systempackages)           # switch : NixOS state version
      check_value "$1" "$2"
      options['systempackages']="$2"
      shift 2
      ;;
    --swap)                     # switch : Enable swap
      options['swap']="true"
      shift
      ;;
    --swapsize)                 # switch : Swap partition size
      check_value "$1" "$2"
      options['swapsize']="$2"
      options['swap']="true"
      shift 2
      ;;
    --swapvol*)                 # switch : Swap volume name
      check_value "$1" "$2"
      options['swapvolname']="$2"
      options['swap']="true"
      shift 2
      ;;
    --target*)                  # switch : Target directory for ISO additions
      check_value "$1" "$2"
      options['target']="$2"
      shift 2
      ;;
    --temp*)                    # switch : Target directory
      check_value "$1" "$2"
      options['tempdir']="$2"
      shift 2
      ;;
    --usage)                    # switch : Action to perform
      check_value "$1" "$2"
      usage="$2"
      print_usage "${usage}"
      shift 2
      exit
      ;;
    --username)                 # switch : User username
      check_value "$1" "$2"
      options['username']="$2"
      shift 2
      ;;
    --verbose)                  # switch : Enable verbose mode
      options['verbose']="true"
      shift
      ;;
    --version|-V)               # switch : Print version information
      print_version
      exit
      ;;
    --videodriver)              # switch : Video Driver
      check_value "$1" "$2"
      options['videodriver']="$2"
      shift 2
      ;;
    --workdir)                  # switch : Set script work directory
      check_value "$1" "$2"
      options['workdir']="$2"
      shift 2
      ;;
    --zfsinstall)               # switch : ZFS install script
      check_value "$1" "$2"
      options['zfsinstall']="$2"
      shift 2
      ;;
    --zsh)                      # switch : Enable zsh
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
