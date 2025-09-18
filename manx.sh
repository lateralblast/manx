#!env bash

# Name:         manx (Manage/Automate NiXOS)
# Version:      0.4.7
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
  # Packages
  packages="curl dmidecode efibootmgr file lsb-release lshw pciutils vim wget"
  # Imports
  imports['hardware']="<nixpkgs/nixos/modules/profiles/all-hardware.nix>"                                         # import : Nix hardware profile
  imports['base']="<nixpkgs/nixos/modules/profiles/base.nix>"                                                     # import : Nix base profile
  imports['minimal']="<nixpkgs/nixos/modules/installer/cd-dvd/installation-cd-minimal-combined.nix>"              # -l import : Nix CD minimal profile
  imports['channel']="<nixpkgs/nixos/modules/installer/cd-dvd/channel.nix>"                                       # import : Nix CD channel profile
#  options['isoimports']="${imports['hardware']} ${imports['base']} ${imports['minimal']} ${imports['channel']}"   # option: - ISO imports
  options['isoimports']="${imports['minimal']} ${imports['channel']}"                                             # option: - ISO imports
  # Options
  options['verbose']="false"                                                # option : Verbose mode
  options['strict']="false"                                                 # option : Strict mode
  options['dryrun']="false"                                                 # option : Dryrun mode
  options['debug']="false"                                                  # option : Debug mode
  options['force']="false"                                                  # option : Force actions
  options['mask']="false"                                                   # option : Mask identifiers
  options['yes']="false"                                                    # option : Answer yes to questions
  options['dhcp']="true"                                                    # option : DHCP network
  options['workdir']="${HOME}/${script['name']}"                            # option : Nix work directory
  options['sshkey']=""                                                      # option : SSH key
  options['disk']="first"                                                   # option : Disk
  options['nic']="first"                                                    # option : NIC
  options['zfs']="false"                                                    # option : ZFS filesystem
  options['ext4']="true"                                                    # option : EXT4 filesystem
  options['language']="en_AU.UTF-8"                                         # option : Language
  options['timezone']="Australia/Melbourne"                                 # option : Timezone
  options['username']=""                                                    # option : Username
  options['userpassword']="nixos"                                           # option : User Password
  options['usercrypt']=""                                                   # option : User Password Crypt
  options['hostname']="nixos"                                               # option : Hostname 
  options['sshkeyfile']=""                                                  # option : SSH key file
  options['filesystem']="ext4"                                              # option : Root filesystem
  options['firmware']="bios"                                                # option : Boot firmware type
  options['bios']="true"                                                    # option : BIOS Boot firmware
  options['uefi']="false"                                                   # option : UEFI Boot firmware
  options['install']="${options['workdir']}/ai/install.sh"                  # option : Install script
  options['nixisoconfig']="${options['workdir']}/iso.nix"                   # option : Nix ISO config
  options['zfsinstall']="${options['workdir']}/ai/zfs.sh"                   # option : ZFS install script
  options['extinstall']="${options['workdir']}/ai/ext4.sh"                  # option : EXT4 install script
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
  options['swapsize']="2G"                                                  # option : Swap partition size
  options['rootsize']="100%"                                                # option : Root partition size
  options['bootpool']="bpool"                                               # option : Boot pool name
  options['rootpool']="rpool"                                               # option : Root pool name
  options['rootpassword']="nixos"                                           # option : Root password
  options['rootcrypt']=""                                                   # option : Root password crypt
  options['username']="nixos"                                               # option : User Username
  options['gecos']="nixos"                                                  # option : User GECOS
  options['shell']="zsh"                                                    # option : User Shell
  options['normaluser']="true"                                              # option : Normal User
  options['extragroups']="wheel"                                            # option : Extra Groups
  options['sudousers']="${options['username']}"                             # option : Sudo Users
  options['sudocommand']="ALL"                                              # option : Sudo Command
  options['sudooptions']="NOPASSWD"                                         # option : Sudo Options
  options['systempackages']="${packages}"                                   # option : System Packages
  options['experimental-features']="nix-command flakes"                     # option : Experimental Features
  options['unfree']="false"                                                 # option : Allow Non Free Packages
  options['stateversion']="25.05"                                           # option : State version
  options['unattended']="true"                                              # option : Execute install script
  options['attended']="false"                                               # option : Don't execute install script
  options['reboot']="true"                                                  # option : Reboot after install
  options['networkmanager']="true"                                          # option : Enable NetworkManager
  options['xserver']="false"                                                # option : Enable Xserver
  options['keymap']="au"                                                    # option : Keymap
  options['videodriver']=""                                                 # option : Video Driver
  options['sddm']="false"                                                   # option : KDE Plasma Login Manager
  options['plasma6']="false"                                                # option : KDE Plasma
  options['gdm']="false"                                                    # option : Gnome Login Manager
  options['gnome']="false"                                                  # option : Gnome
  options['rootkit']="false"                                                # option : Enable rootkit protection
  options['bridge']="false"                                                 # option : Enable bridge
  options['bridgenic']="br0"                                                # option : Bridge NIC
  options['ip']=""                                                          # option : IP Address
  options['cidr']="24"                                                      # option : CIDR
  options['dns']="8.8.8.8"                                                  # option : DNS/Nameserver address
  options['gateway']=""                                                     # option : Gateway address
  options['standalone']="false"                                             # option : Package all requirements on ISO
  options['zsh']="true"                                                     # option : Enable zsh
  options['installdir']="/mnt"                                              # option : Install directory
  options['rootvolname']="nixos"                                            # option : Root volume name
  options['bootvolname']="boot"                                             # option : Boot volume name
  options['swapvolname']="swap"                                             # option : Swap volume name
  options['uefivolname']="uefi"                                             # option : UEFI volume name
  options['homevolname']="home"                                             # option : Home volume name
  options['nixvolname']="nix"                                               # option : Nix volume name
  options['usrvolname']="usr"                                               # option : Usr volume name
  options['varvolname']="var"                                               # option : Var volume name
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
  if [ "${options['zfs']}" = "true" ] || [ "${options['filesystem']}" = "zfs" ]; then
    options['zfs']='true'
    options['filesystem']='zfs'
  fi
  if [ "${options['ext4']}" = "true" ] || [ "${options['filesystem']}" = "ext4" ]; then
    options['ext4']='true'
    options['filesystem']='ext4'
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
  tee "${options['nixisoconfig']}" << NIXCONFIG
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
NIXCONFIG
  if [ "${options['standalone']}" = "true" ]; then
    tee -a "${options['nixisoconfig']}" << NIXCONFIG
    storeContents = [
      config.system.build.toplevel
    ];
    includeSystemBuildDependencies = true;
NIXCONFIG
  else
    tee -a "${options['nixisoconfig']}" << NIXCONFIG
    storeContents = with pkgs; [
      ${options['systempackages']}
    ];
NIXCONFIG
  fi
  tee -a "${options['nixisoconfig']}" << NIXCONFIG
  };

  # Set boot params
  boot.runSize = "${options['runsize']}";

  # Bootloader
  # boot.loader.systemd-boot.enable = ${options['systemd-boot']};
  # boot.loader.efi.canTouchEfiVariables = ${options['touchefi']};

  # Set your time zone
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
  users.users.root.openssh.authorizedKeys.keys = ["${options['sshkey']}" ];

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
mkdir -p /tmp/${options['prefix']}
cp /iso/${options['prefix']}/*.sh /tmp/${options['prefix']}
chmod +x /tmp/${options['prefix']}/*.sh
bash /tmp/${options['prefix']}/${options['filesystem']}.sh
INSTALL
chmod +x "${options['install']}"
}


# Function: create_ext4_install_script
#
# Create EXT4 install script

create_ext_install_script () {
  check_nix_config
  get_ssh_key
  get_password_crypt
  verbose_message "Creating ${options['extinstall']}"
  tee "${options['extinstall']}" << EXTINSTALL
#!/run/current-system/sw/bin/bash
set -x
export PATH="/run/wrappers/bin:/root/.nix-profile/bin:/nix/profile/bin:/root/.local/state/nix/profile/bin:/etc/profiles/per-user/root/bin:/nix/var/nix/profiles/default/bin:/run/current-system/sw/bin"

# Declare/determine disk(s) and network(s)
EXTINSTALL

  if [ "${options['disk']}" = "first" ]; then
    tee -a "${options['extinstall']}" << EXTINSTALL
FIRST_DISK=\$( lsblk -x TYPE | grep disk | sort | head -1 | awk '{print \$1}' )
DISK="/dev/\${FIRST_DISK}"
EXTINSTALL
  else
    tee -a "${options['extinstall']}" << EXTINSTALL
DISK="${options['disk']}"
EXTINSTALL
  fi

  if [ "${options['nic']}" = "first" ]; then
    tee -a "${options['extinstall']}" << EXTINSTALL
NIC=\$( ip link | grep "state UP" | awk '{ print \$2}' | head -1 | grep ^e | cut -f1 -d: )
EXTINSTALL
  else
    tee -a "${options['extinstall']}" << EXTINSTALL
NIC="${options['nic']}"
EXTINSTALL
  fi

  tee -a "${options['extinstall']}" << EXTINSTALL

# Setup environment
DISK_SUFFIX=\$( echo "\${DISK}" | cut -f3 -d/ )
SWAP_SIZE="${options['swapsize']}"
ROOT_SIZE="${options['rootsize']}"
MAIN_CFG="${options['nixconfig']}"
NIX_DIR="${options['nixdir']}"
MAIN_CFG="${options['nixconfig']}"
HW_CFG="${options['nixhwconfig']}"
QEMU_CHECK=\$( cat /proc/ioports |grep QEMU )
ROOT_VOL="${options['rootvolname']}"
BOOT_VOL="${options['bootvolname']}"
SWAP_VOL="${options['swapvolname']}"
UEFI_VOL="${options['uefivolname']}"
HOME_VOL="${options['homevolname']}"
NIX_VOL="${options['nixvolname']}"
USR_VOL="${options['usrvolname']}"
VAR_VOL="${options['varvolname']}"
ROOT_PART="\${DISK}1"
SWAP_PART="\${DISK}2"
BOOT_PART="\${DISK}3"
ROOT_DEV="/dev/disk/by-label/\${ROOT_VOL}"
BOOT_DEV="/dev/disk/by-label/\${BOOT_VOL}"
SWAP_DEV="/dev/disk/by-label/\${SWAP_VOL}"
TARGET_DIR="${options['installdir']}"
ROOT_CRYPT="${options['rootcrypt']}"
UNAME_M=\$(uname -m)
DHCP="${options['dhcp']}"
BRIDGE="${options['bridge']}"
IP="${options['ip']}"
CIDR="${options['cidr']}"
DNS="${options['dns']}"
GATEWAY="${options['gateway']}"
NIX_DIR="${options['nixdir']}"
IMPORTS="${options['imports']}"
STATE_VERSION="${options['stateversion']}"
SYSTEM_PACKAGES="${options['systempackages']}"
HOSTNAME="${options['hostname']}"
UNFREE="${options['unfree']}"
SSH_SERVER="${options['sshserver']}"
TIMEZONE="${options['timezone']}"
XSERVER="${options['xserver']}"
NETWORK_MANAGER="${options['networkmanager']}"
VIDEO_DRIVER="${options['videodriver']}"
KEYMAP="${options['keymap']}"
ROOTKIT="${options['rootkit']}"
LANGUAGE="${options['language']}"
USERNAME="${options['username']}"
EXPERIMENTAL="${options['experimental-features']}"
SUDO_COMMAND="${options['sudocommand']}"
SUDO_OPTIONS="${options['sudooptions']}"
SHELL="${options['shell']}"
NORMAL_USER="${options['normaluser']}"
GECOS="${options['gecos']}"
EXTRA_GROUPS="${options['extragroups']}"
SSH_KEY="${options['sshkey']}"
USER_PASSWORD="${options['userpassword']}"
USER_CRYPT=\$( mkpasswd --method=sha-512 "\${USER_PASSWORD}" )
ZSH_ENABLE="${options['zsh']}"
HOST_ID=\$( head -c 8 /etc/machine-id )
FS_TYPE="${options['filesystem']}"

# Check if BIOS or UEFI boot
if [ -d "/sys/firmware/efi" ]; then
  BIOS="false"
  UEFI="true"
else
  BIOS="true"
  UEFI="false"
fi

# Wipe disk
swapoff -L \${SWAP_PART}
umount -l \${TARGET_DIR}/\${BOOT_VOL}/\${UEFI_VOL}
umount -l \${TARGET_DIR}/\${BOOT_VOL}
umount -l \${TARGET_DIR}/\${HOME_VOL}
umount -l \${TARGET_DIR}/\${NIX_VOL}
umount -l \${TARGET_DIR}/\${USR_VOL}
umount -l \${TARGET_DIR}/\${VAR_VOL}
umount -l \${TARGET_DIR}
wipefs \${DISK}
sgdisk --zap-all \${DISK}
zpool labelclear -f \${DISK}

# Setup disk
if [ "\${BIOS}" = "true" ]; then
  parted \${DISK} -- mklabel msdos
  parted \${DISK} -- mkpart primary \${SWAP_SIZE}iB \${ROOT_SIZE}
  parted \${DISK} -- mkpart primary linux-swap 1GiB \${SWAP_SIZE}iB
  partprobe \${DISK}
  sleep 5s
  mkfs.ext4 -F -L \${ROOT_VOL} \${ROOT_PART}
  mkswap -L swap \${SWAP_PART}
  mount \${ROOT_DEV} \${TARGET_DIR}
  swapon \${SWAP_DEV}
else
  parted \${DISK} -- mklabel gpt
  parted \${DISK} -- mkpart primary \${SWAP_SIZE}iB \${ROOT_SIZE}
  parted \${DISK} -- mkpart primary linux-swap 512MiB \${SWAP_SIZE}iB
  parted \${DISK} -- mkpart ESP fat32 1MiB 512MiB 
  parted \${DISK} -- set 3 esp on
  partprobe \${DISK}
  sleep 5s
  mkfs.ext4 -F -L \${ROOT_VOL} \${ROOT_PART}
  mkswap -L \${SWAP_VOL} \${SWAP_PART}
  mkfs.fat -F 32 -n \${BOOT_VOL} \${BOOT_PART}
  mount \${ROOT_DEV} \${TARGET_DIR}
  mkdir -p \${TARGET_DIR}/\${BOOT_VOL}
  mount \${BOOT_DEV} \${TARGET_DIR}/\${BOOT_VOL}
  chmod 700 \${TARGET_DIR}/\${BOOT_VOL}
  swapon \${SWAP_DEV}
fi


# Generate configuration.nix
mkdir -p \${NIX_DIR}
rm \${NIX_DIR}/*
tee \${MAIN_CFG} << EOF
{ config, lib, pkgs, ... }:
{
  imports = [
    ./hardware-configuration.nix
  ];
  boot.loader.grub.enable = \${BIOS};
  boot.loader.systemd-boot.enable = \${UEFI};
EOF
  if [ "\${BIOS}" = "true" ]; then
    tee -a \${MAIN_CFG} << EOF
    boot.loader.grub.device = "\${DISK}";
EOF
  fi 
tee -a \${MAIN_CFG} << EOF
  networking.hostId = "\${HOST_ID}";
  environment.systemPackages = with pkgs; [ \${SYSTEM_PACKAGES} ];

  # OpenSSH
  services.openssh.enable = \${SSH_SERVER};

  # Hostname
  networking.hostName = "\${HOSTNAME}";

  # NetworkManager
  networking.networkmanager.enable = \${NETWORK_MANAGER};

  # Set your time zone.
  time.timeZone = "\${TIMEZONE}";

  # X11 Window Manager
  services.xserver.enable = \${XSERVER};
  services.xserver.videoDrivers = [ "\${VIDEO_DRIVER}" ];

  # Configure keymap in X11
  services.xserver.xkb = {
    layout = "\${KEYMAP}";
    variant = "";
  };
 
  # Security
  security.rtkit.enable = \${ROOTKIT};

  # Select internationalisation properties.
  i18n.defaultLocale = "\${LANGUAGE}";
  i18n.extraLocaleSettings = {
    LC_ADDRESS = "\${LANGUAGE}";
    LC_IDENTIFICATION = "\${LANGUAGE}";
    LC_MEASUREMENT = "\${LANGUAGE}";
    LC_MONETARY = "\${LANGUAGE}";
    LC_NAME = "\${LANGUAGE}";
    LC_NUMERIC = "\${LANGUAGE}";
    LC_PAPER = "\${LANGUAGE}";
    LC_TELEPHONE = "\${LANGUAGE}";
    LC_TIME = "\${LANGUAGE}";
  };

  # Define a user account. 
  users.users.\${USERNAME} = {
    shell = pkgs.\${SHELL};
    isNormalUser = \${NORMAL_USER};
    description = "\${GECOS}";
    extraGroups = [ "\${EXTRA_GROUPS}" ];
    openssh.authorizedKeys.keys = [ "\${SSH_KEY}" ];
    hashedPassword = "\${USER_CRYPT}";
  };
  programs.zsh.enable = \${ZSH_ENABLE};

  # Sudo configuration
  security.sudo.extraRules= [
    { users = [ "\${USERNAME}" ];
      commands = [
        { command = "\${SUDO_COMMAND}" ;
          options= [ "\${SUDO_OPTIONS}" ];
        }
      ];
    }
  ];

  # Additional Nix options
  nix.settings.experimental-features = "\${EXPERIMENTAL}";

  # Allow unfree packages
  nixpkgs.config.allowUnfree = \${UNFREE};

EOF

if [ "\${DHCP}" = "false" ]; then
  if [ "\${BRIDGE}" = "false" ]; then
    tee -a \${MAIN_CFG} << EOF
  networking = {
    interfaces."\${NIC}".useDHCP = false;
    interfaces."\${NIC}".ipv4.addresses = [{
      address = "\${IP}";
      prefixLength = \${CIDR};
    }];
    defaultGateway = "\${GATEWAY}";
    nameservers = [ "\${DNS}" ];
  };
EOF
  else
    tee -a \${MAIN_CFG} << EOF
  networking = {
    bridges."\${BRIDGE}".interfaces = [ "\${NIC}" ];
    interfaces."\${BRIDGE}".useDHCP = false;
    interfaces."\${NIC}".useDHCP = false;
    interfaces."\${BRIDGE}".ipv4.addresses = [{
      address = "\${IP}";
      prefixLength = \${CIDR};
    }];
    defaultGateway = "\${GATEWAY}";
    nameservers = [ "\${DNS}" ];
  };
EOF
  fi
fi

tee -a \${MAIN_CFG} << EOF
  users.users.root.initialHashedPassword = "\${ROOT_CRYPT}";
  system.stateVersion = "\${STATE_VERSION}";
}
EOF

# Generate hardware-configuration.nix
tee \${HW_CFG} << EOF
{ config, lib, pkgs, modulesPath, ... }:
{
EOF

if [ -n "\${QEMU_CHECK}" ]; then
  tee -a \${HW_CFG} << EOF
  imports = [ (modulesPath + "/profiles/qemu-guest.nix") ];
  boot.initrd.availableKernelModules = [ "ahci" "xhci_pci" "virtio_pci" "sr_mod" "virtio_blk" ];
  boot.initrd.kernelModules = [ ];
  boot.kernelModules = [ "kvm-intel" ];
  boot.extraModulePackages = [ ];
EOF
fi

if [ "\${UEFI}" = "true" ]; then
  tee -a \${HW_CFG} << EOF
  fileSystems."/boot" = { device = "\${BOOT_PART}"; fsType = "vfat"; options = [ "fmask=0022" "dmask=0022" ]; };
EOF
fi

tee -a \${HW_CFG} << EOF
  fileSystems."/" = { device = "\${ROOT_PART}"; fsType = "\${FS_TYPE}"; };
  swapDevices = [ { device = "\${SWAP_PART}"; } ];

  nixpkgs.hostPlatform = lib.mkDefault "\${UNAME_M}-linux";
}
EOF
nixos-install --no-root-passwd
EXTINSTALL
chmod +x "${options['extinstall']}"
}

# Function: create_zfs_install_script
#
# Create ZFS install script

create_zfs_install_script () {
  check_nix_config
  get_ssh_key
  get_password_crypt
  verbose_message "Creating ${options['zfsinstall']}"
  tee "${options['zfsinstall']}" << ZFSINSTALL
#!/run/current-system/sw/bin/bash
set -x
export PATH="/run/wrappers/bin:/root/.nix-profile/bin:/nix/profile/bin:/root/.local/state/nix/profile/bin:/etc/profiles/per-user/root/bin:/nix/var/nix/profiles/default/bin:/run/current-system/sw/bin"

# Declare/determine disk(s) and network(s)
ZFSINSTALL

if [ "${options['disk']}" = "first" ]; then
  tee -a "${options['zfsinstall']}" << ZFSINSTALL
FIRST_DISK=\$( lsblk -x TYPE | grep disk | sort | head -1 | awk '{print \$1}' )
DISK=( /dev/\${FIRST_DISK} )
ZFSINSTALL
else
  tee -a "${options['zfsinstall']}" << ZFSINSTALL
DISK=( ${options['disk']} )
ZFSINSTALL
fi

if [ "${options['nic']}" = "first" ]; then
  tee -a "${options['zfsinstall']}" << ZFSINSTALL
NIC=\$( ip link | grep "state UP" | awk '{ print \$2}' | head -1 | grep ^e | cut -f1 -d: )
ZFSINSTALL
else
  tee -a "${options['zfsinstall']}" << ZFSINSTALL
NIC=( ${options['nic']} )
ZFSINSTALL
fi

tee -a "${options['zfsinstall']}" << ZFSINSTALL
# Declare partitions/pools
DISK_SUFFIX=\$( echo "\${DISK}" | cut -f3 -d/ )
PART_MBR="bootcode"
PART_EFI="efiboot"
PART_BOOT="${options['bootpool']}"
PART_SWAP="swap"
PART_ROOT="${options['rootpool']}"
SWAP_SIZE="${options['swapsize']}"
ZFS_BOOT="${options['bootpool']}"
ZFS_ROOT="${options['rootpool']}"
ZFS_ROOT_VOL="${options['rootvolname']}"
ROOT_CRYPT="${options['rootcrypt']}"
TARGET_DIR="${options['installdir']}"
SWAP_PART="\${DISK}4"
BOOT_VOL="boot"
UEFI_VOL="efi"

# Declare config files etc
REBOOT="${options['reboot']}"
MAIN_CFG="${options['nixconfig']}"
HW_CFG="${options['nixhwconfig']}"
ZFS_CFG="${options['nixzfsconfig']}"
UNAME_M=\$( uname -m )
DHCP="${options['dhcp']}"
BRIDGE="${options['bridge']}"
IP="${options['ip']}"
CIDR="${options['cidr']}"
DNS="${options['dns']}"
GATEWAY="${options['gateway']}"
NIX_DIR="${options['nixdir']}"
IMPORTS="${options['imports']}"
STATE_VERSION="${options['stateversion']}"
SYSTEM_PACKAGES="${options['systempackages']}"
HOSTNAME="${options['hostname']}"
UNFREE="${options['unfree']}"
SSH_SERVER="${options['sshserver']}"
TIMEZONE="${options['timezone']}"
XSERVER="${options['xserver']}"
NETWORK_MANAGER="${options['networkmanager']}"
VIDEO_DRIVER="${options['videodriver']}"
KEYMAP="${options['keymap']}"
ROOTKIT="${options['rootkit']}"
LANGUAGE="${options['language']}"
USERNAME="${options['username']}"
EXPERIMENTAL="${options['experimental-features']}"
SUDO_COMMAND="${options['sudocommand']}"
SUDO_OPTIONS="${options['sudooptions']}"
SHELL="${options['shell']}"
NORMAL_USER="${options['normaluser']}"
GECOS="${options['gecos']}"
EXTRA_GROUPS="${options['extragroups']}"
SSH_KEY="${options['sshkey']}"
USER_CRYPT="${options['usercrypt']}"
ZSH_ENABLE="${options['zsh']}"
HOST_ID=\$( head -c 8 /etc/machine-id )

swapoff -L \${SWAP_PART}
umount -l \${TARGET_DIR}/\${BOOT_VOL}/\${UEFI_VOL}
umount -l \${TARGET_DIR}/\${BOOT_VOL}
umount -l \${TARGET_DIR}/\${HOME_VOL}
umount -l \${TARGET_DIR}/\${NIX_VOL}
umount -l \${TARGET_DIR}/\${USR_VOL}
umount -l \${TARGET_DIR}/\${VAR_VOL}
umount -l \${TARGET_DIR}
zpool destroy -f \${ZFS_BOOT}
zpool destroy -f \${ZFS_ROOT}

# Setup disk(s)
i=0 SWAP_DEVS=()
for d in \${DISK[*]}
do
  wipefs \${d}
  zpool labelclear -f \${d}
  sgdisk --zap-all \${d}
  sgdisk -a1 -n1:0:+100K -t1:EF02 -c 1:\${PART_MBR}\${i} \${d}
  sgdisk -n2:1M:+1G -t2:EF00 -c 2:\${PART_EFI}\${i} \${d}
  sgdisk -n3:0:+4G -t3:BE00 -c 3:\${PART_BOOT}\${i} \${d}
  sgdisk -n4:0:+\${SWAP_SIZE} -t4:8200 -c 4:\${PART_SWAP}\${i} \${d}
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
zpool create -f \\
  -o compatibility=grub2 \\
  -o ashift=12 \\
  -o autotrim=on \\
  -O acltype=posixacl \\
  -O compression=lz4 \\
  -O devices=off \\
  -O normalization=formD \\
  -O relatime=on \\
  -O xattr=sa \\
  -O mountpoint=none \\
  -O checksum=sha256 \\
  -R /mnt \\
  \${ZFS_BOOT} \${ZFS_BOOT_VDEV} /dev/disk/by-partlabel/\${PART_BOOT}*

# Create the root pool
zpool create -f \\
  -o ashift=12 \\
  -o autotrim=on \\
  -O acltype=posixacl \\
  -O compression=zstd \\
  -O dnodesize=auto -O normalization=formD \\
  -O relatime=on \\
  -O xattr=sa \\
  -O mountpoint=none \\
  -O checksum=edonr \\
  -R /mnt \\
  \${ZFS_ROOT} \${ZFS_ROOT_VDEV} /dev/disk/by-partlabel/\${PART_ROOT}*

# Create the boot dataset
zfs create \${ZFS_BOOT}/\${ZFS_ROOT_VOL}

# Create the root dataset
zfs create -o mountpoint=/     \${ZFS_ROOT}/\${ZFS_ROOT_VOL}

# Create datasets (subvolumes) in the root dataset
zfs create \${ZFS_ROOT}/\${ZFS_ROOT_VOL}/home
zfs create -o atime=off \${ZFS_ROOT}/\${ZFS_ROOT_VOL}/nix
zfs create \${ZFS_ROOT}/\${ZFS_ROOT_VOL}/root
zfs create \${ZFS_ROOT}/\${ZFS_ROOT_VOL}/usr
zfs create \${ZFS_ROOT}/\${ZFS_ROOT_VOL}/var

# Create datasets (subvolumes) in the boot dataset
# This comes last because boot order matters
zfs create -o mountpoint=/boot \${ZFS_BOOT}/\${ZFS_ROOT_VOL}/boot

# Create, mount and populate the efi partitions
i=0
for d in \${DISK[*]}
do
  mkfs.vfat -n EFI /dev/disk/by-partlabel/\${PART_EFI}\${i}
  mkdir -p /mnt/boot/efis/\${PART_EFI}\${i}
  mount -t vfat /dev/disk/by-partlabel/\${PART_EFI}\${i} /mnt/boot/efis/\${PART_EFI}\${i}
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
mkdir -p \${NIX_DIR}
tee \${MAIN_CFG} << EOF
{ config, lib, pkgs, ... }:
{
  imports = [
    \${IMPORTS}
    ./hardware-configuration.nix
    ./zfs.nix
  ];
  system.stateVersion = "\${STATE_VERSION}";
}
EOF

# Create ZFS nix config
tee \${ZFS_CFG} << EOF
{ config, pkgs, ... }:

{
  boot.supportedFilesystems = [ "zfs" ];
  networking.hostId = "\${HOST_ID}";
  boot.kernelPackages = config.boot.zfs.package.latestCompatibleLinuxPackages;
  boot.zfs.devNodes = "/dev/disk/by-partlabel";
  environment.systemPackages = with pkgs; [ \${SYSTEM_PACKAGES} ];

  # OpenSSH
  services.openssh.enable = \${SSH_SERVER};

  # Hostname
  networking.hostName = "\${HOSTNAME}";

  # NetworkManager
  networking.networkmanager.enable = \${NETWORK_MANAGER};

  # Set your time zone.
  time.timeZone = "\${TIMEZONE}";

  # X11 Window Manager
  services.xserver.enable = \${XSERVER};
  services.xserver.videoDrivers = [ "\${VIDEO_DRIVER}" ];

  # Configure keymap in X11
  services.xserver.xkb = {
    layout = "\${KEYMAP}";
    variant = "";
  };
 
  # Security
  security.rtkit.enable = \${ROOTKIT};

  # Select internationalisation properties.
  i18n.defaultLocale = "\${LANGUAGE}";
  i18n.extraLocaleSettings = {
    LC_ADDRESS = "\${LANGUAGE}";
    LC_IDENTIFICATION = "\${LANGUAGE}";
    LC_MEASUREMENT = "\${LANGUAGE}";
    LC_MONETARY = "\${LANGUAGE}";
    LC_NAME = "\${LANGUAGE}";
    LC_NUMERIC = "\${LANGUAGE}";
    LC_PAPER = "\${LANGUAGE}";
    LC_TELEPHONE = "\${LANGUAGE}";
    LC_TIME = "\${LANGUAGE}";
  };

  # Define a user account. 
  users.users.\${USERNAME} = {
    shell = pkgs.\${SHELL};
    isNormalUser = \${NORMAL_USER};
    description = "\${GECOS}";
    extraGroups = [ "\${EXTRA_GROUPS}" ];
    openssh.authorizedKeys.keys = [ "\${SSH_KEY}" ];
    hashedPassword = "\${USER_CRYPT}";
  };
  programs.zsh.enable = \${ZSH_ENABLE};

  # Sudo configuration
  security.sudo.extraRules= [
    { users = [ "\${USERNAME}" ];
      commands = [
        { command = "\${SUDO_COMMAND}" ;
          options= [ "\${SUDO_OPTIONS}" ];
        }
      ];
    }
  ];

  # Additional Nix options
  nix.settings.experimental-features = "\${EXPERIMENTAL}";

  # Allow unfree packages
  nixpkgs.config.allowUnfree = \${UNFREE};

#  boot.loader.efi.efiSysMountPoint = "/boot/efi";
#  boot.loader.efi.canTouchEfiVariables = false;
#  boot.loader.generationsDir.copyKernels = true;
#  boot.loader.grub.efiInstallAsRemovable = true;
#  boot.loader.grub.enable = true;
#  boot.loader.grub.copyKernels = true;
#  boot.loader.grub.efiSupport = true;
#  boot.loader.grub.zfsSupport = true;

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

if [ "\${DHCP}" = "false" ]; then
  if [ "\${BRIDGE}" = "false" ]; then
    tee -a \${ZFS_CFG} << EOF
  networking = {
    interfaces."\${NIC}".useDHCP = false;
    interfaces."\${NIC}".ipv4.addresses = [{
      address = "\${IP}";
      prefixLength = \${CIDR};
    }];
    defaultGateway = "\${GATEWAY}";
    nameservers = [ "\${DNS}" ];
  };
EOF
  else
    tee -a \${ZFS_CFG} << EOF
  networking = {
    bridges."\${BRIDGE}".interfaces = [ "\${NIC}" ];
    interfaces."\${BRIDGE}".useDHCP = false;
    interfaces."\${NIC}".useDHCP = false;
    interfaces."\${BRIDGE}".ipv4.addresses = [{
      address = "\${IP}";
      prefixLength = \${CIDR};
    }];
    defaultGateway = "\${GATEWAY}";
    nameservers = [ "\${DNS}" ];
  };
EOF
  fi
fi
tee -a \${ZFS_CFG} << EOF
  ];
  users.users.root.initialHashedPassword = "\${ROOT_CRYPT}";
EOF
tee -a \${ZFS_CFG} << EOF
}
EOF

# Create hardware-configuration.nix
SWAP_UUID=\$(ls -l /dev/disk/by-uuid/ |grep \${DISK_SUFFIX}4 |awk '{print \$9}' )
BOOT_UUID=\$(ls -l /dev/disk/by-uuid/ |grep \${DISK_SUFFIX}2 |awk '{print \$9}' )
QEMU_CHECK=\$( cat /proc/ioports |grep QEMU )

tee \${HW_CFG} << EOF
{ config, lib, pkgs, modulesPath, ... }:
{
EOF

if [ -n "\${QEMU_CHECK}" ]; then
  tee -a \${HW_CFG} << EOF
  imports = [ (modulesPath + "/profiles/qemu-guest.nix") ];
  boot.initrd.availableKernelModules = [ "ahci" "xhci_pci" "virtio_pci" "sr_mod" "virtio_blk" ];
  boot.initrd.kernelModules = [ ];
  boot.kernelModules = [ "kvm-intel" ];
  boot.extraModulePackages = [ ];
EOF
fi

tee -a \${HW_CFG} << EOF
  fileSystems."/" = {
    device = "rpool/nixos";
    neededForBoot = true;
    fsType = "zfs"; options = [ "zfsutil" "X-mount.mkdir" ];
  };

  fileSystems."/home" = {
    device = "rpool/nixos/home";
    fsType = "zfs"; options = [ "zfsutil" "X-mount.mkdir" ];
  };

  fileSystems."/nix" = {
    device = "rpool/nixos/nix";
    fsType = "zfs"; options = [ "zfsutil" "X-mount.mkdir" ];
  };

  fileSystems."/root" = {
    device = "rpool/nixos/root";
    fsType = "zfs"; options = [ "zfsutil" "X-mount.mkdir" ];
  };

  fileSystems."/usr" = {
    device = "rpool/nixos/usr";
    fsType = "zfs"; options = [ "zfsutil" "X-mount.mkdir" ];
  };

  fileSystems."/var" = {
    device = "rpool/nixos/var";
    fsType = "zfs"; options = [ "zfsutil" "X-mount.mkdir" ];
  };

  fileSystems."/boot" = {
    device = "bpool/nixos/boot";
    neededForBoot = true;
    fsType = "zfs"; options = [ "zfsutil" "X-mount.mkdir" ];
  };

  fileSystems."/boot/efis/efiboot0" = {
    device = "/dev/disk/by-uuid/\${BOOT_UUID}";
    fsType = "vfat";
    options = [ "fmask=0022" "dmask=0022" ];
  };

  fileSystems."/boot/efi" = {
    device = "/boot/efis/efiboot0";
    fsType = "none";
    options = [ "bind" ];
  };

  swapDevices = [ { device = "/dev/disk/by-uuid/\${SWAP_UUID}"; } ];
  nixpkgs.hostPlatform = lib.mkDefault "\${UNAME_M}-linux";
}
EOF

nixos-install -v --show-trace --no-root-passwd --substituters "" --root \${TARGET_DIR} 2>&1 |tee \${TARGET_DIR}var/log/install.log
umount -Rl /mnt
zpool export -a
swapoff -a
if [ "\${REBOOT}" = "true" ]; then
  reboot
fi
ZFSINSTALL
chmod +x "${options['zfsinstall']}"
}

# Function: create_iso
#
# Create ISO

create_iso () {
  check_nix_config
  create_nix_iso_config
  create_install_script
  create_zfs_install_script
  create_ext_install_script
  execute_command "cd ${options['workdir']} ; nix-build '<nixpkgs/nixos>' -A config.system.build.isoImage -I nixos-config=${options['nixisoconfig']} --builders ''"
#  execute_command "nixos-generate -f iso -c ${options['nixisoconfig']}"
  iso_dir="${options['workdir']}/result/iso"
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
    createext*)           # action : Create EXT4 install script
      create_ext_install_script
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
    --bridge)               # switch : Enable bridge
      options['bridge']="true"
      shift
      ;;
    --bridgenic)            # switch : Bridge NIC
      check_value "$1" "$2"
      options['bridgenic']="$2"
      shift 2
      ;;
    --bootvol*)             # switch : Boot volume name
      check_value "$1" "$2"
      options['bootvolname']="$2"
      shift 2
      ;;
    --cidr)                 # switch : CIDR
      check_value "$1" "$2"
      options['cidr']="$2"
      shift 2
      ;;
    --createext*)           # switch : Create EXT4 install script
      actions_list+=("createextinstall")
      shift
      ;;
    --createinstall*)       # switch : Create install script
      actions_list+=("createinstall")
      shift
      ;;
    --createiso)            # switch : Create ISO
      actions_list+=("createiso")
      shift
      ;;
    --createnix*)           # switch : Create NIX ISO config
      actions_list+=("createnix")
      shift
      ;;
    --createzfsinstall*)    # switch : Create ZFS install script
      actions_list+=("createzfs")
      shift
      ;;
    --usercrypt|--crypt)    # switch : User Password Crypt 
      check_value "$1" "$2"
      options['usercrypt']="$2"
      shift 2
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
    --dns|--nameserver)     # switch : DNS/Nameserver address
      check_value "$1" "$2"
      options['dns']="$2"
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
    --filesystem*)          # switch : Root Filesystem
      check_value "$1" "$2"
      options['filesystem']="$2"
      shift 2
      ;;
    --firmware)             # switch : Boot firmware type
      check_value "$1" "$2"
      options['firmware']="$2"
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
    --hostname)             # switch : Hostname
      check_value "$1" "$2"
      options['hostname']="$2"
      shift 2
      ;;
    --install)              # switch : Install script
      check_value "$1" "$2"
      options['install']="$2"
      shift 2
      ;;
    --ip)                   # switch : IP address
      check_value "$1" "$2"
      options['ip']="$2"
      shift 2
      ;;
    --isoimports)           # switch : Nixos imports for ISO build
      check_value "$1" "$2"
      options['isoimports']="$2"
      shift 2
      ;;
    --keymap)               # switch : Keymap
      check_value "$1" "$2"
      options['keymap']="$2"
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
    --password|--userpassword)  # switch : User password
      check_value "$1" "$2"
      options['userpassword']="$2"
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
    --rootsize)             # switch : Root partition size
      check_value "$1" "$2"
      options['rootsize']="$2"
      shift 2
      ;;
    --rootvol*)             # switch : Root volume name
      check_value "$1" "$2"
      options['rootvolname']="$2"
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
    --swapsize)             # switch : Swap partition size
      check_value "$1" "$2"
      options['swapsize']="$2"
      shift 2
      ;;
    --swapvol*)             # switch : Swap volume name
      check_value "$1" "$2"
      options['swapvolname']="$2"
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
    --videodriver)          # switch : Video Driver
      check_value "$1" "$2"
      options['videodriver']="$2"
      shift 2
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
