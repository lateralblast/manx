#!env bash

# Name:         manx (Manage/Automate NiXOS)
# Version:      0.0.8
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
  nixbase="nixpkgs/nixos/modules/installer/cd-dvd"
  options['verbose']="false"                                    # option : Verbose mode
  options['strict']="false"                                     # option : Strict mode
  options['dryrun']="false"                                     # option : Dryrun mode
  options['debug']="false"                                      # option : Debug mode
  options['force']="false"                                      # option : Force actions
  options['mask']="false"                                       # option : Mask identifiers
  options['yes']="false"                                        # option : Answer yes to questions
  options['nixdir']="${HOME}/nix"                               # option : Nix work directory
  options['sshkey']=""                                          # option : SSH key
  options['language']="en_AU.UTF-8"                             # option : Language
  options['timezone']="Australia/Melbourne"                     # option : Timezone
  options['username']=""                                        # option : Username
  options['password']=""                                        # option : Password
  options['sshkeyfile']=""                                      # option : SSH key file
  options['install']="${options['nixdir']}/ai/install.sh"       # option : Install script
  options['nixconfig']="${options['nixdir']}/iso.nix"           # option : Nix ISO config
  options['zfsinstall']="${options['nixdir']}/ai/zfs.sh"        # option : ZFS install script
  options['cdimage']="<${nixbase}/installation-cd-minimal.nix>" # option : Nix installation
  options['channel']="<${nixbase}/channel.nix>"                 # option : Nix channel 
  options['runsize']="50%"                                      # option : Run size
  options['prefix']="ai"                                        # option : Install directory prefix
  options['source']="${options['nixdir']}/${options['prefix']}" # option : Source directory
  options['target']="/${options['prefix']}"                     # option : Target directory
  options['systemd-boot']="true"                                # option : systemd-boot
  options['touchefi']="true"                                    # option : Touch EFI
  options['sshserver']="true"                                   # option : Enable SSH server
  options['username']="nixos"                                   # option : User Username
  options['password']="nixos"                                   # option : User Password
  options['shell']="bash"                                       # option : User Shell
  options['normaluser']="true"                                  # option : Normal User
  options['extragroups']="wheel"                                # option : Extra Groups
  options['sudousers']="${options['username']}"                 # option : Sudo Users
  options['sudocommand']="ALL"                                  # option : Sudo Command
  options['sudooptions']="NOPASSWD"                             # option : Sudo Options
  options['systempackages']="vim git efibootmgr zsh"            # option : System Packages
  options['experimental-features']="nix-command flakes"         # option : Experimental Features
  options['unfree']="true"                                      # option : Allow Non Free Packages
  options['stateversion']="25.05"                               # option : State version
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
  if [[ "${option}" =~ ^no ]]; then
    option="${option:2}"
    value="false"
  else
    value="true"
  fi
  options["${option}"]="true"
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
  if [ ! -d "${options['nixdir']}" ]; then
    execute_command "mkdir -p ${options['nixdir']}"
  fi
  if [ ! -d "${options['nixdir']}/ai" ]; then
    execute_command "mkdir -p ${options['nixdir']}/ai"
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
            iso['sshkeyfile']="${key_file}"
            iso['sshkey']=$( <"${iso['sshkeyfile']}" )
          fi
    else
      if [ -f "${options['sshkeyfile']}" ]; then
        iso['sshkey']=$( <"${iso['sshkeyfile']}" )
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

create_nix_config () {
  check_nix_config
  tee -a "${options['nixconfig']}" << EOF
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
      { source = "${options['source']}" ;
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
  system.stateVersion = "${options['stateversion']}";
}
EOF
}

# Function: create_install_script
#
# Create install script

create_install_script () {
  check_nix_config
  tee -a "${options['install']}" << EOF
#!/run/current-system/sw/bin/bash
set -x
export PATH="/run/wrappers/bin:/root/.nix-profile/bin:/nix/profile/bin:/root/.local/state/nix/profile/bin:/etc/profiles/per-user/root/bin:/nix/var/nix/profiles/default/bin:/run/current-system/sw/bin"
mkdir -p /mnt/${options['prefix']}
cp /iso/${options['prefix']}/*.sh /mnt/${options['prefix']}
chmod +x /mnt/${options['prefix']}/*.sh
bash /mnt/${options['prefix']}/zsh.sh
EOF
}

# Function: create_zfs_install_script
#
# Create ZFS install script

create_zfs_install_script () {
  echo ""
}

# Function: create_iso
#
# Create ISO

create_iso () {
  check_nix_config
  create_nix_config
  create_install_script
  create_zfs_install_script
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
    createnix*)           # action : Create ISO
      create_nix_config
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
    --action*)              # switch - Action(s) to perform
      check_value "$1" "$2"
      actions_list+=("$2")
      shift 2
      ;;
    --createinstall*)       # switch - Create install script
      actions_list+=("createinstall")
      shift
      ;;
    --createiso)            # switch - Create ISO
      actions_list+=("createiso")
      shift
      ;;
    --createnix*)           # switch - Create ISO
      actions_list+=("createnix")
      shift
      ;;
    --createzfsinstall*)    # switch - Create ZFS install script
      actions_list+=("createzfs")
      shift
      ;;
    --debug)                # switch - Enable debug mode
      options['debug']="true"
      shift
      ;;
    --dryrun)               # switch - Enable debug mode
      options['dryrun']="true"
      shift
      ;;
    --experimental*)        # switch - SSH key
      check_value "$1" "$2"
      options['experimental-features']="$2"
      shift 2
      ;;
    --extragroup*)          # switch - Extra groups
      check_value "$1" "$2"
      options['extragroups']="$2"
      shift 2
      ;;
    --force)                # switch - Enable force mode
      options['force']="true"
      shift
      ;;
    --help|-h)              # switch - Print help information
      print_help
      shift
      exit
      ;;
    --install)              # switch - Install script
      check_value "$1" "$2"
      options['install']="$2"
      shift 2
      ;;
    --nixconfig)            # switch - Set Nix ISO configuration
      check_value "$1" "$2"
      options['nixconfig']="$2"
      shift 2
      ;;
    --nixdir)               # switch - Set Nix directory
      check_value "$1" "$2"
      options['nixdir']="$2"
      shift 2
      ;;
    --option*)              # switch - Option(s) to set
      check_value "$1" "$2"
      options_list+=("$2")
      shift 2
      ;;
    --password)             # switch - User password
      check_value "$1" "$2"
      options['password']="$2"
      shift 2
      ;;
    --prefix)               # switch - Install prefix
      check_value "$1" "$2"
      options['prefix']="$2"
      shift 2
      ;;
    --runsize)              # switch - Run size
      check_value "$1" "$2"
      options['runsize']="$2"
      shift 2
      ;;
    --shell)                # switch - User Shell
      check_value "$1" "$2"
      options['shell']="$2"
      shift 2
      ;;
    --shellcheck)           # switch - Run shellcheck
      actions_list+=("shellcheck")
      shift
      ;;
    --source)               # switch - Source directory
      check_value "$1" "$2"
      options['source']="$2"
      shift 2
      ;;
    --sshkey)               # switch - SSH key
      check_value "$1" "$2"
      options['sshkey']="$2"
      shift 2
      ;;
    --sshkeyfile)           # switch - SSH key file
      check_value "$1" "$2"
      options['sshkeyfile']="$2"
      shift 2
      ;;
    --stateversion)         # switch - NixOS state version
      check_value "$1" "$2"
      options['stateversion']="$2"
      shift 2
      ;;
    --strict)               # switch - Enable strict mode
      options['strict']="true"
      shift
      ;;
    --sudocommand*)         # switch - Sudo commands
      check_value "$1" "$2"
      options['sudocommand']="$2"
      shift 2
      ;;
    --sudooption*)          # switch - Sudo options
      check_value "$1" "$2"
      options['sudooptions']="$2"
      shift 2
      ;;
    --sudouser*)            # switch - Sudo users
      check_value "$1" "$2"
      options['sudousers']="$2"
      shift 2
      ;;
    --systempackages)       # switch - NixOS state version
      check_value "$1" "$2"
      options['systempackages']="$2"
      shift 2
      ;;
    --target)               # switch - Target directory
      check_value "$1" "$2"
      options['target']="$2"
      shift 2
      ;;
    --usage)                # switch - Action to perform
      check_value "$1" "$2"
      usage="$2"
      print_usage "${usage}"
      shift 2
      exit
      ;;
    --username)             # switch - User username
      check_value "$1" "$2"
      options['username']="$2"
      shift 2
      ;;
    --verbose)              # switch - Enable verbose mode
      options['verbose']="true"
      shift
      ;;
    --version|-V)           # switch - Print version information
      print_version
      exit
      ;;
    --zfsinstall)           # switch - ZFS install script
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
