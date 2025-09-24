umount -l /mnt
zpool destroy -f rpool
export DISK=/dev/vda
sgdisk --zap-all $DISK
zpool labelclear -f $DISK
sgdisk -a1 -n1:0:+1M -t1:EF02 $DISK
sgdisk -n3:1M:+512M -t3:EF00 $DISK
sgdisk -n2:0:0 -t2:BF01 $DISK
partprobe $DISK
sleep 2s
zpool create -f -O mountpoint=none -O atime=off -O compression=lz4 -O xattr=sa -O acltype=posixacl -o ashift=12 -R /mnt rpool ${DISK}2
zfs create -o mountpoint=legacy rpool/root
zfs create -o mountpoint=legacy rpool/nix
zfs create -o mountpoint=legacy rpool/var
zfs create -o mountpoint=legacy rpool/home
mkfs.vfat ${DISK}3
mkdir /mnt/{mnt-root,root,nix,home,boot,var}
mount -t zfs rpool/root /mnt
mkdir /mnt/{mnt-root,root,nix,home,boot,var}
mount -t zfs rpool/nix /mnt/nix
mount -t zfs rpool/home /mnt/home
mount -t zfs rpool/var /mnt/var
mount ${DISK}3 /mnt/boot
mkdir -p /mnt/etc/nixos
rm /mnt/etc/nixos/*

nixos-generate-config --root /mnt

# Edit configs

nixos-install -v --show-trace

umount -Rl /mnt
zpool export -a
swapoff -a

reboot
