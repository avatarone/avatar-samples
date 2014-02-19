#!/bin/bash
# build the sdcard image for qemu with u-boot environment

source ./vars

tmp_dir=`mktemp -d`
echo Using ${tmp_dir} as temp dir
echo Using ${UBOOT_DIR} as uboot base dir

IMG=${UBOOT_DIR}/sdcard.img
echo Creating image ${IMG}

dd if=/dev/zero of=${IMG} bs=1048576 count=64
/sbin/sfdisk ${IMG} <<EOF
,,0xc,*
EOF

sudo /sbin/losetup -o $((512)) /dev/loop0 ${IMG}
sudo /sbin/mkfs.msdos /dev/loop0

sudo mount /dev/loop0 ${tmp_dir}
sudo cp ${UBOOT_DIR}/MLO ${UBOOT_DIR}/u-boot.img ${UBOOT_DIR}/u-boot.bin ${tmp_dir}
sudo umount ${tmp_dir}
sudo /sbin/losetup -d /dev/loop0

rm -rf ${tmp_dir}
