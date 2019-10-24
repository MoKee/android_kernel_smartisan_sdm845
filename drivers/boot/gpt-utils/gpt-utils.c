/*
 * Copyright (c) 2013,2016, The Linux Foundation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer in the documentation and/or other materials provided
 *       with the distribution.
 *     * Neither the name of The Linux Foundation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/******************************************************************************
 * INCLUDE SECTION
 ******************************************************************************/
#include <linux/fcntl.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/stat.h>
#include <linux/ioctl.h>
#include <scsi/ufs/ioctl.h>
#include <scsi/ufs/ufs.h>
#include <linux/unistd.h>
#include <linux/fs.h>
#include <linux/limits.h>
#include <linux/dirent.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <asm/byteorder.h>
#define LOG_TAG "gpt-utils"
#include "gpt-utils.h"
#include "sparse_crc32.h"


/******************************************************************************
 * DEFINE SECTION
 ******************************************************************************/
#define BLK_DEV_FILE    "/dev/block/mmcblk0"
/* list the names of the backed-up partitions to be swapped */
/* extension used for the backup partitions - tzbak, abootbak, etc. */
#define BAK_PTN_NAME_EXT    "bak"
#define XBL_PRIMARY         "/dev/block/bootdevice/by-name/xbl"
#define XBL_BACKUP          "/dev/block/bootdevice/by-name/xblbak"
#define XBL_AB_PRIMARY      "/dev/block/bootdevice/by-name/xbl_a"
#define XBL_AB_SECONDARY    "/dev/block/bootdevice/by-name/xbl_b"
/* GPT defines */
#define MAX_LUNS                    26
//Size of the buffer that needs to be passed to the UFS ioctl
#define UFS_ATTR_DATA_SIZE          32
//This will allow us to get the root lun path from the path to the partition.
//i.e: from /dev/block/sdaXXX get /dev/block/sda. The assumption here is that
//the boot critical luns lie between sda to sdz which is acceptable because
//only user added external disks,etc would lie beyond that limit which do not
//contain partitions that interest us here.
#define PATH_TRUNCATE_LOC (sizeof("/dev/block/sda") - 1)

//From /dev/block/sda get just sda
#define LUN_NAME_START_LOC (sizeof("/dev/block/") - 1)
#define BOOT_LUN_A_ID 1
#define BOOT_LUN_B_ID 2
/******************************************************************************
 * MACROS
 ******************************************************************************/


#define GET_4_BYTES(ptr)    ((uint32_t) *((uint8_t *)(ptr)) | \
        ((uint32_t) *((uint8_t *)(ptr) + 1) << 8) | \
        ((uint32_t) *((uint8_t *)(ptr) + 2) << 16) | \
        ((uint32_t) *((uint8_t *)(ptr) + 3) << 24))

#define GET_8_BYTES(ptr)    ((uint64_t) *((uint8_t *)(ptr)) | \
        ((uint64_t) *((uint8_t *)(ptr) + 1) << 8) | \
        ((uint64_t) *((uint8_t *)(ptr) + 2) << 16) | \
        ((uint64_t) *((uint8_t *)(ptr) + 3) << 24) | \
        ((uint64_t) *((uint8_t *)(ptr) + 4) << 32) | \
        ((uint64_t) *((uint8_t *)(ptr) + 5) << 40) | \
        ((uint64_t) *((uint8_t *)(ptr) + 6) << 48) | \
        ((uint64_t) *((uint8_t *)(ptr) + 7) << 56))

#define PUT_4_BYTES(ptr, y)   *((uint8_t *)(ptr)) = (y) & 0xff; \
        *((uint8_t *)(ptr) + 1) = ((y) >> 8) & 0xff; \
        *((uint8_t *)(ptr) + 2) = ((y) >> 16) & 0xff; \
        *((uint8_t *)(ptr) + 3) = ((y) >> 24) & 0xff;

/******************************************************************************
 * TYPES
 ******************************************************************************/
enum gpt_state {
    GPT_OK = 0,
    GPT_BAD_SIGNATURE,
    GPT_BAD_CRC
};
//List of LUN's containing boot critical images.
//Required in the case of UFS devices
struct update_data {
     char lun_list[MAX_LUNS][PATH_MAX];
     uint32_t num_valid_entries;
};

/******************************************************************************
 * FUNCTIONS
 ******************************************************************************/
/**
 *  ==========================================================================
 *
 *  \brief  Read/Write len bytes from/to block dev
 *
 *  \param [in] fd      block dev file descriptor (returned from open)
 *  \param [in] rw      RW flag: 0 - read, != 0 - write
 *  \param [in] offset  block dev offset [bytes] - RW start position
 *  \param [in] buf     Pointer to the buffer containing the data
 *  \param [in] len     RW size in bytes. Buf must be at least that big
 *
 *  \return  0 on success
 *
 *  ==========================================================================
 */
static int blk_rw(struct file *fd, int rw, int64_t offset, uint8_t *buf, unsigned len)
{
    int r;

    if (fd->f_op->llseek(fd, offset, SEEK_SET) < 0) {
        pr_err("block dev llseek failed");
        return -1;
    }

    if (rw)
        r = fd->f_op->write(fd, buf, len, 0);
    else
        r = fd->f_op->read(fd, buf, len, 0);

    if (r < 0)
        pr_err("block dev %s failed", rw ? "write" : "read");
    else
        r = 0;

    return r;
}



/**
 *  ==========================================================================
 *
 *  \brief  Search within GPT for partition entry with the given name
 *  or it's backup twin (name-bak).
 *
 *  \param [in] ptn_name        Partition name to seek
 *  \param [in] pentries_start  Partition entries array start pointer
 *  \param [in] pentries_end    Partition entries array end pointer
 *  \param [in] pentry_size     Single partition entry size [bytes]
 *
 *  \return  First partition entry pointer that matches the name or NULL
 *
 *  ==========================================================================
 */
static uint8_t *gpt_pentry_seek(const char *ptn_name,
                                const uint8_t *pentries_start,
                                const uint8_t *pentries_end,
                                uint32_t pentry_size)
{
    char *pentry_name;
    unsigned len = strlen(ptn_name);

    for (pentry_name = (char *) (pentries_start + PARTITION_NAME_OFFSET);
         pentry_name < (char *) pentries_end; pentry_name += pentry_size) {
        char name8[MAX_GPT_NAME_SIZE] = {0}; // initialize with null
        unsigned i;

        /* Partition names in GPT are UTF-16 - ignoring UTF-16 2nd byte */
        for (i = 0; i < sizeof(name8) / 2; i++)
            name8[i] = pentry_name[i * 2];
        if (!strncmp(ptn_name, name8, len))
            if (name8[len] == 0 || !strcmp(&name8[len], BAK_PTN_NAME_EXT))
                return (uint8_t *) (pentry_name - PARTITION_NAME_OFFSET);
    }

    return NULL;
}



/**
 *  ==========================================================================
 *
 *  \brief  Swaps boot chain in GPT partition entries array
 *
 *  \param [in] pentries_start  Partition entries array start
 *  \param [in] pentries_end    Partition entries array end
 *  \param [in] pentry_size     Single partition entry size
 *
 *  \return  0 on success, 1 if no backup partitions found
 *
 *  ==========================================================================
 */
static int gpt_boot_chain_swap(const uint8_t *pentries_start,
                                const uint8_t *pentries_end,
                                uint32_t pentry_size)
{
    const char ptn_swap_list[][MAX_GPT_NAME_SIZE] = { PTN_SWAP_LIST };

    int backup_not_found = 1;
    unsigned i;

    for (i = 0; i < ARRAY_SIZE(ptn_swap_list); i++) {
        uint8_t *ptn_entry;
        uint8_t *ptn_bak_entry;
        uint8_t ptn_swap[PTN_ENTRY_SIZE];
        //Skip the xbl partition on UFS devices. That is handled
        //seperately.
        if (gpt_utils_is_ufs_device() && !strncmp(ptn_swap_list[i],
                                PTN_XBL,
                                strlen(PTN_XBL)))
            continue;

        ptn_entry = gpt_pentry_seek(ptn_swap_list[i], pentries_start,
                        pentries_end, pentry_size);
        if (ptn_entry == NULL)
            continue;

        ptn_bak_entry = gpt_pentry_seek(ptn_swap_list[i],
                        ptn_entry + pentry_size, pentries_end, pentry_size);
        if (ptn_bak_entry == NULL) {
            pr_err("'%s' partition not backup - skip safe update",
                    ptn_swap_list[i]);
            continue;
        }

        /* swap primary <-> backup partition entries */
        memcpy(ptn_swap, ptn_entry, PTN_ENTRY_SIZE);
        memcpy(ptn_entry, ptn_bak_entry, PTN_ENTRY_SIZE);
        memcpy(ptn_bak_entry, ptn_swap, PTN_ENTRY_SIZE);
        backup_not_found = 0;
    }

    return backup_not_found;
}



/**
 *  ==========================================================================
 *
 *  \brief  Sets secondary GPT boot chain
 *
 *  \param [in] fd    block dev file descriptor
 *  \param [in] boot  Boot chain to switch to
 *
 *  \return  0 on success
 *
 *  ==========================================================================
 */
static int gpt2_set_boot_chain(struct file *fd, enum boot_chain boot)
{
    int64_t  gpt2_header_offset;
    uint64_t pentries_start_offset;
    uint32_t gpt_header_size;
    uint32_t pentry_size;
    uint32_t pentries_array_size;

    uint8_t *gpt_header = NULL;
    uint8_t  *pentries = NULL;
    uint32_t crc;
    uint32_t blk_size = 0;
    int r;

    if (fd->f_op->unlocked_ioctl(fd, BLKSSZGET, (unsigned long) &blk_size) != 0) {
            pr_err("Failed to get GPT device block size");
            r = -1;
            goto EXIT;
    }
    gpt_header = (uint8_t*)kmalloc(blk_size, GFP_KERNEL);
    if (!gpt_header) {
            pr_err("Failed to allocate memory to hold GPT block");
            r = -1;
            goto EXIT;
    }
    gpt2_header_offset = fd->f_op->llseek(fd, 0, SEEK_END) - blk_size;
    if (gpt2_header_offset < 0) {
        pr_err("Getting secondary GPT header offset failed");
        r = -1;
        goto EXIT;
    }

    /* Read primary GPT header from block dev */
    r = blk_rw(fd, 0, blk_size, gpt_header, blk_size);

    if (r) {
            pr_err("Failed to read primary GPT header from blk dev");
            goto EXIT;
    }
    pentries_start_offset =
        GET_8_BYTES(gpt_header + PENTRIES_OFFSET) * blk_size;
    pentry_size = GET_4_BYTES(gpt_header + PENTRY_SIZE_OFFSET);
    pentries_array_size =
        GET_4_BYTES(gpt_header + PARTITION_COUNT_OFFSET) * pentry_size;

    pentries = (uint8_t *) kcalloc(1, pentries_array_size, GFP_KERNEL);
    if (pentries == NULL) {
        pr_err("Failed to alloc memory for GPT partition entries array");
        r = -1;
        goto EXIT;
    }
    /* Read primary GPT partititon entries array from block dev */
    r = blk_rw(fd, 0, pentries_start_offset, pentries, pentries_array_size);
    if (r)
        goto EXIT;

    crc = sparse_crc32(0, pentries, pentries_array_size);
    if (GET_4_BYTES(gpt_header + PARTITION_CRC_OFFSET) != crc) {
        pr_err("Primary GPT partition entries array CRC invalid");
        r = -1;
        goto EXIT;
    }

    /* Read secondary GPT header from block dev */
    r = blk_rw(fd, 0, gpt2_header_offset, gpt_header, blk_size);
    if (r)
        goto EXIT;

    gpt_header_size = GET_4_BYTES(gpt_header + HEADER_SIZE_OFFSET);
    pentries_start_offset =
        GET_8_BYTES(gpt_header + PENTRIES_OFFSET) * blk_size;

    if (boot == BACKUP_BOOT) {
        r = gpt_boot_chain_swap(pentries, pentries + pentries_array_size,
                                pentry_size);
        if (r)
            goto EXIT;
    }

    crc = sparse_crc32(0, pentries, pentries_array_size);
    PUT_4_BYTES(gpt_header + PARTITION_CRC_OFFSET, crc);

    /* header CRC is calculated with this field cleared */
    PUT_4_BYTES(gpt_header + HEADER_CRC_OFFSET, 0);
    crc = sparse_crc32(0, gpt_header, gpt_header_size);
    PUT_4_BYTES(gpt_header + HEADER_CRC_OFFSET, crc);

    /* Write the modified GPT header back to block dev */
    r = blk_rw(fd, 1, gpt2_header_offset, gpt_header, blk_size);
    if (!r)
        /* Write the modified GPT partititon entries array back to block dev */
        r = blk_rw(fd, 1, pentries_start_offset, pentries,
                    pentries_array_size);

EXIT:
    if(gpt_header)
            kfree(gpt_header);
    if (pentries)
            kfree(pentries);
    return r;
}

/**
 *  ==========================================================================
 *
 *  \brief  Checks GPT state (header signature and CRC)
 *
 *  \param [in] fd      block dev file descriptor
 *  \param [in] gpt     GPT header to be checked
 *  \param [out] state  GPT header state
 *
 *  \return  0 on success
 *
 *  ==========================================================================
 */
static int gpt_get_state(struct file *fd, enum gpt_instance gpt, enum gpt_state *state)
{
    int64_t gpt_header_offset;
    uint32_t gpt_header_size;
    uint8_t  *gpt_header = NULL;
    uint32_t crc;
    uint32_t blk_size = 0;

    *state = GPT_OK;

    if (fd->f_op->unlocked_ioctl(fd, BLKSSZGET, (unsigned long) &blk_size) != 0) {
            pr_err("Failed to get GPT device block size");
            goto error;
    }
    gpt_header = (uint8_t*)kmalloc(blk_size, GFP_KERNEL);
    if (!gpt_header) {
            pr_err("gpt_get_state:Failed to alloc memory for header");
            goto error;
    }
    if (gpt == PRIMARY_GPT)
        gpt_header_offset = blk_size;
    else {
        gpt_header_offset = fd->f_op->llseek(fd, 0, SEEK_END) - blk_size;
        if (gpt_header_offset < 0) {
            pr_err("gpt_get_state:Seek to end of GPT part fail");
            goto error;
        }
    }

    if (blk_rw(fd, 0, gpt_header_offset, gpt_header, blk_size)) {
        pr_err("gpt_get_state: blk_rw failed");
        goto error;
    }
    if (memcmp(gpt_header, GPT_SIGNATURE, sizeof(GPT_SIGNATURE)))
        *state = GPT_BAD_SIGNATURE;
    gpt_header_size = GET_4_BYTES(gpt_header + HEADER_SIZE_OFFSET);

    crc = GET_4_BYTES(gpt_header + HEADER_CRC_OFFSET);
    /* header CRC is calculated with this field cleared */
    PUT_4_BYTES(gpt_header + HEADER_CRC_OFFSET, 0);
    if (sparse_crc32(0, gpt_header, gpt_header_size) != crc)
        *state = GPT_BAD_CRC;
    kfree(gpt_header);
    return 0;
error:
    if (gpt_header)
            kfree(gpt_header);
    return -1;
}



/**
 *  ==========================================================================
 *
 *  \brief  Sets GPT header state (used to corrupt and fix GPT signature)
 *
 *  \param [in] fd     block dev file descriptor
 *  \param [in] gpt    GPT header to be checked
 *  \param [in] state  GPT header state to set (GPT_OK or GPT_BAD_SIGNATURE)
 *
 *  \return  0 on success
 *
 *  ==========================================================================
 */
static int gpt_set_state(struct file *fd, enum gpt_instance gpt, enum gpt_state state)
{
    int64_t gpt_header_offset;
    uint32_t gpt_header_size;
    uint8_t  *gpt_header = NULL;
    uint32_t crc;
    uint32_t blk_size = 0;

    if (fd->f_op->unlocked_ioctl(fd, BLKSSZGET, (unsigned long) &blk_size) != 0) {
            pr_err("Failed to get GPT device block size");
            goto error;
    }
    gpt_header = (uint8_t*)kmalloc(blk_size, GFP_KERNEL);
    if (!gpt_header) {
            pr_err("Failed to alloc memory for gpt header");
            goto error;
    }
    if (gpt == PRIMARY_GPT)
        gpt_header_offset = blk_size;
    else {
        gpt_header_offset = fd->f_op->llseek(fd, 0, SEEK_END) - blk_size;
        if (gpt_header_offset < 0) {
            pr_err("Failed to seek to end of GPT device");
            goto error;
        }
    }
    if (blk_rw(fd, 0, gpt_header_offset, gpt_header, blk_size)) {
        pr_err("Failed to r/w gpt header");
        goto error;
    }
    if (state == GPT_OK)
        memcpy(gpt_header, GPT_SIGNATURE, sizeof(GPT_SIGNATURE));
    else if (state == GPT_BAD_SIGNATURE)
        *gpt_header = 0;
    else {
        pr_err("gpt_set_state: Invalid state");
        goto error;
    }

    gpt_header_size = GET_4_BYTES(gpt_header + HEADER_SIZE_OFFSET);

    /* header CRC is calculated with this field cleared */
    PUT_4_BYTES(gpt_header + HEADER_CRC_OFFSET, 0);
    crc = sparse_crc32(0, gpt_header, gpt_header_size);
    PUT_4_BYTES(gpt_header + HEADER_CRC_OFFSET, crc);

    if (blk_rw(fd, 1, gpt_header_offset, gpt_header, blk_size)) {
        pr_err("gpt_set_state: blk write failed");
        goto error;
    }
    return 0;
error:
    if(gpt_header)
           kfree(gpt_header);
    return -1;
}

int get_scsi_node_from_bootdevice(const char *bootdev_path,
                char *sg_node_path,
                size_t buf_size)
{
        char sg_dir_path[PATH_MAX] = {0};
        char real_path[PATH_MAX] = {0};
        DIR *scsi_dir = NULL;
        struct dirent *de;
        int node_found = 0;
        if (!bootdev_path || !sg_node_path) {
                pr_err("%s : invalid argument",
                                 __func__);
                goto error;
        }
        if (readlink(bootdev_path, real_path, sizeof(real_path) - 1) < 0) {
                        pr_err("failed to resolve link for %s",
                                        bootdev_path);
                        goto error;
        }
        if(strlen(real_path) < PATH_TRUNCATE_LOC + 1){
            pr_err("Unrecognized path :%s:",
                           real_path);
            goto error;
        }
        //For the safe side in case there are additional partitions on
        //the XBL lun we truncate the name.
        real_path[PATH_TRUNCATE_LOC] = '\0';
        if(strlen(real_path) < LUN_NAME_START_LOC + 1){
            pr_err("Unrecognized truncated path :%s:",
                           real_path);
            goto error;
        }
        //This will give us /dev/block/sdb/device/scsi_generic
        //which contains a file sgY whose name gives us the path
        //to /dev/sgY which we return
        snprintf(sg_dir_path, sizeof(sg_dir_path) - 1,
                        "/sys/block/%s/device/scsi_generic",
                        &real_path[LUN_NAME_START_LOC]);
        scsi_dir = opendir(sg_dir_path);
        if (!scsi_dir) {
                pr_err("%s : Failed to open %s",
                                __func__,
                                sg_dir_path);
                goto error;
        }
        while((de = readdir(scsi_dir))) {
                if (de->d_name[0] == '.')
                        continue;
                else if (!strncmp(de->d_name, "sg", 2)) {
                          snprintf(sg_node_path,
                                        buf_size -1,
                                        "/dev/%s",
                                        de->d_name);
                          pr_err("%s:scsi generic node is :%s:",
                                          __func__,
                                          sg_node_path);
                          node_found = 1;
                          break;
                }
        }
        if(!node_found) {
                pr_err("%s: Unable to locate scsi generic node",
                               __func__);
                goto error;
        }
        closedir(scsi_dir);
        return 0;
error:
        if (scsi_dir)
                closedir(scsi_dir);
        return -1;
}

int set_boot_lun(char *sg_dev, uint8_t boot_lun_id)
{
        struct file *fd = NULL;
        int rc;
        struct ufs_ioctl_query_data *data = NULL;
        size_t ioctl_data_size = sizeof(struct ufs_ioctl_query_data) + UFS_ATTR_DATA_SIZE;

        data = (struct ufs_ioctl_query_data*)kmalloc(ioctl_data_size, GFP_KERNEL);
        if (!data) {
                pr_err("%s: Failed to alloc query data struct",
                                __func__);
                goto error;
        }
        memset(data, 0, ioctl_data_size);
        data->opcode = UPIU_QUERY_OPCODE_WRITE_ATTR;
        data->idn = QUERY_ATTR_IDN_BOOT_LU_EN;
        data->buf_size = UFS_ATTR_DATA_SIZE;
        data->buffer[0] = boot_lun_id;
        fd = file_open_name(sg_dev, O_RDWR);
        if (fd == NULL) {
                pr_err("%s: Failed to open %s",
                                __func__,
                                sg_dev);
                goto error;
        }
        rc = fd->f_op->unlocked_ioctl(fd, UFS_IOCTL_QUERY, (unsigned long) data);
        if (rc) {
                pr_err("%s: UFS query ioctl failed",
                                __func__);
                goto error;
        }
        kfree(data);
        return 0;
error:
        if (data)
                kfree(data);
        return -1;
}

//Swtich betwieen using either the primary or the backup
//boot LUN for boot. This is required since UFS boot partitions
//cannot have a backup GPT which is what we use for failsafe
//updates of the other 'critical' partitions. This function will
//not be invoked for emmc targets and on UFS targets is only required
//to be invoked for XBL.
//
//The algorithm to do this is as follows:
//- Find the real block device(eg: /dev/block/sdb) that corresponds
//  to the /dev/block/bootdevice/by-name/xbl(bak) symlink
//
//- Once we have the block device 'node' name(sdb in the above example)
//  use this node to to locate the scsi generic device that represents
//  it by checking the file /sys/block/sdb/device/scsi_generic/sgY
//
//- Once we locate sgY we call the query ioctl on /dev/sgy to switch
//the boot lun to either LUNA or LUNB
int gpt_utils_set_xbl_boot_partition(enum boot_chain chain)
{
        struct kstat st;
        ///sys/block/sdX/device/scsi_generic/
        char sg_dev_node[PATH_MAX] = {0};
        uint8_t boot_lun_id = 0;
        const char *boot_dev = NULL;

        if (chain == BACKUP_BOOT) {
                boot_lun_id = BOOT_LUN_B_ID;
                if (!vfs_stat(XBL_BACKUP, &st))
                        boot_dev = XBL_BACKUP;
                else if (!vfs_stat(XBL_AB_SECONDARY, &st))
                        boot_dev = XBL_AB_SECONDARY;
                else {
                        pr_err("%s: Failed to locate secondary xbl",
                                        __func__);
                        goto error;
                }
        } else if (chain == NORMAL_BOOT) {
                boot_lun_id = BOOT_LUN_A_ID;
                if (!vfs_stat(XBL_PRIMARY, &st))
                        boot_dev = XBL_PRIMARY;
                else if (!vfs_stat(XBL_AB_PRIMARY, &st))
                        boot_dev = XBL_AB_PRIMARY;
                else {
                        pr_err("%s: Failed to locate primary xbl",
                                        __func__);
                        goto error;
                }
        } else {
                pr_err("%s: Invalid boot chain id", __func__);
                goto error;
        }
        //We need either both xbl and xblbak or both xbl_a and xbl_b to exist at
        //the same time. If not the current configuration is invalid.
        if((vfs_stat(XBL_PRIMARY, &st) ||
                                vfs_stat(XBL_BACKUP, &st)) &&
                        (vfs_stat(XBL_AB_PRIMARY, &st) ||
                         vfs_stat(XBL_AB_SECONDARY, &st))) {
                pr_err("%s:primary/secondary XBL prt not found",
                                __func__);
                goto error;
        }
        pr_err("%s: setting %s lun as boot lun",
                        __func__,
                        boot_dev);
        if (get_scsi_node_from_bootdevice(boot_dev,
                                sg_dev_node,
                                sizeof(sg_dev_node))) {
                pr_err("%s: Failed to get scsi node path for xblbak",
                                __func__);
                goto error;
        }
        if (set_boot_lun(sg_dev_node, boot_lun_id)) {
                pr_err("%s: Failed to set xblbak as boot partition",
                                __func__);
                goto error;
        }
        return 0;
error:
        return -1;
}

int add_lun_to_update_list(char *lun_path, struct update_data *dat)
{
        uint32_t i = 0;
        struct kstat st;
        if (!lun_path || !dat){
                pr_err("%s: Invalid data",
                                __func__);
                return -1;
        }
        if (vfs_stat(lun_path, &st)) {
                pr_err("%s: Unable to access %s. Skipping adding to list",
                                __func__,
                                lun_path);
                return -1;
        }
        if (dat->num_valid_entries == 0) {
                pr_err("%s: Copying %s into lun_list[%d]",
                                __func__,
                                lun_path,
                                i);
                strlcpy(dat->lun_list[0], lun_path,
                                PATH_MAX * sizeof(char));
                dat->num_valid_entries = 1;
        } else {
                for (i = 0; (i < dat->num_valid_entries) &&
                                (dat->num_valid_entries < MAX_LUNS - 1); i++) {
                        //Check if the current LUN is not already part
                        //of the lun list
                        if (!strncmp(lun_path,dat->lun_list[i],
                                                strlen(dat->lun_list[i]))) {
                                //LUN already in list..Return
                                return 0;
                        }
                }
                pr_err("%s: Copying %s into lun_list[%d]",
                                __func__,
                                lun_path,
                                dat->num_valid_entries);
                //Add LUN path lun list
                strlcpy(dat->lun_list[dat->num_valid_entries], lun_path,
                                PATH_MAX * sizeof(char));
                dat->num_valid_entries++;
        }
        return 0;
}

//Given a parttion name(eg: rpm) get the path to the block device that
//represents the GPT disk the partition resides on. In the case of emmc it
//would be the default emmc dev(/dev/block/mmcblk0). In the case of UFS we look
//through the /dev/block/bootdevice/by-name/ tree for partname, and resolve
//the path to the LUN from there.
int get_dev_path_from_partition_name(const char *partname,
                char *buf,
                size_t buflen)
{
        struct kstat st;
        char path[PATH_MAX] = {0};
        if (!partname || !buf || buflen < ((PATH_TRUNCATE_LOC) + 1)) {
                pr_err("%s: Invalid argument", __func__);
                goto error;
        }
        if (gpt_utils_is_ufs_device()) {
                //Need to find the lun that holds partition partname
                snprintf(path, sizeof(path),
                                "%s/%s",
                                BOOT_DEV_DIR,
                                partname);
                if (vfs_stat(path, &st)) {
                        goto error;
                }
                if (readlink(path, buf, buflen) < 0)
                {
                        goto error;
                } else {
                        buf[PATH_TRUNCATE_LOC] = '\0';
                }
        } else {
                snprintf(buf, buflen, BLK_DEV_FILE);
        }
        return 0;

error:
        return -1;
}

//Get the block size of the disk represented by decsriptor fd
static uint32_t gpt_get_block_size(struct file *fd)
{
        uint32_t block_size = 0;
        if (fd == NULL) {
                pr_err("%s: invalid descriptor",
                                __func__);
                goto error;
        }
        if (fd->f_op->unlocked_ioctl(fd, BLKSSZGET, (unsigned long) &block_size) != 0) {
                pr_err("%s: Failed to get GPT dev block size", __func__);
                goto error;
        }
        return block_size;
error:
        return 0;
}

//Write the GPT header present in the passed in buffer back to the
//disk represented by fd
static int gpt_set_header(uint8_t *gpt_header, struct file *fd,
                enum gpt_instance instance)
{
        uint32_t block_size = 0;
        off64_t gpt_header_offset = 0;
        if (!gpt_header || fd == NULL) {
                pr_err("%s: Invalid arguments",
                                __func__);
                goto error;
        }
        block_size = gpt_get_block_size(fd);
        if (block_size == 0) {
                pr_err("%s: Failed to get block size", __func__);
                goto error;
        }
        if (instance == PRIMARY_GPT)
                gpt_header_offset = block_size;
        else
                gpt_header_offset = fd->f_op->llseek(fd, 0, SEEK_END) - block_size;
        if (gpt_header_offset <= 0) {
                pr_err("%s: Failed to get gpt header offset",__func__);
                goto error;
        }
        if (blk_rw(fd, 1, gpt_header_offset, gpt_header, block_size)) {
                pr_err("%s: Failed to write back GPT header", __func__);
                goto error;
        }
        return 0;
error:
        return -1;
}

//Read out the GPT header for the disk that contains the partition partname
static uint8_t* gpt_get_header(const char *partname, enum gpt_instance instance)
{
        uint8_t* hdr = NULL;
        char devpath[PATH_MAX] = {0};
        int64_t hdr_offset = 0;
        uint32_t block_size = 0;
        struct file *fd = NULL;
        if (!partname) {
                pr_err("%s: Invalid partition name", __func__);
                goto error;
        }
        if (get_dev_path_from_partition_name(partname, devpath, sizeof(devpath))
                        != 0) {
                pr_err("%s: Failed to resolve path for %s",
                                __func__,
                                partname);
                goto error;
        }
        fd = file_open_name(devpath, O_RDWR);
        if (fd == NULL) {
                pr_err("%s: Failed to open %s",
                                __func__,
                                devpath);
                goto error;
        }
        block_size = gpt_get_block_size(fd);
        if (block_size == 0)
        {
                pr_err("%s: Failed to get gpt block size for %s",
                                __func__,
                                partname);
                goto error;
        }

        hdr = (uint8_t*)kmalloc(block_size, GFP_KERNEL);
        if (!hdr) {
                pr_err("%s: Failed to allocate memory for gpt header",
                                __func__);
        }
        if (instance == PRIMARY_GPT)
                hdr_offset = block_size;
        else {
                hdr_offset = fd->f_op->llseek(fd, 0, SEEK_END) - block_size;
        }
        if (hdr_offset < 0) {
                pr_err("%s: Failed to get gpt header offset",
                                __func__);
                goto error;
        }
        if (blk_rw(fd, 0, hdr_offset, hdr, block_size)) {
                pr_err("%s: Failed to read GPT header from device",
                                __func__);
                goto error;
        }
        return hdr;
error:
        if (hdr)
                kfree(hdr);
        return NULL;
}

//Returns the partition entry array based on the
//passed in buffer which contains the gpt header.
//The fd here is the descriptor for the 'disk' which
//holds the partition
static uint8_t* gpt_get_pentry_arr(uint8_t *hdr, struct file *fd)
{
        uint64_t pentries_start = 0;
        uint32_t pentry_size = 0;
        uint32_t block_size = 0;
        uint32_t pentries_arr_size = 0;
        uint8_t *pentry_arr = NULL;
        int rc = 0;
        if (!hdr) {
                pr_err("%s: Invalid header", __func__);
                goto error;
        }
        if (fd == NULL) {
                pr_err("%s: Invalid fd", __func__);
                goto error;
        }
        block_size = gpt_get_block_size(fd);
        if (!block_size) {
                pr_err("%s: Failed to get gpt block size for",
                                __func__);
                goto error;
        }
        pentries_start = GET_8_BYTES(hdr + PENTRIES_OFFSET) * block_size;
        pentry_size = GET_4_BYTES(hdr + PENTRY_SIZE_OFFSET);
        pentries_arr_size =
                GET_4_BYTES(hdr + PARTITION_COUNT_OFFSET) * pentry_size;
        pentry_arr = (uint8_t*)kcalloc(1, pentries_arr_size, GFP_KERNEL);
        if (!pentry_arr) {
                pr_err("%s: Failed to allocate memory for partition array",
                                __func__);
                goto error;
        }
        rc = blk_rw(fd, 0,
                        pentries_start,
                        pentry_arr,
                        pentries_arr_size);
        if (rc) {
                pr_err("%s: Failed to read partition entry array",
                                __func__);
                goto error;
        }
        return pentry_arr;
error:
        if (pentry_arr)
                kfree(pentry_arr);
        return NULL;
}

static int gpt_set_pentry_arr(uint8_t *hdr, struct file *fd, uint8_t* arr)
{
        uint32_t block_size = 0;
        uint64_t pentries_start = 0;
        uint32_t pentry_size = 0;
        uint32_t pentries_arr_size = 0;
        int rc = 0;
        if (!hdr || fd == NULL || !arr) {
                pr_err("%s: Invalid argument", __func__);
                goto error;
        }
        block_size = gpt_get_block_size(fd);
        if (!block_size) {
                pr_err("%s: Failed to get gpt block size for",
                                __func__);
                goto error;
        }
        pentries_start = GET_8_BYTES(hdr + PENTRIES_OFFSET) * block_size;
        pentry_size = GET_4_BYTES(hdr + PENTRY_SIZE_OFFSET);
        pentries_arr_size =
                GET_4_BYTES(hdr + PARTITION_COUNT_OFFSET) * pentry_size;
        rc = blk_rw(fd, 1,
                        pentries_start,
                        arr,
                        pentries_arr_size);
        if (rc) {
                pr_err("%s: Failed to read partition entry array",
                                __func__);
                goto error;
        }
        return 0;
error:
        return -1;
}



//Allocate a handle used by calls to the "gpt_disk" api's
struct gpt_disk * gpt_disk_alloc()
{
        struct gpt_disk *disk;
        disk = (struct gpt_disk *)kmalloc(sizeof(struct gpt_disk), GFP_KERNEL);
        if (!disk) {
                pr_err("%s: Failed to allocate memory", __func__);
                goto end;
        }
        memset(disk, 0, sizeof(struct gpt_disk));
end:
        return disk;
}

//Free previously allocated/initialized handle
void gpt_disk_free(struct gpt_disk *disk)
{
        if (!disk)
                return;
        if (disk->hdr)
                kfree(disk->hdr);
        if (disk->hdr_bak)
                kfree(disk->hdr_bak);
        if (disk->pentry_arr)
                kfree(disk->pentry_arr);
        if (disk->pentry_arr_bak)
                kfree(disk->pentry_arr_bak);
        kfree(disk);
        return;
}

//fills up the passed in gpt_disk struct with information about the
//disk represented by path dev. Returns 0 on success and -1 on error.
int gpt_disk_get_disk_info(const char *dev, struct gpt_disk *dsk)
{
        struct gpt_disk *disk = NULL;
        struct file *fd = NULL;
        uint32_t gpt_header_size = 0;

        if (!dsk || !dev) {
                pr_err("%s: Invalid arguments", __func__);
                goto error;
        }
        disk = dsk;
        disk->hdr = gpt_get_header(dev, PRIMARY_GPT);
        if (!disk->hdr) {
                pr_err("%s: Failed to get primary header", __func__);
                goto error;
        }
        gpt_header_size = GET_4_BYTES(disk->hdr + HEADER_SIZE_OFFSET);
        disk->hdr_crc = sparse_crc32(0, disk->hdr, gpt_header_size);
        disk->hdr_bak = gpt_get_header(dev, SECONDARY_GPT);
        if (!disk->hdr_bak) {
                pr_err("%s: Failed to get backup header", __func__);
                goto error;
        }
        disk->hdr_bak_crc = sparse_crc32(0, disk->hdr_bak, gpt_header_size);

        //Descriptor for the block device. We will use this for further
        //modifications to the partition table
        if (get_dev_path_from_partition_name(dev,
                                disk->devpath,
                                sizeof(disk->devpath)) != 0) {
                pr_err("%s: Failed to resolve path for %s",
                                __func__,
                                dev);
                goto error;
        }
        fd = file_open_name(disk->devpath, O_RDWR);
        if (fd == NULL) {
                pr_err("%s: Failed to open %s",
                                __func__,
                                disk->devpath);
                goto error;
        }
        disk->pentry_arr = gpt_get_pentry_arr(disk->hdr, fd);
        if (!disk->pentry_arr) {
                pr_err("%s: Failed to obtain partition entry array",
                                __func__);
                goto error;
        }
        disk->pentry_arr_bak = gpt_get_pentry_arr(disk->hdr_bak, fd);
        if (!disk->pentry_arr_bak) {
                pr_err("%s: Failed to obtain backup partition entry array",
                                __func__);
                goto error;
        }
        disk->pentry_size = GET_4_BYTES(disk->hdr + PENTRY_SIZE_OFFSET);
        disk->pentry_arr_size =
                GET_4_BYTES(disk->hdr + PARTITION_COUNT_OFFSET) *
                disk->pentry_size;
        disk->pentry_arr_crc = GET_4_BYTES(disk->hdr + PARTITION_CRC_OFFSET);
        disk->pentry_arr_bak_crc = GET_4_BYTES(disk->hdr_bak +
                        PARTITION_CRC_OFFSET);
        disk->block_size = gpt_get_block_size(fd);
        disk->is_initialized = GPT_DISK_INIT_MAGIC;
        return 0;
error:
        return -1;
}

//Get pointer to partition entry from a allocated gpt_disk structure
uint8_t* gpt_disk_get_pentry(struct gpt_disk *disk,
                const char *partname,
                enum gpt_instance instance)
{
        uint8_t *ptn_arr = NULL;
        if (!disk || !partname || disk->is_initialized != GPT_DISK_INIT_MAGIC) {
                pr_err("%s: Invalid argument",__func__);
                goto error;
        }
        ptn_arr = (instance == PRIMARY_GPT) ?
                disk->pentry_arr : disk->pentry_arr_bak;
        return (gpt_pentry_seek(partname, ptn_arr,
                        ptn_arr + disk->pentry_arr_size ,
                        disk->pentry_size));
error:
        return NULL;
}

//Update CRC values for the various components of the gpt_disk
//structure. This function should be called after any of the fields
//have been updated before the structure contents are written back to
//disk.
int gpt_disk_update_crc(struct gpt_disk *disk)
{
        uint32_t gpt_header_size = 0;
        if (!disk || (disk->is_initialized != GPT_DISK_INIT_MAGIC)) {
                pr_err("%s: invalid argument", __func__);
                goto error;
        }
        //Recalculate the CRC of the primary partiton array
        disk->pentry_arr_crc = sparse_crc32(0,
                        disk->pentry_arr,
                        disk->pentry_arr_size);
        //Recalculate the CRC of the backup partition array
        disk->pentry_arr_bak_crc = sparse_crc32(0,
                        disk->pentry_arr_bak,
                        disk->pentry_arr_size);
        //Update the partition CRC value in the primary GPT header
        PUT_4_BYTES(disk->hdr + PARTITION_CRC_OFFSET, disk->pentry_arr_crc);
        //Update the partition CRC value in the backup GPT header
        PUT_4_BYTES(disk->hdr_bak + PARTITION_CRC_OFFSET,
                        disk->pentry_arr_bak_crc);
        //Update the CRC value of the primary header
        gpt_header_size = GET_4_BYTES(disk->hdr + HEADER_SIZE_OFFSET);
        //Header CRC is calculated with its own CRC field set to 0
        PUT_4_BYTES(disk->hdr + HEADER_CRC_OFFSET, 0);
        PUT_4_BYTES(disk->hdr_bak + HEADER_CRC_OFFSET, 0);
        disk->hdr_crc = sparse_crc32(0, disk->hdr, gpt_header_size);
        disk->hdr_bak_crc = sparse_crc32(0, disk->hdr_bak, gpt_header_size);
        PUT_4_BYTES(disk->hdr + HEADER_CRC_OFFSET, disk->hdr_crc);
        PUT_4_BYTES(disk->hdr_bak + HEADER_CRC_OFFSET, disk->hdr_bak_crc);
        return 0;
error:
        return -1;
}

//Write the contents of struct gpt_disk back to the actual disk
int gpt_disk_commit(struct gpt_disk *disk)
{
        struct file *fd = NULL;
        if (!disk || (disk->is_initialized != GPT_DISK_INIT_MAGIC)){
                pr_err("%s: Invalid args", __func__);
                goto error;
        }
        fd = file_open_name(disk->devpath, O_RDWR);
        if (fd == NULL) {
                pr_err("%s: Failed to open %s",
                                __func__,
                                disk->devpath);
                goto error;
        }
        //Write the primary header
        if(gpt_set_header(disk->hdr, fd, PRIMARY_GPT) != 0) {
                pr_err("%s: Failed to update primary GPT header",
                                __func__);
                goto error;
        }
        //Write back the primary partition array
        if (gpt_set_pentry_arr(disk->hdr, fd, disk->pentry_arr)) {
                pr_err("%s: Failed to write primary GPT partition arr",
                                __func__);
                goto error;
        }
        //Write back the secondary header
        if(gpt_set_header(disk->hdr_bak, fd, SECONDARY_GPT) != 0) {
                pr_err("%s: Failed to update secondary GPT header",
                                __func__);
                goto error;
        }
        //Write back the secondary partition array
        if (gpt_set_pentry_arr(disk->hdr_bak, fd, disk->pentry_arr_bak)) {
                pr_err("%s: Failed to write secondary GPT partition arr",
                                __func__);
                goto error;
        }
        return 0;
error:
        return -1;
}
