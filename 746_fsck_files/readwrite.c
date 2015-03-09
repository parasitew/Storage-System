/* $cmuPDL: readwrite.c,v 1.3 2010/02/27 11:38:39 rajas Exp $ */
/* $cmuPDL: readwrite.c,v 1.4 2014/01/26 21:16:20 avjaltad Exp $ */
/* readwrite.c
 *
 * Code to read and write sectors to a "disk" file.
 * This is a support file for the "fsck" storage systems laboratory.
 *
 * author: Tong Wei (twei1)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>     /* for memcpy() */
#include <fcntl.h>
#include <unistd.h>
#include <inttypes.h>
#include "readwrite.h"
#include <getopt.h>


#include <linux/types.h>

#if defined(__FreeBSD__)
#define lseek64 lseek
#endif

#define EXT2_NDIR_BLOCKS                12
#define EXT2_IND_BLOCK                  EXT2_NDIR_BLOCKS
#define EXT2_DIND_BLOCK                 (EXT2_IND_BLOCK + 1)
#define EXT2_TIND_BLOCK                 (EXT2_DIND_BLOCK + 1)
#define EXT2_N_BLOCKS                   (EXT2_TIND_BLOCK + 1)

#define EXT2_NAME_LEN                    255
#define DEBUG 0

#define EXT2_DIR_PAD                    4
#define EXT2_DIR_ROUND                  (EXT2_DIR_PAD - 1)
#define EXT2_DIR_REC_LEN(name_len)      (((name_len) + 8 + EXT2_DIR_ROUND) & ~EXT2_DIR_ROUND)


struct ext2_dir_entry_2 {
    __u32 inode;
    /* Inode number */
    __u16 rec_len;
    /* Directory entry length */
    __u8 name_len;
    /* Name length */
    __u8 file_type;
    char name[EXT2_NAME_LEN];    /* File name */
};


/*
 * Structure of an inode on the disk
 */
struct ext2_inode {
    __u16 i_mode;
    /* File mode */
    __u16 i_uid;
    /* Low 16 bits of Owner Uid */
    __u32 i_size;
    /* Size in bytes */
    __u32 i_atime;
    /* Access time */
    __u32 i_ctime;
    /* Creation time */
    __u32 i_mtime;
    /* Modification time */
    __u32 i_dtime;
    /* Deletion Time */
    __u16 i_gid;
    /* Low 16 bits of Group Id */
    __u16 i_links_count;
    /* Links count */
    __u32 i_blocks;
    /* Blocks count */
    __u32 i_flags;
    /* File flags */
    union {
        struct {
            __u32 l_i_reserved1;
        } linux1;
        struct {
            __u32 h_i_translator;
        } hurd1;
        struct {
            __u32 m_i_reserved1;
        } masix1;
    } osd1;
    /* OS dependent 1 */
    __u32 i_block[EXT2_N_BLOCKS];
    /* Pointers to blocks */
    __u32 i_generation;
    /* File version (for NFS) */
    __u32 i_file_acl;
    /* File ACL */
    __u32 i_dir_acl;
    /* Directory ACL */
    __u32 i_faddr;
    /* Fragment address */
    union {
        struct {
            __u8 l_i_frag;
            /* Fragment number */
            __u8 l_i_fsize;
            /* Fragment size */
            __u16 i_pad1;
            __u16 l_i_uid_high;
            /* these 2 fields    */
            __u16 l_i_gid_high;
            /* were reserved2[0] */
            __u32 l_i_reserved2;
        } linux2;
        struct {
            __u8 h_i_frag;
            /* Fragment number */
            __u8 h_i_fsize;
            /* Fragment size */
            __u16 h_i_mode_high;
            __u16 h_i_uid_high;
            __u16 h_i_gid_high;
            __u32 h_i_author;
        } hurd2;
        struct {
            __u8 m_i_frag;
            /* Fragment number */
            __u8 m_i_fsize;
            /* Fragment size */
            __u16 m_pad1;
            __u32 m_i_reserved2[2];
        } masix2;
    } osd2;                         /* OS dependent 2 */
};


struct ext2_group_desc {
    __u32 bg_block_bitmap;
    /* Blocks bitmap block */
    __u32 bg_inode_bitmap;
    /* Inodes bitmap block */
    __u32 bg_inode_table;
    /* Inodes table block */
    __u16 bg_free_blocks_count;
    /* Free blocks count */
    __u16 bg_free_inodes_count;
    /* Free inodes count */
    __u16 bg_used_dirs_count;
    /* Directories count */
    __u16 bg_pad;
    __u32 bg_reserved[3];
};

/*
 * Structure of the super block
 */
struct ext2_super_block {
    __u32 s_inodes_count;
    /* Inodes count */
    __u32 s_blocks_count;
    /* Blocks count */
    __u32 s_r_blocks_count;
    /* Reserved blocks count */
    __u32 s_free_blocks_count;
    /* Free blocks count */
    __u32 s_free_inodes_count;
    /* Free inodes count */
    __u32 s_first_data_block;
    /* First Data Block */
    __u32 s_log_block_size;
    /* Block size */
    __s32 s_log_frag_size;
    /* Fragment size */
    __u32 s_blocks_per_group;
    /* # Blocks per group */
    __u32 s_frags_per_group;
    /* # Fragments per group */
    __u32 s_inodes_per_group;
    /* # Inodes per group */
    __u32 s_mtime;
    /* Mount time */
    __u32 s_wtime;
    /* Write time */
    __u16 s_mnt_count;
    /* Mount count */
    __s16 s_max_mnt_count;
    /* Maximal mount count */
    __u16 s_magic;
    /* Magic signature */
    __u16 s_state;
    /* File system state */
    __u16 s_errors;
    /* Behaviour when detecting errors */
    __u16 s_minor_rev_level;
    /* minor revision level */
    __u32 s_lastcheck;
    /* time of last check */
    __u32 s_checkinterval;
    /* max. time between checks */
    __u32 s_creator_os;
    /* OS */
    __u32 s_rev_level;
    /* Revision level */
    __u16 s_def_resuid;
    /* Default uid for reserved blocks */
    __u16 s_def_resgid;           /* Default gid for reserved blocks */
    /*
     * These fields are for EXT2_DYNAMIC_REV superblocks only.
     *
     * Note: the difference between the compatible feature set and
     * the incompatible feature set is that if there is a bit set
     * in the incompatible feature set that the kernel doesn't
     * know about, it should refuse to mount the filesystem.
     *
     * e2fsck's requirements are more strict; if it doesn't know
     * about a feature in either the compatible or incompatible
     * feature set, it must abort and not try to meddle with
     * things it doesn't understand...
     */
    __u32 s_first_ino;
    /* First non-reserved inode */
    __u16 s_inode_size;
    /* size of inode structure */
    __u16 s_block_group_nr;
    /* block group # of this superblock */
    __u32 s_feature_compat;
    /* compatible feature set */
    __u32 s_feature_incompat;
    /* incompatible feature set */
    __u32 s_feature_ro_compat;
    /* readonly-compatible feature set */
    __u8 s_uuid[16];
    /* 128-bit uuid for volume */
    char s_volume_name[16];
    /* volume name */
    char s_last_mounted[64];
    /* directory where last mounted */
    __u32 s_algorithm_usage_bitmap; /* For compression */
    /*
     * Performance hints.  Directory preallocation should only
     * happen if the EXT2_COMPAT_PREALLOC flag is on.
     */
    __u8 s_prealloc_blocks;
    /* Nr of blocks to try to preallocate*/
    __u8 s_prealloc_dir_blocks;
    /* Nr to preallocate for dirs */
    __u16 s_padding1;
    __u32 s_reserved[204];        /* Padding to the end of the block */
};

struct partition {
    unsigned char boot_ind;
    /* 0x80 - active */
    unsigned char head;
    /* starting head */
    unsigned char sector;
    /* starting sector */
    unsigned char cyl;
    /* starting cylinder */
    unsigned char sys_ind;
    /* What partition type */
    unsigned char end_head;
    /* end head */
    unsigned char end_sector;
    /* end sector */
    unsigned char end_cyl;
    /* end cylinder */
    unsigned int start_sect;
    /* starting sector counting from 0 */
    unsigned int nr_sects;      /* nr of sectors in partition */
} __attribute__((packed));

#define MBR_OFFSET 446

#define SUPER_BLK_OFFSET 1024
#define SUPER_BLK_SIZE 1024


#define PART_TYPE_EXT 0x05
#define PART_TYPE_UNUSED 0x00

/* linux: lseek64 declaration needed here to eliminate compiler warning. */
extern int64_t lseek64(int, int64_t, int);

const unsigned int sector_size_bytes = 512;

static int device;  /* disk file descriptor */

/* print_sector: print the contents of a buffer containing one sector.
 *
 * inputs:
 *   char *buf: buffer must be >= 512 bytes.
 *
 * outputs:
 *   the first 512 bytes of char *buf are printed to stdout.
 *
 * modifies:
 *   (none)
 */
void print_sector(unsigned char *buf) {
    int i;
    for (i = 0; i < sector_size_bytes; i++) {
        printf("%02x", buf[i]);
        if (!((i + 1) % 32))
            printf("\n");      /* line break after 32 bytes */
        else if (!((i + 1) % 4))
            printf(" ");   /* space after 4 bytes */
    }
}


/* read_sectors: read a specified number of sectors into a buffer.
 *
 * inputs:
 *   int64 start_sector: the starting sector number to read.
 *                       sector numbering starts with 0.
 *   int numsectors: the number of sectors to read.  must be >= 1.
 *   int device [GLOBAL]: the disk from which to read.
 *
 * outputs:
 *   void *into: the requested number of sectors are copied into here.
 *
 * modifies:
 *   void *into
 */
void read_sectors(int64_t start_sector, unsigned int num_sectors, void *into) {
    ssize_t ret;
    int64_t lret;
    int64_t sector_offset;
    ssize_t bytes_to_read;

    if (num_sectors == 1) {
        //printf("Reading sector %"PRId64"\n", start_sector);
    } else {
        //printf("Reading sectors %"PRId64"--%"PRId64"\n",
        //       start_sector, start_sector + (num_sectors - 1));
    }

    sector_offset = start_sector * sector_size_bytes;

    if ((lret = lseek64(device, sector_offset, SEEK_SET)) != sector_offset) {
        fprintf(stderr, "Seek to position %"PRId64" failed: "
                "returned %"PRId64"\n", sector_offset, lret);
        exit(-1);
    }

    bytes_to_read = sector_size_bytes * num_sectors;

    if ((ret = read(device, into, bytes_to_read)) != bytes_to_read) {
        fprintf(stderr, "Read sector %"PRId64" length %d failed: "
                "returned %"PRId64"\n", start_sector, num_sectors, ret);
        exit(-1);
    }
}


/* write_sectors: write a buffer into a specified number of sectors.
 *
 * inputs:
 *   int64 start_sector: the starting sector number to write.
 *                	sector numbering starts with 0.
 *   int numsectors: the number of sectors to write.  must be >= 1.
 *   void *from: the requested number of sectors are copied from here.
 *
 * outputs:
 *   int device [GLOBAL]: the disk into which to write.
 *
 * modifies:
 *   int device [GLOBAL]
 */
void write_sectors(int64_t start_sector, unsigned int num_sectors, void *from) {
    ssize_t ret;
    int64_t lret;
    int64_t sector_offset;
    ssize_t bytes_to_write;

    if (num_sectors == 1) {
        //printf("Reading sector  %"PRId64"\n", start_sector);
    } else {
        //printf("Reading sectors %"PRId64"--%"PRId64"\n",
        //       start_sector, start_sector + (num_sectors - 1));
    }

    sector_offset = start_sector * sector_size_bytes;

    if ((lret = lseek64(device, sector_offset, SEEK_SET)) != sector_offset) {
        fprintf(stderr, "Seek to position %"PRId64" failed: "
                "returned %"PRId64"\n", sector_offset, lret);
        exit(-1);
    }

    bytes_to_write = sector_size_bytes * num_sectors;

    if ((ret = write(device, from, bytes_to_write)) != bytes_to_write) {
        fprintf(stderr, "Write sector %"PRId64" length %d failed: "
                "returned %"PRId64"\n", start_sector, num_sectors, ret);
        exit(-1);
    }
}

struct partition read_partition(int partition_num) {
    struct partition res_partition;
    res_partition.start_sect = -1;

    if (partition_num == 0) {
        return res_partition;
    }

    int cnt = 1;
    int cnt_next = 1;
    struct partition *part_buf;
    unsigned char buf[sector_size_bytes * 2];
    int start_sect;
    int base_sect;
    int part_type;

    // Read the first sector
    read_sectors(0, 2, buf);


    if (partition_num <= 4) {
        part_buf = (struct partition *) (buf + MBR_OFFSET + (partition_num - 1) * sizeof(struct partition));

        res_partition.start_sect = part_buf->start_sect;
        res_partition.nr_sects = part_buf->nr_sects;
        res_partition.sys_ind = part_buf->sys_ind;

        return res_partition;
    }

    // Read first 4 partitions
    for (int i = 0; i < 4; i++) {
        part_buf = (struct partition *) (buf + MBR_OFFSET + i * sizeof(struct partition));

        start_sect = part_buf->start_sect;
        base_sect = part_buf->start_sect;
        part_type = part_buf->sys_ind;

        //printf("0x%02X %d %d\n", part_buf->sys_ind, part_buf->start_sect, part_buf->nr_sects);

        while (part_type == PART_TYPE_EXT) {
            read_sectors(start_sect, 1, buf);

            part_buf = (struct partition *) (buf + MBR_OFFSET);

            if (part_buf->sys_ind == PART_TYPE_UNUSED) {
                break;
            }


            if (cnt_next == (partition_num - 4)) {
                res_partition.start_sect = part_buf->start_sect + start_sect;
                res_partition.nr_sects = part_buf->nr_sects;
                res_partition.sys_ind = part_buf->sys_ind;

                return res_partition;
            }

            cnt_next++;

            // Read second EBR entry.
            part_buf = (struct partition *) (buf + MBR_OFFSET + 1 * sizeof(struct partition));

            start_sect = part_buf->start_sect + base_sect;
            part_type = part_buf->sys_ind;
        }
    }

    return res_partition;
}

void read_super_blk(int part_start_offset, struct ext2_super_block *super_blk) {
    unsigned char buf[SUPER_BLK_SIZE];

    read_sectors(part_start_offset + SUPER_BLK_OFFSET / sector_size_bytes,
            SUPER_BLK_SIZE / sector_size_bytes, buf);

    memcpy(super_blk, &buf, sizeof(struct ext2_super_block));
}

void print_inode(struct ext2_inode *inode) {
    printf("-------------inode-------------------\n");
    printf("inode mode: 0x%x\n", inode->i_mode);
    printf("inode blocks: %d\n", inode->i_blocks);
    printf("inode links: %d\n", inode->i_links_count);
}

void print_dir_entry(struct ext2_dir_entry_2 *entry) {
    printf("-----------------dir_entry-----------------\n");
    printf("inode: %d\n", entry->inode);
    printf("rec_len: %d\n", entry->rec_len);
    printf("name_len: %d\n", entry->name_len);
    printf("file_type: %d\n", entry->file_type);
    printf("file name: %s\n", entry->name);
    printf("file name len: %d\n", (int) strlen(entry->name));
}

void print_super_block(struct ext2_super_block *sb) {
    printf("\nmagic number: 0x%02X\n", sb->s_magic);
    printf("inodes count: %d\n", sb->s_inodes_count);
    printf("blocks count: %d\n", sb->s_blocks_count);
    printf("inodes per group: %d\n", sb->s_inodes_per_group);
    printf("blocks per group: %d\n", sb->s_blocks_per_group);
    printf("block size: %d\n", (sb->s_log_block_size + 1) * 1024);
    printf("size of inode structure: %d\n", sb->s_inode_size);
}

void print_group_desc(struct ext2_group_desc *group_desc) {
    printf("----------------Block Group Descriptor--------------------------\n");
    printf("block bitmap: %d\n", group_desc->bg_block_bitmap);
    printf("inode bitmap: %d\n", group_desc->bg_inode_bitmap);
    printf("inode table: %d\n", group_desc->bg_inode_table);
    printf("free block count: %d\n", group_desc->bg_free_blocks_count);
    printf("free inode count: %d\n", group_desc->bg_free_inodes_count);
    printf("used dirs count: %d\n", group_desc->bg_used_dirs_count);
}

// Create inode table from all block groups.
void create_inode_table(int part_start_offset,
        struct ext2_super_block *sb, struct ext2_inode *inode_table) {

    int block_size = 1024;
    int group_cnt = (sb->s_inodes_count + sb->s_inodes_per_group - 1) / sb->s_inodes_per_group;
    int group_desc_size = sizeof(struct ext2_group_desc);
    int group_desc_offset;

    // Size of all group descs.
    int total_size = group_cnt * group_desc_size;
    int size = (total_size + sector_size_bytes - 1) / sector_size_bytes * sector_size_bytes;

    // Size of all inodes in the group.
    int total_size1 = sb->s_inodes_per_group * sizeof(struct ext2_inode);
    int size1 = (total_size1 + sector_size_bytes - 1) / sector_size_bytes * sector_size_bytes;

    unsigned char buf[size];
    int inode_cur_offset = 0;

    read_sectors(part_start_offset + (SUPER_BLK_OFFSET + SUPER_BLK_SIZE) /
            sector_size_bytes, size / sector_size_bytes, buf);

    for (int i = 0; i < group_cnt; i++) {
        // Read next group desc
        struct ext2_group_desc *group_desc = (struct ext2_group_desc *) (buf + i * sizeof(struct ext2_group_desc));
        int inode_table_offset = group_desc->bg_inode_table;

        unsigned char inode_buf[size1];
        read_sectors(part_start_offset + inode_table_offset * block_size / sector_size_bytes,
                size1 / sector_size_bytes, inode_buf);

        memcpy(inode_table + inode_cur_offset, inode_buf, total_size1);

        inode_cur_offset += (total_size1 / sizeof(struct ext2_inode));
    }
}

// Create inode table from all block groups.
void create_inode_bitmap(int part_start_offset,
        struct ext2_super_block *sb, unsigned char *inode_bitmap) {

    int block_size = 1024;
    int group_cnt = (sb->s_inodes_count + sb->s_inodes_per_group - 1) / sb->s_inodes_per_group;
    int group_desc_size = sizeof(struct ext2_group_desc);
    int group_desc_offset;

    // Size of all group descs.
    int total_size = group_cnt * group_desc_size;
    int size = (total_size + sector_size_bytes - 1) / sector_size_bytes * sector_size_bytes;

    // Size of all inodes in the group.
    int total_size1 = sb->s_inodes_per_group / 8;
    int size1 = (total_size1 + sector_size_bytes - 1) / sector_size_bytes * sector_size_bytes;

    unsigned char buf[size];
    int cur_offset = 0;

    read_sectors(part_start_offset + (SUPER_BLK_OFFSET + SUPER_BLK_SIZE) /
            sector_size_bytes, size / sector_size_bytes, buf);

    for (int i = 0; i < group_cnt; i++) {
        // Read next group desc
        struct ext2_group_desc *group_desc = (struct ext2_group_desc *) (buf + i * sizeof(struct ext2_group_desc));
        int inode_bitmap_offset = group_desc->bg_inode_bitmap;
        unsigned char buf[size1];
        read_sectors(part_start_offset + inode_bitmap_offset * block_size / sector_size_bytes,
                1, buf);

        memcpy(inode_bitmap + cur_offset, buf, total_size1);

        cur_offset += total_size1;
    }
}

void traverse_dir(int part_start_offset, struct ext2_inode *inode_table,
        int inode_num, int parent_inode_num) {
    struct ext2_inode root_inode;
    //root_inode = ((struct ext2_inode *) inode_table)[inode_num - 1];
    root_inode = inode_table[inode_num - 1];
    int blk_cnt = root_inode.i_blocks;
    int blk_size = 1024;

    struct ext2_dir_entry_2 *entry;
    unsigned char blk_buf[blk_size];

    if (DEBUG) printf("inode num: %d\n", inode_num);
    if (DEBUG) printf("block_cnt: %d\n", blk_cnt);
    if (DEBUG) printf("start block: %d\n", root_inode.i_block[0]);


    for (int i = 0; i < 2; i++) {

        // Read data block.
        read_sectors(part_start_offset + root_inode.i_block[i] * 2, 2, blk_buf);

        // Traverse dir entries.
        int start_offset = 0;
        int entry_num = 0;

        entry = (struct ext2_dir_entry_2 *) (blk_buf + start_offset);


        if (entry->name_len == 0) {
            break;
        }


        while (1) {
            entry = (struct ext2_dir_entry_2 *) (blk_buf + start_offset);


            if (entry->name_len == 0 || entry->rec_len + start_offset > blk_size) {
                break;
            }

            //print_dir_entry(entry);

            if (i == 0 && entry_num == 0) {
                if (strcmp(entry->name, ".") != 0) {
                    strcpy(entry->name, ".");
                    entry->name_len = strlen(entry->name);

                    printf("Pass1 name error: [.], inode: %d\n", entry->inode);
                }

                if (entry->inode != inode_num) {
                    entry->inode = inode_num;
                    printf("Pass1 reference error: [.], inode: %d\n", entry->inode);
                }
            }

            if (i == 0 && entry_num == 1) {
                if (strcmp(entry->name, "..") != 0) {
                    strcpy(entry->name, "..");
                    entry->name_len = strlen(entry->name);

                    printf("Pass1 name error: [..], inode: %d\n", entry->inode);
                }

                if (entry->inode != parent_inode_num) {
                    entry->inode = parent_inode_num;
                    printf("Pass1 reference error: [..], inode: %d\n", entry->inode);
                }
            }

            if (DEBUG) print_dir_entry(entry);

            // Recursive traver non "."/ ".." dirtories
            if (entry_num > 1 && entry->file_type == 2) {
                traverse_dir(part_start_offset, inode_table, entry->inode, inode_num);
            }

            start_offset += entry->rec_len;

            if (start_offset >= blk_size) {
                break;
            }

            entry_num++;
        }
        write_sectors(part_start_offset + root_inode.i_block[i] * 2, 2, blk_buf);
    }
}

void read_blk_group_desc(int part_start_offset, struct ext2_group_desc *group_desc) {
    unsigned char buf[sector_size_bytes];

    read_sectors(part_start_offset + (SUPER_BLK_OFFSET + SUPER_BLK_SIZE) /
            sector_size_bytes, 1, buf);

    memcpy(group_desc, buf, sizeof(struct ext2_group_desc));


    struct ext2_super_block *sb;
    sb = (struct ext2_super_block *) malloc(sizeof(struct ext2_super_block));

    read_super_blk(part_start_offset, sb);

    unsigned char inode_buf[1024];

    read_sectors(part_start_offset + 10, 2, inode_buf);

    struct ext2_inode *inode;
    inode = (struct ext2_inode *) malloc(sizeof(struct ext2_inode));
    memcpy(inode, inode_buf + 1 * sizeof(struct ext2_inode), sizeof(struct ext2_inode));

    // Create inode table
    struct ext2_inode *inode_table;
    inode_table = (struct ext2_inode *) malloc(sb->s_inodes_count * sizeof(struct ext2_inode));
    create_inode_table(part_start_offset, sb, inode_table);

    traverse_dir(part_start_offset, inode_table, 2, 2);
}

int get_inode_bitmap(unsigned char *bitmap, int num) {
    num = num - 1;

    unsigned char value = bitmap[num / 8];

    int cnt = num % 8;

    return (value >> cnt) & 1;
}

int set_inode_bitmap(unsigned char *bitmap, int num, int val) {
    num = num - 1;

    int cnt = num % 8;
    int mask = ~(1 << cnt);

    bitmap[num / 8] = (bitmap[num / 8] & mask) | (val << cnt);
}

void find_unreferenced_inodes(int part_start_offset, struct ext2_super_block *sb,
        struct ext2_inode *inode_table, unsigned char *bitmap, int inode_num) {
    struct ext2_inode root_inode;
    //root_inode = ((struct ext2_inode *) inode_table)[inode_num - 1];
    root_inode = inode_table[inode_num - 1];
    int blk_cnt = root_inode.i_blocks;
    int blk_size = 1024;

    struct ext2_dir_entry_2 *entry;
    unsigned char blk_buf[blk_size];

    if (DEBUG) printf("inode num: %d\n", inode_num);
    if (DEBUG) printf("block_cnt: %d\n", blk_cnt);
    if (DEBUG) printf("start block: %d\n", root_inode.i_block[0]);

    for (int i = 0; i < EXT2_N_BLOCKS; i++) {
        // Read data block.
        read_sectors(part_start_offset + root_inode.i_block[i] * 2, 2, blk_buf);

        // Traverse dir entries.
        int start_offset = 0;
        int entry_num = 0;

        entry = (struct ext2_dir_entry_2 *) (blk_buf + start_offset);


        if (entry->name_len == 0) {
            break;
        }

        while (1) {
            entry = (struct ext2_dir_entry_2 *) (blk_buf + start_offset);

            if (entry->rec_len == 0 || entry->rec_len + start_offset > blk_size) {
                break;
            }

            //print_dir_entry(entry);

            if (entry->inode > 0 && entry->inode < sb->s_inodes_count) {
                int bit = get_inode_bitmap(bitmap, entry->inode);

                if (bit == 1) {
                    set_inode_bitmap(bitmap, entry->inode, 0);
                }
            }

            if (DEBUG) print_dir_entry(entry);

            // Recursive traver non "."/ ".." dirtories
            if (entry_num > 1 && entry->file_type == 2) {
                find_unreferenced_inodes(part_start_offset, sb, inode_table, bitmap, entry->inode);
            }

            start_offset += entry->rec_len;

            if (start_offset >= blk_size) {
                break;
            }

            entry_num++;
        }
    }
}

void find_unreferenced_inodes_step2(int part_start_offset, struct ext2_super_block *sb,
        struct ext2_inode *inode_table, unsigned char *bitmap, int inode_num) {
    struct ext2_inode root_inode;
    //root_inode = ((struct ext2_inode *) inode_table)[inode_num - 1];
    root_inode = inode_table[inode_num - 1];
    int blk_cnt = root_inode.i_blocks;
    int blk_size = 1024;

    struct ext2_dir_entry_2 *entry;
    unsigned char blk_buf[blk_size];

    if (DEBUG) printf("inode num: %d\n", inode_num);
    if (DEBUG) printf("block_cnt: %d\n", blk_cnt);
    if (DEBUG) printf("start block: %d\n", root_inode.i_block[0]);

    for (int i = 0; i < EXT2_N_BLOCKS; i++) {
        // Read data block.
        read_sectors(part_start_offset + root_inode.i_block[i] * 2, 2, blk_buf);

        // Traverse dir entries.
        int start_offset = 0;
        int entry_num = 0;

        entry = (struct ext2_dir_entry_2 *) (blk_buf + start_offset);


        if (entry->name_len == 0) {
            break;
        }

        while (1) {
            entry = (struct ext2_dir_entry_2 *) (blk_buf + start_offset);

            if (entry->rec_len == 0 || entry->rec_len + start_offset >
                    blk_size) {
                break;
            }

            if (entry_num > 1 && get_inode_bitmap(bitmap, entry->inode) == 1) {
                set_inode_bitmap(bitmap, entry->inode, 0);
            }

            if (DEBUG) print_dir_entry(entry);

            // Recursive traver non "."/ ".." dirtories
            if (entry_num > 1 && entry->file_type == 2) {
                find_unreferenced_inodes_step2(part_start_offset, sb,
                        inode_table,  bitmap, entry->inode);
            }

            start_offset += entry->rec_len;

            if (start_offset >= blk_size) {
                break;
            }

            entry_num++;
        }
    }
}

int convert_inode_mode_to_dir_type(struct ext2_inode inode) {
    int value = (int) (inode.i_mode >> 12);

    switch (value) {
        case 1:
            return 5;
        case 2:
            return 3;
        case 4:
            return 2;
        case 6:
            return 4;
        case 8:
            return 1;
        case 10:
            return 7;
        case 12:
            return 6;
        default:
            break;
    }

    return -1;
}

void check_unreferenced_inodes(int part_start_offset) {
    // Find unreferenced inodes
    // Place in /lost+found
    // Name of new entry is inode number

    // Read super block
    struct ext2_super_block *sb;
    sb = (struct ext2_super_block *) malloc(sizeof(struct ext2_super_block));
    read_super_blk(part_start_offset, sb);

    // Read inode bitmap
    unsigned char *inode_bitmap;
    inode_bitmap = (unsigned char *) malloc((sb->s_inodes_count + 7) / 8);
    create_inode_bitmap(part_start_offset, sb, inode_bitmap);

    // Read inode table
    struct ext2_inode *inode_table;
    inode_table = (struct ext2_inode *) malloc(sb->s_inodes_count *  sizeof
            (struct ext2_inode));
    create_inode_table(part_start_offset, sb, inode_table);

    find_unreferenced_inodes(part_start_offset, sb, inode_table, inode_bitmap, 2);

    for (int i = 0; i < sb->s_inodes_count; i++) {
        int bit = get_inode_bitmap(inode_bitmap, i + 1);
        if (bit == 1 && i + 1 > 10) {
            find_unreferenced_inodes_step2(part_start_offset, sb, inode_table, inode_bitmap, i + 1);
        }
    }

    // Insert into lost+found
    int root_inode = 2;
    //root_inode = ((struct ext2_inode *) inode_table)[inode_num - 1];
    int blk_size = 1024;

    struct ext2_dir_entry_2 *entry;
    unsigned char blk_buf[blk_size];
    struct ext2_dir_entry_2 lost_found_entry;

    for (int i = 0; i < EXT2_N_BLOCKS; i++) {
        // Read data block.
        read_sectors(part_start_offset + inode_table[root_inode - 1].i_block[i] * 2, 2, blk_buf);

        int exit = 0;
        // Traverse dir entries.
        int start_offset = 0;
        int entry_num = 0;

        entry = (struct ext2_dir_entry_2 *) (blk_buf + start_offset);


        if (entry->name_len == 0) {
            break;
        }

        while (1) {
            entry = (struct ext2_dir_entry_2 *) (blk_buf + start_offset);

            if (entry->rec_len == 0 || entry->rec_len + start_offset > blk_size) {
                break;
            }

            //print_dir_entry(entry);

            if (entry->inode > 0 && entry->file_type == 2 &&
                    !strcmp(entry->name, "lost+found")) {
                lost_found_entry = *entry;
                break;
            }

            start_offset += entry->rec_len;

            if (start_offset >= blk_size) {
                break;
            }

            entry_num++;
        }
    }

    // Get the last entry.
    int entry_offset = inode_table[lost_found_entry.inode - 1].i_block[0];
    read_sectors(part_start_offset + entry_offset * 2, 2, blk_buf);
    int offset = 0;

    entry = (struct ext2_dir_entry_2 *) (blk_buf + offset);

    while (offset + entry->rec_len < blk_size) {
        entry = (struct ext2_dir_entry_2 *) (blk_buf + offset);

        offset += entry->rec_len;
    }

    offset -= entry->rec_len;
    // Insert new entry
    for (int i = 0; i < sb->s_inodes_count; i++) {
        int bit = get_inode_bitmap(inode_bitmap, i + 1);
        if (bit == 1 && i + 1 > 10) {
            printf("unreferenced inode %d\n", i + 1);

            entry->rec_len = EXT2_DIR_REC_LEN(entry->name_len);

            offset += entry->rec_len;

            char str[1024];

            struct ext2_dir_entry_2 newEntry;

            newEntry.inode = i + 1;
            sprintf(str, "%d", i + 1);
            strcpy(newEntry.name, str);
            newEntry.name_len = strlen(newEntry.name);

            newEntry.file_type = convert_inode_mode_to_dir_type(inode_table[newEntry.inode - 1]);
            newEntry.rec_len = blk_size - offset;

            entry = (struct ext2_dir_entry_2 *) (blk_buf + offset);

            memcpy(blk_buf + offset, &newEntry, EXT2_DIR_REC_LEN(newEntry.name_len));
        }
    }

    write_sectors(part_start_offset + entry_offset * 2, 2, blk_buf);

    free(inode_bitmap);
    free(inode_table);
    free(sb);
}


void write_inode_link(int part_start_offset,
        struct ext2_super_block *sb, int inode, int value) {

    int block_size = 1024;
    int group_cnt = (sb->s_inodes_count + sb->s_inodes_per_group - 1) / sb->s_inodes_per_group;
    int group_desc_size = sizeof(struct ext2_group_desc);
    int group_desc_offset;

    int group_num = (inode - 1) / sb->s_inodes_per_group;
    int inode_num = (inode - 1) % sb->s_inodes_per_group;

    // Size of all group descs.
    int total_size = group_cnt * group_desc_size;
    int size = (total_size + sector_size_bytes - 1) / sector_size_bytes * sector_size_bytes;

    // Size of all inodes in the group.
    int total_size1 = sb->s_inodes_per_group * sizeof(struct ext2_inode);
    int size1 = (total_size1 + sector_size_bytes - 1) / sector_size_bytes * sector_size_bytes;

    unsigned char buf[size];
    int inode_cur_offset = 0;

    read_sectors(part_start_offset + (SUPER_BLK_OFFSET + SUPER_BLK_SIZE) /
            sector_size_bytes, size / sector_size_bytes, buf);

    // Read next group desc
    struct ext2_group_desc *group_desc = (struct ext2_group_desc *)
            (buf + group_num * sizeof(struct ext2_group_desc));

    int inode_table_offset = group_desc->bg_inode_table;

    unsigned char inode_buf[size1];
    read_sectors(part_start_offset + inode_table_offset * block_size / sector_size_bytes,
            size1 / sector_size_bytes, inode_buf);

    struct ext2_inode *inode_tmp = (struct ext2_inode *) inode_buf;
    inode_tmp[inode_num].i_links_count = value;


    write_sectors(part_start_offset + inode_table_offset * block_size / sector_size_bytes,
            size1 / sector_size_bytes, inode_buf);
}


void traverse_dir_count_link(int part_start_offset, int pInt[], struct ext2_inode *inode_table,
        struct ext2_super_block *sb, int inode_num) {
    struct ext2_inode root_inode;
    //root_inode = ((struct ext2_inode *) inode_table)[inode_num - 1];
    int blk_size = 1024;

    struct ext2_dir_entry_2 *entry;
    unsigned char blk_buf[blk_size];

    for (int i = 0; i < EXT2_N_BLOCKS; i++) {
        // Read data block.
        read_sectors(part_start_offset + inode_table[inode_num - 1].i_block[i] * 2, 2, blk_buf);

        // Traverse dir entries.
        int start_offset = 0;
        int entry_num = 0;

        entry = (struct ext2_dir_entry_2 *) (blk_buf + start_offset);

        if (entry->name_len == 0) {
            break;
        }

        while (1) {
            entry = (struct ext2_dir_entry_2 *) (blk_buf + start_offset);

            if (entry->rec_len == 0 || entry->rec_len + start_offset > blk_size) {
                break;
            }

            //print_dir_entry(entry);


            if (entry->inode <= sb->s_inodes_count) {
                pInt[entry->inode - 1]++;
            }

            if (DEBUG) print_dir_entry(entry);

            // Recursive traver non "."/ ".." dirtories
            if (entry_num > 1 && entry->file_type == 2) {
                traverse_dir_count_link(part_start_offset, pInt, inode_table, sb, entry->inode);
            }

            start_offset += entry->rec_len;

            if (start_offset >= blk_size) {
                break;
            }

            entry_num++;
        }
    }
}


void count_inode_link(int part_start_offset) {

    struct ext2_super_block *sb;
    sb = (struct ext2_super_block *) malloc(sizeof(struct ext2_super_block));

    read_super_blk(part_start_offset, sb);

    // Create inode table
    struct ext2_inode *inode_table;
    inode_table = (struct ext2_inode *) malloc(sb->s_inodes_count * sizeof(struct ext2_inode));
    create_inode_table(part_start_offset, sb, inode_table);


    int inode_links[sb->s_inodes_count];

    for (int i = 0; i < sb->s_inodes_count; i++) {
        inode_links[i] = 0;
    }

    traverse_dir_count_link(part_start_offset, inode_links, inode_table, sb, 2);

    for (int i = 0; i < sb->s_inodes_count; i++) {
        if ((i + 1) < 2) {
            continue;
        }

        if (inode_table[i].i_links_count != inode_links[i]) {
            printf("Error inode link count, inode %d %d -> %d\n", i + 1, inode_table[i].i_links_count, inode_links[i]);
            write_inode_link(part_start_offset, sb, i + 1, inode_links[i]);
        }
    }

    free(sb);
    free(inode_table);
}

//----------------------------------------------------------------
// Create inode table from all block groups.
void create_blk_bitmap(int part_start_offset,
        struct ext2_super_block *sb, unsigned char *blk_bitmap) {

    int block_size = 1024;

    int group_cnt = (sb->s_blocks_count + sb->s_blocks_per_group - 1) / sb->s_blocks_per_group;

    int group_desc_size = sizeof(struct ext2_group_desc);
    int group_desc_offset;

    // Size of all group descs.
    int total_size = group_cnt * group_desc_size;
    int size = (total_size + sector_size_bytes - 1) / sector_size_bytes * sector_size_bytes;

    // Size of all blocks in the group.
    int total_size1 = sb->s_blocks_per_group / 8;
    int size1 = (total_size1 + sector_size_bytes - 1) / sector_size_bytes * sector_size_bytes;

    unsigned char buf[size];
    int cur_offset = 0;

    read_sectors(part_start_offset + (SUPER_BLK_OFFSET + SUPER_BLK_SIZE) /
            sector_size_bytes, size / sector_size_bytes, buf);


    for (int i = 0; i < group_cnt; i++) {
        // Read next group desc
        struct ext2_group_desc *group_desc = (struct ext2_group_desc *) (buf + i * sizeof(struct ext2_group_desc));

        int blk_bitmap_offset = group_desc->bg_block_bitmap;

        unsigned char buf_cpy[size1];

        read_sectors(part_start_offset + blk_bitmap_offset * block_size / sector_size_bytes,
                size1 / sector_size_bytes, buf_cpy);

        memcpy(blk_bitmap + cur_offset, buf_cpy, total_size1);

        cur_offset += total_size1;
    }
}

void write_blk_bitmap(int part_start_offset,
        struct ext2_super_block *sb, unsigned char *blk_bitmap) {

    int block_size = 1024;

    int group_cnt = (sb->s_blocks_count + sb->s_blocks_per_group - 1) / sb->s_blocks_per_group;

    int group_desc_size = sizeof(struct ext2_group_desc);
    int group_desc_offset;

    // Size of all group descs.
    int total_size = group_cnt * group_desc_size;
    int size = (total_size + sector_size_bytes - 1) / sector_size_bytes * sector_size_bytes;

    // Size of all blocks in the group.
    int total_size1 = sb->s_blocks_per_group / 8;
    int size1 = (total_size1 + sector_size_bytes - 1) / sector_size_bytes * sector_size_bytes;

    unsigned char buf[size];
    int cur_offset = 0;

    read_sectors(part_start_offset + (SUPER_BLK_OFFSET + SUPER_BLK_SIZE) /
            sector_size_bytes, size / sector_size_bytes, buf);


    for (int i = 0; i < group_cnt; i++) {
        // Read next group desc
        struct ext2_group_desc *group_desc = (struct ext2_group_desc *) (buf + i * sizeof(struct ext2_group_desc));

        int blk_bitmap_offset = group_desc->bg_block_bitmap;

        unsigned char buf_cpy[size1];

        write_sectors(part_start_offset + blk_bitmap_offset * block_size / sector_size_bytes,
                size1 / sector_size_bytes, blk_bitmap + cur_offset);

        cur_offset += total_size1;
    }
}

int get_blk_bitmap(unsigned char *bitmap, int num) {
    num = num - 1;

    unsigned char value = bitmap[num / 8];

    int cnt = num % 8;

    return (value >> cnt) & 1;
}

int set_blk_bitmap(unsigned char *bitmap, int num, int val) {
    num = num - 1;

    int cnt = num % 8;
    int mask = ~(1 << cnt);

    bitmap[num / 8] = (bitmap[num / 8] & mask) | (val << cnt);
}

void read_group_desc(int part_start_offset, struct ext2_super_block *sb, struct ext2_group_desc *group_desc) {
    int group_cnt = (sb->s_blocks_count + sb->s_blocks_per_group - 1) / sb->s_blocks_per_group;

    int group_desc_size = sizeof(struct ext2_group_desc);

    // Size of all group descs.
    int total_size = group_cnt * group_desc_size;
    int size = (total_size + sector_size_bytes - 1) / sector_size_bytes * sector_size_bytes;

    unsigned char buf[size];

    read_sectors(part_start_offset + (SUPER_BLK_OFFSET + SUPER_BLK_SIZE) /
            sector_size_bytes, size / sector_size_bytes, buf);

    memcpy(group_desc, buf, group_desc_size * group_cnt);
}

int has_super_block(int group_num) {
    // 0 1 3 5 7
    int val = group_num;

    if (group_num == 0 || group_num == 1) {
        return 1;
    }

    while (val > 0) {
        if (val % 3 == 0) {
            return 1;
        }

        val /= 3;
    }

    val = group_num;
    while (val > 0) {
        if (val % 5 == 0) {
            return 1;
        }

        val /= 5;
    }

    val = group_num;
    while (val > 0) {
        if (val % 7 == 0) {
            return 1;
        }

        val /= 7;
    }

    return 0;
}

void tracerse_entries(int *cur_cnt, int *blk_num, unsigned char *tmp_bitmap, int part_start_offset, int block_num) {
    int blk_size = 1024;

    *blk_num -= *cur_cnt;
    *cur_cnt = 0;

    int blk_buf[blk_size];

    set_blk_bitmap(tmp_bitmap, block_num, 1);

    read_sectors(part_start_offset + block_num * blk_size / sector_size_bytes, blk_size / sector_size_bytes, blk_buf);

    while (*cur_cnt < *blk_num && *cur_cnt < 256) {
        int num = blk_buf[*cur_cnt];

        set_blk_bitmap(tmp_bitmap, num, 1);

        (*cur_cnt)++;
    }

    *blk_num -= *cur_cnt;
    *cur_cnt = 0;
}

void traverse_file_blk(int part_start_offset, unsigned char *tmp_bitmap, struct ext2_inode *inode_table,
        struct ext2_super_block *sb, int inode_num, int file_type) {
    struct ext2_inode root_inode;

    //root_inode = ((struct ext2_inode *) inode_table)[inode_num - 1];
    int blk_size = 1024;
    int blk_buf[blk_size / sizeof(int)];
    struct ext2_dir_entry_2 *entry;

    int blk_num = (inode_table[inode_num - 1].i_size + blk_size - 1) / blk_size;

    if (inode_table[inode_num - 1].i_size < 60 && file_type == 7) {
        return;
    }

    int cur_cnt = 0;

    // Mark data blocks.
    for (cur_cnt = 0; cur_cnt < 12 && cur_cnt < blk_num; cur_cnt++) {
        set_blk_bitmap(tmp_bitmap, inode_table[inode_num - 1].i_block[cur_cnt], 1);
    }


    tracerse_entries(&cur_cnt, &blk_num, tmp_bitmap, part_start_offset, inode_table[inode_num - 1].i_block[12]);


    if (cur_cnt < blk_num) {

        set_blk_bitmap(tmp_bitmap, inode_table[inode_num - 1].i_block[13], 1);

        read_sectors(part_start_offset + inode_table[inode_num - 1].i_block[13] * blk_size / sector_size_bytes, blk_size / sector_size_bytes, blk_buf);

        int cnt = 0;
        while (cur_cnt < blk_num) {
            tracerse_entries(&cur_cnt, &blk_num, tmp_bitmap, part_start_offset, blk_buf[cnt]);

            cnt++;
        }
    }

    if (file_type != 2) {
        return;
    }

    int entry_num = 0;

    for (int i = 0; i < EXT2_N_BLOCKS; i++) {
        // Read data block.
        unsigned char sect_buf[blk_size];
        read_sectors(part_start_offset + inode_table[inode_num - 1].i_block[i] * 2, 2, sect_buf);

        // Traverse dir entries.
        int start_offset = 0;

        entry = (struct ext2_dir_entry_2 *) (sect_buf + start_offset);

        if (entry->name_len == 0) {
            break;
        }

        while (1) {
            entry = (struct ext2_dir_entry_2 *) (sect_buf + start_offset);

            if (entry->rec_len == 0 || entry->rec_len + start_offset > blk_size) {
                break;
            }

            // Recursive traver non "."/ ".." dirtories
            if (entry_num > 1) {
                traverse_file_blk(part_start_offset, tmp_bitmap, inode_table, sb, entry->inode, entry->file_type);
            }

            start_offset += entry->rec_len;

            if (start_offset >= blk_size) {
                break;
            }

            entry_num++;
        }
    }
}

void block_allocation(int part_start_offset) {
    struct ext2_super_block *sb;
    unsigned char *blk_bitmap, *tmp_bitmap;
    struct ext2_group_desc *group_descs;
    struct ext2_inode *inode_table;

    sb = (struct ext2_super_block *) malloc(sizeof(struct ext2_super_block));
    read_super_blk(part_start_offset, sb);

    // Get all group descripetors
    int blk_size = 1024;
    int group_cnt = (sb->s_blocks_count + sb->s_blocks_per_group - 1) / sb->s_blocks_per_group;
    int group_desc_size = sizeof(struct ext2_group_desc);

    int inode_bitmap_block_size = (sb->s_inodes_per_group / 8 + blk_size - 1) / blk_size;
    int blk_bitmap_block_size = (sb->s_blocks_per_group / 8 + blk_size - 1) / blk_size;
    int inode_table_block_size = (sb->s_inodes_per_group * sizeof(struct ext2_inode) + blk_size - 1) / blk_size;

    inode_table = (struct ext2_inode *) malloc(sb->s_inodes_count * sizeof(struct ext2_inode));
    group_descs = (struct ext2_group_desc *) malloc(group_cnt * group_desc_size);
    blk_bitmap = (unsigned char *) malloc((sb->s_blocks_per_group / 8) * group_cnt);

    tmp_bitmap = (unsigned char *) malloc((sb->s_blocks_per_group / 8) * group_cnt);

    read_group_desc(part_start_offset, sb, group_descs);
    create_inode_table(part_start_offset, sb, inode_table);

    create_blk_bitmap(part_start_offset, sb, blk_bitmap);
    memset(tmp_bitmap, 0, (sb->s_blocks_count + 7) / 8);

    int cnt1 = 0;
    int cnt2 = 0;


    // Mark Super Blocks
    // 0 1 3 5 7
    for (int i = 0; i < group_cnt; i++) {
        struct ext2_group_desc desc = group_descs[i];

        // Mark blk bitmap
        for (int j = 0; j < blk_bitmap_block_size; j++) {
            set_blk_bitmap(tmp_bitmap, desc.bg_block_bitmap + j, 1);
        }

        // Mark inode bitmap
        for (int j = 0; j < inode_bitmap_block_size; j++) {
            set_blk_bitmap(tmp_bitmap, desc.bg_inode_bitmap + j, 1);
        }

        // Mark inode table
        for (int j = 0; j < inode_table_block_size; j++) {
            set_blk_bitmap(tmp_bitmap, desc.bg_inode_table + j, 1);
        }

        if (has_super_block(i)) {
            set_blk_bitmap(tmp_bitmap, desc.bg_block_bitmap - 1, 1);
            set_blk_bitmap(tmp_bitmap, desc.bg_block_bitmap - 2, 1);
        }

    }


    // Mark data block.
    traverse_file_blk(part_start_offset, tmp_bitmap, inode_table, sb, 2, 2);

    for (int i = 0; i < sb->s_blocks_count - 1; i++) {
        int val1 = get_blk_bitmap(blk_bitmap, i + 1);
        int val2 = get_blk_bitmap(tmp_bitmap, i + 1);

        if (val1 != val2) {
            printf("error block: [%d] %d, %d\n", i + 1, val1, val2);
            set_blk_bitmap(blk_bitmap, i + 1, val2);
        }
    }

    write_blk_bitmap(part_start_offset, sb, blk_bitmap);

//    free(blk_bitmap);
//    free(tmp_bitmap);
    free(group_descs);
    free(inode_table);
}

void fsck(int part_start_offset) {
    // Pass1
    printf("Pass 1:\n");
    struct ext2_group_desc gd;
    read_blk_group_desc(part_start_offset, &gd);

    // Pass2
    printf("Pass 2:\n");
    check_unreferenced_inodes(part_start_offset);
    read_blk_group_desc(part_start_offset, &gd);

    // Pass3
    printf("Pass 3:\n");
    count_inode_link(part_start_offset);

    // Pass4
    printf("Pass 4:\n");
    block_allocation(part_start_offset);
}

int main(int argc, char **argv) {
    int partition_num;
    char disk_name[1024];
    int mode = 1;

    int opt = -1;

    while ((opt = getopt(argc, argv, ":p:f:i:")) != -1) {
        switch (opt) {
            case 'p':
                mode = 1;
                partition_num = atoi(optarg);
                break;
            case 'f':
                mode = 2;
                partition_num = atoi(optarg);
                break;
            case 'i':
                strcpy(disk_name, argv[optind - 1]);
                break;
            case ':':
                exit(-1);
            default:
                exit(-1);
        }
    }

    if ((device = open(disk_name, O_RDWR)) == -1) {
        perror("Could not open device file");
        exit(-1);
    }

    if (mode == 1) {
        struct partition part = read_partition(partition_num);

        if (part.start_sect == -1) {
            printf("-1\n");
        } else {
            printf("0x%02X %d %d\n", part.sys_ind, part.start_sect, part.nr_sects);

        }
    } else {
        if (partition_num == 0) {
            int num = 1;
            while (1) {
                struct partition part = read_partition(num);

                if (part.start_sect == -1) {
                    break;
                } else if (part.sys_ind == 0x83) { // EXT2
                    fsck(part.start_sect);
                }

                num++;
            }
        } else {
            struct partition part = read_partition(partition_num);
            int part_start_offset = part.start_sect;

            fsck(part_start_offset);
        }
    }

    close(device);
    return 0;
}
