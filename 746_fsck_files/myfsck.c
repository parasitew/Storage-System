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

    for (int i = 0; i < 3; i++) {
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


//----------------------------------------
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
        printf("off: %d\n", inode_bitmap_offset);
        unsigned char buf[size1];
        read_sectors(part_start_offset + inode_bitmap_offset * block_size / sector_size_bytes,
                1, buf);

        memcpy(inode_bitmap + cur_offset, buf, total_size1);

        printf("\n---\n");
        cur_offset += total_size1;
    }


    void read_partition() {
        struct partition *part_buf;
        unsigned char buf[sector_size_bytes];
        int start_sect;
        int base_sect;
        int part_type;

        // Read the first sector
        read_sectors(0, 1, buf);

        // Read first 4 partitions
        for (int i = 0; i < 4; i++) {
            part_buf = (struct partition *) (buf + MBR_OFFSET + i * sizeof(struct partition));

            start_sect = part_buf->start_sect;
            base_sect = part_buf->start_sect;
            part_type = part_buf->sys_ind;

            printf("0x%02X %d %d\n", part_buf->sys_ind, part_buf->start_sect, part_buf->nr_sects);

            while (i == 4 || part_type == PART_TYPE_EXT) {
                read_sectors(start_sect, 1, buf);

                part_buf = (struct partition *) (buf + MBR_OFFSET + 0 * sizeof(struct partition));

                if (part_buf->sys_ind != PART_TYPE_UNUSED) {
                    printf("0x%02X %d %d\n", part_buf->sys_ind, part_buf->start_sect + base_sect, part_buf->nr_sects);
                } else {
                    break;
                }

                part_buf = (struct partition *) (buf + MBR_OFFSET + 1 * sizeof(struct partition));

                if (part_buf->sys_ind != PART_TYPE_UNUSED) {
                    printf("0x%02X %d %d\n", part_buf->sys_ind, part_buf->start_sect + base_sect, part_buf->nr_sects);

                    start_sect = part_buf->start_sect + base_sect;
                    base_sect = part_buf->start_sect + base_sect;
                    part_type = part_buf->sys_ind;
                } else {
                    break;
                }
            }
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

        for (int i = 0; i < EXT2_N_BLOCKS; i++) {

            // Read data block.
            read_sectors(part_start_offset + root_inode.i_block[i] * 2, 2, blk_buf);

            // Traverse dir entries.
            int start_offset = 0;
            int entry_num = 0;
            int flag = 0;
            while (1) {
                entry = (struct ext2_dir_entry_2 *) (blk_buf + start_offset);


                if (entry->rec_len == 0 || entry->rec_len + start_offset > blk_size) {
                    flag = 1;
                    break;
                }

                if (entry_num == 0) {
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

                if (entry_num == 1) {
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
                    flag = 1;
                    break;
                }

                entry_num++;
            }

            write_sectors(part_start_offset + root_inode.i_block[i] * 2, 2, blk_buf);
            if (flag == 1) {
                break;
            }
        }
    }

    void read_blk_group_desc(int part_start_offset, struct ext2_group_desc *group_desc) {
        unsigned char buf[sector_size_bytes];

        read_sectors(part_start_offset + (SUPER_BLK_OFFSET + SUPER_BLK_SIZE) /
                sector_size_bytes, 1, buf);

        memcpy(group_desc, buf, sizeof(struct ext2_group_desc));

        // --------------------
        if (DEBUG) print_group_desc(group_desc);

        struct ext2_super_block *sb;
        sb = (struct ext2_super_block *) malloc(sizeof(struct ext2_super_block));

        read_super_blk(part_start_offset, sb);

        // ----------------------
        if (DEBUG) print_super_block(sb);

        unsigned char inode_buf[1024];

        read_sectors(part_start_offset + 10, 2, inode_buf);

        struct ext2_inode *inode;
        inode = (struct ext2_inode *) malloc(sizeof(struct ext2_inode));
        memcpy(inode, inode_buf + 1 * sizeof(struct ext2_inode), sizeof(struct ext2_inode));
        printf("mode: %x\n", inode->i_mode);
        printf("address to data: %d\n", inode->i_block[0]);

        // Create inode table
        struct ext2_inode *inode_table;
        inode_table = (struct ext2_inode *) malloc(sb->s_inodes_count * sizeof(struct ext2_inode));
        create_inode_table(part_start_offset, sb, inode_table);

        if (DEBUG) print_inode(&inode_table[11]);

        traverse_dir(part_start_offset, inode_table, 2, 2);
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
            int flag = 0;

            while (1) {
                entry = (struct ext2_dir_entry_2 *) (blk_buf + start_offset);

                if (entry->rec_len == 0 || entry->rec_len + start_offset > blk_size) {
                    flag = 1;
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
                    flag = 1;
                    break;
                }

                entry_num++;
            }

            if (flag == 1) {
                break;
            }
        }
    }

    void check_unreferenced_inodes(int part_start_offset) {
        // Find unreferenced inodes
        // Place in /lost+found
        // Name of new entry is inode number

        // Read super block
        struct ext2_super_block *sb;
        sb = (struct ext2_super_block *) malloc(sizeof(struct ext2_super_block));
        read_super_blk(part_start_offset, sb);
        print_super_block(sb);

        // Read inode bitmap
        printf("------------inode bitmap---------\n");
        unsigned char *inode_bitmap;
        inode_bitmap = (unsigned char *) malloc((sb->s_inodes_count + 7) / 8);
        create_inode_bitmap(part_start_offset, sb, inode_bitmap);

        // Read inode table
        struct ext2_inode *inode_table;
        inode_table = (struct ext2_inode *) malloc(sb->s_inodes_count * sizeof(struct ext2_inode));
        create_inode_table(part_start_offset, sb, inode_table);

        find_unreferenced_inodes(part_start_offset, sb, inode_table, inode_bitmap, 2);

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

            int flag = 1;

            while (1) {
                entry = (struct ext2_dir_entry_2 *) (blk_buf + start_offset);

                if (entry->rec_len == 0 || entry->rec_len + start_offset > blk_size) {
                    break;
                }

                //print_dir_entry(entry);

                if (entry->inode > 0 && entry->file_type == 2 &&
                        !strcmp(entry->name, "lost+found")) {
                    lost_found_entry = *entry;
                    exit = 1;
                    break;
                }

                start_offset += entry->rec_len;

                if (start_offset >= blk_size) {
                    break;
                }

                entry_num++;
            }

            if (exit) {
                break;
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
                newEntry.file_type = 2;
                newEntry.rec_len = blk_size - offset;

                entry = (struct ext2_dir_entry_2 *) (blk_buf + offset);

                memcpy(blk_buf + offset, &newEntry, EXT2_DIR_REC_LEN(newEntry.name_len));
            }
        }

        write_sectors(part_start_offset + entry_offset * 2, 2, blk_buf);
    }


    int main(int argc, char **argv) {
        /* This is a sample program.  If you want to print out sector 57 of
         * the disk, then run the program as:
         *
         *    ./readwrite disk 57
         *
         * You'll of course want to replace this with your own functions.
         */

        unsigned char buf[sector_size_bytes];        /* temporary buffer */
        int the_sector;                     /* IN: sector to read */

        if ((device = open(argv[1], O_RDWR)) == -1) {
            perror("Could not open device file");
            exit(-1);
        }

        the_sector = atoi(argv[2]);
        printf("Dumping sector %d:\n", the_sector);
        read_sectors(the_sector, 1, buf);
        //print_sector(buf);
        printf("------------------------------\n");
        // Part 1
        read_partition();

        // Part2
        // Pass1: Directory pointers
        struct ext2_group_desc gd;
        read_blk_group_desc(63, &gd);
        read_blk_group_desc(48195, &gd);
        read_blk_group_desc(112518, &gd);

        // Pass2:
//    check_unreferenced_inodes(63);
//    check_unreferenced_inodes(48195);
//    check_unreferenced_inodes(112518);

        close(device);
        return 0;
    }
}