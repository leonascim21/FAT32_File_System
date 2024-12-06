#include "fat32.h"

void rmdir(char *dirname) {
    uint32_t current_cluster = current_directory_cluster;
    uint32_t dir_cluster = 0;
    uint32_t dir_entry_offset = 0;
    DirectoryEntry dir;
    int found = 0;

    while (1) {
        uint32_t first_sector = cluster_to_sector(current_cluster);
        uint32_t byte_offset = first_sector * bpb.BytsPerSec;
        fseek(fp, byte_offset, SEEK_SET);

        while (fread(&dir, sizeof(DirectoryEntry), 1, fp) == 1) {
            if (dir.DIR_Name[0] == 0x00) {
                break;
            }
            if (dir.DIR_Name[0] == 0xE5) {
                continue;
            }
            if ((dir.DIR_Attr & 0x0F) == 0x0F) {
                continue;
            }

            char name[12];
            get_directory_entry_name(&dir, name);

            if (strcmp(name, dirname) == 0) {
                if (!(dir.DIR_Attr & ATTR_DIRECTORY)) {
                    printf("not a directory.\n");
                    return;
                }
                if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
                    printf("Cannot remove special directories '.' or '..'.\n");
                    return;
                }

                found = 1;
                dir_entry_offset = ftell(fp) - sizeof(DirectoryEntry);
                dir_cluster = ((uint32_t)dir.DIR_FstClusHI << 16) | dir.DIR_FstClusLO;
                break;
            }
        }

        if (found) {
            break;
        }

        uint32_t fat_offset = current_cluster * 4;
        uint32_t fat_sector = bpb.RsvdSecCnt + (fat_offset / bpb.BytsPerSec);
        uint32_t fat_offset_within_sector = fat_offset % bpb.BytsPerSec;

        fseek(fp, fat_sector * bpb.BytsPerSec + fat_offset_within_sector, SEEK_SET);
        fread(&current_cluster, sizeof(uint32_t), 1, fp);
        current_cluster &= 0x0FFFFFFF;

        if (current_cluster >= EOC) {
            break;
        }
    }

    if (!found) {
        printf("Directory not found.\n");
        return;
    }

    uint32_t first_sector = cluster_to_sector(dir_cluster);
    uint32_t byte_offset = first_sector * bpb.BytsPerSec;
    fseek(fp, byte_offset, SEEK_SET);

    while (fread(&dir, sizeof(DirectoryEntry), 1, fp) == 1) {
        if (dir.DIR_Name[0] == 0x00) {
            break;
        }
        if (dir.DIR_Name[0] != 0xE5 && !(dir.DIR_Attr & 0x0F)) {
            char name[12];
            get_directory_entry_name(&dir, name);
            if (strcmp(name, ".") != 0 && strcmp(name, "..") != 0) {
                printf("Directory is not empty.\n");
                return;
            }
        }
    }

    uint32_t cluster = dir_cluster;
    while (cluster < EOC && cluster != 0x0000000) {
        uint32_t fat_offset = cluster * 4;
        uint32_t fat_sector = bpb.RsvdSecCnt + (fat_offset / bpb.BytsPerSec);
        uint32_t fat_offset_within_sector = fat_offset % bpb.BytsPerSec;

        fseek(fp, fat_sector * bpb.BytsPerSec + fat_offset_within_sector, SEEK_SET);
        uint32_t next_cluster;
        fread(&next_cluster, sizeof(uint32_t), 1, fp);
        next_cluster &= 0x0FFFFFFF;

        uint32_t free_value = 0x00000000;
        fseek(fp, fat_sector * bpb.BytsPerSec + fat_offset_within_sector, SEEK_SET);
        fwrite(&free_value, sizeof(uint32_t), 1, fp);

        cluster = next_cluster;
    }

    fseek(fp, dir_entry_offset, SEEK_SET);
    uint8_t deleted_marker = 0xE5;
    fwrite(&deleted_marker, sizeof(uint8_t), 1, fp);
}

void mkdir(char *dirname) {
    uint32_t first_sector = cluster_to_sector(current_directory_cluster);
    uint32_t byte_offset = first_sector * bpb.BytsPerSec;
    fseek(fp, byte_offset, SEEK_SET);

    DirectoryEntry dir;
    uint32_t entry_offset = 0;

    while (fread(&dir, sizeof(DirectoryEntry), 1, fp) == 1) {
        if (dir.DIR_Name[0] == 0x00 || dir.DIR_Name[0] == 0xE5) {
            entry_offset = ftell(fp) - sizeof(DirectoryEntry);
            break;
        }
        if ((dir.DIR_Attr & 0x0F) == 0x0F) {
            continue;
        }

        char name[12];
        get_directory_entry_name(&dir, name);

        if (strcmp(name, dirname) == 0) {
            printf("Directory with same name already exists\n");
            return;
        }
    }

    uint32_t new_cluster = find_free_cluster();
    if (new_cluster == 0) {
        printf("No free cluster available\n");
        return;
    }

    allocate_cluster(new_cluster, EOC);

    DirectoryEntry new_dir = {0};
    memset(new_dir.DIR_Name, ' ', 11);
    strncpy((char *)new_dir.DIR_Name, dirname, strlen(dirname));
    new_dir.DIR_Attr = ATTR_DIRECTORY;
    new_dir.DIR_FstClusHI = (uint16_t)(new_cluster >> 16);
    new_dir.DIR_FstClusLO = (uint16_t)(new_cluster & 0xFFFF);
    new_dir.DIR_FileSize = 0;

    fseek(fp, entry_offset, SEEK_SET);
    if (fwrite(&new_dir, sizeof(DirectoryEntry), 1, fp) != 1) {
        return;
    }

    uint32_t new_cluster_sector = cluster_to_sector(new_cluster);
    uint32_t new_byte_offset = new_cluster_sector * bpb.BytsPerSec;
    fseek(fp, new_byte_offset, SEEK_SET);

    DirectoryEntry dot = {0}, dotdot = {0};
    memset(dot.DIR_Name, ' ', 11);
    memset(dotdot.DIR_Name, ' ', 11);
    dot.DIR_Name[0] = '.';
    dot.DIR_Attr = ATTR_DIRECTORY;
    dot.DIR_FstClusHI = (uint16_t)(new_cluster >> 16);
    dot.DIR_FstClusLO = (uint16_t)(new_cluster & 0xFFFF);

    dotdot.DIR_Name[0] = '.';
    dotdot.DIR_Name[1] = '.';
    dotdot.DIR_Attr = ATTR_DIRECTORY;
    dotdot.DIR_FstClusHI = (uint16_t)(current_directory_cluster >> 16);
    dotdot.DIR_FstClusLO = (uint16_t)(current_directory_cluster & 0xFFFF);

    fwrite(&dot, sizeof(DirectoryEntry), 1, fp);
    fwrite(&dotdot, sizeof(DirectoryEntry), 1, fp);
}