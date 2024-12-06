#include "fat32.h"

void print_info() {
    unsigned int total_clusters = (bpb.TotSec32 - (bpb.RsvdSecCnt + (bpb.NumFATs * bpb.FATSz32))) / bpb.SecPerClus;
    unsigned int size_of_image = bpb.TotSec32 * bpb.BytsPerSec;

    printf("Position of Root Cluster (in cluster #): %u\n", bpb.RootClus);
    printf("Bytes Per Sector: %u\n", bpb.BytsPerSec);
    printf("Sectors Per Cluster: %u\n", bpb.SecPerClus);
    printf("Total Clusters in Data Region: %u\n", total_clusters);
    printf("Number of Entries in One FAT: %u\n", bpb.FATSz32);
    printf("Size of Image: %u bytes\n", size_of_image);
}

void ls() {
    uint32_t current_cluster = current_directory_cluster;
    int dots_printed = 0;

    while (1) {
        seek_to_cluster(current_cluster);

        DirectoryEntry dir;
        while (fread(&dir, sizeof(DirectoryEntry), 1, fp) == 1) {
            if (dir.DIR_Name[0] == 0x00) {
                break;
            }
            if (dir.DIR_Name[0] == 0xE5 || (dir.DIR_Attr & 0x0F) == 0x0F) {
                continue;
            }

            char name[12];
            get_directory_entry_name(&dir, name);

            if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
                if (dots_printed == 2) {
                    continue;
                }
                dots_printed += 1;
            }

            if (dir.DIR_Attr & ATTR_DIRECTORY) {
                //print codes are to print directories in blue like example
                printf("\x1b[34m%s\x1b[0m\n", name);
            } else {
                printf("%s\n", name);
            }
        }

        uint32_t fat_offset = current_cluster * 4;
        uint32_t fat_sector = bpb.RsvdSecCnt + (fat_offset / bpb.BytsPerSec);
        uint32_t fat_offset_within_sector = fat_offset % bpb.BytsPerSec;

        fseek(fp, fat_sector * bpb.BytsPerSec + fat_offset_within_sector, SEEK_SET);
        fread(&current_cluster, sizeof(uint32_t), 1, fp);

        if (current_cluster >= EOC) {
            break;
        }
    }
}

int exit_shell() {
    if (fp != NULL) {
        fclose(fp);
    }
    printf("exiting\n");
    return 1;
}

void cd(char *dirname) {
    if (strcmp(dirname, ".") == 0) {
        return;
    }

    if (strcmp(dirname, "..") == 0) {
        if (current_directory_cluster == bpb.RootClus) {
            strcpy(current_path, "/");
            return;
        }

        uint32_t first_sector = cluster_to_sector(current_directory_cluster);
        uint32_t byte_offset = first_sector * bpb.BytsPerSec;
        fseek(fp, byte_offset, SEEK_SET);

        DirectoryEntry dir;
        while (fread(&dir, sizeof(DirectoryEntry), 1, fp) == 1) {
            if (strncmp((char *)dir.DIR_Name, "..", 2) == 0 && (dir.DIR_Attr & ATTR_DIRECTORY)) {
                uint32_t parent_cluster = ((uint32_t)dir.DIR_FstClusHI << 16) | dir.DIR_FstClusLO;

                if (parent_cluster == 0) {
                    current_directory_cluster = bpb.RootClus;
                    strcpy(current_path, "/");
                } else {
                    current_directory_cluster = parent_cluster;

                    if (strcmp(current_path, "/") != 0) {
                        char *last_slash = strrchr(current_path, '/');
                        if (last_slash != NULL && last_slash != current_path) {
                            *last_slash = '\0';
                        } else {
                            strcpy(current_path, "/");
                        }
                    }
                }
                return;
            }
        }
        return;
    }

    uint32_t first_sector = cluster_to_sector(current_directory_cluster);
    uint32_t byte_offset = first_sector * bpb.BytsPerSec;
    fseek(fp, byte_offset, SEEK_SET);

    DirectoryEntry dir;
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
            if (dir.DIR_Attr & ATTR_DIRECTORY) {
                current_directory_cluster = ((uint32_t)dir.DIR_FstClusHI << 16) | dir.DIR_FstClusLO;

                if (strcmp(current_path, "/") == 0) {
                    snprintf(current_path, sizeof(current_path), "/%s", name);
                } else {
                    snprintf(current_path + strlen(current_path), sizeof(current_path) - strlen(current_path), "/%s", name);
                }
                return;
            }
        }
    }
}
