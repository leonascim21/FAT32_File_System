#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

FILE *fp;
char image_name[256];
uint32_t current_directory_cluster;
char current_path[256] = "/";

#define ATTR_DIRECTORY 0x10
#define ATTR_ARCHIVE 0x20
#define EOC 0x0FFFFFF8

typedef struct __attribute__((packed)) {
    uint8_t jumpBoot[3];
    uint8_t OEMName[8];
    uint16_t BytsPerSec;
    uint8_t SecPerClus;
    uint16_t RsvdSecCnt;
    uint8_t NumFATs;
    uint16_t RootEntCnt;
    uint16_t TotSec16;
    uint8_t Media;
    uint16_t FATSz16;
    uint16_t SecPerTrk;
    uint16_t NumHeads;
    uint32_t HiddSec;
    uint32_t TotSec32;
    uint32_t FATSz32;
    uint16_t ExtFlags;
    uint16_t FSVer;
    uint32_t RootClus;
    uint16_t FSInfo;
    uint16_t BkBootSec;
    uint8_t Reserved[12];
    uint8_t DrvNum;
    uint8_t Reserved1;
    uint8_t BootSig;
    uint32_t VolID;
    uint8_t VolLab[11];
    uint8_t FilSysType[8];
} BPB;

typedef struct __attribute__((packed)) {
    uint8_t DIR_Name[11];
    uint8_t DIR_Attr;
    uint8_t DIR_NTRes;
    uint8_t DIR_CrtTimeTenth;
    uint16_t DIR_CrtTime;
    uint16_t DIR_CrtDate;
    uint16_t DIR_LstAccDate;
    uint16_t DIR_FstClusHI;
    uint16_t DIR_WrtTime;
    uint16_t DIR_WrtDate;
    uint16_t DIR_FstClusLO;
    uint32_t DIR_FileSize;
} DirectoryEntry;

BPB bpb;

void read_bpb() {
    fseek(fp, 0, SEEK_SET);
    fread(&bpb, sizeof(BPB), 1, fp);
}

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

uint32_t cluster_to_sector(uint32_t cluster) {
    return ((cluster - 2) * bpb.SecPerClus) + (bpb.RsvdSecCnt + (bpb.NumFATs * bpb.FATSz32));
}

void ls() {
    uint32_t current_cluster = current_directory_cluster;
    int dots_printed = 0;

    while (1) {
        uint32_t first_sector = cluster_to_sector(current_cluster);
        uint32_t byte_offset = first_sector * bpb.BytsPerSec;
        fseek(fp, byte_offset, SEEK_SET);

        DirectoryEntry dir;
        while (fread(&dir, sizeof(DirectoryEntry), 1, fp) == 1) {
            if (dir.DIR_Name[0] == 0x00) {
                break;
            }
            if (dir.DIR_Name[0] == 0xE5 || (dir.DIR_Attr & 0x0F) == 0x0F) {
                continue;
            }

            char name[12];
            memcpy(name, dir.DIR_Name, 11);
            name[11] = '\0';
            for (int i = 10; i >= 0; i--) {
                if (name[i] == ' ') {
                    name[i] = '\0';
                } else {
                    break;
                }
            }

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
        memcpy(name, dir.DIR_Name, 11);
        name[11] = '\0';
        for (int i = 10; i >= 0; i--) {
            if (name[i] == ' ') {
                name[i] = '\0';
            } else {
                break;
            }
        }

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

uint32_t find_free_cluster() {
    uint32_t fat_offset, fat_value;
    for (uint32_t cluster = 2; cluster < (bpb.TotSec32 / bpb.SecPerClus); cluster++) {
        fat_offset = cluster * 4;
        uint32_t fat_sector = bpb.RsvdSecCnt + (fat_offset / bpb.BytsPerSec);
        uint32_t fat_offset_within_sector = fat_offset % bpb.BytsPerSec;

        fseek(fp, fat_sector * bpb.BytsPerSec + fat_offset_within_sector, SEEK_SET);
        fread(&fat_value, sizeof(uint32_t), 1, fp);
        fat_value &= 0x0FFFFFFF;

        if (fat_value == 0x00000000) {
            return cluster;
        }
    }
    return 0;
}

void allocate_cluster(uint32_t cluster, uint32_t value) {
    uint32_t fat_offset = cluster * 4;
    uint32_t fat_sector = bpb.RsvdSecCnt + (fat_offset / bpb.BytsPerSec);
    uint32_t fat_offset_within_sector = fat_offset % bpb.BytsPerSec;

    fseek(fp, fat_sector * bpb.BytsPerSec + fat_offset_within_sector, SEEK_SET);
    fwrite(&value, sizeof(uint32_t), 1, fp);
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
        memcpy(name, dir.DIR_Name, 11);
        name[11] = '\0';
        for (int i = 10; i >= 0; i--) {
            if (name[i] == ' ') {
                name[i] = '\0';
            } else {
                break;
            }
        }

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

void creat(char *filename) {
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
        memcpy(name, dir.DIR_Name, 11);
        name[11] = '\0';
        for (int i = 10; i >= 0; i--) {
            if (name[i] == ' ') {
                name[i] = '\0';
            } else {
                break;
            }
        }

        if (strcmp(name, filename) == 0) {
            printf("File with same name already exists\n");
            return;
        }
    }

    fseek(fp, byte_offset, SEEK_SET);
    while (fread(&dir, sizeof(DirectoryEntry), 1, fp) == 1) {
        if (dir.DIR_Name[0] == 0x00 || dir.DIR_Name[0] == 0xE5) {
            memset(&dir, 0, sizeof(DirectoryEntry));
            memset(dir.DIR_Name, ' ', 11);
            strncpy((char *)dir.DIR_Name, filename, strlen(filename));
            dir.DIR_Attr = ATTR_ARCHIVE;
            dir.DIR_FstClusHI = 0;
            dir.DIR_FstClusLO = 0;
            dir.DIR_FileSize = 0;

            fseek(fp, -sizeof(DirectoryEntry), SEEK_CUR);
            fwrite(&dir, sizeof(DirectoryEntry), 1, fp);
            return;
        }
    }
}

int main(int argc, char *argv[]) {
    //error checking for if more than 1 arg is provided when running program
    if (argc != 2) {
        printf("Only argument should be image file\n");
        return 1;
    }

    strncpy(image_name, argv[1], 256);
    fp = fopen(image_name, "rb+");
    if (fp == NULL) {
        perror("Failed to open image file");
        return 1;
    }

    read_bpb();
    current_directory_cluster = bpb.RootClus;

    int exit = 0;
    char command[256];
    while (!exit) {
        printf("%s%s> ", image_name, current_path);
        fgets(command, sizeof(command), stdin);

        command[strcspn(command, "\n")] = 0;

        if (strcmp(command, "info") == 0) {
            print_info();
        } else if (strcmp(command, "exit") == 0) {
            exit = exit_shell();
        } else if (strcmp(command, "ls") == 0) {
            ls();
        } else if (strncmp(command, "cd ", 3) == 0) {
            cd(command + 3);
        } else if (strncmp(command, "mkdir ", 6) == 0) {
            mkdir(command + 6);
        } else if (strncmp(command, "creat ", 6) == 0) {
            creat(command + 6);
        } else {
            printf("Unknown command\n");
        }
    }
    return 0;
}
