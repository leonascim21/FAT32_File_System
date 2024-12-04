#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

FILE *fp;
char image_name[256];
uint32_t current_directory_cluster;

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

        if (dir.DIR_Attr & 0x10) {
            //print codes are to print directories in blue like example
            printf("\x1b[34m%s \x1b[0m \n", name);
        } else {
            printf("%s\n", name);
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
            return;
        }

        uint32_t first_sector = cluster_to_sector(current_directory_cluster);
        uint32_t byte_offset = first_sector * bpb.BytsPerSec;
        fseek(fp, byte_offset, SEEK_SET);

        DirectoryEntry dir;
        while (fread(&dir, sizeof(DirectoryEntry), 1, fp) == 1) {
            if ((dir.DIR_Attr & 0x10) && strncmp((char *)dir.DIR_Name, "..", 2) == 0) {
                current_directory_cluster = ((uint32_t)dir.DIR_FstClusHI << 16) | dir.DIR_FstClusLO;
                return;
            }
        }
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
            if (dir.DIR_Attr & 0x10) {current_directory_cluster = ((uint32_t)dir.DIR_FstClusHI << 16) | dir.DIR_FstClusLO;
                return;
            }
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
    fp = fopen(image_name, "rb");
    if (fp == NULL) {
        perror("Failed to open image file");
        return 1;
    }

    read_bpb();
    current_directory_cluster = bpb.RootClus;

    int exit = 0;
    char command[256];
    while (!exit) {
        printf("%s/> ", image_name);
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
        } else {
            printf("Unknown command\n");
        }
    }
    return 0;
}
