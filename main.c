#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define BPB_BytsPerSec_OFFSET 11
#define BPB_SecPerClus_OFFSET 13
#define BPB_RootClus_OFFSET 44
#define BPB_FATSz32_OFFSET 36
#define BPB_NumFATs_OFFSET 16
#define BPB_TotSec32_OFFSET 32
#define BPB_RsvdSecCnt_OFFSET 14

FILE *fp;
char image_name[256];
uint32_t current_directory_cluster;

typedef struct __attribute__((packed)) {
    uint16_t BytsPerSec;
    uint8_t SecPerClus;
    uint16_t RsvdSecCnt;
    uint8_t NumFATs;
    uint32_t TotSec32;
    uint32_t FATSz32;
    uint32_t RootClus;
} BPB;

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

int exit_shell() {
    if (fp != NULL) {
        fclose(fp);
    }
    printf("exiting\n");
    return 1;
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
        } else {
            printf("Unknown command\n");
        }
    }
    return 0;
}
