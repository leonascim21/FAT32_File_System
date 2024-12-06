#include "fat32.h"

void read_bpb() {
    fseek(fp, 0, SEEK_SET);
    fread(&bpb, sizeof(BPB), 1, fp);
}

void get_directory_entry_name(DirectoryEntry *dir, char *name) {
    memcpy(name, dir->DIR_Name, 11);
    name[11] = '\0';
    for (int i = 10; i >= 0; i--) {
        if (name[i] == ' ') {
            name[i] = '\0';
        } else {
            break;
        }
    }
}

uint32_t cluster_to_sector(uint32_t cluster) {
    return ((cluster - 2) * bpb.SecPerClus) + (bpb.RsvdSecCnt + (bpb.NumFATs * bpb.FATSz32));
}

void seek_to_cluster(uint32_t cluster) {
    uint32_t first_sector = cluster_to_sector(cluster);
    uint32_t byte_offset = first_sector * bpb.BytsPerSec;
    fseek(fp, byte_offset, SEEK_SET);
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

void tokenize_command(char *command, char **tokens, int *token_count) {
    char *token = strtok(command, " ");
    *token_count = 0;

    while (token != NULL) {
        if (token[0] == '"') {
            char str[256] = "";

            strcat(str, token + 1);
            strcat(str, " ");

            token = strtok(NULL, " ");
            while (token != NULL && token[strlen(token) - 1] != '"') {
                strcat(str, token);
                strcat(str, " ");
                token = strtok(NULL, " ");
            }

            if (token != NULL) {
                token[strlen(token) - 1] = '\0';
                strcat(str, token);
            }

            tokens[*token_count] = strdup(str);
            (*token_count)++;
        } else {
            tokens[*token_count] = strdup(token);
            (*token_count)++;
        }
        token = strtok(NULL, " ");
    }
    tokens[*token_count] = NULL;
}