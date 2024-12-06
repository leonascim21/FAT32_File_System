#ifndef FAT32_H
#define FAT32_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define ATTR_DIRECTORY 0x10
#define ATTR_ARCHIVE 0x20
#define EOC 0x0FFFFFF8
#define MAX_OPEN_FILES 10

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

typedef struct {
    char name[12];
    uint32_t cluster;
    char flag[3];
    uint32_t offset;
    int in_use;
    char path[256];
    uint32_t size;
} OpenFile;

extern FILE *fp;
extern char image_name[256];
extern uint32_t current_directory_cluster;
extern char current_path[256];
extern OpenFile open_files[MAX_OPEN_FILES];
extern BPB bpb;

void read_bpb();
void get_directory_entry_name(DirectoryEntry *dir, char *name);
uint32_t cluster_to_sector(uint32_t cluster);
void seek_to_cluster(uint32_t cluster);
void print_info();
void ls();
int exit_shell();
void cd(char*);
uint32_t find_free_cluster();
void allocate_cluster(uint32_t cluster, uint32_t value);
void mkdir(char *dirname);
void creat(char *filename);
void tokenize_command(char *command, char **tokens, int *token_count);
void open_file(char *filename, char *flag);
void lsof();
void close_file(char *filename);
void lseek_file(char *filename, uint32_t offset);
void read_file(char *filename, uint32_t size);
void rm(char *filename);
void rename_file(char *filename, char *new_filename);
void write_file(char *filename, char *string);
void rmdir(char *dirname);
void dump(char *filename);

#endif