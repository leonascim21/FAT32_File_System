#include "fat32.h"

FILE *fp = NULL;
char image_name[256];
uint32_t current_directory_cluster;
char current_path[256] = "/";
OpenFile open_files[MAX_OPEN_FILES] = {0};
BPB bpb;

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

        char *tokens[10];
        int token_count = 0;
        tokenize_command(command, tokens, &token_count);

        if (token_count == 0) {
            continue;
        }

        if (strcmp(tokens[0], "info") == 0) {
            print_info();
        } else if (strcmp(tokens[0], "exit") == 0) {
            exit = exit_shell();
        } else if (strcmp(tokens[0], "ls") == 0) {
            ls();
        } else if (strcmp(tokens[0], "cd") == 0 && token_count > 1) {
            cd(tokens[1]);
        } else if (strcmp(tokens[0], "mkdir") == 0 && token_count > 1) {
            mkdir(tokens[1]);
        } else if (strcmp(tokens[0], "creat") == 0 && token_count > 1) {
            creat(tokens[1]);
        } else if (strcmp(tokens[0], "open") == 0 && token_count > 2) {
            open_file(tokens[1], tokens[2]);
        } else if (strcmp(tokens[0], "lsof") == 0) {
            lsof();
        } else if (strcmp(tokens[0], "close") == 0 && token_count > 1) {
            close_file(tokens[1]);
        } else if (strcmp(tokens[0], "lseek") == 0 && token_count > 2) {
            lseek_file(tokens[1], atoi(tokens[2]));
        }  else if (strcmp(tokens[0], "read") == 0 && token_count > 2) {
            read_file(tokens[1], atoi(tokens[2]));
        } else if (strcmp(tokens[0], "rm") == 0 && token_count > 1) {
            rm(tokens[1]);
        } else if (strcmp(tokens[0], "rename") == 0 && token_count > 2) {
            rename_file(tokens[1], tokens[2]);
        } else if (strcmp(tokens[0], "write") == 0 && token_count > 2) {
            write_file(tokens[1], tokens[2]);
        } else if (strcmp(tokens[0], "rmdir") == 0 && token_count > 1) {
            rmdir(tokens[1]);
        } else if (strcmp(tokens[0], "dump") == 0 && token_count > 1) {
            dump(tokens[1]);
        } else {
            printf("Unknown command\n");
        }
    }
    return 0;
}
