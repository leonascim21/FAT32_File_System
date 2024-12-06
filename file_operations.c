#include "fat32.h"

void open_file(char *filename, char *flag) {
    for (int i = 0; i < MAX_OPEN_FILES; i++) {
        if (open_files[i].in_use && strcmp(open_files[i].name, filename) == 0) {
            printf("File is already open\n");
            return;
        }
    }

    if (strcmp(flag, "-r") != 0 && strcmp(flag, "-w") != 0 && strcmp(flag, "-rw") != 0 && strcmp(flag, "-wr") != 0) {
        printf("Invalid flags\n");
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

        if (strcmp(name, filename) == 0) {
            if (dir.DIR_Attr & ATTR_DIRECTORY) {
                return;
            }

            for (int i = 0; i < MAX_OPEN_FILES; i++) {
                if (!open_files[i].in_use) {
                    strncpy(open_files[i].name, filename, sizeof(open_files[i].name) - 1);
                    open_files[i].cluster = ((uint32_t)dir.DIR_FstClusHI << 16) | dir.DIR_FstClusLO;
                    strncpy(open_files[i].flag, flag + 1, sizeof(open_files[i].flag) - 1);
                    open_files[i].offset = 0;
                    open_files[i].in_use = 1;
                    strncpy(open_files[i].path, current_path, sizeof(open_files[i].path) - 1);
                    open_files[i].size = dir.DIR_FileSize;
                    printf("File successfully open in mode %s\n", flag);
                    return;
                }
            }
        }
    }
}

void lsof() {
    int open_count = 0;
    for (int i = 0; i < MAX_OPEN_FILES; i++) {
        if (open_files[i].in_use) {
            printf("Index: %d, Name: %s, Flag: %s, Offset: %u, Path: %s\n",
                   i, open_files[i].name, open_files[i].flag, open_files[i].offset, open_files[i].path);
            open_count++;
        }
    }
    if (open_count == 0) {
        printf("No open files\n");
    }
}

void close_file(char *filename) {
    int found = 0;

    for (int i = 0; i < MAX_OPEN_FILES; i++) {
        if (open_files[i].in_use && strcmp(open_files[i].name, filename) == 0) {
            open_files[i].in_use = 0;
            memset(open_files[i].name, 0, sizeof(open_files[i].name));
            memset(open_files[i].path, 0, sizeof(open_files[i].path));
            open_files[i].offset = 0;
            open_files[i].size = 0;
            found = 1;
            printf("File closed\n");
            break;
        }
    }

    if (!found) {
        printf("File not open or does not exist\n");
    }
}

void lseek_file(char *filename, uint32_t offset) {
    for (int i = 0; i < MAX_OPEN_FILES; i++) {
        if (open_files[i].in_use && strcmp(open_files[i].name, filename) == 0) {

            uint32_t first_sector = cluster_to_sector(open_files[i].cluster);
            uint32_t byte_offset = first_sector * bpb.BytsPerSec;
            fseek(fp, byte_offset, SEEK_SET);

            DirectoryEntry dir;
            fread(&dir, sizeof(DirectoryEntry), 1, fp);

            uint32_t file_size = open_files[i].size;

            if (offset > file_size) {
                printf("Offset exceeds the file size.\n");
                return;
            }

            open_files[i].offset = offset;
            printf("Offset updated\n");
            return;
        }
    }
    printf("File not open or does not exist.\n");
}

void read_file(char *filename, uint32_t size) {
    for (int i = 0; i < MAX_OPEN_FILES; i++) {
        if (open_files[i].in_use && strcmp(open_files[i].name, filename) == 0) {

            if (strcmp(open_files[i].flag, "r") != 0 && strcmp(open_files[i].flag, "rw") != 0 && strcmp(open_files[i].flag, "wr") != 0) {
                printf("File does not have read flag.\n");
                return;
            }

            uint32_t file_size = open_files[i].size;
            uint32_t offset = open_files[i].offset;
            if (offset + size > file_size) {
                size = file_size - offset;
            }

            uint32_t current_cluster = open_files[i].cluster;
            uint32_t bytes_read = 0;
            char buffer[512];

            while (bytes_read < size) {
                uint32_t sector = cluster_to_sector(current_cluster);
                uint32_t byte_offset = sector * bpb.BytsPerSec + offset % (bpb.SecPerClus * bpb.BytsPerSec);
                fseek(fp, byte_offset, SEEK_SET);

                uint32_t bytes_to_read = bpb.SecPerClus * bpb.BytsPerSec - (offset % (bpb.SecPerClus * bpb.BytsPerSec));
                if (bytes_to_read > size - bytes_read) {
                    bytes_to_read = size - bytes_read;
                }

                size_t read_now = fread(buffer, 1, bytes_to_read, fp);
                buffer[read_now] = '\0';
                printf("%s", buffer);

                bytes_read += read_now;
                offset += read_now;

                if (bytes_read < size) {
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

            open_files[i].offset = offset;
            printf("\n");
            return;
        }
    }
    printf("File is not open or does not exist.\n");
}

void rm(char *filename) {
    for (int i = 0; i < MAX_OPEN_FILES; i++) {
        if (open_files[i].in_use && strcmp(open_files[i].name, filename) == 0) {
            printf("File must be closed to be deleted.\n");
            return;
        }
    }

    uint32_t current_cluster = current_directory_cluster;
    int found = 0;
    uint32_t dir_entry_offset = 0;
    DirectoryEntry dir;

    while (1) {
        seek_to_cluster(current_cluster);

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

            if (strcmp(name, filename) == 0) {
                if (dir.DIR_Attr & ATTR_DIRECTORY) {
                    printf("target is a diretory, use rmdir.\n");
                    return;
                }

                found = 1;
                dir_entry_offset = ftell(fp) - sizeof(DirectoryEntry);
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
        printf("File does not exist\n");
        return;
    }

    current_cluster = ((uint32_t)dir.DIR_FstClusHI << 16) | dir.DIR_FstClusLO;

    while (current_cluster < EOC && current_cluster != 0x0000000) {
        uint32_t fat_offset = current_cluster * 4;
        uint32_t fat_sector = bpb.RsvdSecCnt + (fat_offset / bpb.BytsPerSec);
        uint32_t fat_offset_within_sector = fat_offset % bpb.BytsPerSec;

        fseek(fp, fat_sector * bpb.BytsPerSec + fat_offset_within_sector, SEEK_SET);
        uint32_t next_cluster;
        fread(&next_cluster, sizeof(uint32_t), 1, fp);
        next_cluster &= 0x0FFFFFFF;

        uint32_t free_value = 0x00000000;
        fseek(fp, fat_sector * bpb.BytsPerSec + fat_offset_within_sector, SEEK_SET);
        fwrite(&free_value, sizeof(uint32_t), 1, fp);

        current_cluster = next_cluster;
    }

    fseek(fp, dir_entry_offset, SEEK_SET);
    uint8_t deleted_marker = 0xE5;
    fwrite(&deleted_marker, sizeof(uint8_t), 1, fp);
}

void rename_file(char *filename, char *new_filename) {
    for (int i = 0; i < MAX_OPEN_FILES; i++) {
        if (open_files[i].in_use && strcmp(open_files[i].name, filename) == 0) {
            printf("File must be closed.\n");
            return;
        }
    }

    uint32_t current_cluster = current_directory_cluster;
    DirectoryEntry dir;
    int found = 0;
    int new_name_exists = 0;
    uint32_t entry_offset = 0;
    uint8_t original_attr = 0;
    uint32_t original_cluster = 0;

    while (1) {
        seek_to_cluster(current_cluster);


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

            if (strcmp(name, filename) == 0) {
                if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
                    printf("Cannot rename special directories '.' or '..'.\n");
                    return;
                }
                found = 1;
                entry_offset = ftell(fp) - sizeof(DirectoryEntry);
                original_attr = dir.DIR_Attr;
                original_cluster = ((uint32_t)dir.DIR_FstClusHI << 16) | dir.DIR_FstClusLO;
            } else if (strcmp(name, new_filename) == 0) {
                new_name_exists = 1;
            }
        }

        if (found || new_name_exists) {
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
        printf("File does not exist.\n");
        return;
    }

    if (new_name_exists) {
        printf("File with same name already exists.\n");
        return;
    }

    memset(dir.DIR_Name, ' ', 11);
    strncpy((char *)dir.DIR_Name, new_filename, strlen(new_filename));
    dir.DIR_Attr = original_attr;
    dir.DIR_FstClusHI = (uint16_t)(original_cluster >> 16);
    dir.DIR_FstClusLO = (uint16_t)(original_cluster & 0xFFFF);

    fseek(fp, entry_offset, SEEK_SET);
    fwrite(&dir, sizeof(DirectoryEntry), 1, fp);
}

void write_file(char *filename, char *string) {
    int file_index = -1;
    for (int i = 0; i < MAX_OPEN_FILES; i++) {
        if (open_files[i].in_use && strcmp(open_files[i].name, filename) == 0) {
            if (strcmp(open_files[i].flag, "w") != 0 &&
                strcmp(open_files[i].flag, "rw") != 0 &&
                strcmp(open_files[i].flag, "wr") != 0) {
                printf("File does not have write flag.\n");
                return;
            }
            file_index = i;
            break;
        }
    }

    if (file_index == -1) {
        printf("File is not open or does not exist.\n");
        return;
    }

    uint32_t offset = open_files[file_index].offset;
    uint32_t bytes_per_cluster = bpb.SecPerClus * bpb.BytsPerSec;
    uint32_t length_to_write = (uint32_t)strlen(string);
    uint32_t bytes_written = 0;

    uint32_t dir_cluster = current_directory_cluster;
    uint32_t dir_cluster_to_read = dir_cluster;
    DirectoryEntry dir_entry;
    uint32_t dir_entry_offset = 0;
    int found = 0;

    while (1) {
        uint32_t first_sector = cluster_to_sector(dir_cluster_to_read);
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

            if (strcmp(name, filename) == 0) {
                memcpy(&dir_entry, &dir, sizeof(DirectoryEntry));
                dir_entry_offset = ftell(fp) - sizeof(DirectoryEntry);
                found = 1;
                break;
            }
        }

        if (found) {
            break;
        }

        uint32_t fat_offset = dir_cluster_to_read * 4;
        uint32_t fat_sector = bpb.RsvdSecCnt + (fat_offset / bpb.BytsPerSec);
        uint32_t fat_offset_within_sector = fat_offset % bpb.BytsPerSec;

        fseek(fp, fat_sector * bpb.BytsPerSec + fat_offset_within_sector, SEEK_SET);
        uint32_t next_cluster;
        fread(&next_cluster, sizeof(uint32_t), 1, fp);
        next_cluster &= 0x0FFFFFFF;

        if (next_cluster >= EOC) {
            break;
        }
        dir_cluster_to_read = next_cluster;
    }

    if (!found) {
        printf("File does not exist\n");
        return;
    }

    uint32_t file_size = dir_entry.DIR_FileSize;
    uint32_t current_cluster = open_files[file_index].cluster;

    if (current_cluster == 0) {
        uint32_t new_cluster = find_free_cluster();
        if (new_cluster == 0) {
            return;
        }
        allocate_cluster(new_cluster, EOC);
        current_cluster = new_cluster;
        open_files[file_index].cluster = new_cluster;

        dir_entry.DIR_FstClusHI = (uint16_t)(new_cluster >> 16);
        dir_entry.DIR_FstClusLO = (uint16_t)(new_cluster & 0xFFFF);

        fseek(fp, dir_entry_offset, SEEK_SET);
        fwrite(&dir_entry, sizeof(DirectoryEntry), 1, fp);
    }

    uint32_t cluster_offset = offset / bytes_per_cluster;
    uint32_t offset_within_cluster = offset % bytes_per_cluster;

    for (uint32_t c = 0; c < cluster_offset; c++) {
        uint32_t fat_offset = current_cluster * 4;
        uint32_t fat_sector = bpb.RsvdSecCnt + (fat_offset / bpb.BytsPerSec);
        uint32_t fat_offset_within_sector = fat_offset % bpb.BytsPerSec;

        fseek(fp, fat_sector * bpb.BytsPerSec + fat_offset_within_sector, SEEK_SET);
        uint32_t next_cluster;
        fread(&next_cluster, sizeof(uint32_t), 1, fp);
        next_cluster &= 0x0FFFFFFF;

        if (next_cluster >= EOC) {
            uint32_t new_cluster = find_free_cluster();
            if (new_cluster == 0) {
                return;
            }
            fseek(fp, fat_sector * bpb.BytsPerSec + fat_offset_within_sector, SEEK_SET);
            fwrite(&new_cluster, sizeof(uint32_t), 1, fp);
            allocate_cluster(new_cluster, EOC);
            current_cluster = new_cluster;
        } else {
            current_cluster = next_cluster;
        }
    }

    while (bytes_written < length_to_write) {
        seek_to_cluster(current_cluster);


        uint32_t remaining_in_cluster = bytes_per_cluster - offset_within_cluster;
        uint32_t bytes_to_write = (length_to_write - bytes_written) < remaining_in_cluster ? (length_to_write - bytes_written) : remaining_in_cluster;

        size_t written = fwrite(string + bytes_written, 1, bytes_to_write, fp);
        if (written != bytes_to_write) {
            return;
        }

        bytes_written += bytes_to_write;
        offset_within_cluster = 0;

        if (bytes_written < length_to_write) {
            uint32_t fat_offset = current_cluster * 4;
            uint32_t fat_sector = bpb.RsvdSecCnt + (fat_offset / bpb.BytsPerSec);
            uint32_t fat_offset_within_sector = fat_offset % bpb.BytsPerSec;

            fseek(fp, fat_sector * bpb.BytsPerSec + fat_offset_within_sector, SEEK_SET);
            uint32_t next_cluster;
            fread(&next_cluster, sizeof(uint32_t), 1, fp);
            next_cluster &= 0x0FFFFFFF;

            if (next_cluster >= EOC) {
                uint32_t new_cluster = find_free_cluster();
                if (new_cluster == 0) {
                    return;
                }
                fseek(fp, fat_sector * bpb.BytsPerSec + fat_offset_within_sector, SEEK_SET);
                fwrite(&new_cluster, sizeof(uint32_t), 1, fp);
                allocate_cluster(new_cluster, EOC);
                current_cluster = new_cluster;
            } else {
                current_cluster = next_cluster;
            }
        }
    }

    open_files[file_index].offset += bytes_written;

    if (open_files[file_index].offset > file_size) {
        dir_entry.DIR_FileSize = open_files[file_index].offset;
        fseek(fp, dir_entry_offset, SEEK_SET);
        fwrite(&dir_entry, sizeof(DirectoryEntry), 1, fp);

        open_files[file_index].size = dir_entry.DIR_FileSize;
    }
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
        get_directory_entry_name(&dir, name);

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