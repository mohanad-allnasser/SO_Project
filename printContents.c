#include <stdio.h>
#include <dirent.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

void print_contents(const char *dir_name, int depth_level) {
    DIR *dir;
    struct dirent *entry;
    struct stat statbuf;
    char path[2048];

    dir = opendir(dir_name);
    if (!dir) {
        perror("opendir");
        return;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        snprintf(path, 2048, "%s/%s", dir_name, entry->d_name);

        if (lstat(path, &statbuf) == -1) {
            perror("lstat");
            continue;
        }

        
        for (int i = 0; i < depth_level; i++) { 
            printf("|--");
        }

        if (S_ISDIR(statbuf.st_mode)) {
            printf("%s :\n", entry->d_name);
            print_contents(path, depth_level + 1);
        } else {
            printf("%s\n", entry->d_name);
        }
    }

    closedir(dir);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <directory_name>\n", argv[0]);
        return 1;
    }

    print_contents(argv[1], 0);

    return 0;
}
