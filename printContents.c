#include <stdio.h>
#include <dirent.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

void print_contents(const char *dir_name, int depth_level, FILE *file) {
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
            fprintf(file, "|----");
        }

        if (S_ISDIR(statbuf.st_mode)) {
            fprintf(file, "%s :\n", entry->d_name);
            print_contents(path, depth_level + 1, file);
        } else {
            fprintf(file, "%s\n", entry->d_name);
        }
    }

    closedir(dir);
}

int main(int argc, char *argv[]) {
    if ((argc < 2) || (argc > 11)) {
        fprintf(stderr, "Usage: %s <directory_name1> [<directory_name2>...<directory_name10>]\n", argv[0]);
        return 1;
    }
    
    char dir_names_list[1500];
    for (int i=1; i<=argc; i++){
        
        if (argv[i] == NULL) { 
            break;
        }
        
        if (strstr(dir_names_list, argv[i]) == NULL){
            
            strcat(dir_names_list, argv[i]);
            char output_name[115];
            
            snprintf(output_name, sizeof(output_name), "snapshot(%s).txt", argv[i]);
            FILE *file = fopen(output_name, "w");
            if (!file) {
                perror("fopen");
                return 1;
            }
            
            print_contents(argv[i], 0, file);
            fclose(file);
            printf("Snapshot of directory \"%s\" written to \"%s\"\n", argv[i], output_name);
            
        } 
        
        else {
            printf("The directory \"%s\" already processed\n", argv[i]);
            continue;
        }
        
    }
    
    
    return 0;
}
