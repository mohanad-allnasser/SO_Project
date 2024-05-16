#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/wait.h>

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

int compare_files(const char *file1, const char *file2) {
    FILE *f1 = fopen(file1, "r");
    FILE *f2 = fopen(file2, "r");
    if (!f1 || !f2) {
        perror("Error opening files for comparison");
        return -1;
    }

    int c1, c2;
    do {
        c1 = fgetc(f1);
        c2 = fgetc(f2);
        if (c1 != c2) {
            fclose(f1);
            fclose(f2);
            return 0; // Files are different
        }
    } while (c1 != EOF && c2 != EOF);

    fclose(f1);
    fclose(f2);

    if (c1 == EOF && c2 == EOF) {
        return 1; // Files are identical
    } else {
        return 0; // Files are different
    }
}

void analyze_file(const char *file_path, const char *isolated_dir) {
    pid_t pid = fork(); // Create a child process
    if (pid < 0) {
        perror("fork");
    } else if (pid == 0) {
        // Child process to analyze the file
        execlp("sh", "sh", "verify_for_malicious.sh", file_path, isolated_dir, (char *)NULL);
        perror("execlp");
        exit(1);
    } else {
        // Parent process waits for the child process to finish
        int status;
        waitpid(pid, &status, 0);
    }
}

void check_and_isolate_files(const char *dir_name, const char *isolated_dir) {
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

        if (!S_ISDIR(statbuf.st_mode) && (statbuf.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO)) == 0) {
            // File has no permissions, indicating potential danger
            analyze_file(path, isolated_dir);
        }
    }

    closedir(dir);
}

int main(int argc, char *argv[]) {
    if (argc < 4 || argc > 12) {
        fprintf(stderr, "Usage: %s -o output_directory -s isolated_space_dir <directory_name1> [<directory_name2>...<directory_name10>]\n", argv[0]);
        return 1;
    }

    char *output_dir = NULL;
    char *isolated_dir = NULL;
    int start_index = 1;

    if (strcmp(argv[1], "-o") == 0) {
        if (argc < 6) {
            fprintf(stderr, "Usage: %s -o output_directory -s isolated_space_dir <directory_name1> [<directory_name2>...<directory_name10>]\n", argv[0]);
            return 1;
        }
        output_dir = argv[2];
        if (strcmp(argv[3], "-s") != 0) {
            fprintf(stderr, "Usage: %s -o output_directory -s isolated_space_dir <directory_name1> [<directory_name2>...<directory_name10>]\n", argv[0]);
            return 1;
        }
        isolated_dir = argv[4];
        start_index = 5;
    }

    for (int i = start_index; i < argc; i++) {
        if (argv[i] == NULL) {
            break;
        }

        pid_t pid = fork(); // Create a child process
        if (pid < 0) {
            perror("fork");
            return 1;
        } else if (pid == 0) {
            // Child process
            char output_name[2048];
            snprintf(output_name, sizeof(output_name), "%s/snapshot(%s).txt", output_dir, argv[i]);

            // Check if snapshot file exists
            struct stat statbuf;
            if (stat(output_name, &statbuf) == 0) {
                // Snapshot file exists, compare contents
                char temp_output_name[2048];
                snprintf(temp_output_name, sizeof(temp_output_name), "%s/temp_snapshot(%s).txt", output_dir, argv[i]);

                FILE *temp_file = fopen(temp_output_name, "w");
                if (!temp_file) {
                    perror("fopen");
                    return 1;
                }

                print_contents(argv[i], 0, temp_file);
                fclose(temp_file);

                // Compare files
                int result = compare_files(output_name, temp_output_name);
                if (result == 1) {
                    printf("The folder \"%s\" is up to date\n", argv[i]);
                } else if (result == 0) {
                    // Replace the old snapshot file with the new one
                    remove(output_name);
                    rename(temp_output_name, output_name);
                    printf("The folder \"%s\" updated\n", argv[i]);
                } else {
                    fprintf(stderr, "Error comparing files\n");
                }

                // Remove temporary file
                remove(temp_output_name);
            } else {
                // Snapshot file does not exist, create it
                FILE *file = fopen(output_name, "w");
                if (!file) {
                    perror("fopen");
                    return 1;
                }

                print_contents(argv[i], 0, file);
                fclose(file);
                printf("Snapshot of directory \"%s\" written to \"%s\"\n", argv[i], output_name);
            }

            // Check and isolate potentially dangerous files
            check_and_isolate_files(argv[i], isolated_dir);

            // Child process finished
            exit(0);
        }
    }

    // Parent process waits for all child processes to finish
    int status;
    pid_t wpid;
    while ((wpid = wait(&status)) > 0) {
        if (WIFEXITED(status)) {
            printf("The process with the ID %d finished with the code %d\n", wpid, WEXITSTATUS(status));
        }
    }

    return 0;
}
