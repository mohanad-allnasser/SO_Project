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

void analyze_file(const char *file_path, const char *isolated_dir, int pipe_fd[2]) {
    pid_t pid = fork(); // Create a child process
    if (pid < 0) {
        perror("fork");
    } else if (pid == 0) {
        // Child process to analyze the file
        close(pipe_fd[0]); // Close the read end of the pipe
        dup2(pipe_fd[1], STDOUT_FILENO); // Redirect stdout to the write end of the pipe
        execlp("sh", "sh", "verify_for_malicious.sh", file_path, isolated_dir, (char *)NULL);
        perror("execlp");
        exit(1);
    } else {
        // Parent process does not write to the pipe
        close(pipe_fd[1]); // Close the write end of the pipe
    }
}

int main(int argc, char *argv[]) {
    if (argc < 5 || argc > 12) {
        fprintf(stderr, "Usage: %s -o output_directory -s isolated_space_dir <directory_name1> [<directory_name2>...<directory_name10>]\n", argv[0]);
        return 1;
    }

    char *output_dir = ".";
    char *isolated_dir = NULL;
    int start_index = 1;

    if (strcmp(argv[1], "-o") == 0) {
        if (argc < 6) {
            fprintf(stderr, "Usage: %s -o output_directory -s isolated_space_dir <directory_name1> [<directory_name2>...<directory_name10>]\n", argv[0]);
            return 1;
        }
        output_dir = argv[2];
        if (strcmp(argv[3], "-s") == 0) {
            isolated_dir = argv[4];
            start_index = 5;
        } else {
            fprintf(stderr, "Usage: %s -o output_directory -s isolated_space_dir <directory_name1> [<directory_name2>...<directory_name10>]\n", argv[0]);
            return 1;
        }
    }

    int pipe_fd[2];
    if (pipe(pipe_fd) == -1) {
        perror("pipe");
        return 1;
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

            // Analyze files in the directory for potential threats
            DIR *dir = opendir(argv[i]);
            if (!dir) {
                perror("opendir");
                exit(1);
            }

            struct dirent *entry;
            while ((entry = readdir(dir)) != NULL) {
                if (entry->d_type == DT_REG) {
                    char file_path[2048];
                    snprintf(file_path, sizeof(file_path), "%s/%s", argv[i], entry->d_name);

                    analyze_file(file_path, isolated_dir, pipe_fd);
                }
            }

            closedir(dir);

            // Child process finished
            exit(0);
        }
    }

    // Parent process
    close(pipe_fd[1]); // Close the write end of the pipe

    int status;
    pid_t wpid;
    char buffer[2048];
    int corrupt_files_count = 0;

    while ((wpid = wait(&status)) > 0) {
        if (WIFEXITED(status)) {
            printf("The process with the ID %d finished with the code %d\n", wpid, WEXITSTATUS(status));
            if (WEXITSTATUS(status) == 0) {
                // Read from pipe
                while (read(pipe_fd[0], buffer, sizeof(buffer) - 1) > 0) {
                    buffer[sizeof(buffer) - 1] = '\0'; // Null-terminate the buffer
                    if (strcmp(buffer, "SAFE") != 0) {
                        // File is dangerous, move it to the isolation directory
                        char *file_path = strtok(buffer, "\n");
                        while (file_path != NULL) {
                            printf("Moving dangerous file to isolation directory: %s\n", file_path);
                            char isolate_path[2048];
                            snprintf(isolate_path, sizeof(isolate_path), "%s/%s", isolated_dir, strrchr(file_path, '/') + 1);
                            rename(file_path, isolate_path);
                            corrupt_files_count++;
                            file_path = strtok(NULL, "\n");
                        }
                    }
                }
            }
        }
    }

    close(pipe_fd[0]); // Close the read end of the pipe

    printf("Number of corrupt files found: %d\n", corrupt_files_count);

    return 0;
}
