#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <yara.h>
#include <sys/stat.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096  
#endif

#define PATH_SEPARATOR '/'
#define BUFFER_SIZE 1024


int total_files_scanned = 0;
int total_infected_files = 0;

void displayErrorMessage(int errorCode) {
    printf("Error: %s\n", strerror(errorCode));
}


int scanCallback(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data) {
    int* is_infected = (int*)user_data;  

    switch (message) {
    case CALLBACK_MSG_RULE_MATCHING:
        printf("⚠️ Matched rule: %s\n", ((YR_RULE*)message_data)->identifier);
        *is_infected = 1; 
        break;
    case CALLBACK_MSG_SCAN_FINISHED:
        printf("✅ Scan finished\n");
        break;
    default:
        break;
    }
    return CALLBACK_CONTINUE;
}


void scanFile(const char* filePath, YR_RULES* rules) {
    total_files_scanned++;
    printf("\n🔍 Scanning file: %s\n", filePath);

    int is_infected = 0;
    if (yr_rules_scan_file(rules, filePath, SCAN_FLAGS_REPORT_RULES_MATCHING, scanCallback, &is_infected, 0) != ERROR_SUCCESS) {
        printf("❌ Failed to scan: %s\n", filePath);
    }

    if (is_infected) {
        total_infected_files++;
    } else {
        printf("✅ No threats found in %s\n", filePath);
    }
}


void scanDirectory(const char* dirPath, YR_RULES* rules) {
    DIR* dir;
    struct dirent* entry;

    if (!(dir = opendir(dirPath))) {
        printf("❌ Error opening directory %s: %s\n", dirPath, strerror(errno));
        return;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        char fullPath[PATH_MAX];
        snprintf(fullPath, sizeof(fullPath), "%s%c%s", dirPath, PATH_SEPARATOR, entry->d_name);

        struct stat path_stat;
        if (stat(fullPath, &path_stat) == -1) {
            printf("❌ Error getting file status for %s: %s\n", fullPath, strerror(errno));
            continue;
        }

        if (S_ISDIR(path_stat.st_mode)) {
            scanDirectory(fullPath, rules);
        } else if (S_ISREG(path_stat.st_mode)) {
            scanFile(fullPath, rules);
        }
    }
    closedir(dir);
}


void checkType(const char* path, YR_RULES* rules) {
    struct stat path_stat;
    if (stat(path, &path_stat) == 0) {
        if (S_ISREG(path_stat.st_mode)) {
            scanFile(path, rules);
        } else if (S_ISDIR(path_stat.st_mode)) {
            scanDirectory(path, rules);
        } else {
            printf("❌ Unknown file type: %s\n", path);
        }
    } else {
        printf("❌ Error getting file status: %s\n", strerror(errno));
    }
}

YR_RULES* compileRules(const char* directory_path) {
    DIR* directory = opendir(directory_path);
    if (!directory) {
        printf("❌ Failed to open directory: %s\n", strerror(errno));
        return NULL;
    }

    printf("[+] Successfully opened rules directory: %s\n", directory_path);

    YR_COMPILER* compiler = NULL;
    if (yr_compiler_create(&compiler) != ERROR_SUCCESS) {
        printf("❌ Failed to initialize YARA compiler\n");
        closedir(directory);
        return NULL;
    }

    struct dirent* entry;
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        char rule_file_path[PATH_MAX];
        snprintf(rule_file_path, sizeof(rule_file_path), "%s/%s", directory_path, entry->d_name);

        struct stat path_stat;
        if (stat(rule_file_path, &path_stat) == -1) {
            printf("❌ Failed to get file status for %s: %s\n", rule_file_path, strerror(errno));
            continue;
        }

        if (S_ISREG(path_stat.st_mode) && strstr(entry->d_name, ".yar") != NULL) {
            FILE* rule_file = fopen(rule_file_path, "rb");
            if (rule_file) {
                if (yr_compiler_add_file(compiler, rule_file, NULL, NULL) > 0) {
                    printf("❌ Failed to compile YARA rule: %s\n", rule_file_path);
                } else {
                    printf("[+] Compiled rule: %s\n", rule_file_path);
                }
                fclose(rule_file);
            } else {
                printf("❌ Failed to open rule file: %s\n", strerror(errno));
            }
        }
    }
    closedir(directory);

    YR_RULES* rules = NULL;
    if (yr_compiler_get_rules(compiler, &rules) != ERROR_SUCCESS) {
        printf("❌ Failed to compile rules\n");
        return NULL;
    }

    return rules;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("❌ Usage: %s <file_or_directory_to_scan>\n", argv[0]);
        return 1;
    }

    const char directory_path[] = "./rules";
    char* file_path = argv[1];

    if (yr_initialize() != ERROR_SUCCESS) {
        printf("❌ Failed to initialize YARA\n");
        return 1;
    }
    printf("[+] Successfully initialized YARA\n");

    YR_RULES* rules = compileRules(directory_path);
    if (!rules) {
        yr_finalize();
        return 1;
    }

    checkType(file_path, rules);

 
    printf("\n📊 **Scan Summary**\n");
    printf("📂 Total Files Scanned: %d\n", total_files_scanned);
    printf("⚠️ Infected Files: %d\n", total_infected_files);
    printf("✅ Clean Files: %d\n", total_files_scanned - total_infected_files);

    yr_rules_destroy(rules);
    yr_finalize();
    return 0;
}
