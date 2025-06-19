#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <yaml.h>
#include <stdbool.h>
#include <dirent.h>


#define BUFFER_SIZE 8192

int HTTP_PORT = 8080;
int HTTPS_PORT = 8443;
int ONLY_HTTPS = 0;
int ALLOW_SSH = 1;
char REDIRECT[128];
char DEFAULT_FILE[128] = "index.html";
char CERT_FILE[128] = "cert.pem";
char KEY_FILE[128] = "key.pem";
bool ALLOW_LIST_CONNECT = false; // New config option


void load_config() {
    FILE *file = fopen("config.yaml", "r");
    if (!file) {
        perror("Missing config.yaml");
        exit(1);
    }

    yaml_parser_t parser;
    yaml_token_t token;

    if (!yaml_parser_initialize(&parser)) {
        fputs("Failed to initialize YAML parser\n", stderr);
        exit(1);
    }
    yaml_parser_set_input_file(&parser, file);

    char key[128] = "";
    char parent[128] = "";
    int state = 0;

    while (1) {
        yaml_parser_scan(&parser, &token);
        if (token.type == YAML_STREAM_END_TOKEN)
            break;

        if (token.type == YAML_KEY_TOKEN) {
            state = 1;
        } else if (token.type == YAML_VALUE_TOKEN) {
            state = 2;
        } else if (token.type == YAML_SCALAR_TOKEN) {
            char *value = (char *)token.data.scalar.value;
            if (state == 1) {
                strncpy(key, value, sizeof(key));
            } else if (state == 2) {
                if (strcmp(parent, "") == 0) {
                    if (strcmp(key, "port") == 0) {
                        HTTP_PORT = atoi(value);
                    } else if (strcmp(key, "index_file") == 0) {
                        strncpy(DEFAULT_FILE, value, sizeof(DEFAULT_FILE));
                    } else if (strcmp(key, "https") == 0) {
                        // Shouldn't happen – 'https' is a map, not a value
                    } else if (strcmp(key, "allow_list_content") == 0) {
                        if (strcmp(value, "true") == 0)
                            ALLOW_LIST_CONNECT = true;
                        else
                            ALLOW_LIST_CONNECT = false;
                    }
                } else if (strcmp(parent, "https") == 0) {
                    ALLOW_SSH = 1;  // if https block is present, allow SSH
                    if (strcmp(key, "port") == 0) {
                        HTTPS_PORT = atoi(value);
                    } else if (strcmp(key, "cert") == 0) {
                        strncpy(CERT_FILE, value, sizeof(CERT_FILE));
                    } else if (strcmp(key, "key") == 0) {
                        strncpy(KEY_FILE, value, sizeof(KEY_FILE));
                    } else if (strcmp(key, "force") == 0) {
                        if (strcmp(value, "true") == 0)
                            ONLY_HTTPS = 1;
                        else
                            ONLY_HTTPS = 0;
                    }


                }

                state = 0;
            }
        } else if (token.type == YAML_BLOCK_MAPPING_START_TOKEN) {
            // Reset key for nested map start
            if (strcmp(key, "https") == 0) {
                strncpy(parent, "https", sizeof(parent));
            }
        } else if (token.type == YAML_BLOCK_END_TOKEN) {
            if (strcmp(parent, "https") == 0) {
                parent[0] = '\0';
            }
        }

        yaml_token_delete(&token);
    }

    yaml_parser_delete(&parser);
    fclose(file);

    printf("Config: HTTP_PORT=%d, HTTPS_PORT=%d, ONLY_HTTPS=%d, ALLOW_SSH=%d\n"
           "DEFAULT_FILE=%s, CERT_FILE=%s, KEY_FILE=%s\n",
           HTTP_PORT, HTTPS_PORT, ONLY_HTTPS, ALLOW_SSH,
           DEFAULT_FILE, CERT_FILE, KEY_FILE);
}


const char* get_mime_type(const char* path) {
    if (strstr(path, ".html")) return "text/html";
    if (strstr(path, ".css")) return "text/css";
    if (strstr(path, ".js")) return "application/javascript";
    if (strstr(path, ".png")) return "image/png";
    if (strstr(path, ".jpg") || strstr(path, ".jpeg")) return "image/jpeg";
    if (strstr(path, ".txt")) return "text/plain";
    if (strstr(path, ".json")) return "application/json";
    if (strstr(path, ".xml")) return "application/xml";
    if (strstr(path, ".pdf")) return "application/pdf";
    if (strstr(path, ".zip")) return "application/zip";
    if (strstr(path, ".mp3")) return "audio/mpeg";
    if (strstr(path, ".mp4")) return "video/mp4";
    if (strstr(path, ".gif")) return "image/gif";
    return "application/octet-stream";
}

void log_message(const char *message, const char *level) {
    const char *colorCode;

    if (strcmp(level, "log") == 0) {
        colorCode = "\033[0m";         // Default
        printf("%s", message);
    } else if (strcmp(level, "error") == 0) {
        colorCode = "\033[1;31m";      // Red
    } else if (strcmp(level, "success") == 0) {
        colorCode = "\033[1;32m";      // Green
    } else if (strcmp(level, "info") == 0) {
        colorCode = "\033[1;34m";      // Blue
    } else {
        colorCode = "\033[0m";         // Fallback default
        printf("Unknown log level: %s\n", level);
    }

    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_str[26];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);

    printf("%s[%s] %s\033[0m\n", colorCode, time_str, message);
}

void parse_url_encoded(char *body) {
    char *token = strtok(body, "&");
    while (token) {
        char *equal = strchr(token, '=');
        if (equal) {
            *equal = '\0';
            printf("Field: %s = %s\n", token, equal + 1);
        }
        token = strtok(NULL, "&");
    }
}

void parse_form_data(char *body, const char *boundary) {
    char *part = strstr(body, boundary);
    while (part) {
        char *name_pos = strstr(part, "name=\"");
        if (!name_pos) break;
        name_pos += 6;
        char *name_end = strchr(name_pos, '"');
        *name_end = '\0';

        char *data_start = strstr(name_end + 1, "\r\n\r\n");
        if (!data_start) break;
        data_start += 4;

        char *data_end = strstr(data_start, boundary);
        if (!data_end) break;
        *data_end = '\0';

        printf("Field: %s = %s\n", name_pos, data_start);
        part = strstr(data_end + strlen(boundary), boundary);
    }
}


void send_file(SSL *ssl, const char *filepath) {
    char fullpath[512];
    snprintf(fullpath, sizeof(fullpath), "./www%s", filepath);

    if (strcmp(filepath, "/") == 0) {
        snprintf(fullpath, sizeof(fullpath), "./www/%s", DEFAULT_FILE);
    }

    struct stat st;
    if (stat(fullpath, &st) == -1) {
        const char *not_found = "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n\r\n404 Not Found\n";
        SSL_write(ssl, not_found, strlen(not_found));
        char log_buf[512];
        snprintf(log_buf, sizeof(log_buf), "File not found: %s", fullpath);
        log_message(log_buf, "error");
        return;
    }

    if (S_ISDIR(st.st_mode)) {
        if (!ALLOW_LIST_CONNECT) {
            const char *forbidden = "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\nDirectory listing is disabled.\n";
            SSL_write(ssl, forbidden, strlen(forbidden));
            return;
        }

        // Generate directory listing
        DIR *dir = opendir(fullpath);
        if (!dir) {
            const char *error = "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\n\r\nFailed to read directory.\n";
            SSL_write(ssl, error, strlen(error));
            return;
        }

        char response[8192];
        snprintf(response, sizeof(response),
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
            "<html><head><title>Index of %s</title></head><body>"
            "<h2>Index of %s</h2><ul>", filepath, filepath);

        struct dirent *entry;
        while ((entry = readdir(dir))) {
            if (strcmp(entry->d_name, ".") == 0) continue;
            char entry_path[512];
            snprintf(entry_path, sizeof(entry_path), "%s/%s", filepath, entry->d_name);
            char list_item[256];
            snprintf(list_item, sizeof(list_item), "<li><a href=\"%s\">%s</a></li>", entry_path, entry->d_name);
            strncat(response, list_item, sizeof(response) - strlen(response) - 1);
        }
        closedir(dir);
        strncat(response, "</ul></body></html>", sizeof(response) - strlen(response) - 1);
        SSL_write(ssl, response, strlen(response));
        return;
    }

    // It's a regular file
    FILE *file = fopen(fullpath, "rb");
    if (!file) {
        const char *not_found = "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n\r\n404 Not Found\n";
        SSL_write(ssl, not_found, strlen(not_found));
        char log_buf[512];
        snprintf(log_buf, sizeof(log_buf), "File open failed: %s", fullpath);
        log_message(log_buf, "error");
        return;
    }

    const char *mime = get_mime_type(fullpath);
    fseek(file, 0, SEEK_END);
    long fsize = ftell(file);
    fseek(file, 0, SEEK_SET);

    char header[256];
    snprintf(header, sizeof(header),
             "HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %ld\r\n\r\n",
             mime, fsize);
    SSL_write(ssl, header, strlen(header));

    char buffer[1024];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        SSL_write(ssl, buffer, bytes_read);
    }
    fclose(file);
}



void *handle_client(void *arg) {
    SSL *ssl = (SSL *)arg;

    char buffer[BUFFER_SIZE];
    int received = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (received <= 0) {
        SSL_free(ssl);
        return NULL;
    }
    buffer[received] = '\0';

    char method[8], path[256], protocol[16];
    sscanf(buffer, "%s %s %s", method, path, protocol);

    char *content_type = strstr(buffer, "Content-Type:");
    char *content_length = strstr(buffer, "Content-Length:");
    int length = 0;
    if (content_length) sscanf(content_length, "Content-Length: %d", &length);

    char *body = strstr(buffer, "\r\n\r\n");
    if (body) body += 4;

    // log_message("Received request");
    // with path and method
    sscanf(buffer, "%s %s %s", method, path, protocol);

    char log_buf[512];
    snprintf(log_buf, sizeof(log_buf), "HTTPS %s %s", method, path);
    log_message(log_buf, "info"); // blue color for info


    if (strcmp(method, "GET") == 0) {
        send_file(ssl, path);
    } else if (strcmp(method, "POST") == 0) {
        if (content_type) {
            if (strstr(content_type, "application/x-www-form-urlencoded")) {
                parse_url_encoded(body);
            } else if (strstr(content_type, "multipart/form-data")) {
                char *boundary = strstr(content_type, "boundary=");
                if (boundary) {
                    boundary += 9;
                    char full_boundary[128];
                    sprintf(full_boundary, "--%s", boundary);
                    parse_form_data(body, full_boundary);
                }
            }
        }
        const char *response =
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nPOST data received.\n";
        SSL_write(ssl, response, strlen(response));


    }
    log_message("Client request handled", "info"); // green color for success

    SSL_shutdown(ssl);
    SSL_free(ssl);
    
    return NULL;
}

void *start_http_server(void *arg) {
    int should_redirect = *(int *)arg;

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(HTTP_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("HTTP bind failed");
        exit(1);
    }

    if (listen(server_fd, 10) < 0) {
        perror("HTTP listen failed");
        exit(1);
    }

    printf("HTTP server listening on port %d (mode: %s)\n", HTTP_PORT,
           should_redirect ? "REDIRECT" : "PLAIN");

    while (1) {
        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) {
            perror("HTTP accept failed");
            continue;
        }

        char buffer[BUFFER_SIZE];
        memset(buffer, 0, sizeof(buffer));
        recv(client_fd, buffer, sizeof(buffer) - 1, 0);

        char method[8], path[256], protocol[16];
        sscanf(buffer, "%s %s %s", method, path, protocol);

        char log_buf[512];

        if (should_redirect) {
            const char *response_template =
                "HTTP/1.1 301 Moved Permanently\r\n"
                "Location: https://localhost:%d%s\r\n"
                "Content-Length: 0\r\n"
                "Connection: close\r\n"
                "\r\n";

            char response[512];
            snprintf(response, sizeof(response), response_template, HTTPS_PORT, path);
            snprintf(log_buf, sizeof(log_buf), "HTTP redirect → https://%s:%d%s", REDIRECT, HTTPS_PORT, path);
            log_message(log_buf, "info");

            send(client_fd, response, strlen(response), 0);
            close(client_fd);
            continue;
        }

        snprintf(log_buf, sizeof(log_buf), "HTTP  %s %s", method, path);
        log_message(log_buf, "info");

        if (strcmp(path, "/") == 0) {
            snprintf(path, sizeof(path), "/%s", DEFAULT_FILE);
        }

        char fullpath[512];
        snprintf(fullpath, sizeof(fullpath), "./www%s", path);

        if (strstr(fullpath, "..")) {
            const char *error = "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\nForbidden\n";
            send(client_fd, error, strlen(error), 0);
            snprintf(log_buf, sizeof(log_buf), "Forbidden access to path: %s", fullpath);
            log_message(log_buf, "error");
            log_message("Client connection closed", "info");
            close(client_fd);
            continue;
        }

        struct stat st;
        if (stat(fullpath, &st) == -1) {
            const char *error = "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n\r\nFile not found\n";
            send(client_fd, error, strlen(error), 0);
            snprintf(log_buf, sizeof(log_buf), "File not found: %s", fullpath);
            log_message(log_buf, "error");
            close(client_fd);
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            if (!ALLOW_LIST_CONNECT) {
                const char *forbidden = "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\nDirectory listing is disabled.\n";
                send(client_fd, forbidden, strlen(forbidden), 0);
                close(client_fd);
                continue;
            }

            DIR *dir = opendir(fullpath);
            if (!dir) {
                const char *error = "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\n\r\nFailed to read directory.\n";
                send(client_fd, error, strlen(error), 0);
                close(client_fd);
                continue;
            }

            char response[8192];
            snprintf(response, sizeof(response),
                     "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
                     "<html><head><title>Index of %s</title></head><body>"
                     "<h2>Index of %s</h2><ul>", path, path);

            struct dirent *entry;
            while ((entry = readdir(dir))) {
                if (strcmp(entry->d_name, ".") == 0) continue;
                char entry_path[512];
                snprintf(entry_path, sizeof(entry_path), "%s/%s", path, entry->d_name);
                char list_item[256];
                snprintf(list_item, sizeof(list_item), "<li><a href=\"%s\">%s</a></li>", entry_path, entry->d_name);
                strncat(response, list_item, sizeof(response) - strlen(response) - 1);
            }
            closedir(dir);
            strncat(response, "</ul></body></html>", sizeof(response) - strlen(response) - 1);
            send(client_fd, response, strlen(response), 0);
            close(client_fd);
            continue;
        }

        FILE *file = fopen(fullpath, "rb");
        if (!file) {
            const char *error = "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n\r\nFile not found\n";
            send(client_fd, error, strlen(error), 0);
            snprintf(log_buf, sizeof(log_buf), "File open failed: %s", fullpath);
            log_message(log_buf, "error");
            close(client_fd);
            continue;
        }

        const char *mime = get_mime_type(fullpath);
        fseek(file, 0, SEEK_END);
        long fsize = ftell(file);
        fseek(file, 0, SEEK_SET);

        char header[256];
        snprintf(header, sizeof(header),
                 "HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %ld\r\n\r\n",
                 mime, fsize);
        send(client_fd, header, strlen(header), 0);

        char buf[1024];
        size_t n;
        while ((n = fread(buf, 1, sizeof(buf), file)) > 0) {
            send(client_fd, buf, n, 0);
        }
        fclose(file);

        shutdown(client_fd, SHUT_RDWR);
        close(client_fd);
    }

    return NULL;
}


int main() {
    load_config();

    int should_redirect = (ALLOW_SSH && ONLY_HTTPS);  // redirect only if BOTH true

    // Handle invalid state: ONLY_HTTPS=1 but no SSH
    if (!ALLOW_SSH && ONLY_HTTPS) {
        printf("Cannot run in HTTPS-only mode because ALLOW_SSH=0. Exiting.\n");
        return 1;
    }

    pthread_t http_thread;

    // if (ONLY_HTTPS || !ALLOW_SSH) {
        pthread_create(&http_thread, NULL, start_http_server, &should_redirect);

        // If HTTPS is not allowed, only run HTTP
        if (!ALLOW_SSH) {
            pthread_join(http_thread, NULL);
            return 0;
        }

    // }

    // HTTPS setup
    SSL_library_init();
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) ||
        !SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM)) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(HTTPS_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    bind(server_fd, (struct sockaddr *)&addr, sizeof(addr));
    listen(server_fd, 10);
    printf("HTTPS server listening on port %d\n", HTTPS_PORT);

    while (1) {
        int client_fd = accept(server_fd, NULL, NULL);
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_fd);
        if (SSL_accept(ssl) <= 0) {
            SSL_free(ssl);
            close(client_fd);
            continue;
        }

        pthread_t tid;
        pthread_create(&tid, NULL, handle_client, ssl);
        pthread_detach(tid);
    }

    SSL_CTX_free(ctx);
    close(server_fd);
    return 0;
}
