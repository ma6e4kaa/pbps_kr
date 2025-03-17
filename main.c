#include "httpd.h"
#include "auth.h"
#include <sys/stat.h>
#include <stdio.h>
#include <syslog.h>

#define CHUNK_SIZE 1024 // read 1024 bytes at a time

// Public directory settings
#define INDEX_HTML "/index.html"
#define NOT_FOUND_HTML "/404.html"

char PUBLIC_DIR[255] = "./webroot";

int main(int c, char **v) {
  char *port = (c > 1) ? v[1] : "8000";

  if (c > 2) {
    strncpy(PUBLIC_DIR, v[2], sizeof(PUBLIC_DIR) - 1);
    PUBLIC_DIR[sizeof(PUBLIC_DIR) - 1] = '\0';
  }

  syslog(LOG_INFO, "Starting server on port %s with root directory: %s\n", port, PUBLIC_DIR);
  serve_forever(port);
  return 0;
}

int file_exists(const char *file_name) {
  struct stat buffer;
  int exists;

  exists = (stat(file_name, &buffer) == 0);

  return exists;
}

int read_file_size(const char *file_name) {
  struct stat st;
  if (stat(file_name, &st) == 0)
    return st.st_size;
  return -1;
}

int read_file(const char *file_name) {
  char buf[CHUNK_SIZE];
  FILE *file;
  size_t nread;
  int err = 1;

  file = fopen(file_name, "r");

  if (file) {
    while ((nread = fread(buf, 1, sizeof buf, file)) > 0)
      fwrite(buf, 1, nread, stdout);

    err = ferror(file);
    fclose(file);
  }
  return err;
}

void route_check_auth(const char *auth_header) {
    if (!check_auth(auth_header)) {
      int lenght = HTTP_401;
      log_request("GET", "/", 401, lenght);
      return;
    }
}

void route() {
  ROUTE_START()

  GET("/") {
    const char *auth_header = request_header("Authorization");

    route_check_auth(auth_header);

    char index_html[32];
    sprintf(index_html, "%s%s", PUBLIC_DIR, INDEX_HTML);

    int lenght = HTTP_200;
    if (file_exists(index_html)) {
      lenght += read_file_size(index_html);
      read_file(index_html);
      log_request("GET", "/", 200, lenght);
    } else {
      lenght += printf("Hello! You are using %s\n\n", request_header("User-Agent"));
      log_request("GET", "/", 200, lenght);
    }
  }

  GET("/test") {
    const char *auth_header = request_header("Authorization");

    route_check_auth(auth_header);

    int lenght = HTTP_200;
    lenght += printf("List of request headers:\n\n");

    header_t *h = request_headers();

    while (h->name) {
      lenght += printf("%s: %s\n", h->name, h->value);
      h++;
    }
    log_request("GET", "/test", 200, lenght);
  }

  POST("/") {
    const char *auth_header = request_header("Authorization");

    route_check_auth(auth_header);

    int lenght = HTTP_201;
    lenght += printf("Wow, seems that you POSTed %d bytes.\n", payload_size);
    lenght += printf("Fetch the data using `payload` variable.\n");
    if (payload_size > 0)
      lenght += printf("Request body: %s", payload);
    log_request("POST", "/", 201, lenght);
  }

  GET(uri) {
    const char *auth_header = request_header("Authorization");

    route_check_auth(auth_header);

    char file_name[255];
    sprintf(file_name, "%s%s", PUBLIC_DIR, uri);

    if (file_exists(file_name)) {
      int lenght = HTTP_200 + read_file_size(file_name);
      read_file(file_name);
      log_request("GET", uri, 200, lenght);
    } else {
      int lenght = HTTP_404;
      sprintf(file_name, "%s%s", PUBLIC_DIR, NOT_FOUND_HTML);
      if (file_exists(file_name)) {
        lenght += read_file_size(file_name);
        read_file(file_name);
      }
      log_request("GET", uri, 404, lenght);
    }
  }

  ROUTE_END()
}
