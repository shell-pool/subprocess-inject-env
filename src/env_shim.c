//
// This file gets compiled to env_shim.so by build.rs,
// then injected into subprocesses to create the hook.
//
// It is passed in arguments via environment variables,
// and based on those arguments it starts listening on
// the given unix domain socket, checking that anyone
// who connects has the correct pid. It then reads
// requests using a simple framing protocol and calls
// setenv() returning the response code on the same
// unix socket stream.

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

const char* PASSWORD = "SUBPROCESS_INJECT_ENV__ARG__PASSWORD";
#define PASSWORD_LEN 32

const char* CONTROL_SOCK = "SUBPROCESS_INJECT_ENV__ARG__CONTROL_SOCK";

// protocol:
// auth msg: [32 byte password]
//  - the parent generates the password on spawn and it gets passed down
//    as an env-var parameter.
// setenv request: [4 byte host endian key length][4 byte host endian value length][key][value]
// setenv response: [4 byte host endian setenv return code]

//
// Utility Routines
//

void shim_logf(const char* template, ...) {
  // Fill this in with writing to a file or something if needed
  // for debugging. For now we just drop everything.
}

ssize_t read_all(int fd, void* buffer, size_t count) {
  uint8_t* buf = (uint8_t*)buffer;
  ssize_t bytes = 0;
  while (true) {
    const ssize_t nread = read(fd, &buf[bytes], count - bytes);
    if (nread == -1) {
      return -1;
    }
    bytes += nread;
    if (bytes >= count) {
      return bytes;
    }
  }
}

ssize_t write_all(int fd, void* buffer, size_t count) {
  uint8_t* buf = (uint8_t*)buffer;
  ssize_t bytes = 0;
  while (true) {
    const ssize_t nwritten = write(fd, &buf[bytes], count - bytes);
    if (nwritten == -1) {
      return -1;
    }
    bytes += nwritten;
    if (bytes >= count) {
      return bytes;
    }
  }
}

//
// Server Loop
//

typedef struct {
  int server_fd;
  char password[PASSWORD_LEN];
  // char password[32];
} env_server_args;

void* env_server_loop_thread(void* arg) {
  const env_server_args* args = (env_server_args*)arg;

  while (true) {
    int client_fd = accept(args->server_fd, NULL, NULL);
    if (client_fd == -1) {
        shim_logf("ERROR: accepting connection");
        continue;
    }

    char password[PASSWORD_LEN];
    if (read_all(client_fd, password, PASSWORD_LEN) != PASSWORD_LEN) {
        close(client_fd);
        shim_logf("ERROR: reading password");
        continue;
    }
    if (strncmp(password, args->password, PASSWORD_LEN) != 0) {
      close(client_fd);
      shim_logf("ERROR: access denied (bad password)");
      continue;
    }

    // read request header
    uint32_t key_len, value_len;
    if (read_all(client_fd, &key_len, sizeof(key_len)) != sizeof(key_len) ||
        read_all(client_fd, &value_len, sizeof(value_len)) != sizeof(value_len)) {
        close(client_fd);
        shim_logf("ERROR: reading key and value lengths");
        continue;
    }

    char* key = (char*)malloc(key_len+1);
    char* value = (char*)malloc(value_len+1);
    if (read_all(client_fd, key, key_len) != key_len ||
        read_all(client_fd, value, value_len) != value_len) {
        close(client_fd);
        shim_logf("ERROR: reading key and value");
        continue;
    }
    key[key_len] = '\0'; 
    value[value_len] = '\0';

    // Set Environment Variable
    int32_t ret = setenv(key, value, 1);
    if (ret == -1) {
      shim_logf("ERROR: setenv error (errno=%d)", errno);
      ret = errno;
    }
    free(key);
    free(value);

    // Send Response
    if (write_all(client_fd, &ret, sizeof(ret)) != sizeof(ret)) {
      shim_logf("ERROR: writing response");
    }

    close(client_fd);
  }

  close(args->server_fd);
  free(arg);
  return NULL;
}

//
// Entrypoint
//

__attribute__((constructor)) void init() {
  const char* password = getenv(PASSWORD);
  if (!password) {
    shim_logf("ERROR: no password param");
    return;
  }
  assert(strlen(password) == PASSWORD_LEN);

  const char* control_sock = getenv(CONTROL_SOCK);
  if (!control_sock) {
    shim_logf("ERROR: no control_sock param");
    return;
  }

  // . Create Unix Domain Socket Server
  int server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (server_fd == -1) {
    shim_logf("ERROR: creating socket");
    return;
  }

  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, control_sock, sizeof(addr.sun_path) - 1);
  unlink(control_sock); // Ensure the socket path is not in use

  if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
    close(server_fd);
    shim_logf("ERROR: binding socket");
    return;
  }

  if (listen(server_fd, 5) == -1) {
    close(server_fd);
    shim_logf("ERROR: listening on socket");
    return;
  }

  env_server_args* server_args = (env_server_args*)malloc(sizeof(env_server_args));
  server_args->server_fd = server_fd;
  memmove(server_args->password, password, PASSWORD_LEN);
  pthread_t thread_id;
  int result = pthread_create(&thread_id, NULL, env_server_loop_thread, server_args);
  if (result != 0) {
    shim_logf("ERROR: creating server thread (result=%d)", result);
  }
}
