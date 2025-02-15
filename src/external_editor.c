#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "error.h"
#include "eval.h"
#include "external_editor.h"
#include "input.h"
#include "jobs.h"
#include "memalloc.h"
#include "options.h"
#include "parser.h"
#include "shell.h"
#include "syntax.h"

int use_external_editor = 0;
char dash_session_id[ULID_SIZE] = "";
struct command_info cmd_info = {0};

/* Structure to hold editor output */
struct editor_output {
  char *buffer;
  size_t length;
};

static const char ENCODING[32] = {'0', '1', '2', '3', '4', '5', '6', '7',
                                  '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
                                  'G', 'H', 'J', 'K', 'M', 'N', 'P', 'Q',
                                  'R', 'S', 'T', 'V', 'W', 'X', 'Y', 'Z'};

static int generate_ulid(char *ulid, size_t size) {
  if (!ulid || size < ULID_SIZE) {
    return -1;
  }

  struct timespec ts;
  if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
    return -1;
  }

  uint64_t timestamp =
      ((uint64_t)ts.tv_sec * 1000) + ((uint64_t)ts.tv_nsec / 1000000);

  for (int i = 9; i >= 0; i--) {
    ulid[i] = ENCODING[timestamp & 0x1F];
    timestamp >>= 5;
  }

  for (int i = 10; i < 26; i++) {
    ulid[i] = ENCODING[arc4random() & 0x1F];
  }

  ulid[26] = '\0';
  return 0;
}

/*
 * Get path to external editor from environment
 */
char *get_editor_path(void) {
  DEBUG_LOG("Getting editor path");
  char *editor = getenv("DASH_LINE_EDITOR");
  return editor;
}

/*
 * Check if editor path is valid and secure
 */
int check_editor_path(const char *path) {
  char errmsg[PATH_MAX + 256];

  if (path == NULL) {
    return 0; /* Invalid path */
  }

  /* Check if path points to a regular file */
  struct stat sb;
  if (stat(path, &sb) != 0) {
    snprintf(errmsg, sizeof(errmsg),
             "dash: cannot stat external editor '%s': %s\n", path,
             strerror(errno));
    out2str(errmsg);
    return 0;
  }
  if (!S_ISREG(sb.st_mode)) {
    snprintf(errmsg, sizeof(errmsg),
             "dash: external editor '%s' is not a regular file\n", path);
    out2str(errmsg);
    return 0;
  }

  /* Check if the path is executable */
  if (access(path, X_OK) != 0) {
    snprintf(errmsg, sizeof(errmsg),
             "dash: cannot execute external editor '%s': %s\n", path,
             strerror(errno));
    out2str(errmsg);
    return 0;
  }

  return 1; /* Valid path */
}

/* Helper function to free editor output */
void free_editor_output(struct editor_output *output) {
  if (output) {
    if (output->buffer) {
      ckfree(output->buffer);
    }
    ckfree(output);
  }
}

/*
 * Read editor output from pipe
 */
struct editor_output *editor_read_output(int fd) {
  struct editor_output *output;
  char readbuf[BUFSIZ];
  size_t bufsize = 0;
  size_t total = 0;
  char *colon_pos = NULL;
  int found_separator = 0;

  output = ckmalloc(sizeof(*output));
  output->buffer = NULL;
  output->length = 0;

  while (1) {
    ssize_t n = read(fd, readbuf, sizeof(readbuf));
    if (n <= 0) {
      if (n < 0) {
        if (errno == EINTR) {
          DEBUG_LOG("Read interrupted by signal, retrying");
          continue;
        }
        DEBUG_LOG("Read failed: %s", strerror(errno));
        goto error;
      }
      // EOF
      break;
    }

    /* Check overflow */
    if (n > SIZE_MAX - total - 1) {
      goto error;
    }

    if (total + n + 1 > bufsize) {
      size_t newsize = bufsize * 2;
      if (newsize < bufsize || newsize < (total + n + 1)) {
        // Either multiplication overflow or still not big enough
        goto error;
      }

      char *newbuf = ckrealloc(output->buffer, newsize);
      if (!newbuf) {
        goto error;
      }
      output->buffer = newbuf;
      bufsize = newsize;
    }

    memcpy(output->buffer + total, readbuf, n);
    total += n;
    output->buffer[total] =
        '\0'; // Ensure null termination for string operations

    // Look for ULID:command separator if not found yet
    if (!found_separator && total >= ULID_SIZE) {
      colon_pos = memchr(output->buffer, COMMAND_SEPARATOR, total);
      if (colon_pos && (colon_pos - output->buffer) == ULID_SIZE - 1) {
        // We found the separator at the expected position
        found_separator = 1;

        // Copy ULID to command_info
        memcpy(cmd_info.prev_command_id, output->buffer, ULID_SIZE - 1);
        cmd_info.prev_command_id[ULID_SIZE - 1] = '\0';

        DEBUG_LOG("Found command ID: %s", cmd_info.prev_command_id);

        // Move the actual command to the start of the buffer
        size_t cmd_start = ULID_SIZE; // ULID + separator
        memmove(output->buffer, output->buffer + cmd_start, total - cmd_start);
        total -= cmd_start;

        // Null terminate the new shortened buffer
        output->buffer[total] = '\0';
      }
    }
  }

  if (total > 0) {
    output->buffer[total] = '\0';
    output->length = total;
    return output;
  }

error:
  free_editor_output(output);
  return NULL;
}

/*
 * Format environment variables for dashed process with hardcoded test values
 * Returns 0 on success, -1 on error
 */

char **format_dashed_env(void) {
  extern char **environ;
  size_t env_count = 0;
  size_t i = 0;
  char **envp;
  char numbuf[32]; /* Buffer for number conversions */

  while (environ[env_count] != NULL) {
    env_count++;
  }

  envp = malloc(sizeof(char *) * (env_count + DASHED_ENV_COUNT + 1));
  if (!envp) {
    return NULL;
  }

  // Copy all existing environment variables
  for (i = 0; i < env_count; i++) {
    envp[i] = strdup(environ[i]);
    if (!envp[i]) {
      goto error;
    }
  }

  if (!dash_session_id[0]) {
    DEBUG_LOG("Session ID not initialized");
    goto error;
  }

  /* Format each environment variable with collected values */
  if (asprintf(&envp[i++], "%s=%s", ENV_SESSION_ID, dash_session_id) < 0)
    goto error;

  /* The protocol is to leave the command ID blank if it's not available */
  if (asprintf(&envp[i++], "%s=%s", ENV_PREV_COMMAND_ID,
               cmd_info.prev_command_id[0] ? cmd_info.prev_command_id : "") < 0)
    goto error;

  /* Convert timespec to microseconds since epoch and format as string */
  if (cmd_info.prev_command_id[0]) {
    uint64_t start_us = ((uint64_t)cmd_info.prev_start.tv_sec * 1000000) +
                        ((uint64_t)cmd_info.prev_start.tv_nsec / 1000);
    snprintf(numbuf, sizeof(numbuf), "%" PRIu64, start_us);
  } else {
    numbuf[0] = '\0';
  }
  if (asprintf(&envp[i++], "%s=%s", ENV_PREV_START, numbuf) < 0)
    goto error;

  /* Format duration */
  if (cmd_info.prev_command_id[0]) {
    snprintf(numbuf, sizeof(numbuf), "%ld", cmd_info.prev_duration);
  } else {
    numbuf[0] = '\0';
  }
  if (asprintf(&envp[i++], "%s=%s", ENV_PREV_DURATION, numbuf) < 0)
    goto error;

  /* Use collected working directory */
  if (asprintf(&envp[i++], "%s=%s", ENV_PREV_CWD,
               cmd_info.prev_command_id[0] && cmd_info.prev_cwd[0]
                   ? cmd_info.prev_cwd
                   : "") < 0)
    goto error;

  if (cmd_info.prev_command_id[0]) {
    snprintf(numbuf, sizeof(numbuf), "%d", cmd_info.prev_exit_code);
  } else {
    numbuf[0] = '\0';
  }
  if (asprintf(&envp[i++], "%s=%s", ENV_PREV_EXIT_CODE, numbuf) < 0)
    goto error;

  envp[i] = NULL; /* NULL terminator */

  DEBUG_LOG("Environment variables set with total count: %zu", i);

  return envp;

error:
  while (i > 0) {
    free(envp[--i]);
  }
  free(envp);
  return NULL;
}

static void free_env(char **envp) {
  if (envp) {
    for (int i = 0; envp[i] != NULL; i++) {
      free(envp[i]);
    }
    free(envp);
  }
}

/*
 * Start editor process and setup job control
 */
int editor_start_process(const char *editor_path, int write_fd,
                         struct job *jp) {
  pid_t pid;

  // Format environment variables
  char **envp = format_dashed_env();
  if (!envp) {
    DEBUG_LOG("Failed to format environment variables");
    return -1;
  }

  pid = fork();
  if (pid < 0) {
    DEBUG_LOG("Fork failed: %s", strerror(errno));
    free_env(envp);
    return -1;
  }

  if (pid == 0) {
    /* Child - editor process */
    if (write_fd != 1) {
      if (dup2(write_fd, 1) < 0) {
        DEBUG_LOG("Failed to duplicate fd: %s", strerror(errno));
        _exit(EDITOR_EXIT_EXEC_FAILED);
      }
      close(write_fd);
    }
    int max_fd = sysconf(_SC_OPEN_MAX);
    if (max_fd > 0) {
      for (int fd = 3; fd < max_fd; fd++) {
        close(fd);
      }
    }

    execle(editor_path, editor_path, (char *)0, envp);
    DEBUG_LOG("Failed to execute editor %s: %s", editor_path, strerror(errno));
    _exit(EDITOR_EXIT_EXEC_FAILED);
  }

  /* Parent - setup job info */
  struct procstat *ps = &jp->ps[jp->nprocs++];
  ps->pid = pid;
  ps->status = -1;
  ps->cmd = nullstr;

  free_env(envp);
  return pid;
}

/*
 * Wait for editor process to complete
 */
int editor_wait(pid_t pid) {
  int status;

  DEBUG_LOG("Waiting for editor process pid=%d", pid);
  while (waitpid(pid, &status, 0) == -1) {
    if (errno != EINTR) {
      DEBUG_LOG("Waitpid failed: %s", strerror(errno));
      break;
    }
  }
  DEBUG_LOG("Done waiting for editor process pid=%d", pid);

  return status;
}

/*
 * Process editor exit status and convert to result code
 */
enum external_editor_result editor_process_status(int status) {
  if (!WIFEXITED(status)) {
    DEBUG_LOG("Editor terminated abnormally");
    return EXTERNAL_EDITOR_ERROR;
  }

  int exit_status = WEXITSTATUS(status);
  DEBUG_LOG("Editor exit status: %d", exit_status);

  switch (exit_status) {
  case EDITOR_EXIT_SUCCESS:
    return EXTERNAL_EDITOR_SUCCESS;
  case EDITOR_EXIT_EOF:
    return EXTERNAL_EDITOR_EOF;
  default:
    return EXTERNAL_EDITOR_ERROR;
  }
}

/*
 * Handle editor output according to result
 */
void editor_handle_output(struct editor_output *output,
                          enum external_editor_result result) {
  if (!output)
    return;

  if (!output->buffer)
    return;

  if (result == EXTERNAL_EDITOR_EOF) {
    tokpushback = 1;
    lasttoken = PEOF;
  }

  if (output->length > 0 &&
      (result == EXTERNAL_EDITOR_SUCCESS || result == EXTERNAL_EDITOR_EOF)) {
    DEBUG_LOG("Pushing input string: '%s'", output->buffer);
    pushstring(output->buffer, NULL);
  }

  ckfree(output->buffer);
  ckfree(output);
}

/* public functions */

/*
 * Check if we should use external editor based on:
 * - Input is from terminal
 * - DASH_LINE_EDITOR is set and valid
 * - Not in command substitution
 */
int should_use_external_editor(void) {
  DEBUG_LOG("Start checking if we should use external editor");
  char *editor_path;

  /* Don't use external editor if not interactive or in command substitution */
  if (!iflag || parsefile != &basepf) {
    DEBUG_LOG("Not interactive or in command substitution");
    return 0;
  }

  /* Check if input is from terminal */
  if (!stdin_istty) {
    DEBUG_LOG("Not a tty");
    return 0;
  }

  /* Get and validate editor path */
  editor_path = get_editor_path();
  if (!check_editor_path(editor_path)) {
    DEBUG_LOG("Invalid editor path");
    return 0;
  }

  /* Generate session ID if not already set */
  if (dash_session_id[0] == '\0') {
    if (generate_ulid(dash_session_id, ULID_SIZE) != 0) {
      DEBUG_LOG("Failed to generate session ID");
      return 0;
    }
    DEBUG_LOG("Generated new session ID: %s", dash_session_id);
  }

  return 1;
}

/*
 * Run external editor and process its output
 * Returns one of external_editor_result values
 */
int run_external_editor(void) {
  int pipefd[2] = {-1, -1};
  struct job *jp;
  pid_t pid;
  char *editor_path;
  int status = EXTERNAL_EDITOR_ERROR;
  struct editor_output *output = NULL;

  DEBUG_LOG("Starting external editor");

  /* Get editor path */
  editor_path = get_editor_path();
  if (!check_editor_path(editor_path)) {
    DEBUG_LOG("Invalid editor path");
    use_external_editor = 0;
    goto error;
  }

  if (pipe(pipefd) == -1) {
    DEBUG_LOG("Failed to create pipe: %s", strerror(errno));
    goto error;
  }

  INTOFF;
  jp = makejob(1);

  pid = editor_start_process(editor_path, pipefd[1], jp);
  if (pid < 0) {
    DEBUG_LOG("Failed to start editor process");
    goto cleanup_pipe;
  }

  close(pipefd[1]); /* Close write end in parent */
  pipefd[1] = -1;

  output = editor_read_output(pipefd[0]);
  if (!output) {
    DEBUG_LOG("Failed to read editor output");
  } else {
    DEBUG_LOG("Editor output: '%s'", output->buffer);
  }

  close(pipefd[0]);
  pipefd[0] = -1;

  status = editor_process_status(editor_wait(pid));
  if (status < 0) {
    goto cleanup;
  }

  editor_handle_output(output, status);

  INTON;
  return status;

cleanup_pipe:
  if (pipefd[0] >= 0)
    close(pipefd[0]);
  if (pipefd[1] >= 0)
    close(pipefd[1]);
cleanup:
  free_editor_output(output);
error:
  INTON;
  reset_input();
  return EXTERNAL_EDITOR_ERROR;
}

void collect_external_cmd_preexec(void) {
  /* Only collect info if external editor is enabled */
  if (!use_external_editor) {
    return;
  }

  /* If we already have command info, don't overwrite it */
  if (cmd_info.prev_cwd[0] != '\0') {
    return;
  }

  /* Record command start time */
  clock_gettime(CLOCK_REALTIME, &cmd_info.prev_start);

  /* Record current working directory */
  if (getcwd(cmd_info.prev_cwd, PATH_MAX) == NULL) {
    strcpy(cmd_info.prev_cwd, "/");
  }

  DEBUG_LOG("External command pre-execution info collected - cwd: %s",
            cmd_info.prev_cwd);
}

void collect_external_cmd_status(int status) {
  /* Only collect info if external editor is enabled */
  if (!use_external_editor) {
    return;
  }

  /* Record end time and calculate duration */
  struct timespec end_time;
  clock_gettime(CLOCK_REALTIME, &end_time);

  cmd_info.prev_duration =
      ((end_time.tv_sec - cmd_info.prev_start.tv_sec) * 1000000) +
      ((end_time.tv_nsec - cmd_info.prev_start.tv_nsec) / 1000);

  /* Record exit status */
  cmd_info.prev_exit_code = status;

  DEBUG_LOG(
      "External command execution completed - duration: %ld μs, status: %d",
      cmd_info.prev_duration, cmd_info.prev_exit_code);
}
