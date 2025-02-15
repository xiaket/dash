/*
 * Interface for external editor functionality.
 */

#ifndef EXTERNAL_EDITOR_H
#define EXTERNAL_EDITOR_H

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include "output.h"

#define DASHED_ENV_COUNT 6
#define DASHED_ENV_SIZE (DASHED_ENV_COUNT + 1)  /* +1 for NULL terminator */

/* ULID constants */
#define ULID_SIZE 27 // 26 chars + null terminator
#define COMMAND_SEPARATOR ':'  // Separator between ULID and command in output

/* Environment variable names */
#define ENV_SESSION_ID "DASHED_SESSION_ID"
#define ENV_PREV_COMMAND_ID "DASHED_PREV_COMMAND_ID"
#define ENV_PREV_START "DASHED_PREV_START"
#define ENV_PREV_DURATION "DASHED_PREV_DURATION"
#define ENV_PREV_CWD "DASHED_PREV_CWD"
#define ENV_PREV_EXIT_CODE "DASHED_PREV_EXIT_CODE"

/* Exit codes for editor process */
#define EDITOR_EXIT_SUCCESS 0				/* Normal completion */
#define EDITOR_EXIT_EOF 131					/* Editor signals EOF */
#define EDITOR_EXIT_EXEC_FAILED 127	/* Editor executable/setup failed */

/* Flag to suggest whether to use an external editor */
extern int use_external_editor;

/* Structure to hold command execution information */
struct command_info {
  char prev_command_id[ULID_SIZE]; /* Previous command ULID from dashed */
  struct timespec prev_start;      /* Previous command start time */
  long prev_duration;              /* Previous command duration in ms */
  char prev_cwd[PATH_MAX];         /* Previous working directory */
  int prev_exit_code;              /* Previous command exit status */
};

extern struct command_info cmd_info;

/* Debug logging support */
static int debug_enabled = -1;

static int __attribute__((used)) is_debug_enabled(void) {
  if (debug_enabled == -1) {
    const char *debug_env = getenv("DASH_EXTERNAL_EDITOR_DEBUG");
    debug_enabled = debug_env && *debug_env;
  }
  return debug_enabled;
}

#define DEBUG_LOG(fmt, ...) \
  do { \
    if (is_debug_enabled()) { \
      char debug_buf[256]; \
      snprintf(debug_buf, sizeof(debug_buf), "[DEBUG] " fmt "\n", ##__VA_ARGS__); \
      out2str(debug_buf); \
    } \
  } while (0)

/* Result codes for editor execution */
enum external_editor_result {
  EXTERNAL_EDITOR_SUCCESS = 0,		 /* Normal completion */
  EXTERNAL_EDITOR_EOF = 1,				 /* Editor requests EOF */
  EXTERNAL_EDITOR_ERROR = -1,			/* Error occurred */
};

/* Public functions */

/* 
 * Run the external editor and process its output.
 * Returns one of external_editor_result values.
 */
int run_external_editor(void);

/*
 * Check if external editor should be used for the current input.
 * Returns non-zero if editor should be used, zero otherwise.
 */
int should_use_external_editor(void);

/*
 * Collect working directory and invocation started time for the external editor.
 */
void collect_external_cmd_preexec(void);

/*
 * Collect exit status for the external editor.
*/
void collect_external_cmd_status(int status);

#ifdef UNIT_TESTING
/* Internal functions exposed for testing */
struct editor_output {
    char *buffer;
    size_t length;
};

struct job;

char *get_editor_path(void);
int check_editor_path(const char *path);
struct editor_output *editor_read_output(int fd);
int editor_process_status(int status);
void editor_handle_output(struct editor_output *output, enum external_editor_result result);
void free_editor_output(struct editor_output *output);
int editor_start_process(const char *editor_path, int write_fd, struct job *jp);
int format_dashed_env(char **envp, size_t size);
int editor_wait(pid_t pid);
#endif /* UNIT_TESTING */

#endif /* EXTERNAL_EDITOR_H */
