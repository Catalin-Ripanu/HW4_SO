/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef _CMD_H
#define _CMD_H

#include <unistd.h>
#include "../util/parser/parser.h"

#define SHELL_EXIT -100
#define CHUNK_SIZE 1024

/**
 * Parse and execute a command.
 */
int parse_command(command_t *cmd, int level, command_t *father);

#endif /* _CMD_H */
