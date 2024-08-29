// SPDX-License-Identifier: BSD-3-Clause

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <sys/mman.h>

#include "cmd.h"
#include "utils.h"

#define READ 0
#define WRITE 1
#define DIM 256
static char shared_memory[CHUNK_SIZE];
static char output[CHUNK_SIZE];
static int verify;

/* Functia care construieste un bloc de memorie */
/* ce se partajeaza intre procese */

static void *shared_mem(size_t size)
{
	int visibility = MAP_SHARED | MAP_ANONYMOUS;

	int protection = PROT_READ | PROT_WRITE;

	return mmap(NULL, size, protection, visibility, -1, 0);
}

/* Functia care construieste o comanda, pas cu pas, folosind setarile aferente */

static void construct_command(simple_command_t *s, char *cmd_buffer, int var_cd, int signal, int redir_env,
					   struct word_t *aux_in, struct word_t *aux_out, struct word_t *aux_err)
{
	/* Daca comanda cuprinde argumente pentru redirectarea spre stdin */

	while (var_cd == -1 && aux_in) {
		strcat(cmd_buffer, " < ");
		strcat(cmd_buffer, aux_in->string);
		aux_in = aux_in->next_word;
	}

	/* Partea care se ocupa de procesarea */
	/* argumentelor pentru redirectarea spre stdout */
	int verif = 0;

	while (redir_env && var_cd == -1 && aux_out) {
		/* Daca exista variabile de mediu in prelucrare, */
		/* acestea se vor trata separat */

		if (!verif) {
			strcat(cmd_buffer, " > ");
			verif = 1;
		}
		if (aux_out->expand) {
			if (getenv(aux_out->string))
				strcat(cmd_buffer, getenv(aux_out->string));
		} else {
			strcat(cmd_buffer, aux_out->string);
		}
		aux_out = aux_out->next_part;
	}

	/* Daca comanda cuprinde argumente pentru redirectarea spre stdout */

	while (!signal && var_cd == -1 && aux_out) {
		/* Se trateaza cazul in care un argument apare atat la redirectarea */
		/* spre stdout, cat si la redirectarea spre stderr */

		if (aux_err && !strcmp(aux_out->string, aux_err->string)) {
			aux_err = aux_err->next_word;
			strcat(cmd_buffer, " 1> ");
			strcat(cmd_buffer, aux_out->string);
			strcat(cmd_buffer, " 2>&1 ");
		} else {
			if (s->io_flags == IO_OUT_APPEND)
				strcat(cmd_buffer, " >> ");
			else
				strcat(cmd_buffer, " > ");
			strcat(cmd_buffer, aux_out->string);
		}
		aux_out = aux_out->next_word;
	}

	aux_err = s->err;

	/* Daca comanda cuprinde argumente pentru redirectarea spre stderr */

	while (var_cd == -1 && aux_err) {
		/* Se sare peste acele argumente deja procesate in stdout */

		if (strstr(cmd_buffer, aux_err->string)) {
			aux_err = aux_err->next_word;
			continue;
		} else {
			if (s->io_flags == IO_ERR_APPEND)
				strcat(cmd_buffer, " 2>> ");
			else
				strcat(cmd_buffer, " 2> ");
			strcat(cmd_buffer, aux_err->string);
			aux_err = aux_err->next_word;
		}
	}
}

/* Functia care se ocupa de initializarea parametrilor comenzilor */

static void initialize_params(char *cmd_buffer, struct command_t *cmd)
{
	struct word_t *iter = cmd->scmd->params;
	struct word_t *aux_out_cmd = cmd->scmd->out;
	struct word_t *aux_in_cmd = cmd->scmd->in;
	struct word_t *aux_err_cmd = cmd->scmd->err;

	strcpy(cmd_buffer, cmd->scmd->verb->string);
	if (iter && strstr(iter->string, " "))
		strcat(cmd_buffer, " '");
	else
		strcat(cmd_buffer, " ");

	/* Partea care se ocupa de adaugarea argumentelor pentru a */
	/* putea construi comanda, pas cu pas */

	while (iter) {
		if (!strcmp(iter->string, " "))
			strcat(cmd_buffer, "' '");
		else
			strcat(cmd_buffer, iter->string);
		iter = iter->next_word;
		strcat(cmd_buffer, " ");
	}
	cmd_buffer[strlen(cmd_buffer) - 1] = '\0';

	if (cmd->scmd->params &&
		strstr(cmd->scmd->params->string, " "))
		strcat(cmd_buffer, "' ");
	else
		strcat(cmd_buffer, " ");

	construct_command(cmd->scmd, cmd_buffer, -1, 0, 0,
					  aux_in_cmd, aux_out_cmd, aux_err_cmd);
}

/* Functia care se ocupa de navigarea prin ierarhia sistemului de fisiere */
/* S-au tratat si implementat bonusurile legate de 'cd', din cerinta */

static bool shell_cd(word_t *dir)
{
	/* Daca se doreste navigarea spre directorul 'HOME' */

	if (!dir || !strcmp(dir->string, "~")) {
		char *curr_path = getcwd(NULL, 0);

		DIE(curr_path == NULL, "getcwd() error");
		DIE(setenv("OLDPWD", curr_path, 1) == -1, "setenv() error");
		DIE(chdir(getenv("HOME")) == -1, "chdir() error");
		DIE(setenv("PWD", getenv("HOME"), 1) == -1, "setenv() erorr");
		free(curr_path);
	} else if (!dir->next_word) {
		/* Daca se doreste navigarea spre directorul vechi */

		if (!strcmp(dir->string, "-")) {
			char *path = getenv("PWD");

			DIE(path == NULL, "getenv() error");
			DIE(chdir(getenv("OLDPWD")) == -1, "chdir() error");
			DIE(setenv("PWD", getenv("OLDPWD"), 1) == -1, "setenv() erorr");
			DIE(setenv("OLDPWD", path, 1) == -1, "setenv() erorr");

			/* Daca se doreste navigarea spre un anumit director */

		} else {
			/* Se salveaza calea spre directorul vechi */
			/* pentru a o putea refolosi */

			char *save_oldpwd = getenv("OLDPWD");

			DIE(save_oldpwd == NULL, "getenv() error");
			char *curr_path = getcwd(NULL, 0);

			DIE(curr_path == NULL, "getcwd() error");
			DIE(setenv("OLDPWD", curr_path, 1), "setenv() erorr");
			free(curr_path);
			int ver = chdir(dir->string);

			if (ver == -1) {
				DIE(setenv("OLDPWD", save_oldpwd, 1) == -1, "setenv() erorr");
				return 0;
			}
				curr_path = getcwd(NULL, 0);
				DIE(curr_path == NULL, "getcwd() error");
				DIE(setenv("PWD", curr_path, 1) == -1, "setenv() error");
				free(curr_path);
		}
	}

	return 1;
}

/* Functia care se ocupa de oprirea shell-ului */

static int shell_exit(void)
{
	return SHELL_EXIT;
}

/* Functia care se ocupa de parsarea unei comenzi simple */

static int parse_simple(simple_command_t *s, int level, command_t *father)
{
	if (!s)
		return SHELL_EXIT;
	void *cmd_buffer = shared_mem(CHUNK_SIZE);

	/* Daca se doreste iesirea din shell */

	if (!strcmp(s->verb->string, "exit") || !strcmp(s->verb->string, "quit")) {
		return shell_exit();

		/* Daca se doreste executarea unei simple comenzi de 'cd' */

	} else if (!strcmp(s->verb->string, "cd") &&
			 !s->out && !s->in && !s->err) {
		int var = shell_cd(s->params);

		if (!var)
			printf("no such file or directory\n");
		return var;
	}

	/* Partea care se ocupa de procesarea variabilelor de mediu */

	if (s->verb->next_part && !strcmp(s->verb->next_part->string, "=")) {
		if (s->verb->next_part->next_part->expand) {
			char cmd_helper[DIM];
			char *value = (char *)calloc(DIM, sizeof(char));

			DIE(!value, "malloc() failed");
			if (!strcmp(s->verb->next_part->next_part->string, "USER") &&
				!getenv(s->verb->next_part->next_part->string)) {
				*value = ' ';
			} else {
				DIE(!getenv(s->verb->next_part->next_part->string), "getenv() error");
				strcpy(value, getenv(s->verb->next_part->next_part->string));
			}

			/* Daca variabila respectiva exista deja */

			if (*value) {
				memset(cmd_helper, 0, sizeof(cmd_helper));
				if (*value != ' ')
					sprintf(cmd_helper, "%s", value);
				struct word_t *iter = s->verb->next_part->next_part->next_part;

				while (iter) {
					strcat(cmd_helper, iter->string);
					iter = iter->next_part;
				}

				/* Se facea atribuirea */

				free(value);
				DIE(setenv(s->verb->string, cmd_helper, 1) == -1, "setenv() error");
				sprintf((char *)cmd_buffer, "%s=%s", s->verb->string, cmd_helper);
				DIE(system((char *)cmd_buffer) == -1, "system() error");
				return 0;
			} else {
				return SHELL_EXIT;
			}
		} else {
			/* Daca nu exista, se face una noua */

			DIE(setenv(s->verb->string, s->verb->next_part->next_part->string, 1) == -1, "setenv() error");
			sprintf((char *)cmd_buffer, "%s=%s", s->verb->string, s->verb->next_part->next_part->string);
			DIE(system((char *)cmd_buffer) == -1, "system() error");
			sprintf((char *)cmd_buffer, "echo $%s", s->verb->string);
			DIE(system((char *)cmd_buffer) == -1, "system() error");
			return 0;
		}
	}

	/* Partea care se ocupa de construirea comenzilor */
	/* cu un nivel mai ridicat de complexitate */

	pid_t pid = fork();

	DIE(pid < -1, "fork() error");
	if (pid == 0) {
		int ret_cd = -1;
		int *size = (int *)malloc(sizeof(int));
		char **argv = get_argv(s, size);

		/* Inceputul procesarii unei comenzi de redirectare */
		/* ce contine comanda 'cd' */

		if (!strcmp(s->verb->string, "cd")) {
			strcpy((char *)s->params->string, argv[1]);
			ret_cd = shell_cd(s->params);
			if (!ret_cd) {
				strcpy(cmd_buffer, "echo 'no such file or directory' ");
			} else {
				strcpy((char *)s->params->string, "-");
				shell_cd(s->params);
				strcpy(cmd_buffer, "touch ");
				strcat(cmd_buffer, s->out->string);
			}

			/* Inceputul procesarii unei comenzi oarecare */

		} else {
			if (!strcmp(s->verb->string, "echo"))
				strcpy(cmd_buffer, "/bin/echo");
			else
				strcpy(cmd_buffer, s->verb->string);
		}

		/* Daca nu exista redirectari in comanda, */
		/* aceasta se executa in mod direct */

		if (!s->out && !s->in && !s->err) {
			free(size);
			int exit_status = WEXITSTATUS(execvp(cmd_buffer, argv));

			if (exit_status)
				printf("Execution failed for '%s'\n", (char *)cmd_buffer);
			exit(exit_status);
		} else {
			int expand_signal = 0;
			struct word_t *aux_out = s->out;
			struct word_t *aux_in = s->in;
			struct word_t *aux_err = s->err;

			while (aux_out) {
				if (aux_out->next_part && aux_out->next_part->expand)
					expand_signal = 1;
				if (!expand_signal)
					aux_out = aux_out->next_word;
				else
					aux_out = aux_out->next_part;
			}
			aux_out = s->out;
			aux_in = s->in;
			aux_err = s->err;

			/* Se adauga argumentele comenzii, daca exista */

			if (ret_cd == -1) {
				int i = 1;

				while (i <= *size - 1) {
					if (argv[i] && strcmp(argv[i], "..") != 0) {
						strcat(cmd_buffer, " '");
						strcat(cmd_buffer, argv[i]);
						strcat(cmd_buffer, "' ");
					}
					i++;
				}
			}

			/* Se construieste comanda folosind regulile stabilite anterior */

			construct_command(s, cmd_buffer, ret_cd,
							  expand_signal, expand_signal, aux_in, aux_out, aux_err);

			free(size);
			if (ret_cd == 1 || ret_cd == -1 ||
					(!ret_cd && (strstr(cmd_buffer, "2>")
							 || strstr(cmd_buffer, "2>&1")))) {
				exit(WEXITSTATUS(system(cmd_buffer)));

				/* Cazul in care exista redirectari intr-o comanda 'cd' */

			} else {
				memset(cmd_buffer, 0, sizeof((char *)cmd_buffer));
				strcpy(cmd_buffer, "touch ");

				/* Se produce executia unei comenzi 'touch' */
				/* pentru a reproduce integral comportamentul */
				/* shell-ului oficial */

				strcat(cmd_buffer, s->out->string);
				exit(WEXITSTATUS(system(cmd_buffer)));
			}
		}
	} else {
		int status;

		waitpid(pid, &status, 0);
		if (!strcmp(s->verb->string, "cd"))
			shell_cd(s->params);
		return WEXITSTATUS(status);
	}
}

/* Functia care se ocupa de executia in paralel a 2 comenzi */

static bool run_in_parallel(command_t *cmd1, command_t *cmd2, int level,
							command_t *father)
{
	/* Se formeaza alte 2 procese pentru a executa cele 2 comenzi */

	pid_t pid1 = fork();

	DIE(pid1 < -1, "fork() error");
	if (pid1 == 0) {
		exit(WEXITSTATUS(parse_command(cmd1, level, father)));
	} else {
		pid_t pid2 = fork();

		DIE(pid2 < -1, "fork() error");
		if (pid2 == 0) {
			exit(WEXITSTATUS(parse_command(cmd2, level, father)));
		} else {
			int status1, status2;

			/* Se asteapta terminarea proceselor */

			waitpid(pid1, &status1, 0);
			waitpid(pid2, &status2, 0);
			if (WEXITSTATUS(status1) || WEXITSTATUS(status2))
				return 0;
			return 1;
		}
	}
}

/* Functia care se ocupa de construirea unui pipe anonim pentru */
/* ca 2 procese sa comunice intre ele */

static bool run_on_pipe(command_t *cmd1, command_t *cmd2, int level,
						command_t *father)
{
	int pipefd[2];

	/* Se construieste pipe-ul */

	DIE(pipe(pipefd) == -1, "pipe error");
	pid_t pid = -1;

	if (cmd1->scmd) {
		pid = fork();
		DIE(pid == -1, "fork() error");
	}
	if (pid == 0) {
		close(pipefd[0]);
		char cmd1_buffer[CHUNK_SIZE];

		/* Procesul invocat construieste comanda din stanga pipe-ului */

		memset(cmd1_buffer, 0, sizeof(cmd1_buffer));
		initialize_params(cmd1_buffer, cmd1);
		strcat(cmd1_buffer, "| ");

		/* Transmite informatia pe canalul respectiv */

		DIE(write(pipefd[1], cmd1_buffer, CHUNK_SIZE) == -1, "write() error");
		close(pipefd[1]);
		exit(EXIT_SUCCESS);
	} else {
		close(pipefd[1]);
		char cmd2_buffer[CHUNK_SIZE];

		memset(cmd2_buffer, 0, sizeof(cmd2_buffer));
		int status = 0;

		if (cmd1->scmd) {
			waitpid(pid, &status, 0);
			if (status)
				return WEXITSTATUS(status);
		}

		/* Procesul parinte construieste comanda din dreapta pipe-ului */

		initialize_params(cmd2_buffer, cmd2);
		strcat(cmd2_buffer, " ");
		if (cmd1->scmd) {
			/* Procesul parinte citeste informatia de pe canal */

			DIE(read(pipefd[0], shared_memory, CHUNK_SIZE) == -1, "read() error");
		} else {
			verify = 1;
			strcat(shared_memory, "| ");
		}
		strncat(shared_memory, cmd2_buffer, CHUNK_SIZE);
		pid_t pid2 = fork();

		/* Parintele invoca un alt proces pentru a executa intreaga comanda */
		/* ce contine operatorul '|' */

		if (pid2 == 0) {
			int ret = execl("/bin/bash", "bash", "-c", shared_memory, (char *)0);

			DIE(ret == -1, "execl() error");

			/* Se citeste iesirea comenzii pentru a o afisa in terminal */

			int val = read(1, output, CHUNK_SIZE);

			DIE(val == -1, "read() error");
			output[val] = '\0';
			if ((!cmd1->scmd && !cmd2->scmd->out) || !verify)
				DIE(write(1, output, strlen(output)) == -1, "write() error");
			exit(WEXITSTATUS(ret));
		} else {
			waitpid(pid2, &status, 0);
			close(pipefd[0]);
			return WEXITSTATUS(status);
		}
	}
}

/* Functia care se ocupa de parsarea unei comenzi */

int parse_command(command_t *c, int level, command_t *father)
{
	/* Se pregateste zona de memorie care retine */
	/* urmatoarea iesire a unei comenzi */

	strcpy(shared_memory, " ");
	if (!c)
		return SHELL_EXIT;

	static int ret_value = 1;

	/* Se trateaza fiecare varianta de comanda */

	if (c->op == OP_NONE)
		return parse_simple(c->scmd, level, father);

	command_t *com = c;

	switch (com->op) {
	case OP_SEQUENTIAL:
	{
		/* Cazul in care trebuie sa se avanseze spre frunzele arborelui */
		/* ce se formeaza pe baza comenzilor */

		if (!com->cmd1->scmd)
			ret_value = parse_command(com->cmd1, level, father);
		else
			ret_value = parse_simple(com->cmd1->scmd, level, father);

		if (!com->cmd2->scmd)
			ret_value = parse_command(com->cmd2, level, father);
		else
			ret_value = parse_simple(com->cmd2->scmd, level, father);
	}
	break;

	case OP_PARALLEL:
	{
		ret_value = run_in_parallel(com->cmd1, com->cmd2, level, father);
	}
	break;

	case OP_CONDITIONAL_NZERO:
	{
		/* Cazul in care trebuie sa se avanseze spre frunzele arborelui */
		/* ce se formeaza pe baza comenzilor */

		if (!com->cmd1->scmd)
			ret_value = parse_command(com->cmd1, level, father);
		else
			ret_value = parse_simple(com->cmd1->scmd, level, father);
		if (!com->cmd2->scmd) {
			ret_value = parse_command(com->cmd2, level, father);
		} else {
			/* Se verifica daca ultima comanda a intors */
			/* un cod de eroare diferit de 0 */
			/* Se trateaza separat cazul pentru 'cd' */

			if ((ret_value && !com->cmd1->scmd) ||
				(com->cmd1->scmd &&
				 ((ret_value && strcmp(com->cmd1->scmd->verb->string, "cd")) ||
				  (!ret_value && !strcmp(com->cmd1->scmd->verb->string, "cd")))))
				ret_value = parse_simple(com->cmd2->scmd, level, father);
		}
	}
	break;

	case OP_CONDITIONAL_ZERO:
	{
		/* Cazul in care trebuie sa se avanseze spre frunzele arborelui */
		/* ce se formeaza pe baza comenzilor */

		if (!com->cmd1->scmd)
			ret_value = parse_command(com->cmd1, level, father);
		else
			ret_value = parse_simple(com->cmd1->scmd, level, father);
		if (!com->cmd2->scmd) {
			ret_value = parse_command(com->cmd2, level, father);
		} else {
			/* Se verifica daca ultima comanda a intors */
			/* un cod de eroare egal cu 0 */
			/* Se trateaza separat cazul pentru 'cd' */

			if ((!ret_value && !com->cmd1->scmd) ||
				(com->cmd1->scmd &&
				 ((!ret_value && strcmp(com->cmd1->scmd->verb->string, "cd")) ||
				  (ret_value && !strcmp(com->cmd1->scmd->verb->string, "cd")))))
				ret_value = parse_simple(com->cmd2->scmd, level, father);
		}
	}
	break;

	case OP_PIPE:
	{
		/* Cazul in care trebuie sa se avanseze spre frunzele arborelui */
		/* ce se formeaza pe baza comenzilor */

		verify = 0;
		if (!com->cmd1->scmd)
			ret_value = parse_command(com->cmd1, level, father);
		if (!com->cmd2->scmd)
			ret_value = parse_command(com->cmd2, level, father);

		ret_value = run_on_pipe(com->cmd1, com->cmd2, level, father);
	}
	break;

	default:
		return SHELL_EXIT;
	}
	return ret_value;
}
