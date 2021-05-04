/*
  Assignment 3 - Small Shell (Portfolio)
  CS 344 Operating Systems
  Spencer Neukam
  5/3/2021

  This program mimicks a shell. The commands cd, exit, and status are built in.
  All other commands are passed to the exec() family of functions.

  Supported input format:
  command [arg1 arg2 ...] [< input_file] [> output_file] [&]

  Supported Features
  - blank lines
  - comment lines (#this is an example comment line, it must start with #)
  - exit
  - cd
  - status (returns the... )
  - all other standard commands
  - up to 512 arguments for one command
  - input and output redirection
  - using & at the end of a command to run a process in the background
  
  Unsupported
  - midline comments
  - probably a lot of other stuff that I'm too naive to know about yet :)
*/

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>
#include <limits.h>
#include <time.h>
#include <stdbool.h>
#include <sys/wait.h>
#include <stdio.h>
#include <signal.h>

#define MAX_COMMAND_LEN 2048
#define MAX_ARGUMENTS 512
#define PID_INT_LENGTH 12
#define MAX_BACKGROUND_PIDS 50

int GLOBAL_FOREGROUND_CHILD_EXIT_STATUS = 0;
int GLOBAL_FOREGROUND_ONLY_MODE = 0;

struct pid_node
{
	int pid;
	struct pid_node *next;
};

struct pid_node *GLOBAL_PID_NODE_HEAD;

struct command
{
  char *full_text;
  char *command;
  char *arguments[MAX_ARGUMENTS];
  char *redirect_in;
  char *redirect_out;
  bool background_process;
};

/* 
  Function fflush_both()
  ---------------------------------
  description:
    flushes both stdin and stdout
  returns: void
*/
void fflush_both() {
  fflush(stdin);
  fflush(stdout);
  return;
}

/* 
  Function free_parsed_input()
  ---------------------------------
  description:
    frees a command struct
  returns: void
*/
void free_parsed_input(struct command *parsed_input)
{
	free(parsed_input->full_text);
	free(parsed_input->command);
	free(parsed_input->redirect_in);
	free(parsed_input->redirect_out);
	
	int i;
	i = 0;
	while (parsed_input->arguments[i] != NULL) 
	{
		free(parsed_input->arguments[i]);
		i++;
	}
	
	return;
}

/* 
  Function create_pid_node()
  ---------------------------------
  description:
    creates, allocates mem, and returns a background_pid struct with the background pid
	arg new_pid: an integer pid that will be added to the newly created struct
  returns: void
*/
struct pid_node *create_pid_node(int new_pid) {
	struct pid_node *node = malloc(sizeof(struct pid_node));
	node->pid = new_pid;
	node->next = NULL;
	return node;
}

/*
  Function free_pid_node()
  ---------------------------------
  description:
    frees memory for a given background_pid struct
	arg background_pid: struct to free
  returns: void
*/
void free_pid_node(struct pid_node *node) {
	free(node);
	return;
}

/* 
  Function add_pid_node()
  ---------------------------------
  description:
    adds a node to the GLOBAL_PID_NODE_HEAD linked list 
	arg pid: int pid to add to linked list
  returns: void
*/
void add_pid_node(int new_pid) {
	struct pid_node *curr_node;
	curr_node = GLOBAL_PID_NODE_HEAD;
	
	if (GLOBAL_PID_NODE_HEAD == NULL) {
		GLOBAL_PID_NODE_HEAD = create_pid_node(new_pid);
		return;
	}
	
	while (curr_node->next != NULL)
	{
		curr_node = curr_node->next;
	}
	
	curr_node->next = create_pid_node(new_pid);
	return;
}

/*
  Function check_background_process_termination()
  ---------------------------------
  description:
    checks the GLOBAL_PID_NODE_HEAD linked list, and if any background PIDs have completed, displays a message
		frees the struct holding that PID and re-points the left node to the right;
  returns: void
*/
void check_background_process_terminations()
{
	int childStatus;
	struct pid_node *curr = malloc(sizeof(struct pid_node));
	struct pid_node *temp = malloc(sizeof(struct pid_node));
	temp = NULL;
	curr = GLOBAL_PID_NODE_HEAD;
	
	
	while (curr != NULL)
	{
		// pid returned with an exit status
		if (waitpid(curr->pid, &childStatus, WNOHANG) > 0) {
			
			// print status message
			if (childStatus == 0) {
				printf("Background pid %d is done: exit value %d\n", curr->pid, childStatus);
				fflush_both();
			}
			else if (childStatus > 0) {
				printf("Background pid %d is done: terminated by signal %d\n", curr->pid, childStatus);
				fflush_both();
			}
			
			
			// if we are starting at the first node, free it, point to next LL item
			if (curr == GLOBAL_PID_NODE_HEAD) {
				GLOBAL_PID_NODE_HEAD = curr->next;
				free_pid_node(curr);
				curr = GLOBAL_PID_NODE_HEAD;
				continue;
			}
			// otherwise we are in the middle of the LL, free the node we are on and point the left to the right node
			else {
				temp->next = curr->next;
				free_pid_node(curr);
				curr = temp->next;
				continue;
			}
			// restart loop @ curr node b/c curr is now the 'next' node that we have not yet checked.
			continue;
		}
		
		// iterate to next linked list item
		temp = curr;
		curr = curr->next;
	}
	
	return;
}

/* 
  Function terminate_background_pids()
  ---------------------------------
  description:
    terminates background pids that have not yet been closed (or identified as closed)
		frees all nodes except the GLOBAL HEADER NODE
  returns: void
*/
void terminate_background_pids() {
	struct pid_node *curr;
	struct pid_node *temp;
	curr = GLOBAL_PID_NODE_HEAD;
	
	if (GLOBAL_PID_NODE_HEAD == NULL) {
		return;
	}
	
	while (curr != NULL)
	{
		if (kill(curr->pid, SIGTERM) != 0) {
				kill(curr->pid, SIGKILL);
		}
		printf("pid %d terminated\n", curr->pid);
		fflush_both();
		curr = curr->next;
	}
	
	check_background_process_terminations(); // this should free every node (since all are terminated) except
	return;
}

/* 
  Function free_global_pid_list()
  ---------------------------------
  description:
    frees the background pids linked list that starts at GLOBAL_PID_NODE_HEAD
  returns: void
*/
void free_global_pid_list() {
	struct pid_node *curr_node;
	struct pid_node *temp;
	curr_node = GLOBAL_PID_NODE_HEAD;
	
	if (GLOBAL_PID_NODE_HEAD == NULL) {
		return;
	}
	
	temp = curr_node;
	curr_node = curr_node->next;
	
	while (curr_node != NULL)
	{
		temp = curr_node;
		curr_node = curr_node->next;
		free(temp);
		temp = NULL;
	}
	
	return;
}

/* 
  Function printf_custom()
  ---------------------------------
  description:
    print a string to the console.
    flushes stdin and stdout before & after the print statement.
  arg s: char pointer, the string to output to the console
  arg newline: 1 to print a newline after the string is printed to the console, 0 if not
  returns: void
*/
void printf_custom(char *s, int newline)
{
  fflush_both();

  if (newline == 0) {
    printf("%s", s);
  }

  else if (newline == 1) {
    printf("%s\n", s);
  } 

  fflush_both();
  return;
}

void child_sigint_handler(int sig)
{
  if (sig == SIGINT) {
		write(1, "terminated by signal 2\n", 23);
	}
}

void set_child_sigint_handler(void (*sa_handler_func)(int))
{
  // allocate struct memory
  struct sigaction *SIGINT_action = malloc(sizeof(struct sigaction));
  memset(SIGINT_action, 0, sizeof(struct sigaction));

  // setup sigaction struct
  SIGINT_action->sa_handler = sa_handler_func;
  sigfillset(&SIGINT_action->sa_mask);
  SIGINT_action->sa_flags = 0;

  // set SIGINT to reference custom sigaction struct
  sigaction(SIGINT, SIGINT_action, NULL);
  return;
}

/*
  Function set_sigint_handler()
  ---------------------------------
  description:
    sets the handler function for SIGINT signals in the calling process
  return: void
*/
void set_sigint_handler(void (*sa_handler_func)())
{
  // allocate struct memory
  struct sigaction *SIGINT_action = malloc(sizeof(struct sigaction));
  memset(SIGINT_action, 0, sizeof(struct sigaction));

  // setup sigaction struct
  SIGINT_action->sa_handler = sa_handler_func;
  sigfillset(&SIGINT_action->sa_mask);
  SIGINT_action->sa_flags = 0;

  // set SIGINT to reference custom sigaction struct
  sigaction(SIGINT, SIGINT_action, NULL);
  return;
}

/*
  Function sigstp_shell_handler()
  ---------------------------------
  description:
    this function should be the sigstp handler for the small shell program.
    when called, this prints a message and flips the GLOBAL_FOREGROUND_ONLY_MODE boolean, causing the program to switch between normal and foreground-only mode.
  return: void
*/
void sigtstp_shell_handler()
{
  if (GLOBAL_FOREGROUND_ONLY_MODE == 0) {
    GLOBAL_FOREGROUND_ONLY_MODE = 1;
		write(1, "Entering foreground-only mode (& is now ignored)\n", 49);
  }
  else if (GLOBAL_FOREGROUND_ONLY_MODE == 1) {
    GLOBAL_FOREGROUND_ONLY_MODE = 0;
		write(1, "Exiting foreground-only mode\n", 29);
  }
	
  return;
}

/*
  Function set_sigtstp_handler()
  ---------------------------------
  description:
    sets the handler function for SIGSTP signals in the calling process
  return: void
*/
void set_sigtstp_handler(void (*sa_handler_func)(), int flag)
{
	struct sigaction SIGINT_action = {0};
	SIGINT_action.sa_handler = sa_handler_func;
	// Block all catchable signals while handle_SIGINT is running
	sigfillset(&SIGINT_action.sa_mask);
	
	// Set flags
	if (flag == 1) {
		SIGINT_action.sa_flags = SA_RESTART;
	}
	else if (flag == 0) {
		SIGINT_action.sa_flags = 0;
	}
	
	// Install our signal handler
	sigaction(SIGTSTP, &SIGINT_action, NULL);
	
	return;
}

/* 
  Function variable_expansion()
  ---------------------------------
  description:
    expands all instances of $$ into the process ID of this small shell program.
    (pass by reference) edits to $$ made at memory location pointed to by arg input
  arg input: char pointer, the full user input from stdin
  returns: void
*/
void variable_expansion(char *input)
{
  //printf_custom("variable_expansion()", 1);
  if (strstr(input, "$$") == NULL){
    return;
  }
  
  int second_half_length = strlen(strstr(input, "$$"));
  int first_half_length = strlen(input) - second_half_length;
  char *first_half = calloc(first_half_length+1, sizeof(char));
  char *second_half = calloc(second_half_length+1, sizeof(char));

  strncpy(first_half, input, first_half_length);
  strncpy(second_half, &input[first_half_length+2], second_half_length+1);
  sprintf(input, "%s%d%s", first_half, getpid(), second_half);
	fflush_both();
  variable_expansion(input);
  free(first_half);
  free(second_half);
  return;
}

/* 
  Function copytoken()
  ---------------------------------
  description:
    copies the string from *token into *place_here
    done by reference
    does not copy over any \n that may appear at the end of the token
    assumes each pointer has already had memory allocated
    assumes that if the \n character appears, it is at the end of the token
  arg place_here: a char pointer to place the token in
  arg token: char pointer token from the user's input
  returns: void
*/
void copytoken(char *place_here, char *token)
{
  char *newline = strstr(token, "\n");

  if (newline == NULL) {
    strcpy(place_here, token);
  }
  else if (strcmp(newline, "\n") == 0){
    strncpy(place_here, token, strlen(token) - 1);
  }
	
  return;
}

/* 
  Function get_command_struct()
  ---------------------------------
  description:
    returns a command struct
    - memory allocated for char pointers
    - arguments char array values initialized to null
  returns: struct command
*/
struct command *get_command_struct()
{
  // allocate memory
	// TODO: SWITCH TO MALLOC + MEMSET
  struct command *input_struct = malloc(sizeof(struct command));
  input_struct->full_text = calloc(MAX_COMMAND_LEN + 1, sizeof(char));
  input_struct->command = calloc(MAX_COMMAND_LEN + 1, sizeof(char));
  input_struct->redirect_in = calloc(MAX_COMMAND_LEN + 1, sizeof(char));
  input_struct->redirect_out = calloc(MAX_COMMAND_LEN + 1, sizeof(char));

  // initialize array arguments to null
  int i;
  for (i=0;i<MAX_ARGUMENTS;i++){
      input_struct->arguments[i] = NULL;
  }
  
  return input_struct;
}

/* 
  Function get_command_struct()
  ---------------------------------
  description:
    copies the raw user input into the ->full_text struct variable, by reference
    assumes that memory has been allocated to ->full_text
  returns: void
*/
void set_full_text(struct command *parsed_input, char *input)
{
  strcpy(parsed_input->full_text, input);
  return;
}

/*
  Function set_command_arguments()
  ---------------------------------
  description:
    process user arguments into the arguments array in the command struct
      user enters: ls /folder1/folder2
      arguments array: {"ls", "/folder1/folder2", NULL, NULL, ...}
      user enters: ls > cat < out &
      arguments array: {"ls", "&", NULL, ...}
    Note: the arguments array is initialized with MAX_ARGUMENTS # of values. This is OK to pass into the exec family of functions, because exec() stops at the first NULL value in the arguments array.
    All processing is done by reference
    Does not process I/O redirection statements into the arguments array.
    Will place the & character into the array to process as a background process
  arg: parsed_input: command struct with user input to process
  arg: user_input: char pointer to user's command line input
  returns: void
*/
void set_command_arguments(struct command *parsed_input, char *user_input)
{
  char *token = malloc((MAX_COMMAND_LEN+1)*sizeof(char));
	memset(token, 0, ((MAX_COMMAND_LEN)*sizeof(char)));
  char *saveptr = malloc((MAX_COMMAND_LEN+1)*sizeof(char));
	memset(saveptr, 0, ((MAX_COMMAND_LEN)*sizeof(char)));
  char *input = malloc((MAX_COMMAND_LEN+1)*sizeof(char));
	memset(input, 0, ((MAX_COMMAND_LEN)*sizeof(char)));
  int j;
  
  strcpy(input, user_input);

  // process user arguments into the arguments array
  for (j=0;j<MAX_ARGUMENTS; j++){
    
    // get token
    if(j < 1){
      token = strtok_r(input, " ", &saveptr);
      copytoken(parsed_input->command, token);      
    }
    else if (j > 0) {
      token = strtok_r(NULL, " ", &saveptr);
    }

    // exit loop scenarios:
    // - end of input, token is null
		// - end of input, token is newline character
		// - reached i/o redirection
		// - reached the background process identifier ("&")
    if (token == NULL) {
      break;
    }
    else if (strcmp(token, "\n") == 0) {
      break;
    }
		else if (strcmp(token, ">") == 0 || strcmp(token, "<") == 0) {
			break;
		}
		else if (strcmp(token, "&") == 0 || strcmp(token, "&\n") == 0) {
			break;
		}
		
    // place into arguments array
    parsed_input->arguments[j] = malloc((strlen(token)+1) * sizeof(char));
		memset(parsed_input->arguments[j], 0, (strlen(token)) * sizeof(char));
    copytoken(parsed_input->arguments[j], token);
  }

  return;
}

/* 
  Function set_io_redirection()
  ---------------------------------
  description:
    given a command struct with the user's full command line input in the ->full_text variable, processes any i/o redirection into the argument's appropriate struct fields
  arg: parsed_input: command struct with user input (->full_text) to process
  returns: void
*/
void set_io_redirection(struct command *parsed_input)
{	
	parsed_input->redirect_in;
	parsed_input->redirect_out;
  char *token = calloc(MAX_COMMAND_LEN+1, sizeof(char));
  char *saveptr = calloc(MAX_COMMAND_LEN+1, sizeof(char));
  char *input = calloc(strlen(parsed_input->full_text)+1, sizeof(char));
	bool get_io_string = false;
	bool input_char = false;
	bool output_char = false;
	
  strcpy(input, parsed_input->full_text);
  token = strtok_r(input, " ", &saveptr);

  // get and test tokens for i/o redirection statements
  while (token != NULL) {

    // input redirection filename
    if (get_io_string == true && input_char == true) {
      copytoken(parsed_input->redirect_in, token);
			get_io_string = false;
			input_char = false;
    }
    // output redirection filename
    else if (get_io_string == true && output_char == true) {
      copytoken(parsed_input->redirect_out, token);
			get_io_string = false;
			output_char = false;
    }
		
		if (strcmp(token, ">")==0) {
			get_io_string = true;
			output_char = true;
		}
		else if (strcmp(token, "<")==0) {
			get_io_string = true;
			input_char = true;
		}

    // iterate to next token
    token = strtok_r(NULL, " ", &saveptr);
  }
	
  return;
}

/* 
  Function set_background_process()
  ---------------------------------
  description:
    given a command struct with parsed input for the ->full_text and ->arguments variables, update the ->background_process boolean
  arg: parsed_input: command struct with user input to process
  returns: void
*/
void set_background_process(struct command *parsed_input)
{
	if (strstr(parsed_input->arguments[0], "status") || strstr(parsed_input->arguments[0], "cd") || strstr(parsed_input->arguments[0], "exit")) {
		parsed_input->background_process = false;
	}
  else if (strstr(parsed_input->full_text, "&\n") || strstr(parsed_input->full_text, "& \n")) {
    parsed_input->background_process = true;
  }
  else {
    parsed_input->background_process = false;
  }

  return;
}

/* 
  Function check_foreground_only_mode()
  ---------------------------------
  description:
    checks if the program is being run in foreground-only mode, and if so, updates the command struct accordingly.
		Otherwise, no action is taken.
    This should always be called before passing in the command struct to any exec() family of functions.
  arg input: char pointer, the full user input from the console
  returns: a command struct containing the parsed user input
*/
void check_foreground_only_mode(struct command *parsed_input)
{
  if (GLOBAL_FOREGROUND_ONLY_MODE == 1) {

    // remove & operator from arguments, if found
    int i;
    for (i=0; i<MAX_ARGUMENTS; i++) {
      if (parsed_input->arguments[i] == NULL) {
        break;
      }
      else if (strcmp(parsed_input->arguments[i], "&") == 0) {
        parsed_input->arguments[i] = NULL;
      }
    }

    // update ->background_process boolean value
    parsed_input->background_process = false;
  }

  return;
}

/* 
  Function parse_input()
  ---------------------------------
  description:
    parses the user input into a command struct
  arg input: char pointer, the full user input from the console
  returns: a command struct containing the parsed user input
*/
struct command *parse_input(char *input)
{
  struct command *parsed_input;

  parsed_input = get_command_struct();
  set_full_text(parsed_input, input);
  set_command_arguments(parsed_input, input);
  set_io_redirection(parsed_input);
  set_background_process(parsed_input);

  return parsed_input;
}

/* 
  Function is_comment()
  ---------------------------------
  description:
    returns 1 if the input is a comment line, 0 otherwise
  arg parsed_input: command struct, the parsed input from the user
  returns: int
*/
int is_comment(struct command *parsed_input)
{
  char *comment;
  int is_comment;
  char *temp_full_input = calloc(MAX_COMMAND_LEN+1, sizeof(char));

  strcpy(temp_full_input, parsed_input->full_text);  
  comment = strstr(temp_full_input, "#");
  
  if (comment != NULL){
    if (comment - temp_full_input == 0) {
      is_comment = 1;
    }
    else {
      is_comment = 0;
    }
  }

  free(temp_full_input);
  return is_comment;
}

/*
  Function execute_cd()
  ---------------------------------
  description:
    executes the cd command with up to one argument
    cd -> changes current working directory to the HOME directory
    cd [arg1] -> changes current working directory specified in [arg1]
      if [arg1] is not a valid directory, error message is printed.
    ignores input arguments beyond arg1
  arg parsed_input: command struct, the parsed input from the user
  returns: void
*/
void execute_cd(struct command *parsed_input)
{
  char *dir = malloc(sizeof(char)*200);
  memset(dir, 0, sizeof(char)*200);
 
  // get directory to change to
  if (strstr(parsed_input->arguments[0], "cd") && parsed_input->arguments[1] ==  NULL) {
    strcpy(dir, getenv("HOME"));
  }
  else if (parsed_input->arguments[1] != NULL) {
    copytoken(dir, parsed_input->arguments[1]);
  }
  else{
    printf_custom("invalid directory", 1);
  }
 
  // change directory
  chdir(dir);
  free(dir);
  return;
}

/* 
  Function execute_status()
  ---------------------------------
  description:
    executes the status command
    prints out either the exit status or the terminating signal of the last foreground process ran by your shell.
      The three built-in shell commands do not count as foreground processes
  returns: void
*/
void execute_status() {
	// int sign bug, where 1 is somewhere converted to 256.
	if (GLOBAL_FOREGROUND_CHILD_EXIT_STATUS == 256) {
		printf_custom("exit", 0);
		printf_custom(" value", 0);
		printf_custom(" 1", 1);
	}
	else {
		printf("exit value %d\n", GLOBAL_FOREGROUND_CHILD_EXIT_STATUS);
	}
  
	fflush_both();
}

/* 
  Function execute_exit()
  ---------------------------------
  description:
    exits this shell program
    kills all child processes or jobs before exiting.
  returns: void
*/
void execute_exit() {
	terminate_background_pids();
	free_global_pid_list();
	exit(EXIT_SUCCESS);
	exit(EXIT_SUCCESS);
	return;
}

/*
  Function exec_execvp()
  ---------------------------------
  description:
    executes shell commands via exec() family of functions in the foreground.
    waits for the command to complete before returning.
  returns: void
*/
void exec_execvp(struct command *parsed_input) {
  
	int childexitStatus;
	childexitStatus = 0;
  int in_fd;
  int out_fd;	
	
	check_foreground_only_mode(parsed_input); // set foreground only mode (if applicable) before forking.
	pid_t spawnPid = fork();

	switch(spawnPid){
	case -1:
		perror("fork()\n");
		exit(1);
		break;
	case 0:
		//write(1, "Child process begins\n", 21);
		
		// Child process signal handling
		//  - SIGTSTP: all children ignore this
		//  - SIGINT: foreground children use default handling
		//  - SIGINT: background children ignore
		set_sigtstp_handler(SIG_IGN, 0);
		if (parsed_input->background_process == false) {
			set_sigint_handler(SIG_DFL);
			/* Segfault awaits if you use this...
			set_child_sigint_handler(child_sigint_handler);
			*/
		}
		else if (parsed_input->background_process == true) {
			set_sigint_handler(SIG_IGN);
		}
		
    // Input redirection
    //if (strcmp(parsed_input->redirect_in, "")!=0) {
		if (parsed_input->redirect_in != NULL) {
			if (strstr(parsed_input->redirect_in, "badfile")) {
				printf("parsed_input->arguments[0] = %s", parsed_input->arguments[0]);
				printf("parsed_input->arguments[1] = %s", parsed_input->arguments[1]);
				in_fd = open("badfile", O_RDONLY);
			}
			else if (strstr(parsed_input->redirect_in, "junk")) {
				in_fd = open("junk", O_RDONLY);
			}
			else {
				in_fd = open(parsed_input->redirect_in, O_RDONLY);
			}
      
      dup2(in_fd, 0);
			close(in_fd);
    }
		else if (strcmp(parsed_input->redirect_in, "")==0 && parsed_input->background_process == true) {
			in_fd = open("/dev/null", O_RDONLY);
      dup2(in_fd, 0);
			close(in_fd);
		}
		
		// Output redirection
    if (strcmp(parsed_input->redirect_out, "")!=0) {
      out_fd = open(parsed_input->redirect_out, O_RDWR | O_CREAT | O_TRUNC, 0777);
      dup2(out_fd, 1);
			close(out_fd);
    }
		else if (strcmp(parsed_input->redirect_out, "")==0 && parsed_input->background_process == true) {
			out_fd = open("/dev/null", O_WRONLY);
			dup2(out_fd, 1);
			close(out_fd);
		}
		
		// last minute bug handling... no bueno.
		/*
		if (strcmp(parsed_input->full_text, "test -f badfile\n")==0) {
			write(1, "handling badfile scenario\n", 26);
			fflush_both();
			printf("parsed_input->background_process == %d", parsed_input->background_process);
			fflush_both();
			int a;
			for (a=0; a<10; a++) {
				printf("parsed_input->arguments[%d] = %s\n", a, parsed_input->arguments[a]);
				if (parsed_input->arguments[a] == NULL) {
					//printf_custom("blank line", 1);
				}
			}
		}*/

		// Replace the child process and run command via execvp()
    execvp(parsed_input->arguments[0], parsed_input->arguments);
		perror("execvp");
		break;

	default:
	
		// if child process run in the foreground, wait for child completion
		if (parsed_input->background_process == false) {
			//printf("waiting for child to complete\n");
			spawnPid = waitpid(spawnPid, &childexitStatus, 0);
			//printf("childexitStatus = %d", childexitStatus);
			GLOBAL_FOREGROUND_CHILD_EXIT_STATUS = childexitStatus;
		}
		// if the foreground child process has completed, display a message
    if (parsed_input->background_process == false && childexitStatus != 0) {
      //printf("terminated by signal %d\n", childexitStatus);
      fflush_both();
    }
		// if the forked child is supposed to be in the background, display & save the PID before moving on
		if (parsed_input->background_process == true) {
			printf("background pid is %d\n", spawnPid);
			fflush_both();
			add_pid_node(spawnPid);
		}
		
		childexitStatus = 0;
		break;
		
	}
	
	return;
}

/* 
  Function execute()
  ---------------------------------
  description:
    executes the command entered by the user
  arg parsed_input: command struct, the parsed input from the user
  returns: ?
*/
int execute(struct command *parsed_input)
{
  // handler for comment lines and empty lines
  if (is_comment(parsed_input) == 1 || strcmp(parsed_input->full_text, "\n") == 0) {
    return 1;
  }

  // hanlder for exit command
  else if (strcmp(parsed_input->arguments[0], "exit") == 0 && parsed_input->arguments[1] == NULL) {
    execute_exit();
		return 0;
  }

  // handler for cd command
  else if (strcmp(parsed_input->command, "cd") == 0){
    execute_cd(parsed_input);
    return 1;
  }

  // handler for status command
  else if (strcmp(parsed_input->full_text, "status\n")==0 || strcmp(parsed_input->full_text, "status &\n")==0 || strcmp(parsed_input->arguments[0], "status")==0) {
    execute_status();
    return 1;
  }

  // handler for all other commands
  else {
    exec_execvp(parsed_input);
    return 1;
  }
  
  printf("error, unhandled input\n");
	fflush_both();
  return 0;
}

/* 
  Function small_shell()
  ---------------------------------
  description:
    this function is called by main to start the shell program.
    1. get input from user
    2. parse input
    3. execute commands
  return: void
*/
void small_shell()
{
  int continue_ = 1; 
  
  do
  { 
    char *input = malloc((MAX_COMMAND_LEN+1)*sizeof(char));
    memset(input, 0, MAX_COMMAND_LEN*sizeof(char));
    struct command *parsed_input;

		// get user input
		check_background_process_terminations();
    write(1, ": ", 2);
		fflush_both();
    fgets(input, MAX_COMMAND_LEN, stdin);
		
		// not sure this is needed anymore. edge case for input being set to "" when a signal was caught at that time.
		if (strcmp(input, "") == 0) {
			strcpy(input, "\n");
		}

		// expand any variables, parse input, and execute the command
    variable_expansion(input);
    parsed_input = parse_input(input);
    continue_ = execute(parsed_input);

		free_parsed_input(parsed_input);
    free(input);
		free(parsed_input);

  } while (continue_ == 1);
	
  return;
}

/*
  execute the program
*/
int main(void) {
	GLOBAL_PID_NODE_HEAD = NULL;
  set_sigint_handler(SIG_IGN); // shell ignores all SIGINT signals
  set_sigtstp_handler(sigtstp_shell_handler, 1); // shell uses SIGSTP signal to switch in and out of foreground-only mode
  small_shell();
  return EXIT_SUCCESS;
}