#include "systemcalls.h"
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

/**
 * @param cmd the command to execute with system()
 * @return true if the command in @param cmd was executed
 *   successfully using the system() call, false if an error occurred,
 *   either in invocation of the system() call, or if a non-zero return
 *   value was returned by the command issued in @param cmd.
*/
bool do_system(const char *cmd)
{
    if ( cmd == NULL )
    {
        return false;
    }
    
    int ret;
    ret = system(cmd);

    // From man system:
    // If a child process could not be created, or its status could
    // not be retrieved, the return value is -1 and errno is set to
    // indicate the error.
    if ( ret == -1 )
    {
        perror("system() failed");
        return false;
    }

    // From man system:
    // If a shell could not be executed in the child process [.. or if ..]
    // all system calls succeed [..] the return value is a "wait status" that
    // can be examined using the macros described in waitpid(2).  (i.e.,
    // WIFEXITED(), WEXITSTATUS(), and so on)
    if ( !(WIFEXITED(ret) && WEXITSTATUS(ret) == 0) )
    {
        printf("A shell could not be executed in the child process, or the command failed\n");
        return false;
    }

    return true;
}

/**
* @param count -The numbers of variables passed to the function. The variables are command to execute.
*   followed by arguments to pass to the command
*   Since exec() does not perform path expansion, the command to execute needs
*   to be an absolute path.
* @param ... - A list of 1 or more arguments after the @param count argument.
*   The first is always the full path to the command to execute with execv()
*   The remaining arguments are a list of arguments to pass to the command in execv()
* @return true if the command @param ... with arguments @param arguments were executed successfully
*   using the execv() call, false if an error occurred, either in invocation of the
*   fork, waitpid, or execv() command, or if a non-zero return value was returned
*   by the command issued in @param arguments with the specified arguments.
*/

bool do_exec(int count, ...)
{
    va_list args;
    va_start(args, count);
    char * command[count+1];
    int i;
    for(i=0; i<count; i++)
    {
        command[i] = va_arg(args, char *);
    }
    command[count] = NULL;

    fflush(stdout);
    pid_t pid;
    pid = fork();
    if ( pid == -1 )
    {
        perror("fork() failed");
        return false;
    }
    else if ( pid == 0 )
    {
        // In the child: Replace image with command.
        execv(command[0], command);

        // If we got here, execv failed
        perror("execv failed");
        exit(EXIT_FAILURE);
    }

    // In the parent: Wait for child to finish.
    int status;
    if ( waitpid(pid, &status, 0) == -1 )
    {
        perror("waitpid() failed");
        return false;
    }

    // Check that the child exited normally
    if ( !(WIFEXITED(status) && WEXITSTATUS(status) == 0) )
    {
        printf("The command failed\n");
        return false;
    }

    va_end(args);

    return true;
}

/**
* @param outputfile - The full path to the file to write with command output.
*   This file will be closed at completion of the function call.
* All other parameters, see do_exec above
*/
bool do_exec_redirect(const char *outputfile, int count, ...)
{
    va_list args;
    va_start(args, count);
    char * command[count+1];
    int i;
    for(i=0; i<count; i++)
    {
        command[i] = va_arg(args, char *);
    }
    command[count] = NULL;

    // Open a fd which will be duplicated onto stdout in the child
    int fd;
    fd = open(outputfile, O_WRONLY|O_CREAT|O_TRUNC, 0644);
    if ( fd == -1 )
    {
        perror("Could not open file for writing");
        return false;
    }

    pid_t pid;
    pid = fork();
    switch ( pid )
    {
        case -1:
        {
            perror("fork() failed");
            return false;
        }
        case 0: // In the child
        {
            // Duplicate fd onto stdout
            if (dup2(fd, STDOUT_FILENO) < 0)
            {
                perror("dup2");
                return false;
            }
            close(fd);

            // Replace image with command.
            execv(command[0], command);

            // If we got here, execv failed
            perror("execv failed");
            exit(EXIT_FAILURE);
        }
        default: // In the parent
        {
            close(fd);
        }
    }

    // In the parent: Wait for child to finish.
    int status;
    if ( waitpid(pid, &status, 0) == -1 )
    {
        perror("waitpid() failed");
        return false;
    }

    // Check that the child exited normally
    if ( !(WIFEXITED(status) && WEXITSTATUS(status) == 0) )
    {
        printf("The command failed\n");
        return false;
    }

    va_end(args);

    return true;
}
