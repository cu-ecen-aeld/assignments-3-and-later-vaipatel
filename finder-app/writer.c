#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <syslog.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

int main(int _argc, char* _argv[])
{
	// Setup syslog
	openlog(NULL, LOG_CONS, LOG_USER);

	// Check args
	if ( _argc != 3 )
	{
		syslog(LOG_ERR,
			"Usage: ./writer WRITEFILE WRITESTR\n"
			"Writes a string to a new or existing file. Overwrites existing content.\n"
			"\n"
			"Arguments:\n"
			"  WRITEFILE       New or existing file to write to\n"
			"  WRITESTR        String to write into WRITEFILE. Existing content will be overwritten\n"
			"\n"
		);
		return 1;
	}

	// Fetch args and print debug info to syslog
	const char* filename = _argv[1];
	const char* writestr = _argv[2];
	syslog(LOG_DEBUG, "Writing %s to %s\n", writestr, filename);

	// Create or truncate open the file for writing. Set permissions to 664.
	int fd;
	fd = creat(filename, 0664);
	// The above should be same as fd = open(filename, O_WRONLY | O_TRUNC | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
	if ( fd == -1 )
	{
		syslog(LOG_ERR, "Error: Could not open file %s for writing\n", filename);
		return 1;
	}

	// Write the string to the file
	ssize_t len = strlen(writestr);
	ssize_t written = write(fd, writestr, len);
	if ( written == -1 )
	{
		syslog(LOG_ERR, "Error: Write failed: %s\n", strerror(errno));
		close(fd);
		return 1;
	}
	else if ( written != len )
	{
		syslog(LOG_ERR, "Error: Partial write. Wrote %zd of %zd bytes.\n", written, len);
		close(fd);
		return 1;
	}
	close(fd);
	return 0;
}
