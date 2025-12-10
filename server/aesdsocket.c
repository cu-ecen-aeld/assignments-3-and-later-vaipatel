#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <syslog.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>

#define PORT            "9000"  // Port we will bind to
#define BACKLOG         10      // Backlog for listen()
#define RECV_BUF_SIZE   1024    // Receive buffer size
#define DATA_FILE       "/var/tmp/aesdsocketdata" // Where receive data is appended
#define INIT_PACKET_CAP 128     // Initial capacity to reserve for 

// Global state
volatile sig_atomic_t exit_requested = 0;

// Function Prototypes
int SetupServerSocket(void);
void HandleClient(int client_fd);
int AppendToPacketBuffer(char** packet_buf, size_t* packet_len, size_t* packet_cap,
						 const char* src, size_t src_len, const char* logstr);
int SendDataToClient(int client_fd);
int Daemonize(int server_fd);
int RegisterSignalHandler();
void SignalHandler(int signo);

int main(int argc, char *argv[])
{
    // Check for daemon mode
    int daemon_mode = 0;

    if (argc == 2 && strcmp(argv[1], "-d") == 0)
    {
        daemon_mode = 1;
    }
    else if (argc > 1)
    {
        fprintf(stderr, "Usage: %s [-d]\n", argv[0]);
        return EXIT_FAILURE;
    }

    // Setup signal handling for SIGINT and SIGTERM
    if ( RegisterSignalHandler() < 0 ) 
    {
        return -1;
    }

    // Set up the server socket i.e. bind/listen, BEFORE daemonizing.
    int server_fd = SetupServerSocket();
    if ( server_fd == -1 )
    {
        return -1;
    }
	
	// Daemonize
	if (daemon_mode)
    {
        if ( Daemonize(server_fd) != 0 )
		{
			// We failed to daemonize. We could be here in the parent because
			// the fork() failed or in the child due to post-fork() failure.
			// Either way we close the server socket and return.
			close(server_fd);
            return -1;
		}
		// We successfully daemonized. Only the child remains.
    }
	
    // Open connection to syslog
    openlog("aesdsocket", LOG_PID, LOG_USER);

    // Server's accept loop
    while ( !exit_requested )
    {
        // Start an empty client addr, which will be populated by accept().
        // We use sockaddr_storag cuz we used AF_UNSPEC for the server socket.
        // (If we restrict to IPv4/v6 we can use sockaddr_in/in6)
        struct sockaddr_storage client_addr;
        socklen_t client_addr_len = sizeof(client_addr);

        // Accept connection.
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_addr_len);
        if (client_fd == -1)
        {
            if ( errno == EINTR )
            {
                // Interrupted by signal, likely SIGINT/SIGTERM
                // If exit was requested, break to cleanup, otherwise retry
                if ( exit_requested )
                {
                    break;
                }
                else
                {
                    continue;
                }
            }

            // Real error (not just a signal interruption)
            perror("accept");
            syslog(LOG_ERR, "accept error: %s", strerror(errno));
            // Keep the server running; try accepting again
            continue;
        }

        // Log accepted connection info to syslog.
        char host[NI_MAXHOST];
        int rc = getnameinfo((struct sockaddr *)&client_addr, // The client socket addr
                                client_addr_len,              // Client socket addr length
                                host,                         // Output buffer for host name
                                sizeof(host),                 // Size of hostname buffer
                                NULL,                         // Output buffer for service name
                                0,                            // Size of service buffer
                                NI_NUMERICHOST                // Flag: Want IP
        );

        if (rc == 0)
        {
            syslog(LOG_INFO, "Accepted connection from %s", host);
        }
        else
        {
            syslog(LOG_ERR, "Accepted connection from (unknown), getnameinfo error: %s", gai_strerror(rc));
        }

        printf("aesdsocket: accepted new connection\n");

        // Do the recv/send logic between the server and client.
        HandleClient(client_fd);

        close(client_fd);

        // Log closed connection
        syslog(LOG_INFO, "Closed connection from %s", host);
    }

    if (exit_requested)
    {
        syslog(LOG_INFO, "Caught signal, exiting");
    }

    // Delete the data file
    if (unlink(DATA_FILE) == -1)
    {
        // Only care about delete errors if the data file was actually created.
        if (errno != ENOENT)
        {
            syslog(LOG_ERR, "Error deleting %s: %s", DATA_FILE, strerror(errno));
        }
    }

    close(server_fd);

    closelog();

    return EXIT_SUCCESS;
}

/*
 * Sets up the server socket, binds it to the right port, and marks it as listen()ing.
 * Returns the socket fd on success, else -1 on failure.
 */
int SetupServerSocket(void)
{
    printf("aesdsocket: setting up server, will bind to port %s\n", PORT);
    
    int sockfd = -1;
    int rv;
    int reuseaddr_optval = 1;
    struct addrinfo hints;            // Hints given to getaddrinfo()
    struct addrinfo* servinfo = NULL; // Gets populated by getaddrinfo
    struct addrinfo* p = NULL;        // For looping over servinfo linked list

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;    // Allow IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM;  // TCP stream socket
    hints.ai_flags    = AI_PASSIVE;   // For wildcard IP address i.e. binding with INADDR_ANY
    hints.ai_protocol = 0;            // Any protocol

    // Construct our addrinfo struct servinfo
    rv = getaddrinfo(NULL, PORT, &hints, &servinfo);
    if ( rv != 0) 
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return -1;
    }

    // getaddrinfo() returns a list of address structures.
    // Try each address until we successfully bind().
    // If socket() (or bin()) fails, we (close the socket
    // and) try the next address.
    for (p = servinfo; p != NULL; p = p->ai_next)
    {
        // Create the socket fd.
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd == -1)
        {
            perror("socket");
            continue;   // Try next addrinfo entry
        }

        // Not necessary, but lets the kernel rebind if program crashes/is restarted quickly.
        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr_optval, sizeof(reuseaddr_optval)) == -1)
        {
            perror("setsockopt");
            close(sockfd);
            sockfd = -1;
            break;      // Fatal for our purposes
        }

        // Bind.
        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1)
        {
            perror("bind");
            close(sockfd);
            sockfd = -1;
            continue;   // Try next addrinfo entry
        }

        // Successfully bound
        break;
    }

    // servinfo was malloced so it needs to be freed.
    freeaddrinfo(servinfo);

    // Return -1 if we could not obtain/bind to a socket.
    if (sockfd == -1 || p == NULL)
    {
        fprintf(stderr, "aesdsocket: server failed to bind to port %s\n", PORT);
        return -1;
    }

    printf("aesdsocket: successfully bound to port %s, will start listening\n", PORT);

    // Mark socket as listening for and accepting connections.
    if (listen(sockfd, BACKLOG) == -1)
    {
        perror("listen");
        close(sockfd);
        
        return -1;
    }

    printf("aesdsocket: server is listening, will accept new connections\n");
    
    return sockfd;
}

/*
 * Read all available bytes from the client.
 */
void HandleClient(int client_fd)
{
    // Open data file once per client and reuse the fd
    int data_fd = open(DATA_FILE, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (data_fd == -1)
    {
        int local_errno = errno;
        perror("Failed to open data file");
        syslog(LOG_ERR, "Error opening %s: %s", DATA_FILE, strerror(local_errno));
        return;
    }

    char recv_buf[RECV_BUF_SIZE];
    char *packet_buf = NULL;
    size_t packet_len = 0;
	size_t packet_cap = 0;
    int senderr = 0;

    while ( !exit_requested && !senderr )
    {
        ssize_t num_bytes = recv(client_fd, recv_buf, sizeof(recv_buf), 0);
        if (num_bytes == -1)
        {
            if (errno == EINTR)
            {
                // If the receive was interrupted by delivery of a signal before
                // any data was available, retry recv. This will also check the
                // exit flag on next iter.
                continue;
            }
            // Truly had an error
            syslog(LOG_ERR, "recv error: %s", strerror(errno));
            break;
        }
        else if (num_bytes == 0)
        {
            // Client closed connection
            break;
        }
		
		size_t start = 0;
		
        // Parse recv_buf into packets
        for ( ssize_t i = 0;
              i < num_bytes && !exit_requested && !senderr;
              i++ )
        {
			// Handle complete packet
			if ( recv_buf[i] == '\n' )
			{
				// Grow the packet buffer to the segment since the start.
				// (The buffer already has any earlier segments from prev partials)
				size_t segment_len = (size_t)(i + 1) - start;
				if ( AppendToPacketBuffer(
						&packet_buf,
						&packet_len,
						&packet_cap,
						recv_buf + start,
						segment_len,
						"building complete packet") != 0
				)
				{
					// Packet was discarded; skip bytes up to and including '\n'
                    start = (size_t)i + 1;
                    continue;
				}
				
				// We have a complete packet! Write it to file.
				size_t total_written = 0;
				while ( total_written < packet_len )
				{
					ssize_t w = write(data_fd, packet_buf + total_written, packet_len - total_written);
					if (w == -1)
                    {
                        if (errno == EINTR)
                        {
                            // If the call was interrupted by a signal before any data was written, retry
                            continue;
                        }
						// Truly had an error
                        syslog(LOG_ERR, "Error writing to %s: %s", DATA_FILE, strerror(errno));
                        break; // (just end up writing the partial file and fail the unit tests)
                    }
					
					total_written += (size_t)w;
				}
				
				// Send file data to client
                senderr = (SendDataToClient(client_fd) < 0);
				
				// Reset packet_len for next packet, but the keep packet_buf at packet_cap.
                packet_len = 0;

                // Next segment starts after this newline
                start = (size_t)i + 1;
			}
        }
		
		// Handle any trailing partial packet
		if (!exit_requested && !senderr && start < (size_t)num_bytes)
		{
			// Grow the packet buffer and write the leftover bytes to it
			size_t leftover_len = (size_t)num_bytes - start;
			if ( AppendToPacketBuffer(
					&packet_buf,
					&packet_len,
					&packet_cap,
					recv_buf + start,
					leftover_len,
					"buffering partial packet") != 0 )
			{
				// Partial packet discarded
				continue;
			}
		}
    }
    
    // Cleanup
    free(packet_buf);
    packet_buf = NULL;
	
    // Close data file
    if ( data_fd != -1 )
    {
        if ( close(data_fd) == -1 )
        {
            syslog(LOG_ERR, "Error closing %s: %s", DATA_FILE, strerror(errno));
        }
    }
}

/*
 * Appends src, which could correspond to a partial packet segment, to packet_buf.
 *
 * packet_buf has capacity packet_cap, and is already currently filled upto packet_len.
 * If more capacity is needed to fit src, this function will grow packet_buf. It will
 * first try to grow it geometrically. Failing that it will fallback to growing exactly.
 * After growing packet_buf, packet_len and packet_cap will all be updated.
 *
 * log_str is for custom error logging context (and usage context when encountering a
 * call to this function).
 *
 * Returns 0 on success, -1 on failure in which case the packet_buf is discarded.
 */
int AppendToPacketBuffer(
	char** packet_buf,
	size_t* packet_len,
	size_t* packet_cap,
	const char* src,
	size_t src_len,
	const char* logstr
)
{
	size_t needed = *packet_len + src_len;
	if ( needed > *packet_cap )
	{
		size_t new_cap = (*packet_cap != 0) ? *packet_cap : INIT_PACKET_CAP;
		while ( new_cap < needed )
		{
			new_cap *= 2;
		}
	
		// Try reallocating the packet buffer to new_cap bytes
		char* new_buf = realloc(*packet_buf, new_cap);
		if ( new_buf == NULL )
		{
			// Could be that new_cap was too much for the system,
			// but needed bytes might still fit? Fallback to needed.
			new_buf = realloc(*packet_buf, needed);
			if ( new_buf == NULL )
			{
				syslog(LOG_ERR,
                       "realloc failed in %s for size %zu, discarding current packet",
                       logstr, new_cap);
				free(*packet_buf);
				*packet_buf = NULL;
				*packet_len = 0;
				*packet_cap = 0;
				return -1;
			}
		}
		
		// Point to the grown buffer and capacity
		*packet_buf = new_buf;
		*packet_cap = new_cap;
	}
	
	// Copy src into packet_buf
	memcpy(*packet_buf + *packet_len, src, src_len);
    *packet_len += src_len;
	
	return 0;
}

/*
 * Sends the data in the data file to the client.
 */
int SendDataToClient(int client_fd)
{
    int fd = open(DATA_FILE, O_RDONLY);
    if (fd == -1)
    {
        syslog(LOG_ERR, "Error opening %s for read: %s", DATA_FILE, strerror(errno));
        return -1;
    }

    char buf[RECV_BUF_SIZE];
    int ret = 0;
    int error = 0;

    while (!error)
    {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n == 0)
        {
            // EOF
            break;
        }
        else if (n == -1)
        {
            if (errno == EINTR)
            {
                // If the call was interrupted by a signal before any data was read, retry read
                continue;
            }
            // Truly had an error
            syslog(LOG_ERR, "Error reading from %s: %s", DATA_FILE, strerror(errno));
            ret = -1;
            error = 1;
            break;
        }

        size_t total_sent = 0;
        while (total_sent < (size_t)n)
        {
            ssize_t s = send(client_fd,
                             buf + total_sent,
                             (size_t)n - total_sent,
                             0);
            if (s == -1)
            {
                if (errno == EINTR)
                {
                    // If a signal occurred before any data was transmitted, retry send
                    continue;
                }
                // Truly had an error
                syslog(LOG_ERR, "Error sending to client: %s", strerror(errno));
                ret = -1;
                error = 1;
                break;
            }
            total_sent += (size_t)s;
        }
    }

    // Cleanup
    if (close(fd) == -1)
    {
        syslog(LOG_ERR, "Error closing %s after read: %s", DATA_FILE, strerror(errno));
    }

    return ret;
}

/*
 * Daemonize the process.
 *
 * - Assumes server_fd is a bound+listening socket.
 * - On success:
 *   * The child just returns 0 and server_fd remains open.
 *   * The parent just exits the process cleanly.
 * - On error:
 *   * Returns -1 in the parent if fork failed, else in the
 *     child post-fork().
 */
int Daemonize(int server_fd)
{
    pid_t pid = fork();
    if (pid < 0)
    {
        // Fork failed
        perror("fork");
        return -1;
    }

    if (pid > 0)
    {
        // Parent process: close the listening socket and exit.
        // Child inherited server_fd, so it will keep using it.
        close(server_fd);
        _exit(EXIT_SUCCESS);
    }

    // Child process continues here: this will become the daemon.

    // Start a new session and detach from controlling terminal
    if (setsid() == -1)
    {
        perror("setsid");
        return -1;
    }

	// Change working directory to root so we don't block someone
	// from unmounting/deleting the dir in which we were started.
    if (chdir("/") == -1)
    {
		// chdir failed, treating as fatal
        perror("chdir");
		return -1;
    }

    // Redirect stdin, stdout, stderr to /dev/null
    int devnull_fd = open("/dev/null", O_RDWR);
    if (devnull_fd == -1)
	{
		// /dev/null open failed, treating as fatal
		perror("open /dev/null");
		return -1;
    }
	else
    {
        // Ignoring errors from dup2
        (void)dup2(devnull_fd, STDIN_FILENO);
        (void)dup2(devnull_fd, STDOUT_FILENO);
        (void)dup2(devnull_fd, STDERR_FILENO);

        if (devnull_fd > STDERR_FILENO)
        {
            close(devnull_fd);
        }
    }

    // In the child/daemon, server_fd is still open and ready for accept().
    return 0;
}

/*
 * Registers the signal handler for SIGTERM and SIGINT.
 */
int RegisterSignalHandler()
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SignalHandler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(SIGINT, &sa, NULL) == -1)
    {
        perror("sigaction SIGINT");
        return -1;
    }

    if (sigaction(SIGTERM, &sa, NULL) == -1)
    {
        perror("sigaction SIGTERM");
        return -1;
    }

    return 0;
}

/*
 * Handles SIGTERM and SIGINT.
 */
void SignalHandler(int signo)
{
    (void)signo;
    exit_requested = 1;
}
