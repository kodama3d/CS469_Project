/******************************************************************************

PROGRAM:  ssl-server.c
AUTHOR:   Jeffrey Krauss
COURSE:   CS469 - Distributed Systems (Regis University)
SYNOPSIS:  Server program

******************************************************************************/
#include <fcntl.h>
#include <stdio.h>
#include <regex.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <dirent.h>
#include <stdint.h>

#define BUFFER_SIZE			256
#define DEFAULT_PORT		4433
#define CERTIFICATE_FILE	"cert.pem"
#define KEY_FILE			"key.pem"
#define ACCOUNT_FILE		"./user_database.txt"
#define MP3DIR				"/mp3"
#define MP3LISTFILE		    "mp3_list.txt"
#define ERRSTR_SIZE			4
#define TEST_MP3_FILE		"./mp3/04 Koj nyob qhov twg.mp3"
#define DEBUG				true

int validateUserLogin(SSL* ssl, char client_addr[], int validLogin);  // Read the user name from the client

/******************************************************************************

This function does the basic necessary housekeeping to establish TCP connections
to the server.  It first creates a new socket, binds the network interface of the
machine to that socket, then listens on the socket for incoming TCP connections.

*******************************************************************************/
int create_socket(unsigned int port) {
    
    int    s;
    struct sockaddr_in addr;

    // First we set up a network socket. An IP socket address is a combination
    // of an IP interface address plus a 16-bit port number. The struct field
    // sin_family is *always* set to AF_INET. Anything else returns an error.
    // The TCP port is stored in sin_port, but needs to be converted to the
    // format on the host machine to network byte order, which is why htons()
    // is called. Setting s_addr to INADDR_ANY binds the socket and listen on
    // any available network interface on the machine, so clients can connect
    // through any, e.g., external network interface, localhost, etc.

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    // Create a socket (endpoint) for network communication.  The socket()
    // call returns a socket descriptor, which works exactly like a file
    // descriptor for file system operations we worked with in CS431
    //
    // Sockets are by default blocking, so the server will block while reading
    // from or writing to a socket. For most applications this is acceptable.
    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        fprintf(stderr, "Server: Unable to create socket: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    // When you create a socket, it exists within a namespace, but does not have
    // a network address associated with it.  The bind system call creates the
    // association between the socket and the network interface.
    //
    // An error could result from an invalid socket descriptor, an address already
    // in use, or an invalid network address
    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "Server: Unable to bind to socket: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    // Listen for incoming TCP connections using the newly created and configured
    // socket. The second argument (1) indicates the number of pending connections
    // allowed, which in this case is one.  That means if the server is connected
    // to one client, a second client attempting to connect may receive an error,
    // e.g., connection refused.
    //
    // Failure could result from an invalid socket descriptor or from using a socket
    // descriptor that is already in use.
    if (listen(s, 1) < 0) {
        fprintf(stderr, "Server: Unable to listen: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    fprintf(stdout, "Server: Listening on TCP port %u\n", port);

    return s;
}

/******************************************************************************

This function does some initialization of the OpenSSL library functions used in
this program.  The function SSL_load_error_strings registers the error strings
for all of the libssl and libcrypto functions so that appropriate textual error
messages can be displayed when error conditions arise.  OpenSSL_add_ssl_algorithms
registers the available SSL/TLS ciphers and digests used for encryption.

******************************************************************************/
void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

/******************************************************************************

EVP_cleanup removes all of the SSL/TLS ciphers and digests registered earlier.

******************************************************************************/
void cleanup_openssl() {
    EVP_cleanup();
}

/******************************************************************************

An SSL_CTX object is an instance of a factory design pattern that produces SSL
connection objects, each called a context. A context is used to set parameters
for the connection, and in this program, each context is configured using the
configure_context() function below. Each context object is created using the
function SSL_CTX_new(), and the result of that call is what is returned by this
function and subsequently configured with connection information.

One other thing to point out is when creating a context, the SSL protocol must
be specified ahead of time using an instance of an SSL_method object.  In this
case, we are creating an instance of an SSLv23_server_method, which is an
SSL_METHOD object for an SSL/TLS server. Of the available types in the OpenSSL
library, this provides the most functionality.

******************************************************************************/
SSL_CTX* create_new_context() {
	const SSL_METHOD* 	ssl_method; // This should be declared 'const' to avoid getting
									// a warning from the call to SSLv23_server_method()
	SSL_CTX*    	ssl_ctx;

    // Use SSL/TLS method for server
    ssl_method = SSLv23_server_method();

    // Create new context instance
    ssl_ctx = SSL_CTX_new(ssl_method);
    if (ssl_ctx == NULL) {
        fprintf(stderr, "Server: cannot create SSL context:\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ssl_ctx;
}

/******************************************************************************

We will use Elliptic Curve Diffie Hellman anonymous key agreement protocol for
the session key shared between client and server.  We first configure the SSL
context to use that protocol by calling the function SSL_CTX_set_ecdh_auto().
The second argument (onoff) tells the function to automatically use the highest
preference curve (supported by both client and server) for the key agreement.

Note that for error conditions specific to SSL/TLS, the OpenSSL library does
not set the variable errno, so we must use the built-in error printing routines.

******************************************************************************/
void configure_context(SSL_CTX* ssl_ctx) {
    SSL_CTX_set_ecdh_auto(ssl_ctx, 1);

    // Set the certificate to use, i.e., 'cert.pem'
    if (SSL_CTX_use_certificate_file(ssl_ctx, CERTIFICATE_FILE, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Server: cannot set certificate:\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Set the private key contained in the key file, i.e., 'key.pem'
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0 ) {
        fprintf(stderr, "Server: cannot set certificate:\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

/******************************************************************************
This function is repeated throughout the program, so it takes in parameters 
to perform SSL message transfer functions, and takes care of error handling.
ssl: required for sending SSL message
msg: data content in char string format
char_cnt: bytes sent in message, necessary for client to determine error messages
******************************************************************************/
int send_message(SSL* ssl, char* msg, int char_cnt) {
	int		nbytes_written;
	char	buffer[BUFFER_SIZE];
	
	bzero(buffer, BUFFER_SIZE);	// zero out buffer
	strcpy(buffer, msg);		// Copy the message to the buffer
  	
	nbytes_written = SSL_write(ssl, buffer, char_cnt);		// transmit message to client
	
	if (nbytes_written <= 0) {							// test for written byte count
		fprintf(stderr, "Server: Could not write message to client: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	} else
		if (DEBUG)										// show result message
			printf("Server: Message transmitted to client: \"%s\"\n", msg);

	return errno;
}

// Function used for sending mp3 list and mp3 files
int send_mp3_list(SSL* ssl, char file_path[], char client_addr[]) {
	int		readfd, rcount, err_num;
	char	file_buffer[BUFFER_SIZE];
	char	err_str[ERRSTR_SIZE];		// char for error number with terminator
	
	readfd = open(file_path, O_RDONLY, 0);	// open input file stream
			
	if(readfd >= 0) {							// test input stream for file name
		
		do {									// loop through until end of file
			bzero(file_buffer, BUFFER_SIZE);					// clear file_buffer
			rcount = read(readfd, file_buffer, BUFFER_SIZE);	// read and count chars
					
			if (rcount <= 0) {									// test for read error
				sprintf(err_str, "%d", errno);					// stringify error number
				err_num = send_message(ssl, err_str, ERRSTR_SIZE);	// send read error
				printf("Server: Unable to read %s: %s\n", file_buffer, strerror(errno));
				}
			else {
				file_buffer[rcount] = 0;	// terminates erroneous data at end of file_buffer...
				err_num = send_message(ssl, file_buffer, rcount);	// send data to client
				}
		} while (rcount != 0 && rcount == BUFFER_SIZE);	// tests for no error and full file_buffer
				
		close(readfd);		// close input stream
			
		// Commented out, error on Jeff's machine due to 4 extra bytes in the file_buffer
		// send EOF to client
		//sprintf(err_str, "%d", errno);						// stringify error number
		//err_num = send_message(ssl, err_str, ERRSTR_SIZE);	// errno should be 0 - "Success"
				
		if (err_num == 0)
			fprintf(stdout, "Server: Completed mp3 list transfer to client (%s)\n", client_addr);
		else
			fprintf(stderr, "Server: Error sending EOF to client (%s)\n", client_addr);
			
		// unable to read local file
		} else {							// error opening file
			// errno 2 - No such file or directory, or 13 - Permission denied
			err_num = errno;				// copy number
			fprintf(stderr, "Server: Unable to open %s: %s\n", file_buffer, strerror(err_num));
				
			// send error to client
			sprintf(err_str, "%d", err_num);	// stringify error number
			err_num = send_message(ssl, err_str, ERRSTR_SIZE);
			if (err_num != 0)
				fprintf(stderr, "Server: Error sending error to client (%s)\n", client_addr);
		}
	return errno;
}

/******************************************************************************
	Scans mp3 directory for number of files and longest file name.

******************************************************************************/
int define_mp3_list(int * max_length) {
	struct dirent*	currentEntry;
	char			dirname[BUFFER_SIZE];
	DIR*			d;
	int				file_count = 0;
	
	getcwd(dirname, BUFFER_SIZE);		// Get current directory
	strcat(dirname, MP3DIR);			// Create mp3 directory name
	
	// Open the directory and check for error
	if (DEBUG)
		printf("Server: Opening MP3 directory: %s\n", dirname);
	d = opendir(dirname);
	if (d == NULL) {
		fprintf(stderr, "Server: Could not open directory %s: %s\n", dirname, 
				strerror(errno));
		return 0;
	}

	currentEntry = readdir(d);			// Read mp3 directory

	while(currentEntry != NULL) {		// loop through files in directory
		if (currentEntry->d_type == DT_REG) {
			file_count++;				// Count number of files
			
			// Store longest file name (Unable to set variable string length)
			//if (* max_length < (int) strlen(currentEntry->d_name))
			//	* max_length = (int) strlen(currentEntry->d_name);
		}
		currentEntry = readdir(d);    	// Get the next directory entry
	}	// End of file list loop

	closedir(d);
	return file_count;
}	// End of define_mp3_list

/******************************************************************************
	Builds the mp3 list

******************************************************************************/
void get_mp3_list(char mp3_list[][BUFFER_SIZE]) {
	struct dirent* currentEntry;
	struct stat    fileInfo;
	char           olddir[BUFFER_SIZE];
	char           dirname[BUFFER_SIZE];
	DIR*           d;
	int				file_count = 0;
	
	getcwd(olddir, BUFFER_SIZE);		// Save current working directory
	getcwd(dirname, BUFFER_SIZE);
	strcat(dirname, MP3DIR);			// Create mp3 directory name
	
	d = opendir(dirname);				// Directory already tested during scan
	chdir(dirname);						// Move to mp3 directory
	currentEntry = readdir(d);			// Read mp3 directory
	while(currentEntry != NULL) {		// loop through files in directory
		// Only print regular files
		if (currentEntry->d_type == DT_REG) {
			// Copy file name to mp3_list and increment counter
			strcpy(mp3_list[file_count], currentEntry->d_name);	
			file_count++;
			
			stat(currentEntry->d_name, &fileInfo);	// Read file stats
			fprintf(stdout, "   Reading: %-30s\t%lu bytes\n", currentEntry->d_name, 
				fileInfo.st_size);					// Display file name and size
		}
		
		currentEntry = readdir(d);    	// Get the next directory entry
	}	// End of file list loop
	
	chdir(olddir);						// Go back to previous directory
	closedir(d);
}	// End of get_mp3_list

/******************************************************************************
	Writes the mp3 list file

******************************************************************************/
int write_mp3_file(char mp3_list[][BUFFER_SIZE], int list_len) {
	// char list_fn[13]; // JK: I get an error using the assignment below "Illegal Expression: 4"
    char	list_fn[strlen(MP3LISTFILE)];
	int		writefd;
	char	buffer[BUFFER_SIZE];
	
	strcpy(list_fn, MP3LISTFILE);
	
	// creates empty file for the copy
	writefd = creat(list_fn, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	
	if (DEBUG)
		printf("\nWriting to file: '");
	
	for (int i = 0; i < list_len; i++) {
		strcpy(buffer, mp3_list[i]);
		strcat(buffer, ";");
		if (DEBUG)
			printf("%s", buffer);
			
		write(writefd, buffer, strlen(buffer));	// writes to copy, using the read buffer limit
	}
	
	if (DEBUG)
		printf("'\n\n");

	close(writefd);		// closes new file
}

// This will return a song number i.e. 1, 2, 10, etc.
int get_song_number(SSL* ssl) {
    char	buffer[BUFFER_SIZE];
	char	*ptr;
	long	long_number;
	int		song_number;
	
	SSL_read(ssl, buffer, BUFFER_SIZE);		// client's number as string
	long_number = strtol(buffer, &ptr, 10);	// convert to number
	song_number = (int) long_number;		// convert to int
	song_number--;							// decrement for array selection
	
	return song_number;
}



int send_mp3(SSL* ssl, char filename[], char client_addr[]) {
    char	path_fn[BUFFER_SIZE];
	int		byte_count = 0;			// For debugging
	int		wcount = 0;				// Amount written by SSL_write
	int		fileSize = 0;			// Used with stat to get file size
	char	mp3Buffer[BUFFER_SIZE];	// Buffer to send mp3 file bytes
	struct	stat st;				// Used to get file size
	int		err_num;
	int		rcount = 0;				// Erase previous rcount assignment
	char	err_str[ERRSTR_SIZE];	// char for error number with terminator
	char	buffer[BUFFER_SIZE];
	
	// Create the target path and filename
	strcpy(path_fn, ".");
	strcat(path_fn, MP3DIR);
	strcat(path_fn, "/");
	strcat(path_fn, filename);
	
	if (DEBUG)
		printf("Server: Target filename: '%s'\n   Target path: '%s'\n", filename, path_fn);

	// Use the song sent by the buffer to locate the song and open the file
	int mp3_fd = open(path_fn, O_RDONLY, 0);
	
	// File descriptor created successfully
	if (mp3_fd >= 0) {
		
		// Get the file size and send it to the client
		fstat(mp3_fd, &st);
		fileSize = st.st_size;
		
		if (DEBUG) {
			printf("   MP3 file opened and fd created.\n");
			printf("   MP3 file size is: %d.\n", fileSize);
		}
		
		// Send the size of the file to the client
		bzero(buffer, BUFFER_SIZE);
		sprintf(buffer, "%d", fileSize);
		send_message(ssl, buffer, BUFFER_SIZE);
		
		// Read bytes from the file and send them to client using SSL_write()
		do {
			bzero(mp3Buffer, BUFFER_SIZE);
			rcount = read(mp3_fd, mp3Buffer, BUFFER_SIZE);
			
			// Identify errors with read syscall
			if (rcount <= 0) {
				sprintf(err_str, "%d", errno);                    // stringify error number
				err_num = send_message(ssl, err_str, ERRSTR_SIZE);    // send read error
				printf("Server: Unable to read %d: %s\n", mp3_fd, strerror(errno));
			
			// Read syscall successfull
			} else {
				mp3Buffer[rcount] = '\0';                   // Null terminate
				wcount = SSL_write(ssl, mp3Buffer, rcount); // Send mp3 bytes to client
				byte_count += rcount;                            // Sum the bytes written
			}
		} while(rcount != 0 && rcount == BUFFER_SIZE);
		
		if (DEBUG)
			fprintf(stdout, "Server: Reached end of file...\n");
		
		// send EOF to client
		sprintf(err_str, "%d", errno);						// stringify error number
		err_num = send_message(ssl, err_str, ERRSTR_SIZE);	// errno should be 0 - "Success"
		
		if (err_num == 0)
			fprintf(stdout, "Server: Completed file transfer to client (%s)\n", client_addr);
		else
			fprintf(stderr, "Server: Error sending EOF to client (%s)\n", client_addr);
	
		if (DEBUG)
			printf("Total bytes written to buffer was: %d\n", byte_count);
		
	} else {
		// errno 2 - No such file or directory, or 13 - Permission denied
		err_num = errno;
		fprintf(stderr, "Server: Unable to open %s: %s\n", buffer, strerror(err_num));
		
		// send error to client
		sprintf(err_str, "%d", err_num);    // stringify error number
		err_num = send_message(ssl, err_str, ERRSTR_SIZE);
		if (err_num != 0)
			fprintf(stderr, "Server: Error sending error to client (%s)\n", client_addr);
	}
	close(mp3_fd);
}

void run_SongSlinger(SSL* ssl, char mp3_list[][BUFFER_SIZE], char client_addr[]) {
	char	mp3_filename[BUFFER_SIZE];
	bool	playing = true;
	
	send_mp3_list(ssl, MP3LISTFILE, client_addr);	// Send list of available MP3's to client

	// Playing songs loop
	do {
		if (DEBUG)
			printf("Waiting for client: Select Song?...\n");
		
		int song_num = get_song_number(ssl);		// Get the song number selected by user
		strcpy(mp3_filename, mp3_list[song_num]);	// Convert to the song filename
		send_mp3(ssl, mp3_filename, client_addr);	// Send mp3 to client
		
		if (DEBUG)
			printf("Waiting for client: Continue?...\n");
		
		SSL_read(ssl, mp3_filename, BUFFER_SIZE);
		
		if (DEBUG)
			printf("Received: %s\n", mp3_filename);
		
		if (strcmp(mp3_filename, "N") == 0)
			playing = false;
		
	} while (playing);
}
			


/******************************************************************************

The sequence of steps required to establish a secure SSL/TLS connection is:

1.  Initialize the SSL algorithms
2.  Create and configure an SSL context object
3.  Create a new network socket in the traditional way
4.  Listen for incoming connections
5.  Accept incoming connections as they arrive
6.  Create a new SSL object for the newly arrived connection
7.  Bind the SSL object to the network socket descriptor

Once these steps are completed successfully, use the functions SSL_read() and
SSL_write() to read from/write to the socket, but using the SSL object rather
then the socket descriptor.  Once the session is complete, free the memory
allocated to the SSL object and close the socket descriptor.

******************************************************************************/

int main(int argc, char **argv)
{
    SSL_CTX*		ssl_ctx;
    unsigned int 	sockfd;
    unsigned int 	port;
    //char			buffer[BUFFER_SIZE];
	int				mp3_count, max_length = 0;

    // Get mp3 file count and file name size
	mp3_count = define_mp3_list(& max_length);
	if (mp3_count <= 0)
		exit(EXIT_FAILURE);
				
	// Initialize mp3 list
	char mp3_list[mp3_count][BUFFER_SIZE];
	memset(mp3_list, 0, mp3_count * BUFFER_SIZE * sizeof(char));	// Runs without it?
	
	// Read directory into list and write list to file
	get_mp3_list(mp3_list);
	write_mp3_file(mp3_list, mp3_count);
	
	if (DEBUG)		// Shows that file list is in main
		for (int i = 0; i < sizeof(mp3_list)/sizeof(mp3_list[0]); i++)
			printf("   String Array #%i: '%s'\n", i, mp3_list[i]);
	
	// Create SSL method
	init_openssl();
	
	// create new SSL connection state object
    ssl_ctx = create_new_context();
	
	// set certificates and keys
    configure_context(ssl_ctx);
	
	// TODO: Create failure transparency here using two static ports
    // Port can be specified on the command line. If it's not, use the default port
    switch(argc) {
		case 1:
			port = DEFAULT_PORT;
			break;
        case 2:
			port = atoi(argv[1]);
			break;
        default:
			fprintf(stderr, "Usage: ssl-server <port> (optional)\n");
			exit(EXIT_FAILURE);
    }

    // Create the underlying TCP socket connection to the remote host
    sockfd = create_socket(port);

    // Wait for incoming connections and handle them as the arrive
    while(true) {
        SSL*            ssl;
        int             client;
        int             validLogin = 0;
        struct          sockaddr_in addr;
        unsigned int    len = sizeof(addr);
        char            client_addr[INET_ADDRSTRLEN];
        
        // Once an incoming connection arrives, accept it.  If this is successful, we
        // now have a connection between client and server and can communicate using
        // the socket descriptor
        client = accept(sockfd, (struct sockaddr*)&addr, &len);
        if (client < 0) {
            fprintf(stderr, "Server: Unable to accept connection: %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }

        // Display the IPv4 network address of the connected client
        inet_ntop(AF_INET, (struct in_addr*)&addr.sin_addr, client_addr, INET_ADDRSTRLEN);
        fprintf(stdout, "Server: Established TCP connection with client (%s) on port %u\n", client_addr, port);
    
        // Here we are creating a new SSL object to bind to the socket descriptor
        ssl = SSL_new(ssl_ctx);

        // Bind the SSL object to the network socket descriptor.  The socket descriptor
        // will be used by OpenSSL to communicate with a client. This function should
        // only be called once the TCP connection is established.
        SSL_set_fd(ssl, client);

        // The last step in establishing a secure connection is calling SSL_accept(),
        // which executes the SSL/TLS handshake.  Because network sockets are
        // blocking by default, this function will block as well until the handshake
        // is complete.
        if (SSL_accept(ssl) <= 0) {
            fprintf(stderr, "Server: Could not establish secure connection:\n");
            ERR_print_errors_fp(stderr);
        }
        else
            fprintf(stdout, "Server: Established SSL/TLS connection with client (%s)\n", client_addr);
			// Don't transmit to client for transparency
        
        // Process username and login while the client username/password combo is incorrect
		while (validLogin != 2)
			validLogin = validateUserLogin(ssl, client_addr, validLogin);

        if (validLogin == 2) {
			run_SongSlinger(ssl, mp3_list, client_addr);

		}
        // Terminate the SSL session, close the TCP connection, and clean up
        fprintf(stdout, "Server: Terminating SSL session and TCP connection with client (%s)\n", client_addr);
        SSL_free(ssl);
        close(client);
    }
    // Tear down and clean up server data structures before terminating
    SSL_CTX_free(ssl_ctx);
    cleanup_openssl();
    close(sockfd);

    return 0;
}

// Check that the operation reads a user name and matches a username in the database
// TODO: integrate this with the client i.e. if return == 0 no user name exists, return == 1 username exists but password was wrong, return == 2 username password combo was correct
int validateUserLogin(SSL* ssl, char client_addr[INET_ADDRSTRLEN], int validLogin) {
    int regCheck = 0;
    char username[BUFFER_SIZE];
    char password[BUFFER_SIZE];
	char buffer[BUFFER_SIZE];
	int serverLoginMsg = 0;
	int clientLoginMsg;
	regex_t regex;					// Regex variable
	
	if (DEBUG)
		printf("Server: Waiting for client to send authentication through SSL...\n");
	
	// SSL_read call
	clientLoginMsg = SSL_read(ssl, buffer, BUFFER_SIZE);
	if (clientLoginMsg < 0) {    // Check the call for errors
		int sslReadError = SSL_get_error(ssl, clientLoginMsg);
		fprintf(stdout, "Error with SSL_read() call: %d.\n", sslReadError);
	}
	
	// Open the file
	FILE* fp = fopen(ACCOUNT_FILE, "r");
	if (fp <= 0) {
		fprintf(stderr, "Server: Error opening password file: %s\n", ACCOUNT_FILE);
		exit(EXIT_FAILURE);
	}
	
    // Regex pattern for: validate login(username, password);
    char *regexPattern = "^validate login[[:punct:]].*, .*[[:punct:]];$";
    
	// Validate regex compiling
    if (regcomp(&regex, regexPattern, REG_EXTENDED) != 0) {
        
	    // Output the error message
        fprintf(stderr, "Error compiling regex using pattern: %s", regexPattern);
        
        // Erase the buffer
        bzero(buffer, BUFFER_SIZE);
        
        // Put the error message in the buffer for the client
        sprintf(buffer, "Error on server side compiling the pattern recognizer, please contact the helpdesk.");
        
        // Write it to the SSL socket descriptor
        send_message(ssl, buffer, BUFFER_SIZE);
        
        return 0;
    
    // Regex compiling was successful
    } else {

        // Examine the string for a pattern match
        regCheck = regexec(&regex, buffer, (size_t) 0, NULL, 0);
        
		if (DEBUG)
			printf("Server received login: '%s'\nServer reading account file:\n", buffer);
		
        // The client sent a matching pattern
        if (regCheck == 0) {
			
            // Assign the entire operation to a string
            char clientUserName[BUFFER_SIZE];
            char clientPassword[BUFFER_SIZE];
	         
            // Use sscanf to assign the username and password
            if (sscanf(buffer, "validate login(%[^,], %[^)];", clientUserName, clientPassword) == 2) {
				
                // Continue until end of the file
                while (!feof(fp)) {
                    // Scan the username, password, and authentication variables from each line
                    fscanf(fp, "%[^;];%[^;];\n", username, password);
					
					if (DEBUG)
						printf("     Username: %s, Password: %s\n", username, password);
                    
                    // The client's username matches a username in the database
                    if (strcmp(username, clientUserName) == 0) {
                        //*** The file password may have the \n still attached to the end of the string
						if (strlen(password) == (strlen(clientPassword) + 2))
							password[strlen(password)-2] = '\0';
													
						if (DEBUG) {
							printf("Server:   username: %s found\n", clientUserName);
							printf("   File password  : '%s'\n", password);
							printf("   Client password: '%s'\n", clientPassword);
							printf("   Password length: %li:%li\n", strlen(password), strlen(clientPassword));
						}

                        // The client's password matches the password in the database
                        if(strcmp(password, clientPassword) == 0) {
                            printf("Server: %s@%s authenticated!\n\n", username, client_addr);
							send_message(ssl, "2", BUFFER_SIZE);
                            return 2;  // Username and password match
                        } else {
							
							// The client's password does not match
							printf("Server: %s@Client entered the wrong password!\n\n", username);
							send_message(ssl, "1", BUFFER_SIZE);
							return 1;  // Username only, error with hash
						}
                    }
                }
            }
        }
    }
    fclose(fp);
	
	// The clients username and password do not match
	printf("Server: Invalid authentication!\n\n");
	send_message(ssl, "0", BUFFER_SIZE);
    return 0;	// No username match found
}