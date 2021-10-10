/******************************************************************************

PROGRAM:    cs469project.c
AUTHOR:     Jeffrey Krauss, Dustin Segawa
COURSE:     CS469 - Distributed Systems (Regis University)
SYNOPSIS:   Description here.

******************************************************************************/

// cd desktop/cs469project
// gcc -o proj cs469project.c
// ./cs469projserver --> listening on 4433
// ./cs469projclient --> asks for username and password
// Client to server command: ./client 98.43.2.117:4433

#include <time.h>
#include <netdb.h>
#include <errno.h>
#include <stdio.h>
#include <resolv.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <fcntl.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

// SSL header files
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#define DEFAULT_PORT        4433        // Primary port
#define BACKUP_PORT         4435        // Backup port for fault tolerance
#define D_HOST              98.43.2.117 // This host for production
#define DEFAULT_HOST        "localhost" // This host for testing
#define JEFF_HOSTNAME       "Jeffreys-MacBook-Pro.local"
#define MAX_HOSTNAME_LENGTH 256
#define BUFFER_SIZE         256
#define USERNAME_LENGTH     32
#define PASSWORD_LENGTH     32
#define HASH_LENGTH         256         // J: hash length shouldn't be over 256
#define DEBUG               true		// D: I use this while building code

// Method declarations
void open_SSL();                                        // Initialize OpenSSL
SSL_CTX* initSSL(void);                                 // Create an SSL client method
int create_socket(char* hostname, unsigned int port);   // Secure TCP connection to server
void login_message();                                   // Login screen message
char* get_login_info();                                 // Get the client's username and hash
void getPassword(char* password);                       // Get the client's password
int send_message(SSL* ssl, char* msg, int char_cnt);	// Sends SSL message and handles errors
int validateUserLogin(SSL* ssl, char buffer[]);         // Authenticate the username/hash with server
void displayMenu(SSL* ssl, char buffer[]);                  // Display the MP3 file menu
void selectSong(SSL* ssl, char buffer[], char songMenu[]);  // Select a song from the MP3 file menu

// Struct representing username and password
struct user_login {
    char username[USERNAME_LENGTH];
    char password[PASSWORD_LENGTH];
} u_login;

/**
  1. TCP connection
  2. SSL/TLS connection (client authenticates server)
  3. Fault tolerant server handling on alternate port
  4. Client login (server authenticates client)
  5. Server authorizes the client
  6. User selects to view music or exit
  7. User downloads a song
  8. User plays song
  9. User selects a new song or exits
  10. Close the sockets
 */
int main(int argc, char** argv) {

    unsigned int      port = DEFAULT_PORT;
    char              remote_host[MAX_HOSTNAME_LENGTH];
    char              buffer[BUFFER_SIZE];
    char*             temp_ptr;
    int               sockfd;
    int               writefd;
    int               rcount;
    int               wcount;
    int               total = 0;
    int               validLogin = 0;
    SSL_CTX*          ssl_ctx;
    SSL*              ssl;
    
    // Set the hostname name so the client doesn't have to
    // TODO: change to JEFF_HOSTNAME when testing on Jeff's machiine
    strncpy(remote_host, DEFAULT_HOST, MAX_HOSTNAME_LENGTH);
    
	// REQ: Client should automatically acquire backup servers when primary servers not available
	
    // Initialize Open_SSL
    open_SSL();
    
    // Create the SSL client method
    ssl_ctx = initSSL();
    
    // Create a new SSL connection state object
    ssl = SSL_new(ssl_ctx);
    
    // Create the underlying TCP socket connection to the remote host
    sockfd = create_socket(remote_host, port);

    // Bind the SSL object to the network socket descriptor
    SSL_set_fd(ssl, sockfd);

    // Initiates an SSL session over the existing socket connection, returns 1 if successful
    if (SSL_connect(ssl) == 1) {}
        // SSL/TLS established, do nothing to allow for transparency
    else {
        fprintf(stderr, "Error: could not establish SSL connection, please contact the help desk for assistance.\n");
        exit(EXIT_FAILURE);
    }
    
    // Display the login message to the client
    login_message();
    
    // Produce a hash using the user's password + salt
    strcpy(u_login.password, get_login_info());
    
    // Send the client's login info to the server for validation
    validLogin = validateUserLogin(ssl, buffer);
    
    // Username and password match, receive file list
    if (validLogin == 2) {
        displayMenu(ssl, buffer);
    }
    
	// REQ: LOOP Client will receive request for termination or list files 

		// REQ: Client will request list of files 
			  // Client will receive list of files 
			  // Client will display list of files to user 

		// REQ: Client will request to play a file 
			  // Client will receive file over buffered transfer 
			  // Client will play MP3 file once received 
			  // Client will delete file once played 

    // Deallocate memory for the SSL data structures and close the socket
    SSL_free(ssl);
    SSL_CTX_free(ssl_ctx);
    close(sockfd);
    fprintf(stdout, "Client: Terminated SSL/TLS connection with server '%s'\n", remote_host);
  
    return(0);
}

// Initializes OpenSSL
void open_SSL() {
    
    // Initialize OpenSSL ciphers and digests
    OpenSSL_add_all_algorithms();

    // SSL_library_init() registers the available SSL/TLS ciphers and digests.
    if(SSL_library_init() < 0) {
        fprintf(stderr, "Client: Could not initialize the OpenSSL library!\n");
        exit(EXIT_FAILURE);
    }
} // End of open_SSL method

// Create the SSL client method
SSL_CTX* initSSL(void) {
    
    const SSL_METHOD*     method;
    SSL_CTX*              ssl_ctx;
    
    // Use the SSL/TLS method for clients
    method = SSLv23_client_method();

    // Create new context instance
    ssl_ctx = SSL_CTX_new(method);
    
    if (ssl_ctx == NULL) {
        fprintf(stderr, "Unable to create a new SSL context structure.\n");
        exit(EXIT_FAILURE);
    }
    
    // This disables SSLv2, which means only SSLv3 and TLSv1 are available
    // to be negotiated between client and server
    SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2);
    
    return ssl_ctx;

}

// Establish a secure TCP connection to the server specified by 'hostname'
int create_socket(char* hostname, unsigned int port) {
    
    int                sockfd;
    struct hostent*    host;
    struct sockaddr_in dest_addr;

    host = gethostbyname(hostname);
    
    if (host == NULL) {
        fprintf(stderr, "Client: Cannot resolve hostname %s\n",  hostname);
        exit(EXIT_FAILURE);
    }
  
    // Create a socket (endpoint) for network communication.
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        fprintf(stderr, "Server: Unable to create socket: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
  
    dest_addr.sin_family=AF_INET;       // Setup a network socket
    dest_addr.sin_port=htons(port);     // Convert TCP port to network byte order using htons()
    dest_addr.sin_addr.s_addr = *(long*)(host->h_addr);  // Netork address of remote host
  
    // Connect to the remote host
    if (connect(sockfd, (struct sockaddr *) &dest_addr, sizeof(struct sockaddr)) < 0) {
        
        // Can't connect to remote host, try backup port
        dest_addr.sin_port=htons(BACKUP_PORT);
        
        // It doesn't work with the backup, exit
        if (connect(sockfd, (struct sockaddr *) &dest_addr, sizeof(struct sockaddr)) < 0) {
            fprintf(stderr, "Client: Cannot connect to host %s [%s] on port %d: %s\n",
                hostname, inet_ntoa(dest_addr.sin_addr), port, strerror(errno));
            exit(EXIT_FAILURE);
        }
    }
    
    return sockfd;
    
} // End of create_socket method

// Output login message to the client
void login_message() {
    fprintf(stdout, "\nWelcome to Song Slinger!\n\nEnter your username and password.\n\n");
}

// Get the user's login information: username and password
char* get_login_info() {
    
    const char seedchars[64] = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    static char hash[HASH_LENGTH];
    char salt[] = "$1$........";  // $1$ == MD5
   
    // Assign a seed for random generation - should give the same salt each time
    srand(2);
    
    // Convert the remaining salt characters into pseudorandom numbers
    for (int i = 0; i < 8; i++) {
        salt[3+i] = seedchars[rand() % (sizeof(seedchars) - 1)];
    }
    
    // Enter the username that will be stored with the hash
    fprintf(stdout, "Enter username: ");
    fgets(u_login.username, sizeof(u_login.username), stdin);
    u_login.username[strlen(u_login.username)-1] = '\0';
    
    // Enter the password
    fprintf(stdout, "Enter password: ");
    getPassword(u_login.password);
    
    // Now we create a cryptographic hash of the password with the SHA256
    // algorithm using the generated salt string
    strncpy(hash, crypt(u_login.password, salt), HASH_LENGTH);
	
    if (DEBUG)   // D: I use these while building code
        printf("Client: Salt is: %s, Password with hash: %s\n", salt, hash);

    // Let's just get rid of that password since we're done with it
    bzero(u_login.password, PASSWORD_LENGTH);
    
    return hash;
}

// This function reads in a character string that represents a password,
// but does so while not echoing the characters typed to the console.
void getPassword(char* password) {
    static struct termios oldsettings, newsettings;
    int c, i = 0;

    // Save the current terminal settings and copy settings for resetting
    tcgetattr(STDIN_FILENO, &oldsettings);
    newsettings = oldsettings;

    // Hide, i.e., turn off echoing, the characters typed to the console
    newsettings.c_lflag &= ~(ECHO);

    // Set the new terminal settings
    tcsetattr(STDIN_FILENO, TCSANOW, &newsettings);

    // Read the password from the console one character at a time
    while ((c = getchar())!= '\n' && c != EOF && i < HASH_LENGTH)
      password[i++] = c;
    
    password[i] = '\0';

    // Restore the old (saved) terminal settings
    tcsetattr(STDIN_FILENO, TCSANOW, &oldsettings);
	
	printf("\n");		// new line after hiding password
	
	if (DEBUG)	// D: I use these while building code
		printf("Client: Password Entered: '%s'\n", password);
    
} // End of getPassword

/******************************************************************************
This function is repeated throughout the program, so it takes in parameters necessary
to perform SSL message transfer functions, and takes care of error handling.
ssl: required for sending SSL message
msg: data content in char string format
char_cnt: bytes sent in message, necessary for client to determine error messages
******************************************************************************/
int send_message(SSL* ssl, char* msg, int char_cnt) {
	int		nbytes_written;
  	
	nbytes_written = SSL_write(ssl, msg, char_cnt);		// transmit message to client
	
	if (nbytes_written <= 0) {							// test for written byte count
		fprintf(stderr, "Server: Could not write message to client: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	} else
		if (DEBUG)										// show result message
			printf("Server: Message transmitted to client: \"%s\"\n", msg);

	return errno;
}	// End of send_message

// Validates the username and password (hash) with the server
int validateUserLogin(SSL* ssl, char buffer[]) {
    
    // The read username operation is in formate: read login(client_username, client_password);
    char clientLoginInfo[BUFFER_SIZE] = {0};
    
    // Zero the buffer
    bzero(buffer, BUFFER_SIZE);
    
    // Concatenate the string with the operation
    snprintf(clientLoginInfo, BUFFER_SIZE, "validate login(%s, %s);", u_login.username, u_login.password);
	
    // Copy the operation to the buffer
    strcpy(buffer, clientLoginInfo);
    
	if (DEBUG)
		printf("Client: Info sent to server: %s\n", buffer);
	
    // Send the operation to the server
    int clientLoginMsg = SSL_write(ssl, buffer, BUFFER_SIZE);
    
    // Check the call for errors
    if (clientLoginMsg < 0) {
        int sslWriteError = SSL_get_error(ssl, clientLoginMsg);
        fprintf(stdout, "Error: could not send username to the server, please contact the help desk for assistance.\n");
        exit(EXIT_FAILURE);
    }
    
    // Receive confirmation message from server
	clientLoginMsg = SSL_read(ssl, buffer, BUFFER_SIZE);
    
    if (strcmp(buffer, "0") == 0) {
        printf("Client: Username does not exist on server, please enter a valid user name.\n");
        return 0;
    } else if (strcmp(buffer, "1") == 0) {
		printf("Client: Server password does not match.\n");
        return 1;
    } else if (strcmp(buffer, "2") == 0) {
		printf("Client: Server Login Successful!\n");
		return 2;
	}
    
} // End of validateUserLogin

// Loop that asks the client to see the song menu or exit the program
void displayMenu(SSL* ssl, char buffer[]) {
    
    int     userInput = 0;          // User input select to exit or view the a song menu
    int     exitFlag = 0;           // Exit while loops without return per Regis standards
    char    selectAgain;            // Char variable to select another song or not
    char    songMenu[BUFFER_SIZE];  // Song menu for the client to view
    
    // Get the mp3 file message from the buffer
    int mp3FileMsg = SSL_read(ssl, buffer, BUFFER_SIZE);

    strcpy(songMenu, buffer);  // Copy the buffer into a song menu to free up the buffer
    
    printf("\n");  // New line to clean up the output
    
    while(exitFlag != 1) {
        // First ask the user if they want to see the song menu or exit
        printf("1: View the song menu.\n");
        printf("2: Exit the program.\n");
        printf("Please enter your input:\n");
        scanf("%d", &userInput);
        printf("\n");
        
        size_t i = 0;  // Iteration variable
        
        switch(userInput) {
            // Loop through the song menu and display the string names
            case 1:
                printf("Song Menu:\n");
                while (songMenu[i] != '\0') {
                    if (songMenu[i] == ';') {
                        printf("\n");
                        i++;
                    }
                    if (songMenu[i] != '\0') {
                        printf("%c", songMenu[i]);
                        i++;
                    }
                }
                printf("\n");  // Clean up the output
                
                // Select a song and send it to the server
                selectSong(ssl, buffer, songMenu);
                
                // Loop to allow the client to select another song or exit
                while(exitFlag != 1) {
                    
                    // Ask the client to select another song or not
                    printf("\nEnter Y to select another song or N to exit the program:\n");
                    scanf(" %c", &selectAgain);
                    fflush(stdin);
                    
                    size_t j = 0;  // Iteration variable
                    
                    printf("\n");  // Clean up the output
                    
                    switch(selectAgain) {
                        // Yes, show the menu and allow another selection
                        case 'Y':
                            printf("Song Menu:\n");
                            while (songMenu[j] != '\0') {
                                if (songMenu[j] == ';') {
                                    printf("\n");
                                    j++;
                                }
                                if (songMenu[j] != '\0') {
                                    printf("%c", songMenu[j]);
                                    j++;
                                }
                            }
                            printf("\n");
                            selectSong(ssl, buffer, songMenu);
                            break;
                        
                        // They don't want to select another song, exit program
                        case 'N':
                            printf("Exiting program.\n");
                            printf("Thank you for using Song Slinger!.\n");
                            exitFlag = 1;
                            break;
                        
                        // They have to type Y or N to continue
                        default:
                            printf("Please type either Y or N\n");
                            break;
                    } // End of inner switch statement
                } // End of inner while loop
                break;
            
            // Exit the entire method
            case 2:
                printf("Thank you for using Song Slinger!\n\n");
                exitFlag = 1;
                break;

            // Remind the client to select either 1 or 2
            default:
                printf("Please type either 1 or 2\n\n");
                break;
                
        } // End of outer switch statement
    } // End of outer while loop
} // End of displayMenu method

// Select a song from the song menu
void selectSong(SSL* ssl, char buffer[], char songMenu[]) {
    
    char song[BUFFER_SIZE];  // The song selection that the user types
    
    // Ask the user for a song selection
    printf("Please type the song you want to play\n");
    scanf(" %[^\n]", song);
    fflush(stdin);
        
    if (DEBUG)
        printf("Song selected by user is: %s\n", song);
    
    // TODO: finds any substring so make sure it's an exact match
    char *foundSong = strstr(songMenu, song);  // Look for song as substring of songMenu
        
    if (foundSong) {
        if (DEBUG)
            printf("Song found in song menu.\n");
            
        bzero(buffer, BUFFER_SIZE);                 // Erase the buffer
        strcpy(buffer, song);                       // Copy the song name to the buffer
        send_message(ssl, buffer, BUFFER_SIZE);     // Send the song selection back to the buffer
        
        
        // TODO: receive the song from the buffer, play it, return to previous method
            
        } else {
            printf("Song does not exist. Please check your spelling.\n");
        }
    
} // End of selectSong
