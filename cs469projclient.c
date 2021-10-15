/******************************************************************************

PROGRAM:    cs469projclient.c
AUTHOR:     Jeffrey Krauss, Dustin Segawa
COURSE:     CS469 - Distributed Systems (Regis University)
SYNOPSIS:   Description here.

******************************************************************************/
// Client to server command: ./client 98.43.2.117:4433

#include <time.h>
#include <netdb.h>
#include <fcntl.h>
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
#include <SDL2/SDL.h>
#include <SDL2/SDL_mixer.h>

// SSL header files
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#define DEFAULT_PORT        4433        // Primary port
#define BACKUP_PORT         4434        // Backup port for fault tolerance
#define D_HOST              "98.43.2.117" // This host for production
#define DEFAULT_HOST        "localhost" // This host for testing
#define SONG_FILE_LOC       "./mp3/a.mp3"
#define MAX_HOSTNAME_LENGTH 256
#define BUFFER_SIZE         256
#define ERRSTR_SIZE			4
#define USERNAME_LENGTH     32
#define PASSWORD_LENGTH     32
#define HASH_LENGTH         256         // J: hash length shouldn't be over 256
#define DEBUG               true		// D: I use this while building code

// Method declarations
void open_SSL();                                            // Initialize OpenSSL
SSL_CTX* initSSL(void);                                     // Create an SSL client method
int create_socket(char* hostname, unsigned int port);       // Secure TCP connection to server
void login_message();                                       // Login screen message
char* get_login_info();                                     // Get the client's username and hash
void getPassword(char* password);                           // Get the client's password
int send_message(SSL* ssl, char* msg, int char_cnt);        // Sends SSL message and handles errors
int validateUserLogin(SSL* ssl, char buffer[]);             // Authenticate the username/hash with server
void displayMenu(SSL* ssl, char buffer[]);                  // Display the MP3 file menu
void selectSong(SSL* ssl, char buffer[], char songMenu[]);  // Select a song from the MP3 file menu
void idSSLReadError(int sslReadError);                      // Error identification for SSL_read() call
void errorCreatingFD(int fd);                               // Error handling for creating file descriptors
void playMP3File(int mp3_fd);                               // Plays an MP3 file
void deleteMP3File();                                       // Deletes an MP3 file

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
    
	// Loops until logged in TODO: find an escape without crashing server
    do {
		// Display the login message to the client
		login_message();
		
        // Produce a hash using the user's password + salt
        strcpy(u_login.password, get_login_info());
    
        // Send the client's login info to the server for validation
        validLogin = validateUserLogin(ssl, buffer);
        
    } while (validLogin != 2);
    
    // Username and password match, receive file list
    if (validLogin == 2) {
        displayMenu(ssl, buffer);
    }

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
	} else {
        printf("Error with username or password.\n");
        return 0;
    }
    
} // End of validateUserLogin

// Loop that asks the client to see the song menu or exit the program
void displayMenu(SSL* ssl, char buffer[]) {
    
    int     userInput = 0;          // User input select to exit or view the a song menu
    int     exitFlag = 0;           // Exit while loops without return per Regis standards
    char    selectAgain;            // Char variable to select another song or not
    char    songMenu[BUFFER_SIZE];  // Song menu for the client to view
	int		songCounter = 1;
    
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
                printf("Song Menu:\n1 - ");
                while (songMenu[i] != '\0') {
                    if (songMenu[i] == ';') {
                        songCounter++;
						if(songMenu[i+1] == '\0')
							printf("\n");
						else
							printf("\n%i - ", songCounter);
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
							send_message(ssl, "Y", BUFFER_SIZE);
							songCounter = 1;
                            printf("Song Menu:\n1 - ");
                            while (songMenu[j] != '\0') {
                                if (songMenu[j] == ';') {
									songCounter++;
									if(songMenu[j+1] == '\0')
										printf("\n");
									else
										printf("\n%i - ", songCounter);
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
							send_message(ssl, "N", BUFFER_SIZE);
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
    
    int mp3_fd = 0;         // MP3 file descriptor
    int rcount = 0;         // Number of bytes read from SSL_read()
    int wcount = 0;         // Number of bytes written to mp3 file
    int count = 0;          // Used with debugging to confirm file size
    int getFileSize = 0;    // SSL_read() to get a file size from server
    long fileSize = 0;      // File size after conversion from str to long int
    char *endptr;           // Pointer for string to long int conversion
    char song[BUFFER_SIZE]; // The song selection that the user types
	bool reading_state = true;
    
    // Ask the user for a song selection
    printf("Please type the song you want to play\n");
    scanf(" %[^\n]", song);
    fflush(stdin);
        
    if (DEBUG)
        printf("\nSong selected by user is: %s.\n", song);
    
    // TODO: finds any substring so make sure it's an exact match
    char *foundSong = strstr(songMenu, song);  // Look for song as substring of songMenu
        
    if (foundSong) {
        if (DEBUG)
            printf("Song exists in song menu.\n");
        
        bzero(buffer, BUFFER_SIZE);                 // Erase the buffer
        strcpy(buffer, song);                       // Copy the song name to the buffer
        send_message(ssl, buffer, BUFFER_SIZE);     // Send the song selection back to the buffer
        
        // Get the file size from the server
        getFileSize = SSL_read(ssl, buffer, BUFFER_SIZE);
        
        if (DEBUG)
            printf("File size is: %s\n", buffer);
        
        errno = 0;                              // Don't want to use a previous errno value
        fileSize = strtol(buffer, &endptr, 0);  // Convert the file size string to a long int
        
        // Check for errors
        if (errno != 0) {
            fprintf(stderr, "Error reading the file size: %s.\n", strerror(errno));
            exit(EXIT_FAILURE);
        }

        // No digits found in the buffer string
        if (endptr == buffer) {
            fprintf(stderr, "Error reading the file size: %s.\n", strerror(errno));
            exit(EXIT_FAILURE);
        }
        
        if (DEBUG)
            printf("File size after long int conversion is: %ld.\n", fileSize);
        
        
		if( access(SONG_FILE_LOC, F_OK ) == 0 )		// file exists
			deleteMP3File();					// Delete the file
		
		// Create the file for read and write access	
		mp3_fd = open(SONG_FILE_LOC, O_RDWR | O_CREAT, 0);
		
        // File descriptor created successfully
        if (mp3_fd >= 0) {
            
            if (DEBUG)
                printf("MP3 file created on client.\n");
			
			int i = 0;

            // SSL_read and write to the mp3 file while bytes remain
            do {
				// SSL_read call
                bzero(buffer, BUFFER_SIZE);
				rcount = SSL_read(ssl, buffer, BUFFER_SIZE);
				buffer[rcount] = '\0';                      		// Null terminate
                
                // Identify any errors with SSL_read()
                if (rcount <= 0) {
					reading_state = false;							// flags exit loop
                    if (DEBUG) {
                        int sslReadError = SSL_get_error(ssl, rcount);
                        idSSLReadError(sslReadError);
                    }
					
				//***** Added this block to handle terminal codes
                } else if (rcount == ERRSTR_SIZE) {					// check based on data size
					// 0 is end of file
					if (strcmp(buffer, "0") == 0) {
						fprintf(stdout, "Client: Successfully received mp3 file...\n");
						reading_state = false;						// flags exit loop
					
					// all other terminal errors
					} else if (0 < atoi(buffer) && atoi(buffer) <= 13) {
						fprintf(stderr, "Client: Could not retrieve file: %s\n",
														strerror(atoi(buffer)));
						reading_state = false;						// flags exit loop
					
					/* NOTE: numbers 0-13 transferred as data would be less
					than 4 bytes unless surrounded by white space */
					
					} else {
					// not a terminal error message, write to copy
						wcount = write(mp3_fd, buffer, rcount);     // Write the bytes to the MP3 fd
						count += wcount;                            // Sum the bytes written
						bzero(buffer, BUFFER_SIZE);                 // Erase the buffer
					}
				// SSL_read() is successful
                } else {
                    //buffer[rcount] = '\0';                 	// Null terminate
                    wcount = write(mp3_fd, buffer, rcount);     // Write the bytes to the MP3 fd
					count += wcount;                            // Sum the bytes written
                    bzero(buffer, BUFFER_SIZE);                 // Erase the buffer
                }
                
            // Continue while data is being sent by the server
            } while (reading_state);
            
            if (DEBUG)
                printf("\nTotal amount written to MP3 file is: %d\n", count);
            
        // Error creating the file descriptor
        } else {
            errorCreatingFD(mp3_fd);
        }
        
        // Check that the bytes written local file match the file size read by the server
        if (count != fileSize) {
            printf("File size does not match the file sent by Song Slinger, exiting program.\n");
            exit(EXIT_FAILURE);
        }
        
        // Play the MP3 file
        // playMP3File(mp3_fd);	// disabled for Dustin's broken client...
        
        // Delete the file
        deleteMP3File();
        
        close(mp3_fd);
            
        } else {
            printf("Song not found on the song menu. Please check your spelling.\n");
        }

    
} // End of selectSong

// Plays an MP3 file using the file descriptor
// Based on Dr. Hemmes playaudio.c file
void playMP3File(int mp3_fd) {
    
    char song_buffer[128];             // Used to read the entire 128-byte ID3 tag
    
    // Get the metadata for the song
    lseek(mp3_fd, -128L, SEEK_END);
    
    // Read the 128-byte ID3 tag from the end of the file
    read(mp3_fd, song_buffer, 128);
    
    // Open the MP3 file. 44.1kHz represents the sample rate, 2 = stereo,
    // and 1024 means the file will be processed in 1 KB chunks.
    if (Mix_OpenAudio(44100, AUDIO_S16SYS, 2, 1024) < 0) {
        fprintf(stderr, "Error opening MP3 file to play: %s.\n", Mix_GetError());
        exit(EXIT_FAILURE);
    }
    
    // Loads the music file
    Mix_Music *music = Mix_LoadMUS(SONG_FILE_LOC);
    if(!music) {
        fprintf(stderr, "Error loading the MP3 file to play: %s.\n", Mix_GetError());
        exit(EXIT_FAILURE);
    }
    
    // Play the music! The second parameter sets the number of times to play
    // the song. A value of -1 is used for looping.
    Mix_PlayMusic(music, 1);
    
    // This needs to be here otherwise the program terminates immediately.
    // Delay value doesn't seem to matter much. Once the music stops playing,
    // program exits the loop and terminates.
    while (1) {
        SDL_Delay(200);
        if (Mix_PlayingMusic() == 0)
            break;
    }
    
    // Clean up dynamically allocated memory
    Mix_FreeMusic(music);
    Mix_CloseAudio();
    Mix_Quit();
    
} // End of playMP3File method

// Deletes a file from the local system
void deleteMP3File() {
    
    int deleteFile = 0;
    
    deleteFile = remove(SONG_FILE_LOC);
    
    if (deleteFile == 0) {
        if (DEBUG)
            printf("File deleted succesfully.\n");
    } else {
        fprintf(stderr, "Error deleting file from user's system: %s.\n", strerror(errno));
        fprintf(stdout, "Exiting program.\n");
        exit(EXIT_FAILURE);
    }
    
}

// Handle errors when creating a file descriptor
void errorCreatingFD(int fd) {
    fprintf(stderr, "Error creating %d: %s.\n", fd, strerror(errno));
    fprintf(stdout, "Exiting program.\n");
    exit(EXIT_FAILURE);
}

// Passes an error from SSL_get_error and outputs the error message
void idSSLReadError(int sslReadError) {
    
    fprintf(stdout, "Error with SSL_read() call, id returned: %d.\n", sslReadError);
    
    if (sslReadError == SSL_ERROR_ZERO_RETURN)
        fprintf(stderr, "SSL_ERROR_ZERO_RETURN: %s\n", strerror(errno));
    if (sslReadError == SSL_ERROR_WANT_READ)
        fprintf(stderr, "SSL_ERROR_WANT_READ: %s\n", strerror(errno));
    if (sslReadError == SSL_ERROR_WANT_WRITE)
        fprintf(stderr, "SSL_ERROR_WANT_WRITE: %s\n", strerror(errno));
    if (sslReadError == SSL_ERROR_WANT_CONNECT)
        fprintf(stderr, "SSL_ERROR_WANT_CONNECT: %s\n", strerror(errno));
    if (sslReadError == SSL_ERROR_WANT_ACCEPT)
        fprintf(stderr, "SSL_ERROR_WANT_ACCEPT: %s\n", strerror(errno));
    if (sslReadError == SSL_ERROR_WANT_X509_LOOKUP)
        fprintf(stderr, "SSL_ERROR_WANT_X509_LOOKUP: %s\n", strerror(errno));
    if (sslReadError == SSL_ERROR_SYSCALL)
        fprintf(stderr, "SSL_ERROR_SYSCALL: %s\n", strerror(errno));
        
    // Once bytes are 0, it may produce this error message, in that case ignore it
    if (sslReadError == SSL_ERROR_SSL)
        fprintf(stderr, "SSL_ERROR_SSL: %s\n", strerror(errno));
        
} // End of idSSLReadError
