/******************************************************************************

PROGRAM:  cs469projclient.c
AUTHOR:     Jeffrey Krauss, Dustin Segawa
COURSE:     CS469 - Distributed Systems (Regis University)
SYNOPSIS:  Client program in a client-server architecture which allows
the client to download and play mp3 files from the server.  The client
verifies the server via SSL over TCP, then the server authenticates the
client with a username and password.  After authentication, the client
can request a list of songs and select a song.  This selection is sent to
the server and the server then transfers the file over SSL to the client.
After the song has been received, the client plays the entire song using
the SDL2 library.  After the song is finished, the client can continue to
select and play songs in a loop, or exit the program.  Upon exit or any
failure, the SSL/TCP connection is closed and the program exits.

******************************************************************************/

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

// SDL2 allows client to play MP3 songs
#include <SDL2/SDL.h>
#include <SDL2/SDL_mixer.h>

// SSL header files
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#define DEFAULT_PORT        4433           // Primary port
#define BACKUP_PORT         4434           // Backup port for fault tolerance
#define PROD_HOST           "98.43.2.117"  // This host for production
#define DEFAULT_HOST        "localhost"    // This host for testing
#define SONG_FILE_LOC       "./mp3/a.mp3"  // File name and location for local mp3 file
#define MAX_HOSTNAME_LENGTH 256
#define BUFFER_SIZE         256            // Main buffer used for SSL_read/write calls
#define ERRSTR_SIZE         4
#define USERNAME_LENGTH     32
#define PASSWORD_LENGTH     32
#define HASH_LENGTH         256
#define DEBUG               true           // Set to true to see program flow

// Method declarations
void open_SSL();                                                                // Initialize OpenSSL
SSL_CTX* initSSL(void);                                                         // Create an SSL client method
int create_socket(char* hostname, unsigned int port);                           // Secure TCP connection to server
void login_message();                                                           // Login screen message
char* get_login_info();                                                         // Get the client's username and hash
void get_password(char* password);                                              // Get the client's password
int send_message(SSL* ssl, char* msg, int char_cnt);                            // Sends SSL message and handles errors
int validate_user_login(SSL* ssl, char buffer[]);                               // Authenticate the username/hash with server
void display_menu(SSL* ssl, char buffer[]);                                     // Display the MP3 file menu
void select_song(SSL* ssl, char buffer[], char songMenu[], int songCounter);    // Select a song from the MP3 file menu
void play_mp3_file(int mp3_fd);                                                 // Plays an MP3 file
void delete_mp3_file();                                                         // Deletes an MP3 file
void error_creating_fd(int fd);                                                 // Error handling for creating file descriptors
void id_SSL_read_error(int sslReadError);                                       // Error identification for SSL_read() call

// Struct representing client username and password
struct user_login {
    char username[USERNAME_LENGTH];
    char password[PASSWORD_LENGTH];  // This is a hash, the password is not stored
} u_login;

/**
  1. TCP connection
  2. Fault tolerant server handling on alternate port
  3. SSL/TLS connection (client authenticates server)
  4. Client login (server authenticates client)
  5. Client selects to view music or exit
  6. Client selects a song
  7. Server sends/client receives the song
  8. Client plays song
  9. Client selects a new song or exits
  10. Close the sockets
  11. Program exits
 */
int main(int argc, char** argv) {

    unsigned int      port = DEFAULT_PORT;
    char              remote_host[MAX_HOSTNAME_LENGTH];
    char              buffer[BUFFER_SIZE];
    char*             temp_ptr;
    int               sockfd = 0;
    int               writefd = 0;
    int               rcount = 0;
    int               wcount = 0;
    int               loginAttempts = 0;
    int               validLogin = 0;
    SSL_CTX*          ssl_ctx;
    SSL*              ssl;
    
    // Set the hostname name for transparency sake
    strncpy(remote_host, PROD_HOST, MAX_HOSTNAME_LENGTH);
    
    // Initialize Open_SSL
    open_SSL();
    
    // Create the SSL client method
    ssl_ctx = initSSL();
    
    // Create a new SSL connection state object
    ssl = SSL_new(ssl_ctx);

    // Create the underlying TCP socket connection to the remote host on default port
    sockfd = create_socket(remote_host, port);
    if (sockfd != 0) {
        if (DEBUG)
            printf("Client: connected to host on port: %d\n", port);
    
    // It didn't work, try the backup port
    } else {
        if (DEBUG)
            printf("Client: no connection made with port: %d\n", port);
        port = BACKUP_PORT;
        sockfd = create_socket(remote_host, port);
        if (sockfd != 0) {
            if (DEBUG)
                printf("Client: connected to host on port: %d\n", port);
            else {
                if (DEBUG)
                    printf("Client: no connection made with port: %d\n", port);
                printf("No connection made with server on either port, please contact the help desk for assistance.\nExiting program.\n");
                exit(EXIT_FAILURE);
            }
        }
    }

    // Bind the SSL object to the network socket descriptor
    SSL_set_fd(ssl, sockfd);

    // Initiates an SSL session over the existing socket connection, returns 1 if successful
    if (SSL_connect(ssl) == 1) {
        if (DEBUG)
            printf("Client: SSL connection over TCP successful.\n");
    }
    
    // SSL/TLS not established, exit program
    else {
        fprintf(stderr, "Error: Could not establish SSL connection, please contact the help desk for assistance.\n");
        exit(EXIT_FAILURE);
    }
    
    // Loops until login successful and less than 3 attempts made
    do {
        login_message();
        
        // Produce a hash using the user's password + salt
        strcpy(u_login.password, get_login_info());
    
        // Send the client's login info to the server for validation
        validLogin = validate_user_login(ssl, buffer);
        
        // Increment login attempts
        loginAttempts++;
        
        // If client unsuccessful on the 3rd time, exit the program
        if (validLogin != 2 && loginAttempts == 3) {
            printf("\nMax Login Attempts Reached: %d.\n", loginAttempts);
            printf("Contact the Help Desk for Assistance.\n");
            printf("Exiting program.\n\n");
            exit(EXIT_FAILURE);
        }
        
    } while (validLogin != 2);
    
    // Username and password match, start receive file list, select song, play song loop
    if (validLogin == 2) {
        display_menu(ssl, buffer);
    }

    // Deallocate memory for the SSL data structures and close the socket
    SSL_free(ssl);
    SSL_CTX_free(ssl_ctx);
    close(sockfd);
    
    if (DEBUG)
        printf("Client: Terminated SSL/TLS connection with server '%s'\n", remote_host);
  
    return(0);
}

/**
 Initializes OpenSSL
 */
void open_SSL() {
    
    // Initialize OpenSSL ciphers and digests
    OpenSSL_add_all_algorithms();

    // SSL_library_init() registers the available SSL/TLS ciphers and digests.
    if(SSL_library_init() < 0) {
        fprintf(stderr, "Error: Could not initialize the OpenSSL library, please contact the help desk for assistance.\n");
        exit(EXIT_FAILURE);
    }
    
} // End of open_SSL method

/**
 Creates the SSL client method and returns SSL_CTX object
 */
SSL_CTX* initSSL(void) {
    
    const SSL_METHOD*     method;
    SSL_CTX*              ssl_ctx;
    
    // Use the SSL/TLS method for clients
    method = SSLv23_client_method();

    // Create new context instance
    ssl_ctx = SSL_CTX_new(method);
    
    if (ssl_ctx == NULL) {
        fprintf(stderr, "Error: Unable to create a new SSL context structure, please contact the help desk for assistance.\n");
        exit(EXIT_FAILURE);
    }
    
    // This disables SSLv2, which means only SSLv3 and TLSv1 are available
    // to be negotiated between client and server
    SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2);
    
    return ssl_ctx;

} // End of initSSL method

/**
 Establishes a secure TCP connection to the server specified by hostname and returns the socket descriptor
 */
int create_socket(char* hostname, unsigned int port) {
    
    int                sockfd;
    struct hostent*    host;
    struct sockaddr_in dest_addr;

    host = gethostbyname(hostname);
    
    if (host == NULL) {
        fprintf(stderr, "Error: Cannot resolve hostname: %s, please contact the help desk for assistance.\n",  hostname);
        exit(EXIT_FAILURE);
    }
  
    // Create a socket (endpoint) for network communication.
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    
    if (sockfd < 0) {
        fprintf(stderr, "Error: Unable to create socket: %s, please contact the help desk for assistance.\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
  
    dest_addr.sin_family=AF_INET;                        // Setup a network socket
    dest_addr.sin_port=htons(port);                      // Convert TCP port to network byte order using htons()
    dest_addr.sin_addr.s_addr = *(long*)(host->h_addr);  // Netork address of remote host
  
    // Connect to the remote host
    if (connect(sockfd, (struct sockaddr *) &dest_addr, sizeof(struct sockaddr)) < 0) {
        
        // It doesn't work with the default port
        if (connect(sockfd, (struct sockaddr *) &dest_addr, sizeof(struct sockaddr)) < 0) {
            fprintf(stderr, "Error: Cannot connect to host %s [%s] on  port %d, please contact the help desk for assistance.\n: %s\n",
                hostname, inet_ntoa(dest_addr.sin_addr), port, strerror(errno));
            return 0;
        }
    }
    
    return sockfd;
    
} // End of create_socket method

/**
 Used to output a login message to the client
 */
void login_message() {
    
    fprintf(stdout, "\nWelcome to Song Slinger!\n\nEnter your username and password.\n\n");
    
} // End of login_message

/**
 1. Receive the username and password typed in by the client.
 2. Clients are already registered on the server with the client username and hash.
 3. Here the client enters a username and password, salt is added to the password, then it is hashed.
 4. This is assigned to a login struct, hash is returned, and this is later used for client authentication on the server side.
 5. To prevent a different hash each time, an SRAND seed is used.
 6. This seed allows the same password + salt to create the same hash each time, rather than other pseudorandom methods (time(NULL), pid(), etc.)
 7. If the wrong password is entered, the password + salt hash will not be authenticated by the server because it will not match the username/hash database
 */
char* get_login_info() {
    
    const char seedchars[64] = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    static char hash[HASH_LENGTH];
    char salt[] = "$1$........";  // $1$ = MD5
   
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
    get_password(u_login.password);
    
    // Create a hash using the password and salt
    strncpy(hash, crypt(u_login.password, salt), HASH_LENGTH);
    
    // Should generate the same salt each time
    if (DEBUG) {
        printf("Salt is: '%s'\n", salt);
        printf("Hash is: '%s'\n\n", hash);
    }

    // Let's just get rid of that password since we're done with it
    bzero(u_login.password, PASSWORD_LENGTH);
    
    return hash;
    
} // End of get_login_info method

/**
 Used in conjunction with the get_login_method to read a string representing a password without
 echoing the characters typed to the consol
 */
void get_password(char* password) {
    static struct termios oldsettings, newsettings;
    int c, i = 0;

    // Save the current terminal settings and copy settings for resetting
    tcgetattr(STDIN_FILENO, &oldsettings);
    newsettings = oldsettings;

    // Turn off echoing
    newsettings.c_lflag &= ~(ECHO);

    // Set the new terminal settings
    tcsetattr(STDIN_FILENO, TCSANOW, &newsettings);

    // Read the password from the console one character at a time
    while ((c = getchar())!= '\n' && c != EOF && i < HASH_LENGTH)
      password[i++] = c;
    
    password[i] = '\0';

    // Restore the old (saved) terminal settings
    tcsetattr(STDIN_FILENO, TCSANOW, &oldsettings);
    
} // End of get_password

/**
 The SSL_write() call is used frequently throughout the program, this method is used to call
 SSL_write() and handle errors, returns errno
 */
int send_message(SSL* ssl, char* msg, int char_cnt) {
    
    int nbytes_written = 0;
    
    // Transmit the message to the client
    nbytes_written = SSL_write(ssl, msg, char_cnt);
    
    // Check the call for failure or success
    if (nbytes_written <= 0) {
        fprintf(stderr, "Client: Could not write message to server: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    } else
        if (DEBUG)
            printf("Client: Message transmitted to server: \"%s\"\n", msg);

    return errno;
    
} // End of send_message

/**
 1. Creates an operation: "validate login(username, hash)"
 2. Sends the operation to the server for operation validation then client authentication
 3. Receives 3 possible values from server: 0 (username does not exist), 1 (password incorrect), 2 (login successful)
 4. Any misc error returns 0
 */
int validate_user_login(SSL* ssl, char buffer[]) {
    
    int clientLoginMsg = 0;
    char clientLoginInfo[BUFFER_SIZE] = {0};
    
    // Zero the buffer
    bzero(buffer, BUFFER_SIZE);
    
    // Concatenate the string with the operation
    snprintf(clientLoginInfo, BUFFER_SIZE, "validate login(%s, %s);", u_login.username, u_login.password);
    
    // Copy the operation to the buffer
    strcpy(buffer, clientLoginInfo);
    
    // Send the operation to the server
    clientLoginMsg = SSL_write(ssl, buffer, BUFFER_SIZE);
    
    // Check the call for errors
    if (clientLoginMsg < 0) {
        int sslWriteError = SSL_get_error(ssl, clientLoginMsg);
        fprintf(stdout, "Error: could not send username to the server, please contact the help desk for assistance.\n");
        exit(EXIT_FAILURE);
    }
    
    // Receive confirmation message from server
    clientLoginMsg = SSL_read(ssl, buffer, BUFFER_SIZE);
    
    if (strcmp(buffer, "0") == 0) {
        printf("\n\nUsername does not exist, please enter a valid user name.\n");
        return 0;
    } else if (strcmp(buffer, "1") == 0) {
        printf("\n\nPassword does not match, please enter a valid password.\n");
        return 1;
    } else if (strcmp(buffer, "2") == 0) {
        printf("\n\nLogin Successful!\n");
        return 2;
    } else {
        printf("\n\nError with username or password, please enter a valid username and password.\n");
        return 0;
    }
    
} // End of validate_user_login

/**
 1. Receives a list of downloadable files from the server
 2. Displays the list and allows looping (after a selection is made)
 */
void display_menu(SSL* ssl, char buffer[]) {
    
    int     mp3FileMsg = 0;         // SSL_read call to receive the list of songs
    int     userInput = 0;          // User input select to exit or view the a song menu
    int     exitFlag = 0;           // Exit while loops without return per Regis standards
    int     songCounter = 1;        // Incrementer for clean song menu output
    char    selectAgain;            // Char variable to select another song or not
    char    songMenu[BUFFER_SIZE];  // Song menu for the client to view
    
    // Get the mp3 file message from the buffer
    mp3FileMsg = SSL_read(ssl, buffer, BUFFER_SIZE);

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
                songCounter = 1;
                printf("Song Menu:\n1 - ");
                while (songMenu[i] != '\0' ) {
                    if (songMenu[i] == ';') {
                        songCounter++;
                        if (songMenu[i+1] == '\0')
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
                select_song(ssl, buffer, songMenu, songCounter);
                
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
                            
                            select_song(ssl, buffer, songMenu, songCounter);
                            break;
                        
                        // They don't want to select another song, exit program
                        case 'N':
                            send_message(ssl, "N", BUFFER_SIZE);
                            printf("Exiting program.\n\n");
                            printf("Thank you for using Song Slinger!\n\n");
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
} // End of display_menu method

/**
 1. Allows the client to select a song from the menu that was displayed
 2. Confirms the song number does exist in the current menu
 3. Sends the song selection to the server
 4. The server sends back the song file size
 5. Client creates a local mp3 file
 6. Server writes the song bytes, client reads those bytes to the local file
 7. If the file size read matches the size sent by the server, the song plays
 8. The file is deleted
 9. Returns to the previous menu to allow the user to select a new song or exit
 */
void select_song(SSL* ssl, char buffer[], char songMenu[], int songCounter) {
    
    int song = 0;                   // User selects the song based on the menu number
    int minSong = 0;                // No song is numbered 0
    int maxSong = (songCounter - 1);// Max number of songs is songCounter - 1
    int mp3_fd = 0;                 // MP3 file descriptor
    int rcount = 0;                 // Number of bytes read from SSL_read()
    int wcount = 0;                 // Number of bytes written to mp3 file
    int count = 0;                  // Used with debugging to confirm file size
    int getFileSize = 0;            // SSL_read() to get a file size from server
    long fileSize = 0;              // File size after conversion from str to long int
    char *endptr;                   // Pointer for string to long int conversion
    char songStr[BUFFER_SIZE];      // The song selection that the user types
    bool reading_state = true;      // Flags an exit loop
    
    // Loop until the user selects a valid song
    do {
        // Ask the user for a song selection
        printf("Please type the song number you want to play:\n");
        bzero(songStr, BUFFER_SIZE);
        scanf(" %[^\n]", songStr);
        fflush(stdin);
        
        errno = 0;
        song = strtol(songStr, &endptr, 0);
        
        // Check for errors
        if (errno != 0) {
            fprintf(stderr, "Error: cannot read song selection %s, please contact the help desk for assistance.\n", strerror(errno));
            exit(EXIT_FAILURE);
        }

        // No digits found in the buffer string
        if (endptr == buffer) {
            fprintf(stderr, "Error: cannot read song selection %s, please contact the help desk for assistance.\n", strerror(errno));
            exit(EXIT_FAILURE);
        }
        
        if (song <= minSong || song > maxSong) {
            printf("Please enter a song number between %d and %d\n", minSong+1, maxSong);
        }
        
    } while (song <= minSong || song > maxSong);
    
    if (DEBUG)
        printf("\nSong number selected by user is: %d.\n", song);
    
    // TODO: finds any substring so make sure it's an exact match
    //char *foundSong = strstr(songMenu, song);  // Look for song as substring of songMenu
        
    if (DEBUG)
        printf("Song exists in song menu.\n");
        
    bzero(buffer, BUFFER_SIZE);                 // Erase the buffer
    strcpy(buffer, songStr);                    // Copy the song name to the buffer
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
        
    if (access(SONG_FILE_LOC, F_OK) == 0 )  // The file already exists
        delete_mp3_file();                    // Delete it to ensure clean creation
        
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
            buffer[rcount] = '\0';                              // Null terminate
                
            // Identify any errors with SSL_read()
            if (rcount <= 0) {
                reading_state = false;                          // Flags exit loop
                if (DEBUG) {
                    int sslReadError = SSL_get_error(ssl, rcount);
                    id_SSL_read_error(sslReadError);
                }
                
            // Handle terminal codes
            } else if (rcount == ERRSTR_SIZE) {                 // Check based on data size
                    
                // 0 is end of file
                if (strcmp(buffer, "0") == 0) {
                    fprintf(stdout, "\nFile downloaded successfully.\n");
                    reading_state = false;                      // Flags exit loop
                        
                // All other terminal errors
                } else if (0 < atoi(buffer) && atoi(buffer) <= 13) {
                    fprintf(stderr, "Client: Could not retrieve file: %s\n", strerror(atoi(buffer)));
                    reading_state = false;                      // Flags exit loop
                        
                    /* NOTE: numbers 0-13 transferred as data would be less
                    than 4 bytes unless surrounded by white space */
                    
                // Not a terminal error message, write to copy
                } else {
                    wcount = write(mp3_fd, buffer, rcount);     // Write the bytes to the MP3 fd
                    count += wcount;                            // Sum the bytes written
                    bzero(buffer, BUFFER_SIZE);                 // Erase the buffer
                }
                
            // SSL_read() is successful
            } else {
                wcount = write(mp3_fd, buffer, rcount);     // Write the bytes to the MP3 fd
                count += wcount;                            // Sum the bytes written
                bzero(buffer, BUFFER_SIZE);                 // Erase the buffer
            }
                
        // Continue while data is being sent by the server
        } while (reading_state);
            
        if (DEBUG)
            printf("\nTotal amount written to MP3 file is: %d\n", count);
            
        // Deal with permission error with new file
        char cmd[32];
        sprintf(cmd, "chmod 666 %s", SONG_FILE_LOC);
        system(cmd);

    // Error creating the file descriptor
    } else {
        error_creating_fd(mp3_fd);
    }
        
    // Check that the bytes written local file match the file size read by the server
    if (count != fileSize) {
        printf("File size does not match the file sent by Song Slinger, exiting program.\n\n");
        exit(EXIT_FAILURE);
    }
        
    play_mp3_file(mp3_fd);  // Play the MP3 file
    delete_mp3_file();      // Delete the file
    close(mp3_fd);          // Close the file

} // End of select_song

/**
 1. Reads metadata from the MP3 file
 2. Opens the MP3 file
 3. Loads the MP3 file
 4. Plays the MP3 file
 5. Code and comments based on playaudio.c file from Dr. Hemmes, Regis Unversity
 */
void play_mp3_file(int mp3_fd) {
    
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
    
} // End of play_mp3_file method

/**
 Used to delete the local MP3 file from the client side
 */
void delete_mp3_file() {
    
    int deleteFile = 0;
    
    deleteFile = remove(SONG_FILE_LOC);
    
    if (deleteFile == 0) {
        if (DEBUG)
            printf("File deleted succesfully.\n");
    } else {
        fprintf(stderr, "Error: Problem deleting the MP3 file from user's system: %s, please contact the help desk for assistance.\n", strerror(errno));
        fprintf(stdout, "Exiting program.\n");
        exit(EXIT_FAILURE);
    }
    
} // End of delete_mp3_file method

/**
 If there is an issue with creating a file descriptor (mainly used for creating the MP3 file),
 then output the error and exit the program.
 */
void error_creating_fd(int fd) {
    
    fprintf(stderr, "Error: Problem creating the MP3 file on the user's system %d: %s, please contact the help desk for assistance\n", fd, strerror(errno));
    fprintf(stdout, "Exiting program.\n");
    exit(EXIT_FAILURE);
    
} // End of error_creating_fd method

/**
 Passes an error from SSL_get_error and outputs the error message
 */
void id_SSL_read_error(int sslReadError) {
    
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
        
} // End of id_SSL_read_error method
