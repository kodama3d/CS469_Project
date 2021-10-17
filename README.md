# CS469_Project
Group project with Jeff Krauss

CS469 Project Instructions for Song Slinger
By Jeff Krauss and Dustin Segawa

The makefile requires the following to be installed in the Linux terminal for both client and server.
	MP3 player
		sudo apt-get install -y libsdl2-dev libsdl2-mixer-2.0-0 libsdl2-mixer-dev 
		gcc -o playaudio playaudio.c -lSDL2_mixer -lSDL2
	SSL
		sudo apt-get install libssl-dev

The Server
•	Started in Linux using ‘./cs469projserver’ in the terminal window
o	Opening additional servers will create backup servers on sequential ports
•	Authentication is based on the userdatabase.txt file
o	Stored in the format: username;salt&hashed-password;

The Client
•	Started in Linux using the command ‘./cs469projclient’ in the terminal window
•	Prompted for login
o	Enter valid username
o	Enter valid password
•	Enter ‘1’ to see the song list (or ‘2’ to terminate)
•	Enter the song number listed
o	The song will play until the end
•	Enter ‘Y’ to play another song, or ‘N’ to exit
•	‘N’ will terminate the connection, leaving the server open to another connection.

