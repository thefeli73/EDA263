/* $Header: https://svn.ita.chalmers.se/repos/security/edu/course/computer_security/trunk/lab/login_linux/login_linux.c 585 2013-01-19 10:31:04Z pk@CHALMERS.SE $ */

/* gcc -std=gnu99 -Wall -g -o mylogin login_linux.c -lcrypt */

/* Note, makepass.c is first used to create hashed password 
   then, info is manually saved in file passdb */


#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <string.h>
#include <signal.h>
#include <pwd.h>
#include <sys/types.h>
#include <crypt.h>
#include "pwent.h" /* Step 2 */
#include <termios.h>
#include <stdbool.h>

#define TRUE 1
#define FALSE 0
#define LENGTH 16

void sighandler() {
	//sigset_t mask;
	//sigfillset(&mask);
	//sigprocmask(SIG_SETMASK, &mask, NULL);

	signal(SIGINT, SIG_IGN); /* This will catch ctrl+c and ignore it*/
	//signal(SIGTSTP, SIG_IGN); /* This will catch ctrl+z and ignore it*/
    //signal(SIGTERM,SIG_IGN); //TODO block termios kanske...
}


int main(int argc, char *argv[]) {

	//struct passwd *passwddata /* Step 1 */
	mypwent *passwddata; /* Step 2 */

	char important1[LENGTH] = "**IMPORTANT 1**";

	char user[LENGTH];

	char important2[LENGTH] = "**IMPORTANT 2**";

	//char *c_pass; //you might want to use this variable later... TODO
	//char prompt[] = "password: ";
	//char *user_pass;
    char user_pass[LENGTH]; // TODO la till denna

	sighandler();

	while (TRUE) {
		/* check what important variable contains - do not remove, part of buffer overflow test */
		printf("Value of variable 'important1' before input of login name: %s\n",
				important1);
		printf("Value of variable 'important2' before input of login name: %s\n",
				important2);

        //////////////////////////////////////////////////////////////////////////////////////////
        
		printf("login: ");
		fflush(NULL); /* Flush all  output buffers */
		__fpurge(stdin); /* Purge any data in stdin buffer */

        bool okusername = true;
        /* using fgets instead of gets to avoid buffer overflow attacks*/
		if (fgets(user,sizeof(user),stdin) == NULL ) {
            // if error or EOF (ctrl+d)
            // TODO need for more error handling ? 
			clearerr(stdin);
            okusername = false;
		}
		
        if (strlen(user) == sizeof(user)-1 || strlen(user) == 1){
            // too long username or no username was entered
            okusername = false;
        }
        else{
            // replacing \n with \0
            user[strcspn(user,"\n")] = '\0'; 
		}
		
		//////////////////////////////////////////////////////////////////////////////////////////
        
		/* check to see if important variable is intact after input of login name - do not remove */
		printf("Value of variable 'important 1' after input of login name: %*.*s\n",
				LENGTH - 1, LENGTH - 1, important1);
		printf("Value of variable 'important 2' after input of login name: %*.*s\n",
		 		LENGTH - 1, LENGTH - 1, important2);

        //////////////////////////////////////////////////////////////////////////////////////////
        
        // using termios instead of the outdated getpass for a more secure program
        // user_pass = getpass(prompt);

        struct termios old_term_flags, new_term_flags;

        /* Turn echoing off so password will not be shown in terminal */
        if (tcgetattr(fileno(stdin), &old_term_flags) != 0){
            perror("Error");
            exit(EXIT_FAILURE);
        }
        new_term_flags = old_term_flags;
        new_term_flags.c_lflag &= ~ECHO;
        if (tcsetattr(fileno(stdin), TCSAFLUSH, &new_term_flags) != 0) {
            perror("Error");
            exit(EXIT_FAILURE);
        }

        bool okpassword = true;
        printf("password: ");
        if (fgets(user_pass,sizeof(user_pass),stdin) == NULL ) {
			clearerr(stdin);
            okpassword = false;
		}
        if (strlen(user_pass) == sizeof(user_pass)-1 || strlen(user_pass) == 1){
            okpassword = false;
        } 

        /* Restore terminal */
        if (tcsetattr(fileno(stdin), TCSAFLUSH, &old_term_flags) != 0) {
            perror("Error");
			exit(EXIT_FAILURE);
        }
        
        if (!okpassword || !okusername){
            printf("\nLogin Incorrect \n \n");
            continue;
        }
        user_pass[strcspn(user_pass, "\n")] = '\0'; // replacing \n with \0

        //////////////////////////////////////////////////////////////////////////////////////////
    
        // get user info from passdb
        passwddata = mygetpwnam(user); 
        
		if (passwddata != NULL) {
            
            if (passwddata->pwfailed >= 10) {
				printf("\nToo many failed login attempts. Your account has been locked.\nContact and Admin to unlock your account.\n");
                continue;
			}
			
            /* Encryp user_pass with salt included */
			char *user_pass_encrypted = crypt(user_pass, passwddata->passwd_salt);
			if (user_pass_encrypted == NULL) {
				perror("Error");exit(EXIT_FAILURE);
			}

            if (!strcmp(user_pass_encrypted, passwddata->passwd)) {
                // successfull login
                printf("\n%d failed attemts to login \n",passwddata->pwfailed);
				passwddata->pwfailed = 0;
				passwddata->pwage = passwddata->pwage + 1;
                
				if (mysetpwent(user, passwddata) < 0) {
					perror("Error");exit(EXIT_FAILURE);
				}
				if (passwddata->pwage > 10) {
					printf("You need to change your password !\n");
				} 
				
				
				
				/*  check UID, see setuid(2) */
				if (setuid(passwddata->uid) < 0) { 
					perror("Error");
					exit(EXIT_FAILURE);
                    // TODO kommer alltid bara hit
				}
				/*  start a shell, use execve(2) */
				if (execve("/bin/bash",NULL,NULL) < 0) {
					perror("Error");
					exit(EXIT_FAILURE);
				}
				printf("\nWelcome to this system !\n");
			} 
			else {
                // user name exists but password does not match
				passwddata->pwfailed = passwddata->pwfailed + 1;
				if (mysetpwent(user, passwddata) < 0) { 
					perror("Error");
					exit(EXIT_FAILURE);
				}
			}
		}
		printf("\nLogin Incorrect \n \n");
	}
	return 0;
}
