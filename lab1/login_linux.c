/* $Header: https://svn.ita.chalmers.se/repos/security/edu/course/computer_security/trunk/lab/login_linux/login_linux.c 585 2013-01-19 10:31:04Z pk@CHALMERS.SE $ */

/* gcc -std=gnu99 -Wall -g -o mylogin login_linux.c -lcrypt */

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

#define TRUE 1
#define FALSE 0
#define LENGTH 16

void sighandler() {
	//sigset_t mask;
	//sigfillset(&mask);
	//sigprocmask(SIG_SETMASK, &mask, NULL);

	signal(SIGINT, SIG_IGN); /* This will catch ctrl+c and ignore it*/
	//signal(SIGTSTP, SIG_IGN); /* This will catch ctrl+z and ignore it*/
	/* add signalhandling routines here */
	/* see 'man 2 signal' */
}

int main(int argc, char *argv[]) {

	//struct passwd *passwddata /* Step 1 */
	mypwent *passwddata; /* Step 2 */
	/* see pwent.h */

	char important1[LENGTH] = "**IMPORTANT 1**";

	char user[LENGTH];

	char important2[LENGTH] = "**IMPORTANT 2**";

	//char   *c_pass; //you might want to use this variable later...
	char prompt[] = "password: ";
	char *user_pass;

	sighandler();

	while (TRUE) {
		/* check what important variable contains - do not remove, part of buffer overflow test */
		printf("Value of variable 'important1' before input of login name: %s\n",
				important1);
		printf("Value of variable 'important2' before input of login name: %s\n",
				important2);

		printf("login: ");
		fflush(NULL); /* Flush all  output buffers */
		__fpurge(stdin); /* Purge any data in stdin buffer */

		if (fgets(user,sizeof(user),stdin) == NULL ) {
			clearerr(stdin); //if EOF only, clear error
			continue; ///*  overflow attacks.  */
		}
		user[strlen(user)-1] = '\0'; //replacing \n with \0
		
		/* check to see if important variable is intact after input of login name - do not remove */
		printf("Value of variable 'important 1' after input of login name: %*.*s\n",
				LENGTH - 1, LENGTH - 1, important1);
		printf("Value of variable 'important 2' after input of login name: %*.*s\n",
		 		LENGTH - 1, LENGTH - 1, important2);

		// using makepass.c to create hashed password -> saving it manually in passdb

		user_pass = getpass(prompt); //enter password using deprecated function :/
		passwddata = mygetpwnam(user); //get user info from passdb

		if (passwddata != NULL) {
			/* You have to encrypt user_pass for this to work */
			/* Don't forget to include the salt */
			

			char *user_pass_encrypted = crypt(user_pass, passwddata->passwd_salt);
			if (&user_pass_encrypted == NULL) {
				perror("Error");exit(EXIT_FAILURE);
			}
			printf("encryption of typed pass: %s \n", user_pass_encrypted);
			if (passwddata->pwfailed >= 10) {
				printf("Too many failed login attempts. Your account has been locked.\nContact and Admin to unlock your account.\n");
			} else if (!strcmp(user_pass_encrypted, passwddata->passwd)) {

				printf(" You're in !\n");
				passwddata->pwfailed = 0;
				passwddata->pwage = passwddata->pwage + 1;
				mysetpwent(user, passwddata);
				if (passwddata->pwage > 100) {
					printf(" Your password is OLD!!!!\n");
				} 
				
				/*  check UID, see setuid(2) */
				setuid(passwddata->uid);
				/*  start a shell, use execve(2) */
				if (execve("/bin/bash",NULL,NULL) < 0) {     /* execute the command  */
					perror("Error");exit(EXIT_FAILURE);
				}
			} else {
				passwddata->pwfailed = passwddata->pwfailed + 1;
				mysetpwent(user, passwddata);
			}
		}
		printf("Login Incorrect \n");
	}
	return 0;
}
