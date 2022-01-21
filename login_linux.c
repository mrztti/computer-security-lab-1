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
/* Uncomment next line in step 2 */
#include "pwent.h"

#define TRUE 1
#define FALSE 0
#define LENGTH 16

#define PASSWORD_AGE_LIMIT 10
#define PASSWORD_MAX_ATTEMPTS 3

void doNothing() {}

void sighandler() {
	signal(SIGABRT, doNothing);
	signal(SIGFPE, doNothing);
	signal(SIGILL, doNothing);
	signal(SIGINT, doNothing);
	signal(SIGSEGV, doNothing);
	signal(SIGTERM, doNothing);
}

int main(int argc, char *argv[]) {

	mypwent *passwddata; /* this has to be redefined in step 2 */
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

		// if (gets(user) == NULL) /* gets() is vulnerable to buffer */
		// 	exit(0); /*  overflow attacks.  */
		// Writing 16 characters then "foo" will result in the variable `important2` being overwritten with "foo"

		if (fgets(user, LENGTH, stdin) == NULL)
			exit(0);

		user[strlen(user) - 1] = '\0'; /* remove newline */

		if (strlen(user) == 0) {
			exit(0);
		}

		fflush(stdin);

		/* check to see if important variable is intact after input of login name - do not remove */
		printf("Value of variable 'important 1' after input of login name: %*.*s\n",
				LENGTH - 1, LENGTH - 1, important1);
		printf("Value of variable 'important 2' after input of login name: %*.*s\n",
		 		LENGTH - 1, LENGTH - 1, important2);

		user_pass = getpass(prompt);
		//TODO clean password
		passwddata = mygetpwnam(user);

		// user -> username
		// user_pass -> psswd

		if (passwddata != NULL) {
			/* You have to encrypt user_pass for this to work */
			/* Don't forget to include the salt */
			char* enc = crypt(user_pass, passwddata->passwd_salt);

			if (passwddata->pwfailed >= PASSWORD_MAX_ATTEMPTS) {
				printf("User has been locked out of system due to too many attempts.\n");
				exit(1);
			}

			if (!strcmp(enc, passwddata->passwd)) {
				printf(" You're in !\n");

				passwddata->pwfailed = 0;
				++(passwddata->pwage);
				mysetpwent(user, passwddata);

				if (passwddata->pwage >= PASSWORD_AGE_LIMIT) {
					printf("[Warning] Please change your password, it has been used too often!\n");
				}

				setuid(passwddata->uid);

				char* argv[] = { NULL };
				char* envp[] = { NULL };
				execve("/bin/sh", argv, envp);

				exit(0);
			} else {
				++(passwddata->pwfailed);
				mysetpwent(user, passwddata);
				printf("Login Incorrect [%d / %d consecutive errors]\n", passwddata->pwfailed, PASSWORD_MAX_ATTEMPTS);
				break;

			}
		}

		printf("Login Incorrect \n");
	}
	return 0;
}
