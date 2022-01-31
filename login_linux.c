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
#define FLUSH() {fflush(stdin);}

int login();

void doNothing() {}

void sighandler() {
	signal(SIGABRT, doNothing);
	signal(SIGFPE, doNothing);
	signal(SIGKILL, doNothing);
	signal(SIGINT, doNothing);
	signal(SIGSEGV, doNothing);
	signal(SIGTERM, doNothing);
}

int main(int argc, char *argv[]) {
	return login();
}

int login(){

	mypwent *passwddata; /* this has to be redefined in step 2 */
	/* see pwent.h */

	char important1[LENGTH] = "**IMPORTANT 1**";

	char user[LENGTH];

	char important2[LENGTH] = "**IMPORTANT 2**";

	//char   *c_pass; //you might want to use this variable later...
	char prompt[] = "password: ";
	char *user_pass;

	sighandler();

	/* check what important variable contains - do not remove, part of buffer overflow test */
	printf("Value of variable 'important1' before input of login name: %s\n",
			important1);
	printf("Value of variable 'important2' before input of login name: %s\n",
			important2);

	printf("login: ");
	FLUSH(); /* Flush all output buffers */
	__fpurge(stdin); /* Purge any data in stdin buffer */

	// if (gets(user) == NULL) /* gets() is vulnerable to buffer */
	// 	exit(0); /*  overflow attacks.  */
	// Writing 16 characters then "foo" will result in the variable `important2` being overwritten with "foo"

	if (fgets(user, LENGTH, stdin) == NULL){
		printf("\nInvalid input\n");
		__fpurge(stdin); /* Purge any data in stdin buffer */
		clearerr(stdin);
		FLUSH();
		return login();
	}
	user[strlen(user) - 1] = '\0'; /* remove newline */
	if (strlen(user) == 0) {
		return 0;
	}
	FLUSH();

	/* check to see if important variable is intact after input of login name - do not remove */
	printf("Value of variable 'important 1' after input of login name: %*.*s\n",
			LENGTH - 1, LENGTH - 1, important1);
	printf("Value of variable 'important 2' after input of login name: %*.*s\n",
			LENGTH - 1, LENGTH - 1, important2);

	user_pass = getpass(prompt);
	passwddata = mygetpwnam(user);

	if (passwddata != NULL) {
		// Lockout user if too many attempts
		if (passwddata->pwfailed >= PASSWORD_MAX_ATTEMPTS) {
			printf("User has been locked out of system due to too many attempts.\n");
			return login();
		}

		// Encrypt given pwd with the given salt and compare
		char* enc = crypt(user_pass, passwddata->passwd_salt);
		if (!strcmp(enc, passwddata->passwd)) {
			printf("--= USER LOGGED IN =--\n");
			passwddata->pwfailed = 0;

			// Manage password age
			++(passwddata->pwage);
			mysetpwent(user, passwddata);
			if (passwddata->pwage >= PASSWORD_AGE_LIMIT) {
				printf("[Warning] Please change your password, it has been used too often!\n");
			}

            // Try to set UID
			const int uidSuccess = setuid(passwddata->uid);

            if (uidSuccess == 0) {
                // OK, the UID has been set, open new bash session
                char* argv[] = { NULL };
                char* envp[] = { NULL };
                execve("/bin/sh", argv, envp);
            } else {
                printf("[Warning] Failed to open a shell as %s. Are you allowed to do so?\n", passwddata->pwname);
                return login();
            }
		}
		else
		{
			// Increment error counter
			++(passwddata->pwfailed);
			mysetpwent(user, passwddata);
			printf("Login Incorrect [%d / %d consecutive errors]\n", passwddata->pwfailed, PASSWORD_MAX_ATTEMPTS);
			return login();
		}
	}
	printf("Login Incorrect \n");
	return login();
}
