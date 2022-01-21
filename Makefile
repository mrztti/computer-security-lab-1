all: login_linux makepass

mylogin: mylogin.c pwent.h pwent.c
	gcc -g -Wall pwent.c mylogin.c -lcrypt -o mylogin

login_linux: login_linux.c pwent.h pwent.c
	gcc -g -Wall pwent.c login_linux.c -lcrypt -o login_linux

makepass: makepass.c
	gcc -g -Wall makepass.c -lcrypt -o makepass

clean:
	rm -f *.o mylogin login_linux
