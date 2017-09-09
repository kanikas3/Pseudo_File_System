all:
	gcc -o spawn spawn.c

install: all
	scp spawn user@192.168.53.89:~

clean:
	rm spawn
