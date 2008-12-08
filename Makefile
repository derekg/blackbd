CC=gcc


blackbd: 
	$(CC) -Wall -O3 blackbd.c -levent -o blackbd 
clean:
	rm -f blackbd

