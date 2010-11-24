CC=gcc


blackbd: 
	$(CC) -I/opt/local/include -Wall -O3 blackbd.c -L/opt/local/lib -levent -o blackbd 
clean:
	rm -f blackbd

