CC=gcc

INC=-I/opt/local/include
LDIR=-L/opt/local/lib

blackbd: 
	$(CC) -Wall -O3 $(INC) $(LDIR) blackbd.c -levent -o blackbd 
clean:
	rm -f blackbd

