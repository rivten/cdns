dns: dns.o
	gcc $< -o $@

dns.o: dns.c
	gcc -c $< -o $@ -Wall -Wextra -pedantic
