all: sniff.c
	gcc sniff.c -lpcap -o sniffer -g
