#ifndef _GNU_SOURCE
	#define _GNU_SOURCE
#endif
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <ctype.h>
#include <unistd.h>
#include <pcap/pcap.h>

void callback_function(u_char *arg, const struct pcap_pkthdr *pkthdr,
		const u_char *packet)
{
	bpf_u_int32 i; //like pkthdr->len
	printf("destination:\x1b[34m");
	for(i = 0; i < 6; ++i)
		printf(" %02X", (int)packet[i]);
	printf("\x1b[0m source:\x1b[33m");
	for(; i < 12; ++i)
		printf(" %02X", (int)packet[i]);
	printf("\x1b[0m type: \x1b[31m");
	for(; i < 14; ++i)
		printf(" %02X", (int)packet[i]);
	printf("\x1b[0m\n");
	for(i = 0; i < pkthdr->len; i+=*(size_t*)arg)
	{
		bpf_u_int32 j;
		if(i < 6)
			printf("\x1b[34m");
		else if(i < 12)
			printf("\x1b[33m");
		else if(i < 14)
			printf("\x1b[31m");
		for(j = 0; j < *(size_t*)arg; ++j)
		{
			if(i+j == 6)
				printf("\x1b[33m");
			if(i+j == 12)
				printf("\x1b[31m");
			if(i+j == 14)
				printf("\x1b[0m");
			if(i+j < pkthdr->len)
				printf("%02X ", (int)packet[i+j]);
			else
				printf("   ");
		}
		if(i+j < 14)
			printf("\x1b[0m");
		printf("| ");
		for(j = 0; j < *(size_t*)arg; ++j)
		{
			if(i+j >= pkthdr->len)
				break;
			if(isprint(packet[i+j]))
				printf("%c", (char)packet[i+j]);
			else
				printf(".");
		}
		printf("\n");
	}
	printf("\n");
	fflush(stdout);
}

void print_help(char* my_name)
{
	printf("Usage: %s -i interface [ -p ] [ -s size ] [ -l limit ]\n size - number bytes in one line. Default - 8\n", my_name);
}

int main(int argc, char *argv[])
{
	char *interface = NULL;
	int promisc_mode = 0;
	size_t *print_bytes = (size_t*)malloc(sizeof(size_t));
	*print_bytes = 8;
	size_t size = 100;
	int ch;
	while((ch = getopt(argc, argv, "i:ps:l:")) != -1)
	{
		switch(ch)
		{
		case 'i':
			interface = optarg;
			break;
		case 'p':
			promisc_mode = 1;
			break;
		case 'l':
			size = atol(optarg);
			break;
		case 's':
			*print_bytes = atol(optarg);
			break;
		case ':':
			printf("Был пропущен параметр\n");
			print_help(argv[0]);
			return 1;
		case '?':
			printf("Неизвестный параметр: %c\n", optopt);
			print_help(argv[0]);
			return 1;
		default:
			break;
		}
	}
	if(interface == NULL)
	{
		print_help(argv[0]);
		return 1;
	}
	char str_err[100];
	pcap_t *dev = pcap_open_live(interface, 65535, promisc_mode,
			100, str_err);
	if(dev == NULL)
	{
		fprintf(stderr, "error in pcap_open: %s\n", str_err);
		return 1;
	}
	int ret = pcap_loop(dev, size, callback_function, (u_char*)print_bytes);
	pcap_close(dev);
	return 0;
}
