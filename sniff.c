#ifndef _GNU_SOURCE
	#define _GNU_SOURCE
#endif
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <ctype.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>

struct color
{
	struct color *next;
	bpf_u_int32 start;
	bpf_u_int32 end;
	char *str;

};

struct color* find_color(struct color* colors, bpf_u_int32 num)
{
	struct color *ret;
	for(ret = colors; ret != NULL; ret = ret->next)
		if(num >= ret->start && num <= ret->end)
			return ret;
	return NULL;
}

void print_raw(u_char *arg, const struct pcap_pkthdr *pkthdr,
		const u_char *packet, struct color *colors)
{
	bpf_u_int32 i; //like pkthdr->len
	for(i = 0; i < pkthdr->len; i+=*(size_t*)arg)
	{
		bpf_u_int32 j;
		struct color *current = NULL;
		for(j = 0; j < *(size_t*)arg; ++j)
		{
			if(current == NULL)
			{
				current = find_color(colors, i+j);
				if(current != NULL)
					printf("%s", current->str);
			}
			if(i+j < pkthdr->len)
				printf("%02X ", (int)packet[i+j]);
			else
				printf("   ");
			if(current != NULL && i+j+1 >= current->end)
			{
				printf("\x1b[0m");
				current = NULL;
			}
		}
		printf("\x1b[0m| ");
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
}

void print_ip(u_char *arg, const struct pcap_pkthdr *pkthdr,
		const u_char *packet, struct color *colors)
{
	struct color *temp = (struct color*)malloc(sizeof(struct color));
	colors->next = temp;

	printf("(IPv4)\ntotal length: %hu (0x%04hx)",
			ntohs(*(unsigned short*)(&packet[2])),
			ntohs(*(unsigned short*)(&packet[2])));
	printf(" TTL: %hhu Protocol: %hhu (0x%02hhx)\n", packet[8],
			packet[9], packet[9]);

	temp->str = "\x1b[35m";
	temp->start = 12;
	temp->end = 15;
	printf("IP source: \x1b[35m%hhu.%hhu.%hhu.%hhu\x1b[0m (\x1b[35m0x%08x\x1b[0m)\n",
			packet[12], packet[13], packet[14], packet[15],
			ntohl(*(unsigned*)(&packet[12])));

	temp->next = (struct color*)malloc(sizeof(struct color));
	temp = temp->next;
	temp->str = "\x1b[36m";
	temp->start = 16;
	temp->end = 19;
	temp->next = NULL;
	printf("IP destination: \x1b[36m%hhu.%hhu.%hhu.%hhu\x1b[0m (\x1b[36m0x%08x\x1b[0m)\n",
			packet[16], packet[17], packet[18], packet[19],
			ntohl(*(unsigned*)(&packet[16])));
}

void free_color(struct color *color)
{
	if(color->next != NULL)
		free_color(color->next);
	free(color);
}

void print_packet(u_char *arg, const struct pcap_pkthdr *pkthdr,
		const u_char *packet)
{
	bpf_u_int32 i; //like pkthdr->len
	struct color colors;
	printf("destination:\x1b[34m");
	for(i = 0; i < 6; ++i)
		printf(" %02X", (int)packet[i]);
	colors.start = 0;
	colors.end = 5;
	colors.str = "\x1b[34m";

	struct color *temp = (struct color*)malloc(sizeof(struct color));
	printf("\x1b[0m source:\x1b[33m");

	colors.next = temp;
	temp->str = "\x1b[33m";
	temp->start = i;

	for(; i < 12; ++i)
		printf(" %02X", (int)packet[i]);
	temp->end = i-1;

	temp = (struct color*)malloc(sizeof(struct color));
	colors.next->next = temp;
	temp->next = NULL;
	temp->str = "\x1b[31m";
	temp->start = i;
	printf("\x1b[0m type: \x1b[31m");
	for(; i < 14; ++i)
		printf(" %02X", (int)packet[i]);
	printf(" \x1b[0m");
	temp->end = i-1;
	//if type == 0x0800
	if(packet[12] == 0x8 && packet[13] == 0x0)
	{
		print_ip(arg, pkthdr, &packet[i], temp);
		while(temp->next != NULL)
		{
			temp->next->start += i;
			temp->next->end += i;
			temp = temp->next;
		}
	}
	else if(packet[12] == 0x8 && packet[13] == 0x6)
		printf("(ARP)\n");
	else
		printf("\n");
	print_raw(arg, pkthdr, packet, &colors);
	free_color(colors.next);
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
	int ret = pcap_loop(dev, size, print_packet, (u_char*)print_bytes);
	pcap_close(dev);
	return 0;
}
