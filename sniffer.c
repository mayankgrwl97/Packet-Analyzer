#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>


#include  <signal.h>

//#include "p.h"


struct dnsheader {
	uint16_t	tid;		/* Transaction ID */
	uint16_t	flags;		/* Flags */
	uint16_t	nqueries;	/* Questions */
	uint16_t	nanswers;	/* Answers */
	uint16_t	nauth;		/* Authority PRs */
	uint16_t	nother;		/* Other PRs */
	//unsigned char	data[1];	/* Data, variable length */
};
typedef struct dnsheader dnsheader;



void     INThandler(int);
FILE *fp;
int boolo = 1;
//char* table[1000];
char st[1000];
int sno = 1;

void printtime(FILE* fp)
{
	time_t mytime;
    mytime = time(NULL);
    // fprintf(fp, ctime(&mytime));
    return;
}


/*
void printtime(FILE* fp)
{
	char buff[20];
	struct tm *sTm;

	time_t now = time (0);
    sTm = gmtime (&now);

    strftime (buff, sizeof(buff), "%Y-%m-%d %H:%M:%S\n", sTm);
  	fprintf(fp, buff);
	// time_t mytime;
    // mytime = time(NULL);
    // fprintf(fp, ctime(&mytime));
    return;
}*/

void printData(FILE* fp, char* apdu, int size)
{
	int i;
	fprintf(fp, "\t");
	for( i=0; i<size; i++)
	{
		if(i%16 == 0 && i != 0)
		{
			fprintf(fp, "\n\t");
		}
		if(apdu[i] >= 32 && apdu[i] <= 128)
			fprintf(fp, "%c", (unsigned char)apdu[i]);
		else
			fprintf(fp, ".");
	}

	fprintf(fp, "\n\n");
	return;
}

void printhttp(FILE* fp, char* httppacket, int size)
{
	int i;
	fprintf(fp, "\t");
	for( i=0; i<size-4; i++)
	{
		// if((httppacket[i] < 32 || httppacket[i] > 128) && (httppacket[i+1] < 32 || httppacket[i+1] > 128))
		if(httppacket[i] == '\r' && httppacket[i+1] == '\n' && httppacket[i+2] == '\r' && httppacket[i+3] == '\n')
		{
			fprintf(fp, "\n\n");
			return;
		}
		if(httppacket[i] == '\r' && httppacket[i+1] == '\n')
		{
			i+=1;
			fprintf(fp, "\n\t");
		}
		else
			fprintf(fp, "%c", (unsigned char) httppacket[i]);
	}
	fprintf(fp, "\n\n");
	return ;
}

struct sockaddr_in source, dest;

void analyse_summary(char* frame, int size)
{

	struct ethhdr *ethdr = (struct ethhdr*)frame;
	int ethdrsize = sizeof(struct ethhdr);
	struct iphdr* iph = (struct iphdr*)(frame + ethdrsize);

	// printf("%")
	memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;//source ip address

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;//destination ip address

    //printf("%-18s", inet_ntoa(source.sin_addr));
    //printf("%-18s", inet_ntoa(dest.sin_addr));
	
	char* proto[10];
	if(iph->protocol == 6)
	{
		struct tcphdr* tcph=(struct tcphdr*)(frame + iph->ihl*4 + ethdrsize);
		// printf("%d %d", tcph->source, tcph->dest)
		if(ntohs(tcph->source) == 80 || ntohs(tcph->dest) == 80)
			{strcpy(proto,"HTTP ");//printf("HTTP\t");
			}
		else
			{strcpy(proto,"TCP ");//printf("TCP \t");
			}

	}
	else if(iph->protocol == 17)
	{
		strcpy(proto,"UDP ");//printf("UDP \t");
	}
	else
	{
		strcpy(proto,"IP ");//printf("IP  \t");
	}

	//printf("%-5d", size);
	//printf("\n");
	//table[sno] = st;
	char str1[22];
	char str2[22];
	sprintf(str1, "%-21s", inet_ntoa(source.sin_addr));
	sprintf(str2, "%-21s", inet_ntoa(dest.sin_addr));
	sprintf(st,"%-5d%s%s%-5s%-5d",sno,str1,str2,proto,size);
	
	//sprintf(st,"%d-%s-%s-%s-%d",sno++,inet_ntoa(source.sin_addr),inet_ntoa(dest.sin_addr),proto,size);
	//sprintf(st,"%s",proto);
	printf("%s\n",st);
	fprintf(fp,"%s\n",st);
	//printf("~%s",table[sno-1]);
	return;
}

void analyse(int sno, char* frame, int size)
{
	char filename[25];
	sprintf(filename, "dump/%d.txt\0", sno);
	FILE* fp = fopen(filename, "w");
	struct ethhdr *ethdr = (struct ethhdr *)frame; //pointer to ethernet header from the frame
	int ethdrsize = sizeof(struct ethhdr);
	struct iphdr *iph = (struct iphdr *)(frame + ethdrsize);

//printing the EHTERNET header if the underlying protocol is IPv4
	if((unsigned short)ethdr->h_proto == 8)
	{
		fprintf(fp, "Frame, %d bytes captured (%d bits)\n", size, size*8);
		//fprintf(fp, "\tCapture Time : ");
		//printtime(fp);
		fprintf(fp, "\tDestination HW_addr : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X \n",ethdr->h_dest[0] , ethdr->h_dest[1] , ethdr->h_dest[2] , ethdr->h_dest[3] , ethdr->h_dest[4] , ethdr->h_dest[5]);
		fprintf(fp, "\tSource HW_addr : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X \n", ethdr->h_source[0] , ethdr->h_source[1] , ethdr->h_source[2] , ethdr->h_source[3] , ethdr->h_source[4] , ethdr->h_source[5]);
		fprintf(fp, "\tProtocol : IPv4 (0x%.2X%.2X)", frame[12], frame[13]);
	}
	else
		return;
	fprintf(fp, "\n\n");

// printing the IP header //

	memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;//source ip address

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;//destination ip address

	fprintf(fp, "Internet Protocol version %d, ", (unsigned int)iph->version);
	fprintf(fp, "Src: %s --> ", inet_ntoa(source.sin_addr));
	fprintf(fp, "Dst: %s\n", inet_ntoa(dest.sin_addr));
	int version = iph->version,i;
	fprintf(fp, "\t");
	for( i=3; i>=0; i--)
	{
		if(version>>i & 1)
			fprintf(fp, "1");
		else
			fprintf(fp, "0");
	}
	fprintf(fp, " .... = Version: %d\n", version);
	fprintf(fp, "\t.... ");
	int ipheaderlen = iph->ihl;
	for( i=3; i>=0; i--)
	{
		if(ipheaderlen>>i & 1)
			fprintf(fp, "1");
		else
			fprintf(fp, "0");
	}
	fprintf(fp, " = Header Length: %d bytes\n", ipheaderlen*4);
	fprintf(fp, "\tType Of Service : 0x%.2X\n", iph->tos);
	fprintf(fp, "\tTotal Length : %d\n", ntohs(iph->tot_len));
	fprintf(fp, "\tIdentification : %.4X (%d)\n", iph->id, ntohs(iph->id));
	int frag = iph->frag_off;
	fprintf(fp, "\tFlags:\n");
	if((frag >> 15) & 1)
		fprintf(fp, "\t  1... .... = Reserved bit: Set\n");
	else
		fprintf(fp, "\t  0... .... = Reserved bit: Not set\n");

	if((frag >> 14) & 1)
		fprintf(fp, "\t  .1.. .... = Don't fragment: Set\n");
	else
		fprintf(fp, "\t  .0.. .... = Don't fragment: Not set\n");

	if((frag >> 13) & 1)
		fprintf(fp, "\t  ..1. .... = More fragments: Set\n");
	else
		fprintf(fp, "\t  ..0. .... = More fragments: Not Set\n");
	fprintf(fp, "\tFragment Offset: %d\n", frag);

	fprintf(fp, "\tTime To live: %d\n", iph->ttl);
	fprintf(fp, "\tProtocol: ");
	if(iph->protocol == 6)
		fprintf(fp, "TCP (6)\n");
	else if(iph->protocol == 17)
		fprintf(fp, "UDP (17)\n");
	fprintf(fp, "\tHeader Checksum: 0x%.4X\n", iph->check);
	fprintf(fp, "\tSource: %s\n", inet_ntoa(source.sin_addr));
	fprintf(fp, "\tDestination: %s\n", inet_ntoa(dest.sin_addr));

// Storing total header size upto IP layer
	int headersize = ethdrsize + ipheaderlen*4;
// Printing TCP header //
	if(iph->protocol == 6)
	{
	// unsigned short int iphdrlen = iph->ihl*4;
		// int tcp_header_size =  ethdrsize + iphdrlen + (tcph->doff)*4;
		struct tcphdr* tcph=(struct tcphdr*)(frame + ipheaderlen*4 + ethdrsize);

		headersize += (tcph->doff)*4;
		fprintf(fp, "\nTransmission Control Protocol, Src Port: %u , Dst Port %u , Seq: %u, Ack: %u, Len: %d\n",
					ntohs(tcph->source),
					ntohs(tcph->dest),
					ntohl(tcph->seq),
					ntohl(tcph->ack_seq),
					(unsigned int)tcph->doff*4);

		fprintf(fp, "\tSource Port: %u\n",ntohs(tcph->source));
		fprintf(fp, "\tDestination Port: %u\n",ntohs(tcph->dest));
		fprintf(fp, "\tSequence number: %u\n",ntohl(tcph->seq));
		fprintf(fp, "\tAcknowledgement number: %u\n",ntohl(tcph->ack_seq));
		fprintf(fp, "\tHeader Length: %d (bytes)\n",(unsigned int)tcph->doff*4);

		fprintf(fp, "\tFlags: \n");
		//fprintf(fp, "\t.... %d... .... = Cogstion Window Reduced\n",(unsigned int)tcph->cwr);
		//fprintf(fp, "\t.... .%d.. .... = ECN-Echo\n",(unsigned int)tcph->ece);
		fprintf(fp, "\t.... ..%d. .... = Urgent\n",(unsigned int)tcph->urg);
		fprintf(fp, "\t.... ...%d .... = Acknowledgement\n",(unsigned int)tcph->ack);
		fprintf(fp, "\t.... .... %d... = Push\n",(unsigned int)tcph->psh);
		fprintf(fp, "\t.... .... .%d.. = Reset\n",(unsigned int)tcph->rst);
		fprintf(fp, "\t.... .... ..%d. = Syn\n",(unsigned int)tcph->syn);
		fprintf(fp, "\t.... .... ...%d = Fin\n",(unsigned int)tcph->fin);
		
		fprintf(fp, "\tWindow size value: %d\n",ntohs(tcph->window));
		fprintf(fp, "\tChecksum: 0x %.2X\n",ntohs(tcph->check));
		fprintf(fp, "\tUrgent Pointer: %d\n",tcph->urg_ptr);

		if((ntohs(tcph->source) == 80) || (ntohs(tcph->dest) == 80))
		{
			fprintf(fp, "\nData Dump\n");
			printData(fp, frame + headersize, size - headersize);
			printhttp(fp, frame + headersize, size - headersize);
			fclose(fp);
			return;
		}
	}

// Printing UDP header //

	if(iph->protocol == 17)
	{
	    struct udphdr *udph = (struct udphdr*)(frame + ipheaderlen*4  + sizeof(struct ethhdr));
		headersize += sizeof(udph);
	    fprintf(fp, "\nUser Datagram Protocol, ");
	    fprintf(fp, "Src Port: %d, ", ntohs(udph->source));
	    fprintf(fp, "Dst Port: %d\n", ntohs(udph->dest));
	    fprintf(fp, "\tSource Port: %d\n", ntohs(udph->source));
	    fprintf(fp, "\tDestination Port: %d\n", ntohs(udph->dest));
	    fprintf(fp, "\tLength: %d\n", ntohs(udph->len));
	    fprintf(fp, "\tChecksum: %.4X\n",udph->check);


	    if((ntohs(udph->source) == 53) || (ntohs(udph->dest) == 53))
		{
			//fprintf(fp,"\nData Dump\n");
			struct dnsheader *dnsh = (struct dnsheader *)(frame + headersize);
			headersize += sizeof(dnsh);
			fprintf(fp,"\nDomain Name System\n");
			fprintf(fp,"Transaction ID: 0x%.4X\n", ntohs(dnsh->tid) );
			fprintf(fp,"Flags : 0x%.4X\n",ntohs(dnsh->flags));//0x%.4X
			fprintf(fp,"Questions: %d\n",ntohs(dnsh->nqueries) );
			fprintf(fp,"Answers: %d\n",ntohs(dnsh->nanswers) );
			fprintf(fp,"Authority RRS: %d\n",ntohs(dnsh->nauth) );
			fprintf(fp,"Additional RRS: %d\n",ntohs(dnsh->nother) );
			//fprintf(fp,"Data: %c\n",dnsh->data);
			// printf("%s\n", );
			fclose(fp);
			return;
		}

	    // 
	}
// Printing APDU //
	// printData(frame + headersize, size-headersize);
	fclose(fp);
	return;
}

void caller()
{
	
	signal(SIGINT, INThandler);
	int raw_socket;
	raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	unsigned char frame[65535];

	struct timeval stop, start;
	gettimeofday(&start, NULL);

	if(raw_socket < 0)
	{
		printf("Unable to open socket\n");
		return 0;
	}

	//int sno = 1;
	fp = fopen("log.txt","w+");
	while(boolo)//sno<10)
	{
		int size = recv(raw_socket, frame, 1024, 0);
		gettimeofday(&stop, NULL);
		//printf("%-6d", sno++);
		analyse_summary(frame, size);
		// printf("\n");
		analyse(sno, frame, size);
		fflush(fp);
		sno++;
	}

	fclose(fp);

	return;// 0;
}


void  INThandler(int sig)
{
	char  c;

	signal(sig, SIG_IGN);
	printf("\nYou hit Ctrl-C?\nTo continue sniffing packets press 'n' or for graphical analysis press 'y' [y/n]: ");
	c = getchar();
	if (c == 'y' || c == 'Y')
	{
		//main(1,NULL);
		//exit(0);
		boolo = 0;
	}
	  
	else
	{
	  signal(SIGINT, INThandler);
	}
	getchar(); // Get new line character
}
