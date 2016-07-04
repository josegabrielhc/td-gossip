#define APP_NAME		"Gossip"
#define APP_DESC		"Mensageiro baseado em UDP"
#define APP_COPYRIGHT	"Trabalho de Transmissao de dados, UnB"
#define APP_DISCLAIMER	"11/1205011 - Jose G. H. Cavalcanti"

//creditos aos codigos base: http://www.tcpdump.org/sniffex.c;
//sample udp1 libnet 1.2-rc3

//uso auxiliar: sudo tcpdump -i lo udp port 8125 -vv -X;

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string>
#include <ncurses.h>
#include <thread>
#include "./libnet_test.h"

using namespace std;

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
//#define ETHER_ADDR_LEN	6

/* Ethernet header */

bool isServer = false;
bool hasDestination = false;
bool exitflag = false;
bool hasErased = false;
string origem = "";
string destino = "";
string porta = "";
const char* c_origem;
const char* c_destino;
char *cp;
string arg0;
libnet_t *l;
libnet_ptag_t ip, ipo;
libnet_ptag_t udp;
u_long src_ip, dst_ip;
u_short src_prt, dst_prt;

struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};


struct sniff_udp{
	u_short ud_sport;
	u_short ud_dport;
	u_short ud_lenght;
	u_short checksum;
};
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
print_payload(const u_char *payload, int len);

void
print_hex_ascii_line(const u_char *payload, int len, int offset);

void
print_app_banner(void);

/*
 * app name/banner
 */
void
print_app_banner(void)
{
	attron(A_BOLD);
	printw("%s - %s\n", APP_NAME, APP_DESC);
	printw("%s\n", APP_COPYRIGHT);
	printw("%s\n", APP_DISCLAIMER);
	printw("\n");
	attroff(A_BOLD);
	refresh();

return;
}

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);
	
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");
	
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	
	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}

void
print_carga(const u_char *payload, int len)
{
	attron(A_BOLD);
	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;
	char *mensagem = new char [len+2];
	
	if (len <= 0)
		return;

	/* data spans multiple lines */
	for (int i = 0;i<len; i++) {
		mensagem[i] = payload[i];
	}
	mensagem[len]='\n';
	mensagem[len+1]='\0';
	printw("m: %s",mensagem);
	refresh();
	std::this_thread::sleep_for(std::chrono::milliseconds(200));
	attroff(A_BOLD);

return;
}
void buildDestination(){
	//caso destino
	if (!(cp = strrchr((char*) c_destino, '.')))
      {
      	usage((char*)arg0.c_str());
		printw("foi aqui!\n");
		refresh();
      }
      dst_prt = (u_short)atoi(porta.c_str());
	//printf("%s\n", c_destino);
      if ((dst_ip = libnet_name2addr4(l,(char*) c_destino, LIBNET_RESOLVE)) == -1)
      {
      	fprintf(stderr, "Bad destination IP address: %s\n", destino.c_str());
		exit(EXIT_FAILURE);
      }
	if (!src_ip || !src_prt || !dst_ip || !dst_prt)
	{	
		usage((char*)arg0.c_str());
		printw("nao,foi aqui!\n");
		refresh();
		exit(EXIT_FAILURE);
    	}
}
/*
 * dissect/print packet
 */
void sendMessage(string);

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

	static int count = 1;                   /* packet counter */
	
	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_udp *udp;            /* The TCP header */
	const u_char *payload;                    /* Packet payload */

	int size_ip;
	int size_udp;
	int size_payload;
	
	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);
	
	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
		
	if(ip->ip_p!=IPPROTO_UDP) return;
	
	udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
	size_udp = 8;
		
	payload = (const u_char *)(packet + SIZE_ETHERNET + size_ip + size_udp);
	
	size_payload = ntohs(ip->ip_len) - (size_ip + size_udp);
	
	if(isServer&&!hasDestination){
		destino = string(inet_ntoa(ip->ip_src));
		c_destino = destino.c_str();
		hasDestination = true;
		buildDestination();
	}

	string ip_origin = string(inet_ntoa(ip->ip_src));
	if (size_payload > 0) {
		//printf("   Payload (%d bytes):\n", size_payload);
		//print_payload(payload, size_payload);
		if(ip_origin!=origem){
			print_carga(payload, size_payload);
			string temporary = string(reinterpret_cast<const char*>(payload));
			if(temporary == "hi guest!"){
				hasDestination = true;			
			}			
			if(temporary == "hi host!"){
				sendMessage("hi guest!");
			}
			//printw("       From: %s\n", inet_ntoa(ip->ip_src));
			//printw("         To: %s\n", inet_ntoa(ip->ip_dst));
			//refresh();
		}
	}
return;
}
void usage(char *name)
{
    fprintf(stderr,
        "usage: %s -s source_ip.source_port -d destination_ip.destination_port"
        " [-p payload]\n",
        name);
}
void sendMessage(string temp){
	u_char opt[20];
	int build_ip;
	u_short payload_s;
	char *payload;
	payload = (char*) temp.c_str();
	payload_s = strlen(payload);
	udp = libnet_build_udp(
            src_prt,                                /* source port */
            dst_prt,                            /* destination port */
            LIBNET_UDP_H + payload_s,               /* packet length */
            0,                                      /* checksum */
            (uint8_t*)payload,                     /* payload */
            payload_s,                              /* payload size */
            l,                                      /* libnet handle */
            udp);                                   /* libnet id */
	if (udp == -1)
	{
		fprintf(stderr, "Can't build UDP header: %s\n", libnet_geterror(l));
	}

	if (1)
	{
		build_ip = 0;
		/* this is not a legal options string */
		for (int j = 0; j < 20; j++)
		{
			opt[j] = libnet_get_prand(LIBNET_PR2);
		}
		ipo = libnet_build_ipv4_options(
                opt,
                20,
                l,
                ipo);
            if (ipo == -1)
            {
                fprintf(stderr, "Can't build IP options: %s\n", libnet_geterror(l));
            }

            ip = libnet_build_ipv4(
                LIBNET_IPV4_H + 20 + payload_s + LIBNET_UDP_H, /* length */
                0,                                          /* TOS */
                242,                                        /* IP ID */
                0,                                          /* IP Frag */
                64,                                         /* TTL */
                IPPROTO_UDP,                                /* protocol */
                0,                                          /* checksum */
                src_ip,
                dst_ip,
                NULL,                                       /* payload */
                0,                                          /* payload size */
                l,                                          /* libnet handle */
               ip);                                         /* libnet id */
            if (ip == -1)
            {
                fprintf(stderr, "Can't build IP header: %s\n", libnet_geterror(l));
            }
        }

        /*
         *  Write it to the wire.
         */
        //fprintf(stderr, "%d byte packet, ready to go\n",libnet_getpacket_size(l));
        int c = libnet_write(l);
        /*if (c == -1)
        {
            fprintf(stderr, "Write error: %s\n", libnet_geterror(l));
            goto bad;
        }
        else
        {
            fprintf(stderr, "Wrote %d byte UDP packet; check the wire.\n", c);
        }*/
}

void loop_in(pcap_t *handle){
	std::string temp = "";
	char temp_c [256] = "";
	int c;
	bool hasString = false;
	int i = 0, wx, wy;
	while(temp!="exit"){
		temp.clear();
		c = getch();
		addch(c);
		temp_c[i] = c;
		i++;
		if(c == KEY_BACKSPACE || c == KEY_DC || c == 127){
			for(int j = 0; j<3;j++){
				nocbreak();
				getyx(stdscr, wy, wx);
				move(wy, wx-1);   
				delch();
				cbreak();
				refresh();
			}
			if(i>=2){
				i--;i--;
				if(i==0) temp_c[i]= 0;
			}
		}
		//getstr(temp_c);
		if(c=='\n') hasString = true;
		if(hasString){
			temp_c[i-1]='\0';
			temp = std::string(temp_c);
			if(hasDestination){
				sendMessage(temp);
				//printw("p: %s-%d\n",temp.c_str(),temp.size());
			}else{
				printw("Nenhuma mensagem ainda recebida, para que haja destinatario\n");
				if(!isServer){
					sendMessage("hi host!");
				}
			}
			refresh();
			i = 0;			
			hasString = false;
		}
	}
	exitflag = true;
}
int main(int argc, char **argv)
{	
	initscr();
	scrollok(stdscr,TRUE);
	cbreak();
	noecho();

	origem = "127.0.0.79\0";	
	destino = "";
	porta = "10101";
	hasDestination = false;
	isServer = false;
	arg0 = argv[0];
	if(argc == 1) {
		//Caso o programa seja chamado sem argumentos.
		printw("Erro fatal: Sem argumentos de entrada!\n\n");
		refresh();
		return (1);
	}
	else if(argc > 3){
		//Argumentos em excesso.
		printw("Erro! Quantidade invalida de argumentos!\n");
		refresh();
		return 0;
	}
	else if(argc == 3||argc == 2){
		//Entrada correta.
		string temp = string(argv[1]);
		if(temp=="-s"||temp=="-S"){
			isServer = true;
			if(argc==3){
				porta = string(argv[2]);				
			}
		}
		else{
			origem = "127.0.0.90\0";
			if(argc==2){
				destino = string(argv[1]);
			}
			else{
				destino = string(argv[1]);
				porta = string(argv[2]);
			};
		}
	}
	else if((argc==2)&&((string(argv[1])=="--help")||(string(argv[1])=="-help"))){
		//Saida de ajuda.
		return 0;
	}
	else{
		//Caso generico de erro.
		printw("Comando invalido!\n");
		refresh();
		return 0;
	}
	c_origem = origem.c_str();
	c_destino = destino.c_str();
	int c, i, j, build_ip;

	libnet_ptag_t ip, ipo;
	libnet_ptag_t udp;
	char *payload;
	u_short payload_s;
	struct libnet_stats ls;

	char errbuf1[LIBNET_ERRBUF_SIZE];
	l = libnet_init(
		LIBNET_RAW4,                            /* injection type */
		NULL,                                   /* network interface */
		errbuf1);                                /* errbuf */

	if (l == NULL)
	{
		fprintf(stderr, "libnet_init() failed: %s\n", errbuf1);
		exit(EXIT_FAILURE);
	}
	src_ip  = 0;
	dst_ip  = 0;
	src_prt = 0;
	dst_prt = 0;
	payload = NULL;
	payload_s = 0;
	ip = ipo = udp = 0;

	//caso fonte
	if (!(cp = strrchr(const_cast<char*>(origem.c_str()), '.')))
      {
      	usage(argv[0]);
      }

      src_prt = (u_short)atoi(porta.c_str())-1;
      if ((src_ip = libnet_name2addr4(l, const_cast<char*>(origem.c_str()), LIBNET_RESOLVE)) == -1)
      {
      	fprintf(stderr, "Bad source IP address: %s\n", origem.c_str());
      	exit(EXIT_FAILURE);
      }
	
	if(!isServer){
		buildDestination();
	}

	//----------------------------------
	
	char *dev = NULL;			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */

	string filter = "ip host " + origem;
	char filter_exp[filter.size()+1];
	strcpy(filter_exp,filter.c_str());		/* filter expression [3] */
	struct bpf_program fp;			/* compiled filter program (expression) */    u_char opt[20];
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	int num_packets = 100000;			/* number of packets to capture */

	print_app_banner();

	/* check for capture device name on command-line */
	dev = const_cast<char*>("lo");

	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		    dev, errbuf);
		net = 0;
		mask = 0;
	}

	/* open capture device */
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* now we can set our callback function */
	
	printw("Origem: %s\n",origem.c_str());
	printw("Destino: %s\n", destino.c_str());
	//printw("%d-%d\n",isServer,hasDestination);
	refresh();
	if(!isServer){
		sendMessage("hi host!");
	}	
	std::thread t1(loop_in, handle);
	while(!exitflag){
		pcap_loop(handle, 1, got_packet, NULL);
	}
	t1.join();

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);
	libnet_stats(l, &ls);
	libnet_destroy(l);
	endwin();
	return 0;
}

