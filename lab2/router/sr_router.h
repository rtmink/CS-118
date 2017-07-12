/*-----------------------------------------------------------------------------
 * File: sr_router.h
 * Date: ?
 * Authors: Guido Apenzeller, Martin Casado, Virkam V.
 * Contact: casado@stanford.edu
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_ROUTER_H
#define SR_ROUTER_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>

#include "sr_protocol.h"
#include "sr_arpcache.h"

/* we dont like this debug , but what to do for varargs ? */
#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ## args)
#define DebugMAC(x) \
  do { int ivyl; for(ivyl=0; ivyl<5; ivyl++) printf("%02x:", \
  (unsigned char)(x[ivyl])); printf("%02x",(unsigned char)(x[5])); } while (0)
#else
#define Debug(x, args...) do{}while(0)
#define DebugMAC(x) do{}while(0)
#endif

#define INIT_TTL 255
#define PACKET_DUMP_SIZE 1024

/* forward declare */
struct sr_if;
struct sr_rt;

/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */

struct sr_instance
{
    int  sockfd;   /* socket to server */
    char user[32]; /* user name */
    char host[32]; /* host name */ 
    char template[30]; /* template name if any */
    unsigned short topo_id;
    struct sockaddr_in sr_addr; /* address to server */
    struct sr_if* if_list; /* list of interfaces */
    struct sr_rt* routing_table; /* routing table */
    struct sr_arpcache cache;   /* ARP cache */
    pthread_attr_t attr;
    FILE* logfile;
};

/* ME */
void process_arp(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface);
void process_arp_request(struct sr_instance *sr, struct sr_arp_hdr *arp_hdr, struct sr_if *interface);
void process_icmp(struct sr_instance *sr, struct sr_ip_hdr *ip_hdr);
void forward_ip_pkt(struct sr_instance *sr, struct sr_ip_hdr *ip_hdr);
int valid_arp(uint8_t *packet, unsigned int len);
int valid_ip(uint8_t *packet, unsigned int len);
int valid_icmp(struct sr_ip_hdr *ip_hdr);
void sr_send_icmp(struct sr_instance *sr, uint8_t *packet, unsigned int len, uint8_t type, uint8_t code);
void sr_encap_and_send_pkt(struct sr_instance *sr, uint8_t *packet, unsigned int len, uint32_t dest_ip, int send_icmp, enum sr_ethertype type);
int sr_isBroadcastPacket(uint8_t *packet);
int target_host(struct sr_instance* sr, uint8_t *packet, char* interface);
int sr_type_arp(struct sr_ethernet_hdr *ethernetHdr);
int sr_type_ip(struct sr_ethernet_hdr *ethernetHdr);
struct sr_arp_hdr* arp_header(uint8_t *packet);
uint16_t arp_hrd(struct sr_arp_hdr *arp_hdr);
uint16_t arp_pro(struct sr_arp_hdr *arp_hdr);
uint16_t arp_opcode(struct sr_arp_hdr *arp_hdr);
struct sr_ip_hdr* ip_header(uint8_t *packet);
uint8_t ip_header_len_bytes(struct sr_ip_hdr *ip_hdr);
uint16_t ip_total_len(struct sr_ip_hdr *ip_hdr);
struct sr_icmp_hdr *icmp_hdr_from_ip_hdr(struct sr_ip_hdr *ip_hdr);
struct in_addr ip_in_addr(uint32_t ip);
struct sr_rt *sr_longest_prefix_match(struct sr_instance *sr, struct in_addr addr);


/* -- sr_main.c -- */
int sr_verify_routing_table(struct sr_instance* sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet(struct sr_instance* , uint8_t* , unsigned int , const char*);
int sr_connect_to_server(struct sr_instance* ,unsigned short , char* );
int sr_read_from_server(struct sr_instance* );

/* -- sr_router.c -- */
void sr_init(struct sr_instance* );
void sr_handlepacket(struct sr_instance* , uint8_t * , unsigned int , char* );

/* -- sr_if.c -- */
void sr_add_interface(struct sr_instance* , const char* );
void sr_set_ether_ip(struct sr_instance* , uint32_t );
void sr_set_ether_addr(struct sr_instance* , const unsigned char* );
void sr_print_if_list(struct sr_instance* );

#endif /* SR_ROUTER_H */
