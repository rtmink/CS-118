/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/* ME */
#define DEFAULT_TTL 64

#define ICMP_IP_HDR_LEN 5
#define ICMP_IP_HDR_LEN_BYTES ICMP_IP_HDR_LEN * 4

#define ICMP_COPIED_DATAGRAM_DATA_LEN 8

#define ICMP_CODE_NET 0
#define ICMP_CODE_HOST 1
#define ICMP_CODE_PORT 3

#define ICMP_TYPE_ECHO_REPLY 0
#define ICMP_TYPE_ECHO_REQUEST 8
#define ICMP_TYPE_UNREACHABLE 3
#define ICMP_TYPE_TIME_EXCEEDED 11

#define DEBUG 0

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    printf("*** -> Received packet of length %d \n",len);
	
    /* ME */
    struct sr_ethernet_hdr *ethernetHdr = (struct sr_ethernet_hdr *)packet;
    
    if (sr_type_arp(ethernetHdr)) {
        
        if (DEBUG)
            printf("*** -> Processing ARP\n");
        process_arp(sr, packet, len, interface);
    }
    else if (sr_type_ip(ethernetHdr)) {
        
        struct sr_ip_hdr *ipHdr = ip_header(packet);
        
        print_hdr_ip((uint8_t *)ipHdr);
        
        if (DEBUG)
            printf("*** -> Processing IP\n");
        
        if (!valid_ip(packet, len)) {
            if (DEBUG)
                printf("*** -> Invalid IP\n");
            return;
        }
        
        /* Checksum check succeeds */
        
        if (target_host(sr, packet, interface)) {
            /* IP packet for us */
            
            if (DEBUG)
                printf("*** -> Processing IP for us\n");
            
            if (ipHdr->ip_p == ip_protocol_icmp) {
                /* ICMP */
                if (DEBUG)
                    printf("*** -> Processing ICMP for us\n");
                process_icmp(sr, ipHdr);
            }
            else
                /* TCP/UDP */
                sr_send_icmp(sr, (uint8_t *)ipHdr, ip_total_len(ipHdr), ICMP_TYPE_UNREACHABLE, ICMP_CODE_PORT);
        }
        else {
            /* IP packet for others */
            
            if (DEBUG)
                printf("*** -> Processing IP for others\n");
            
            forward_ip_pkt(sr, ipHdr);
        }
    }
    else {
        if (DEBUG)
            printf("\n\nNot IP nor ARP\n\n");
    }
    
}/* end sr_ForwardPacket */

void process_arp(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface)
{
    struct sr_arpentry *arp_entry;
    struct sr_arpreq *arp_req;
    struct sr_arp_hdr *arp_hdr;
    struct sr_if *rec_if;
    
    if (!valid_arp(packet, len))
        return;
    
    /* Ignore the packet if we are not the target host */
    if (!target_host(sr, packet, interface))
        return;
    
    /* Add sender's protocol address to table */
    rec_if = sr_get_interface(sr, interface);
    arp_hdr = arp_header(packet);
    arp_entry = sr_arpcache_lookup(&sr->cache, arp_hdr->ar_sip);
    
    if (arp_entry)
        /* ARP entry exists; free the copy */
        free(arp_entry);
    else
    {
        /* ARP entry does not exist */
        arp_req = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
        
        if (arp_req) {
            /* Now that ARP entry exists,
                Send all packets on the req->packets linked list */
            
            if (DEBUG)
                printf("^^Send all queued packets\n");
            
            sr_arpreq_send_packets(sr, arp_req);
        }
    }
    
    /* Handle the request if any */
    if (arp_opcode(arp_hdr) == arp_op_request)
        process_arp_request(sr, arp_hdr, rec_if);
}

void process_arp_request(struct sr_instance *sr, struct sr_arp_hdr *arp_hdr, struct sr_if *interface)
{
    struct sr_arp_hdr reply_arp_hdr;
    
    /* Create a ARP header with appropriate reply info */
    reply_arp_hdr.ar_hrd = htons(arp_hrd_ethernet);
    reply_arp_hdr.ar_pro = htons(arp_pro_ip);
    reply_arp_hdr.ar_hln = ETHER_ADDR_LEN;
    reply_arp_hdr.ar_pln = sizeof(uint32_t);
    reply_arp_hdr.ar_op = htons(arp_op_reply);
    reply_arp_hdr.ar_sip = interface->ip;
    reply_arp_hdr.ar_tip = arp_hdr->ar_sip;
    memcpy(reply_arp_hdr.ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
    memcpy(reply_arp_hdr.ar_sha, interface->addr, ETHER_ADDR_LEN);
    
    /* Encapsulate and attempt to send it */
    sr_encap_and_send_pkt(sr, (uint8_t *)&reply_arp_hdr, sizeof(struct sr_arp_hdr), arp_hdr->ar_sip, 1, ethertype_arp);
}

void process_icmp(struct sr_instance *sr, struct sr_ip_hdr *ip_hdr)
{
    if (DEBUG)
        printf("Processing ICMP\n");
    
    if (!valid_icmp(ip_hdr))
        return;
    
    if (DEBUG)
        printf("Valid ICMP\n");
    
    sr_send_icmp(sr, (uint8_t *)ip_hdr, ip_total_len(ip_hdr), ICMP_TYPE_ECHO_REPLY, 0);
}

void forward_ip_pkt(struct sr_instance *sr, struct sr_ip_hdr *ip_hdr)
{
    struct sr_ip_hdr *forward_ip_hdr;
    unsigned int len;
    
    /* Decrement TTL */
    ip_hdr->ip_ttl--;

    len = ip_total_len(ip_hdr);
    if (ip_hdr->ip_ttl == 0) {
        /* ICMP Time exceeded */
        if (DEBUG)
            printf("TTL == 0 => Time Exceeded!!!\n");
        sr_send_icmp(sr, (uint8_t *)ip_hdr, len, ICMP_TYPE_TIME_EXCEEDED, ICMP_CODE_NET);
        return;
    }
    
    /* Update checksum */
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, ip_header_len_bytes(ip_hdr));
    
    forward_ip_hdr = malloc(len);
    memcpy(forward_ip_hdr, ip_hdr, len);
    sr_encap_and_send_pkt(sr, (uint8_t *)forward_ip_hdr, len, ip_hdr->ip_dst, 1, ethertype_ip);
    free(forward_ip_hdr);
}

int valid_arp(uint8_t *packet, unsigned int len)
{
    struct sr_arp_hdr *arp_hdr;
    
    if (len < sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr))
        return 0;
    
    arp_hdr = arp_header(packet);
    if (arp_hrd(arp_hdr) != arp_hrd_ethernet)
        return 0;
    
    if (arp_pro(arp_hdr) != arp_pro_ip)
        return 0;
    
    return 1;
}

int valid_ip(uint8_t *packet, unsigned int len)
{
    uint16_t expected_cksum;
    struct sr_ip_hdr *ip_hdr;
    uint16_t received_cksum;
    
    if (len < sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr))
        return 0;
    
    ip_hdr = ip_header(packet);
    
    if (len < sizeof(struct sr_ethernet_hdr) + ip_header_len_bytes(ip_hdr))
        return 0;
    
    received_cksum = ip_hdr->ip_sum;
    ip_hdr->ip_sum = 0;
    expected_cksum = cksum(ip_hdr, ip_header_len_bytes(ip_hdr));
    
    if (received_cksum != expected_cksum)
        return 0;
    
    if (len != sizeof(struct sr_ethernet_hdr) + ip_total_len(ip_hdr))
        return 0;
    
    if (ip_hdr->ip_v != ip_version_4)
        return 0;
    
    return 1;
}

int valid_icmp(struct sr_ip_hdr *ip_hdr)
{
    uint16_t expected_cksum;
    struct sr_icmp_hdr *icmp_hdr;
    uint16_t received_cksum;
    
    /* Validate the checksum */
    icmp_hdr = icmp_hdr_from_ip_hdr(ip_hdr);
    received_cksum = icmp_hdr->icmp_sum;
    icmp_hdr->icmp_sum = 0;
    expected_cksum = cksum(icmp_hdr, ip_total_len(ip_hdr) - ip_header_len_bytes(ip_hdr));
    
    if (expected_cksum != received_cksum)
        return 0;
    
    if ((icmp_hdr->icmp_type != ICMP_TYPE_ECHO_REQUEST) ||
        (icmp_hdr->icmp_code != ICMP_TYPE_ECHO_REPLY))
        return 0;
    
    return 1;
}

void sr_send_icmp(struct sr_instance *sr, uint8_t *packet, unsigned int len, uint8_t type, uint8_t code)
{
    struct sr_ip_hdr *old_ip_hdr;
    struct sr_ip_hdr *ip_hdr_ptr;
    struct sr_ip_hdr ip_hdr;
    
    struct sr_icmp_hdr *icmp_hdr_ptr;
    struct sr_icmp_hdr icmp_hdr;
    struct sr_icmp_t3_hdr icmp_t3_hdr;
    
    struct sr_if *interface;
    struct sr_rt *rt;
    
    uint8_t *new_pkt;
    uint16_t icmp_len;
    uint16_t ip_tot_len;
    uint32_t dst_ip;
    
    /* Destination unreachable or Time exceeded */
    if (type == ICMP_TYPE_UNREACHABLE || type == ICMP_TYPE_TIME_EXCEEDED)
    {
        old_ip_hdr = (struct sr_ip_hdr *)packet;
        
        /* Unreachable */
        if (type == ICMP_TYPE_UNREACHABLE) {
            if (DEBUG)
                printf("<> ICMP - unreachable\n");
        }
        
        /* Time exceeded */
        if (type == ICMP_TYPE_TIME_EXCEEDED) {
            if (DEBUG)
                printf("<> ICMP - time exceeded\n");
        }
        
        /* Use type 3 ICMP header */
        icmp_t3_hdr.icmp_type = type;
        icmp_t3_hdr.icmp_code = code;
        icmp_t3_hdr.unused = 0;
        icmp_t3_hdr.next_mtu = 0;
        
        /* ICMP data = old IP header (20 bytes) + first 8 bytes of old datagram */
        memcpy(icmp_t3_hdr.data, old_ip_hdr, ICMP_DATA_SIZE); /* size = 28 */
        
        icmp_len = sizeof(icmp_t3_hdr);
        
        /* Update IP header */
        ip_hdr.ip_hl = ICMP_IP_HDR_LEN;
        ip_hdr.ip_v = ip_version_4;
        ip_hdr.ip_tos = 0; /* Initialize it to 0 bcos it is never used anyways */
        ip_hdr.ip_id = old_ip_hdr->ip_id;
        ip_hdr.ip_off = htons(IP_DF); /* don't fragment */
        ip_hdr.ip_ttl = DEFAULT_TTL;
        ip_hdr.ip_p = ip_protocol_icmp;
        ip_hdr.ip_dst = old_ip_hdr->ip_src;
        dst_ip = old_ip_hdr->ip_src;
        
        /* Look up longest prefix match in routing table */
        rt = sr_longest_prefix_match(sr, ip_in_addr(ip_hdr.ip_dst));
        if (rt == 0) {
            /* error: No matching destination */
            if (DEBUG)
                printf("***No matching destination for ICMP outgoing message\n");
            return;
        }
        
        /* Update source IP to be outgoing interface's ip address */
        interface = sr_get_interface(sr, (const char *)rt->interface);
        ip_hdr.ip_src = interface->ip;
        
        /* Header len + Body len */
        ip_tot_len = ICMP_IP_HDR_LEN_BYTES + icmp_len;
        ip_hdr.ip_len = htons(ip_tot_len);
        
        /* Allocate a packet, copy everything */
        new_pkt = malloc(ip_tot_len);
        memcpy(new_pkt, &ip_hdr, ICMP_IP_HDR_LEN_BYTES);
        
        /* Copy IP body aka ICMP message */
        memcpy(new_pkt + ICMP_IP_HDR_LEN_BYTES, &icmp_t3_hdr, sizeof(icmp_t3_hdr));
    }
    
    /* Echo reply */
    else if (type == ICMP_TYPE_ECHO_REPLY)
    {
        if (DEBUG)
            printf("<> ICMP - echo reply\n");
        
        /* Update IP header */
        old_ip_hdr = (struct sr_ip_hdr *)packet;
        dst_ip = old_ip_hdr->ip_src;
        old_ip_hdr->ip_src = old_ip_hdr->ip_dst;
        old_ip_hdr->ip_dst = dst_ip;
        old_ip_hdr->ip_ttl = DEFAULT_TTL;
        
        /* Update ICMP type from request to reply */
        icmp_hdr_ptr = icmp_hdr_from_ip_hdr(old_ip_hdr);
        icmp_hdr_ptr->icmp_code = code; /* 0 => no code */
        icmp_hdr_ptr->icmp_type = type;
        
        /* Allocate a copy of the packet */
        ip_tot_len = ip_total_len(old_ip_hdr); /* ntohs */
        new_pkt = malloc(ip_tot_len);
        memcpy(new_pkt, old_ip_hdr, ip_tot_len);
        
        /* Calculate ICMP message length for checksum */
        icmp_len = ip_tot_len - ICMP_IP_HDR_LEN;
    }
    
    /* Update checksum of IP */
    ip_hdr_ptr = (struct sr_ip_hdr *)new_pkt;
    ip_hdr_ptr->ip_sum = 0;
    ip_hdr_ptr->ip_sum = cksum(ip_hdr_ptr, ICMP_IP_HDR_LEN_BYTES);
    
    /* Update checksum of ICMP message starting at 'type' field */
    icmp_hdr_ptr = icmp_hdr_from_ip_hdr(ip_hdr_ptr);
    icmp_hdr_ptr->icmp_sum = 0;
    icmp_hdr_ptr->icmp_sum = cksum(icmp_hdr_ptr, icmp_len);
    
    /* Encapsulate and send */
    sr_encap_and_send_pkt(sr, new_pkt, ip_tot_len, dst_ip, 1, ethertype_ip);
    free(new_pkt);
}

void sr_encap_and_send_pkt(struct sr_instance *sr, uint8_t *packet, unsigned int len, uint32_t dest_ip, int send_icmp, enum sr_ethertype type)
{
    struct sr_arpentry *arp_entry;
    struct sr_arpreq *arp_req;
    struct sr_ethernet_hdr eth_hdr;
    uint8_t *eth_pkt;
    struct sr_if *interface;
    struct sr_rt *rt;
    unsigned int eth_pkt_len;
    
    rt = sr_longest_prefix_match(sr, ip_in_addr(dest_ip));
    
    /* If no matching entry, send ICMP network unreachable */
    if (rt == 0) {
        if (send_icmp)
            sr_send_icmp(sr, packet, len, ICMP_TYPE_UNREACHABLE, ICMP_CODE_NET);
        
        return;
    }
    
    interface = sr_get_interface(sr, rt->interface);
    
    /* Send packet if ARP entry exists in cache */
    arp_entry = sr_arpcache_lookup(&sr->cache, rt->gw.s_addr);
    if (arp_entry || type == ethertype_arp)
    {
        /* Create ethernet packet */
        /* Ethernet header + IP/ARP packet (header + body) */
        eth_pkt_len = len + sizeof(eth_hdr);
        eth_hdr.ether_type = htons(type); /* IP/ARP */
        
        /* ARP request */
        if (type == ethertype_arp && ((struct sr_arp_hdr *)packet)->ar_op == htons(arp_op_request)) {
            /* Broadcast ARP request by setting destination address to 255 */
            memset(eth_hdr.ether_dhost, 255, ETHER_ADDR_LEN);
            
            if (DEBUG)
                printf("Create ARP request\n");
        }
        
        /* IP packet or ARP reply */
        else {
            /* Set destination address to receiver's mac address */
           memcpy(eth_hdr.ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
        
            if (DEBUG)
                printf("Create ARP reply or IP packet\n");
        }
        
        /* Set source address to the interface's mac address */
        memcpy(eth_hdr.ether_shost, interface->addr, ETHER_ADDR_LEN);
        eth_pkt = malloc(eth_pkt_len);
        memcpy(eth_pkt, &eth_hdr, sizeof(eth_hdr));
        memcpy(eth_pkt + sizeof(eth_hdr), packet, len);
        sr_send_packet(sr, eth_pkt, eth_pkt_len, rt->interface);
        
        if (DEBUG)
            printf("Sent packet\n\n");
        
        free(eth_pkt);
        
        if (arp_entry)
            free(arp_entry);
    }
    
    /* Otherwise, add to ARP request queue */
    else
    {
        if (DEBUG)
            printf("Add ARP request to queue\n");
        
        eth_pkt = malloc(len);
        memcpy(eth_pkt, packet, len);
        arp_req = sr_arpcache_queuereq(&sr->cache, rt->gw.s_addr, eth_pkt, len, rt->interface);
        sr_arpreq_handle(sr, arp_req);
        free(eth_pkt);
    }
}

int sr_isBroadcastPacket(uint8_t *packet)
{
    struct sr_ethernet_hdr *ethernetHdr = (struct sr_ethernet_hdr *)packet;
    
    int i;
    for (i = 0; i < ETHER_ADDR_LEN; i++) {
        if (ethernetHdr->ether_dhost[i] != 0xff)
            return 0;
    }
    
    return 1;
}

int target_host(struct sr_instance* sr, uint8_t *packet, char* interface)
{
    struct sr_ethernet_hdr *ethernetHdr = (struct sr_ethernet_hdr *)packet;
    struct sr_if *incomingIF = sr_get_interface(sr, interface);
    
    if (sr_type_arp(ethernetHdr)) {
        struct sr_arp_hdr *arpHdr = arp_header(packet);
        
        while (incomingIF) {
            if (incomingIF->ip == arpHdr->ar_tip)
            /* We are the target host */
                return 1;
            
            incomingIF = incomingIF->next;
        }
        
    }
    else if (sr_type_ip(ethernetHdr)) {
        struct sr_ip_hdr *ipHdr = ip_header(packet);
        
        while (incomingIF) {
            if (incomingIF->ip == ipHdr->ip_dst)
                /* We are the target host */
                return 1;
            
            incomingIF = incomingIF->next;
        }
    }
    
    return 0;
}

int sr_type_arp(struct sr_ethernet_hdr *ethernetHdr)
{
    return ntohs(ethernetHdr->ether_type) == ethertype_arp;
}

int sr_type_ip(struct sr_ethernet_hdr *ethernetHdr)
{
    return ntohs(ethernetHdr->ether_type) == ethertype_ip;
}

struct sr_arp_hdr* arp_header(uint8_t *packet)
{
    return (struct sr_arp_hdr *)(packet + sizeof(struct sr_ethernet_hdr));
}

uint16_t arp_hrd(struct sr_arp_hdr *arp_hdr)
{
    return ntohs(arp_hdr->ar_hrd);
}

uint16_t arp_pro(struct sr_arp_hdr *arp_hdr)
{
    return ntohs(arp_hdr->ar_pro);
}

uint16_t arp_opcode(struct sr_arp_hdr *arp_hdr)
{
    return ntohs(arp_hdr->ar_op);
}

struct sr_ip_hdr* ip_header(uint8_t *packet)
{
    return (struct sr_ip_hdr *)(packet + sizeof(struct sr_ethernet_hdr));
}

uint8_t ip_header_len_bytes(struct sr_ip_hdr *ip_hdr)
{
    return ip_hdr->ip_hl * 4;
}

uint16_t ip_total_len(struct sr_ip_hdr *ip_hdr)
{
    return ntohs(ip_hdr->ip_len);
}

struct sr_icmp_hdr *icmp_hdr_from_ip_hdr(struct sr_ip_hdr *ip_hdr)
{
    uint8_t *icmp_hdr;
    
    icmp_hdr = (uint8_t *)(ip_hdr) + ip_header_len_bytes(ip_hdr);
    return (struct sr_icmp_hdr *)icmp_hdr;
}

struct in_addr ip_in_addr(uint32_t ip)
{
    struct in_addr ip_ia;
    ip_ia.s_addr = ip;
    return ip_ia;
}

/* rt.c */
struct sr_rt *sr_longest_prefix_match(struct sr_instance *sr, struct in_addr addr)
{
    struct sr_rt *cur;
    struct sr_rt *longest;
    unsigned long longest_len;
    
    cur = sr->routing_table;
    longest = 0;
    longest_len = 0;
    
    while (cur) {
        
        if (((cur->dest.s_addr & cur->mask.s_addr) == (addr.s_addr & cur->mask.s_addr)) && (longest_len <= cur->mask.s_addr))
        {
            longest_len = cur->mask.s_addr;
            longest = cur;
        }
        
        cur = cur->next;
    }
    
    return longest;
}




















