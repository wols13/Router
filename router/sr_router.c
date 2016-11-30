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
    /* TODO BIG BIG BIG TODO: Maybe?  MAYBE?!!?*/

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

int sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  struct sr_ethernet_hdr* ether_hdr = 0;
  struct sr_ip_hdr* ip_hdr = 0;
  struct sr_if* currInterface = 0;
  struct sr_arpentry* ARPentry = 0;
  struct sr_arpreq* ARPreq = 0;
  struct sr_if *nexthopIface, *nat_iface;
  uint16_t tempChecksum;
  uint8_t* icmp_reply;
  int type, icmp_reply_len, nat_result;

  /* Check len meets minimum size */
  if (len < sizeof(struct sr_ethernet_hdr) ){
	/* Send ICMP reply to sender of type 12 code 2 (Bad length) */
	create_send_icmpMessage(sr, packet, len, 12, 2, interface);
	fprintf(stderr , "** Error: packet is wayy to short \n");
    return -1;
  }

	    printf("Hello\n");
  /* Extract ethernet header */
  ether_hdr = (struct sr_ethernet_hdr*)packet;
  
  /* Need to check if it contains an ARP or IP packet */
  if (ntohs(ether_hdr->ether_type) == ethertype_arp) {
		handle_arpIncomingMessage(&packet, sr, len);
		return 0;
  }
  
	    printf("Hello\n");
	/* Extract IP header */
	ip_hdr = (struct sr_ip_hdr*)(packet + sizeof(struct sr_ethernet_hdr));

	    printf("Yellow\n");

	nat_iface = longestPrefixMatch(sr, ip_hdr->ip_dst);
	if (nat_iface != NULL) 	{
           sr->nat.ip_ext = nat_iface->ip;
        }
	    printf("Hello\n");
	/* validate checksum */
	tempChecksum = ip_hdr->ip_sum;
	ip_hdr->ip_sum = 0;
	if (tempChecksum != cksum(ip_hdr, sizeof(struct sr_ip_hdr))) {
		/* Drop the packet */
		fprintf(stderr , "** Error: checksum mismatch \n");
		return -1;
	}
	
	/* If NAT enabled, update packet metadata */
	if (sr->nat_enabled == 1) {
	    nat_result = sr_nat_update_headers(&sr, &packet, interface);
		if (nat_result == -1) {
			return -1;
		} else if (nat_result == -2) {
			create_send_icmpMessage(sr, packet, len, 3, 3, interface);
			return -1;
		}
	}
	
	/* Decrement TTL */
	(ip_hdr->ip_ttl)--;

	/* Recalculate checksum here */
	tempChecksum = cksum(ip_hdr, sizeof(struct sr_ip_hdr));
	ip_hdr->ip_sum = tempChecksum;

	/* See if dest ip is one of our interfaces. If it IS, send it out through that interface */
	currInterface = sr->if_list;
	while (currInterface != NULL) {
		/* This checks if the interface ip is the same as the dest ip in the packet header */
		if (currInterface->ip == ip_hdr->ip_dst) {
			/*  If it is destined for us, then send an ICMP echo  */
			if (ip_hdr->ip_p == ip_protocol_icmp) {
				type = 0;
				icmp_reply_len = len;
			} else {
				/* Send destination unreachable type 3 code 3 (port unreachable) */
				type = 3;
				icmp_reply_len = 70;
			}

			ARPentry = sr_arpcache_lookup(&(sr->cache), ip_hdr->ip_src);
			icmp_reply = create_icmpMessage(sr, packet, len, type, type, currInterface->name);
			if (ARPentry != NULL){				
				sr_send_packet(sr, icmp_reply, icmp_reply_len, interface);
				free(icmp_reply);
				return 0;
			} else {
				ARPreq = sr_arpcache_queuereq(&(sr->cache), ip_hdr->ip_src, icmp_reply, icmp_reply_len, interface);
				handle_arpreq(sr, ARPreq);
				return 0;
			}
		}
		currInterface = currInterface->next;
	}
	
	/* Check if TTL = 0 (and it's not destined for our interface) and handle */
	if (ip_hdr->ip_ttl < 1) {
		/* Send ICMP reply to sender type 11 code 0 */
		create_send_icmpMessage(sr, packet, len, 11, 0, interface);
		fprintf(stderr , "** Packet's TTL is 0 \n");
		return -1;
	}

	/* Otherwise find longest prefix match (through routing table) and send it there */
	nexthopIface = longestPrefixMatch(sr, ip_hdr->ip_dst);
	if (!nexthopIface) {
		/* Send destination unreachable type 3 code 0 (Net unreachable) */
		create_send_icmpMessage(sr, packet, len, 3, 0, interface);
		fprintf(stderr , "** Error: No prefix match! \n");
		return -1;
	}

	ARPentry = sr_arpcache_lookup(&(sr->cache), ip_hdr->ip_dst);
	if (ARPentry != NULL) {
		/* MAC Address = ARPentry->mac; */
		memcpy(ether_hdr->ether_dhost, ARPentry->mac, ETHER_ADDR_LEN);
		memcpy(ether_hdr->ether_shost, nexthopIface->addr, ETHER_ADDR_LEN);
		
		sr_send_packet(sr, packet, len, nexthopIface->name);
		free(ARPentry);
	} else {
		/* Add a ARP request onto the ARP request queue */
		ARPreq = sr_arpcache_queuereq(&(sr->cache), ip_hdr->ip_dst, packet, len, nexthopIface->name);

		/* Write and call handle_arpreq */
		handle_arpreq(sr, ARPreq);
	}

	return 0;

}/* end sr_ForwardPacket */
