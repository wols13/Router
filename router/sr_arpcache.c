#include <netinet/in.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include <stdlib.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_utils.h"

/* 	Function that handles incoming ARP messages
 * 	Depending on whether it's a reply or a request, handle it differently.
 */
 
void handle_arpIncomingMessage(uint8_t **packet, struct sr_instance *sr, unsigned int len) {
	/* NOTE TO USE THE ETHERNET PROTOCOL ENUM FOR ARP messages AND also in ARP header to denote it's an ARP reply */	
	struct sr_if *currIface;
	struct sr_packet *pendingPkt;
	struct sr_arp_hdr *arp_hdr;
	struct sr_arpreq *req;
	
	/* Extract ARP header */
	arp_hdr = (struct sr_arp_hdr*)(*packet + sizeof(struct sr_ethernet_hdr));
		
	/* Check to see if reply or request */
	if (ntohs(arp_hdr->ar_op) == arp_op_reply) {
		req = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip); /* Sender's ip and mac */
		if (req != NULL){ 
			pendingPkt = req->packets;
			/* forward all packets from the req's queue on to that destination */
			while (pendingPkt != NULL) {
				/* CHECK: that it sends (FOR DEBUG PURPOSES) */
				/* Change ethernet addresses */
				struct sr_ethernet_hdr* pendingEtherHeader = (struct sr_ethernet_hdr*)pendingPkt->buf;
				memcpy(pendingEtherHeader->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
				struct sr_if* pendingIface = sr_get_interface(sr, pendingPkt->iface);
				memcpy(pendingEtherHeader->ether_shost, pendingIface->addr, ETHER_ADDR_LEN);
					
				sr_send_packet(sr, pendingPkt->buf, pendingPkt->len, pendingPkt->iface);
				pendingPkt = pendingPkt->next;
			}
			
			sr_arpreq_destroy(&(sr->cache), req);
		}
	} else {
		/* Go through linked list of interfaces, check their IP vs the destination IP of the ARP request packet */
		currIface = sr->if_list;
		while (currIface != NULL) {
			/* Check if packet is intended for us */
			if (currIface->ip == arp_hdr->ar_tip) {
				/* Create ARP reply packet (encapsulate in ethernet frame) and send to source of ARP request */
				struct sr_ethernet_hdr *ether_hdr = (struct sr_ethernet_hdr*)*packet;
				uint8_t *new_packet = (uint8_t *)malloc(sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr));
				struct sr_ethernet_hdr *new_ether_hdr = (struct sr_ethernet_hdr*)new_packet;
				struct sr_arp_hdr *new_arp_hdr = (struct sr_arp_hdr*)(new_packet + sizeof(struct sr_ethernet_hdr));

				/* The recipient MAC address will be the original sender's */
				memcpy(new_ether_hdr, ether_hdr, sizeof(struct sr_ethernet_hdr)); 
				memcpy(new_ether_hdr->ether_dhost, ether_hdr->ether_shost, ETHER_ADDR_LEN);
				/* The sending MAC address will be the interface's */
				memcpy(&(new_ether_hdr->ether_shost), &(currIface->addr), ETHER_ADDR_LEN);
				memcpy(new_arp_hdr, arp_hdr, sizeof(struct sr_arp_hdr));
				new_arp_hdr->ar_op = htons(arp_op_reply);
				new_arp_hdr->ar_tip = arp_hdr->ar_sip;
				new_arp_hdr->ar_sip = currIface->ip;
				memcpy(new_arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
				memcpy(new_arp_hdr->ar_sha, currIface->addr, ETHER_ADDR_LEN);

				sr_send_packet(sr, new_packet, len, currIface->name);
				break;
			}
			currIface = currIface->next;
		}
		
	}
}




/*	Function that handles sending ARP requests if necessary

	function handle_arpreq(req):
       		if difftime(now, req->sent) > 1.0
	           if req->times_sent >= 5:
               send icmp host unreachable to source addr of all pkts waiting
                 on this request
               arpreq_destroy(req)
           else:
               send arp request
               req->sent = now
               req->times_sent++
*/
void handle_arpreq(struct sr_instance *sr, struct sr_arpreq* req){
	struct sr_arpcache *cache = &(sr->cache);
	struct sr_packet *packet;
	struct sr_if *currIface, *returnIface;
	struct sr_ip_hdr *ip_hdr, *returnIP;
	uint8_t *returnICMP;
	time_t now;

	now = time(NULL);
	if (difftime(now, req->sent) >= 1.0) {
		if (req->times_sent >= 5) {
			packet = req->packets;			
			while (packet != NULL) {
				/* Send type 3 code 1 ICMP (Host Unreachable) */
				ip_hdr = (struct sr_ip_hdr*)(packet->buf + sizeof(struct sr_ethernet_hdr));
				returnIface = longestPrefixMatch(sr, ip_hdr->ip_src);
				if (returnIface != NULL){
					returnICMP = create_icmpMessage(sr, packet->buf, packet->len, 3, 1, returnIface->name);
					returnIP = (struct sr_ip_hdr*)(returnICMP + sizeof(struct sr_ethernet_hdr));
					returnIP->ip_src = returnIface->ip;
					sr_send_packet(sr, returnICMP, 70, returnIface->name);
					free(returnICMP);
				}
				packet = packet->next;
			}
			/* Destroy the request afterwards */
			sr_arpreq_destroy(cache, req);
		} else {
			/* BROADCAST ARP request */
			uint8_t* broadcast_packet = malloc(sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr));
			unsigned int new_pkt_len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr);
			struct sr_ethernet_hdr* new_ether_hdr = (struct sr_ethernet_hdr*)broadcast_packet;
			struct sr_arp_hdr* new_arp_hdr = (struct sr_arp_hdr*)(broadcast_packet + sizeof(struct sr_ethernet_hdr));
			memset(&new_ether_hdr->ether_dhost, 0xff, ETHER_ADDR_LEN);
			new_ether_hdr->ether_type = ntohs(ethertype_arp);
			
			currIface = sr->if_list;
			
			new_arp_hdr->ar_hrd = ntohs(arp_hrd_ethernet);
			new_arp_hdr->ar_pro = ntohs(ethertype_ip);
			new_arp_hdr->ar_hln = ETHER_ADDR_LEN;
			new_arp_hdr->ar_pln = 4; 
			new_arp_hdr->ar_op =  ntohs(arp_op_request);
			memset(&new_arp_hdr->ar_tha, 0, ETHER_ADDR_LEN);
			new_arp_hdr->ar_tip = req->ip;		
			
			while (currIface != NULL) {
				memcpy(&new_ether_hdr->ether_shost, currIface->addr, ETHER_ADDR_LEN);
				memcpy(&new_arp_hdr->ar_sha, currIface->addr, ETHER_ADDR_LEN);
				new_arp_hdr->ar_sip = currIface->ip;

				sr_send_packet(sr, broadcast_packet, new_pkt_len, currIface->name);

				currIface = currIface->next;
			}
			now = time(NULL);
			req->sent = now;
			req->times_sent++;
			free(broadcast_packet);
		}
	}
}


/*
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) {
    /* Requests are stored as a link list */
    struct sr_arpcache *ARPcache = &(sr->cache);
    struct sr_arpreq *currReq = ARPcache->requests;
    struct sr_arpreq *nextReq;

    while (currReq != NULL) {
		/* Save next request pointer in case handle req destroys currReq */
		nextReq = currReq->next;
		handle_arpreq(sr, currReq);
		currReq = nextReq;
	}
    
}

/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));

    struct sr_arpentry *entry = NULL, *copy = NULL;

    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }

    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }

    pthread_mutex_unlock(&(cache->lock));

    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.

   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));

    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }

    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }

    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));

        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }

    pthread_mutex_unlock(&(cache->lock));

    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));

    struct sr_arpreq *req, *prev = NULL, *next = NULL;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            if (prev) {
                next = req->next;
                prev->next = next;
            }
            else {
                next = req->next;
                cache->requests = next;
            }

            break;
        }
        prev = req;
    }

    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }

    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }

    pthread_mutex_unlock(&(cache->lock));

    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));

    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL;
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {
                if (prev) {
                    next = req->next;
                    prev->next = next;
                }
                else {
                    next = req->next;
                    cache->requests = next;
                }

                break;
            }
            prev = req;
        }

        struct sr_packet *pkt, *nxt;

        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }

        free(entry);
    }

    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");

    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }

    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));

    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;

    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));

    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);

    while (1) {
        sleep(1.0);

        pthread_mutex_lock(&(cache->lock));

        time_t curtime = time(NULL);

        int i;
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }

        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }

    return NULL;
}
