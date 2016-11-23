
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>

int sr_nat_init(struct sr_nat *nat) { /* Initializes the nat */

  assert(nat);

  /* Acquire mutex lock */
  pthread_mutexattr_init(&(nat->attr));
  pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
  int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

  /* Initialize timeout thread */

  pthread_attr_init(&(nat->thread_attr));
  pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

  nat->mappings = NULL;
  /* Initialize any variables here */
  /* TODO */

  return success;
}


int sr_handle_nat(sr, packet, len, interface) {
	/* IP Types
	 * NAT Hosts:                   0
	 * NAT Box Internal IP:         1
	 * NAT Box External IP:         2
	 * None Of The Above (Outside): 3 */
	uint32_t *source_ip, *dest_ip; 
	int source_ip_position, dest_ip_position;
	
	struct sr_ethernet_hdr* ether_hdr = (struct sr_ethernet_hdr*)packet;
	
	/* Check is packet is an IP or ARP, the obtain src & dst ip */
	if (ntohs(ether_hdr->ether_type) == ethertype_arp) {
		struct sr_arp_hdr *arp_hdr = (struct sr_arp_hdr*)(*packet + sizeof(struct sr_ethernet_hdr));
		source_ip = (uint32_t *)arp_hdr->ar_sip;
		dest_ip = (uint32_t *)arp_hdr->ar_tip;
	} else {
		struct sr_ip_hdr* ip_hdr = (struct sr_ip_hdr*)(packet + sizeof(struct sr_ethernet_hdr));
		source_ip = (uint32_t *)ip_hdr->ip_src;
		dest_ip = (uint32_t *)ip_hdr->ip_dst;
	}
	
	//Source is either type 0 or 3
	if ((source_ip & 4294967040) == 167772416){
		source_ip_position = 0;
	} else {
		source_ip_position = 3
	}
	
	//Destination is either type 1, 2 or 3
	if (dest_ip == 167772427){
		dest_ip_position = 1;
	} else if (dest_ip == 2889876225) {
		dest_ip_position = 2;
	} else {
		dest_ip_position = 3;
	}
	
	//NAT hosts pinging Internal 
	//NAT hosts pinging External
	//Outside to NAT hosts
	//NAT hosts to Outside
}


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

  pthread_mutex_lock(&(nat->lock));

  /* free nat memory here */
  free(nat);

  ////////////////////////////////////////////////////////////////////////////

  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));

}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
  struct sr_nat *nat = (struct sr_nat *)nat_ptr;
  struct sr_nat_mapping *mappings, *prev_mapping = NULL;
  
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));

    time_t curtime = time(NULL);

    /* handle periodic tasks here */
    mappings = nat->mappings;
    while (mappings != NULL) {
		if (mappings->type == nat_mapping_icmp){
			/* ICMP Timeout */
			if (difftime(now, mappings->last_updated) >= ICMP_timeout) {
				if (prev_mapping == NULL){
					nat->mappings = mappings->next;
					free(mappings);
					mappings = nat->mappings;
				} else {
					prev_mapping->next = mappings->next;
					free(mappings);
					mappings = prev_mapping->next;
				}
			} else {
				prev_mapping = mappings;
				mappings = mappings->next;
			}
		} else if (mappings->type == nat_mapping_tcp) {
			/// what we can o 			
		}
	}
    
    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy */
  struct sr_nat_mapping *copy = NULL;

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy. */
  struct sr_nat_mapping *copy = NULL;

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle insert here, create a mapping, and then return a copy of it */
  struct sr_nat_mapping *mapping = NULL;

  pthread_mutex_unlock(&(nat->lock));
  return mapping;
}
