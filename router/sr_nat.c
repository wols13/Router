
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

sr_nat_ip_position * sr_nat_get_ip_positions(struct sr_instance *sr, struct sr_ip_hdr* ip_hdr) {
	static sr_nat_ip_position result[2];
	struct sr_if* currInterface = 0;
	
	//Source is either type nat_position_host or nat_position_outside
	if ((ip_hdr->ip_src & NAT_HOST_MASK) == NAT_HOST_PREFIX){
		result[0] = nat_position_host;
	} else {
		result[0] = nat_position_server;
	}
	
	//Destination is can be any position
	currInterface = sr->if_list;
	while (currInterface != NULL) {
		if (currInterface->ip == ip_hdr->ip_dst) {
			result[1] = nat_position_interface;
			return result;
		}
		currInterface = currInterface->next;
	}

	result[1] = nat_position_server;
	
	return result;
}

int sr_nat_update_headers(struct sr_instance *sr, uint8_t *packet) {
	uint16_t target_port, source_port;
	sr_nat_ip_position *ip_positions, source_ip_position, dest_ip_position;
	struct sr_nat_mapping lookup_result;
	sr_nat_mapping_type mapping_type;
	struct sr_icmp_t8_hdr* icmp_hdr;
	struct sr_tcp_hdr* tcp_hdr;
	struct sr_nat_mapping *mappings;
	struct sr_nat_connection *conns;
	
	struct sr_ip_hdr* ip_hdr = (struct sr_ip_hdr*)(packet + sizeof(struct sr_ethernet_hdr));
	
	if (ip_hdr->ip_p == ip_protocol_icmp) {
		icmp_hdr = (struct sr_icmp_t8_hdr*)(ip_hdr + sizeof(struct sr_ip_hdr));
		mapping_type = nat_mapping_icmp;
		target_port = icmp_hdr->icmp_id;
		source_port = icmp_hdr->icmp_id;
	} else {
		tcp_hdr = (struct sr_tcp_hdr*)(ip_hdr + sizeof(struct sr_ip_hdr));
		mapping_type = nat_mapping_tcp;
		target_port = tcp_hdr->tcp_dst_port;
		source_port = tcp_hdr->tcp_src_port;
	}
	
	/* Determine whether src and dst are inside or outside to the NAT box */
	ip_positions = sr_nat_get_ip_positions(sr, ip_hdr);
	source_ip_position = ip_positions[0];
	dest_ip_position = ip_positions[1];
	
	/* From server to NAT hosts */
	if (source_ip_position == nat_position_server && dest_ip_position == nat_position_interface) {
		lookup_result = sr_nat_lookup_external(&(sr->nat), target_port, mapping_type);
		
		/* Drop packet if no mapping exists */
		if (lookup_result == NULL) {
			/* If ICMP, drop immediately */
			if (mapping_type == nat_mapping_icmp) {
				fprintf(stderr,"Error: No existing mappings, dropping packet.\n");
				return -1;
			}
			
			/* If TCP, wait 6 seconds for outbound SYN */
			sleep(6.0);
			
			mappings = sr->nat.mappings;
			while (mappings != NULL) {
				conns = mappings->conns;
				while (conns != NULL) {
					if (conns->server_ip == ip_hdr->ip_src) {
						return -1;
					}
					conns = conns->next;
				}
				mappings = mappings->next;
			}
			
			/* -2: Send ICMP (3, 3) back to sender */
			return -2;
		}
		
		/* Replace destination IP */
		memcpy(ip_hdr->ip_dst, lookup_result->ip_int, sizeof(uint32_t));
		
		/* Replace dest port */
		if (mapping_type == nat_mapping_icmp) {
			memcpy(icmp_hdr->icmp_id, lookup_result->aux_int, sizeof(uint16_t));
		} else {
			memcpy(tcp_hdr->tcp_dst_port, lookup_result->aux_int, sizeof(uint16_t));
		}
	/* From NAT hosts to server */
	} else if (source_ip_position == nat_position_host && dest_ip_position == nat_position_server) { 
		lookup_result = sr_nat_lookup_internal(&(sr->nat), ip_hdr->ip_src, source_port, mapping_type);
		
		/* If no existing mapping, make one */
		if (lookup_result == NULL) {
			lookup_result = sr_nat_insert_mapping(&(sr->nat), ip_hdr->ip_src, source_port, mapping_type);
		}
		
		/* Replace source IP */
		memcpy(ip_hdr->ip_src, lookup_result->ip_ext, sizeof(uint32_t));
		
		/* Replace src port */
		if (mapping_type == nat_mapping_icmp) {
			memcpy(icmp_hdr->icmp_id, lookup_result->aux_ext, sizeof(uint16_t));
		} else {
			memcpy(tcp_hdr->tcp_src_port, lookup_result->aux_ext, sizeof(uint16_t));
		}
	}
	
	return 0;
}


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

  pthread_mutex_lock(&(nat->lock));

  /* free nat memory here */
  free(nat);

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
			// what we can o
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
