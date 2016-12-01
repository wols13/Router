#include <time.h>
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "sr_utils.h"
#include "sr_if.h"

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

sr_nat_ip_position * sr_nat_get_ip_positions(struct sr_instance *sr, struct sr_ip_hdr* ip_hdr, char* interface) {
	static sr_nat_ip_position result[2];
	struct sr_if* currInterface = 0;
	
	/* Source is either type nat_position_host or nat_position_outside */
	if (strncmp(interface, "eth1", 4) == 0) {
		result[0] = nat_position_host;
	} else {
		result[0] = nat_position_server;
	}
	
	/* Destination is can be any position */
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

int sr_nat_update_headers(struct sr_instance **sr, uint8_t **packet, char* interface) {
	uint16_t target_port, source_port, tempChecksum;
	sr_nat_ip_position *ip_positions, source_ip_position, dest_ip_position;
	struct sr_nat_mapping *lookup_result;
	sr_nat_mapping_type mapping_type;
	struct sr_icmp_t8_hdr* icmp_hdr;
	struct sr_tcp_hdr* tcp_hdr;
	struct sr_nat_mapping *mappings;
	struct sr_nat_connection *conns;
	
	struct sr_ip_hdr* ip_hdr = (struct sr_ip_hdr*)(*packet + sizeof(struct sr_ethernet_hdr));
	int ip_size = 4 * ip_hdr->ip_hl;
	
	if (ip_hdr->ip_p == ip_protocol_icmp) {
		icmp_hdr = (struct sr_icmp_t8_hdr*)(*packet + ip_size + sizeof(struct sr_ethernet_hdr));
		mapping_type = nat_mapping_icmp;
		target_port = icmp_hdr->icmp_id;
		source_port = icmp_hdr->icmp_id;
	} else {
		tcp_hdr = (struct sr_tcp_hdr*)(*packet + ip_size + sizeof(struct sr_ethernet_hdr));
		mapping_type = nat_mapping_tcp;
		target_port = tcp_hdr->tcp_dst_port;
		source_port = tcp_hdr->tcp_src_port;
	}

	/* Determine whether src and dst are inside or outside to the NAT box */
	ip_positions = sr_nat_get_ip_positions(*sr, ip_hdr, interface);
	source_ip_position = ip_positions[0];
	dest_ip_position = ip_positions[1];

	/* From server to NAT hosts */
	if (source_ip_position == nat_position_server && dest_ip_position == nat_position_interface) {
		lookup_result = sr_nat_lookup_external(&((*sr)->nat), target_port, mapping_type);
		
		/* Drop packet if no mapping exists */
		if (lookup_result == NULL) {
			if(ntohs(target_port) >= 1024){
				sleep(6.0);
			}

			return 0;
		}
		
		/* Replace destination IP */
		ip_hdr->ip_dst = lookup_result->ip_int;
		
		/* Replace dest port */
		if (mapping_type == nat_mapping_icmp) {
			icmp_hdr->icmp_id = lookup_result->aux_int;
			/* Recalculate checksum here */
			icmp_hdr->icmp_sum = 0;
			tempChecksum = cksum(icmp_hdr, ip_hdr->ip_len - sizeof(struct sr_ip_hdr));
			icmp_hdr->icmp_sum = tempChecksum;
		} else {
			tcp_hdr->tcp_dst_port = lookup_result->aux_int;
			add_connection(&((*sr)->nat), lookup_result, ip_hdr->ip_src, 1);
			/* Recalculate checksum here */
			tcp_hdr->tcp_checksum = 0;
			tempChecksum = cksum(tcp_hdr, ip_hdr->ip_len - sizeof(struct sr_ip_hdr));
			tcp_hdr->tcp_checksum = tempChecksum;
		}

	/* From NAT hosts to server */
	} else if (source_ip_position == nat_position_host && dest_ip_position == nat_position_server) { 
		lookup_result = sr_nat_lookup_internal(&((*sr)->nat), ip_hdr->ip_src, source_port, mapping_type);

		/* If no existing mapping, make one */
		if (lookup_result == NULL) {
			lookup_result = sr_nat_insert_mapping(&((*sr)->nat), ip_hdr->ip_src, source_port, mapping_type);
		}

		/* Replace source IP */
		ip_hdr->ip_src = lookup_result->ip_ext;
		
		/* Replace src port */
		if (mapping_type == nat_mapping_icmp) {
			icmp_hdr->icmp_id = lookup_result->aux_ext;
			icmp_hdr->icmp_sum = 0;
			tempChecksum = cksum(icmp_hdr, ip_hdr->ip_len - sizeof(struct sr_ip_hdr));
			icmp_hdr->icmp_sum = tempChecksum;
		} else {
			tcp_hdr->tcp_src_port = lookup_result->aux_ext;
			add_connection(&((*sr)->nat), lookup_result, ip_hdr->ip_dst, 0);
			tcp_hdr->tcp_checksum = 0;
			tempChecksum = cksum(tcp_hdr, ip_hdr->ip_len - sizeof(struct sr_ip_hdr));
			tcp_hdr->tcp_checksum = tempChecksum;
		}
	}

	/* free(lookup_result); */
	return 0;
}

struct sr_nat_connection *add_connection(struct sr_nat *nat, struct sr_nat_mapping *mapping, uint32_t server_ip, int initializer){
	/* Initializer: (0) NAT Host, (1) Server */
	pthread_mutex_lock(&(nat->lock));
	
	struct sr_nat_connection *new_conn = malloc(sizeof(struct sr_nat_connection));
	new_conn->server_ip = server_ip;
	new_conn->last_updated = time(NULL);
	new_conn->state = nat_conn_state_transitory;
	new_conn->next = NULL;
	
	struct sr_nat_connection *conn = mapping->conns;
	
	if (conn == NULL){
		mapping->conns = new_conn;
		pthread_mutex_unlock(&(nat->lock));
		return new_conn;
	}
		
	while (conn) {
		if (conn->server_ip == server_ip) {
			conn->last_updated = time(NULL);
			if (initializer == 0) {
				conn->state = nat_conn_state_established;
			}
			free(new_conn);
			pthread_mutex_unlock(&(nat->lock));
			return conn;
		}
		if (conn->next == NULL){
			conn->next = new_conn;
			pthread_mutex_unlock(&(nat->lock));
			return new_conn;
		}
		conn = conn->next;
	}
	pthread_mutex_unlock(&(nat->lock));
	/* Should never get here */
	return NULL;
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
 /* struct sr_nat *nat = (struct sr_nat *)nat_ptr;
  struct sr_nat_mapping *mappings, *prev_mapping = NULL;
  
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));

    time_t curtime = time(NULL);

    * handle periodic tasks here *
    mappings = nat->mappings;
    while (mappings != NULL) {
		if (mappings->type == nat_mapping_icmp){
			* ICMP Timeout *
			if (difftime(curtime, mappings->last_updated) >= nat->ICMP_timeout) {
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
			* jhfjkkkkkkkkkkkkkkkkkgjhfkjlhjfgkf   k  hkfgjkh j *
		}
	}
    
    pthread_mutex_unlock(&(nat->lock));
  }*/
  return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {
	struct sr_nat_mapping *currMapping = nat->mappings;

	pthread_mutex_lock(&(nat->lock));

	/* handle lookup here, malloc and assign to copy */
	struct sr_nat_mapping *copy = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));

	if (currMapping != NULL) {
		memcpy(copy, currMapping, sizeof(struct sr_nat_mapping));
	} else {
		pthread_mutex_unlock(&(nat->lock));
		return NULL;
	}
	  
	while (copy != NULL) {
		if (copy->aux_ext == aux_ext) {
			break;
		}

		if(copy->next == NULL){
			pthread_mutex_unlock(&(nat->lock));
			return NULL;
		}
		memcpy(copy, copy->next, sizeof(struct sr_nat_mapping));
	}
	  
	pthread_mutex_unlock(&(nat->lock));
	return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy. */
	struct sr_nat_mapping *copy = malloc(sizeof(struct sr_nat_mapping));

	if (nat->mappings) {
		memcpy(copy, nat->mappings, sizeof(struct sr_nat_mapping));
	} else {
		pthread_mutex_unlock(&(nat->lock));
		return NULL;
	}
	  
	while (copy) {
		if (copy->ip_int == ip_int && copy->aux_int == aux_int) {
			break;
		}

		if (copy->next == NULL){
			pthread_mutex_unlock(&(nat->lock));
			return NULL;
		}
		memcpy(copy, copy->next, sizeof(struct sr_nat_mapping));
	}

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
	uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {
	struct sr_nat_mapping *currMapping = nat->mappings;

	pthread_mutex_lock(&(nat->lock));

	/* handle insert here, create a mapping, and then return a copy of it */
	struct sr_nat_mapping *mapping = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
	struct sr_nat_mapping *copy = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
	mapping->type = type;
	mapping->ip_int = ip_int;
	mapping->ip_ext = nat->ip_ext;
	mapping->aux_int = aux_int;
	mapping->aux_ext = nat->next_port;
	nat->next_port++;
	mapping->last_updated = time(NULL);	
	mapping->conns = NULL;
	mapping->next = NULL;
	  
	/* Loop to end of nat->mappings then add */
	if (currMapping == NULL) {
		nat->mappings = mapping;
	} else {
		while (currMapping != NULL) {
			if (currMapping->next == NULL){
				currMapping->next = mapping;
				break;
			}
			currMapping = currMapping->next;
		}
	}

	memcpy(copy, mapping, sizeof(struct sr_nat_mapping));
	pthread_mutex_unlock(&(nat->lock));
	return copy;
}
