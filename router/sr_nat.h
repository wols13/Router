
#ifndef SR_NAT_TABLE_H
#define SR_NAT_TABLE_H

#define NAT_HOST_MASK 4278190080
#define NAT_HOST_PREFIX 167772160

#include <inttypes.h>
#include <time.h>
#include <pthread.h>

typedef enum {
  nat_position_interface, /* NAT Box Interface IP */
  nat_position_host, /* NAT Hosts */
  nat_position_server /* Server IP */
} sr_nat_ip_position;

typedef enum {
  nat_mapping_icmp,
  nat_mapping_tcp
  /* nat_mapping_udp, */
} sr_nat_mapping_type;

typedef enum {
  nat_conn_state_established,
  nat_conn_state_transitory
} sr_nat_connection_state;

struct sr_nat_connection {
  /* add TCP connection state data members here */
  uint32_t server_ip;
  time_t last_updated;
  sr_nat_connection_state state;
  struct sr_nat_connection *next;
};

struct sr_nat_mapping {
  sr_nat_mapping_type type;
  uint32_t ip_int; /* internal ip addr */
  uint32_t ip_ext; /* external ip addr */
  uint16_t aux_int; /* internal port or icmp id */
  uint16_t aux_ext; /* external port or icmp id */
  time_t last_updated; /* use to timeout mappings */
  struct sr_nat_connection *conns; /* list of connections. null for ICMP */
  struct sr_nat_mapping *next;
};

struct sr_nat {
  int ICMP_timeout;
  int TCP_established_timeout;
  int TCP_transitory_timeout;
  uint32_t ip_ext;
  uint16_t next_port;
  struct sr_nat_mapping *mappings;

  /* threading */
  pthread_mutex_t lock;
  pthread_mutexattr_t attr;
  pthread_attr_t thread_attr;
  pthread_t thread;
};

#include "sr_router.h"

int   sr_nat_init(struct sr_nat *nat);     /* Initializes the nat */
sr_nat_ip_position * sr_nat_get_ip_positions(struct sr_instance *sr, struct sr_ip_hdr* ip_hdr);
int sr_nat_update_headers(struct sr_instance **sr, uint8_t **packet);
struct sr_nat_connection *add_connection(struct sr_nat *nat, struct sr_nat_mapping *mapping, uint32_t server_ip, int initializer);
int   sr_nat_destroy(struct sr_nat *nat);  /* Destroys the nat (free memory) */
void *sr_nat_timeout(void *nat_ptr);  /* Periodic Timout */

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type );

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );

/* Insert a new mapping into the nat's mapping table.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );


#endif
