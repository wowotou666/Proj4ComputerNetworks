/* 
 * Copyright (c) 2020, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

// TODO: Change this file

#include <string.h>
#include <errno.h>
#include <petnet.h>

#include <petlib/pet_util.h>
#include <petlib/pet_log.h>
#include <petlib/pet_hashtable.h>
#include <petlib/pet_json.h>

#include <util/ip_address.h>
#include <util/inet.h>
#include <util/checksum.h>

#include "ethernet.h"
#include "ipv4.h"
#include "tcp.h"
#include "tcp_connection.h"
#include "packet.h"
#include "socket.h"
#include <unistd.h>

#define min(a,b) ((a) < (b) ? (a) : (b))

extern int petnet_errno;


struct tcp_state {
    struct tcp_con_map * con_map;
};



static inline struct tcp_raw_hdr *
__get_tcp_hdr(struct packet * pkt)
{
    struct tcp_raw_hdr * tcp_hdr = pkt->layer_2_hdr + pkt->layer_2_hdr_len + pkt->layer_3_hdr_len;

    pkt->layer_4_type    = TCP_PKT;
    pkt->layer_4_hdr     = tcp_hdr;
    pkt->layer_4_hdr_len = tcp_hdr->header_len * 4;

    return tcp_hdr;
}


static inline struct tcp_raw_hdr *
__make_tcp_hdr(struct packet * pkt, 
               uint32_t        option_len)
{
    pkt->layer_4_type    = TCP_PKT;
    pkt->layer_4_hdr     = pet_malloc(sizeof(struct tcp_raw_hdr) + option_len);
    pkt->layer_4_hdr_len = sizeof(struct tcp_raw_hdr) + option_len;

    return (struct tcp_raw_hdr *)(pkt->layer_4_hdr);
}

static inline void *
__get_payload(struct packet * pkt)
{
    if (pkt->layer_3_type == IPV4_PKT) {
        struct ipv4_raw_hdr * ipv4_hdr = pkt->layer_3_hdr;

        pkt->payload     = pkt->layer_4_hdr + pkt->layer_4_hdr_len;
        pkt->payload_len = ntohs(ipv4_hdr->total_len) - (pkt->layer_3_hdr_len + pkt->layer_4_hdr_len);

        return pkt->payload;
    } else {
        log_error("Unhandled layer 3 packet format\n");
        return NULL;
    }

}

static inline uint32_t
__get_payload_length(struct packet * pkt)
{
	if (pkt->layer_3_type == IPV4_PKT) {
		struct ipv4_raw_hdr * ipv4_hdr = pkt->layer_3_hdr;

		pkt->payload     = pkt->layer_4_hdr + pkt->layer_4_hdr_len;
		pkt->payload_len = ntohs(ipv4_hdr->total_len) - (pkt->layer_3_hdr_len + pkt->layer_4_hdr_len);

		return pkt->payload_len;
	} else {
		log_error("Unhandled layer 3 packet format\n");
		return 0;
	}
}

/*calculate the checksum*/
static inline uint16_t
__calculate_chksum(struct tcp_connection * connection,
					 struct packet       * pkt)
{
	struct ipv4_pseudo_hdr hdr;
	uint16_t checksum = 0;

	memset(&hdr, 0, sizeof(struct ipv4_pseudo_hdr));

	ipv4_addr_to_octets(connection->ipv4_tuple.local_ip,  hdr.src_ip);
	ipv4_addr_to_octets(connection->ipv4_tuple.remote_ip,  hdr.dst_ip);

	hdr.proto  = IPV4_PROTO_TCP;
	hdr.length = htons(pkt->layer_4_hdr_len + pkt->payload_len);

	checksum = calculate_checksum_begin(&hdr, sizeof(struct ipv4_pseudo_hdr) / 2);
	checksum = calculate_checksum_continue(checksum, pkt->layer_4_hdr, pkt->layer_4_hdr_len / 2);
	checksum = calculate_checksum_continue(checksum, pkt->payload,     pkt->payload_len     / 2);


	/*
     * If there is an odd number of data bytes we have to include a 0-byte after the the last byte
	 */
	if ((pkt->payload_len % 2) != 0) {
		uint16_t tmp = *(uint8_t *)(pkt->payload + pkt->payload_len - 1);

		checksum = calculate_checksum_finalize(checksum, &tmp, 1);
	} else {
		checksum = calculate_checksum_finalize(checksum, NULL, 0);
	}

	return checksum;
}

pet_json_obj_t
tcp_hdr_to_json(struct tcp_raw_hdr * hdr)
{
    pet_json_obj_t hdr_json = PET_JSON_INVALID_OBJ;

    hdr_json = pet_json_new_obj("TCP Header");

    if (hdr_json == PET_JSON_INVALID_OBJ) {
        log_error("Could not create TCP Header JSON\n");
        goto err;
    }

    pet_json_add_u16 (hdr_json, "src port",    ntohs(hdr->src_port));
    pet_json_add_u16 (hdr_json, "dst port",    ntohs(hdr->dst_port));
    pet_json_add_u32 (hdr_json, "seq num",     ntohl(hdr->seq_num));
    pet_json_add_u32 (hdr_json, "ack num",     ntohl(hdr->ack_num));
    pet_json_add_u8  (hdr_json, "header len",  hdr->header_len * 4);
    pet_json_add_bool(hdr_json, "URG flag",    hdr->flags.URG);
    pet_json_add_bool(hdr_json, "ACK flag",    hdr->flags.ACK);
    pet_json_add_bool(hdr_json, "URG flag",    hdr->flags.URG);
    pet_json_add_bool(hdr_json, "RST flag",    hdr->flags.RST);
    pet_json_add_bool(hdr_json, "SYN flag",    hdr->flags.SYN);
    pet_json_add_bool(hdr_json, "FIN flag",    hdr->flags.FIN);
    pet_json_add_u16 (hdr_json, "recv win",    ntohs(hdr->recv_win));
    pet_json_add_u16 (hdr_json, "checksum",    ntohs(hdr->checksum));
    pet_json_add_u16 (hdr_json, "urgent ptr",  ntohs(hdr->urgent_ptr));


    return hdr_json;

err:
    if (hdr_json != PET_JSON_INVALID_OBJ) pet_json_free(hdr_json);

    return PET_JSON_INVALID_OBJ;
}


void
print_tcp_header(struct tcp_raw_hdr * tcp_hdr)
{
    pet_json_obj_t hdr_json = PET_JSON_INVALID_OBJ;

    char * json_str = NULL;

    hdr_json = tcp_hdr_to_json(tcp_hdr);

    if (hdr_json == PET_JSON_INVALID_OBJ) {
        log_error("Could not serialize TCP Header to JSON\n");
        return;
    }

    json_str = pet_json_serialize(hdr_json);

    pet_printf("\"TCP Header\": %s\n", json_str);

    pet_free(json_str);
    pet_json_free(hdr_json);

    return;
}

/*set flags for various cases*/
static inline int
__set_flag(struct tcp_connection * connection, struct tcp_raw_hdr* tcp_hdr)
{
	//TODO: fix this part
	switch (connection->con_state) {
		case SYN_RCVD:
			tcp_hdr->flags.SYN = 1;
			tcp_hdr->flags.ACK = 1;
			return 0;
		case SYN_SENT:
			tcp_hdr->flags.SYN = 1;
			return 0;
		case ESTABLISHED:
			tcp_hdr->flags.ACK = 1;
			return 0;
		case CLOSE_WAIT:
			tcp_hdr->flags.FIN = 1;
			return 0;
		case FIN_WAIT1:
			tcp_hdr->flags.FIN = 1;
			return 0;
		case FIN_WAIT2:
			tcp_hdr->flags.ACK = 1;
			return 0;
		case TIME_WAIT:
		case CLOSED:
		case LISTEN:
			return -1;
		case LAST_ACK:
			tcp_hdr->flags.ACK = 1;
			return 0;
		case CLOSING:
			tcp_hdr->flags.FIN = 1;
			tcp_hdr->flags.ACK = 1;
			return 0;
		default:
			tcp_hdr->flags.ACK = 1;
			return 0;
	}
	return -1;
}

/*send packets' data*/
static inline int
__send_pkt(struct tcp_connection * connection, size_t len)
{
	struct packet       * pkt       = NULL;
	struct tcp_raw_hdr  * tcp_hdr   = NULL;

	uint32_t data_capacity = petnet_state->device_mtu - (sizeof(struct eth_raw_hdr) + ipv4_expected_hdr_len() + sizeof(struct tcp_raw_hdr));

	/*length's exceeding limit causes an error*/
	if (len > data_capacity) {
		log_error("length larger than data capacity");
		goto err;
	}

	pkt     = create_empty_packet();
	tcp_hdr = __make_tcp_hdr(pkt,len); //tcp header initialization

	__set_flag(connection,tcp_hdr);
	tcp_hdr->src_port = htons(connection->ipv4_tuple.local_port);
	tcp_hdr->dst_port = htons(connection->ipv4_tuple.remote_port);
	tcp_hdr->dst_port = htons(connection->ipv4_tuple.remote_port);
	tcp_hdr->header_len   = pkt->layer_4_hdr_len;
	tcp_hdr->seq_num = htonl(connection->seq_num);
	tcp_hdr->ack_num = htonl(connection->ack_num);
	tcp_hdr->recv_win = htons(65535);
	tcp_hdr->checksum = 0;

	/*capacity set and memory allocation of data packets*/
	pkt->payload_len = min((uint16_t)pet_socket_send_capacity(connection->sock),connection->recv_win_received);
	pkt->payload     = pet_malloc(pkt->payload_len);


	tcp_hdr->checksum = __calculate_chksum(connection, pkt);
	pet_socket_sending_data(connection->sock, pkt->payload, pkt->payload_len); //data input
	ipv4_pkt_tx(pkt, connection->ipv4_tuple.remote_ip);
	connection->seq_num += pkt->payload_len;

	return 0;

err:
	if (pkt)  free_packet(pkt);

	return -1;
}

// Finished and correctly working
/*When we pass in a socket, it makes a new connection,
on an empty connection with the local addr and local port variables. 
Then we add the previous sock to the newly formed listening connection.*/
int 
tcp_listen(struct socket    * sock, 
           struct ipv4_addr * local_addr,
           uint16_t           local_port)
{
	struct tcp_state      * tcp_state   = petnet_state->tcp_state;
	struct tcp_connection * connection         = NULL;

	connection = create_ipv4_tcp_con(tcp_state->con_map, local_addr, ipv4_addr_from_str("0.0.0.0") , local_port, local_port);

	if (connection == NULL) {
		pet_socket_error(sock, EINVAL);
		goto err;
	}

	connection->con_state = LISTEN;
	add_sock_to_tcp_con(tcp_state->con_map, connection, sock);

	put_and_unlock_tcp_con(connection);
	pet_printf("listening on port %d\n", local_port);

	return 0;

err:
	if (connection) put_and_unlock_tcp_con(connection);
	return -1;
}

/**/
int 
tcp_connect_ipv4(struct socket    * sock, 
                 struct ipv4_addr * local_addr, 
                 uint16_t           local_port,
                 struct ipv4_addr * remote_addr,
                 uint16_t           remote_port)
{
	struct tcp_state      * tcp_state   = petnet_state->tcp_state;
	struct tcp_connection * connection  = create_ipv4_tcp_con(tcp_state->con_map,local_addr, remote_addr, local_port, remote_port );

	if (connection == NULL){
		pet_socket_error(sock, EINVAL);
		goto err;
	}

	connection->con_state = SYN_SENT; //SYN sending
	add_sock_to_tcp_con(tcp_state->con_map, connection, sock);

	__send_pkt(connection,1); //connection established

	put_and_unlock_tcp_con(connection);
	return 0;

err:
	if (connection) put_and_unlock_tcp_con(connection);
	return -1;
}


int
tcp_send(struct socket * sock)
{
	struct tcp_state      * tcp_state   = petnet_state->tcp_state;
	struct tcp_connection * connection  = get_and_lock_tcp_con_from_sock(tcp_state->con_map, sock);

	if (connection == NULL) {
		pet_socket_error(sock, EINVAL);
		goto err;
	}

    /*connection establishion check*/
	if (connection->con_state != ESTABLISHED){
		log_error("NOT ESTABLISHED\n");
		goto err;
	}

	__send_pkt(connection,1);

	put_and_unlock_tcp_con(connection);

	return 0;

err:
	if (connection) put_and_unlock_tcp_con(connection);
	return -1;
}


int
tcp_close(struct socket * sock)
{
	struct tcp_state      * tcp_state   = petnet_state->tcp_state;
	struct tcp_connection * connection  = get_and_lock_tcp_con_from_sock(tcp_state->con_map, sock);


	if (connection == NULL || connection->con_state == CLOSED) {
		pet_socket_error(sock, EINVAL);
		goto err;
	}

	if (connection->con_state == CLOSED) {
		log_error("already closed\n");
		goto err;
	}

	connection->con_state = FIN_WAIT1;
	__send_pkt(connection,1);

	put_and_unlock_tcp_con(connection);

	return 0;

err:
	if (connection) put_and_unlock_tcp_con(connection);
	return -1;
}


int 
tcp_pkt_rx(struct packet * pkt)
{
	struct tcp_state* tcp_state = petnet_state->tcp_state;
	struct tcp_connection* con = NULL;
	struct tcp_connection* listen_con = NULL;
	struct ipv4_raw_hdr * ipv4_hdr  = (struct ipv4_raw_hdr *)pkt->layer_3_hdr;
	struct tcp_raw_hdr  * tcp_hdr   = NULL;
	void                * payload   = NULL;

	struct ipv4_addr * src_ip = NULL;
	struct ipv4_addr * dst_ip = NULL;

	int ret = 0;

	tcp_hdr  = __get_tcp_hdr(pkt);
	payload  = __get_payload(pkt);

	if (petnet_state->debug_enable) {
		print_tcp_header(tcp_hdr);
	}


	src_ip   = ipv4_addr_from_octets(ipv4_hdr->src_ip);
	dst_ip   = ipv4_addr_from_octets(ipv4_hdr->dst_ip);



	if (pkt->layer_3_type == IPV4_PKT) {
		//print_tcp_header(tcp_hdr);
		// Handle IPV4 Packet

		// passive connection
		if (tcp_hdr->flags.SYN && !tcp_hdr->flags.ACK) {

			con = create_ipv4_tcp_con(tcp_state->con_map, dst_ip, src_ip, ntohs(tcp_hdr->dst_port), ntohs(tcp_hdr->src_port));
			listen_con = get_and_lock_tcp_con_from_ipv4(tcp_state->con_map, dst_ip, ipv4_addr_from_str("0.0.0.0") , ntohs(tcp_hdr->dst_port), ntohs(tcp_hdr->dst_port));
			if (con == NULL || listen_con == NULL){
				log_error("Connection not found\n");
				put_and_unlock_tcp_con(listen_con);
				put_and_unlock_tcp_con(con);
				return -1;
			}

			con->con_state = SYN_RCVD;
			add_sock_to_tcp_con(tcp_state->con_map, con, listen_con->sock);

			put_and_unlock_tcp_con(listen_con);
			put_and_unlock_tcp_con(con);
		}
		/*check whether condition exists*/
		con = get_and_lock_tcp_con_from_ipv4(tcp_state->con_map, dst_ip, src_ip, ntohs(tcp_hdr->dst_port), ntohs(tcp_hdr->src_port));
		if (con == NULL){
			return -1;
		}
		con->ack_num_r = ntohl(tcp_hdr->ack_num);
		con->seq_num_r = ntohl(tcp_hdr->seq_num);
		if (con->seq_num_r != 0 ) {
			con->ack_num = con->seq_num_r;
		}
		if (con->ack_num_r != 0 ){
			con->seq_num = con->ack_num_r;
		}
		con->recv_win_received = ntohs(tcp_hdr->recv_win);
		switch (con->con_state) {
			
			case SYN_RCVD:
				if(tcp_hdr->flags.ACK){
					con->con_state = ESTABLISHED;
					add_sock_to_tcp_con(tcp_state->con_map,con,pet_socket_accepted(con->sock, src_ip, ntohs(tcp_hdr->src_port)));
					pet_printf("Handshake setup\n");
				}else{
					con->ack_num++;
					__send_pkt(con,1);
					con->seq_num++;
				}
				break;

			case SYN_SENT:
				if(tcp_hdr->flags.ACK && tcp_hdr->flags.SYN){
					con->con_state = ESTABLISHED;
					con->ack_num++;
					__send_pkt(con,1);
					pet_socket_connected(con->sock);
				}else{
					con->ack_num++;
					__send_pkt(con,1);
				}
				break;

			case ESTABLISHED:
				if(tcp_hdr->flags.FIN){
					pet_printf("try to close the connection \n");
					con->ack_num++;
					__send_pkt(con,1);
					con->con_state = CLOSE_WAIT;
				}else if(tcp_hdr->flags.ACK && __get_payload_length(pkt) != 0){
					pet_printf("receive data %u bytes\n ", __get_payload_length(pkt));
					con->ack_num += __get_payload_length(pkt);
					__send_pkt(con,1);
				}
				break;

			case CLOSE_WAIT:
				pet_printf("CLOSE_WAIT \n");
				con->ack_num++;
				__send_pkt(con,1);
				con->con_state = LAST_ACK;
				break;

			case LAST_ACK:
				if (tcp_hdr->flags.ACK){
					pet_printf("Connection CLOSED \n");
					con->con_state = CLOSED;
					pet_socket_closed(con->sock);
					remove_tcp_con(tcp_state->con_map, con);
					return 0;
				}
				break;

			case FIN_WAIT1:
				if (tcp_hdr->flags.ACK){
					pet_printf("FIN_WAIT1 \n");
					con->con_state = FIN_WAIT2;
				}
				break;

			case FIN_WAIT2:
				if (tcp_hdr->flags.FIN){
					pet_printf("FIN_WAIT2 \n");
					con->ack_num++;
					__send_pkt(con,1);
					con->con_state = TIME_WAIT;
				}
				break;

			case TIME_WAIT:
				sleep(30);
				con->con_state = CLOSED;
				pet_socket_closed(con->sock);
				remove_tcp_con(tcp_state->con_map, con);
				return ret;
				
			default:
				break;
		}

		put_and_unlock_tcp_con(con);
		pet_socket_received_data(con->sock,payload,pkt->payload_len);
		return ret;
	}
	return -1;
}

/*initialize the tcp state*/
int 
tcp_init(struct petnet * petnet_state)
{
    struct tcp_state * state = pet_malloc(sizeof(struct tcp_state));
	state->con_map  = create_tcp_con_map();
    petnet_state->tcp_state = state;
    return 0;
}

