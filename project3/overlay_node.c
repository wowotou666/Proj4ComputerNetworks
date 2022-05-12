/*
 * CS 1652 Project 3 
 * (c) Amy Babay, 2022
 * (c) <Student names here>
 * 
 * Computer Science Department
 * University of Pittsburgh
 */

#include <time.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/errno.h>

#include <spu_alarm.h>
#include <spu_events.h>

#include "packets.h"
#include "client_list.h"
#include "node_list.h"
#include "edge_list.h"

#define PRINT_DEBUG 1

#define MAX_CONF_LINE 1024

#define INFINITE	10000000


enum mode {
    MODE_NONE,
    MODE_LINK_STATE,
    MODE_DISTANCE_VECTOR,
};

static uint32_t           My_IP      = 0;
static uint32_t           My_ID      = 0;
static uint16_t           My_Port    = 0;
static enum mode          Route_Mode = MODE_NONE;
static struct client_list Client_List;
static struct node_list   Node_List;
static struct edge_list   Edge_List;


typedef struct {
	int id;
	long cost;
} IF;

IF ifs[MAX_NODES + 1];
int ifcount;
int seqs[MAX_NODES + 1];
int my_seq;
int next_hops[MAX_NODES + 1];
long dists[MAX_NODES + 1];
int prevs[MAX_NODES + 1];
int states[MAX_NODES + 1];
int updated[MAX_NODES + 1];
int updatedcount;


long get_current_us(void)
{
    long            us;
    struct timespec spec;

    clock_gettime(CLOCK_REALTIME, &spec);

    us = spec.tv_sec * 1000000;
    us += spec.tv_nsec / 1000;
    return us;
}


void dv_dump()
{
	int i;
	return;
	
	
	Alarm(PRINT, "============================\n");
	for(i = 0; i < MAX_NODES; ++i) {
		if(next_hops[i] >= 0) {
			Alarm(PRINT, "dventry: dest=%d cost=%ld nexthop=%d\n", i, dists[i], next_hops[i]);
		}
	}
	
}


void dv_recalulate(int idx, long old, long new)
{
	int id = ifs[idx].id;
	int i;
	
	updatedcount = 0;
	
	for(i = 0; i < MAX_NODES; ++i) {
		if(i == id) {
			
			dists[i] = new;
			if(new == INFINITE) {
				next_hops[i] = -1;
			}
			else {
				next_hops[i] = i;
			}
			updated[updatedcount++] = i;
			continue;
		}
		
		if(next_hops[i] == id) {
			if(new == INFINITE) {
				dists[i] = INFINITE;
				next_hops[i] = -1;
			}
			else {
				dists[i] += new - old;
			}
			updated[updatedcount++] = i;
			continue;
		}
	}
	
	updated[updatedcount++] = My_ID;
	
	dv_dump();
}


void lsa_recalculate()
{
	int i, j;
	int mi, next;
	long m;
	long cost;
	int curr;
	
	Alarm(DEBUG, "LSA Recalculating\n");
	
	for(i = 0; i < MAX_NODES; ++i) {
		dists[i] = INFINITE;
		next_hops[i] = -1;
		states[i] = 0;
	}
	
	for(i = 0; i < ifcount; ++i) {
		 next = ifs[i].id;
		 cost = ifs[i].cost;

		for(j = 0; j < Edge_List.num_edges; ++j) {
			if(Edge_List.edges[j]->src_id != My_ID) continue;
			if(Edge_List.edges[j]->dst_id != next) continue;
			Edge_List.edges[j]->cost = cost;
			break;
		}
	 }
	
	dists[My_ID] = 0;
	next_hops[My_ID] = My_ID;
	
	while(1) {
		m = INFINITE;
		mi = -1;
		
		for(i = 0; i < MAX_NODES; ++i) {
			if(states[i]) continue;
			if(dists[i] >= INFINITE) continue;
			if(dists[i] < m) {
				m = dists[i];
				mi = i;
			}
		}
				
		if(mi < 0) break;
		
		states[mi] = 1;
		
		for(i = 0; i < Edge_List.num_edges; ++i) {
			if(Edge_List.edges[i]->src_id != mi) continue;
			next = Edge_List.edges[i]->dst_id;
			cost = Edge_List.edges[i]->cost;
			if(cost >= INFINITE) continue;
			
			if(dists[mi] + cost < dists[next]) {
				dists[next] = dists[mi] + cost;
				prevs[next] = mi;
			}
		}
	}
		
	for(i = 0; i < MAX_NODES; ++i) {
		if(dists[i] >= INFINITE) continue;
		if(i == My_ID) continue;
		
		curr = i;
		while(prevs[curr] != My_ID) {
			curr = prevs[curr];
		}
		
		next_hops[i] = curr;
		
		Alarm(DEBUG, "LSA node %d cost %ld nexthop %d\n", i, dists[i], next_hops[i]);
	}
}


void send_dvs();
void send_lsas();
void send_heartbeat(int idx);
void heartbeat_timeout(int idx, void* data)
{
	long cost;
	long save;
	
	Alarm(DEBUG, "Link to %d is down\n", ifs[idx].id);
	
	cost = INFINITE;
	if(ifs[idx].cost != cost) {
		save = ifs[idx].cost;
		ifs[idx].cost = INFINITE;
		
		if(Route_Mode == MODE_LINK_STATE) {
			lsa_recalculate();
			send_lsas();
		}
		else {
			dv_recalulate(idx, save, INFINITE);
			send_dvs();
		}
	}
	
	send_heartbeat(idx);
	
}


void resend_timeout(int idx, void* data)
{
	send_heartbeat(idx);
}


void send_heartbeat(int idx)
{
	struct heartbeat_pkt pkt;
	struct node* n;
	int sock;
	int ret;
	struct sockaddr_in addr;
	
	pkt.hdr.type = CTRL_HEARTBEAT;
	pkt.hdr.src_id = My_ID;
	pkt.hdr.dst_id = ifs[idx].id;
	pkt.us = get_current_us();
	
	n = get_node_from_id(&Node_List, ifs[idx].id);
	addr = n->addr;
	addr.sin_port = htons(ntohs(addr.sin_port) + 1);
	
	if((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        Alarm(EXIT, "overlay_node: node UDP socket error: %s\n", strerror(errno));
    }

	
	Alarm(DEBUG, "overlay_node: sending heartbeat to node %d\n", ifs[idx].id);
	
	ret = sendto(sock, &pkt, sizeof(pkt), 0,
                 (struct sockaddr *)&addr,
                 sizeof(addr));
    if (ret < 0) {
        Alarm(EXIT, "Error sending to node with sock %d\n",
              sock);
    }
	
	close(sock);
	
	sp_time delay;
	delay.sec = 3;
	delay.usec = 0;
	E_queue(heartbeat_timeout, idx, NULL, delay);
}


void send_lsa(int idx, struct lsa_pkt* pkt)
{
	struct node* n;
	int sock;
	int ret;
	int i;
	struct sockaddr_in addr;
	
	pkt->hdr.dst_id = ifs[idx].id;
	
	n = get_node_from_id(&Node_List, ifs[idx].id);
	addr = n->addr;
	addr.sin_port = htons(ntohs(addr.sin_port) + 1);
	
	if((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        Alarm(EXIT, "overlay_node: node UDP socket error: %s\n", strerror(errno));
    }

	
	Alarm(DEBUG, "overlay_node: sending lsa to node %d, seq=%d\n", ifs[idx].id, my_seq);
	
	ret = sendto(sock, pkt, sizeof(*pkt), 0,
                 (struct sockaddr *)&addr,
                 sizeof(addr));
    if (ret < 0) {
        Alarm(EXIT, "Error sending to node with sock %d\n",
              sock);
    }
	
	close(sock);
}


void send_lsas2(struct lsa_pkt* pkt)
{
	int i;
	
	for(i = 0; i < ifcount; ++i) {
		if(ifs[i].cost < INFINITE) {
			send_lsa(i, pkt);
		}
	}
}


void send_lsas()
{
	int i;
	
	struct lsa_pkt pkt;
	pkt.hdr.type = CTRL_LSA;
	pkt.hdr.src_id = My_ID;
	pkt.node = My_ID;
	pkt.seq = my_seq;
	
	pkt.ifcount = ifcount;
	for(i = 0; i < ifcount; ++i) {
		pkt.ids[i] = ifs[i].id;
		pkt.costs[i] = ifs[i].cost;
	}
	
	my_seq++;
	
	send_lsas2(&pkt);
}


void send_dv(int idx)
{
	
	struct node* n;
	int sock;
	int ret;
	int i;
	struct sockaddr_in addr;
	int next;
	struct dv_pkt pkt;
	
	pkt.hdr.type = CTRL_DV;
	pkt.hdr.src_id = My_ID;
	
	pkt.dvcount = 0;
	for(i = 0; i < updatedcount; ++i) {
		next = updated[i];
		if(next_hops[next] == ifs[idx].id) {
			continue;
		}
		
		pkt.ids[pkt.dvcount] = updated[i];
		pkt.costs[pkt.dvcount] = dists[updated[i]];
		pkt.dvcount++;
	}
	
	
	pkt.hdr.dst_id = ifs[idx].id;
	
	
	n = get_node_from_id(&Node_List, ifs[idx].id);
	addr = n->addr;
	addr.sin_port = htons(ntohs(addr.sin_port) + 1);
	
	if((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        Alarm(EXIT, "overlay_node: node UDP socket error: %s\n", strerror(errno));
    }
	
	Alarm(PRINT, "overlay_node: sending dv to node %d, dvcount=%d\n", ifs[idx].id, pkt.dvcount);
	
	ret = sendto(sock, &pkt, sizeof(pkt), 0,
                 (struct sockaddr *)&addr,
                 sizeof(addr));
    if (ret < 0) {
        Alarm(EXIT, "Error sending to node with sock %d\n",
              sock);
    }
	
	close(sock);
}


void send_dvs()
{
	int i;
	
	if(updatedcount <= 0) return;
	
	
	for(i = 0; i < ifcount; ++i) {
		if(ifs[i].cost < INFINITE) {
			send_dv(i);
		}
	}
}


/* Forward the packet to the next-hop node based on forwarding table */
void forward_data(struct data_pkt *pkt)
{
	struct node* n;
	int ret;
	int next;
	int sock;
	
    Alarm(DEBUG, "overlay_node: forwarding data to overlay node %u, client port "
                 "%u\n", pkt->hdr.dst_id, pkt->hdr.dst_port);
    /*
     * Students fill in! Do forwarding table lookup, update path information in
     * header (see deliver_locally for an example), and send packet to next hop
     * */
	 
	{
		 next = next_hops[pkt->hdr.dst_id];
		 if(next < 0) {
			 Alarm(PRINT, "overlay_node: no route for %d\n", pkt->hdr.dst_id);
			 return;
		 }
		 
		n = get_node_from_id(&Node_List, next);
		
		if((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
			Alarm(EXIT, "overlay_node: node UDP socket error: %s\n", strerror(errno));
		}
		
		pkt->hdr.path[pkt->hdr.path_len++] = My_ID;
		
		Alarm(DEBUG, "overlay_node: sending data to node %d\n", next);
		
		ret = sendto(sock, pkt, sizeof(*pkt), 0,
					 (struct sockaddr *)&n->addr,
					 sizeof(n->addr));
		if (ret < 0) {
			Alarm(EXIT, "Error sending to node with sock %d\n",
				  sock);
		}
		
		close(sock);
	 }
}

/* Deliver packet to one of my local clients */
void deliver_locally(struct data_pkt *pkt)
{
    int path_len = 0;
    int bytes = 0;
    int ret = -1;
    struct client_conn *c = get_client_from_port(&Client_List, pkt->hdr.dst_port);

    /* Check whether we have a local client with this port to deliver to. If
     * not, nothing to do */
    if (c == NULL) {
        Alarm(PRINT, "overlay_node: received data for client that does not "
                     "exist! overlay node %d : client port %u\n",
                     pkt->hdr.dst_id, pkt->hdr.dst_port);
        return;
    }

    Alarm(DEBUG, "overlay_node: Delivering data locally to client with local "
                 "port %d\n", c->data_local_port);

    /* stamp packet so we can see the path taken */
    path_len = pkt->hdr.path_len;
    if (path_len < MAX_PATH) {
        pkt->hdr.path[path_len] = My_ID;
        pkt->hdr.path_len++;
    }

    /* Send data to client */
    bytes = sizeof(struct data_pkt) - MAX_PAYLOAD_SIZE + pkt->hdr.data_len;
    ret = sendto(c->data_sock, pkt, bytes, 0,
                 (struct sockaddr *)&c->data_remote_addr,
                 sizeof(c->data_remote_addr));
    if (ret < 0) {
        Alarm(PRINT, "Error sending to client with sock %d %d:%d\n",
              c->data_sock, c->data_local_port, c->data_remote_port);
        goto err;
    }

    return;

err:
    remove_client_with_sock(&Client_List, c->control_sock);
}

/* Handle incoming data message from another overlay node. Check whether we
 * need to deliver locally to a connected client, or forward to the next hop
 * overlay node */
void handle_overlay_data(int sock, int code, void *data)
{
    int bytes;
    struct data_pkt pkt;
    struct sockaddr_in recv_addr;
    socklen_t fromlen;

    Alarm(DEBUG, "overlay_node: received overlay data msg!\n");

    fromlen = sizeof(recv_addr);
    bytes = recvfrom(sock, &pkt, sizeof(pkt), 0, (struct sockaddr *)&recv_addr,
                     &fromlen);
    if (bytes < 0) {
        Alarm(EXIT, "overlay node: Error receiving overlay data: %s\n",
              strerror(errno));
    }

    /* If there is data to forward, find next hop and forward it */
    if (pkt.hdr.data_len > 0) {
        char tmp_payload[MAX_PAYLOAD_SIZE+1];
        memcpy(tmp_payload, pkt.payload, pkt.hdr.data_len);
        tmp_payload[pkt.hdr.data_len] = '\0';
        Alarm(DEBUG, "Got forwarded data packet of %d bytes: %s\n",
              pkt.hdr.data_len, tmp_payload);

        if (pkt.hdr.dst_id == My_ID) {
            deliver_locally(&pkt);
        } else {
            forward_data(&pkt);
        }
    }
}

/* Respond to heartbeat message by sending heartbeat echo */
void handle_heartbeat(struct heartbeat_pkt *pkt)
{
	struct heartbeat_echo_pkt pkt2;
	struct node* n;
	int sock;
	int ret;
	struct sockaddr_in addr;
	
    if (pkt->hdr.type != CTRL_HEARTBEAT) {
        Alarm(PRINT, "Error: non-heartbeat msg in handle_heartbeat\n");
        return;
    }

    Alarm(DEBUG, "Got heartbeat from %d\n", pkt->hdr.src_id);

     /* Students fill in! */
	 
	pkt2.hdr.type = CTRL_HEARTBEAT_ECHO;
	pkt2.hdr.src_id = My_ID;
	pkt2.hdr.dst_id = pkt->hdr.src_id;
	pkt2.us = pkt->us;
	
	n = get_node_from_id(&Node_List, pkt->hdr.src_id);
	addr = n->addr;
	addr.sin_port = htons(ntohs(addr.sin_port) + 1);
	
	if((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        Alarm(EXIT, "overlay_node: node UDP socket error: %s\n", strerror(errno));
    }
	
	Alarm(DEBUG, "overlay_node: sending heartbeat echo to node %d\n", pkt->hdr.src_id);
	
	ret = sendto(sock, &pkt2, sizeof(pkt2), 0,
                 (struct sockaddr *)&addr,
                 sizeof(addr));
    if (ret < 0) {
        Alarm(EXIT, "Error sending to node with sock %d\n",
              sock);
    }
	
	close(sock);
}

/* Handle heartbeat echo. This indicates that the link is alive, so update our
 * link weights and send update if we previously thought this link was down.
 * Push forward timer for considering the link dead */
void handle_heartbeat_echo(struct heartbeat_echo_pkt *pkt)
{
	int idx = -1;
	int i;
	long cost;
	long save;
	
    if (pkt->hdr.type != CTRL_HEARTBEAT_ECHO) {
        Alarm(PRINT, "Error: non-heartbeat_echo msg in "
                     "handle_heartbeat_echo\n");
        return;
    }

    Alarm(DEBUG, "Got heartbeat_echo from %d\n", pkt->hdr.src_id);

     /* Students fill in! */
	 for(i = 0; i < ifcount; ++i) {
		 if(ifs[i].id == pkt->hdr.src_id) {
			 idx = i;
			 break;
		 }
	 }
	 
	 if(idx < 0) return;
	 
	 cost = get_current_us() - pkt->us;
	 if(cost > INFINITE) {
		 cost = INFINITE;
	 }
	 
	 Alarm(DEBUG, "Link to %d cost %ld\n", pkt->hdr.src_id, cost);
	 
	 if(ifs[idx].cost != cost) {
		save = ifs[idx].cost;
		ifs[idx].cost = cost;
		
		if(Route_Mode == MODE_LINK_STATE) {
			lsa_recalculate();
			send_lsas();
		}
		else {
			dv_recalulate(idx, save, cost);
			send_dvs();
		}
	}
	 
	 E_dequeue(heartbeat_timeout, idx, NULL);
	 
	 sp_time delay;
	 delay.sec = 3;
	 delay.usec = 0;
	 E_queue(resend_timeout, idx, NULL, delay);
}

/* Process received link state advertisement */
void handle_lsa(struct lsa_pkt *pkt)
{
	int i, j;
	int node, seq, next;
	long cost;
	
    if (pkt->hdr.type != CTRL_LSA) {
        Alarm(PRINT, "Error: non-lsa msg in handle_lsa\n");
        return;
    }

    if (Route_Mode != MODE_LINK_STATE) {
        Alarm(PRINT, "Error: LSA msg but not in link state routing mode\n");
    }

    Alarm(DEBUG, "Got lsa from %d node=%d seq=%d\n", pkt->hdr.src_id, pkt->node, pkt->seq);

     /* Students fill in! */
	 node = pkt->node;
	 seq = pkt->seq;
	 
	 if(seq <= seqs[node]) {
		 return;
	 }
	 
	 seqs[node] = seq;
	 
	 for(i = 0; i < pkt->ifcount; ++i) {
		 next = pkt->ids[i];
		 cost = pkt->costs[i];

		for(j = 0; j < Edge_List.num_edges; ++j) {
			if(Edge_List.edges[j]->src_id != node) continue;
			if(Edge_List.edges[j]->dst_id != next) continue;
			Edge_List.edges[j]->cost = cost;
			break;
		}
	 }
	 
	 send_lsas2(pkt);
	 
	 lsa_recalculate();
}

/* Process received distance vector update */
void handle_dv(struct dv_pkt *pkt)
{
	int i;
	int next;
	long cost;
	int idx = -1;
	
    if (pkt->hdr.type != CTRL_DV) {
        Alarm(PRINT, "Error: non-dv msg in handle_dv\n");
        return;
    }

    if (Route_Mode != MODE_DISTANCE_VECTOR) {
        Alarm(PRINT, "Error: Distance Vector Update msg but not in distance "
                     "vector routing mode\n");
    }

    Alarm(PRINT, "Got dv from %d\n", pkt->hdr.src_id);

     /* Students fill in! */
	 for(i = 0; i < ifcount; ++i) {
		 if(ifs[i].id == pkt->hdr.src_id) {
			 idx = i;
			 break;
		 }
	 }
	 
	 if(idx < 0) return;
	 
	 updatedcount = 0;
	 
	 for(i = 0; i < pkt->dvcount; ++i) {
		 next = pkt->ids[i];
		 cost = pkt->costs[i] + ifs[idx].cost;
		 if(cost > INFINITE) {
			 cost = INFINITE;
		 }
			
		 Alarm(PRINT, "dv: node %d cost %ld from %d\n", next, cost, ifs[idx].id);
		 
		 if(dists[next] < INFINITE && next_hops[next] == ifs[idx].id) {
			 dists[next] = cost;
			 if(cost == INFINITE) {
				 next_hops[next] = -1;
			 }
			 
			 Alarm(PRINT, "dv updated: node %d cost %ld nexthop %d\n", next, cost, next_hops[next]);
			 updated[updatedcount++] = next;
			 continue;
		 }
		 
		 if(cost < dists[next]) {
			 dists[next] = cost;
			 next_hops[next] = ifs[idx].id;
			 Alarm(PRINT, "dv updated: node %d cost %ld nexthop %d\n", next, cost, next_hops[next]);
			 updated[updatedcount++] = next;
		 }
	 }
	 
	 dv_dump();
	 send_dvs();
}

/* Process received overlay control message. Identify message type and call the
 * relevant "handle" function */
void handle_overlay_ctrl(int sock, int code, void *data)
{
    char buf[MAX_CTRL_SIZE];
    struct sockaddr_in recv_addr;
    socklen_t fromlen;
    struct ctrl_hdr * hdr = NULL;
    int bytes = 0;

    Alarm(DEBUG, "overlay_node: received overlay control msg!\n");

    fromlen = sizeof(recv_addr);
    bytes = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&recv_addr,
                     &fromlen);
    if (bytes < 0) {
        Alarm(EXIT, "overlay node: Error receiving ctrl message: %s\n",
              strerror(errno));
    }
    hdr = (struct ctrl_hdr *)buf;

    /* sanity check */
    if (hdr->dst_id != My_ID) {
        Alarm(PRINT, "overlay_node: Error: got ctrl msg with invalid dst_id: "
              "%d\n", hdr->dst_id);
    }

    if (hdr->type == CTRL_HEARTBEAT) {
        /* handle heartbeat */
        handle_heartbeat((struct heartbeat_pkt *)buf);
    } else if (hdr->type == CTRL_HEARTBEAT_ECHO) {
        /* handle heartbeat echo */
        handle_heartbeat_echo((struct heartbeat_echo_pkt *)buf);
    } else if (hdr->type == CTRL_LSA) {
        /* handle link state update */
        handle_lsa((struct lsa_pkt *)buf);
    } else if (hdr->type == CTRL_DV) {
        /* handle distance vector update */
        handle_dv((struct dv_pkt *)buf);
    }
}

void handle_client_data(int sock, int unused, void *data)
{
    int ret, bytes;
    struct data_pkt pkt;
    struct sockaddr_in recv_addr;
    socklen_t fromlen;
    struct client_conn *c;

    Alarm(DEBUG, "Handle client data\n");
    
    c = (struct client_conn *) data;
    if (sock != c->data_sock) {
        Alarm(EXIT, "Bad state! sock %d != data sock\n", sock, c->data_sock);
    }

    fromlen = sizeof(recv_addr);
    bytes = recvfrom(sock, &pkt, sizeof(pkt), 0, (struct sockaddr *)&recv_addr,
                     &fromlen);
    if (bytes < 0) {
        Alarm(PRINT, "overlay node: Error receiving from client: %s\n",
              strerror(errno));
        goto err;
    }

    /* Special case: initial data packet from this client. Use it to set the
     * source port, then ack it */
    if (c->data_remote_port == 0) {
        c->data_remote_addr = recv_addr;
        c->data_remote_port = ntohs(recv_addr.sin_port);
        Alarm(DEBUG, "Got initial data msg from client with sock %d local port "
                     "%u remote port %u\n", sock, c->data_local_port,
                     c->data_remote_port);

        /* echo pkt back to acknowledge */
        ret = sendto(c->data_sock, &pkt, bytes, 0,
                     (struct sockaddr *)&c->data_remote_addr,
                     sizeof(c->data_remote_addr));
        if (ret < 0) {
            Alarm(PRINT, "Error sending to client with sock %d %d:%d\n", sock,
                  c->data_local_port, c->data_remote_port);
            goto err;
        }
    }

    /* If there is data to forward, find next hop and forward it */
    if (pkt.hdr.data_len > 0) {
        char tmp_payload[MAX_PAYLOAD_SIZE+1];
        memcpy(tmp_payload, pkt.payload, pkt.hdr.data_len);
        tmp_payload[pkt.hdr.data_len] = '\0';
        Alarm(DEBUG, "Got data packet of %d bytes: %s\n", pkt.hdr.data_len, tmp_payload);

        /* Set up header with my info */
        pkt.hdr.src_id = My_ID;
        pkt.hdr.src_port = c->data_local_port;

        /* Deliver / Forward */
        if (pkt.hdr.dst_id == My_ID) {
            deliver_locally(&pkt);
        } else {
            forward_data(&pkt);
        }
    }

    return;

err:
    remove_client_with_sock(&Client_List, c->control_sock);
    
}

void handle_client_ctrl_msg(int sock, int unused, void *data)
{
    int bytes_read = 0;
    int bytes_sent = 0;
    int bytes_expected = sizeof(struct conn_req_pkt);
    struct conn_req_pkt rcv_req;
    struct conn_ack_pkt ack;
    int ret = -1;
    int ret_code = 0;
    char * err_str = "client closed connection";
    struct sockaddr_in saddr;
    struct client_conn *c;

    Alarm(DEBUG, "Client ctrl message, sock %d\n", sock);

    /* Get client info */
    c = (struct client_conn *) data;
    if (sock != c->control_sock) {
        Alarm(EXIT, "Bad state! sock %d != data sock\n", sock, c->control_sock);
    }

    if (c == NULL) {
        Alarm(PRINT, "Failed to find client with sock %d\n", sock);
        ret_code = -1;
        goto end;
    }

    /* Read message from client */
    while (bytes_read < bytes_expected &&
           (ret = recv(sock, ((char *)&rcv_req)+bytes_read,
                       sizeof(rcv_req)-bytes_read, 0)) > 0) {
        bytes_read += ret;
    }
    if (ret <= 0) {
        if (ret < 0) err_str = strerror(errno);
        Alarm(PRINT, "Recv returned %d; Removing client with control sock %d: "
                     "%s\n", ret, sock, err_str);
        ret_code = -1;
        goto end;
    }

    if (c->data_local_port != 0) {
        Alarm(PRINT, "Received req from already connected client with sock "
                     "%d\n", sock);
        ret_code = -1;
        goto end;
    }

    /* Set up UDP socket requested for this client */
    if ((c->data_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        Alarm(PRINT, "overlay_node: client UDP socket error: %s\n", strerror(errno));
        ret_code = -1;
        goto send_resp;
    }

    /* set server address */
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = INADDR_ANY;
    saddr.sin_port = htons(rcv_req.port);

    /* bind UDP socket */
    if (bind(c->data_sock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
        Alarm(PRINT, "overlay_node: client UDP bind error: %s\n", strerror(errno));
        ret_code = -1;
        goto send_resp;
    }

    /* Register socket with event handling system */
    ret = E_attach_fd(c->data_sock, READ_FD, handle_client_data, 0, c, MEDIUM_PRIORITY);
    if (ret < 0) {
        Alarm(PRINT, "Failed to register client UDP sock in event handling system\n");
        ret_code = -1;
        goto send_resp;
    }

send_resp:
    /* Send response */
    if (ret_code == 0) { /* all worked correctly */
        c->data_local_port = rcv_req.port;
        ack.id = My_ID;
    } else {
        ack.id = 0;
    }
    bytes_expected = sizeof(ack);
    Alarm(DEBUG, "Sending response to client with control sock %d, UDP port "
                 "%d\n", sock, c->data_local_port);
    while (bytes_sent < bytes_expected) {
        ret = send(sock, ((char *)&ack)+bytes_sent, sizeof(ack)-bytes_sent, 0);
        if (ret < 0) {
            Alarm(PRINT, "Send error for client with sock %d (removing...): "
                         "%s\n", sock, strerror(ret));
            ret_code = -1;
            goto end;
        }
        bytes_sent += ret;
    }

end:
    if (ret_code != 0 && c != NULL) remove_client_with_sock(&Client_List, sock);
}

void handle_client_conn(int sock, int unused, void *data)
{
    int conn_sock;
    struct client_conn new_conn;
    struct client_conn *ret_conn;
    int ret;

    Alarm(DEBUG, "Handle client connection\n");

    /* Accept the connection */
    conn_sock = accept(sock, NULL, NULL);
    if (conn_sock < 0) {
        Alarm(PRINT, "accept error: %s\n", strerror(errno));
        goto err;
    }

    /* Set up the connection struct for this new client */
    new_conn.control_sock     = conn_sock;
    new_conn.data_sock        = -1;
    new_conn.data_local_port  = 0;
    new_conn.data_remote_port = 0;
    ret_conn = add_client_to_list(&Client_List, new_conn);
    if (ret_conn == NULL) {
        goto err;
    }

    /* Register the control socket for this client */
    ret = E_attach_fd(new_conn.control_sock, READ_FD, handle_client_ctrl_msg,
                      0, ret_conn, MEDIUM_PRIORITY);
    if (ret < 0) {
        goto err;
    }

    return;

err:
    if (conn_sock >= 0) close(conn_sock);
}

void init_overlay_data_sock(int port)
{
    int sock = -1;
    int ret = -1;
    struct sockaddr_in saddr;

    if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        Alarm(EXIT, "overlay_node: data socket error: %s\n", strerror(errno));
    }

    /* set server address */
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = INADDR_ANY;
    saddr.sin_port = htons(port);

    /* bind listening socket */
    if (bind(sock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
        Alarm(EXIT, "overlay_node: data bind error: %s\n", strerror(errno));
    }

    /* Register socket with event handling system */
    ret = E_attach_fd(sock, READ_FD, handle_overlay_data, 0, NULL, MEDIUM_PRIORITY);
    if (ret < 0) {
        Alarm(EXIT, "Failed to register overlay data sock in event handling system\n");
    }

}

void init_overlay_ctrl_sock(int port)
{
    int sock = -1;
    int ret = -1;
    struct sockaddr_in saddr;

    if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        Alarm(EXIT, "overlay_node: ctrl socket error: %s\n", strerror(errno));
    }

    /* set server address */
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = INADDR_ANY;
    saddr.sin_port = htons(port);
	
    /* bind listening socket */
    if (bind(sock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
        Alarm(EXIT, "overlay_node: ctrl bind error: %s\n", strerror(errno));
    }

    /* Register socket with event handling system */
    ret = E_attach_fd(sock, READ_FD, handle_overlay_ctrl, 0, NULL, MEDIUM_PRIORITY);
    if (ret < 0) {
        Alarm(EXIT, "Failed to register overlay ctrl sock in event handling system\n");
    }
}

void init_client_sock(int client_port)
{
    int client_sock = -1;
    int ret = -1;
    struct sockaddr_in saddr;
	int enable = 1;

    if ((client_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        Alarm(EXIT, "overlay_node: client socket error: %s\n", strerror(errno));
    }

    /* set server address */
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = INADDR_ANY;
    saddr.sin_port = htons(client_port);
	
	
	if (setsockopt(client_sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
		printf("setsockopt(SO_REUSEADDR) failed\n");
	}

    /* bind listening socket */
    if (bind(client_sock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
        Alarm(EXIT, "overlay_node: client bind error: %s\n", strerror(errno));
    }

    /* start listening */
    if (listen(client_sock, 32) < 0) {
        Alarm(EXIT, "overlay_node: client bind error: %s\n", strerror(errno));
        exit(-1);
    }

    /* Register socket with event handling system */
    ret = E_attach_fd(client_sock, READ_FD, handle_client_conn, 0, NULL, MEDIUM_PRIORITY);
    if (ret < 0) {
        Alarm(EXIT, "Failed to register client sock in event handling system\n");
    }

}


void init_ifs()
{
	int i;
	
	ifcount = 0;
	
	for(i = 0; i < Edge_List.num_edges; ++i) {
		if(Edge_List.edges[i]->src_id == My_ID) {
			ifs[ifcount].id = Edge_List.edges[i]->dst_id;
			ifs[ifcount].cost = INFINITE;
			Alarm(DEBUG, "INTERFACE id=%d cost=%d\n", ifs[ifcount].id, ifs[ifcount].cost);
			ifcount++;
		}
	}
	
	for(i = 0; i < ifcount; ++i) {
		send_heartbeat(i);
	}
}
	


void init_link_state()
{
	int i;
	
    Alarm(DEBUG, "init link state\n");
	
	init_ifs();
	
	for(i = 0; i < Edge_List.num_edges; ++i) {
		Edge_List.edges[i]->cost = INFINITE;
	}
	
	lsa_recalculate();
	
	my_seq = 1;
}

void init_distance_vector()
{
	int i;
	
    Alarm(DEBUG, "init distance vector\n");
	
	init_ifs();
	
	for(i = 0; i < MAX_NODES; ++i) {
		dists[i] = INFINITE;
		next_hops[i] = -1;
	}
	
	dists[My_ID] = 0;
}

uint32_t ip_from_str(char *ip)
{
    struct in_addr addr;

    inet_pton(AF_INET, ip, &addr);
    return ntohl(addr.s_addr);
}

void process_conf(char *fname, int my_id)
{
    char     buf[MAX_CONF_LINE];
    char     ip_str[MAX_CONF_LINE];
    FILE *   f        = NULL;
    uint32_t id       = 0;
    uint16_t port     = 0;
    uint32_t src      = 0;
    uint32_t dst      = 0;
    uint32_t cost     = 0;
    int node_sec_done = 0;
    int ret           = -1;
    struct node n;
    struct edge e;
    struct node *retn = NULL;
    struct edge *rete = NULL;

    Alarm(DEBUG, "Processing configuration file %s\n", fname);

    /* Open configuration file */
    f = fopen(fname, "r");
    if (f == NULL) {
        Alarm(EXIT, "overlay_node: error: failed to open conf file %s : %s\n",
              fname, strerror(errno));
    }

    /* Read list of nodes from conf file */
    while (fgets(buf, MAX_CONF_LINE, f)) {
        Alarm(DEBUG, "Read line: %s", buf);

        if (!node_sec_done) {
            // sscanf
            ret = sscanf(buf, "%u %s %hu", &id, ip_str, &port);
            Alarm(DEBUG, "    Node ID: %u, Node IP %s, Port: %u\n", id, ip_str, port);
            if (ret != 3) {
                Alarm(DEBUG, "done reading nodes\n");
                node_sec_done = 1;
                continue;
            }

            if (id == my_id) {
                Alarm(DEBUG, "Found my ID (%u). Setting IP and port\n", id);
                My_Port = port;
                My_IP = ip_from_str(ip_str);
            }

            n.id = id;
            memset(&n.addr, 0, sizeof(n.addr));
            n.addr.sin_family = AF_INET;
            n.addr.sin_addr.s_addr = htonl(ip_from_str(ip_str));
            n.addr.sin_port = htons(port);
            n.next_hop = NULL;
            retn = add_node_to_list(&Node_List, n);
            if (retn == NULL) {
                Alarm(EXIT, "Failed to add node to list\n");
            }

        } else { /* Edge section */
            ret = sscanf(buf, "%u %u %u", &src, &dst, &cost);
            Alarm(DEBUG, "    Src ID: %u, Dst ID %u, Cost: %u\n", src, dst, cost);
            if (ret != 3) {
                Alarm(DEBUG, "done reading nodes\n");
                node_sec_done = 1;
                continue;
            }

            e.src_id = src;
            e.dst_id = dst;
            e.cost = cost;
            e.src_node = get_node_from_id(&Node_List, e.src_id);
            e.dst_node = get_node_from_id(&Node_List, e.dst_id);
            if (e.src_node == NULL || e.dst_node == NULL) {
                Alarm(EXIT, "Failed to find node for edge (%u, %u)\n", src, dst);
            }
            rete = add_edge_to_list(&Edge_List, e);
            if (rete == NULL) {
                Alarm(EXIT, "Failed to add edge to list\n");
            }
        }
    }
}

int 
main(int argc, char ** argv) 
{

    char * conf_fname    = NULL;

    if (PRINT_DEBUG) {
        Alarm_set_types(DEBUG);
    }

    /* parse args */
    if (argc != 4) {
        Alarm(EXIT, "usage: overlay_node <id> <config_file> <mode: LS/DV>\n");
    }

    My_ID      = atoi(argv[1]);
    conf_fname = argv[2];

    if (!strncmp("LS", argv[3], 3)) {
        Route_Mode = MODE_LINK_STATE;
    } else if (!strncmp("DV", argv[3], 3)) {
        Route_Mode = MODE_DISTANCE_VECTOR;
    } else {
        Alarm(EXIT, "Invalid mode %s: should be LS or DV\n", argv[5]);
    }

    Alarm(DEBUG, "My ID             : %d\n", My_ID);
    Alarm(DEBUG, "Configuration file: %s\n", conf_fname);
    Alarm(DEBUG, "Mode              : %d\n\n", Route_Mode);

    process_conf(conf_fname, My_ID);
    Alarm(DEBUG, "My IP             : "IPF"\n", IP(My_IP));
    Alarm(DEBUG, "My Port           : %u\n", My_Port);

    { /* print node and edge lists from conf */
        int i;
        struct node *n;
        struct edge *e;
        for (i = 0; i < Node_List.num_nodes; i++) {
            n = Node_List.nodes[i];
            Alarm(DEBUG, "Node %u : "IPF":%u\n", n->id,
                  IP(ntohl(n->addr.sin_addr.s_addr)),
                  ntohs(n->addr.sin_port));
        }

        for (i = 0; i < Edge_List.num_edges; i++) {
            e = Edge_List.edges[i];
            Alarm(DEBUG, "Edge (%u, %u) : "IPF":%u -> "IPF":%u\n",
                  e->src_id, e->dst_id,
                  IP(ntohl(e->src_node->addr.sin_addr.s_addr)),
                  ntohs(e->src_node->addr.sin_port),
                  IP(ntohl(e->dst_node->addr.sin_addr.s_addr)),
                  ntohs(e->dst_node->addr.sin_port));
        }
    }
    
    /* Initialize event system */
    E_init();

    /* Set up TCP socket for client connection requests */
    init_client_sock(My_Port);

    /* Set up UDP sockets for sending and receiving messages from other
     * overlay nodes */
    init_overlay_data_sock(My_Port);
    init_overlay_ctrl_sock(My_Port+1);

    if (Route_Mode == MODE_LINK_STATE) {
        init_link_state();
    } else {
        init_distance_vector();
    }

    /* Enter event handling loop */
    Alarm(DEBUG, "Entering event loop!\n");
    E_handle_events();

    return 0;
}
