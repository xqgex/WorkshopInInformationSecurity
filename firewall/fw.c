#include "fw.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ilor Ifrach");

//**********************************************************
//****	Function Declaration				****
//**********************************************************
void init_default_rule(void);
int check_matching_packet_rule(rule_t *, struct iphdr *, __be16, __be16, ack_t);
long str_to_long(char *);
rule_t* parse_rule_line(char *);
__be32 size_to_mask(__u8);
unsigned int hook_func(unsigned int, struct sk_buff *, const struct net_device *, const struct net_device *, int (*okfn)(struct sk_buff *));
void delete_rules_array(void);
static ssize_t rules_read(struct file *, char *, size_t, loff_t *);
static ssize_t rules_write(struct file *, const char *, size_t, loff_t *);
static ssize_t log_read(struct file *, char *, size_t, loff_t *);
ssize_t active_display(struct device *, struct device_attribute *, char *);
ssize_t active_modify(struct device *, struct device_attribute *, const char *, size_t);
ssize_t rules_size_display(struct device *, struct device_attribute *, char *);
ssize_t log_size_display(struct device *, struct device_attribute *, char *);
ssize_t log_clear_modify(struct device *, struct device_attribute *, const char *, size_t);
ssize_t conn_tab_display(struct device *, struct device_attribute *, char *);
static int __init my_module_init_function(void);
static void __exit my_module_exit_function(void);
int is_empty(void);
struct conn_node* search_node_conn_table(__be32, __be32, __be16, __be16);
struct conn_node* search_src_conn_table(__be32, __be16);
void delete_node_conn_table(struct conn_node *);
int insert_first_conn_table(__be32, __be32, __be16, __be16, struct tcphdr *, state_t);
int insert_first(unsigned char, unsigned char, unsigned char, __be32, __be32, __be16, __be16, reason_t);
int delete_first(void);
int write_to_log(unsigned int hooknum, reason_t reason, struct iphdr * ip_header, __be16 src_port, __be16 dst_port, unsigned int action);
int destroy(int);
void update_flags(struct tcphdr *, struct conn_node *);
int check_packet_match_next_state(struct tcphdr *, struct conn_node *);



//**********************************************************
//****	Module Variables				****
//**********************************************************
static int major_number_rules = -1;
static int major_number_log = -1;
static int major_number_fw = -1;
static int active = 1;
static int rules_counter = 0;
static unsigned long log_counter = 0;
static unsigned long conn_counter = 0;
static rule_t* rules_array[MAX_RULES];
static rule_t* rule_default;
static struct class* sysfs_class = NULL;
static struct device* sysfs_device_log = NULL;
static struct device* sysfs_device_rules = NULL;
static struct device* sysfs_device_fw = NULL;
static struct log_node* log_head = NULL;
static struct conn_node* conn_table_head = NULL;
static struct nf_hook_ops nfho; // Main hook function
static struct file_operations fops_rules = {
	.owner = THIS_MODULE,
	.read = rules_read,
	.write = rules_write
};
static struct file_operations fops_log = {
	.owner = THIS_MODULE,
	.read = log_read
};
static DEVICE_ATTR(active,	S_IRWXU	| S_IRWXG | S_IRWXO, active_display,	active_modify);
static DEVICE_ATTR(rules_size,	S_IRUSR | S_IRGRP | S_IROTH, rules_size_display,NULL);
static DEVICE_ATTR(log_size,	S_IRUSR | S_IRGRP | S_IROTH, log_size_display,	NULL);
static DEVICE_ATTR(log_clear,	S_IWUSR	| S_IWGRP | S_IWOTH, NULL,		log_clear_modify);
static DEVICE_ATTR(conn_tab,	S_IRUSR | S_IRGRP | S_IROTH, conn_tab_display,	NULL);

//**********************************************************
//****	Module Functions				****
//**********************************************************
void init_default_rule(void) {
	strncpy(rule_default->rule_name, "Default rule", 13);
	rule_default->direction = DIRECTION_ANY;
	rule_default->src_ip = 16777343; // 127.0.0.1
	rule_default->src_prefix_mask = 255; // 255.0.0.0
	rule_default->src_prefix_size = 8;
	rule_default->dst_ip = 16777343; // 127.0.0.1
	rule_default->dst_prefix_mask = 255; // 255.0.0.0
	rule_default->dst_prefix_size = 8;
	rule_default->src_port = PORT_ANY;
	rule_default->dst_port = PORT_ANY;
	rule_default->protocol = PROT_ANY;
	rule_default->ack = ACK_ANY;
	rule_default->action = NF_ACCEPT;
}

int check_matching_packet_rule(rule_t* rule, struct iphdr* ip_header, __be16 src_port, __be16 dst_port, ack_t ack) {
	int found_port = 0;
	int found_direction = 0;
	//check protocol
	if (rule->protocol != PROT_ANY && rule->protocol != ip_header->protocol) {
		return 0;
	}
	//check ack
	if (rule->protocol == PROT_TCP && rule->ack != ACK_ANY && rule->ack != ack) {
		return 0;
	} // if it isn't tcp, the ack is ack_any but it dosen't matter.
	//check port
	if (rule->src_port == PORT_ANY) {
		found_port = 1;
	} else if (rule->src_port == PORT_ABOVE_1023 && (src_port > PORT_ABOVE_1023)) {
		found_port = 1;
	} else if (rule->src_port == src_port) {
		found_port = 1;
	}
	if (found_port == 0) {
		return 0;
	}
	found_port = 0;
	if (rule->dst_port == PORT_ANY) {
		found_port = 1;
	} else if (rule->dst_port == PORT_ABOVE_1023 && (dst_port > PORT_ABOVE_1023)) {
		found_port = 1;
	} else if (rule->dst_port == dst_port) {
		found_port = 1;
	}
	if (found_port == 0) {
		return 0;
	}
	// Check direction
	if (rule->direction == DIRECTION_OUT || rule->direction == DIRECTION_ANY) {
		if (rule->src_ip == 0 || (rule->src_ip&rule->src_prefix_mask) == (ip_header->saddr&rule->src_prefix_mask)) {
			if (rule->dst_ip == 0 || (rule->dst_ip&rule->dst_prefix_mask) == (ip_header->daddr&rule->dst_prefix_mask)) {
				found_direction = 1;
			}
		}
	}
	if (rule->direction == DIRECTION_IN || rule->direction == DIRECTION_ANY) {
		if (rule->dst_ip == 0 || (rule->dst_ip&rule->dst_prefix_mask) == (ip_header->saddr&rule->src_prefix_mask)) {
			if (rule->src_ip == 0 || (rule->src_ip&rule->src_prefix_mask) == (ip_header->daddr&rule->dst_prefix_mask)) {
				found_direction = 1;
			}
		}
	}
	if (found_direction == 0) {
		return 0;
	}
	return 1;
}

long str_to_long(char* input) {
	long result = -1;
	if (kstrtol(input, 10, &result) != 0) {
		return -1; // Underflow
	}
	return result;
}

rule_t* parse_rule_line(char* line) {
	char rule_name[20];
	unsigned long src_ip = 0, dst_ip = 0;
	int src_port = 0, dst_port = 0, direction = 0, protocol = 0, ack = 0, action = 0;
	int src_prefix_size = 0, dst_prefix_size = 0;
	rule_t* new_rule = (rule_t*)kmalloc(sizeof(rule_t), GFP_ATOMIC);
	if(!new_rule) {
		printk("parse_rule_line kmalloc failed\n"); 
		return NULL;
	}
	if (sscanf(line, "%s %d %lu %d %lu %d %d %d %d %d %d", rule_name, &direction, &src_ip, &src_prefix_size,
								&dst_ip, &dst_prefix_size, &protocol, &src_port,
								&dst_port, &ack, &action) != 11) {
		kfree(new_rule);
		return NULL;
	}
	// rule_name
	if (strlen(rule_name) > 20) {
		printk("parse_rule_line strlen(rule_name) == %d\n", strlen(rule_name));
		kfree(new_rule);
		return NULL;
	}
	strcpy(new_rule->rule_name, rule_name);
	// direction
	if (direction < 1 || 3 < direction) {
		kfree(new_rule);
		return NULL;
	}
	new_rule->direction = direction;
	// src_ip
	if (src_ip < 0 || src_ip > (unsigned long)858993459*(unsigned long)5) { // 4294967295
		kfree(new_rule);
		return NULL;
	}
	new_rule->src_ip = (__be32)src_ip;
	// src_prefix_size
	if (src_prefix_size < 0 || src_prefix_size > 32) {
		kfree(new_rule);
		return NULL;
	}
	new_rule->src_prefix_mask = (__be32)size_to_mask(src_prefix_size);
	new_rule->src_prefix_size = (__u8)src_prefix_size;
	// dst_ip
	if (dst_ip < 0 || dst_ip > (unsigned long)858993459*(unsigned long)5) { // 4294967295
		kfree(new_rule);
		return NULL;
	}
	new_rule->dst_ip = (__be32)dst_ip;
	// dst_prefix_size
	if (dst_prefix_size < 0 || dst_prefix_size > 32) {
		kfree(new_rule);
		return NULL;
	}
	new_rule->dst_prefix_mask = (__be32)size_to_mask(dst_prefix_size);
	new_rule->dst_prefix_size = (__u8)dst_prefix_size;
	// protocol
	if (protocol != 1 && protocol != 6 && protocol != 17 && protocol != 255 && protocol != 143) {
		kfree(new_rule);
		return NULL;
	}
	new_rule->protocol = protocol;
	// src_port
	if (src_port < PORT_ANY || src_port > PORT_ABOVE_1023) {
		kfree(new_rule);
		return NULL;
	}
	new_rule->src_port = (__be16)src_port;
	// dst_port
	if (dst_port < PORT_ANY || dst_port > PORT_ABOVE_1023) {
		kfree(new_rule);
		return NULL;
	}
	new_rule->dst_port = (__be16)dst_port;
	// ack
	if (ack < 1 || 3 < ack) {
		kfree(new_rule);
		return NULL;
	}
	new_rule->ack = ack;
	// action
	if (action < 0 || 1 < action) {
		kfree(new_rule);
		return NULL;
	}
	new_rule->action = action;
	return new_rule;
}

__be32 size_to_mask(__u8 size){
	__u8 i;
	__be32 mask = 1;
	for (i=1; i<size; ++i) {
		mask = mask*2;
		mask++;
	}
	return mask;
}

// function to be called by hook
unsigned int hook_func(unsigned int hooknum,
			struct sk_buff* skb,
			const struct net_device* in,
			const struct net_device* out,
			int (*okfn)(struct sk_buff *)) {
	struct iphdr* ip_header;
	reason_t reason = REASON_ILLEGAL_VALUE;
	ack_t ack = ACK_ANY;
	__be16 src_port = 0;
	__be16 dst_port = 0;
	struct icmphdr* icmp_header;
	struct udphdr* udp_header;
	struct tcphdr* tcp_header;
	struct conn_node* searched_connection;
	struct conn_node* searched_server;
	__u16 fin = 0; //fin flag in tcp
	__u16 urg = 0; //urg flag in tcp
	__u16 psh = 0; //psh flag in tcp
	unsigned int action = NF_DROP;
	unsigned int found_match_rule = 0;
	unsigned long timenow = 0;
	struct timespec ts;
	state_t state = -1;
	int tcplen = 0;
	int i = 0;
	if (!skb) {
		printk("skb is NULL\n");
		return NF_DROP;
	}
	ip_header = (struct iphdr *)skb_network_header(skb);
	if (!ip_header) {
		printk("ip_header is NULL\n");
		return NF_DROP;
	}
	if (ip_header->protocol == IPPROTO_TCP) { // Transmission Control Protocol, IPPROTO_TCP = 6
		tcp_header = tcp_hdr(skb);
		//tcp_header = (struct tcphdr *)(skb_transport_header(skb)+20); // TODO XXX This is from checksum.c
		if (!tcp_header) {
			printk("tcp_header is NULL\n");
			return NF_DROP;
		}
		src_port = tcp_header->source;
		dst_port = tcp_header->dest;
		if (tcp_header->ack == 0) {
			ack = ACK_NO;
		} else {
			ack = ACK_YES;
		}
		fin = tcp_header->fin;
		urg = tcp_header->urg;
		psh = tcp_header->psh;
	} else if (ip_header->protocol == IPPROTO_UDP) { // User Datagram Protocol, IPPROTO_UDP = 17
		udp_header = udp_hdr(skb);
		src_port = udp_header->source;
		dst_port = udp_header->dest;
	} else if (ip_header->protocol == IPPROTO_ICMP) { // Internet Control Message Protocol, IPPROTO_ICMP = 1
		icmp_header = icmp_hdr(skb);
		src_port = icmp_header->type;
		dst_port = icmp_header->code;
	} else {
		printk("Unknown protocol\n");
		return NF_DROP;
	}
	//////////////////////////////////////////////////
	getnstimeofday(&ts);
	timenow = ts.tv_sec;
	if (active == 0) {
		action = NF_ACCEPT;
		reason = REASON_FW_INACTIVE;
	//Packet from proxy!
	} else if ((PROXY_IP == ip_header->saddr)&&(htons(PROXY_PORT) == src_port)) { // If src ip (ip_header->saddr) and port (src_port) are from the proxy
		searched_connection = search_src_conn_table(ip_header->daddr, dst_port); // Search the packet in the connection table SRC based on the packet DST
		if ((searched_connection == NULL) || (ip_header->protocol != IPPROTO_TCP)) {
			printk("Got unknown packet from the proxy\n");
			return NF_DROP;
		}
		// Restore the packet
		ip_header->saddr = searched_connection->conn->src_ip;
		src_port = searched_connection->conn->src_port;
		tcp_header->source = src_port;
		ip_header->daddr = searched_connection->conn->dst_ip;
		dst_port = searched_connection->conn->dst_port;
		tcp_header->dest = dst_port;
		tcp_header->res1 = searched_connection->conn->res1;
		tcp_header->doff = searched_connection->conn->doff;
		tcp_header->fin = searched_connection->conn->fin;
		tcp_header->syn = searched_connection->conn->syn;
		tcp_header->rst = searched_connection->conn->rst;
		tcp_header->psh = searched_connection->conn->psh;
		tcp_header->ack = searched_connection->conn->ack;
		tcp_header->urg = searched_connection->conn->urg;
		tcp_header->ece = searched_connection->conn->ece;
		tcp_header->cwr = searched_connection->conn->cwr;
		// Calculate tcp_header&ip_header checksum
		tcplen = (skb->len - ((ip_header->ihl )<< 2));
		tcp_header->check = 0;
		tcp_header->check = tcp_v4_check(tcplen, ip_header->saddr, ip_header->daddr,csum_partial((char*)tcp_header, tcplen,0));
		skb->ip_summed = CHECKSUM_NONE; //stop offloading
		ip_header->check = 0;
		ip_header->check = ip_fast_csum((u8 *)ip_header, ip_header->ihl);
		//
		action = NF_ACCEPT;
		reason = REASON_ACCEPTED_BY_PROXY;
	//Some packet, need to transfer it to the proxy.
	} else if ((searched_connection = search_node_conn_table(ip_header->saddr, ip_header->daddr, src_port, dst_port)) != NULL) { // search the packet in the connection table. src and dst in the connection table. If it is different null, it is found 
		if (searched_connection->conn->state == STATE_DATA) { // Connection state is 'data' and packet flags match 'data' state flags
			if ((src_port == 80 || dst_port == 80) || src_port == 20) { // If (source/dest port is 80) or (source port is 20)
				// Save the flags in the connection table
				update_flags(tcp_header, searched_connection);
				// Edit packet so it will be Sent to the proxy
				ip_header->saddr = searched_connection->conn->src_ip;
				tcp_header->source = searched_connection->conn->src_port;
				ip_header->daddr = PROXY_IP;
				tcp_header->dest = htons(PROXY_PORT);
				// Calculate tcp_header&ip_header checksum
				tcplen = (skb->len - ((ip_header->ihl )<< 2));
				tcp_header->check = 0;
				tcp_header->check = tcp_v4_check(tcplen, ip_header->saddr, ip_header->daddr,csum_partial((char*)tcp_header, tcplen,0));
				skb->ip_summed = CHECKSUM_NONE; //stop offloading
				ip_header->check = 0;
				ip_header->check = ip_fast_csum((u8 *)ip_header, ip_header->ihl);
				//
				reason = REASON_SENT_TO_PROXY;
			} else {
				reason = REASON_HANDSHAKE_MATCH;
			}
			action = NF_ACCEPT;
		} else { // Start connection or close connection
			if ((searched_connection->conn->state == STATE_START_1 || searched_connection->conn->state == STATE_START_2 || searched_connection->conn->state == STATE_START_3)
				&& timenow - searched_connection->conn->timestamp >= 25) { // If timeout
				// Delete the record
				delete_node_conn_table(searched_connection);
				action = NF_DROP;
				reason = REASON_HANDSHAKE_TIMEOUT;
			} else if ((state = check_packet_match_next_state(tcp_header, searched_connection)) != -1) {// If packet flag match the next state at the connection table
				// Update connection table state to be the next state
				searched_connection->conn->state = state;
				if ((searched_connection->conn->state == STATE_DATA) && (dst_port == 21)) { // If Handshake completed and the server port is 21
					// Add a new row to the connection table with server port 20
					if (insert_first_conn_table(ip_header->saddr, ip_header->daddr, 0, 20, tcp_header, STATE_START_1) == 0) {
						printk("hook_func failed to insert new record with 20 dst_port into the dynamic connection table\n");
						return NF_DROP;
					}
				}
				action = NF_ACCEPT;
				reason = REASON_HANDSHAKE_MATCH;
			} else if(searched_connection->conn->state == STATE_CLOSE_1 && (dst_port == 21)) { // We insert to the fin 
				searched_server = search_node_conn_table(ip_header->saddr, ip_header->daddr, 0, 20); 
				if (searched_server != NULL) {
					delete_node_conn_table(searched_server);
				} else {
					printk("we didn't find the server record in the conn table\n");
					return NF_DROP;
				}
				action = NF_ACCEPT;
				reason = REASON_HANDSHAKE_MATCH;
			} else if ((searched_connection->conn->state == STATE_CLOSE_4)) { // If it is the final state, remove the record from the conn table
				delete_node_conn_table(searched_connection);
				action = NF_ACCEPT;
				reason = REASON_HANDSHAKE_MATCH;
			} else {
				action = NF_DROP;
				reason = REASON_HANDSHAKE_FAILED;
			}
		}
	} else { // Compare to the static table
		// Default rule
		res = check_matching_packet_rule(rule_default, ip_header, src_port, dst_port, ack);
		if (res == 1) {
			return NF_ACCEPT;
		}
		// XMAS check
		if (fin == 1 && urg == 1 && psh == 1) {
			reason = REASON_XMAS_PACKET;
			action = NF_DROP;
		} else { // Check rules
			for (i=0; i<rules_counter; ++i) {
				res = check_matching_packet_rule(rules_array[i], ip_header, src_port, dst_port, ack);
				if (res == 1) {
					reason = i;
					action = rules_array[i]->action;
					found_match_rule = 1;
					break;
				}
			}
			if (found_match_rule == 0) {
				reason = REASON_NO_MATCHING_RULE;
				action = NF_ACCEPT;
			}
		}
		if ((action == NF_ACCEPT) && (ip_header->protocol == IPPROTO_TCP) && (tcp_header->syn == 1) && (tcp_header->ack == 0)) {
			// Create new record at the connection table
			if (insert_first_conn_table(ip_header->saddr, ip_header->daddr, src_port, dst_port ,tcp_header, STATE_START_1) == 0) {
				printk("hook_func failed to insert new record into the dynamic connection table\n");
				return NF_DROP;
			}
		}
	}
	if (write_to_log(hooknum, reason, ip_header, src_port, dst_port, action) == 0) {
		printk("hook_func write_to_log failed\n");
		return NF_DROP;
	}
	return action;
}



void update_flags(struct tcphdr* tcp_header, struct conn_node* searched_connection) {
	searched_connection->conn->res1 = tcp_header->res1;
	searched_connection->conn->doff = tcp_header->doff;
	searched_connection->conn->fin = tcp_header->fin;
	searched_connection->conn->syn = tcp_header->syn;
	searched_connection->conn->rst = tcp_header->rst;
	searched_connection->conn->psh = tcp_header->psh;
	searched_connection->conn->ack = tcp_header->ack;
	searched_connection->conn->urg = tcp_header->urg;
	searched_connection->conn->ece = tcp_header->ece;
	searched_connection->conn->cwr = tcp_header->cwr;
}

int check_packet_match_next_state(struct tcphdr* tcp_header, struct conn_node* searched_connection) {
	if((searched_connection->conn->state == STATE_START_1) && (tcp_header->syn == 1) && (tcp_header->ack == 0) && (tcp_header->fin == 0)) {
		return STATE_START_2;
	}
	else if((searched_connection->conn->state == STATE_START_2) && (tcp_header->syn == 1) && (tcp_header->ack == 1) && (tcp_header->fin == 0)) {
		return STATE_START_3;
	}
	else if((searched_connection->conn->state == STATE_START_3) && (tcp_header->syn == 0) && (tcp_header->ack == 1) && (tcp_header->fin == 0)) {
		return STATE_DATA;
	}
	else if((searched_connection->conn->state == STATE_DATA) && (tcp_header->syn == 0) && (tcp_header->fin == 0)) {
		return STATE_DATA;
	}
	else if((searched_connection->conn->state == STATE_DATA) && (tcp_header->syn == 0) && (tcp_header->ack == 0) && (tcp_header->fin == 1)) {
		return STATE_CLOSE_1;
	}
	else if((searched_connection->conn->state == STATE_CLOSE_1) && (tcp_header->syn == 0) && (tcp_header->ack == 1) && (tcp_header->fin == 0)) {
		return STATE_CLOSE_2;
	}
	else if((searched_connection->conn->state == STATE_CLOSE_2) && (tcp_header->syn == 0) && (tcp_header->ack == 0) && (tcp_header->fin == 1)) {
		return STATE_CLOSE_3;
	}
	else if((searched_connection->conn->state == STATE_CLOSE_3) && (tcp_header->syn == 0) && (tcp_header->ack == 1) && (tcp_header->fin == 0)) {
		return STATE_CLOSE_4;
	}
	return -1;
}

void delete_rules_array(void) {
	int i;
	for (i=0; i<rules_counter; ++i) {
		if (rules_array[i] != NULL) {
			kfree(rules_array[i]);
		}
	}
	rules_counter = 0;
}

// Called when a process, which already opened the dev file, attempts to read from it.
static ssize_t rules_read(struct file* filp, char* buffer, size_t length, loff_t* offset) {
	int bytes_read = 0; // Number of bytes actually written to the buffer
	int i = 0;
	int length_rule = 0;
	char* msg = (char *)kmalloc(sizeof(char)*MAX_RULES_LENGTH*MAX_RULES, GFP_ATOMIC);
	char* loop_rules = (char *)kmalloc(sizeof(char)*MAX_RULES_LENGTH, GFP_ATOMIC);
	if (!msg || !loop_rules) {
		printk("rules_read kmalloc failed\n");
		return 0;
	}
	*msg = '\0';
	*loop_rules = '\0';
	for (i=0; i<rules_counter; ++i) {
		length_rule = sprintf(loop_rules, "%s %d %lu %d %lu %d %d %d %d %d %d\n",
					rules_array[i]->rule_name,
					(int)rules_array[i]->direction,
					(unsigned long)rules_array[i]->src_ip,
					(int)rules_array[i]->src_prefix_size,
					(unsigned long)rules_array[i]->dst_ip,
					(int)rules_array[i]->dst_prefix_size,
					(int)rules_array[i]->protocol,
					(int)rules_array[i]->src_port,
					(int)rules_array[i]->dst_port,
					(int)rules_array[i]->ack,
					(int)rules_array[i]->action);
		if (length_rule <= 0) {
			printk("rules_read sprintf failed\n");
			kfree(msg);
			kfree(loop_rules);
			return bytes_read;
		}
		bytes_read += length_rule;
		strncat(msg, loop_rules, length_rule);
	}
	if (copy_to_user(buffer, msg, bytes_read) != 0) {
		printk("rules_read copy_to_user failed\n");
	}
	kfree(msg);
	kfree(loop_rules);
	return bytes_read;
}

// Called when a process writes to dev file: echo "hi" > /dev/hello
static ssize_t rules_write(struct file* filp, const char* buff, size_t len, loff_t* off) {
	rule_t* res;
	char* loop_token;
	char* loop_end;
	char* msg = (char *)kmalloc(sizeof(char)*MAX_RULES_LENGTH*MAX_RULES, GFP_ATOMIC);
	char* loop_line = (char *)kmalloc(sizeof(char)*MAX_RULES_LENGTH*MAX_RULES, GFP_ATOMIC);
	if (!msg || !loop_line) {
		printk("rules_write kmalloc failed\n");
		return 0;
	}
	*msg = '\0';
	*loop_line = '\0';
	if (snprintf(msg, len, "%s", buff) < 0) {
		printk("rules_write snprintf failed\n");
		kfree(msg);
		kfree(loop_line);
		return 0;
	}
	delete_rules_array();
	strcpy(loop_line, msg);
	if (loop_line == NULL) {
		kfree(msg);
		kfree(loop_line);
		return -EINVAL;
	}
	if (len == 0) {
		kfree(msg);
		kfree(loop_line);
		return len;
	}
	loop_token = loop_line;
	loop_end = loop_line;
	while (loop_token != NULL) {
		strsep(&loop_end, "\n");
		res = parse_rule_line(loop_token);
		if (res == NULL){
			delete_rules_array();
			printk("Invalid rules file\n");
			kfree(loop_line);
			kfree(msg);
			return -EINVAL;
		} else {
			rules_array[rules_counter] = res;
			rules_counter++;
		}
		loop_token = loop_end;
	}
	kfree(loop_line);
	kfree(msg);
	return len;
}

// Called when a process, which already opened the dev file, attempts to read from it.
static ssize_t log_read(struct file* filp, char* buffer, size_t length, loff_t* offset) {
	int bytes_read = 0; // Number of bytes actually written to the buffer
	struct log_node* tmp = log_head;
	int length_log = 0;
	char* msg = (char *)kmalloc(sizeof(char)*log_counter*MAX_LOG_LENGTH, GFP_ATOMIC);
	char* loop_log = (char *)kmalloc(sizeof(char)*MAX_LOG_LENGTH, GFP_ATOMIC);
	if (!msg || !loop_log) {
		printk("log_read kmalloc failed\n");
		return 0;
	}
	*msg = '\0';
	*loop_log = '\0';
	while (tmp != NULL) {
		length_log = sprintf(loop_log, "timestamp: %ld, protocol: %u, action: %u, hooknum: %u, src_ip: %d, dst_ip: %d, src_port: %d, dst_port: %d, reason: %d, count: %d\n",
					tmp->log->timestamp,
					tmp->log->protocol,
					tmp->log->action,
					tmp->log->hooknum,
					tmp->log->src_ip,
					tmp->log->dst_ip,
					tmp->log->src_port,
					tmp->log->dst_port,
					(int)tmp->log->reason,
					tmp->log->count);
		if (length_log <= 0) {
			printk("log_read sprintf failed\n");
			kfree(msg);
			kfree(loop_log);
			return bytes_read;
		}
		bytes_read += length_log;
		strncat(msg, loop_log, length_log);
		tmp = tmp->next;
	}
	if (copy_to_user(buffer, msg, bytes_read) != 0) {
		printk("log_read copy_to_user failed\n");
	}
	kfree(msg);
	kfree(loop_log);
	return bytes_read;
}

ssize_t active_display(struct device* dev, struct device_attribute* attr, char* buf) {
	return scnprintf(buf, PAGE_SIZE, "%d\n", active);
}

ssize_t active_modify(struct device* dev, struct device_attribute* attr, const char* buf, size_t count) {
	int temp = 0;
	if (sscanf(buf, "%d", &temp) == 1) {
		if (temp == 0) {
			active = 0;
			printk("Firewall status changed to => deactive\n");
		} else if (temp == 1) {
			active = 1;
			printk("Firewall status changed to => active\n");
		} else {
			printk("Invalid value for active");
		}
	}
	return count;
}

ssize_t rules_size_display(struct device* dev, struct device_attribute* attr, char* buf) {
	return scnprintf(buf, PAGE_SIZE, "%d", rules_counter);
}

ssize_t log_size_display(struct device* dev, struct device_attribute* attr, char* buf) {
	return scnprintf(buf, PAGE_SIZE, "%ld", log_counter);
}

ssize_t log_clear_modify(struct device* dev, struct device_attribute* attr, const char* buf, size_t count) {
	while (is_empty() == 0) {
		if (delete_first() == 0){
			printk("log_clear_modify delete_first failed\n");
			return 0;
		}
	}
	return count;
}

ssize_t conn_tab_display(struct device* dev, struct device_attribute* attr, char* buf) {
	return scnprintf(buf, PAGE_SIZE, "%d", 0); // TODO conn_tab
}

static int __init my_module_init_function(void) {
	nfho.hook = hook_func; // Function to call when conditions below met
	nfho.hooknum = NF_INET_PRE_ROUTING;//NF_INET_FORWARD;
	nfho.pf = PF_INET; // IPV4 packets
	nfho.priority = NF_IP_PRI_FIRST; // Set to highest priority over all other hook functions
	nf_register_hook(&nfho); // Register hook
	// Create char device
	major_number_log = register_chrdev(0, DEVICE_NAME_LOG, &fops_log);
	if (major_number_log < 0) {
		return destroy(0);
	}
	major_number_rules = register_chrdev(0, DEVICE_NAME_RULES, &fops_rules);
	if (major_number_rules < 0) {
		return destroy(1);
	}
	// Create sysfs class
	sysfs_class = class_create(THIS_MODULE, CLASS_NAME);
	if (IS_ERR(sysfs_class)) {
		return destroy(2);
	}
	// Create sysfs device
	sysfs_device_log = device_create(sysfs_class, NULL, MKDEV(major_number_log, 0), NULL, CLASS_NAME "_" DEVICE_NAME_LOG);
	if (IS_ERR(sysfs_device_log)) {
		return destroy(3);
	}
	sysfs_device_rules = device_create(sysfs_class, NULL, MKDEV(major_number_rules, 0), NULL, CLASS_NAME "_" DEVICE_NAME_RULES);
	if (IS_ERR(sysfs_device_rules)) {
		return destroy(4);
	}
	sysfs_device_fw = device_create(sysfs_class, NULL, MKDEV(major_number_fw, 0), NULL, CLASS_NAME "_" DEVICE_NAME_FW);
	if (IS_ERR(sysfs_device_fw)) {
		return destroy(5);
	}
	// Create sysfs file attributes	
	if (device_create_file(sysfs_device_rules, (const struct device_attribute *)&dev_attr_active.attr)) {
		return destroy(6);
	}
	if (device_create_file(sysfs_device_rules, (const struct device_attribute *)&dev_attr_rules_size.attr)) {
		return destroy(7);
	}
	if (device_create_file(sysfs_device_log, (const struct device_attribute *)&dev_attr_log_size.attr)) {
		return destroy(8);
	}
	if (device_create_file(sysfs_device_log, (const struct device_attribute *)&dev_attr_log_clear.attr)) {
		return destroy(9);
	}
	if (device_create_file(sysfs_device_fw, (const struct device_attribute *)&dev_attr_conn_tab.attr)) {
		return destroy(10);
	}
	rule_default = (rule_t*)kmalloc(sizeof(rule_t), GFP_ATOMIC);
	if (!rule_default) {
		printk("rule_default kmalloc failed\n");
		return destroy(11);
	}
	init_default_rule();
	return 0; // If non-0 return means init_module failed
}

static void __exit my_module_exit_function(void) {
	destroy(99);
}

int is_empty(void) {
	if (log_head == NULL) {
		return 1;
	}
	return 0;
}

struct conn_node* search_node_conn_table(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port) {
	struct conn_node * tmp = conn_table_head;
	while (tmp != NULL) {
		if (tmp->conn->src_ip == src_ip &&
		tmp->conn->dst_ip == dst_ip &&
		(tmp->conn->src_port == src_port || tmp->conn->src_port == 0) &&
		tmp->conn->dst_port == dst_port) {
			return tmp;
		} else if (tmp->conn->dst_ip == src_ip &&
		tmp->conn->src_ip == dst_ip &&
		tmp->conn->dst_port == src_port &&
		(tmp->conn->src_port == dst_port || tmp->conn->src_port == 0)) {
			return tmp;
		}
		tmp = tmp->next;
	}
	return tmp;
}

struct conn_node* search_src_conn_table(__be32 src_ip, __be16 src_port) {
	struct conn_node * tmp = conn_table_head;
	while (tmp != NULL) {
		if (tmp->conn->src_ip == src_ip && (tmp->conn->src_port == src_port || tmp->conn->src_port == 0)) {
			return tmp;
		}
		tmp = tmp->next;
	}
	return tmp;
}

void delete_node_conn_table(struct conn_node* link) {
	link->prev->next = link->next;
	link->next->prev = link->prev;
	kfree(link); 
}

int insert_first_conn_table(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, struct tcphdr* tcp_header, state_t state) {
	struct conn_node *link = (struct conn_node*)kmalloc(sizeof(struct conn_node), GFP_ATOMIC); // Create a link
	conn_row_t *new_conn = (conn_row_t*)kmalloc(sizeof(conn_row_t), GFP_ATOMIC);
	struct timespec ts;
	if (!link || !new_conn) {
		printk("insert_first_conn_table kmalloc failed\n");
		return 0;
	}
	new_conn->src_ip = src_ip;
	new_conn->dst_ip = dst_ip;
	new_conn->src_port = src_port;
	new_conn->dst_port = dst_port;
	new_conn->res1 = tcp_header->res1;
	new_conn->doff = tcp_header->doff;
	new_conn->fin = tcp_header->fin;
	new_conn->syn = tcp_header->syn;
	new_conn->rst = tcp_header->rst;
	new_conn->psh = tcp_header->psh;
	new_conn->ack = tcp_header->ack;
	new_conn->urg = tcp_header->urg;
	new_conn->ece = tcp_header->ece;
	new_conn->cwr = tcp_header->cwr;
	new_conn->state = state;
	getnstimeofday(&ts);
	new_conn->timestamp = ts.tv_sec;
	link->conn = new_conn;
	link->next = conn_table_head; // Point it to old first node
	link->prev = NULL;
	conn_counter++;
	return 1;		
}

int insert_first(unsigned char protocol,
		unsigned char action,
		unsigned char hooknum,
		__be32 src_ip,
		__be32 dst_ip,
		__be16 src_port,
		__be16 dst_port,
		reason_t reason) {
	struct timespec ts;
	struct log_node *link = (struct log_node*)kmalloc(sizeof(struct log_node), GFP_ATOMIC); // Create a link
	log_row_t *new_log = (log_row_t*)kmalloc(sizeof(log_row_t), GFP_ATOMIC);
	if (!link || !new_log) {
		printk("insert_first kmalloc failed\n");
		return 0;
	}
	new_log->protocol = protocol;
	new_log->action = action;
	new_log->hooknum = hooknum;
	new_log->src_ip = src_ip;
	new_log->dst_ip = dst_ip;
	new_log->src_port = src_port;
	new_log->dst_port = dst_port;
	new_log->reason = reason;
	new_log->count = 1;
	getnstimeofday(&ts);
	new_log->timestamp = ts.tv_sec;
	link->log = new_log;
	link->next = log_head; // Point it to old first node
	log_head = link; // Point first to new first node
	log_counter++;
	return 1;
}

int delete_first(void) {
	struct log_node* temp_link;
	if (is_empty() == 1) {
		return 0;
	}
	temp_link = log_head; // Save reference to first link
	log_head = log_head->next; // Mark next to first link as first
	kfree(temp_link);
	log_counter--;
	return 1; // Return the deleted link
}

int write_to_log(unsigned int hooknum, reason_t reason, struct iphdr* ip_header, __be16 src_port, __be16 dst_port, unsigned int action) {
	struct timespec ts;
	struct log_node* tmp = log_head;
	while (tmp != NULL) {
		if (tmp->log->protocol == (unsigned char)ip_header->protocol &&
		    tmp->log->action == (unsigned char)action && 
		    tmp->log->hooknum == (unsigned char)hooknum &&
		    tmp->log->src_ip == ip_header->saddr &&
		    tmp->log->dst_ip == ip_header->daddr &&
		    tmp->log->src_port == src_port &&
		    tmp->log->dst_port == dst_port &&
		    tmp->log->reason == reason)  {
			tmp->log->count++;
			getnstimeofday(&ts);
			tmp->log->timestamp = ts.tv_sec;
			return 1;
		}
		tmp = tmp->next;
	}
	if (insert_first((unsigned char)ip_header->protocol,
			 (unsigned char)action,
			 (unsigned char)hooknum,
			 ip_header->saddr,
			 ip_header->daddr,
			 src_port,
			 dst_port,
			 reason) == 0) {
		printk("write_to_log insert_first failed\n");
		return 0;
	}
	return 1;
}

int destroy(int stage) {
	if (12 <= stage) {kfree(rule_default);}
	if (11 <= stage) {device_remove_file(sysfs_device_rules,	(const struct device_attribute *)&dev_attr_active.attr);}
	if (10 <= stage) {device_remove_file(sysfs_device_rules,	(const struct device_attribute *)&dev_attr_rules_size.attr);}
	if (9 <= stage) {device_remove_file(sysfs_device_log,	(const struct device_attribute *)&dev_attr_log_size.attr);}
	if (8 <= stage) {device_remove_file(sysfs_device_log,	(const struct device_attribute *)&dev_attr_log_clear.attr);}
	if (7 <= stage) {device_remove_file(sysfs_device_fw,	(const struct device_attribute *)&dev_attr_conn_tab.attr);}
	if (6 <= stage) {device_destroy(sysfs_class, MKDEV(major_number_fw, 0));}
	if (5 <= stage) {device_destroy(sysfs_class, MKDEV(major_number_rules, 0));}
	if (4 <= stage) {device_destroy(sysfs_class, MKDEV(major_number_log, 0));}
	if (3 <= stage) {class_destroy(sysfs_class);}
	if (2 <= stage) {unregister_chrdev(major_number_rules, DEVICE_NAME_RULES);}
	if (1 <= stage) {unregister_chrdev(major_number_log, DEVICE_NAME_LOG);}
	return -1;
}

module_init(my_module_init_function);
module_exit(my_module_exit_function);
