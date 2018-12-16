#include "fw.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ilor Ifrach");

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
	__u16 fin = 0; //fin flag in tcp
	__u16 urg = 0; //urg flag in tcp
	__u16 psh = 0; //psh flag in tcp
	int res = 0;
	int i = 0;
	unsigned int action = NF_DROP;
	unsigned int found_match_rule = 0;
	ip_header = (struct iphdr *)skb_network_header(skb);
	if (ip_header->protocol == IPPROTO_TCP) { // Transmission Control Protocol, IPPROTO_TCP = 6
		tcp_header = tcp_hdr(skb);
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
	}
	if (active == 0) {
		action = NF_ACCEPT;
		reason = REASON_FW_INACTIVE;
	} else {
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
			for (i=0; i<rules_counter; i++) {
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
	}
	if (write_to_log(hooknum, reason, ip_header, src_port, dst_port, action) == 0) {
		printk("hook_func write_to_log failed\n");
		return NF_DROP;
	}
	return action;
}

void delete_rules_array(void) {
	int i;
	for (i=0; i<rules_counter; i++) {
		if (rules_array[i] != NULL) {
			kfree(rules_array[i]);
		}
	}
	rules_counter = 0;
}

static int __init my_module_init_function(void) {
	nfho.hook = hook_func; // Function to call when conditions below met
	nfho.hooknum = NF_INET_PRE_ROUTING;//NF_INET_FORWARD;
	nfho.pf = PF_INET; // IPV4 packets
	nfho.priority = NF_IP_PRI_FIRST; // Set to highest priority over all other hook functions
	nf_register_hook(&nfho); // Register hook
	// Create char device
	major_number_rules = register_chrdev(0, DEVICE_NAME_RULES, &fops_rules);
	if (major_number_rules < 0) {
		return -1;
	}
	major_number_log = register_chrdev(0, DEVICE_NAME_LOG, &fops_log);
	if (major_number_log < 0) {
		return -1;
	}
	// Create sysfs class
	sysfs_class = class_create(THIS_MODULE, CLASS_NAME);
	if (IS_ERR(sysfs_class)) {
		unregister_chrdev(major_number_rules, DEVICE_NAME_RULES);
		unregister_chrdev(major_number_log, DEVICE_NAME_LOG);
		return -1;
	}
	// Create sysfs device
	sysfs_device_rules = device_create(sysfs_class, NULL, MKDEV(major_number_rules, 0), NULL, CLASS_NAME "_" DEVICE_NAME_RULES);
	if (IS_ERR(sysfs_device_rules)) {
		class_destroy(sysfs_class);
		unregister_chrdev(major_number_rules, DEVICE_NAME_RULES);
		unregister_chrdev(major_number_log, DEVICE_NAME_LOG);
		return -1;
	}
	sysfs_device_log = device_create(sysfs_class, NULL, MKDEV(major_number_log, 0), NULL, CLASS_NAME "_" DEVICE_NAME_LOG);
	if (IS_ERR(sysfs_device_log)) {
		class_destroy(sysfs_class);
		unregister_chrdev(major_number_rules, DEVICE_NAME_RULES);
		unregister_chrdev(major_number_log, DEVICE_NAME_LOG);
		return -1;
	}
	// Create sysfs file attributes	
	if (device_create_file(sysfs_device_rules, (const struct device_attribute *)&dev_attr_active.attr)) {
		device_destroy(sysfs_class, MKDEV(major_number_rules, 0));
		device_destroy(sysfs_class, MKDEV(major_number_log, 0));
		class_destroy(sysfs_class);
		unregister_chrdev(major_number_rules, DEVICE_NAME_RULES);
		unregister_chrdev(major_number_log, DEVICE_NAME_LOG);
		return -1;
	}
	if (device_create_file(sysfs_device_rules, (const struct device_attribute *)&dev_attr_rules_size.attr)) {
		device_remove_file(sysfs_device_rules, (const struct device_attribute *)&dev_attr_active.attr);
		device_destroy(sysfs_class, MKDEV(major_number_rules, 0));
		device_destroy(sysfs_class, MKDEV(major_number_log, 0));
		class_destroy(sysfs_class);
		unregister_chrdev(major_number_rules, DEVICE_NAME_RULES);
		unregister_chrdev(major_number_log, DEVICE_NAME_LOG);
		return -1;
	}
	if (device_create_file(sysfs_device_log, (const struct device_attribute *)&dev_attr_log_size.attr)) {
		device_remove_file(sysfs_device_rules, (const struct device_attribute *)&dev_attr_active.attr);
		device_remove_file(sysfs_device_rules, (const struct device_attribute *)&dev_attr_rules_size.attr);
		device_destroy(sysfs_class, MKDEV(major_number_rules, 0));
		device_destroy(sysfs_class, MKDEV(major_number_log, 0));
		class_destroy(sysfs_class);
		unregister_chrdev(major_number_rules, DEVICE_NAME_RULES);
		unregister_chrdev(major_number_log, DEVICE_NAME_LOG);
		return -1;
	}
	if (device_create_file(sysfs_device_log, (const struct device_attribute *)&dev_attr_log_clear.attr)) {
		device_remove_file(sysfs_device_rules, (const struct device_attribute *)&dev_attr_active.attr);
		device_remove_file(sysfs_device_rules, (const struct device_attribute *)&dev_attr_rules_size.attr);
		device_remove_file(sysfs_device_log, (const struct device_attribute *)&dev_attr_log_size.attr);
		device_destroy(sysfs_class, MKDEV(major_number_rules, 0));
		device_destroy(sysfs_class, MKDEV(major_number_log, 0));
		class_destroy(sysfs_class);
		unregister_chrdev(major_number_rules, DEVICE_NAME_RULES);
		unregister_chrdev(major_number_log, DEVICE_NAME_LOG);
		return -1;
	}
	rule_default = (rule_t*)kmalloc(sizeof(rule_t), GFP_ATOMIC);
	if (!rule_default) {
		printk("rule_default kmalloc failed\n");
		return -1;
	}
	init_default_rule();
	return 0; // If non-0 return means init_module failed
}

static void __exit my_module_exit_function(void) {
	nf_unregister_hook(&nfho);
	device_remove_file(sysfs_device_rules,	(const struct device_attribute *)&dev_attr_active.attr);
	device_remove_file(sysfs_device_rules,	(const struct device_attribute *)&dev_attr_rules_size.attr);
	device_remove_file(sysfs_device_log,	(const struct device_attribute *)&dev_attr_log_size.attr);
	device_remove_file(sysfs_device_log,	(const struct device_attribute *)&dev_attr_log_clear.attr);
	device_destroy(sysfs_class, MKDEV(major_number_rules, 0));
	device_destroy(sysfs_class, MKDEV(major_number_log, 0));
	class_destroy(sysfs_class);
	unregister_chrdev(major_number_rules, DEVICE_NAME_RULES);
	unregister_chrdev(major_number_log, DEVICE_NAME_LOG);
}

int is_empty(void) {
	if (log_head == NULL) {
		return 1;
	}
	return 0;
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

module_init(my_module_init_function);
module_exit(my_module_exit_function);
