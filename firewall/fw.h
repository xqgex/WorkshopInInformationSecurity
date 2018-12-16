#ifndef _FW_H_
#define _FW_H_

#include "define.h"
#include "sysfs.h"

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
static int __init my_module_init_function(void);
static void __exit my_module_exit_function(void);
int is_empty(void);
int insert_first(unsigned char, unsigned char, unsigned char, __be32, __be32, __be16, __be16, reason_t);
int delete_first(void);
int write_to_log(unsigned int hooknum, reason_t reason, struct iphdr* ip_header, __be16 src_port, __be16 dst_port, unsigned int action);

#endif // _FW_H_
