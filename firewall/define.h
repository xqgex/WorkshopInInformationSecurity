#ifndef DEFINES_H_
#define DEFINES_H_

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/uaccess.h>
#include <linux/time.h>

#define MAX_RULES_LENGTH		90
#define MAX_LOG_LENGTH			200
#define DEVICE_NAME_RULES		"rules"
#define DEVICE_NAME_LOG			"log"
#define DEVICE_NAME_CONN_TAB		"conn_tab"
#define CLASS_NAME			"fw"
#define LOOPBACK_NET_DEVICE_NAME	"lo"
#define IN_NET_DEVICE_NAME		"eth1"
#define OUT_NET_DEVICE_NAME		"eth2"
#define IP_VERSION			(4)
#define PORT_ANY			(0)
#define PORT_ABOVE_1023			(1023)
#define MAX_RULES			(50)

/*******************************************************************/
/****	typedef enum						****/
/*******************************************************************/
typedef enum { // the protocols we will work with
	PROT_ICMP	= 1,
	PROT_TCP	= 6,
	PROT_UDP	= 17,
	PROT_OTHER	= 255,
	PROT_ANY	= 143,
} prot_t;
typedef enum { // various reasons to be registered in each log entry
	REASON_FW_INACTIVE	= -1,
	REASON_NO_MATCHING_RULE	= -2,
	REASON_XMAS_PACKET	= -4,
	REASON_ILLEGAL_VALUE	= -6,
} reason_t;
typedef enum { // device minor numbers, for your convenience
	MINOR_RULES	= 0,
	MINOR_LOG	= 1,
} minor_t;
typedef enum {
	ACK_NO		= 0x01,
	ACK_YES		= 0x02,
	ACK_ANY		= ACK_NO | ACK_YES,
} ack_t;
typedef enum {
	DIRECTION_IN	= 0x01,
	DIRECTION_OUT	= 0x02,
	DIRECTION_ANY	= DIRECTION_IN | DIRECTION_OUT,
} direction_t;

/*******************************************************************/
/****	typedef enum						****/
/*******************************************************************/
typedef struct { // rule base
	char rule_name[20];			// names will be no longer than 20 chars
	direction_t direction;
	__be32	src_ip;
	__be32	src_prefix_mask;		// e.g., 255.255.255.0 as int in the local endianness
	__u8	src_prefix_size;		// valid values: 0-32, e.g., /24 for the example above (the field is redundant - easier to print)
	__be32	dst_ip;
	__be32	dst_prefix_mask;		// as above
	__u8	dst_prefix_size;		// as above	
	__be16	src_port;			// number of port or 0 for any or port 1023 for any port number > 1023
	__be16	dst_port;			// number of port or 0 for any or port 1023 for any port number > 1023 
	__u8	protocol;			// values from: prot_t
	ack_t	ack;				// values from: ack_t
	__u8	action;				// valid values: NF_ACCEPT, NF_DROP
} rule_t;
typedef struct { // logging
	unsigned long		timestamp;	// time of creation/update
	unsigned char		protocol;	// values from: prot_t
	unsigned char		action;		// valid values: NF_ACCEPT, NF_DROP
	unsigned char		hooknum;	// as received from netfilter hook
	__be32			src_ip;		// if you use this struct in userspace, change the type to unsigned int
	__be32			dst_ip;		// if you use this struct in userspace, change the type to unsigned int
	__be16			src_port;	// if you use this struct in userspace, change the type to unsigned short
	__be16			dst_port;	// if you use this struct in userspace, change the type to unsigned short
	reason_t		reason;		// rule#index, or values from: reason_t
	unsigned int		count;		// counts this line's hits
	struct list_head list; /* kernel's list structure */
} log_row_t;
struct log_node {
	log_row_t* log;
	struct log_node *next;
};

//**********************************************************
//****	Module Variables				****
//**********************************************************
static int major_number_rules;
static int major_number_log;
static int active = 1;
static int rules_counter = 0;
static unsigned long log_counter = 0;
static rule_t* rules_array[MAX_RULES];
static rule_t* rule_default;
static struct class* sysfs_class = NULL;
static struct device* sysfs_device_rules = NULL;
static struct device* sysfs_device_log = NULL;
static struct log_node* log_head = NULL;
static struct nf_hook_ops nfho; // Main hook function

#endif /* DEFINES_H_ */
