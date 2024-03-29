#ifndef _FW_H_
#define _FW_H_

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
#include <net/tcp.h>

#define MAX_RULES_LENGTH		90
#define MAX_LOG_LENGTH			200
#define MAX_CONN_LENGTH			200
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
#define PROXY_IP			213070643
#define PROXY_PORT			54321

/*******************************************************************/
/****	typedef enum						****/
/*******************************************************************/
typedef enum {
	STATE_START_1		= 1,
	STATE_START_2		= 2,
	STATE_START_3		= 3,
	STATE_DATA		= 9,
	STATE_CLOSE_1		=11,
	STATE_CLOSE_2		=12,
	STATE_CLOSE_3		=13,
	STATE_CLOSE_4		=14,
} state_t;
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
	REASON_ACCEPTED_BY_PROXY= -7,
	REASON_SENT_TO_PROXY	= -8,
	REASON_HANDSHAKE_MATCH	= -9,
	REASON_HANDSHAKE_TIMEOUT= -10,
	REASON_HANDSHAKE_FAILED	= -11,
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
/****	typedef struct						****/
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
	struct list_head list;			// kernel's list structure
} log_row_t;
typedef struct { // conn_table
	__be32			src_ip;			// if you use this struct in userspace, change the type to unsigned int
	__be32			dst_ip;			// if you use this struct in userspace, change the type to unsigned int
	__be16			src_port;		// if you use this struct in userspace, change the type to unsigned short
	__be16			dst_port;		// if you use this struct in userspace, change the type to unsigned short
	__u16			res1:4, doff:4, fin:1, syn:1, rst:1, psh:1, ack:1, urg:1, ece:1, cwr:1;
	state_t			state;
	unsigned long 		timestamp
} conn_row_t;
struct log_node {
	log_row_t* log;
	struct log_node *next;
};
struct conn_node {
	conn_row_t* conn;
	struct conn_node *next;
	struct conn_node *prev;
};

#endif // _FW_H_
