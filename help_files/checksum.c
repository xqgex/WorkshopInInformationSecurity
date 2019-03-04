unsigned int hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)) {
	struct iphdr *ip_header;
	struct tcphdr *tcp_header;
	int tcplen;
	if (!skb) {
		return NF_ACCEPT;
	}
	ip_header = (struct iphdr *)skb_network_header(skb);
	if (!ip_header) {
		return NF_ACCEPT;
	}
	if (ip_header->protocol != 6) { //non TCP packet
		return NF_ACCEPT;
	}
	tcp_header = (struct tcphdr *)(skb_transport_header(skb)+20); //for incoming packets use +20
	if (!tcp_header)
		return NF_ACCEPT;
	if (tcp_header->dest == htons(80)) {
		//changing of routing
		ip_header->daddr = <my_ip>; //change to yours IP
		tcp_header->dest = <my_port>; //change to yours listening port
		//here start the fix of checksum for both IP and TCP
		tcplen = (skb->len - ((ip_header->ihl )<< 2));
		tcp_header->check=0;
		tcp_header->check = tcp_v4_check(tcplen, ip_header->saddr, ip_header->daddr,csum_partial((char*)tcp_header, tcplen,0));
		skb->ip_summed = CHECKSUM_NONE; //stop offloading
		ip_header->check = 0;
		ip_header->check = ip_fast_csum((u8 *)ip_header, ip_header->ihl);
		return NF_ACCEPT;
	} else {
		return NF_ACCEPT;
	}
}
