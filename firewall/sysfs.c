#include "sysfs.h"

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
	for (i=0; i<rules_counter; i++) {
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
