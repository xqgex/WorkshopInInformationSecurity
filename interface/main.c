#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#define PAGE_SIZE		4096
#define RULES_STRUCT_SIZE	90
#define LOG_STRUCT_SIZE		200

#define ARGS_ACTIVATE		"activate"
#define ARGS_DEACTIVATE		"deactivate"
#define ARGS_SHOW_RULES		"show_rules"
#define ARGS_CLEAR_RULES	"clear_rules"
#define ARGS_LOAD_RULES		"load_rules"
#define ARGS_SHOW_LOG		"show_log"
#define ARGS_CLEAR_LOG		"clear_log"
#define ARGS_SHOW_CONN_TABLE	"show_connection_table"

#define FILE_RULES		"/dev/fw_rules"
#define FILE_RULES_ACTIVE	"/sys/class/fw/fw_rules/active"
#define FILE_RULES_SIZE		"/sys/class/fw/fw_rules/rules_size"
#define FILE_LOG		"/dev/fw_log"
#define FILE_LOG_SIZE		"/sys/class/fw/fw_log/log_size"
#define FILE_LOG_CLEAR		"/sys/class/fw/fw_log/log_clear"
#define FILE_CONN_TABLE		"/sys/class/fw/conn_tab"

long str2long(char* input) {
	char *ptr;
	long result = strtol(input, &ptr, 10);
	if (ptr == input || *ptr != '\0' || ((result == LONG_MIN || result == LONG_MAX) && errno == ERANGE)) {
		return -1; // Underflow
	}
	return result;
}

int isValidIpAddress(char *ipAddress) {
	struct sockaddr_in sa;
	int result = inet_pton(AF_INET, ipAddress, &(sa.sin_addr));
	return result != 0;
}

unsigned int ip_to_int(char* str) {
	int a, b, c, d;
	char arr[4];
	if (sscanf(str, "%d.%d.%d.%d", &a, &b, &c, &d) == 4) {
		arr[0] = a;
		arr[1] = b;
		arr[2] = c;
		arr[3] = d;
		return *(unsigned int *)arr;
	} else {
		return 0;
	}
}

int int_to_ip(char* ip, char** final_line) {
	unsigned long ip_long = 0;
	if (sscanf(ip, "%lu", &ip_long) == 1) {
		if (ip_long == 0) {
			asprintf(final_line, "%s any", *final_line);
			return 1;
		} else {
			unsigned char bytes[4];
			bytes[0] = ip_long & 0xFF;
			bytes[1] = (ip_long >> 8) & 0xFF;
			bytes[2] = (ip_long >> 16) & 0xFF;
			bytes[3] = (ip_long >> 24) & 0xFF;
			asprintf(final_line, "%s %d.%d.%d.%d", *final_line, bytes[0], bytes[1], bytes[2], bytes[3]);
			return 0;
		}
	}
}


int valid_and_parse_line(char* line, char** final_line) {
	int space_counter = 0;
	char *end_str;
	char* pch = strtok_r(line," ",&end_str);
	long val;
	unsigned int ip;
	int prefix_size, port, direction, protocol, ack, action;
	while (pch != NULL) {
		switch (space_counter) {
			case 0: // <rule_name>
				if (strlen(pch)>20) {
					return 1;
				}
				if (asprintf(final_line, "%s%s", *final_line, pch) < 0) {
					return 1;
				}
				break;
			case 1: // <direction>
				if (strcmp("in",pch) == 0) {
					direction = 0x01;
				} else if (strcmp("out",pch) == 0) {
					direction = 0x02;
				} else if (strcmp("any",pch) == 0) {
					direction = 0x01 | 0x02;
				} else {
					return 1;
				}
				if (asprintf(final_line, "%s %d", *final_line, direction) < 0) {
					return 1;
				}
				break;
			case 2: // <Source_IP>/<nps>
			case 3: // <Dest_IP>/<nps>
				if (strcmp("any",pch) != 0) {
					char *end_token;
					char *token = strtok_r(pch, "/", &end_token);
					if (token == NULL || isValidIpAddress(token) == 0) {
						return 1;
					}
					ip = ip_to_int(token);
					token = strtok_r(NULL, "/", &end_token);
					if (token == NULL) {
						return 1;
					}
					val = str2long(token);
					if (val < 1 || val > 32) {
						return 1;
					}
					prefix_size = val;
				} else {
					ip = 0;
					prefix_size = 0;
				}
				if (asprintf(final_line, "%s %ld %d", *final_line, ip, prefix_size) < 0) {
					return 1;
				}
				break;
			case 4: // <protocol>
				if (strcmp("ICMP",pch) == 0) {
					protocol = 1;
				} else if (strcmp("TCP",pch) == 0) {
					protocol = 6;
				} else if (strcmp("UDP",pch) == 0) {
					protocol = 17;
				} else if (strcmp("any",pch) == 0) {
					protocol = 143;
				} else if (strcmp("other",pch) == 0) {
					protocol = 255;
				} else {
					return 1;
				}
				if (asprintf(final_line, "%s %d", *final_line, protocol) < 0) {
					return 1;
				}
				break;
			case 5: // <Source_port>
			case 6: // <Dest_port>
				if (strcmp("any", pch) == 0) {
					port = 0;
				} else if (strcmp(">1023",pch) == 0) {
					port = 1023;
				} else {
					val = str2long(pch);
					if (val < 0 || val > 1023) {
						return 1;
					}
					port = val;
				}
				if (asprintf(final_line, "%s %d", *final_line, port) < 0) {
					return 1;
				}
				break;
			case 7: // <ack>
				if (strcmp("no", pch) == 0) {
					ack = 0x01;
				} else if (strcmp("yes", pch) == 0) {
					ack = 0x02;
				} else if (strcmp("any", pch) == 0) {
					ack = 0x01 | 0x02;
				} else {
					return 1;
				}
				if (asprintf(final_line, "%s %d", *final_line, ack) < 0) {
					return 1;
				}
				break;
			case 8: // <action>
				if (strcmp("accept", pch) == 0 || strcmp("accept\n", pch) == 0 || strcmp("accept\r\n", pch) == 0) {
					action = 1;
				} else if (strcmp("drop", pch) == 0 || strcmp("drop\n", pch) == 0 || strcmp("drop\r\n", pch) == 0) {
					action = 0;
				} else {
					return 1;
				}
				if (asprintf(final_line, "%s %d", *final_line, action) < 0) {
					return 1;
				}
				break;
			case 9:
				return 1;
		}
		pch = strtok_r(NULL, " ", &end_str);
		space_counter++;
	}
	if (asprintf(final_line, "%s\n", *final_line) < 0) {
		return 1;
	}
	return 0;
}

int parse_rules_file(char* input_file, char** data) {
	FILE* fp;
	char* line = NULL;
	size_t len = 0;
	char* final_line = (char *)malloc(sizeof(char)*RULES_STRUCT_SIZE);
	if (!final_line) {
		printf("parse_rules_file() malloc failed\n");
		return 1;
	}
	*final_line = '\0';
	fp = fopen(input_file, "r");
	if (fp == NULL) {
		printf("parse rules_file: fopen failed\n");
		free(final_line);
		return 1;
	}
	while (getline(&line, &len, fp) != -1) {
		if (valid_and_parse_line(line, &final_line)==1) {
			printf("parse rules_file: valid_and_parse_line failed\n");
			free(final_line);
			free(line);
			return 1;
		}
		if (asprintf(data, "%s", final_line) < 0) {
			free(final_line);
			free(line);
			return 1;
		}
	}
	fclose(fp);
	if (line) {
		free(line);
	}
	free(final_line);
	return 0;
}

int write_file(char* path, char* buf, int buf_size, int permission, int do_lseek) {
	int fd = open(path, permission);
	if (fd < 0) {
	    perror("open: ");
	    return 1;
	}
	if ((do_lseek == 1) && (lseek(fd, 0, SEEK_SET) < 0)) {
		perror("lseek: ");
		return 1;
	}
	if (write(fd, buf, buf_size) < 0) {
		perror("write: ");
		return 1;
	}
	close(fd);
	return 0;
}

int read_file(char* path, char** buf, int buf_size, int permission, int do_lseek) {
	int fd = open(path, permission);
	if (fd < 0) {
		perror("open: ");
		return 1;
	}
	if ((do_lseek == 1) && (lseek(fd, 0, SEEK_SET) < 0)) {
		perror("lseek: ");
		return 1;
	}
	int readed_bytes = read(fd, *buf, buf_size);
	if (readed_bytes < 0) {
		perror("read: ");
		return 1;
	}
	close(fd);
	return 0;
}

//loopback 3 16777343 654311424 8 16777343 654311424 8 0 0 143 3 1
int parse_to_human_format_rules(char* line, char** final_line){
	int space_counter = 0;
	int ignore_mask = 0;
	char *end_str;
	char* pch = strtok_r(line," ",&end_str);
	long val;
	unsigned int ip;
	int prefix_size, port, direction, protocol, ack, action;
	while (pch != NULL) {
		switch (space_counter) {
			case 0: // <rule_name>
				if (asprintf(final_line, "%s%s", *final_line, pch) < 0) {
					return 1;
				}
				break;
			case 1: // <direction>
				if (strcmp(pch, "1") == 0) {
					if (asprintf(final_line, "%s in", *final_line) < 0) {
						return 1;
					}
				} else if (strcmp(pch, "2") == 0) {
					if (asprintf(final_line, "%s out", *final_line) < 0) {
						return 1;
					}
				} else if (strcmp(pch, "3") == 0) {
					if (asprintf(final_line, "%s any", *final_line) < 0) {
						return 1;
					}
				}
				break;
			case 2: // <Src_IP>
			case 4: // <Dest_IP>
				ignore_mask = int_to_ip(pch, final_line);
				break;
			case 3: //<nps>
			case 5: //<nps>
				if (ignore_mask == 0) {
					if (asprintf(final_line, "%s/%s", *final_line, pch) < 0) {
						return 1;
					}
				} else {
					ignore_mask = 1;
				}
				break;	
			case 6: //protocol
				if (strcmp(pch, "1") == 0) {
					if (asprintf(final_line, "%s ICMP", *final_line) < 0) {
						return 1;
					}
				} else if (strcmp(pch, "6") == 0) {
					if (asprintf(final_line, "%s TCP", *final_line) < 0) {
						return 1;
					}
				} else if (strcmp(pch, "17") == 0) {
					if (asprintf(final_line, "%s UDP", *final_line) < 0) {
						return 1;
					}
				} else if (strcmp(pch, "255") == 0) {
					if (asprintf(final_line, "%s OTHER", *final_line) < 0) {
						return 1;
					}
				} else if (strcmp(pch, "143") == 0) {
					if (asprintf(final_line, "%s any", *final_line) < 0) {
						return 1;
					}
				}
				break;
			case 7: // <Source_port>
			case 8: // <Dest_port>
				if (strcmp(pch, "0") == 0) {
					if (asprintf(final_line, "%s any", *final_line) < 0) {
						return 1;
					}
				} else if (strcmp(pch, "1023") == 0) {
					if (asprintf(final_line, "%s >1023", *final_line) < 0) {
						return 1;
					}
				} else {
					if (asprintf(final_line, "%s %s", *final_line, pch) < 0) {
						return 1;
					}
				}
				break;
			case 9: // <ack>
				if (strcmp(pch, "1") == 0) {
					if (asprintf(final_line, "%s no", *final_line) < 0) {
						return 1;
					}
				} else if (strcmp(pch, "2") == 0) {
					if (asprintf(final_line, "%s yes", *final_line) < 0) {
						return 1;
					}
				} else {
					if (asprintf(final_line, "%s any", *final_line) < 0) {
						return 1;
					}
				}
				break;
			case 10: // <action>
				if (strcmp(pch, "0") == 0) {
					if (asprintf(final_line, "%s drop", *final_line) < 0) {
						return 1;
					}
				} else if (strcmp(pch, "1") == 0) {
					if (asprintf(final_line, "%s accept", *final_line) < 0) {
						return 1;
					}
				}
				break;
			case 11:
				return 1;
		}
		pch = strtok_r(NULL, " ", &end_str);
		space_counter++;
	}
	if (asprintf(final_line, "%s\n", *final_line) < 0) {
		return 1;
	}
	return 0;
}

//timestamp: 1543590916, protocol: 6, action: 0, hooknum: 0, src_ip: 425639259, dst_ip: 251789322, src_port: 69, dst_port: 11264, reason: -4, count: 2
int parse_to_human_format_log(char* line, char** final_line){
	int space_counter = 0;
	int ignore_mask = 0;
	char *end_str;
	char* pch = strtok_r(line," ",&end_str);
	long val;
	unsigned int ip;
	int prefix_size, port, direction, protocol, ack, action;
	while (pch != NULL) {
		switch (space_counter) {
			case 9: // <Src_IP>
			case 11: // <Dest_IP>
				pch[strlen(pch)-1] = '\0';
				ignore_mask = int_to_ip(pch, final_line);
				break;
			case 3: //protocol
				if (strcmp(pch, "1,") == 0) {
					if (asprintf(final_line, "%s ICMP", *final_line) < 0) {
						return 1;
					}
				} else if (strcmp(pch, "6,") == 0) {
					if (asprintf(final_line, "%s TCP", *final_line) < 0) {
						return 1;
					}
				} else if (strcmp(pch, "17,") == 0) {
					if (asprintf(final_line, "%s UDP", *final_line) < 0) {
						return 1;
					}
				} else if (strcmp(pch, "255,") == 0) {
					if (asprintf(final_line, "%s OTHER", *final_line) < 0) {
						return 1;
					}
				} else if (strcmp(pch, "143,") == 0) {
					if (asprintf(final_line, "%s any", *final_line) < 0) {
						return 1;
					}
				}
				break;
			case 5: // <action>
				if (strcmp(pch, "0,") == 0) {
					if (asprintf(final_line, "%s drop", *final_line) < 0) {
						return 1;
					}
				} else if (strcmp(pch, "1,") == 0) {
					if (asprintf(final_line, "%s accept", *final_line) < 0) {
						return 1;
					}
				}
				break;
			case 17: // <reason>
				if (strcmp(pch, "-1,") == 0) {
					if (asprintf(final_line, "%s FW_INACTIVE", *final_line) < 0) {
						return 1;
					}
				} else if (strcmp(pch, "-2,") == 0) {
					if (asprintf(final_line, "%s NO_MATCHING_RULE", *final_line) < 0) {
						return 1;
					}
				} else if (strcmp(pch, "-4,") == 0) {
					if (asprintf(final_line, "%s XMAS_PACKET", *final_line) < 0) {
						return 1;
					}
				} else if (strcmp(pch, "-6,") == 0) {
					if (asprintf(final_line, "%s ILLEGAL_VALUE", *final_line) < 0) {
						return 1;
					}
				} else {
					if (asprintf(final_line, "%s RULE_%s\n", *final_line, pch) < 0) {
						return 1;
					}
				}
				break;
			default: 
				if (asprintf(final_line, "%s %s", *final_line, pch) < 0) {
					return 1;
				}
		}
		pch = strtok_r(NULL, " ", &end_str);
		space_counter++;
	}
	if (asprintf(final_line, "%s\n", *final_line) < 0) {
		return 1;
	}
	return 0;
}


int main(int argc, char **argv) {
	if (argc==2) {
		if (strcmp(argv[1],ARGS_ACTIVATE)==0) {
			return write_file(FILE_RULES_ACTIVE, "1", 1, O_RDWR, 1);
		} else if (strcmp(argv[1],ARGS_DEACTIVATE)==0) {
			return write_file(FILE_RULES_ACTIVE, "0", 1, O_RDWR, 1);
		} else if (strcmp(argv[1],ARGS_SHOW_RULES)==0) {
			char* size_str = malloc(PAGE_SIZE * sizeof(char));
			if (!size_str) {
				printf("malloc failed\n");
			}
			*size_str = '\0';
			if (read_file(FILE_RULES_SIZE, &size_str, PAGE_SIZE, O_RDONLY, 1) == 1) {
				free(size_str);
				return 1;
			}
			long size_long = str2long(size_str);
			free(size_str);
			if (size_long < 0 || size_long > 50) {
				printf("invalid log size - %ld", size_long);
				return 1;
			}
			char* rules = malloc(size_long * RULES_STRUCT_SIZE * sizeof(char));
			if (!rules) {
				printf("malloc failed\n");
				return 1;
			}
			*rules = '\0';
			if (read_file(FILE_RULES, &rules, size_long*RULES_STRUCT_SIZE, O_RDWR, 0) == 1) {
				free(rules);
				return 1;
			}
			char* final_rules = malloc(size_long * RULES_STRUCT_SIZE * sizeof(char));
			*final_rules = '\0';
			char* end_str;
			char* pch = strtok_r(rules,"\n",&end_str);
			while (pch != NULL) {
				if (parse_to_human_format_rules(pch, &final_rules) == 1){
					printf("parsing error\n");
					return 1;
				}
				pch = strtok_r(NULL, "\n", &end_str);
			}
			printf("%s", final_rules);
			free(rules);
		} else if (strcmp(argv[1],ARGS_CLEAR_RULES)==0) {
			return write_file(FILE_RULES, "", 0, O_RDWR, 0);
		} else if (strcmp(argv[1],ARGS_SHOW_LOG)==0) {
			char* size_str = malloc(PAGE_SIZE * sizeof(char));
			if (!size_str) {
				printf("malloc failed\n");
				return 1;
			}
			*size_str = '\0';
			if (read_file(FILE_LOG_SIZE, &size_str, PAGE_SIZE, O_RDONLY, 1) == 1) {
				free(size_str);
				return 1;
			}
			long size_long = str2long(size_str);
			free(size_str);
			if (size_long <= 0) {
				return 1;
			}
			char* log = malloc(size_long * LOG_STRUCT_SIZE * sizeof(char));
			if (!log) {
				printf("malloc failed\n");
				return 1;
			}
			*log = '\0';
			if (read_file(FILE_LOG, &log, size_long*LOG_STRUCT_SIZE, O_RDONLY, 0) == 1) {
				free(log);
				return 1;
			}
			char* final_log = malloc(size_long * LOG_STRUCT_SIZE * sizeof(char));
			*final_log = '\0';
			char* end_str;
			char* pch = strtok_r(log,"\n",&end_str);
			while (pch != NULL) {
				if (parse_to_human_format_log(pch, &final_log) == 1){
					printf("parsing error\n");
					return 1;
				}
				pch = strtok_r(NULL, "\n", &end_str);
			}
			printf("%s", final_log);
			free(log);
		} else if (strcmp(argv[1],ARGS_CLEAR_LOG)==0) {
			return write_file(FILE_LOG_CLEAR, "c", 1, O_WRONLY, 1);
		} else if (strcmp(argv[1],ARGS_SHOW_CONN_TABLE)==0) {
			char* conn_table = malloc(PAGE_SIZE * sizeof(char));
			if (read_file(FILE_CONN_TABLE, &conn_table, PAGE_SIZE, O_RDONLY, 1) == 1) {
				free(conn_table);
				return 1;
			}
			printf("%s" , conn_table);
			free(conn_table);
		} else {
			printf("Invalid call\n");
		}
	} else if (argc==3 && strcmp(argv[1], ARGS_LOAD_RULES)==0) {
		int data_size = 0;
		char* data;
		if (parse_rules_file(argv[2], &data)==1) {
			printf("load rules: parse_rules_file failed \n");
			return 1;
		}
		write_file(FILE_RULES, data, strlen(data), O_RDWR, 0);
	} else {
		printf("Invalid call\n");
	}
}

