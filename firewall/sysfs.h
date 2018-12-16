#ifndef _SYSFS_H_
#define _SYSFS_H_

#include "define.h"

//**********************************************************
//****	Function Declaration				****
//**********************************************************
static ssize_t rules_read(struct file *, char *, size_t, loff_t *);
static ssize_t rules_write(struct file *, const char *, size_t, loff_t *);
static ssize_t log_read(struct file *, char *, size_t, loff_t *);
ssize_t active_display(struct device *, struct device_attribute *, char *);
ssize_t active_modify(struct device *, struct device_attribute *, const char *, size_t);
ssize_t rules_size_display(struct device *, struct device_attribute *, char *);
ssize_t log_size_display(struct device *, struct device_attribute *, char *);
ssize_t log_clear_modify(struct device *, struct device_attribute *, const char *, size_t);

//**********************************************************
//****	Module Variables				****
//**********************************************************
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

#endif // _SYSFS_H_
