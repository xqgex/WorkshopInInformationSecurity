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

#endif // _SYSFS_H_
