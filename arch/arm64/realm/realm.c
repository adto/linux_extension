// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2022 - experimental arm64 realm module
 * Author: Adam Toth <tothadamster@gmail.com>
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kdev_t.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/slab.h> //kmalloc()
#include <linux/uaccess.h> //copy_to/from_user()
#include <linux/ioctl.h>
#include <linux/sched.h> //get current as current process

#define REALM_MAJOR 1
#define REALM_MINOR 1
#define STR_INDIR(x) #x
#define STR(x) STR_INDIR(x)
#define REALM_VERSION STR(REALM_MAJOR.REALM_MINOR)
#define WR_VALUE _IOW(REALM_MINOR,'a',int32_t*)
#define RD_VALUE _IOR(REALM_MINOR,'b',int32_t*)
#define ENTER_REALM _IO(REALM_MINOR,'c')
#define EXIT_REALM _IO(REALM_MINOR,'d')

int32_t value = 0;
dev_t dev = 0;
static struct class *dev_class;
static struct cdev realm_cdev;
/*
** Function Prototypes
*/
static int      __init realm_init(void);
static void     __exit realm_exit(void);
static int      realm_open(struct inode *inode, struct file *file);
static int      realm_release(struct inode *inode, struct file *file);
static ssize_t  realm_read(struct file *filp, char __user *buf, size_t len,loff_t * off);
static ssize_t  realm_write(struct file *filp, const char *buf, size_t len, loff_t * off);
static long     realm_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
/*
** File operation sturcture
*/
static struct file_operations fops =
{
        .owner          = THIS_MODULE,
        .read           = realm_read,
        .write          = realm_write,
        .open           = realm_open,
        .unlocked_ioctl = realm_ioctl,
        .release        = realm_release,
};
/*
** This function will be called when we open the realm file
*/
static int realm_open(struct inode *inode, struct file *file)
{
        pr_info("Device file of realm is opened.\n");
        return 0;
}
/*
** This function will be called when we close the realm file
*/
static int realm_release(struct inode *inode, struct file *file)
{
        pr_info("Device file of realm is closed.\n");
        return 0;
}
/*
** This function will be called when we read the realm file
*/
static ssize_t realm_read(struct file *filp, char __user *buf, size_t len, loff_t *off)
{
        pr_info("Read function of realm is called.\n");
        return 0;
}
/*
** This function will be called when we write the Device file
*/
static ssize_t realm_write(struct file *filp, const char __user *buf, size_t len, loff_t *off)
{
        pr_info("Write function of realm is called.\n");
        return len;
}
/*
** This function will be called when we write IOCTL on the Device file
*/
static long realm_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
         switch(cmd) {
         	 	case ENTER_REALM:
         	 		pr_info("All hope abandon ye who enter the Realm here!\n");

         	 		pr_info("The process is \"%s\" (pid %i)\n", current->comm, current->pid);


					break;

         	 	case EXIT_REALM:
         	 		pr_info("Exit the realm.\n");
					break;

                case WR_VALUE:
					if( copy_from_user(&value ,(int32_t*) arg, sizeof(value)) )
					{
							pr_err("Data Write : Err!\n");
					}
					pr_info("Value = %d\n", value);
					break;

                case RD_VALUE:
					if( copy_to_user((int32_t*) arg, &value, sizeof(value)) )
					{
							pr_err("Data Read : Err!\n");
					}
					break;

                default:
					pr_info("Default\n");
					break;
        }
        return 0;
}

/*
** Module Init function
*/
static int __init realm_init(void)
{
        /*Allocating Major number*/
        if((alloc_chrdev_region(&dev, REALM_MAJOR, REALM_MINOR, "realm")) <0){
                pr_err("Cannot allocate major number\n");
                return -1;
        }
        pr_info("Major = %d Minor = %d \n",MAJOR(dev), MINOR(dev));

        /*Creating cdev structure*/
        cdev_init(&realm_cdev,&fops);

        /*Adding character device to the system*/
        if((cdev_add(&realm_cdev,dev,1)) < 0){
            pr_err("Cannot add the device to the system\n");
            goto r_class;
        }

        /*Creating struct class*/
        if((dev_class = class_create(THIS_MODULE,"realm_class")) == NULL){
            pr_err("Cannot create the struct class\n");
            goto r_class;
        }

        /*Creating device*/
        if((device_create(dev_class,NULL,dev,NULL,"realm")) == NULL){
            pr_err("Cannot create the Device 1\n");
            goto r_device;
        }
        pr_info("Device Driver Insert...Done!!!\n");
        return 0;

r_device:
        class_destroy(dev_class);
r_class:
        unregister_chrdev_region(dev,1);
        return -1;
}
/*
** Module exit function
*/
static void __exit realm_exit(void)
{
        device_destroy(dev_class,dev);
        class_destroy(dev_class);
        cdev_del(&realm_cdev);
        unregister_chrdev_region(dev, 1);
        pr_info("Removal of realm is done.\n");
}

module_init(realm_init);
module_exit(realm_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Adam Toth <tothadamster@gmail.com>");
MODULE_DESCRIPTION("Experimental arm64 realm module");
MODULE_VERSION(REALM_VERSION);
