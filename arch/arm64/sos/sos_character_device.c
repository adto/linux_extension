// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2022 - experimental arm64 sos module
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
#include <linux/arm-smccc.h> //for HVC/SMC function call
#include <asm/sos_asm.h>
#include "sos_character_device.h"


#define SOS_MAJOR 1
#define SOS_MINOR 1
#define STR_INDIR(x) #x
#define STR(x) STR_INDIR(x)
#define SOS_VERSION STR(SOS_MAJOR.SOS_MINOR)
#define WR_VALUE _IOW(SOS_MINOR,'a',int32_t*) //obsolete
#define RD_VALUE _IOR(SOS_MINOR,'b',int32_t*) //obsolete
#define ENTER_SOS _IO(SOS_MINOR,'c') //obsolete
#define EXIT_SOS _IO(SOS_MINOR,'d') //obsolete
#define SERVICE_SOS _IO(SOS_MINOR,'e')
#define INIT_SOS _IO(SOS_MINOR,'f') //obsolete

#define GENERIC_ERROR -1

//define SOS specific services
#define SOS_INIT_HYP 0x01u
#define SOS_ENTER 0x02u
#define SOS_EXIT 0x03u
#define SOS_GET_STATUS 0x04u
#define SOS_RESET_HYP 0xFFu


int32_t value = 0;
dev_t dev = 0;
static struct class *dev_class;
static struct cdev sos_cdev;
/*
** Function definitions
*/
static int      __init sos_init(void);
static void     __exit sos_exit(void);
static int      sos_open(struct inode *inode, struct file *file);
static int      sos_release(struct inode *inode, struct file *file);
static ssize_t  sos_read(struct file *filp, char __user *buf, size_t len,loff_t * off);
static ssize_t  sos_write(struct file *filp, const char *buf, size_t len, loff_t * off);
static long     sos_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
static int      hvc_start(unsigned long func_id);
static void     sos_init_hyp(void);

/*
** File operation structure
*/
static struct file_operations fops =
{
        .owner          = THIS_MODULE,
        .read           = sos_read,
        .write          = sos_write,
        .open           = sos_open,
        .unlocked_ioctl = sos_ioctl,
        .release        = sos_release,
};

/*
** This function is used to start synchronous HVC function call
*/
static int hvc_start(unsigned long func_id)
{
	struct arm_smccc_res res;

	arm_smccc_hvc(func_id, 0, 0, 0, 0, 0, 0, 0, &res);
	if (res.a0 != 0) {
		sos_info("hvc_start() returns res.a0 = 0x%lx\n", res.a0);
		return GENERIC_ERROR;
	}

	return 0;
}

/*
** This function will be called when we open the sos file
*/
static int sos_open(struct inode *inode, struct file *file)
{
        sos_info("Device file of sos is opened.\n");
        return 0;
}

/*
** This function will be called when we close the sos file
*/
static int sos_release(struct inode *inode, struct file *file)
{
        sos_info("Device file of sos is closed.\n");
        return 0;
}

/*
** This function will be called when we read the sos file
*/
static ssize_t sos_read(struct file *filp, char __user *buf, size_t len, loff_t *off)
{
        sos_info("Read function of sos is called.\n");
        return 0;
}

/*
** This function will be called when we write the Device file
*/
static ssize_t sos_write(struct file *filp, const char __user *buf, size_t len, loff_t *off)
{
        sos_info("Write function of sos is called.\n");
        return len;
}

__attribute__ ((__noinline__))
void * get_pc (void) { return __builtin_return_address(0); }

/* Do hypervisor init. */
static void sos_init_hyp(void) {

	int r;

	r = sos_arch_init(NULL);
	if (r)
		goto out_fail;

	//adto TBD


out_fail:
	return;

}

/* This function will be called when we write IOCTL on the Device file. */
static long sos_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	unsigned int service_id;

	switch(cmd) {
		case SERVICE_SOS:
			service_id = *((unsigned int*)arg);
			switch(service_id) {
				case SOS_INIT_HYP:
					sos_info("Service the sos: SOS_INIT_HYP\n");
					break;

				case SOS_ENTER:
					sos_info("Service the sos: SOS_ENTER\n");
					break;

				case SOS_EXIT:
					sos_info("Service the sos: SOS_EXIT\n");
					break;

				case SOS_GET_STATUS:
					sos_info("Service the sos: SOS_GET_STATUS\n");
					break;

				case SOS_RESET_HYP:
					sos_info("Service the sos: SOS_RESET_HYP\n");
					break;

				default:
					sos_info("Unknown service, do nothing!\n");
					break;
			}
			break;

		default:
			sos_info("Default\n");
			break;
	}
	return 0;
}

			//This is HVC call
			//(void)hvc_start(1);

			/*end of test area*/
			//break;

//	 case INIT_SOS:
//			sos_info("Init the sos: \n", arg);
//
//			//This is HVC call
//			//(void)hvc_start(1);
//
//			/*end of test area*/
//			break;


//		case ENTER_SOS:
//			sos_info("All hope abandon ye who enter the SOS here!\n");
//
//			/*test area*/
//			//uint64_t foo;
//			//asm volatile ("mov %0, lr" : "=r"(foo) ::);
//			//sos_info("%lx\n", foo);
//
//			//uint64_t function_address = (uint64_t) sos_ioctl;
//			//sos_info("%lx\n", function_address);
//
//			//sos_info("%lx\n", get_pc());
//
//			//sos_info("The process is \"%s\" (pid %i)\n", current->comm, current->pid);
//
//			//This is HVC call
//			//(void)hvc_start(1);
//
//			/*end of test area*/
//			break;

//		case EXIT_SOS:
//			sos_info("Exit the sos.\n");
//			break;

//		case WR_VALUE:
//			if( copy_from_user(&value ,(int32_t*) arg, sizeof(value)) )
//			{
//					pr_err("Data Write : Err!\n");
//			}
//			sos_info("Value = %d\n", value);
//			break;

//		case RD_VALUE:
//			if( copy_to_user((int32_t*) arg, &value, sizeof(value)) )
//			{
//					pr_err("Data Read : Err!\n");
//			}
//			break;


//	}
//	return 0;
//}

/*
** Module Init function
*/
static int __init sos_init(void)
{
        /*Allocating Major number*/
        if((alloc_chrdev_region(&dev, SOS_MAJOR, SOS_MINOR, "sos")) <0){
                pr_err("Cannot allocate major number\n");
                return -1;
        }
        sos_info("Major = %d Minor = %d \n",MAJOR(dev), MINOR(dev));

        /*Creating cdev structure*/
        cdev_init(&sos_cdev,&fops);

        /*Adding character device to the system*/
        if((cdev_add(&sos_cdev,dev,1)) < 0){
            pr_err("Cannot add the device to the system\n");
            goto r_class;
        }

        /*Creating struct class*/
        if((dev_class = class_create(THIS_MODULE,"sos_class")) == NULL){
            pr_err("Cannot create the struct class\n");
            goto r_class;
        }

        /*Creating device*/
        if((device_create(dev_class,NULL,dev,NULL,"sos")) == NULL){
            pr_err("Cannot create the Device 1\n");
            goto r_device;
        }
        sos_info("Device Driver Insert...Done!!!\n");

        //do some real shit
        sos_init_hyp();

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
static void __exit sos_exit(void)
{
        device_destroy(dev_class,dev);
        class_destroy(dev_class);
        cdev_del(&sos_cdev);
        unregister_chrdev_region(dev, 1);
        sos_info("Removal of sos is done.\n");
}

module_init(sos_init);
module_exit(sos_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Adam Toth <tothadamster@gmail.com>");
MODULE_DESCRIPTION("Experimental arm64 sos module");
MODULE_VERSION(SOS_VERSION);
