/*
 * RINA management functionalities
 *
 *    Vincenzo Maffione <v.maffione@gmail.it>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <linux/module.h>
#include <linux/aio.h>
#include <linux/miscdevice.h>
#include <linux/poll.h>
#include <linux/moduleparam.h>


static ssize_t
rina_ctrl_aio_write(struct kiocb *iocb, const struct iovec *iv,
        unsigned long iovlen, loff_t pos)
{
    struct file *file = iocb->ki_filp;
    // file->private_data;
    (void)file;

    /* XXX file->f_flags & O_NONBLOCK */

    return 0;
}

static ssize_t
rina_ctrl_aio_read(struct kiocb *iocb, const struct iovec *iv,
        unsigned long iovcnt, loff_t pos)
{
    struct file *file = iocb->ki_filp;
    //vmpi_info_t *mpi = file->private_data;

    (void)file;

    return 0;
}

static int
rina_ctrl_open(struct inode *inode, struct file *f)
{
    f->private_data = NULL;

    return 0;
}

static int
rina_ctrl_release(struct inode *inode, struct file *f)
{
    f->private_data = NULL;

    return 0;
}

static const struct file_operations rina_ctrl_fops = {
    .owner          = THIS_MODULE,
    .release        = rina_ctrl_release,
    .open           = rina_ctrl_open,
    .write          = do_sync_write,
    .aio_write      = rina_ctrl_aio_write,
    .read           = do_sync_read,
    .aio_read       = rina_ctrl_aio_read,
    .llseek         = noop_llseek,
};

#define RINA_CTRL_MINOR     247

static struct miscdevice rina_ctrl_misc = {
    .minor = RINA_CTRL_MINOR,
    .name = "rina-ctrl",
    .fops = &rina_ctrl_fops,
};

static int __init
rina_ctrl_init(void)
{
    int ret;

    ret = misc_register(&rina_ctrl_misc);
    if (ret) {
        printk("Failed to register rina-ctrl misc device\n");
        return ret;
    }

    return 0;
}

static void __exit
rina_ctrl_fini(void)
{
    misc_deregister(&rina_ctrl_misc);
}

module_init(rina_ctrl_init);
module_exit(rina_ctrl_fini);
MODULE_LICENSE("GPL");
MODULE_ALIAS_MISCDEV(RINA_CTRL_MINOR);
MODULE_ALIAS("devname: rina-ctrl");
