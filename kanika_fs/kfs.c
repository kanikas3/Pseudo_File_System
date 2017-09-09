/*
 * Resizable simple ram filesystem for Linux.
 *
 * Copyright (C) 2000 Linus Torvalds.
 *               2000 Transmeta Corp.
 *
 * Usage limits added by David Gibson, Linuxcare Australia.
 * This file is released under the GPL.
 */

/*
 * NOTE! This filesystem is probably most useful
 * not as a real filesystem, but as an example of
 * how virtual filesystems can be written.
 *
 * It doesn't get much simpler than this. Consider
 * that this file implements the full semantics of
 * a POSIX-compliant read-write filesystem.
 *
 * Note in particular how the filesystem does not
 * need to implement any data structures of its own
 * to keep track of the virtual data: using the VFS
 * caches is sufficient.
 */

#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/highmem.h>
#include <linux/time.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/backing-dev.h>
//#include <linux/ramfs.h>
#include <linux/sched.h>
#include <linux/parser.h>
#include <linux/magic.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fsnotify.h>
#include <linux/namei.h>
#include <linux/dcache.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kanika Sabharwal");

#define KFS_DEFAULT_MODE	0755
#define KFS_MAGIC	0x73234357

struct kfs_file_info {
	struct task_struct* task;
	int type;
	char* info_string;
	int len;
};

static const struct super_operations kfs_ops;
static const struct inode_operations kfs_dir_inode_operations;

static const struct address_space_operations kfs_aops = {
	.readpage	= simple_readpage,
	.write_begin	= simple_write_begin,
	.write_end	= simple_write_end,
	//.set_page_dirty	= __set_page_dirty_no_writeback,
};

/*static unsigned long kfs_mmu_get_unmapped_area(struct file *file,
		unsigned long addr, unsigned long len, unsigned long pgoff,
		unsigned long flags)
{
	return current->mm->get_unmapped_area(file, addr, len, pgoff, flags);
}*/

static inline bool d_really_is_positive(const struct dentry *dentry)
{
	return dentry->d_inode != NULL;
}

/*
 * The operations on our "files".
 */

/*
 * Open a file.  All we have to do here is to copy over a
 * copy of the counter pointer so it's easier to get at.
 */
static int kfs_open(struct inode *inode, struct file *filp)
{
	filp->private_data = inode->i_private;
	return 0;
}

static const char * const task_state_array[] = {
	"R (running)",		/*   0 */
	"S (sleeping)",		/*   1 */
	"D (disk sleep)",	/*   2 */
	"T (stopped)",		/*   4 */
	"t (tracing stop)",	/*   8 */
	"X (dead)",		/*  16 */
	"Z (zombie)",		/*  32 */
};

static inline const char *get_task_state(struct task_struct *tsk)
{
	unsigned int state = (tsk->state | tsk->exit_state) & TASK_REPORT;

	/*
	 * Parked tasks do not run; they sit in __kthread_parkme().
	 * Without this check, we would report them as running, which is
	 * clearly wrong, so we report them as sleeping instead.
	 */
	if (tsk->state == TASK_PARKED)
		state = TASK_INTERRUPTIBLE;

	return task_state_array[fls(state)];
}

#define BUFSIZE 500

static void kfs_update_task_status(struct kfs_file_info *info)
{
	struct task_struct *task;
	char *str;
	int is_kernel;
	task = info->task;
	str = info->info_string;

	if(str)
		kfree(str);

	info->info_string = kmalloc(BUFSIZE, GFP_KERNEL);
	str = info->info_string;

	if(!task)
		info->len = snprintf(str, BUFSIZE, "NONE");
	
	is_kernel = (task->flags & PF_KTHREAD) > 0 ? 1 : 0;
	if(is_kernel) 
	{
		info->len = snprintf(str, BUFSIZE, "Status: %s\nKernel Thread: %s\nCPU: %d\nStart Time: %llu\nName: %s\nMemory Info:\n\tStack:%p\nPriority:\n\tStatic:%d\n\tDynamic:%d\nEND\n", 
			get_task_state(task), "YES",  task_cpu(task), task->start_time, task->comm, task->stack, task->static_prio, task->prio);
	}
	else
	{
		info->len = snprintf(str, BUFSIZE, "Status: %s\nKernel Thread: %s\nCPU: %d\nStart Time: %llu\nName: %s\nMemory Info:\n\tStack:%p\n\tTotal Pages Mapped:%lu\n\tPinned Pages:%lu\n\tStack VM:%lu\nPriority:\n\tStatic:%d\n\tDynamic:%d\nEND\n", 
			get_task_state(task), "NO",  task_cpu(task), task->start_time, task->comm, task->stack,
			task->mm->total_vm, task->mm->pinned_vm, task->mm->stack_vm, task->static_prio, task->prio);	
	}
}

#define TMPSIZE 20
/*
 * Read a file.  
 */
static ssize_t kfs_read_file(struct file *filp, char *buf,
		size_t count, loff_t *offset)
{
	char *str;
	int len;
	struct kfs_file_info *info = (struct kfs_file_info *) filp->private_data;
	if(!info || !info->task)
		return -EINVAL;

	if(info->type != 1)
		return 0;

	if(!(*offset) || !info->info_string) 
	{
		kfs_update_task_status(info);
	}

/*
 * Copy it back, increment the offset, and we're done.
 */
	str = info->info_string;
	len = info->len;
	if(!str)
		return -EINVAL;
	if(*offset > len)
		return 0;
	if(count > len - *offset)
		count = len - *offset;

	if (copy_to_user(buf, info->info_string + *offset, count))
		return -EFAULT;
	*offset += count;
	return count;
}

/*
 * Write a file.
 */
static ssize_t kfs_write_file(struct file *filp, const char *buf,
		size_t count, loff_t *offset)
{
	struct kfs_file_info *finfo = (struct kfs_file_info*) filp->private_data;
	char tmp[TMPSIZE];
	int err;
	struct siginfo sinfo;
	int signum, ret;

	if(finfo->type != 2)
	{
		return -EINVAL;
	}
/*
 * Only write from the beginning.
 */
	if (*offset != 0)
	{
		return -EINVAL;
	}

	if (count >= TMPSIZE)
	{
		return -EINVAL;
	}
	memset(tmp, 0, TMPSIZE);
	if (copy_from_user(tmp, buf, count))
		return -EFAULT;


	err = kstrtoint(tmp, 10, &signum);
	if (unlikely(err))
	{
		return err;
	}

	memset(&sinfo, 0, sizeof(struct siginfo));
	sinfo.si_signo = signum;
	ret = send_sig_info(signum, &sinfo, finfo->task);
	if (ret < 0) {
	  printk(KERN_INFO "error sending signal\n");
	}

	return count;
}


/*
 * Now we can put together our file operations structure.
 */
const struct file_operations kfs_file_operations = {
	.open	= kfs_open,
	.read 	= kfs_read_file,
	.write  = kfs_write_file,
};

/*const struct file_operations kfs_file_operations = {
	.read_iter	= generic_file_read_iter,
	.write_iter	= generic_file_write_iter,
	.mmap		= generic_file_mmap,
	.fsync		= noop_fsync,
	.splice_read	= generic_file_splice_read,
	.splice_write	= iter_file_splice_write,
	.llseek		= generic_file_llseek,
	.get_unmapped_area	= kfs_mmu_get_unmapped_area,
};*/

const struct inode_operations kfs_file_inode_operations = {
	.setattr	= simple_setattr,
	.getattr	= simple_getattr,
};

struct inode *kfs_get_inode(struct super_block *sb,
				const struct inode *dir, umode_t mode, dev_t dev)
{
	struct inode * inode = new_inode(sb);

	if (inode) {
		inode->i_ino = get_next_ino();
		inode_init_owner(inode, dir, mode);
		inode->i_mapping->a_ops = &kfs_aops;
		mapping_set_gfp_mask(inode->i_mapping, GFP_HIGHUSER);
		mapping_set_unevictable(inode->i_mapping);
		inode->i_atime = inode->i_mtime = inode->i_ctime = CURRENT_TIME;
		switch (mode & S_IFMT) {
		default:
			init_special_inode(inode, mode, dev);
			break;
		case S_IFREG:
			//inode->i_op = &aamfs_file_inode_operations;
			inode->i_fop = &kfs_file_operations;
			break;
		case S_IFDIR:
			inode->i_op = &kfs_dir_inode_operations;
			inode->i_fop = &simple_dir_operations;

			/* directory inodes start off with i_nlink == 2 (for "." entry) */
			inc_nlink(inode);
			break;
		case S_IFLNK:
			inode->i_op = &page_symlink_inode_operations;
			break;
		}
	}
	return inode;
}

/*
 * File creation. Allocate an inode, and we're done..
 */
/* SMP-safe */
static int
kfs_mknod(struct inode *dir, struct dentry *dentry, umode_t mode, dev_t dev)
{
	struct inode * inode = kfs_get_inode(dir->i_sb, dir, mode, dev);
	int error = -ENOSPC;

	if (inode) {
		d_instantiate(dentry, inode);
		dget(dentry);	/* Extra count - pin the dentry in core */
		error = 0;
		dir->i_mtime = dir->i_ctime = CURRENT_TIME;
	}
	return error;
}

static int kfs_mkdir(struct inode * dir, struct dentry * dentry, umode_t mode)
{
	int retval = kfs_mknod(dir, dentry, mode | S_IFDIR, 0);
	if (!retval)
		inc_nlink(dir);
	return retval;
}

static int kfs_create(struct inode *dir, struct dentry *dentry, umode_t mode, bool excl)
{
	return kfs_mknod(dir, dentry, mode | S_IFREG, 0);
}

static int kfs_symlink(struct inode * dir, struct dentry *dentry, const char * symname)
{
	struct inode *inode;
	int error = -ENOSPC;

	inode = kfs_get_inode(dir->i_sb, dir, S_IFLNK|S_IRWXUGO, 0);
	if (inode) {
		int l = strlen(symname)+1;
		error = page_symlink(inode, symname, l);
		if (!error) {
			d_instantiate(dentry, inode);
			dget(dentry);
			dir->i_mtime = dir->i_ctime = CURRENT_TIME;
		} else
			iput(inode);
	}
	return error;
}

static void kfs_evict_inode(struct inode *inode)
{
	clear_inode(inode);
	if(inode->i_private)
	{	
		if (((struct kfs_file_info*) inode->i_private)->info_string)
			kfree(((struct kfs_file_info*) inode->i_private)->info_string);
		kfree(inode->i_private);
	}
}

static const struct inode_operations kfs_dir_inode_operations = {
	.create		= kfs_create,
	.lookup		= simple_lookup,
	.link		= simple_link,
	.unlink		= simple_unlink,
	.symlink	= kfs_symlink,
	.mkdir		= kfs_mkdir,
	.rmdir		= simple_rmdir,
	.mknod		= kfs_mknod,
	.rename		= simple_rename,
};

static const struct super_operations kfs_ops = {
	.statfs		= simple_statfs,
	.evict_inode	= kfs_evict_inode,
	.drop_inode	= generic_delete_inode,
	.show_options	= generic_show_options,
};

struct kfs_mount_opts {
	umode_t mode;
};

enum {
	Opt_mode,
	Opt_err
};

static const match_table_t tokens = {
	{Opt_mode, "mode=%o"},
	{Opt_err, NULL}
};

struct kfs_fs_info {
	struct kfs_mount_opts mount_opts;
};

static int kfs_parse_options(char *data, struct kfs_mount_opts *opts)
{
	substring_t args[MAX_OPT_ARGS];
	int option;
	int token;
	char *p;

	opts->mode = KFS_DEFAULT_MODE;

	while ((p = strsep(&data, ",")) != NULL) {
		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
		case Opt_mode:
			if (match_octal(&args[0], &option))
				return -EINVAL;
			opts->mode = option & S_IALLUGO;
			break;
		/*
		 * We might like to report bad mount options here;
		 * but traditionally kfs has ignored all mount options,
		 * and as it is used as a !CONFIG_SHMEM simple substitute
		 * for tmpfs, better continue to ignore other mount options.
		 */
		}
	}

	return 0;
}

static struct dentry *kfs_create_file (const char *name, umode_t mode,
		struct dentry *parent, void* data)
{
	struct dentry *dentry;
	struct inode *inode;
	struct qstr qname;


	qname.name = name;
	qname.len = strlen (name);
	qname.hash = full_name_hash(name, qname.len);

	dentry = d_alloc(parent, &qname);
	if (!dentry) 
	{
		printk(KERN_INFO "d_alloc failed");
		return NULL;
	}

	inode = kfs_get_inode(parent->d_sb, parent->d_inode, mode | S_IFREG, 0);
	if (unlikely(!inode))
	{	
		printk(KERN_INFO "kfs_get_inode failed");
		return NULL;
	}

	inode->i_private = data;
	d_add(dentry, inode);

	//inode->i_fop = proxy_fops;
	//dentry->d_fsdata = (void *)real_fops;

	//d_instantiate(dentry, inode);
	//fsnotify_create(d_inode(dentry->d_parent), dentry);
	return dentry;
}

static struct dentry *kfs_create_dir (const char *name, umode_t mode,
		struct dentry *parent)
{
	struct dentry *dentry;
	struct inode *inode;
	struct qstr qname;


	qname.name = name;
	qname.len = strlen (name);
	qname.hash = full_name_hash(name, qname.len);

	dentry = d_alloc(parent, &qname);
	if (!dentry) 
	{
		printk(KERN_INFO "d_alloc failed");
		return NULL;
	}

	inode = kfs_get_inode(parent->d_sb, parent->d_inode, mode | S_IFDIR, 0);
	if (unlikely(!inode))
	{	
		printk(KERN_INFO "kfs_get_inode failed");
		return NULL;
	}

	d_add(dentry, inode);

	//inode->i_fop = proxy_fops;
	//dentry->d_fsdata = (void *)real_fops;

	//d_instantiate(dentry, inode);
	//fsnotify_create(d_inode(dentry->d_parent), dentry);
	return dentry;
}

static void kfs_create_processtree(struct dentry *dir_root, struct task_struct *task_root)
{
	struct list_head *list;
	struct task_struct *new;
//	struct task_struct *new_copy;
	struct dentry* subdir;
	struct kfs_file_info *info = NULL;
	char name[50];
	list_for_each(list, &task_root->children){
		new = list_entry(list, struct task_struct, sibling);
		/*new_copy = new;
		while(new_copy->parent != &init_task){
			new_copy = new_copy->parent;
		}
		*/
		sprintf(name, "%d", new->pid);
		subdir = kfs_create_dir(name, 0777, dir_root);
		if (subdir) {
			info = kmalloc(sizeof(*info), GFP_KERNEL);
			info->task = new;
			info->type = 1;
			info->info_string = NULL;
			info->len = 0;
			sprintf(name, "%d.status", new->pid);
			kfs_create_file(name, 0777, subdir, info);

			info = kmalloc(sizeof(*info), GFP_KERNEL);
			info->task = new;
			info->type = 2;
			info->info_string = NULL;
			info->len = 0;
			kfs_create_file("signal", 0777, subdir, info);

			if((&new->children)->next != &new->children)
        			kfs_create_processtree(subdir, new);
		}

//		printk("%s ->[%d] %s\n",separator, new->pid, new->comm);


	}
}

int kfs_fill_super(struct super_block *sb, void *data, int silent)
{
	struct kfs_fs_info *fsi;
	struct inode *inode;
	struct dentry* subdir;
	int err;
	struct kfs_file_info *info = NULL;
	char name[50];

	save_mount_options(sb, data);

	fsi = kzalloc(sizeof(struct kfs_fs_info), GFP_KERNEL);
	sb->s_fs_info = fsi;
	if (!fsi)
		return -ENOMEM;

	err = kfs_parse_options(data, &fsi->mount_opts);
	if (err)
		return err;

	sb->s_maxbytes		= MAX_LFS_FILESIZE;
	sb->s_blocksize		= PAGE_CACHE_SIZE;
	sb->s_blocksize_bits	= PAGE_CACHE_SHIFT;
	sb->s_magic		= KFS_MAGIC;
	sb->s_op		= &kfs_ops;
	sb->s_time_gran		= 1;

	inode = kfs_get_inode(sb, NULL, S_IFDIR | fsi->mount_opts.mode, 0);
	sb->s_root = d_make_root(inode);
	if (!sb->s_root)
		return -ENOMEM;

	sprintf(name, "%d", (&init_task)->pid);
	subdir = kfs_create_dir(name, 0777, sb->s_root);
	if (subdir) 
	{
		info = kmalloc(sizeof(*info), GFP_KERNEL);
		info->task = &init_task;
		info->type = 1;
		info->info_string = NULL;
		info->len = 0;
		sprintf(name, "%d.status", (&init_task)->pid);
		kfs_create_file(name, 0777, subdir, info);

		info = kmalloc(sizeof(*info), GFP_KERNEL);
		info->task = &init_task;
		info->type = 2;
		info->info_string = NULL;
		info->len = 0;
		kfs_create_file("signal", 0777, subdir, info);

		kfs_create_processtree(subdir, &init_task);
	}



	/*for(i=0;i<100;i++)
	{
		sprintf(name, "filename-%d", i);
		if(kfs_create_file(name, 0755, sb->s_root, NULL) == NULL)
			printk(KERN_INFO "Something wrong creating file");
	}*/

	return 0;
}

struct dentry *kfs_mount(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data)
{
	return mount_nodev(fs_type, flags, data, kfs_fill_super);
}

static void kfs_kill_sb(struct super_block *sb)
{
	kfree(sb->s_fs_info);
	kill_litter_super(sb);
}

static struct file_system_type kfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "kfs",
	.mount		= kfs_mount,
	.kill_sb	= kfs_kill_sb,
	.fs_flags	= FS_USERNS_MOUNT,
};


/*
 * Get things set up.
 */
static int __init kfs_init(void)
{
	return register_filesystem(&kfs_fs_type);
}

static void __exit kfs_exit(void)
{
	unregister_filesystem(&kfs_fs_type);
}

module_init(kfs_init);
module_exit(kfs_exit);
