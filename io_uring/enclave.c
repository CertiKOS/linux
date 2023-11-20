// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/io_uring.h>
#include <linux/arm-smccc.h>
#include <linux/mman.h>
#include <linux/anon_inodes.h>
#include <asm-generic/mman-common.h>

#include <uapi/linux/io_uring.h>
#include <uapi/certikos/spawn.h>

#include "io_uring.h"
#include "enclave.h"

struct io_enclave_mmap
{
    struct file * file;
    size_t size;
    int eid;
    uint64_t user_data;
};


struct io_enclave_spawn
{
    struct enclave_spawn_param_t __user *params;
};


static int io_enclave_release(
        struct inode *inode,
        struct file *file)
{
    return 0;
}

static int io_enclave_mmap_internal(
        struct file *file,
        struct vm_area_struct *vma)
{
    struct io_enclave_mmap * enclave_mmap = file->private_data;

    size_t len = vma->vm_end - vma->vm_start;
    gfp_t gfp = GFP_KERNEL_ACCOUNT | __GFP_ZERO | __GFP_NOWARN | __GFP_COMP;
    void * kva = (void *)__get_free_pages(gfp, get_order(len));
    if(!kva)
    {
        printk(KERN_WARNING "NO MEMORY LEFT! Get free pages failed.\n");
        return -ENOMEM;
    }

    unsigned long pfn = (uintptr_t)virt_to_phys(kva) >> PAGE_SHIFT;
    int ret = remap_pfn_range(vma, vma->vm_start, pfn, len, vma->vm_page_prot);

    //TODO check res return value
    //TODO derive eid from some saved state, or pass proxy pid to reg calls
    struct arm_smccc_res res;
    arm_smccc_smc(ARM_SMCCC_REG_RINGLEADER_SHMEM,
            (uintptr_t)virt_to_phys(kva),
            (uintptr_t)vma->vm_start,
            len,
            enclave_mmap->eid,
            enclave_mmap->user_data,
            0, 0, &res);

    return ret;
}


static const struct file_operations io_enclave_fops = {
    .release            = io_enclave_release,
    .mmap               = io_enclave_mmap_internal,
};





int io_enclave_mmap_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
    struct io_enclave_mmap * enclave_mmap;

    enclave_mmap = io_kiocb_to_cmd(req, struct io_enclave_mmap);
    enclave_mmap->size = READ_ONCE(sqe->len);
    enclave_mmap->eid = READ_ONCE(sqe->off);
    enclave_mmap->user_data = READ_ONCE(sqe->user_data);

    //TODO check features
    return 0;
}


int io_enclave_mmap(struct io_kiocb *req, unsigned int issue_flags)
{
    struct io_enclave_mmap * enclave_mmap;
    unsigned long uva;

    enclave_mmap = io_kiocb_to_cmd(req, struct io_enclave_mmap);
    size_t len = PAGE_ALIGN(enclave_mmap->size);

    if(len == 0)
    {
        printk(KERN_WARNING "io_enclave: invalid size.\n");
        io_req_set_res(req, -1, 0);
        return IOU_OK;
    }

    //TODO allocate enclave_mmap
    struct file * file = anon_inode_getfile_secure(
        "[io_enclave_shmem]",
        &io_enclave_fops,
        enclave_mmap,
        O_RDWR | O_CLOEXEC,
        NULL);

    if(IS_ERR(file))
    {
        printk(KERN_WARNING "io_enclave: failed to create shmem file.\n");
        io_req_set_res(req, -1, 0);
        return IOU_OK;
    }


    unsigned long populate = 0;
    uva = do_mmap(file, 0, len,
        PROT_READ | PROT_WRITE,
        MAP_LOCKED | MAP_SHARED | MAP_POPULATE,
        0, /* offset */
        &populate,
        NULL);

    if(uva == -1)
    {
        printk(KERN_WARNING "io_enclave: mmap of shmem failed\n");
        io_req_set_res(req, -1, 0);
        return IOU_OK;
    }


    io_req_set_res(req, 0, 0);
    return IOU_OK;
}

int io_enclave_spawn_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
    struct io_enclave_spawn * enclave_spawn;

    enclave_spawn = io_kiocb_to_cmd(req, struct io_enclave_spawn);
    enclave_spawn->params =
        (struct enclave_spawn_param_t __user *)READ_ONCE(sqe->addr);

    //TODO check features
    return 0;
}

int io_enclave_spawn(struct io_kiocb *req, unsigned int issue_flags)
{
    struct io_enclave_spawn * enclave_spawn;
    struct enclave_spawn_param_t p;
    struct enclave_spawn_param_t *kparams;
    int len;

    enclave_spawn = io_kiocb_to_cmd(req, struct io_enclave_spawn);
    if (copy_from_user(&p, enclave_spawn->params, sizeof(p)))
    {
        io_req_set_res(req, -EFAULT, 0);
        return IOU_OK;
    }

    kparams = kmalloc(sizeof(*kparams), GFP_KERNEL);
    memcpy(kparams, &p, sizeof(*kparams));

    len = strnlen_user(p.bin_name, ENCLAVE_BIN_NAME_MAX_LEN) + 1;
    kparams->bin_name = kmalloc(len, GFP_KERNEL);
    strncpy_from_user(kparams->bin_name, p.bin_name, len);
    /* TODO error check */

    kparams->argv = NULL;
    kparams->envp = NULL;

    struct arm_smccc_res res;
    arm_smccc_smc(ARM_SMCCC_SPAWN_ENCLAVE,
        (uintptr_t)virt_to_phys(kparams),
        0,
        0,
        0,
        0,
        0,
        0,
        &res);

    kfree(kparams->bin_name);
    //kfree(kparams->argv);
    //kfree(kparams->envp);
    kfree(kparams);

    io_req_set_res(req, 0, 0);
    return IOU_OK;
}


//int io_enclave_share_rings_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
//{
//    return 0;
//}
//
//int io_enclave_share_rings(struct io_kiocb *req, unsigned int issue_flags)
//{
//    return 0;
//}


