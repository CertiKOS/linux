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
    struct sys_spawn_param_t *kparams;
    struct io_uring_params * k_io_params;
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


static size_t argv_envp_count(const char __user * const __user * argv,
        size_t max, size_t elem_max, size_t *total)
{
    size_t argv_size;
    *total = 0;

    for(argv_size = 0; argv_size < max; argv_size++) {
        const char __user *argv_ptr = NULL;
        if(get_user(argv_ptr, argv + argv_size))
        {
            return 0;
        }

        if(!argv_ptr)
            break;

        /* assume 8 byte alignment */
        *total += round_up(strnlen_user(argv_ptr, elem_max) + 1, 8);
    }

    return argv_size;
}


int io_enclave_spawn_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
    int ret = 0;
    struct io_enclave_spawn * enclave_spawn;
    size_t name_size, argv_size, envp_size, argv_total, envp_total;
    char * bin_name = NULL;
    char **argv = NULL;
    char **envp = NULL;
    struct sys_spawn_param_t __user *p;
    struct io_uring_params __user * io_params = (void *)READ_ONCE(sqe->addr2);

    /* put len in addr2, don't accept fixed buffers */
    if (sqe->len || sqe->buf_index || sqe->rw_flags ||
            sqe->splice_fd_in) {
        ret = -EINVAL;
        goto out;
    }

    enclave_spawn = io_kiocb_to_cmd(req, struct io_enclave_spawn);
    enclave_spawn->kparams =
        kmalloc(sizeof(*enclave_spawn->kparams), GFP_KERNEL);
    if(!enclave_spawn->kparams) {
        ret = -ENOMEM;
        goto out;
    }

    p = (void *)READ_ONCE(sqe->addr);
    if(copy_from_user(enclave_spawn->kparams, p, sizeof(*p))) {
        ret = -EFAULT;
        goto out1;
    }


    name_size = strnlen_user(enclave_spawn->kparams->bin_name,
            ENCLAVE_BIN_NAME_MAX_LEN);
    argv_size = argv_envp_count(
            (const char __user * const __user*)enclave_spawn->kparams->argv,
            ENCLAVE_ARGV_MAX_LEN,
            ENCLAVE_ARGV_ELEM_MAX_LEN,
            &argv_total);
    envp_size = argv_envp_count(
            (const char __user * const __user*)enclave_spawn->kparams->envp,
            ENCLAVE_ENVP_MAX_LEN,
            ENCLAVE_ENVP_ELEM_MAX_LEN,
            &envp_total);

    bin_name = kmalloc(name_size, GFP_KERNEL);
    argv = kmalloc(argv_size * sizeof(char*), GFP_KERNEL);
    envp = kmalloc(envp_size * sizeof(char*), GFP_KERNEL);


    if(!bin_name || !argv || !envp) {
        ret = -ENOMEM;
        goto out2;
    }

    if(copy_from_user(bin_name, enclave_spawn->kparams->bin_name, name_size) ||
       copy_from_user(argv,     enclave_spawn->kparams->argv, argv_size * sizeof(char*)) ||
       copy_from_user(envp,     enclave_spawn->kparams->envp, envp_size * sizeof(char*)))
    {
        ret = -EFAULT;
        goto out2;
    }

    //TODO copy args


    enclave_spawn->k_io_params =
        kmalloc(sizeof(*enclave_spawn->k_io_params), GFP_KERNEL);
    if(!enclave_spawn->k_io_params)
    {
        ret = -ENOMEM;
        goto out2;
    }


    if(copy_from_user(enclave_spawn->k_io_params, io_params, sizeof(*io_params)))
    {
        ret = -EFAULT;
        goto out3;
    }

    printk("name:%s (%zu), argv_size=%zu, envp_size=%zu\n",
            bin_name, name_size, argv_size, envp_size);


    enclave_spawn->kparams->bin_name    = (void *)virt_to_phys(bin_name);
    enclave_spawn->kparams->argv        = (void *)virt_to_phys(argv);
    enclave_spawn->kparams->envp        = (void *)virt_to_phys(envp);

    return ret;
out3:
    kfree(enclave_spawn->k_io_params);
out2:
    kfree(envp);
    kfree(argv);
    kfree(bin_name);
out1:
    kfree(enclave_spawn->kparams);
out:
    return ret;
}

int io_enclave_spawn(struct io_kiocb *req, unsigned int issue_flags)
{
    struct io_enclave_spawn * enclave_spawn;

    enclave_spawn = io_kiocb_to_cmd(req, struct io_enclave_spawn);

    struct arm_smccc_res res;
    arm_smccc_smc(ARM_SMCCC_SPAWN_ENCLAVE,
        (uintptr_t)virt_to_phys(enclave_spawn->kparams),
        (uintptr_t)virt_to_phys(req->ctx->rings),
        (uintptr_t)virt_to_phys(req->ctx->sq_sqes),
        (uintptr_t)virt_to_phys(enclave_spawn->k_io_params),
        io_rings_size(req->ctx, NULL),
        0,
        0,
        &res);

    if(res.a0 == (unsigned long)-1)
    {
        req_set_fail(req);
    }

    //TODO free original kernel pointers
    //kfree(enclave_spawn->kparams->bin_name);
    //kfree(enclave_spawn->kparams->argv);
    //kfree(enclave_spawn->kparams->envp);
    //kfree(enclave_spawn->kparams);

    io_req_set_res(req, 0, 0);
    return IOU_OK;
}


