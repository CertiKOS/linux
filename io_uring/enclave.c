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
#include <linux/mm_types.h>

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
    uintptr_t *phys_addr_array;
    struct page ** pages;
};


struct io_enclave_spawn
{
    struct sys_spawn_param_t *kparams;
    struct io_uring_params * k_io_params;
    char *bin_name;
    char **argv;
    char **envp;
    char *argv_strs;
    char *envp_strs;
};


static int io_enclave_release(
        struct inode *inode,
        struct file *file)
{
    struct io_enclave_mmap * enclave_mmap = file->private_data;
    printk(KERN_WARNING "release mmap %lu\n", enclave_mmap->size);
    kfree(enclave_mmap->phys_addr_array);
    kfree(enclave_mmap->pages);
    return 0;
}

static int io_enclave_mmap_internal(
        struct file *file,
        struct vm_area_struct *vma)
{
    int res;
    struct io_enclave_mmap * enclave_mmap = file->private_data;
    size_t len = vma->vm_end - vma->vm_start;
    unsigned long n_pages = len >> PAGE_SHIFT;
    vm_flags_set(vma, VM_MIXEDMAP | VM_DONTEXPAND);

    //printk("vm_flags=%lx\n", vma->vm_flags);
    //printk("vm_ops=%lx\n", (uintptr_t)(vma->vm_ops));

    struct page ** page_array =
        kmalloc_array(n_pages, sizeof(struct page *), GFP_KERNEL | __GFP_ZERO);
    if(!page_array)
    {
        printk(KERN_WARNING "page_array kmalloc failed.\n");
        return -ENOMEM;
    }

    uintptr_t * phys_addr_array =
        kmalloc_array(n_pages, sizeof(uintptr_t), GFP_KERNEL);
    if(!phys_addr_array)
    {
        printk(KERN_WARNING "phys_addr_array kmalloc failed.\n");
        kfree(page_array);
        return -ENOMEM;
    }

    enclave_mmap->phys_addr_array = phys_addr_array;
    enclave_mmap->pages = page_array;

    unsigned long bulk_res = alloc_pages_bulk_array(
            GFP_KERNEL_ACCOUNT | __GFP_ZERO | __GFP_NOWARN | __GFP_COMP,
            n_pages, page_array);
    if(bulk_res != n_pages)
    {
        printk("bulk alloc 0x%lx/0x%lx pages\n", bulk_res, n_pages);
        return -ENOMEM;
    }


    res = vm_insert_pages(vma, vma->vm_start, page_array, &bulk_res);
    if(res || bulk_res != 0)
    {
        printk("didn't inserted %lx pages (%i)\n", bulk_res, res);
        return -EFAULT;
    }

    for(unsigned long i = 0; i < n_pages; i++)
    {
        //printk("page %lx -> %llx\n", (uintptr_t)page_array[i], page_to_phys(page_array[i]));
        phys_addr_array[i] = page_to_phys(page_array[i]);
    }

    struct arm_smccc_res smc_res;
    arm_smccc_smc(ARM_SMCCC_REG_RINGLEADER_SHMEM,
            virt_to_phys(phys_addr_array),
            (uintptr_t)vma->vm_start,
            len,
            enclave_mmap->eid,
            enclave_mmap->user_data,
            0, 0, &smc_res);

    return 0;
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
        MAP_LOCKED | MAP_SHARED | MAP_POPULATE | MAP_ANONYMOUS,
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

    return argv_size + 1;
}


static int phys_array_of_user_str_array(
        const char __user * const __user * uarr,
        size_t arr_max,
        size_t elem_max,
        char *** arr_out,
        char ** arr_strs_out)
{
    size_t total;
    size_t arr_size = argv_envp_count(
            (const char __user * const __user*)uarr,
            arr_max,
            elem_max,
            &total);

    char ** arr = kmalloc_array(arr_size, sizeof(char*), GFP_KERNEL);
    char * arr_strs = kmalloc(total, GFP_KERNEL);
    char * arr_strs_head = arr_strs;

    if(!arr || !arr_strs)
    {
        printk("Failed to kmalloc space for argv/envp\n");
        return -ENOMEM;
    }

    if(copy_from_user(arr, uarr, arr_size * sizeof(char*)))
    {
        printk("Failed to copy argv/envp from user\n");
        kfree(arr);
        kfree(arr_strs);
        return -EFAULT;
    }

    for(size_t i = 0; i < arr_size; i++)
    {
        if(arr[i] == NULL)
            continue;

        size_t sz = strnlen_user(arr[i], elem_max);

        if((uintptr_t)arr_strs_head - (uintptr_t)arr_strs + sz > total)
        {
            printk("Overflow of argv/envp strs\n");
            kfree(arr);
            kfree(arr_strs);
            return -EFAULT;
        }

        size_t copied = strncpy_from_user(arr_strs_head, arr[i], sz);
        if(copied + 1 != sz)
        {
            printk("strncopy fault %lx != %lx\n", copied + 1, sz);
            kfree(arr);
            kfree(arr_strs);
            return -EFAULT;
        }
        arr_strs_head[copied] = '\0';

        arr[i] = (void*)virt_to_phys(arr_strs_head);
        arr_strs_head += sz;
    }

    *arr_out = arr;
    *arr_strs_out = arr_strs;
    return arr_size;
}


int io_enclave_spawn_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
    int ret = 0;
    struct io_enclave_spawn * enclave_spawn;
    size_t name_size, argv_size, envp_size;
    char * bin_name = NULL;
    char **argv = NULL;
    char **envp = NULL;
    char *argv_strs = NULL;
    char *envp_strs = NULL;
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
        printk("Failed to allocate memory for bin_name\n");
        ret = -ENOMEM;
        goto out;
    }

    p = (void *)READ_ONCE(sqe->addr);
    if(copy_from_user(enclave_spawn->kparams, p, sizeof(*p))) {
        printk("Failed to allocate memory for bin_name\n");
        ret = -EFAULT;
        goto out1;
    }

    name_size = strnlen_user(enclave_spawn->kparams->bin_name,
            ENCLAVE_BIN_NAME_MAX_LEN);

    bin_name = kmalloc(name_size, GFP_KERNEL);
    if(!bin_name) {
        printk("Failed to allocate memory for bin_name\n");
        ret = -ENOMEM;
        goto out1;
    }

    if(copy_from_user(bin_name, enclave_spawn->kparams->bin_name, name_size))
    {
        ret = -EFAULT;
        goto out2;
    }

    ret = phys_array_of_user_str_array(
        (const char __user * const __user *)enclave_spawn->kparams->argv,
        ENCLAVE_ARGV_MAX_LEN,
        ENCLAVE_ARGV_ELEM_MAX_LEN,
        &argv,
        &argv_strs);
    if(ret < 0)
    {
        goto out2;
    }
    argv_size = ret;

    ret = phys_array_of_user_str_array(
        (const char __user * const __user *)enclave_spawn->kparams->envp,
        ENCLAVE_ENVP_MAX_LEN,
        ENCLAVE_ENVP_ELEM_MAX_LEN,
        &envp,
        &envp_strs);
    if(ret < 0)
    {
        goto out2;
    }
    envp_size = ret;

    enclave_spawn->k_io_params =
        kmalloc(sizeof(*enclave_spawn->k_io_params), GFP_KERNEL);
    if(!enclave_spawn->k_io_params)
    {
        printk("Failed to allocate memory for bin_name\n");
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
    enclave_spawn->kparams->argv_size   = argv_size;
    enclave_spawn->kparams->envp_size   = envp_size;

    enclave_spawn->bin_name = bin_name;
    enclave_spawn->argv = argv;
    enclave_spawn->envp = envp;
    enclave_spawn->argv_strs = argv_strs;
    enclave_spawn->envp_strs = envp_strs;

    return 0;
out3:
    kfree(enclave_spawn->k_io_params);
out2:
    kfree(envp);
    kfree(argv);
    kfree(envp_strs);
    kfree(argv_strs);
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
    kfree(enclave_spawn->bin_name);
    kfree(enclave_spawn->argv);
    kfree(enclave_spawn->envp);
    kfree(enclave_spawn->argv_strs);
    kfree(enclave_spawn->envp_strs);

    io_req_set_res(req, 0, 0);
    return IOU_OK;
}


