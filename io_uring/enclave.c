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
#include <uapi/certikos/smccc.h>

#include "io_uring.h"
#include "enclave.h"
#include "rsrc.h"


struct enclave_mmap_data
{
    int             eid;
    uint64_t        user_data;
    uintptr_t *     paddrs;
    int             paddrs_order;
    struct page **  pages;
    size_t          pages_size;
};

struct io_enclave_mmap
{
    struct file * file;
    size_t size;
    struct enclave_mmap_data *mmap_data;
};


struct enclave_spawn_data
{
    char *bin_name;
    char **argv;
    char **envp;
    char *argv_strs;
    char *envp_strs;

    int kparams_order;
    int k_io_params_order;
    int bin_name_order;
    int argv_order;
    int envp_order;
    int argv_strs_order;
    int envp_strs_order;
};

struct io_enclave_spawn
{
    struct sys_spawn_param_t *kparams;
    struct io_uring_params * k_io_params;
    struct enclave_spawn_data *data;
};


static void
free_enclave_mmap_data(struct enclave_mmap_data *data)
{
    if(!data)
        return;

    if(data->pages)
    {
        for(unsigned long i = 0; i < data->pages_size; i++)
        {
            __free_page(data->pages[i]);
        }
        kfree(data->pages);
    }

    free_pages((uintptr_t)data->paddrs, data->paddrs_order);
    kfree(data);
}


static int io_enclave_release(
        struct inode *inode,
        struct file *file)
{
    struct enclave_mmap_data * priv = file->private_data;
    printk(KERN_WARNING "release mmap (%zu pages)\n", priv->pages_size);

    //TODO these should be freed by the enclave
    //We need to create an interface to allow the CertiKOS to free these

    free_enclave_mmap_data(priv);
    file->private_data = NULL;
    return 0;
}

static int io_enclave_mmap_internal(
        struct file *file,
        struct vm_area_struct *vma)
{
    int res;
    struct enclave_mmap_data * priv = file->private_data;
    size_t len = vma->vm_end - vma->vm_start;
    vm_flags_set(vma, VM_MIXEDMAP | VM_DONTEXPAND);

    priv->pages_size = len >> PAGE_SHIFT;
    priv->pages = kmalloc_array(priv->pages_size, sizeof(struct page *),
            GFP_KERNEL | __GFP_ZERO);
    if(!priv->pages)
    {
        printk(KERN_WARNING "page_array kmalloc failed.\n");
        res = -ENOMEM;
        goto out;
    }


    /* We want full pages here. CertiKOS will check that this memory is unused
     * at the granularity of a page. */
    priv->paddrs_order = get_order(priv->pages_size * sizeof(uintptr_t));
    priv->paddrs = (void*)__get_free_pages(GFP_KERNEL, priv->paddrs_order);
    if(!priv->paddrs)
    {
        printk(KERN_WARNING "phys_addr_array kmalloc failed.\n");
        res = -ENOMEM;
        goto out_free_page_array;
    }


    unsigned long bulk_res = alloc_pages_bulk_array(
            GFP_KERNEL_ACCOUNT | __GFP_ZERO | __GFP_NOWARN,
            priv->pages_size, priv->pages);
    if(bulk_res != priv->pages_size)
    {
        printk("Failed bulk alloc 0x%lx/0x%lx pages\n", bulk_res, priv->pages_size);
        res = -ENOMEM;
        goto out_free_phys_addr_array;
    }


    res = vm_insert_pages(vma, vma->vm_start, priv->pages, &bulk_res);
    if(res || bulk_res != 0)
    {
        printk("didn't inserted %lx pages (%i)\n", bulk_res, res);
        res = -EFAULT;
        goto out_free_phys_addr_array;
    }

    for(unsigned long i = 0; i < priv->pages_size; i++)
    {
        priv->paddrs[i] = page_to_phys(priv->pages[i]);
    }

    struct arm_smccc_res smc_res;
    arm_smccc_smc(
            ARM_SMCCC_CALL_VAL(
                ARM_SMCCC_FAST_CALL,
                ARM_SMCCC_SMC_64,
                ARM_SMCCC_OWNER_TRUSTED_OS,
                CERTIKOS_SMCCC_FUNC_NUM_RINGLEADER_REG_SHMEM),
            virt_to_phys(priv->paddrs),
            (uintptr_t)vma->vm_start,
            len,
            priv->eid,
            priv->user_data,
            0, 0, &smc_res);
    //TODO: handle error

goto out;


out_free_phys_addr_array:
    free_pages((uintptr_t)priv->paddrs, priv->paddrs_order);
out_free_page_array:
    kfree(priv->pages);
out:
    return res;
}


static const struct file_operations io_enclave_fops = {
    .release            = io_enclave_release,
    .mmap               = io_enclave_mmap_internal,
};





int io_enclave_mmap_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
    struct io_enclave_mmap * enclave_mmap;

    /* don't accept fixed buffers */
    if (sqe->buf_index || sqe->rw_flags || sqe->splice_fd_in) {
        return -EINVAL;
    }

    enclave_mmap = io_kiocb_to_cmd(req, struct io_enclave_mmap);
    enclave_mmap->size = READ_ONCE(sqe->len);
    enclave_mmap->mmap_data = kmalloc(sizeof(*enclave_mmap->mmap_data), GFP_KERNEL);
    if(!enclave_mmap->mmap_data)
    {
        printk(KERN_WARNING "io_enclave: failed to allocate mmap.\n");
        return -ENOMEM;
    }

    enclave_mmap->mmap_data->eid = READ_ONCE(sqe->off);
    enclave_mmap->mmap_data->user_data = READ_ONCE(sqe->user_data);

    return 0;
}



int io_enclave_mmap(struct io_kiocb *req, unsigned int issue_flags)
{
    struct io_enclave_mmap * enclave_mmap;
    u64 uva;

    enclave_mmap = io_kiocb_to_cmd(req, struct io_enclave_mmap);
    size_t len = PAGE_ALIGN(enclave_mmap->size);

    if(len == 0)
    {
        printk(KERN_WARNING "io_enclave: invalid size.\n");
        io_req_set_res(req, -1, 0);
        return IOU_OK;
    }


    struct file *file = anon_inode_getfile_secure(
        "[io_enclave_shmem]",
        &io_enclave_fops,
        enclave_mmap->mmap_data,
        O_RDWR | O_CLOEXEC,
        NULL);

    if(IS_ERR(file))
    {
        printk(KERN_WARNING "io_enclave: failed to create shmem file.\n");
        io_req_set_res(req, -1, 0);
        return IOU_OK;
    }


    //TODO current->mm lock ok?
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
        fput(file);
        return IOU_OK;
    }


    /* Register this shared memory with io_uring so we can used FIXED ops */
    int ret;
    if(!req->ctx->user_bufs) {
        unsigned int nr_buffers = 64;

        ret = io_sqe_buffers_register(req->ctx, NULL, nr_buffers, NULL);
        if(ret) {
            printk(KERN_WARNING "io_enclave: failed to register buffers %i\n", ret);
            io_req_set_res(req, ret, 0);
            fput(file);
            return IOU_OK;
        }
    }

    struct iovec __user * data = u64_to_user_ptr(uva);
    struct io_uring_rsrc_update2 __user * up =
        (struct io_uring_rsrc_update2 __user *)(data + 1);

    struct iovec my_data = {
        .iov_base = u64_to_user_ptr(uva),
        .iov_len = len
    };
    if(copy_to_user(data, &my_data, sizeof(my_data)))
    {
        printk(KERN_WARNING "io_enclave: failed to copy data\n");
        io_req_set_res(req, -1, 0);
        fput(file);
        return IOU_OK;
    }

    unsigned int i;
    for(i = 0; i < req->ctx->nr_user_bufs; i++) {
        if(req->ctx->user_bufs[i] == req->ctx->dummy_ubuf) break;
    }

    if(i >= req->ctx->nr_user_bufs) {
        printk(KERN_WARNING "io_enclave: fixed buffers full.\n");
        /* TODO expand buffers */
    }

    struct io_uring_rsrc_update2 my_up = {
        .offset = i,
        .nr = 1,
        .data = uva,
    };
    if(copy_to_user(up, &my_up, sizeof(my_up)))
    {
        printk(KERN_WARNING "io_enclave: failed to copy up\n");
        io_req_set_res(req, -1, 0);
        fput(file);
        return IOU_OK;
    }

    ret = io_register_rsrc_update(req->ctx, up, sizeof(*up), IORING_RSRC_BUFFER);
    if(ret != 1) {
        printk(KERN_WARNING "io_enclave: failed to update buffers %i\n",ret);
        io_req_set_res(req, ret, 0);
        fput(file);
        return IOU_OK;
    }

    int fd = get_unused_fd_flags(O_RDWR | O_CLOEXEC);
    if(fd < 0)
    {
        printk(KERN_WARNING "io_enclave: failed to get fd\n");
        io_req_set_res(req, -1, 0);
        fput(file);
        return IOU_OK;
    }

    fd_install(fd, file);

    io_req_set_res(req, len, 0);
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
        char ** arr_strs_out,
        int * arr_out_order,
        int * arr_strs_out_order)
{
    size_t total;
    size_t arr_size = argv_envp_count(
            (const char __user * const __user*)uarr,
            arr_max,
            elem_max,
            &total);

    *arr_out_order = get_order(arr_size*sizeof(char*));
    *arr_strs_out_order = get_order(total);

    /* whole pages are needed here */
    char ** arr = (void*)__get_free_pages(GFP_KERNEL, *arr_out_order);
    char * arr_strs = (void*)__get_free_pages(GFP_KERNEL, *arr_strs_out_order);
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

    enclave_spawn->data = kmalloc(sizeof(*enclave_spawn->data), GFP_KERNEL | __GFP_ZERO);
    if(!enclave_spawn->data) {
        ret = -ENOMEM;
        goto out;
    }

    enclave_spawn->data->kparams_order =
        get_order(sizeof(*enclave_spawn->kparams));

    enclave_spawn->kparams = (void*)__get_free_pages(GFP_KERNEL,
            enclave_spawn->data->kparams_order);
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
    enclave_spawn->data->bin_name_order = get_order(name_size);
    bin_name = (void*)__get_free_pages(GFP_KERNEL,
            enclave_spawn->data->bin_name_order);
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
        &argv_strs,
        &enclave_spawn->data->argv_order,
        &enclave_spawn->data->argv_strs_order);
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
        &envp_strs,
        &enclave_spawn->data->envp_order,
        &enclave_spawn->data->envp_strs_order);
    if(ret < 0)
    {
        goto out2;
    }
    envp_size = ret;

    enclave_spawn->data->k_io_params_order =
        get_order(sizeof(*enclave_spawn->k_io_params));
    enclave_spawn->k_io_params = (void*)__get_free_pages(GFP_KERNEL,
            enclave_spawn->data->k_io_params_order);
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

    //printk("name:%s (%zu), argv_size=%zu, envp_size=%zu\n",
    //        bin_name, name_size, argv_size, envp_size);


    enclave_spawn->kparams->bin_name    = (void *)virt_to_phys(bin_name);
    enclave_spawn->kparams->argv        = (void *)virt_to_phys(argv);
    enclave_spawn->kparams->envp        = (void *)virt_to_phys(envp);
    enclave_spawn->kparams->argv_size   = argv_size;
    enclave_spawn->kparams->envp_size   = envp_size;

    enclave_spawn->data->bin_name = bin_name;
    enclave_spawn->data->argv = argv;
    enclave_spawn->data->envp = envp;
    enclave_spawn->data->argv_strs = argv_strs;
    enclave_spawn->data->envp_strs = envp_strs;

    return 0;
out3:
    free_pages((uintptr_t)enclave_spawn->k_io_params,   enclave_spawn->data->k_io_params_order);
out2:
    free_pages((uintptr_t)envp,                         enclave_spawn->data->envp_order);
    free_pages((uintptr_t)argv,                         enclave_spawn->data->argv_order);
    free_pages((uintptr_t)envp_strs,                    enclave_spawn->data->envp_strs_order);
    free_pages((uintptr_t)argv_strs,                    enclave_spawn->data->argv_strs_order);
    free_pages((uintptr_t)bin_name,                     enclave_spawn->data->bin_name_order);
    free_pages((uintptr_t)enclave_spawn->kparams,       enclave_spawn->data->kparams_order);
out1:
    kfree(enclave_spawn->data);
out:
    return ret;
}

int io_enclave_spawn(struct io_kiocb *req, unsigned int issue_flags)
{
    struct io_enclave_spawn * enclave_spawn;

    enclave_spawn = io_kiocb_to_cmd(req, struct io_enclave_spawn);

    struct arm_smccc_res res;
    arm_smccc_smc(
        ARM_SMCCC_CALL_VAL(
            ARM_SMCCC_FAST_CALL,
            ARM_SMCCC_SMC_64,
            ARM_SMCCC_OWNER_TRUSTED_OS,
            CERTIKOS_SMCCC_FUNC_NUM_SPAWN_ENCLAVE),
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

    free_pages((uintptr_t)enclave_spawn->data->bin_name,   enclave_spawn->data->bin_name_order);
    free_pages((uintptr_t)enclave_spawn->data->argv,       enclave_spawn->data->argv_order);
    free_pages((uintptr_t)enclave_spawn->data->envp,       enclave_spawn->data->envp_order);
    free_pages((uintptr_t)enclave_spawn->data->argv_strs,  enclave_spawn->data->argv_strs_order);
    free_pages((uintptr_t)enclave_spawn->data->envp_strs,  enclave_spawn->data->envp_strs_order);
    free_pages((uintptr_t)enclave_spawn->k_io_params,   enclave_spawn->data->k_io_params_order);
    free_pages((uintptr_t)enclave_spawn->kparams,       enclave_spawn->data->kparams_order);

    io_req_set_res(req, 0, 0);
    return IOU_OK;
}


