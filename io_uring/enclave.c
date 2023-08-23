// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/io_uring.h>
#include <linux/arm-smccc.h>

#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "enclave.h"


struct io_enclave_mmap
{
    struct file * file;
    size_t size;
    int eid;
    uint64_t user_data;
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
    int err;
    void * kva;
    struct page ** pages;
    struct io_enclave_mmap * enclave_mmap;
    unsigned long uva;
    gfp_t gfp;
    struct arm_smccc_res res;

    enclave_mmap = io_kiocb_to_cmd(req, struct io_enclave_mmap);
    size_t len = PAGE_ALIGN(enclave_mmap->size);

    if(len == 0)
    {
        printk(KERN_WARNING "Invalid size.\n");
        //TODO
	    io_req_set_res(req, 0, 0);
    	return IOU_OK;
    }

    printk(KERN_WARNING "enclave mmap size=%lu!\n", len);

    //TODO memlock
    gfp = GFP_KERNEL_ACCOUNT | __GFP_ZERO | __GFP_NOWARN | __GFP_COMP;
    kva = (void *)__get_free_pages(gfp, get_order(enclave_mmap->size));
    if(!kva)
    {
        printk(KERN_WARNING "NO MEMORY LEFT! Get free pages failed.\n");
        //TODO
	    io_req_set_res(req, 0, 0);
	    return IOU_OK;
    }


    uva = get_unmapped_area(NULL, 0, enclave_mmap->size, 0, 0);
    if(IS_ERR_VALUE(uva))
    {
        printk(KERN_WARNING "Failed to get unmapped are.\n");
        //TODO
	    io_req_set_res(req, 0, 0);
    	return IOU_OK;
    }

    printk(KERN_WARNING "got unmapped virtual address %lx mapping to kva %lx\n",
        uva, (unsigned long)kva);

    printk(KERN_WARNING "total pages=%lu\n", len >> PAGE_SHIFT);

    pages = kmalloc(sizeof(struct page *) * (len >> PAGE_SHIFT), GFP_KERNEL);
    if(!pages)
    {
        printk(KERN_WARNING "NO MEMORY LEFT! kmalloc failed.\n");
        //TODO
	    io_req_set_res(req, 0, 0);
	    return IOU_OK;
    }

    for(unsigned long i = 0; i < (len >> PAGE_SHIFT); i++)
    {
        struct page * pg = virt_to_page(kva + i*(PAGE_SIZE));
        //ClearPageReserved(pg);
        get_page(pg);
        pages[i] = pg;
        printk(KERN_WARNING "page addr=%llx\n", (unsigned long long)page_address(pg));
    }

    err = install_special_mapping(current->mm, uva, len,
        VM_READ | VM_MAYREAD | VM_WRITE | VM_MAYWRITE, pages);
    if(err)
    {
        printk(KERN_WARNING "install failed\n");
       //TODO
	    io_req_set_res(req, 0, 0);
    	return IOU_OK;
    }
    printk(KERN_WARNING "registering installed phys_addr= %llx\n", virt_to_phys(kva));
    arm_smccc_smc(ARM_SMCCC_REGISTER_SHMEM,
            (uintptr_t)virt_to_phys(kva),
            (uintptr_t)uva,
            len,
            enclave_mmap->eid,
            enclave_mmap->user_data,
            0, 0, &res);

	io_req_set_res(req, 0, 0);
	return IOU_OK;
}
