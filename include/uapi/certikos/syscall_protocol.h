/**
 * @file syscall.h
 * @brief System call protocols between user and kernel
 * (number and arguments encodings)
 * @version 0.1
 * @date 2019-03-25
 *
 * ! this file is shared between user and kernel
 *
 */

#ifndef _SYSCALL_PROTOCOL_H_
#define _SYSCALL_PROTOCOL_H_

#if defined(_KERN_)
#include <lib/common.h>
#include <lib/export/include/app.h>
#include <lib/export/include/virt_if.h>
#else
#include <types.h>
#include <app.h>
#include <virt_if.h>
#endif


/**
 * Calling conventions of system calls in CertiKOS:
 *
 * 1. All system calls are triggered by the `sysenter` instruction.
 *
 * 2. The caller in ring 3 should identify the system call number and the
 *    necessary arguments before triggering system call.
 *
 * 3. The system call number is identified via the value in EAX. All valid
 *    system call numbers are listed in __syscall_nr (except MAX_SYSCALL_NR).
 *    Any system call with an invalid system call number will return with
 *    an error code ERR_INVALID_CALL_NO.
 *
 * 4. A system call can take at most 3 arguments which are passed via registers
 *    EDX, ESI and EDI.
 *    TODO: update to EBX, ECX, EDX, ESI, EDI, and EBP.
 *
 * 5. A system call always returns with an error number via register EAX.  All
 *    valid error numbers are listed in __error_nr. E_SUCC indicates no errors
 *    happen.
 *
 * 6. A system call can return at most 3 32-bit values via registers
 *    EDX, ESI and EDI.
 */

enum syscall_nr_t
{
    SYS_puts            = 0,    /* output a string to the screen */
    SYS_writes          = 1,    /* output a binary stream to an io device */
    SYS_gets            = 2,    /* get a char from console */
    SYS_reads           = 3,    /* read a binary stream to an io device */
    SYS_spawn           = 4,    /* create a new process */
    SYS_enable_policy   = 5,    /* enable a scheduling policy of a scheduler */
    SYS_select_server   = 6,    /* select a sever algorithm for a partition
                                 * scheduler */
    SYS_yield           = 7,    /* yield to another process */
    SYS_get_cpuid       = 8,    /* current CPU index */
    SYS_get_pid         = 9,    /* current process ID */
    SYS_send            = 10,   /* asynchronized IPC send */
    SYS_recv            = 11,   /* synchronized IPC receive */
    SYS_fast_send       = 12,   /* fast asynchronized IPC send */
    SYS_fast_recv       = 13,   /* fast synchronized IPC receive */
    SYS_sm_offer        = 14,   /* shared memory IPC offer */
    SYS_sm_status       = 15,   /* shared memory IPC status */
    SYS_get_tsc_per_ms  = 16,   /* TSC frequency in milliseconds */
    SYS_virt            = 17,   /* hypervisor call */
    SYS_start           = 18,   /* system initialization finished */
    SYS_exit            = 19,   /* process exit */
    SYS_number_of_cpus  = 20,   /* number of CPUs */
    SYS_disk            = 21,   /* disk operations */
    SYS_platform        = 22,   /* get the type of hosting platform */
    SYS_shutdown        = 23,   /* put system into power-off mode */
    SYS_reboot          = 24,   /* restart the machine */
    SYS_sleep           = 25,   /* put system into sleep mode */
    SYS_vmm_control     = 26,   /* virtual machine monitor control */
    SYS_net_transmit    = 27,   /* */
    SYS_net_receive     = 28,   /* */
    SYS_spi_slave_xfer  = 29,   /* */
    SYS_device_control  = 30,   /* */
    SYS_mmap            = 31,   /* */
    SYS_cacheflush      = 32,   /* */
    SYS_tros_node       = 33,   /* */
    SYS_tros_advertise  = 34,   /* */
    SYS_tros_subscribe  = 35,   /* */
    SYS_tros_publish    = 36,   /* */
    SYS_tros_fetch      = 37,   /* */
    SYS_tros_start      = 38,   /* */
    SYS_io_uring_setup  = 39,   /* */
    SYS_measure_syscall = 40,   /* enter syscall measurement mode */
    SYS_measure_kern    = 41,   /* measure kernel functions */
    HVC_flush_vm_context= 42,   /* */
    HVC_vcpu_run        = 43,   /* */
    SYS_enclave         = 44,   /* create an enclave node */
    SYS_world_create    = 45,   /* */
    SYS_world_start     = 46,   /* */
    SYS_set_tid_address = 47,   /* musl */
    SYS_brk             = 48,   /* change the heap size */
    SYS_mprotect        = 49,
    SYS_munmap          = 50,


    MAX_SYSCALL_NR, /* XXX: always put it at the end of __syscall_nr */
};

enum syscall_error_t
{
    SYS_E_SUCC = 0,
    SYS_E_INVALID_SYSCALL_NR,
    SYS_E_ADDR_NOT_IN_USER,
    SYS_E_ADDR_NOT_ALLOC,
    SYS_E_ADDR_NOT_ALIGNED,
    SYS_E_ID_OUT_OF_BOUNDARY,
    SYS_E_PROC_CREATE_FAILED,
    SYS_E_INVALID_PID,
    SYS_E_SIZE_OUT_OF_BOUND,
    SYS_E_PERMISSION_DENIED,
    SYS_E_GENERAL_FAIL,
    SYS_E_OPERATION_NOT_EXIST,
    SYS_E_NOT_SUPPORT,
    SYS_E_DEVICE_NOT_EXISTS,
    SYS_E_DEVICE_FAILURE,
    SYS_E_INSUFFICIENT_QUOTA,
    SYS_E_POLL_NOT_READY,
    SYS_E_INVALID_REQUEST,

    MAX_SYS_E,
};

__attribute__((weak)) const char* const syscall_func_name[MAX_SYSCALL_NR] = {
    [SYS_puts]           = "sys_puts",
    [SYS_gets]           = "sys_gets",
    [SYS_spawn]          = "sys_spawn",
    [SYS_enable_policy]  = "sys_enable_policy",
    [SYS_select_server]  = "sys_select_server",
    [SYS_yield]          = "sys_yield",
    [SYS_get_cpuid]      = "sys_get_cpuid",
    [SYS_get_pid]        = "sys_get_pid",
    [SYS_send]           = "sys_send",
    [SYS_recv]           = "sys_recv",
    [SYS_fast_send]      = "sys_fast_send",
    [SYS_fast_recv]      = "sys_fast_recv",
    [SYS_sm_offer]       = "sys_sm_offer",
    [SYS_sm_status]      = "sys_sm_status",
    [SYS_get_tsc_per_ms] = "sys_get_tsc_per_ms",
    [SYS_virt]           = "sys_virt",
    [SYS_start]          = "sys_start",
    [SYS_exit]           = "sys_exit",
    [SYS_number_of_cpus] = "sys_number_of_cpus",
    [SYS_platform]       = "sys_platform",
    [SYS_disk]           = "sys_disk",
    [SYS_vmm_control]    = "sys_vmm_control",
    [SYS_spi_slave_xfer] = "sys_spi_slave_xfer",
    [SYS_device_control] = "sys_device_control",
    [SYS_enclave]        = "sys_enclave",
    [SYS_mmap]           = "sys_mmap",
    [SYS_cacheflush]     = "sys_cacheflush",
    [SYS_tros_node]      = "sys_tros_node",
    [SYS_tros_advertise] = "sys_tros_advertise",
    [SYS_tros_subscribe] = "sys_tros_subscribe",
    [SYS_tros_publish]   = "sys_tros_publish",
    [SYS_tros_fetch]     = "sys_tros_fetch",
    [SYS_tros_start]     = "sys_tros_start",
    [SYS_io_uring_setup] = "sys_io_uring_setup",

    [SYS_measure_syscall] = "sys_measure_syscall",
    [SYS_measure_kern]    = "sys_measure_kern",

    [HVC_flush_vm_context] = "hyp_flush_vm_context",
    [HVC_vcpu_run]         = "hyp_vcpu_run",

    [SYS_world_create] = "sys_world_create",
    [SYS_world_start]  = "sys_world_start",
};

/**
 * @brief error code for system exit reasons, weakly linked, only keep one copy
 * in each address space.
 */
__attribute__((weak)) const char* const syscall_error_code[MAX_SYS_E] = {
    [SYS_E_SUCC]               = "system call successful",
    [SYS_E_INVALID_SYSCALL_NR] = "unknown syscall number",
    [SYS_E_ADDR_NOT_IN_USER]   = "address provided out of user range",
    [SYS_E_ADDR_NOT_ALLOC]     = "address provided contains unmapped pages",
    [SYS_E_ADDR_NOT_ALIGNED]   = "address provided is not aligned",
    [SYS_E_ID_OUT_OF_BOUNDARY] = "provided ID out of boundary",
    [SYS_E_PROC_CREATE_FAILED] = "process creation failed",
    [SYS_E_INVALID_PID]        = "provided invalid pid",
    [SYS_E_SIZE_OUT_OF_BOUND]  = "given size exceeds the bound",
    [SYS_E_PERMISSION_DENIED]  = "no permission to perform this operation",
    [SYS_E_GENERAL_FAIL] = "general fail, check details for the subsystem",
    [SYS_E_OPERATION_NOT_EXIST] = "no such operation",
    [SYS_E_NOT_SUPPORT]         = "not supported.",
    [SYS_E_DEVICE_NOT_EXISTS]   = "device not exists",
    [SYS_E_DEVICE_FAILURE]      = "hardware failure",
    [SYS_E_INSUFFICIENT_QUOTA]  = "insufficient quota",
    [SYS_E_POLL_NOT_READY]      = "not ready",
    [SYS_E_INVALID_REQUEST]     = "invalid request",
};


/* shared memory call */
enum syscall_sm_state_t
{
    SMC_READY   = 0u,
    SMC_PENDING = 1u,
    SMC_DEAD    = 2u,
};

/* kernel function measurement */
enum measure_kern_func_t
{
    MEASUREMENT_RESET = 0,
    MEASUREMENT_TRACK,
    MEASUREMENT_DUMP,
    MEASURE_KERN_SYS_GET_PID,
    MEASURE_KERN_SYS_GET_CPUID,
    MEASURE_PAGE_TABLE_SWITCH,
    MEASURE_MEMSET,
    MEASURE_MCS_LOCK_UNLOCK,
    MEASURE_VMCS_ACCESS,

    NUM_OF_KERN_FUNC_MEASUREMENT,
};

enum sys_disk_operation_t
{
    SYS_DISK_CAPACITY = 0,  /* read the capacity (in blocks) of the disk */
    SYS_DISK_BLK_SIZE,      /* read the block size */
    SYS_DISK_READ_BUFFER,   /* read block of the disk */
    SYS_DISK_WRITE_BUFFER,  /* write memory to the disk */
    SYS_DISK_READ_THROUGH,  /* read and flush */
    SYS_DISK_WRITE_THROUGH, /* write and flush */
    SYS_DISK_FLUSH,         /* flush the disk */
    SYS_DISK_TEST,          /* call test in test_disk */

    MAX_SYS_DISK_OP
};

struct sys_disk_io_t
{
    enum sys_disk_operation_t op;   /* operation */
    size_t                    disk; /* select a disk to perform the operation */
    uint64_t  lba; /* linear index of the block to perform the operation */
    uintptr_t va;  /* virtual address of the input / output buffer */
    size_t    n;   /* number of blocks */

    /* return values */
    uint64_t  result;
};

struct sys_spawn_param_t
{
    //TODO set proper types here
    int sched_level;
#define SYS_SCHED_LEVEL_PARTITION 0
#define SYS_SCHED_LEVEL_TASK      1

    int sched_policy;
#define SYS_SCHED_POLICY_RT_TDMA 0
#define SYS_SCHED_POLICY_RT_FP   1
#define SYS_SCHED_POLICY_RT_EDF  2
#define SYS_SCHED_POLICY_RR      3
#define SYS_SCHED_POLICY_IDLE    4

    int partition_id; /* only if sched_level == TASK */
    int period;
    int max_budget;
    int priority;
};

#define SYS_SCHED_SERVER_ALGORITHM_POLLING_SERVER      0
#define SYS_SCHED_SERVER_ALGORITHM_IDLE_POLLING_SERVER 1
#define SYS_SCHED_SERVER_ALGORITHM_DEFERRABLE_SERVER   2
#define SYS_SCHED_SERVER_ALGORITHM_SPORADIC_SERVER     3

/**
 * type of the host platform
 */
enum platform_type_t
{
    PLATFORM_HARDWARE = 0, /* real hardware */
    PLATFORM_VIRT_QEMU,
    PLATFORM_VIRT_VMWARE,
    PLATFORM_VIRT_XEN,
    PLATFORM_VIRT_GCP,
    PLATFORM_VIRT_AWS,

    MAX_PLATFORM_TYPE
};


/**
 * sys_device_control requests
 */

enum sys_device_control_request_t
{
    DEV_OPEN_CONSOLE,
    DEV_TIMER_EXPERIMENT_START,
    DEV_DEBUG,
    DEV_CONSOLE_NON_BLOCKING,
};

struct device_io_request_t
{
    char*  data;
    size_t data_size;
};



/* MMAP return */
#define MAP_FAILED ((void *) -1)

/* MMAP Flags (POSIX compliant) */
#define MAP_SHARED     0x01
#define MAP_PRIVATE    0x02
#define MAP_SHARED_VALIDATE 0x03
#define MAP_TYPE       0x0f
#define MAP_FIXED      0x10
#define MAP_ANON       0x20
#define MAP_ANONYMOUS  MAP_ANON
#define MAP_NORESERVE  0x4000
#define MAP_GROWSDOWN  0x0100
#define MAP_DENYWRITE  0x0800
#define MAP_EXECUTABLE 0x1000
#define MAP_LOCKED     0x2000
#define MAP_POPULATE   0x8000
#define MAP_NONBLOCK   0x10000
#define MAP_STACK      0x20000
#define MAP_HUGETLB    0x40000
#define MAP_SYNC       0x80000
#define MAP_FIXED_NOREPLACE 0x100000
#define MAP_FILE       0

/* mmap/mprotect prot bits */
#define PROT_NONE      0
#define PROT_READ      1
#define PROT_WRITE     2
#define PROT_EXEC      4
#define PROT_GROWSDOWN 0x01000000
#define PROT_GROWSUP   0x02000000


/* TODO make this generic */
#define IO_URING_RING_FD    (100)
#define IO_URING_SHMEM_FD   (101)
#define THINROS_FD          (200)

#endif /* !_SYSCALL_PROTOCOL_H_ */
