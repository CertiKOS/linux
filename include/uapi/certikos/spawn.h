/* SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR MIT */
/*
 * Header file for CertiKOS interface
 */
#ifndef CERTIKOS_UAPI_EXPORT_SPAWN_H
#define CERTIKOS_UAPI_EXPORT_SPAWN_H

#ifdef __cplusplus
extern "C" {
#endif

#define ENCLAVE_BIN_NAME_MAX_LEN   (0x1000)
#define ENCLAVE_ARGV_ELEM_MAX_LEN  (0x1000)
#define ENCLAVE_ENVP_ELEM_MAX_LEN  (0x1000)


struct enclave_spawn_param_t
{
    char *bin_name;
    char **argv;
    char **envp;
    int quota_pages;

    /* RT-PARAMS */
    int sched_policy;
    int partition_id;
    int period;
    int max_budget;
    int priority;
};

#ifdef __cplusplus
}
#endif

#endif
