#ifndef _APP_H_
#define _APP_H_

/**
 * @file app.h
 * Note: automatically generated, do not modify!
 */

#define KCONF_SECURE_WORLD_DMA      (NO)
#define KCONF_SECURE_WORLD_PRIMARY_UART_IRQ      (NO)
#define KCONF_SECURE_WORLD_SECONDARY_UART_IRQ      (NO)
#define KCONF_RPI_MINIUART_DEFAULT      (YES)
#define THINROS_BENCHMARK_TOPICS      (NO)

#ifndef __ASSEMBLER__

enum user_process_type
{
	USR_NORMAL,
	USR_ENCLAVE,

	MAX_USR_PROC_TYPES
};

enum user_processes
{
	BINARY_PROC_IO_URING_DEMO = 0,
	BINARY_PROC_MUSL_DEMO = 1,

	MAX_PROC_BINARIES
};

__attribute__((weak)) const char * user_process_names[2] =
{
	[BINARY_PROC_IO_URING_DEMO] = "io_uring_demo",
	[BINARY_PROC_MUSL_DEMO] = "musl_demo",
};

__attribute__((weak)) const int user_process_quotas[2] =
{
	[BINARY_PROC_IO_URING_DEMO] = 128,
	[BINARY_PROC_MUSL_DEMO] = 128,
};

#ifdef _KERN_
extern const enum user_process_type elf_binary_type[2];
extern unsigned int quota_cpu[6];

extern const char ** user_process_argv[];
extern const char ** user_process_envp[];

extern const int user_process_argv_size[];
extern const int user_process_envp_size[];

#endif /* _KERN_ */

__attribute__((unused)) static const char * app_suite_name  =
    "io_uring_demo";

#endif /* !__ASSEMBLER__ */
#endif /* !_APP_H_ */