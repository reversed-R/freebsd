#ifndef _SYS_SIGNALFD_H_
#define _SYS_SIGNALFD_H_

#include <sys/types.h>
#include <sys/fcntl.h>

struct signalfd_siginfo {
	uint32_t ssi_signo;    /* Signal number */
	int32_t ssi_errno;     /* Error number (unused) */
	int32_t ssi_code;      /* Signal code */
	uint32_t ssi_pid;      /* PID of sender */
	uint32_t ssi_uid;      /* Real UID of sender */
	int32_t ssi_fd;	       /* File descriptor (SIGIO) */
	uint32_t ssi_tid;      /* Kernel timer ID (POSIX timers) */
	uint32_t ssi_band;     /* Band event (SIGIO) */
	uint32_t ssi_overrun;  /* POSIX timer overrun count */
	uint32_t ssi_trapno;   /* Trap number that caused signal */
	int32_t ssi_status;    /* Exit status or signal (SIGCHLD) */
	int32_t ssi_int;       /* Integer sent by sigqueue(3) */
	uint64_t ssi_ptr;      /* Pointer sent by sigqueue(3) */
	uint64_t ssi_utime;    /* User CPU time consumed (SIGCHLD) */
	uint64_t ssi_stime;    /* System CPU time consumed (SIGCHLD) */
	uint64_t ssi_addr;     /* Address that generated signal (for
				  hardware-generated signals) */
	uint16_t ssi_addr_lsb; /* Least significant bit of address (SIGBUS;
				  since Linux 2.6.37) */
	uint8_t pad[40]; /* Pad size to 128 bytes (allow for additional fields
			   in the future) */
};

/* Creation flags. */
#define SFD_NONBLOCK O_NONBLOCK
#define SFD_CLOEXEC  O_CLOEXEC

#endif /* !_SYS_SIGNALFD_H_ */
