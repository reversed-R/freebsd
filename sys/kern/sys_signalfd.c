#include <sys/file.h>
#include <sys/mutex.h>
#include <sys/poll.h>
#include <sys/proc.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/uio.h>

/*
 * One structure allocated per timerfd descriptor.
 *
 * Locking semantics:
 * (s)	locked by sfd_lock mtx
 * (l)	locked by signalfd_list_lock sx
 * (c)	const until freeing
 */
struct signalfd {
	/* User specified. */
	struct itimerspec sfd_time; /* (s) sfd timer */
	clockid_t sfd_clockid;	    /* (c) timing base */
	int sfd_flags;		    /* (c) creation flags */
	int sfd_timflags;	    /* (s) timer flags */

	/* Used internally. */
	struct signalfd_siginfo sfd_info; /* (s) signal info */
	bool sfd_expired;		  /* (s) true upon initial expiration */
	struct mtx sfd_lock;		  /* sfd mtx lock */
	struct callout sfd_callout;	  /* (s) expiration notification */
	struct selinfo sfd_sel;		  /* (s) I/O alerts */
	struct timespec sfd_boottim;	  /* (s) cached boottime */
	int sfd_jumped;			  /* (s) timer jump status */
	LIST_ENTRY(timerfd) entry;	  /* (l) entry in list */

	/* For stat(2). */
	ino_t sfd_ino;		      /* (c) inode number */
	struct timespec sfd_atim;     /* (s) time of last read */
	struct timespec sfd_mtim;     /* (s) time of last settime */
	struct timespec sfd_birthtim; /* (c) creation time */
};

static int
signalfd_read(struct file *fp, struct uio *uio, struct ucred *active_cred,
    int flags, struct thread *td)
{
	struct signalfd *sfd = fp->f_data;
	struct signalfd_siginfo *info;
	int error = 0;

	if (uio->uio_resid < sizeof(struct signalfd_siginfo))
		return (EINVAL);

	// TODO:
	//
	// mtx_lock(&sfd->sfd_lock);
	// info = &sfd->sfd_info;
	// mtx_unlock(&sfd->sfd_lock);

	error = uiomove(info, sizeof(struct signalfd_siginfo), uio);

	return (error);
}

static int
signalfd_poll(struct file *fp, int events, struct ucred *active_cred,
    struct thread *td)
{
	struct signalfd *sfd = fp->f_data;
	int revents = 0;

	// TODO:

	return (revents);
}

static const struct fileops signalfdops = {
	.fo_read = signalfd_read,
	.fo_write = invfo_rdwr,
	.fo_truncate = invfo_truncate,
	// .fo_ioctl = signalfd_ioctl,
	.fo_poll = signalfd_poll,
	// .fo_kqfilter = signalfd_kqfilter,
	// .fo_stat = signalfd_stat,
	// .fo_close = signalfd_close,
	.fo_chmod = invfo_chmod,
	.fo_chown = invfo_chown,
	.fo_sendfile = invfo_sendfile,
	// .fo_fill_kinfo = signalfd_fill_kinfo,
	.fo_cmp = file_kcmp_generic,
	.fo_flags = DFLAG_PASSABLE,
};
