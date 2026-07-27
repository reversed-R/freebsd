// clangd-format off
#include <sys/proc.h>
// clangd-format on
#include <sys/file.h>
#include <sys/mutex.h>
#include <sys/poll.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/sysproto.h>
#include <sys/uio.h>

#include "security/audit/audit.h"
#include "sys/filedesc.h"
#include "sys/selinfo.h"
#include "sys/signalvar.h"
#include "sys/syscallsubr.h"
#include "sys/systm.h"

static MALLOC_DEFINE(M_SIGNALFD, "signalfd", "signalfd structures");

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
	sigset_t sfd_mask;

	/* Used internally. */
	struct signalfd_siginfo sfd_info; /* (s) signal info */
	struct mtx sfd_lock;		  /* sfd mtx lock */

	// /* For stat(2). */
	// ino_t sfd_ino;		      /* (c) inode number */
	// struct timespec sfd_atim;     /* (s) time of last read */
	// struct timespec sfd_mtim;     /* (s) time of last settime */
	// struct timespec sfd_birthtim; /* (c) creation time */
};

static void
siginfo_from_ksiginfo(struct signalfd_siginfo *si, ksiginfo_t *ksi)
{
	si->ssi_signo = ksi->ksi_info.si_signo;
	si->ssi_code = ksi->ksi_info.si_code;
	si->ssi_pid = ksi->ksi_info.si_pid;
	si->ssi_uid = ksi->ksi_info.si_uid;
	si->ssi_errno = ksi->ksi_info.si_errno;
	si->ssi_status = ksi->ksi_info.si_status;
	si->ssi_addr = (uint64_t)(uintptr_t)ksi->ksi_info.si_addr;
	si->ssi_int = ksi->ksi_info.si_value.sival_int;
	si->ssi_ptr = (uint64_t)(uintptr_t)ksi->ksi_info.si_value.sival_ptr;
	si->ssi_tid = ksi->ksi_info.si_timerid;
	si->ssi_band = (uint32_t)ksi->ksi_info.si_band;
}

static int
signalfd_read(struct file *fp, struct uio *uio, struct ucred *active_cred,
    int flags, struct thread *td)
{
	struct proc *p = td->td_proc;
	struct signalfd *sfd = fp->f_data;
	struct signalfd_siginfo si;
	ksiginfo_t ksi;
	int error = 0, sig = 0;

	if (uio->uio_resid < sizeof(struct signalfd_siginfo))
		return (EINVAL);

	PROC_LOCK(p);
retry:
	for (int i = 1; i <= _SIG_MAXSIG; i++) {
		if (SIGISMEMBER(sfd->sfd_mask, i) &&
		    SIGISMEMBER(p->p_siglist, i)) {
			sig = i;
			break;
		}
	}

	if (sig == 0) {
		if (fp->f_flag & FNONBLOCK) {
			/* nonblocking */
			PROC_UNLOCK(p);
			return (EAGAIN);
		} else {
			/* blocking */
			error = msleep(&p->p_signalfd_sel, &p->p_mtx, PCATCH,
			    "sfdrd", 0);
			if (error == 0)
				goto retry;
			PROC_UNLOCK(p);
			return (error);
		}
	}

	sigqueue_get(&p->p_sigqueue, sig, &ksi);
	PROC_UNLOCK(p);

	bzero(&si, sizeof(struct signalfd_siginfo));
	siginfo_from_ksiginfo(&si, &ksi);
	error = uiomove(&si, sizeof(struct signalfd_siginfo), uio);
	return (error);
}

static int
signalfd_poll(struct file *fp, int events, struct ucred *active_cred,
    struct thread *td)
{
	struct proc *p = td->td_proc;
	struct signalfd *sfd = fp->f_data;
	sigset_t pending;
	int revents = 0;

	PROC_LOCK(p);
	if (events & (POLLIN | POLLRDNORM)) {
		pending = p->p_siglist;
		SIGSETAND(pending, sfd->sfd_mask);
		if (SIGNOTEMPTY(pending))
			revents |= events & (POLLIN | POLLRDNORM);
	}
	if (revents == 0)
		selrecord(td, &p->p_signalfd_sel);
	PROC_UNLOCK(p);

	return (revents);
}

static int
signalfd_close(struct file *fp, struct thread *td)
{
	struct signalfd *sfd = fp->f_data;

	mtx_destroy(&sfd->sfd_lock);
	free(sfd, M_SIGNALFD);
	fp->f_ops = &badfileops;

	return (0);
}

static const struct fileops signalfdops = {
	.fo_read = signalfd_read,
	.fo_write = invfo_rdwr,
	.fo_truncate = invfo_truncate,
	// .fo_ioctl = signalfd_ioctl,
	.fo_poll = signalfd_poll,
	// .fo_kqfilter = signalfd_kqfilter,
	// .fo_stat = signalfd_stat,
	.fo_close = signalfd_close,
	.fo_chmod = invfo_chmod,
	.fo_chown = invfo_chown,
	.fo_sendfile = invfo_sendfile,
	// .fo_fill_kinfo = signalfd_fill_kinfo,
	.fo_cmp = file_kcmp_generic,
	.fo_flags = DFLAG_PASSABLE,
};

// @mask: must be kernel pointer
int
kern_signalfd(struct thread *td, int fd, sigset_t *mask, int flags)
{
	struct file *fp;
	struct signalfd *sfd;
	int error, new_fd, fflags;

	AUDIT_ARG_VALUE(fd);
	AUDIT_ARG_FFLAGS(flags);

	/* check mask */
	SIG_CANTMASK(*mask);

	/* validate and set fflags */
	if ((flags & ~(SFD_CLOEXEC | SFD_NONBLOCK)) != 0)
		return (EINVAL);

	fflags = FREAD;
	if ((flags & SFD_CLOEXEC) != 0)
		fflags |= O_CLOEXEC;
	if ((flags & SFD_NONBLOCK) != 0)
		fflags |= FNONBLOCK;

	if (fd >= 0) {
		/* bind with existing fd */
		error = fget(td, fd, &cap_no_rights, &fp);
		if (error != 0)
			return (error);

		if (fp->f_type != DTYPE_SIGNALFD) {
			fdrop(fp, td);
			return (EINVAL);
		}

		sfd = fp->f_data;

		mtx_lock(&sfd->sfd_lock);
		sfd->sfd_mask = *mask;
		mtx_unlock(&sfd->sfd_lock);

		fdrop(fp, td);

		td->td_retval[0] = fd;
		return (0);
	} else if (fd == -1) {
		/* allocate new fd */
		error = falloc(td, &fp, &new_fd, fflags);
		if (error != 0)
			return (error);

		sfd = malloc(sizeof(*sfd), M_SIGNALFD, M_WAITOK | M_ZERO);
		if (sfd == NULL)
			return ENOMEM;
		sfd->sfd_mask = *mask;
		mtx_init(&sfd->sfd_lock, "signalfd", NULL, MTX_DEF);

		finit(fp, fflags, DTYPE_SIGNALFD, sfd, &signalfdops);
		fdrop(fp, td);

		td->td_retval[0] = new_fd;
		return (0);
	} else {
		return (EINVAL);
	}
}

int
sys_signalfd(struct thread *td, struct signalfd_args *uap)
{
	sigset_t mask;
	int error;

	error = copyin(uap->mask, &mask, sizeof(mask));
	if (error != 0)
		return (error);

	return (kern_signalfd(td, uap->fd, &mask, uap->flags));
}
