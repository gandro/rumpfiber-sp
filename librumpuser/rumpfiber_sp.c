/*	$NetBSD: rumpfiber_sp.c,v 1.4 2015/02/15 00:54:32 justin Exp $	*/

/*
 * Copyright (c) 2015 Sebastian Wicki.  All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "rumpuser_port.h"

#if !defined(lint)
__RCSID("$NetBSD: rumpfiber_sp.c,v 1.4 2015/02/15 00:54:32 justin Exp $");
#endif /* !lint */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include <rump/rump.h> /* XXX: for rfork flags */
#include <rump/rumpuser.h>

#include "rumpuser_int.h"

#include "rumpfiber.h"


////////// TODO use sp_common //////////
/*
 * Bah, I hate writing on-off-wire conversions in C
 */

enum { RUMPSP_REQ, RUMPSP_RESP, RUMPSP_ERROR };
enum {	RUMPSP_HANDSHAKE,
	RUMPSP_SYSCALL,
	RUMPSP_COPYIN, RUMPSP_COPYINSTR,
	RUMPSP_COPYOUT, RUMPSP_COPYOUTSTR,
	RUMPSP_ANONMMAP,
	RUMPSP_PREFORK,
	RUMPSP_RAISE };

enum { HANDSHAKE_GUEST, HANDSHAKE_AUTH, HANDSHAKE_FORK, HANDSHAKE_EXEC };

/*
 * error types used for RUMPSP_ERROR
 */
enum rumpsp_err { RUMPSP_ERR_NONE = 0, RUMPSP_ERR_TRYAGAIN, RUMPSP_ERR_AUTH,
	RUMPSP_ERR_INVALID_PREFORK, RUMPSP_ERR_RFORK_FAILED,
	RUMPSP_ERR_INEXEC, RUMPSP_ERR_NOMEM, RUMPSP_ERR_MALFORMED_REQUEST };

#define AUTHLEN 4 /* 128bit fork auth */

struct rsp_hdr {
	uint64_t rsp_len;
	uint64_t rsp_reqno;
	uint16_t rsp_class;
	uint16_t rsp_type;
	/*
	 * We want this structure 64bit-aligned for typecast fun,
	 * so might as well use the following for something.
	 */
	union {
		uint32_t sysnum;
		uint32_t error;
		uint32_t handshake;
		uint32_t signo;
	} u;
};
#define HDRSZ sizeof(struct rsp_hdr)
#define rsp_sysnum u.sysnum
#define rsp_error u.error
#define rsp_handshake u.handshake
#define rsp_signo u.signo

#define MAXBANNER 96

/*
 * Data follows the header.  We have two types of structured data.
 */

/* copyin/copyout */
struct rsp_copydata {
	size_t rcp_len;
	void *rcp_addr;
	uint8_t rcp_data[0];
};

/* syscall response */
struct rsp_sysresp {
	int rsys_error;
	register_t rsys_retval[2];
};

#include <stdarg.h>
#define DPRINTF(x) mydprintf x
static void
mydprintf(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

#include <sys/socket.h>
#include <sys/un.h>

#include <assert.h>
#include <fcntl.h>
#include <poll.h>


static char banner[MAXBANNER];

#define PROTOMAJOR 0
#define PROTOMINOR 4

#ifndef MAXCLI
#define MAXCLI 256
#endif

struct spservarg {
	int sps_sock;
};

#define CLI_STATE_NEW     0
#define CLI_STATE_RUNNING 1
#define CLI_STATE_DYING   2

struct client {
	int fd;
	int state;
	struct pollfd *poll_fd;
	
	struct lwp *spc_mainlwp;
	pid_t spc_pid;

	struct iovec *send_iov_base;
	struct iovec *send_iov;
	int send_iovcnt;

	struct rsp_hdr recv_hdr;
	uint8_t *recv_buf;
	size_t recv_off;
};

static struct pollfd pfdlist[MAXCLI];
static struct client clilist[MAXCLI];

#define IOVPUT(_io_, _b_) _io_.iov_base = 			\
    (void *)&_b_; _io_.iov_len = sizeof(_b_);
#define IOVPUT_WITHSIZE(_io_, _b_, _l_) _io_.iov_base =		\
    (void *)(_b_); _io_.iov_len = _l_;
#define SENDIOV(_cli_, _iov_) enqueue_send(_cli_, _iov_, __arraycount(_iov_))
////////// TODO split sp_common //////////

/*
 * Manual wrappers, since librump does not have access to the
 * user namespace wrapped interfaces.
 */

static void
lwproc_switch(struct lwp *l)
{

	rumpuser__hyp.hyp_schedule();
	rumpuser__hyp.hyp_lwproc_switch(l);
	rumpuser__hyp.hyp_unschedule();
}

static void
lwproc_release(void)
{

	rumpuser__hyp.hyp_schedule();
	rumpuser__hyp.hyp_lwproc_release();
	rumpuser__hyp.hyp_unschedule();
}

static int
lwproc_rfork(void *ptr, int flags, const char *comm)
{
	int rv;

	rumpuser__hyp.hyp_schedule();
	rv = rumpuser__hyp.hyp_lwproc_rfork(ptr, flags, comm);
	rumpuser__hyp.hyp_unschedule();

	return rv;
}

static int
lwproc_newlwp(pid_t pid)
{
	int rv;

	rumpuser__hyp.hyp_schedule();
	rv = rumpuser__hyp.hyp_lwproc_newlwp(pid);
	rumpuser__hyp.hyp_unschedule();

	return rv;
}

static struct lwp *
lwproc_curlwp(void)
{
	struct lwp *l;

	rumpuser__hyp.hyp_schedule();
	l = rumpuser__hyp.hyp_lwproc_curlwp();
	rumpuser__hyp.hyp_unschedule();

	return l;
}

static pid_t
lwproc_getpid(void)
{
	pid_t p;

	rumpuser__hyp.hyp_schedule();
	p = rumpuser__hyp.hyp_getpid();
	rumpuser__hyp.hyp_unschedule();

	return p;
}

static void
lwproc_execnotify(const char *comm)
{

	rumpuser__hyp.hyp_schedule();
	rumpuser__hyp.hyp_execnotify(comm);
	rumpuser__hyp.hyp_unschedule();
}

static void
lwproc_lwpexit(void)
{

	rumpuser__hyp.hyp_schedule();
	rumpuser__hyp.hyp_lwpexit();
	rumpuser__hyp.hyp_unschedule();
}

static int
rumpsyscall(int sysnum, void *data, register_t *regrv)
{
	long retval[2] = {0, 0};
	int rv;

	rumpuser__hyp.hyp_schedule();
	rv = rumpuser__hyp.hyp_syscall(sysnum, data, retval);
	rumpuser__hyp.hyp_unschedule();

	regrv[0] = retval[0];
	regrv[1] = retval[1];
	return rv;
}

static int
enqueue_send(struct client *cli, struct iovec *iov, int iovcnt)
{
	struct iovec *iov_base;

	/* ensure client is not being polled */
	assert(cli->poll_fd->fd < 0);
	
	if (iovcnt < 0)
		return EINVAL;
	
	/* copy input, since it might outlive the caller */
	iov_base = malloc(sizeof(*iov) * iovcnt);
	if (iov_base == NULL)
		return ENOMEM;

	memcpy(iov_base, iov, sizeof(*iov) * iovcnt);

	cli->send_iov = cli->send_iov_base = iov_base;
	cli->send_iovcnt = iovcnt;
	DPRINTF(("rump_sp: set to send for %d\n", cli->fd));

	cli->poll_fd->events = POLLOUT;
	cli->poll_fd->fd = cli->fd;
	
	return 0;
}

static void
reset_recv(struct client *cli)
{
	free(cli->recv_buf);
	cli->recv_buf = NULL;
	cli->recv_off = 0;
}

static int
handle_send(struct client *cli)
{
	struct msghdr msg;
	ssize_t nbytes = 0;

	assert(cli->poll_fd->events == POLLOUT);

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = cli->send_iov;
	msg.msg_iovlen = cli->send_iovcnt;

	nbytes = sendmsg(cli->fd, &msg, MSG_NOSIGNAL);
	DPRINTF(("rump_sp: sendmsg on fd %d returned %zd\n", cli->fd, nbytes));
	if (nbytes == -1)  {
		if (errno == EPIPE)
			return ENOTCONN;
		if (errno != EAGAIN)
			return errno;
		return  0;
	}
	if (nbytes == 0) {
		return ENOTCONN;
	}
		
	while ((nbytes >= (ssize_t)cli->send_iov[0].iov_len) 
		&& cli->send_iovcnt)
	{
		nbytes -= cli->send_iov[0].iov_len;

		cli->send_iov++;
		cli->send_iovcnt--;
	}
	if (cli->send_iovcnt > 0) {
		/* adjust left-overs */
		cli->send_iov[0].iov_base = (void *)
			((uint8_t *)cli->send_iov[0].iov_base + nbytes);
		cli->send_iov[0].iov_len -= nbytes;
	} else {
		DPRINTF(("rump_sp: set to receive for %d\n", cli->fd));
		/* cleanup, set to receive */
		reset_recv(cli);
		cli->poll_fd->events = POLLIN;
		free(cli->send_iov_base);
	}
	
	return 0;
}

static int
handle_recv(struct client *cli)
{
	int fd = cli->fd;
	size_t left;
	size_t framelen;
	ssize_t n;
	

	assert(cli->poll_fd->events == POLLIN);

	/* still reading header? */
	if (cli->recv_off < HDRSZ) {
		DPRINTF(("rump_sp: getting header at offset %zu\n",
		    cli->recv_off));

		left = HDRSZ - cli->recv_off;
		/*LINTED: cast ok */
		n = read(fd, (uint8_t*)&cli->recv_hdr + cli->recv_off, left);
		if (n == 0) {
			return -1;
		}
		if (n == -1) {
			if (errno == EAGAIN)
				return 0;
			return -1;
		}

		cli->recv_off += n;
		if (cli->recv_off < HDRSZ) {
			return 0;
		}

		/*LINTED*/
		framelen = cli->recv_hdr.rsp_len;

		if (framelen < HDRSZ) {
			return -1;
		} else if (framelen == HDRSZ) {
			goto success;
		}

		cli->recv_buf = malloc(framelen - HDRSZ);
		if (cli->recv_buf == NULL) {
			return -1;
		}
		memset(cli->recv_buf, 0, framelen - HDRSZ);

		/* "fallthrough" */
	} else {
		/*LINTED*/
		framelen = cli->recv_hdr.rsp_len;
	}

	left = framelen - cli->recv_off;

#if 0
	DPRINTF(("rump_sp: readframe getting body at offset %zu, left %zu\n",
	    cli->recv_off, left));
#endif
	if (left == 0)
		goto success;

	n = read(fd, cli->recv_buf + (cli->recv_off - HDRSZ), left);
	if (n == 0) {
		return -1;
	}
	if (n == -1) {
		if (errno == EAGAIN)
			return 0;
		return -1;
	}
	cli->recv_off += n;
	left -= n;
	
	if (left > 0)
		return 0;

success:
		DPRINTF(("rump_sp: disable polling for %d\n", cli->fd));
		cli->poll_fd->fd = -1;
		cli->poll_fd->events = 0;
		return 1;
}

static void
send_error_resp(struct client *cli, uint64_t reqno, enum rumpsp_err error)
{
	struct rsp_hdr rhdr;
	struct iovec iov[1];

	rhdr.rsp_len = sizeof(rhdr);
	rhdr.rsp_reqno = reqno;
	rhdr.rsp_class = RUMPSP_ERROR;
	rhdr.rsp_type = 0;
	rhdr.rsp_error = error;

	IOVPUT(iov[0], rhdr);

	(void)SENDIOV(cli, iov);
}

static int
send_handshake_resp(struct client *cli, uint64_t reqno, int error)
{
	struct rsp_hdr rhdr;
	struct iovec iov[2];
	int rv;

	rhdr.rsp_len = sizeof(rhdr) + sizeof(error);
	rhdr.rsp_reqno = reqno;
	rhdr.rsp_class = RUMPSP_RESP;
	rhdr.rsp_type = RUMPSP_HANDSHAKE;
	rhdr.rsp_error = 0;

	IOVPUT(iov[0], rhdr);
	IOVPUT(iov[1], error);
	
	rv = SENDIOV(cli, iov);
	
	return rv;
}

static int
send_syscall_resp(struct client *cli, uint64_t reqno, int error,
	register_t *retval)
{
	struct rsp_hdr rhdr;
	struct rsp_sysresp sysresp;
	struct iovec iov[2];
	int rv;

	rhdr.rsp_len = sizeof(rhdr) + sizeof(sysresp);
	rhdr.rsp_reqno = reqno;
	rhdr.rsp_class = RUMPSP_RESP;
	rhdr.rsp_type = RUMPSP_SYSCALL;
	rhdr.rsp_sysnum = 0;

	sysresp.rsys_error = error;
	memcpy(sysresp.rsys_retval, retval, sizeof(sysresp.rsys_retval));

	DPRINTF(("rump_sp: syscall response of size %zu\n", rhdr.rsp_len));

	IOVPUT(iov[0], rhdr);
	IOVPUT(iov[1], sysresp);

	rv = SENDIOV(cli, iov);

	return rv;
}

static void 
handle_syscall(struct client *cli)
{
	register_t retval[2] = {0, 0};
	struct rsp_hdr *rhdr = &cli->recv_hdr;
	uint8_t *data = cli->recv_buf;
	int rv, sysnum;

	sysnum = (int)rhdr->rsp_sysnum;
	DPRINTF(("rump_sp: handling syscall %d from client %d\n",
	    sysnum, cli->spc_pid));

	if (__predict_false((rv = lwproc_newlwp(cli->spc_pid)) != 0)) {
		retval[0] = -1;
		send_syscall_resp(cli, rhdr->rsp_reqno, rv, retval);
		return;
	}
	//cli->spc_syscallreq = rhdr->rsp_reqno;
	rv = rumpsyscall(sysnum, data, retval);
	//spc->spc_syscallreq = 0;
	lwproc_release();

	DPRINTF(("rump_sp: got return value %d & %d/%d\n",
	    rv, retval[0], retval[1]));

	send_syscall_resp(cli, rhdr->rsp_reqno, rv, retval);
}

static void
handle_req(struct client *cli)
{
	uint64_t reqno;
	int error;

	DPRINTF(("rump_sp: handle req type: %"PRIu16" len: %"PRIu64" class: %"PRIu16" reqno: %"PRIu64"\n",
		cli->recv_hdr.rsp_type,
		cli->recv_hdr.rsp_len,
		cli->recv_hdr.rsp_class,
		cli->recv_hdr.rsp_reqno));

	reqno = cli->recv_hdr.rsp_reqno;
	if (__predict_false(cli->state == CLI_STATE_NEW)) {
		if (cli->recv_hdr.rsp_type != RUMPSP_HANDSHAKE) {
			//send_error_resp(spc, reqno, RUMPSP_ERR_AUTH);
			shutdown(cli->fd, SHUT_RDWR);
			//spcfreebuf(spc);*/
			return;
		}

		if (cli->recv_hdr.rsp_handshake == HANDSHAKE_GUEST) {
			char *comm = (char *)cli->recv_buf;
			size_t commlen = cli->recv_hdr.rsp_len - HDRSZ;

			/* ensure it's 0-terminated */
			/* XXX make sure it contains sensible chars? */
			comm[commlen] = '\0';

			/* make sure we fork off of proc1 */
			_DIAGASSERT(lwproc_curlwp() == NULL);

			if ((error = lwproc_rfork(cli,
			    RUMP_RFFD_CLEAR, comm)) != 0) {
				shutdown(cli->fd, SHUT_RDWR);
			}

			//spcfreebuf(spc);
			if (error)
				return;

			cli->spc_mainlwp = lwproc_curlwp();

			send_handshake_resp(cli, reqno, 0);
		} else if (cli->recv_hdr.rsp_handshake == HANDSHAKE_FORK) {
			DPRINTF(("FORK HANDSHAKE\n"));
#if 0
			struct lwp *tmpmain;
			struct prefork *pf;
			struct handshake_fork *rfp;
			int cancel;

			if (spc->spc_off-HDRSZ != sizeof(*rfp)) {
				send_error_resp(spc, reqno,
				    RUMPSP_ERR_MALFORMED_REQUEST);
				shutdown(spc->spc_fd, SHUT_RDWR);
				spcfreebuf(spc);
				return;
			}

			/*LINTED*/
			rfp = (void *)spc->spc_buf;
			cancel = rfp->rf_cancel;

			pthread_mutex_lock(&pfmtx);
			LIST_FOREACH(pf, &preforks, pf_entries) {
				if (memcmp(rfp->rf_auth, pf->pf_auth,
				    sizeof(rfp->rf_auth)) == 0) {
					LIST_REMOVE(pf, pf_entries);
					LIST_REMOVE(pf, pf_spcentries);
					break;
				}
			}
			pthread_mutex_unlock(&pfmtx);
			spcfreebuf(spc);

			if (!pf) {
				send_error_resp(spc, reqno,
				    RUMPSP_ERR_INVALID_PREFORK);
				shutdown(spc->spc_fd, SHUT_RDWR);
				return;
			}

			tmpmain = pf->pf_lwp;
			free(pf);
			lwproc_switch(tmpmain);
			if (cancel) {
				lwproc_release();
				shutdown(spc->spc_fd, SHUT_RDWR);
				return;
			}

			/*
			 * So, we forked already during "prefork" to save
			 * the file descriptors from a parent exit
			 * race condition.  But now we need to fork
			 * a second time since the initial fork has
			 * the wrong spc pointer.  (yea, optimize
			 * interfaces some day if anyone cares)
			 */
			if ((error = lwproc_rfork(spc,
			    RUMP_RFFD_SHARE, NULL)) != 0) {
				send_error_resp(spc, reqno,
				    RUMPSP_ERR_RFORK_FAILED);
				shutdown(spc->spc_fd, SHUT_RDWR);
				lwproc_release();
				return;
			}
			spc->spc_mainlwp = lwproc_curlwp();
			lwproc_switch(tmpmain);
			lwproc_release();
			lwproc_switch(spc->spc_mainlwp);

			send_handshake_resp(spc, reqno, 0);
#endif
		} else {
			//send_error_resp(spc, reqno, RUMPSP_ERR_AUTH);
			shutdown(cli->fd, SHUT_RDWR);
			//spcfreebuf(spc);
			return;
		}

		cli->spc_pid = lwproc_getpid();

		DPRINTF(("rump_sp: handshake for client %p complete, pid %d\n",
		    cli, cli->spc_pid));
		    
		lwproc_switch(NULL);
		cli->state = CLI_STATE_RUNNING;
		return;
	}
#if 0
	if (__predict_false(spc->spc_hdr.rsp_type == RUMPSP_PREFORK)) {
		struct prefork *pf;
		uint32_t auth[AUTHLEN];
		size_t randlen;
		int inexec;

		DPRINTF(("rump_sp: prefork handler executing for %p\n", spc));
		spcfreebuf(spc);

		pthread_mutex_lock(&spc->spc_mtx);
		inexec = spc->spc_inexec;
		pthread_mutex_unlock(&spc->spc_mtx);
		if (inexec) {
			send_error_resp(spc, reqno, RUMPSP_ERR_INEXEC);
			shutdown(spc->spc_fd, SHUT_RDWR);
			return;
		}

		pf = malloc(sizeof(*pf));
		if (pf == NULL) {
			send_error_resp(spc, reqno, RUMPSP_ERR_NOMEM);
			return;
		}

		/*
		 * Use client main lwp to fork.  this is never used by
		 * worker threads (except in exec, but we checked for that
		 * above) so we can safely use it here.
		 */
		lwproc_switch(spc->spc_mainlwp);
		if ((error = lwproc_rfork(spc, RUMP_RFFD_COPY, NULL)) != 0) {
			DPRINTF(("rump_sp: fork failed: %d (%p)\n",error, spc));
			send_error_resp(spc, reqno, RUMPSP_ERR_RFORK_FAILED);
			lwproc_switch(NULL);
			free(pf);
			return;
		}

		/* Ok, we have a new process context and a new curlwp */
		rumpuser_getrandom(auth, sizeof(auth), 0, &randlen);
		memcpy(pf->pf_auth, auth, sizeof(pf->pf_auth));
		pf->pf_lwp = lwproc_curlwp();
		lwproc_switch(NULL);

		pthread_mutex_lock(&pfmtx);
		LIST_INSERT_HEAD(&preforks, pf, pf_entries);
		LIST_INSERT_HEAD(&spc->spc_pflist, pf, pf_spcentries);
		pthread_mutex_unlock(&pfmtx);

		DPRINTF(("rump_sp: prefork handler success %p\n", spc));

		send_prefork_resp(spc, reqno, auth);
		return;
	}

	if (__predict_false(spc->spc_hdr.rsp_type == RUMPSP_HANDSHAKE)) {
		int inexec;

		if (spc->spc_hdr.rsp_handshake != HANDSHAKE_EXEC) {
			send_error_resp(spc, reqno,
			    RUMPSP_ERR_MALFORMED_REQUEST);
			shutdown(spc->spc_fd, SHUT_RDWR);
			spcfreebuf(spc);
			return;
		}

		pthread_mutex_lock(&spc->spc_mtx);
		inexec = spc->spc_inexec;
		pthread_mutex_unlock(&spc->spc_mtx);
		if (inexec) {
			send_error_resp(spc, reqno, RUMPSP_ERR_INEXEC);
			shutdown(spc->spc_fd, SHUT_RDWR);
			spcfreebuf(spc);
			return;
		}

		pthread_mutex_lock(&spc->spc_mtx);
		spc->spc_inexec = 1;
		pthread_mutex_unlock(&spc->spc_mtx);

		/*
		 * start to drain lwps.  we will wait for it to finish
		 * in another thread
		 */
		lwproc_switch(spc->spc_mainlwp);
		lwproc_lwpexit();
		lwproc_switch(NULL);

		/*
		 * exec has to wait for lwps to drain, so finish it off
		 * in another thread
		 */
		schedulework(spc, SBA_EXEC);
		return;
	}
#endif
	if (__predict_false(cli->recv_hdr.rsp_type != RUMPSP_SYSCALL)) {
		send_error_resp(cli, reqno, RUMPSP_ERR_MALFORMED_REQUEST);
		//spcfreebuf(spc);
		return;
	}
	
	handle_syscall(cli);
}

static unsigned int
handle_conn(int fd)
{
	int i, newfd, flags;
	struct iovec iov[1];
	struct sockaddr_storage ss;
	socklen_t sl = sizeof(ss);
	
	newfd = accept(fd, (struct sockaddr *)&ss, &sl);
	if (newfd == -1)
		return 0;

	flags = fcntl(newfd, F_GETFL, 0);
	if (fcntl(newfd, F_SETFL, flags | O_NONBLOCK) == -1) {
		close(newfd);
		return 0;
	}

	/* grab first free slot */
	for (i = 0; i < MAXCLI; i++) {
		if (clilist[i].fd == -1)
			break;
	}
	
	if (i == MAXCLI) {
		/* EBUSY */
		close(newfd);
		return 0;
	}

	pfdlist[i].fd = -1;
	pfdlist[i].events = 0;
	clilist[i].fd = newfd;
	clilist[i].poll_fd = &pfdlist[i];
	
	IOVPUT_WITHSIZE(iov[0], &banner, strlen(banner));
	SENDIOV(&clilist[i], iov);

	DPRINTF(("rump_sp: added new connection fd %d at idx %u\n", newfd, i));

	return i;
}



static void
mainloop(void *arg)
{
	int rv, seen;
	unsigned int idx, maxidx, newidx;
	struct spservarg *sarg = arg;
	struct client *cli = NULL;

	for (idx = 0; idx < MAXCLI; idx++) {
		pfdlist[idx].fd = -1;
		clilist[idx].fd = -1;
	}

	pfdlist[0].fd = clilist[0].fd = sarg->sps_sock;
	pfdlist[0].events = POLLIN;
	maxidx = 0;

	DPRINTF(("rump_sp: server mainloop\n"));

	for (;;) {
		rv = poll(pfdlist, maxidx+1, 0);
		
		if (rv == 0) {
			/* nothing to do */
			schedule();
			continue;
		} else if (rv == -1) {
			if(errno != EINTR) { // TODO handle EAGAIN?
				fprintf(stderr, 
					"rump_spserver: poll returned %d\n",
			 		errno);
			 	return;
			}
			continue;
		}

		seen = 0;
		for (idx = 0; seen < rv && idx <= maxidx; idx++) {
			if (!(pfdlist[idx].revents & (POLLIN|POLLOUT)))
				continue;
			seen++;
			if (idx > 0) {
				cli = &clilist[idx];
				if (pfdlist[idx].revents & POLLIN) {
					rv = handle_recv(cli);
					if (rv == 1) {
						handle_req(cli);
					} else if (rv == -1) {
						fprintf(stderr, 
						"cannot receive");
					}
				} else if (pfdlist[idx].revents & POLLOUT) {
					handle_send(cli);
				}
			} else {
				DPRINTF(("rump_sp: handle new connection\n"));
				newidx = handle_conn(pfdlist[0].fd);
				
				if (!newidx)
					continue;
				
				if (newidx > maxidx)
					maxidx = newidx;
				DPRINTF(("rump_sp: maxid now %d\n", maxidx));
			}
		}
	}
}

/*ARGSUSED*/
int
rumpuser_sp_init(const char *url,
	const char *ostype, const char *osrelease, const char *machine)
{
	// TODO port parseurl() from sp_common
	struct thread *thr;
	struct spservarg *sarg;
	struct sockaddr_un s_un;
	socklen_t slen;
	int error = 0, s;

	snprintf(banner, sizeof(banner), "RUMPSP-%d.%d-%s-%s/%s\n",
	    PROTOMAJOR, PROTOMINOR, ostype, osrelease, machine);

	s = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (s == -1) {
		error = errno;
		goto out;
	}

	sarg = malloc(sizeof(*sarg));
	if (sarg == NULL) {
		close(s);
		error = ENOMEM;
		goto out;
	}

	memset(&s_un, 0, sizeof(s_un));
	s_un.sun_family = AF_LOCAL;
	strcpy(s_un.sun_path, "/tmp/fibersock");
	slen = strlen(s_un.sun_path) + sizeof(s_un.sun_family);
	unlink(s_un.sun_path);

	sarg->sps_sock = s;

	if (bind(s, (struct sockaddr *)&s_un, slen) == -1) {
		error = errno;
		fprintf(stderr, "rump_sp: failed to bind to URL %s\n", url);
		goto out;
	}
	if (listen(s, MAXCLI) == -1) {
		error = errno;
		fprintf(stderr, "rump_sp: server listen failed\n");
		goto out;
	}

	thr = create_thread("rump_sp_server", NULL, mainloop, sarg, NULL, 0);
	if (!thr) {
		// TODO are there other reasons for failing?
		error = ENOMEM;
	}
	
	// TODO figure out how to schedule server thread in background
	for (;;) {
		schedule();
	}
 out:
	ET(error);
}

/*ARGSUSED*/
void
rumpuser_sp_fini(void *arg)
{

}

/*ARGSUSED*/
int
rumpuser_sp_raise(void *arg, int signo)
{

	abort();
}

/*ARGSUSED*/
int
rumpuser_sp_copyin(void *arg, const void *raddr, void *laddr, size_t len)
{

	abort();
}

/*ARGSUSED*/
int
rumpuser_sp_copyinstr(void *arg, const void *raddr, void *laddr, size_t *len)
{

	abort();
}

/*ARGSUSED*/
int
rumpuser_sp_copyout(void *arg, const void *laddr, void *raddr, size_t dlen)
{

	abort();
}

/*ARGSUSED*/
int
rumpuser_sp_copyoutstr(void *arg, const void *laddr, void *raddr, size_t *dlen)
{

	abort();
}

/*ARGSUSED*/
int
rumpuser_sp_anonmmap(void *arg, size_t howmuch, void **addr)
{

	abort();
}
