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
 
#define QUEUEDEBUG
 

#include "rumpuser_port.h"

#include <sys/queue.h>

#include <assert.h>
#include <fcntl.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include <rump/rump.h> /* for rfork flags */
#include <rump/rumpuser.h>

#include "rumpuser_int.h"
#include "rumpfiber.h"
#include "rumpuser_sp.h"

#include "rumpsp_sock.c"

#define PROTOMAJOR 0
#define PROTOMINOR 4

#define DEBUG
#ifdef DEBUG
#define DPRINTF(x) mydprintf x
static void
mydprintf(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}
#else
#define DPRINTF(x)
#endif

#define IOVPUT(_io_, _b_) _io_.iov_base = 			\
    (void *)&_b_; _io_.iov_len = sizeof(_b_);
#define IOVPUT_WITHSIZE(_io_, _b_, _l_) _io_.iov_base =		\
    (void *)(_b_); _io_.iov_len = _l_;
#define SENDIOV(_cl_, _iov_) client_send(_cl_, _iov_, __arraycount(_iov_))

static char banner[MAXBANNER];

#define CLIENT_STATE_NEW	0
#define CLIENT_STATE_RUNNING	1
#define CLIENT_STATE_DYING	2

struct sp_client;

#define IOFLAG_STATUS_WAITING	0
#define IOFLAG_STATUS_DONE	1
#define IOFLAG_STATUS_FAILED	2

struct ioflag {
	int status;
	struct thread *waiter;
};

struct iorespbuf {
	uint64_t reqno;

	struct rsp_hdr resp_hdr;
	uint8_t *resp_data;
	size_t resp_dlen;

	TAILQ_ENTRY(iorespbuf) entries;
	struct ioflag flag;
};

struct iosendbuf {
	uint8_t *send_buf;
	size_t send_len;

	TAILQ_ENTRY(iosendbuf) entries;
	struct ioflag flag;
};

struct ioreqbuf {
	struct sp_client *cl;

	struct rsp_hdr req_hdr;
	uint8_t *req_data;
	size_t req_dlen;
	
	struct thread *thr;
};

struct prefork {
	uint32_t pf_auth[AUTHLEN];
	struct lwp *pf_lwp;

	LIST_ENTRY(prefork) pf_entries;		/* global list */
	LIST_ENTRY(prefork) pf_clentries;	/* linked from forking spc */
};
static LIST_HEAD(, prefork) preforks = LIST_HEAD_INITIALIZER(preforks);

struct sp_client {
	int state;
	int nthreads;
	struct rumpsp_chan *chan;

	struct rsp_hdr recv_hdr;
	uint8_t *recv_buf;
	size_t recv_off;

	TAILQ_HEAD(, iosendbuf) sendqueue;
	TAILQ_HEAD(, iorespbuf) respwaiter;

	struct lwp *mainlwp;
	pid_t pid;
	uint64_t next_reqno;
	
	int inexec;
	LIST_HEAD(, prefork) pflist;
};


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
lwproc_rfork(void *arg, int flags, const char *comm)
{
	int rv;

	rumpuser__hyp.hyp_schedule();
	rv = rumpuser__hyp.hyp_lwproc_rfork(arg, flags, comm);
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

static void
ioflag_init(struct ioflag *flag)
{

	flag->status = IOFLAG_STATUS_WAITING;
	flag->waiter = get_current();
}

static int
ioflag_wait(struct ioflag *flag)
{

	while (flag->status == IOFLAG_STATUS_WAITING) {
		block(flag->waiter);
		schedule();
	}

	return (flag->status != IOFLAG_STATUS_DONE);
}

static void
ioflag_signal(struct ioflag *flag)
{
	flag->status = IOFLAG_STATUS_DONE;
	wake(flag->waiter);
}

static void
ioflag_failed(struct ioflag *flag)
{
	flag->status = IOFLAG_STATUS_FAILED;
	wake(flag->waiter);
}

static int
ioflag_iswaiting(struct ioflag *flag)
{
	return flag->status == IOFLAG_STATUS_WAITING;
}

static void
clfree(struct sp_client *cl)
{
	DPRINTF(("rump_sp: close client %p, pid %d\n", cl, cl->pid));
	rumpsp_close(cl->chan);
	free(cl);
}

static void
disconnect(struct sp_client *cl)
{
	struct iorespbuf *respbuf, *tmpresp;
	struct iosendbuf *sendbuf, *tmpsend; 

	if (cl->state == CLIENT_STATE_DYING)
		return;

	cl->state = CLIENT_STATE_DYING;
	rumpsp_disable_events(cl->chan, RUMPSP_EVENT_READABLE);
	rumpsp_disable_events(cl->chan, RUMPSP_EVENT_WRITABLE);

	TAILQ_FOREACH_SAFE(respbuf, &cl->respwaiter, entries, tmpresp) {
		TAILQ_REMOVE(&cl->respwaiter, respbuf, entries);
		ioflag_failed(&respbuf->flag);
	}

	TAILQ_FOREACH_SAFE(sendbuf, &cl->sendqueue, entries, tmpsend) {
		TAILQ_REMOVE(&cl->sendqueue, sendbuf, entries);
		ioflag_failed(&sendbuf->flag);
	}
	
	if (cl->nthreads == 0) {
		clfree(cl);
	}
}

static int
client_send(struct sp_client *cl, struct iovec *iov, size_t iovlen)
{
	int error;
	size_t i, len, off;
	uint8_t *buf;
	struct iosendbuf sendbuf;

	len = 0;
	for (i = 0; i < iovlen; i++) {
		len += iov[i].iov_len;
	}

	buf = malloc(len);
	if (buf == NULL)
		return ENOMEM;

	off = 0;
	for (i = 0; i < iovlen; i++) {
		memcpy(buf + off, iov[i].iov_base, iov[i].iov_len);
		off += iov[i].iov_len;
	}

	sendbuf.send_len = len;
	sendbuf.send_buf = buf;

	ioflag_init(&sendbuf.flag);

	TAILQ_INSERT_TAIL(&cl->sendqueue, &sendbuf, entries);
	rumpsp_enable_events(cl->chan, RUMPSP_EVENT_WRITABLE);

	error = ioflag_wait(&sendbuf.flag);

	free(buf);

	return error;
}

static struct iorespbuf *
client_enqueue_wait(struct sp_client *cl, uint64_t reqno)
{
	struct iorespbuf *respbuf;

	respbuf = malloc(sizeof(*respbuf));
	if (respbuf == NULL)
		return NULL;

	respbuf->reqno = reqno;
	ioflag_init(&respbuf->flag);
	TAILQ_INSERT_TAIL(&cl->respwaiter, respbuf, entries);
	
	return respbuf;
}

static void
client_cancel_wait(struct sp_client *cl, struct iorespbuf *respbuf)
{
	if (ioflag_iswaiting(&respbuf->flag)) {
		TAILQ_REMOVE(&cl->respwaiter, respbuf, entries);
	}
}

static int
client_wait(struct iorespbuf *respbuf)
{

	return ioflag_wait(&respbuf->flag);
}


static int
client_resp_error(struct sp_client *cl, uint64_t reqno, enum rumpsp_err error)
{
	struct rsp_hdr rhdr;
	struct iovec iov[1];

	rhdr.rsp_len = sizeof(rhdr);
	rhdr.rsp_reqno = reqno;
	rhdr.rsp_class = RUMPSP_ERROR;
	rhdr.rsp_type = 0;
	rhdr.rsp_error = error;

	IOVPUT(iov[0], rhdr);

	return SENDIOV(cl, iov);
}

static int
client_resp_handshake(struct sp_client *cl, uint64_t reqno, int error)
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

	rv = SENDIOV(cl, iov);

	return rv;
}

static int
client_resp_syscall(struct sp_client *cl, uint64_t reqno, int error,
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

	IOVPUT(iov[0], rhdr);
	IOVPUT(iov[1], sysresp);

	rv = SENDIOV(cl, iov);

	return rv;
}


static int
client_resp_prefork(struct sp_client *cl, uint64_t reqno, uint32_t *auth)
{
	struct rsp_hdr rhdr;
	struct iovec iov[2];
	int rv;

	rhdr.rsp_len = sizeof(rhdr) + AUTHLEN*sizeof(*auth);
	rhdr.rsp_reqno = reqno;
	rhdr.rsp_class = RUMPSP_RESP;
	rhdr.rsp_type = RUMPSP_PREFORK;
	rhdr.rsp_sysnum = 0;

	IOVPUT(iov[0], rhdr);
	IOVPUT_WITHSIZE(iov[1], auth, AUTHLEN*sizeof(*auth));

	rv = SENDIOV(cl, iov);

	return rv;
}

static int
client_copyin_req(struct sp_client *cl, const void *remaddr, size_t *dlen,
	int wantstr, void **resp)
{
	struct rsp_hdr rhdr;
	struct rsp_copydata copydata;
	struct iorespbuf *respbuf;
	struct iovec iov[2];
	int rv;

	DPRINTF(("copyin_req: %zu bytes from %p\n", *dlen, remaddr));

	rhdr.rsp_len = sizeof(rhdr) + sizeof(copydata);
	rhdr.rsp_reqno = cl->next_reqno++;
	rhdr.rsp_class = RUMPSP_REQ;
	if (wantstr)
		rhdr.rsp_type = RUMPSP_COPYINSTR;
	else
		rhdr.rsp_type = RUMPSP_COPYIN;
	rhdr.rsp_sysnum = 0;

	copydata.rcp_addr = __UNCONST(remaddr);
	copydata.rcp_len = *dlen;

	respbuf = client_enqueue_wait(cl, rhdr.rsp_reqno);

	IOVPUT(iov[0], rhdr);
	IOVPUT(iov[1], copydata);

	rv = SENDIOV(cl, iov);
	if (rv) {
		client_cancel_wait(cl, respbuf);
		goto out;
	}

	rv = client_wait(respbuf);
	if (rv)
		goto out;

	*resp = respbuf->resp_data;
	if (wantstr)
		*dlen = respbuf->resp_dlen;

out:
	free(respbuf);
	return rv;

}

static int
client_copyout_req(struct sp_client *cl, const void *remaddr,
	const void *data, size_t dlen)
{
	struct rsp_hdr rhdr;
	struct rsp_copydata copydata;
	struct iovec iov[3];
	int rv;

	DPRINTF(("copyout_req (async): %zu bytes to %p\n", dlen, remaddr));

	rhdr.rsp_len = sizeof(rhdr) + sizeof(copydata) + dlen;
	rhdr.rsp_reqno = cl->next_reqno++;
	rhdr.rsp_class = RUMPSP_REQ;
	rhdr.rsp_type = RUMPSP_COPYOUT;
	rhdr.rsp_sysnum = 0;

	copydata.rcp_addr = __UNCONST(remaddr);
	copydata.rcp_len = dlen;

	IOVPUT(iov[0], rhdr);
	IOVPUT(iov[1], copydata);
	IOVPUT_WITHSIZE(iov[2], __UNCONST(data), dlen);

	rv = SENDIOV(cl, iov);

	return rv;
}

static int
client_anonmmap_req(struct sp_client *cl, size_t howmuch, void **resp)
{
	struct rsp_hdr rhdr;
	struct iorespbuf *respbuf;
	struct iovec iov[2];
	int rv;

	DPRINTF(("anonmmap_req: %zu bytes\n", howmuch));

	rhdr.rsp_len = sizeof(rhdr) + sizeof(howmuch);
	rhdr.rsp_reqno = cl->next_reqno++;
	rhdr.rsp_class = RUMPSP_REQ;
	rhdr.rsp_type = RUMPSP_ANONMMAP;
	rhdr.rsp_sysnum = 0;

	IOVPUT(iov[0], rhdr);
	IOVPUT(iov[1], howmuch);

	respbuf = client_enqueue_wait(cl, rhdr.rsp_reqno);
	rv = SENDIOV(cl, iov);
	if (rv) {
		client_cancel_wait(cl, respbuf);
		goto out;
	}

	rv = client_wait(respbuf);
	if (rv)
		goto out;
	
	*resp = respbuf->resp_data;

	DPRINTF(("anonmmap: mapped at %p\n", **(void ***)resp));

out:
	free(respbuf);
	return rv;
}

static int
client_raise_req(struct sp_client *cl, int signo)
{
	struct rsp_hdr rhdr;
	struct iovec iov[1];
	int rv;

	rhdr.rsp_len = sizeof(rhdr);
	rhdr.rsp_class = RUMPSP_REQ;
	rhdr.rsp_type = RUMPSP_RAISE;
	rhdr.rsp_signo = signo;

	IOVPUT(iov[0], rhdr);

	rv = SENDIOV(cl, iov);

	return rv;
}

static void
client_new_handshake(struct ioreqbuf *reqbuf)
{
	int error;
	uint64_t reqno;
	struct sp_client *cl = reqbuf->cl;

	if (reqbuf->req_hdr.rsp_type != RUMPSP_HANDSHAKE) {
		disconnect(cl);
		return;
	}

	reqno = reqbuf->req_hdr.rsp_reqno;

	if (reqbuf->req_hdr.rsp_handshake == HANDSHAKE_GUEST) {
		char *comm = (char *)reqbuf->req_data;
		size_t commlen = reqbuf->req_dlen;

		/* ensure it's 0-terminated */
		/* XXX make sure it contains sensible chars? */
		comm[commlen] = '\0';

		/* make sure we fork off of proc1 */
		_DIAGASSERT(lwproc_curlwp() == NULL);

		if ((error = lwproc_rfork(cl,
		    RUMP_RFFD_CLEAR, comm)) != 0) {
		    	disconnect(cl);
		    	return;
		}

		//spcfreebuf(spc);
		if (error)
			return;

		cl->mainlwp = lwproc_curlwp();

		client_resp_handshake(cl, reqno, 0);
	} else if (reqbuf->req_hdr.rsp_handshake == HANDSHAKE_FORK) {
		struct lwp *tmpmain;
		struct prefork *pf;
		struct handshake_fork *rfp;
		int cancel;

		if (reqbuf->req_dlen != sizeof(*rfp)) {
			client_resp_error(cl, reqno,
			    RUMPSP_ERR_MALFORMED_REQUEST);
			disconnect(cl);
			return;
		}

		/*LINTED*/
		rfp = (void *)reqbuf->req_data;
		cancel = rfp->rf_cancel;

		LIST_FOREACH(pf, &preforks, pf_entries) {
			if (memcmp(rfp->rf_auth, pf->pf_auth,
			    sizeof(rfp->rf_auth)) == 0) {
				LIST_REMOVE(pf, pf_entries);
				LIST_REMOVE(pf, pf_clentries);
				break;
			}
		}

		if (!pf) {
			client_resp_error(cl, reqno,
			    RUMPSP_ERR_INVALID_PREFORK);
			disconnect(cl);
			return;
		}

		tmpmain = pf->pf_lwp;
		free(pf);
		lwproc_switch(tmpmain);
		if (cancel) {
			lwproc_release();
			disconnect(cl);
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
		if ((error = lwproc_rfork(cl,
		    RUMP_RFFD_SHARE, NULL)) != 0) {
			client_resp_error(cl, reqno,
			    RUMPSP_ERR_RFORK_FAILED);
			disconnect(cl);
			lwproc_release();
			return;
		}
		cl->mainlwp = lwproc_curlwp();
		lwproc_switch(tmpmain);
		lwproc_release();
		lwproc_switch(cl->mainlwp);

		client_resp_handshake(cl, reqno, 0);
	} else {
		client_resp_error(cl, reqno, RUMPSP_ERR_AUTH);
		disconnect(cl);
		return;
	}

	cl->pid = lwproc_getpid();

	DPRINTF(("rump_sp: handshake for client %p complete, pid %d\n",
		cl, cl->pid));

	lwproc_switch(NULL);
	cl->state = CLIENT_STATE_RUNNING;
}

static void
client_prefork(struct ioreqbuf *reqbuf)
{
	struct sp_client *cl = reqbuf->cl;
	struct prefork *pf;
	uint32_t auth[AUTHLEN];
	uint64_t reqno;
	size_t randlen;
	int error;

	reqno = reqbuf->req_hdr.rsp_reqno;

	DPRINTF(("rump_sp: prefork handler executing for %p\n", cl));

	if (cl->inexec) {
		client_resp_error(cl, reqno, RUMPSP_ERR_INEXEC);
		disconnect(cl);
		return;
	}

	pf = malloc(sizeof(*pf));
	if (pf == NULL) {
		client_resp_error(cl, reqno, RUMPSP_ERR_NOMEM);
		return;
	}

	/*
	 * Use client main lwp to fork.  this is never used by
	 * worker threads (except in exec, but we checked for that
	 * above) so we can safely use it here.
	 */
	lwproc_switch(cl->mainlwp);
	if ((error = lwproc_rfork(cl, RUMP_RFFD_COPY, NULL)) != 0) {
		DPRINTF(("rump_sp: fork failed: %d (%p)\n", error, cl));
		client_resp_error(cl, reqno, RUMPSP_ERR_RFORK_FAILED);
		lwproc_switch(NULL);
		free(pf);
		return;
	}

	/* Ok, we have a new process context and a new curlwp */
	rumpuser_getrandom(auth, sizeof(auth), 0, &randlen);
	memcpy(pf->pf_auth, auth, sizeof(pf->pf_auth));
	pf->pf_lwp = lwproc_curlwp();
	lwproc_switch(NULL);

	LIST_INSERT_HEAD(&preforks, pf, pf_entries);
	LIST_INSERT_HEAD(&cl->pflist, pf, pf_clentries);

	DPRINTF(("rump_sp: prefork handler success %p\n", cl));

	client_resp_prefork(cl, reqno, auth);
}

static void
client_exec(struct ioreqbuf *reqbuf)
{
	struct sp_client *cl = reqbuf->cl;
	uint64_t reqno = reqbuf->req_hdr.rsp_reqno;
	char *comm = (char *)reqbuf->req_data;
	size_t commlen = reqbuf->req_dlen;


	if (reqbuf->req_hdr.rsp_handshake != HANDSHAKE_EXEC) {
		client_resp_error(cl, reqno,
		    RUMPSP_ERR_MALFORMED_REQUEST);
		disconnect(cl);
		return;
	}

	if (cl->inexec) {
		client_resp_error(cl, reqno, RUMPSP_ERR_INEXEC);
		disconnect(cl);
		return;
	}

	cl->inexec = 1;

	/*
	 * start to drain lwps.  we will wait for it to finish
	 * in another thread
	 */
	lwproc_switch(cl->mainlwp);
	lwproc_lwpexit();
	lwproc_switch(NULL);

	while (cl->nthreads > 1) {
		schedule();
	}
	
	if (cl->state == CLIENT_STATE_RUNNING) {
		comm[commlen] = '\0';

		lwproc_switch(cl->mainlwp);
		lwproc_execnotify(comm);
		lwproc_switch(NULL);

		cl->inexec = 0;
		client_resp_handshake(cl, reqno, 0);
	}
}

static void
client_syscall(struct ioreqbuf *reqbuf)
{
	struct sp_client *cl = reqbuf->cl;
	uint64_t reqno = reqbuf->req_hdr.rsp_reqno;
	register_t retval[2] = {0, 0};
	int rv, sysnum;

	if (reqbuf->req_hdr.rsp_type != RUMPSP_SYSCALL) {
		client_resp_error(cl, reqno, RUMPSP_ERR_MALFORMED_REQUEST);
		return;
	}

	sysnum = (int)reqbuf->req_hdr.rsp_sysnum;
	DPRINTF(("rump_sp: handling syscall %d from client %d\n",
	    sysnum, cl->pid));

	if ((rv = lwproc_newlwp(cl->pid)) != 0) {
		retval[0] = -1;
		client_resp_syscall(cl, reqno, rv, retval);
		return;
	}
	
	//cl->spc_syscallreq = rhdr->rsp_reqno;
	rv = rumpsyscall(sysnum, reqbuf->req_data, retval);
	//spc->spc_syscallreq = 0;
	lwproc_release();

	DPRINTF(("rump_sp: got return value %d & %d/%d\n",
	    rv, retval[0], retval[1]));

	client_resp_syscall(cl, reqno, rv, retval);
}

static void
client_exitthread(struct sp_client *cl)
{
	cl->nthreads--;

	/* last to leave cleans up */
	if (cl->state == CLIENT_STATE_DYING && cl->nthreads == 0) {
		clfree(cl);
	}

	exit_thread();
}

static void
client_sendbanner(void *arg)
{
	int rv;
	struct sp_client *cl = arg;
	struct iovec iov[1];

	DPRINTF(("rump_sp: sending banner\n"));
	IOVPUT_WITHSIZE(iov[0], banner, strlen(banner));

	rv = SENDIOV(cl, iov);
	
	if (rv)
		disconnect(cl);

	client_exitthread(cl);
}

static void
client_handlereq(void *arg)
{
	struct ioreqbuf *reqbuf = arg;
	struct sp_client *cl = reqbuf->cl;
	
	DPRINTF(("rump_sp: handle request\n"));
	
	if (cl->state == CLIENT_STATE_NEW) {
		client_new_handshake(reqbuf);
	} else if (reqbuf->req_hdr.rsp_type == RUMPSP_PREFORK) {
		client_prefork(reqbuf);
	} else if (reqbuf->req_hdr.rsp_type == RUMPSP_HANDSHAKE) {
		client_exec(reqbuf);
	} else {
		client_syscall(reqbuf);
	}

	free(reqbuf->req_data);
	free(reqbuf);
	
	client_exitthread(cl);
}

static void
donesend(struct sp_client *cl, int success)
{
	struct iosendbuf *sendbuf = TAILQ_FIRST(&cl->sendqueue);

	assert(sendbuf != NULL);

	TAILQ_REMOVE(&cl->sendqueue, sendbuf, entries);
	if (TAILQ_EMPTY(&cl->sendqueue)) {
		rumpsp_disable_events(cl->chan, RUMPSP_EVENT_WRITABLE);
	}

	if (success) {
		ioflag_signal(&sendbuf->flag);
	} else {
		ioflag_failed(&sendbuf->flag);
	}
}

static void
dorequest(struct sp_client *cl)
{
	struct ioreqbuf *reqbuf;

	reqbuf = malloc(sizeof(*reqbuf));
	if (reqbuf == NULL) {
		disconnect(cl);
		return;
	}
	
	cl->nthreads++;

	reqbuf->cl = cl;
	reqbuf->req_hdr = cl->recv_hdr;
	reqbuf->req_data = cl->recv_buf;
	reqbuf->req_dlen = cl->recv_hdr.rsp_len - HDRSZ;
	reqbuf->thr = create_thread("rump_sp_reqhandler", NULL, 
					client_handlereq, reqbuf, NULL, 0);
}

static void
doresponse(struct sp_client *cl)
{
	struct iorespbuf *respbuf = NULL;

	TAILQ_FOREACH(respbuf, &cl->respwaiter, entries) {
		if (respbuf->reqno == cl->recv_hdr.rsp_reqno)
			break;
	}
	
	if (respbuf == NULL) {
		disconnect(cl);
		return;
	}

	respbuf->resp_hdr = cl->recv_hdr;
	respbuf->resp_data = cl->recv_buf;
	respbuf->resp_dlen = cl->recv_hdr.rsp_len - HDRSZ;

	TAILQ_REMOVE(&cl->respwaiter, respbuf, entries);

	ioflag_signal(&respbuf->flag);
}

static void
chanreadable(struct rumpsp_chan *chan, void *token)
{
	struct sp_client *cl = token;
	size_t left;
	size_t framelen;
	ssize_t n;

	/* still reading header? */
	if (cl->recv_off < HDRSZ) {
#if 1
		DPRINTF(("rump_sp: reading header at offset %zu\n",
			cl->recv_off));
#endif

		left = HDRSZ - cl->recv_off;
		n = rumpsp_read(chan,
				(uint8_t*)&cl->recv_hdr + cl->recv_off, left);
		if (n == 0) {
			disconnect(cl);
			return;
		}
		if (n == -1) {
			if (errno != EAGAIN) {
				disconnect(cl);
			}
			return;
		}

		cl->recv_off += n;
		if (cl->recv_off < HDRSZ) {
			return;
		}

		/*LINTED*/
		framelen = cl->recv_hdr.rsp_len;

		if (framelen < HDRSZ) {
			return;
		} else if (framelen == HDRSZ) {
			goto complete;
		}

		cl->recv_buf = malloc(framelen - HDRSZ);
		if (cl->recv_buf == NULL) {
			disconnect(cl);
			return;
		}

		memset(cl->recv_buf, 0, framelen - HDRSZ);

		/* "fallthrough" */
	} else {
		/*LINTED*/
		framelen = cl->recv_hdr.rsp_len;
	}

	left = framelen - cl->recv_off;

#if 1
	DPRINTF(("rump_sp: reading body at offset %zu, left %zu\n",
	    cl->recv_off, left));
#endif
	if (left == 0)
		goto complete;

	n = rumpsp_read(chan, cl->recv_buf + (cl->recv_off - HDRSZ), left);
	if (n == 0) {
		disconnect(cl);
		return;
	}
	if (n == -1) {
		if (errno != EAGAIN) {
			free(cl->recv_buf);
			disconnect(cl);
		}
		return;
	}
	cl->recv_off += n;
	left -= n;
	
	if (left > 0)
		return;

complete:
	DPRINTF(("rump_sp: read completed.\n"));
	switch (cl->recv_hdr.rsp_class) {
	case RUMPSP_RESP:
		doresponse(cl);
		break;
	case RUMPSP_REQ:
		dorequest(cl);
		break;
	default:
		free(cl->recv_buf);
		disconnect(cl);
		break;
	}
	
	cl->recv_buf = NULL;
	cl->recv_off = 0;
}

static void
chanwritable(struct rumpsp_chan *chan, void *token)
{
	struct sp_client *cl = token;
	struct iosendbuf *sb;
	ssize_t n;

	sb = TAILQ_FIRST(&cl->sendqueue);
	
	DPRINTF(("rump_sp: writing buffer %p, length %zu\n", 
			sb->send_buf, sb->send_len));
	
	n = rumpsp_write(chan, sb->send_buf, sb->send_len);
	if (n == 0) {
		return;
	}
	if (n == -1) {
		if (errno != EAGAIN) {
			donesend(cl, 0); // TODO should pass up errno for send
		}
		return;
	}

	sb->send_buf += n;
	sb->send_len -= n;

	if (sb->send_len > 0) {
		return;
	}

	DPRINTF(("rump_sp: disable writing to %p\n", cl));
	donesend(cl, 1);
}

static void
chanaccepted(struct rumpsp_chan *chan, void **token)
{
	struct sp_client *cl;
	
	cl = malloc(sizeof(*cl));
	if (cl == NULL) {
		rumpsp_close(chan);
		return;
	}

	memset(cl, 0, sizeof(*cl));

	*token = cl;

	cl->state = CLIENT_STATE_NEW;
	cl->nthreads = 1;
	cl->inexec = 0;
	cl->chan = chan;

	TAILQ_INIT(&cl->sendqueue);
	TAILQ_INIT(&cl->respwaiter);
	LIST_INIT(&cl->pflist);

	rumpsp_enable_events(chan, RUMPSP_EVENT_READABLE);

	create_thread("rump_sp_greeter", NULL, client_sendbanner, cl, NULL, 0);

	DPRINTF(("rump_sp: accepted new client %p\n", cl));
}

static void
mainloop(void *arg)
{
	int err;

	DPRINTF(("rump_sp: server mainloop\n"));

	for (;;) {
		err = rumpsp_dispatch(10);
		if (err)
			return;
		schedule();
	}
}

/*ARGSUSED*/
int
rumpuser_sp_init(const char *url,
	const char *ostype, const char *osrelease, const char *machine)
{
	int err;
	struct thread *thr;
	struct rumpsp_handlers hndlrs;

	snprintf(banner, sizeof(banner), "RUMPSP-%d.%d-%s-%s/%s\n",
	         PROTOMAJOR, PROTOMINOR, ostype, osrelease, machine);

	hndlrs.accepted = chanaccepted;
	hndlrs.readable = chanreadable;
	hndlrs.writable = chanwritable;

	err = rumpsp_init_server(url, hndlrs);
	if (err)
		goto out;

	thr = create_thread("rump_sp_mainloop", NULL, mainloop, NULL, NULL, 0);
	if (!thr) {
		err = ENOMEM;
		goto out;
	}
	
	// TODO figure out how to schedule server thread in background
	for (;;) {
		schedule();
	}
 out:
	ET(err);
}

/*ARGSUSED*/
void
rumpuser_sp_fini(void *arg)
{
	rumpsp_cleanup();
}

static int
sp_copyin(void *arg, const void *raddr, void *laddr, size_t *len, int wantstr)
{
	struct sp_client *cl = arg;
	void *rdata = NULL;
	int rv, nlocks;

	rumpkern_unsched(&nlocks, NULL);

	rv = client_copyin_req(cl, raddr, len, wantstr, &rdata);
	if (rv)
		goto out;

	memcpy(laddr, rdata, *len);
	free(rdata);

 out:
	rumpkern_sched(nlocks, NULL);
	if (rv)
		rv = EFAULT;
	ET(rv);
}

int
rumpuser_sp_copyin(void *arg, const void *raddr, void *laddr, size_t len)
{
	int rv;

	rv = sp_copyin(arg, raddr, laddr, &len, 0);
	ET(rv);
}

int
rumpuser_sp_copyinstr(void *arg, const void *raddr, void *laddr, size_t *len)
{
	int rv;

	rv = sp_copyin(arg, raddr, laddr, len, 1);
	ET(rv);
}

static int
sp_copyout(void *arg, const void *laddr, void *raddr, size_t dlen)
{
	struct sp_client *cl = arg;
	int nlocks, rv;

	rumpkern_unsched(&nlocks, NULL);
	rv = client_copyout_req(cl, raddr, laddr, dlen);
	rumpkern_sched(nlocks, NULL);

	if (rv)
		rv = EFAULT;
	ET(rv);
}

int
rumpuser_sp_copyout(void *arg, const void *laddr, void *raddr, size_t dlen)
{
	int rv;

	rv = sp_copyout(arg, laddr, raddr, dlen);
	ET(rv);
}

int
rumpuser_sp_copyoutstr(void *arg, const void *laddr, void *raddr, size_t *dlen)
{
	int rv;

	rv = sp_copyout(arg, laddr, raddr, *dlen);
	ET(rv);
}

int
rumpuser_sp_anonmmap(void *arg, size_t howmuch, void **addr)
{
	struct sp_client *cl = arg;
	void *resp, *rdata = NULL; /* XXXuninit */
	int nlocks, rv;

	rumpkern_unsched(&nlocks, NULL);

	rv = client_anonmmap_req(cl, howmuch, &rdata);
	if (rv) {
		rv = EFAULT;
		goto out;
	}

	resp = *(void **)rdata;
	free(rdata);

	if (resp == NULL) {
		rv = ENOMEM;
	}

	*addr = resp;

 out:
	rumpkern_sched(nlocks, NULL);
	ET(rv);
}

int
rumpuser_sp_raise(void *arg, int signo)
{
	struct sp_client *cl = arg;
	int rv, nlocks;

	rumpkern_unsched(&nlocks, NULL);
	rv = client_raise_req(cl, signo);
	rumpkern_sched(nlocks, NULL);

	return rv;
}
