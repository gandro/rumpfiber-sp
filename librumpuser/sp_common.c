/*      $NetBSD: sp_common.c,v 1.38 2014/01/08 01:45:29 pooka Exp $	*/

/*
 * Copyright (c) 2010, 2011 Antti Kantee.  All Rights Reserved.
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

/*
 * Common client/server sysproxy routines.  #included.
 */

#include "rumpuser_port.h"

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "rumpuser_sp.h"

#include "sp_parse.c"

/*
 * XXX: NetBSD's __unused collides with Linux headers, so we cannot
 * define it before we've included everything.
 */
#if !defined(__unused) && defined(__GNUC__)
#define __unused __attribute__((__unused__))
#endif

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

#ifndef HOSTOPS
#define host_poll poll
#define host_read read
#define host_sendmsg sendmsg
#define host_setsockopt setsockopt
#endif

#define IOVPUT(_io_, _b_) _io_.iov_base = 			\
    (void *)&_b_; _io_.iov_len = sizeof(_b_);
#define IOVPUT_WITHSIZE(_io_, _b_, _l_) _io_.iov_base =		\
    (void *)(_b_); _io_.iov_len = _l_;
#define SENDIOV(_spc_, _iov_) dosend(_spc_, _iov_, __arraycount(_iov_))

struct respwait {
	uint64_t rw_reqno;
	void *rw_data;
	size_t rw_dlen;
	int rw_done;
	int rw_error;

	pthread_cond_t rw_cv;

	TAILQ_ENTRY(respwait) rw_entries;
};

struct prefork;
struct spclient {
	int spc_fd;
	int spc_refcnt;
	int spc_state;

	pthread_mutex_t spc_mtx;
	pthread_cond_t spc_cv;

	struct lwp *spc_mainlwp;
	pid_t spc_pid;

	TAILQ_HEAD(, respwait) spc_respwait;

	/* rest of the fields are zeroed upon disconnect */
#define SPC_ZEROFF offsetof(struct spclient, spc_pfd)
	struct pollfd *spc_pfd;

	struct rsp_hdr spc_hdr;
	uint8_t *spc_buf;
	size_t spc_off;

	uint64_t spc_nextreq;
	uint64_t spc_syscallreq;
	uint64_t spc_generation;
	int spc_ostatus, spc_istatus;
	int spc_reconnecting;
	int spc_inexec;

	LIST_HEAD(, prefork) spc_pflist;
};
#define SPCSTATUS_FREE 0
#define SPCSTATUS_BUSY 1
#define SPCSTATUS_WANTED 2

#define SPCSTATE_NEW     0
#define SPCSTATE_RUNNING 1
#define SPCSTATE_DYING   2

static int readframe(struct spclient *);
static void handlereq(struct spclient *);

static __inline void
spcresetbuf(struct spclient *spc)
{

	spc->spc_buf = NULL;
	spc->spc_off = 0;
}

static __inline void
spcfreebuf(struct spclient *spc)
{

	free(spc->spc_buf);
	spcresetbuf(spc);
}

static void
sendlockl(struct spclient *spc)
{

	while (spc->spc_ostatus != SPCSTATUS_FREE) {
		spc->spc_ostatus = SPCSTATUS_WANTED;
		pthread_cond_wait(&spc->spc_cv, &spc->spc_mtx);
	}
	spc->spc_ostatus = SPCSTATUS_BUSY;
}

static void __unused
sendlock(struct spclient *spc)
{

	pthread_mutex_lock(&spc->spc_mtx);
	sendlockl(spc);
	pthread_mutex_unlock(&spc->spc_mtx);
}

static void
sendunlockl(struct spclient *spc)
{

	if (spc->spc_ostatus == SPCSTATUS_WANTED)
		pthread_cond_broadcast(&spc->spc_cv);
	spc->spc_ostatus = SPCSTATUS_FREE;
}

static void
sendunlock(struct spclient *spc)
{

	pthread_mutex_lock(&spc->spc_mtx);
	sendunlockl(spc);
	pthread_mutex_unlock(&spc->spc_mtx);
}

static int
dosend(struct spclient *spc, struct iovec *iov, size_t iovlen)
{
	struct msghdr msg;
	struct pollfd pfd;
	ssize_t n = 0;
	int fd = spc->spc_fd;

	pfd.fd = fd;
	pfd.events = POLLOUT;

	memset(&msg, 0, sizeof(msg));

	for (;;) {
		/* not first round?  poll */
		if (n) {
			if (host_poll(&pfd, 1, INFTIM) == -1) {
				if (errno == EINTR)
					continue;
				return errno;
			}
		}

		msg.msg_iov = iov;
		msg.msg_iovlen = iovlen;
		n = host_sendmsg(fd, &msg, MSG_NOSIGNAL);
		if (n == -1)  {
			if (errno == EPIPE)
				return ENOTCONN;
			if (errno != EAGAIN)
				return errno;
			continue;
		}
		if (n == 0) {
			return ENOTCONN;
		}

		/* ok, need to adjust iovec for potential next round */
		while (n >= (ssize_t)iov[0].iov_len && iovlen) {
			n -= iov[0].iov_len;
			iov++;
			iovlen--;
		}

		if (iovlen == 0) {
			_DIAGASSERT(n == 0);
			break;
		} else {
			iov[0].iov_base =
			    (void *)((uint8_t *)iov[0].iov_base + n);
			iov[0].iov_len -= n;
		}
	}

	return 0;
}

static void
doputwait(struct spclient *spc, struct respwait *rw, struct rsp_hdr *rhdr)
{

	rw->rw_data = NULL;
	rw->rw_dlen = rw->rw_done = rw->rw_error = 0;
	pthread_cond_init(&rw->rw_cv, NULL);

	pthread_mutex_lock(&spc->spc_mtx);
	rw->rw_reqno = rhdr->rsp_reqno = spc->spc_nextreq++;
	TAILQ_INSERT_TAIL(&spc->spc_respwait, rw, rw_entries);
}

static void __unused
putwait_locked(struct spclient *spc, struct respwait *rw, struct rsp_hdr *rhdr)
{

	doputwait(spc, rw, rhdr);
	pthread_mutex_unlock(&spc->spc_mtx);
}

static void
putwait(struct spclient *spc, struct respwait *rw, struct rsp_hdr *rhdr)
{

	doputwait(spc, rw, rhdr);
	sendlockl(spc);
	pthread_mutex_unlock(&spc->spc_mtx);
}

static void
dounputwait(struct spclient *spc, struct respwait *rw)
{

	TAILQ_REMOVE(&spc->spc_respwait, rw, rw_entries);
	pthread_mutex_unlock(&spc->spc_mtx);
	pthread_cond_destroy(&rw->rw_cv);

}

static void __unused
unputwait_locked(struct spclient *spc, struct respwait *rw)
{

	pthread_mutex_lock(&spc->spc_mtx);
	dounputwait(spc, rw);
}

static void
unputwait(struct spclient *spc, struct respwait *rw)
{

	pthread_mutex_lock(&spc->spc_mtx);
	sendunlockl(spc);

	dounputwait(spc, rw);
}

static void
kickwaiter(struct spclient *spc)
{
	struct respwait *rw;
	int error = 0;

	pthread_mutex_lock(&spc->spc_mtx);
	TAILQ_FOREACH(rw, &spc->spc_respwait, rw_entries) {
		if (rw->rw_reqno == spc->spc_hdr.rsp_reqno)
			break;
	}
	if (rw == NULL) {
		DPRINTF(("no waiter found, invalid reqno %" PRIu64 "?\n",
		    spc->spc_hdr.rsp_reqno));
		pthread_mutex_unlock(&spc->spc_mtx);
		spcfreebuf(spc);
		return;
	}
	DPRINTF(("rump_sp: client %p woke up waiter at %p\n", spc, rw));
	rw->rw_data = spc->spc_buf;
	rw->rw_done = 1;
	rw->rw_dlen = (size_t)(spc->spc_off - HDRSZ);
	if (spc->spc_hdr.rsp_class == RUMPSP_ERROR) {
		error = rw->rw_error = errmap(spc->spc_hdr.rsp_error);
	}
	pthread_cond_signal(&rw->rw_cv);
	pthread_mutex_unlock(&spc->spc_mtx);

	if (error)
		spcfreebuf(spc);
	else
		spcresetbuf(spc);
}

static void
kickall(struct spclient *spc)
{
	struct respwait *rw;

	/* DIAGASSERT(mutex_owned(spc_lock)) */
	TAILQ_FOREACH(rw, &spc->spc_respwait, rw_entries)
		pthread_cond_broadcast(&rw->rw_cv);
}

static int
readframe(struct spclient *spc)
{
	int fd = spc->spc_fd;
	size_t left;
	size_t framelen;
	ssize_t n;

	/* still reading header? */
	if (spc->spc_off < HDRSZ) {
		DPRINTF(("rump_sp: readframe getting header at offset %zu\n",
		    spc->spc_off));

		left = HDRSZ - spc->spc_off;
		/*LINTED: cast ok */
		n = host_read(fd, (uint8_t*)&spc->spc_hdr + spc->spc_off, left);
		if (n == 0) {
			return -1;
		}
		if (n == -1) {
			if (errno == EAGAIN)
				return 0;
			return -1;
		}

		spc->spc_off += n;
		if (spc->spc_off < HDRSZ) {
			return 0;
		}

		/*LINTED*/
		framelen = spc->spc_hdr.rsp_len;

		if (framelen < HDRSZ) {
			return -1;
		} else if (framelen == HDRSZ) {
			return 1;
		}

		spc->spc_buf = malloc(framelen - HDRSZ);
		if (spc->spc_buf == NULL) {
			return -1;
		}
		memset(spc->spc_buf, 0, framelen - HDRSZ);

		/* "fallthrough" */
	} else {
		/*LINTED*/
		framelen = spc->spc_hdr.rsp_len;
	}

	left = framelen - spc->spc_off;

	DPRINTF(("rump_sp: readframe getting body at offset %zu, left %zu\n",
	    spc->spc_off, left));

	if (left == 0)
		return 1;
	n = host_read(fd, spc->spc_buf + (spc->spc_off - HDRSZ), left);
	if (n == 0) {
		return -1;
	}
	if (n == -1) {
		if (errno == EAGAIN)
			return 0;
		return -1;
	}
	spc->spc_off += n;
	left -= n;

	/* got everything? */
	if (left == 0)
		return 1;
	else
		return 0;
}
