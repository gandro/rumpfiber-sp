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

#ifndef _RUMP_RUMPUSER_SP_H_
#define _RUMP_RUMPUSER_SP_H_

#include <sys/types.h>

#include <errno.h>

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

/*
 * The mapping of the above types to errno.  They are almost never exposed
 * to the client after handshake (except for a server resource shortage
 * and the client trying to be funny).  This is a function instead of
 * an array to catch missing values.  Theoretically, the compiled code
 * should be the same.
 */
static int
errmap(enum rumpsp_err error)
{

	switch (error) {
	/* XXX: no EAUTH on Linux */
	case RUMPSP_ERR_NONE:			return 0;
	case RUMPSP_ERR_AUTH:			return EPERM;
	case RUMPSP_ERR_TRYAGAIN:		return EAGAIN;
	case RUMPSP_ERR_INVALID_PREFORK:	return ESRCH;
	case RUMPSP_ERR_RFORK_FAILED:		return EIO; /* got a light? */
	case RUMPSP_ERR_INEXEC:			return EBUSY;
	case RUMPSP_ERR_NOMEM:			return ENOMEM;
	case RUMPSP_ERR_MALFORMED_REQUEST:	return EINVAL;
	}

	return -1;
}

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

struct handshake_fork {
	uint32_t rf_auth[4];
	int rf_cancel;
};

#endif /* _RUMP_RUMPUSER_SP_H_ */
