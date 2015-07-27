#include <sys/socket.h>
#include <sys/un.h>

#ifndef HOSTOPS
#define host_poll poll
#define host_read read
#define host_sendmsg sendmsg
#define host_setsockopt setsockopt
#endif

#include "sp_parse.c"

#define MAXFDS 256

struct rumpsp_chan;

typedef void (*rumpsp_accept_fn)(struct rumpsp_chan *, void **token);
typedef void (*rumpsp_callback_fn)(struct rumpsp_chan *, void *token);

struct rumpsp_chan {
	void *token;

	int fd;
};

struct rumpsp_handlers {
	rumpsp_accept_fn accepted;
	rumpsp_callback_fn writable;
	rumpsp_callback_fn readable;
};



static unsigned int protoidx;
static struct sockaddr *protosa;

static unsigned int maxidx;
static struct pollfd pollfds[MAXFDS];
static struct rumpsp_chan chanfds[MAXFDS];

static struct rumpsp_handlers handlers;

static unsigned int
getidx(struct rumpsp_chan *chan)
{

	return chan - chanfds;
}

static void
rumpsp_cleanup(void)
{
	parsetab[protoidx].cleanup(protosa);
}

static int
rumpsp_init_server(const char *url, struct rumpsp_handlers hndlrs)
{
	struct sockaddr *sap;
	unsigned int i;
	int err, sockfd, flags;

	err = parseurl(url, &sap, &protoidx, 1);

	if (err)
		return err;
	
	sockfd = socket(parsetab[protoidx].domain, SOCK_STREAM, 0);
	if (sockfd == -1) {
		return errno;
	}

	if (bind(sockfd, sap, parsetab[protoidx].slen) == -1) {
		fprintf(stderr, "rump_sp: failed to bind to URL %s\n", url);
		close(sockfd);
		return errno;
	}

	if (listen(sockfd, MAXFDS) == -1) {
		fprintf(stderr, "rump_sp: server listen failed\n");
		close(sockfd);
		return errno;
	}

	/* make sure accept() does not block */
	flags = fcntl(sockfd, F_GETFL, 0);
	if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) == -1) {
		close(sockfd);
		return errno;
	}

	protosa = sap;
	handlers = hndlrs;

	for (i = 0; i < MAXFDS; i++) {
		chanfds[i].fd = -1;
	}

	chanfds[0].fd = sockfd;
	pollfds[0].fd = sockfd;
	pollfds[0].events = POLLIN;
	maxidx = 0;

	return 0;
}

static ssize_t
rumpsp_read(struct rumpsp_chan *chan, void *data, size_t size)
{
	return read(chan->fd, data, size);
}

static ssize_t
rumpsp_write(struct rumpsp_chan *chan, void *data, size_t size)
{
	return write(chan->fd, data, size);
}

static void
rumpsp_close(struct rumpsp_chan *chan)
{
	int fd = chan->fd;
	unsigned int idx = getidx(chan);
	struct pollfd *pfd = &pollfds[idx];
	
	chan->token = NULL;
	chan->fd = -1;
	
	pfd->fd = -1;
	pfd->events = 0;
	
	if (idx == maxidx) {
		idx = maxidx - 1;
		while (idx) {
			if (chanfds[idx].fd != -1) {
				maxidx = idx;
				break;
			}
			idx--;
		}
	}

	close(fd);
}

#define RUMPSP_EVENT_WRITABLE	0x1
#define RUMPSP_EVENT_READABLE	0x2

static int 
rumpsp_enable_events(struct rumpsp_chan *chan, int events)
{
	struct pollfd *pfd = &pollfds[getidx(chan)];

	if (events & RUMPSP_EVENT_WRITABLE) {
		pfd->events |= POLLOUT;
	}
	
	if (events & RUMPSP_EVENT_READABLE) {
		pfd->events |= POLLIN;
	}
	
	if (pfd->events)
		pfd->fd= chan->fd;
	
	return 0;
}

static int 
rumpsp_disable_events(struct rumpsp_chan *chan, int events)
{
	struct pollfd *pfd = &pollfds[getidx(chan)];

	if (events & RUMPSP_EVENT_WRITABLE) {
		pfd->events &= ~POLLOUT;
	}
	
	if (events & RUMPSP_EVENT_READABLE) {
		pfd->events &= ~POLLIN;
	}
	
	if (!pfd->events)
		pfd->fd= -1;
	
	return 0;
}

static void
dispatch_accept(int fd)
{
	struct sockaddr_storage ss;
	socklen_t sl = sizeof(ss);
	int newfd, flags;
	unsigned int idx;

	newfd = accept(fd, (struct sockaddr *)&ss, &sl);
	if (newfd == -1)
		return;
	
	for (idx = 0; idx < MAXFDS; idx++) {
		if (chanfds[idx].fd == -1)
			break;
	}

	if (idx == MAXFDS) {
		close(newfd);
		return;
	}

	flags = fcntl(newfd, F_GETFL, 0);
	if (fcntl(newfd, F_SETFL, flags | O_NONBLOCK) == -1) {
		close(newfd);
		return;
	}

	if (parsetab[protoidx].connhook(newfd) != 0) {
		close(newfd);
		return;
	}
	
	if (idx > maxidx) {
		maxidx = idx;
	}

	chanfds[idx].fd = newfd;
	handlers.accepted(&chanfds[idx], &chanfds[idx].token);
}

static int
rumpsp_dispatch(int timeout_ms)
{
	unsigned int idx;
	int rv, seen;

	rv = poll(pollfds, maxidx+1, timeout_ms);
	if (rv == 0)
		return 0;
	
	if (rv < 0)
		return errno;

	seen = 0;
	for (idx = 0; seen < rv && idx <= maxidx; idx++) {
		struct rumpsp_chan *chan = &chanfds[idx];

		if (!(pollfds[idx].revents & (POLLIN|POLLOUT)))
			continue;
		seen++;

		if (idx == 0) {
			dispatch_accept(chan->fd);
		} else {
			if (pollfds[idx].revents & POLLIN) {
				handlers.readable(chan, chan->token);
			}

			if (pollfds[idx].revents & POLLOUT) {
				handlers.writable(chan, chan->token);
			}
		}
	}

	return 0;
}
