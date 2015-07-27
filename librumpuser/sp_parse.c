#include <sys/socket.h>
#include <sys/un.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

typedef int (*addrparse_fn)(const char *, struct sockaddr **, int);
typedef int (*connecthook_fn)(int);
typedef void (*cleanup_fn)(struct sockaddr *);

static int
tcp_parse(const char *addr, struct sockaddr **sa, int allow_wildcard)
{
	struct sockaddr_in sin;
	char buf[64];
	const char *p;
	size_t l;
	int port;

	memset(&sin, 0, sizeof(sin));
	SIN_SETLEN(sin, sizeof(sin));
	sin.sin_family = AF_INET;

	p = strchr(addr, ':');
	if (!p) {
		fprintf(stderr, "rump_sp_tcp: missing port specifier\n");
		return EINVAL;
	}

	l = p - addr;
	if (l > sizeof(buf)-1) {
		fprintf(stderr, "rump_sp_tcp: address too long\n");
		return EINVAL;
	}
	strncpy(buf, addr, l);
	buf[l] = '\0';

	/* special INADDR_ANY treatment */
	if (strcmp(buf, "*") == 0 || strcmp(buf, "0") == 0) {
		sin.sin_addr.s_addr = INADDR_ANY;
	} else {
		switch (inet_pton(AF_INET, buf, &sin.sin_addr)) {
		case 1:
			break;
		case 0:
			fprintf(stderr, "rump_sp_tcp: cannot parse %s\n", buf);
			return EINVAL;
		case -1:
			fprintf(stderr, "rump_sp_tcp: inet_pton failed\n");
			return errno;
		default:
			assert(/*CONSTCOND*/0);
			return EINVAL;
		}
	}

	if (!allow_wildcard && sin.sin_addr.s_addr == INADDR_ANY) {
		fprintf(stderr, "rump_sp_tcp: client needs !INADDR_ANY\n");
		return EINVAL;
	}

	/* advance to port number & parse */
	p++;
	l = strspn(p, "0123456789");
	if (l == 0) {
		fprintf(stderr, "rump_sp_tcp: port now found: %s\n", p);
		return EINVAL;
	}
	strncpy(buf, p, l);
	buf[l] = '\0';

	if (*(p+l) != '/' && *(p+l) != '\0') {
		fprintf(stderr, "rump_sp_tcp: junk at end of port: %s\n", addr);
		return EINVAL;
	}

	port = atoi(buf);
	if (port < 0 || port >= (1<<(8*sizeof(in_port_t)))) {
		fprintf(stderr, "rump_sp_tcp: port %d out of range\n", port);
		return ERANGE;
	}
	sin.sin_port = htons(port);

	*sa = malloc(sizeof(sin));
	if (*sa == NULL)
		return errno;
	memcpy(*sa, &sin, sizeof(sin));
	return 0;
}

static int
tcp_connecthook(int s)
{
	int x;

	x = 1;
	host_setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &x, sizeof(x));

	return 0;
}

static char parsedurl[256];

/*ARGSUSED*/
static int
unix_parse(const char *addr, struct sockaddr **sa, int allow_wildcard)
{
	struct sockaddr_un s_un;
	size_t slen;
	int savepath = 0;

	if (strlen(addr) >= sizeof(s_un.sun_path))
		return ENAMETOOLONG;

	/*
	 * The pathname can be all kinds of spaghetti elementals,
	 * so meek and obidient we accept everything.  However, use
	 * full path for easy cleanup in case someone gives a relative
	 * one and the server does a chdir() between now than the
	 * cleanup.
	 */
	memset(&s_un, 0, sizeof(s_un));
	s_un.sun_family = AF_LOCAL;
	if (*addr != '/') {
		char mywd[PATH_MAX];

		if (getcwd(mywd, sizeof(mywd)) == NULL) {
			fprintf(stderr, "warning: cannot determine cwd, "
			    "omitting socket cleanup\n");
		} else {
			if (strlen(addr)+strlen(mywd)+1
			    >= sizeof(s_un.sun_path))
				return ENAMETOOLONG;
			strcpy(s_un.sun_path, mywd);
			strcat(s_un.sun_path, "/");
			savepath = 1;
		}
	}
	strcat(s_un.sun_path, addr);
#if defined(__linux__) || defined(__sun__) || defined(__CYGWIN__)
	slen = sizeof(s_un);
#else
	s_un.sun_len = SUN_LEN(&s_un);
	slen = s_un.sun_len+1; /* get the 0 too */
#endif

	if (savepath && *parsedurl == '\0') {
		snprintf(parsedurl, sizeof(parsedurl),
		    "unix://%s", s_un.sun_path);
	}

	*sa = malloc(slen);
	if (*sa == NULL)
		return errno;
	memcpy(*sa, &s_un, slen);

	return 0;
}

static void
unix_cleanup(struct sockaddr *sa)
{
	struct sockaddr_un *s_sun = (void *)sa;

	/*
	 * cleanup only absolute paths.  see unix_parse() above
	 */
	if (*s_sun->sun_path == '/') {
		unlink(s_sun->sun_path);
	}
}

/*ARGSUSED*/
static int
notsupp(void)
{

	fprintf(stderr, "rump_sp: support not yet implemented\n");
	return EOPNOTSUPP;
}

static int
success(void)
{

	return 0;
}

static struct {
	const char *id;
	int domain;
	socklen_t slen;
	addrparse_fn ap;
	connecthook_fn connhook;
	cleanup_fn cleanup;
} parsetab[] = {
	{ "tcp", PF_INET, sizeof(struct sockaddr_in),
	    tcp_parse, tcp_connecthook, (cleanup_fn)success },
	{ "unix", PF_LOCAL, sizeof(struct sockaddr_un),
	    unix_parse, (connecthook_fn)success, unix_cleanup },
	{ "tcp6", PF_INET6, sizeof(struct sockaddr_in6),
	    (addrparse_fn)notsupp, (connecthook_fn)success,
	    (cleanup_fn)success },
};
#define NPARSE (sizeof(parsetab)/sizeof(parsetab[0]))

static int
parseurl(const char *url, struct sockaddr **sap, unsigned *idxp,
	int allow_wildcard)
{
	char id[16];
	const char *p, *p2;
	size_t l;
	unsigned i;
	int error;

	/*
	 * Parse the url
	 */

	p = url;
	p2 = strstr(p, "://");
	if (!p2) {
		fprintf(stderr, "rump_sp: invalid locator ``%s''\n", p);
		return EINVAL;
	}
	l = p2-p;
	if (l > sizeof(id)-1) {
		fprintf(stderr, "rump_sp: identifier too long in ``%s''\n", p);
		return EINVAL;
	}

	strncpy(id, p, l);
	id[l] = '\0';
	p2 += 3; /* beginning of address */

	for (i = 0; i < NPARSE; i++) {
		if (strcmp(id, parsetab[i].id) == 0) {
			error = parsetab[i].ap(p2, sap, allow_wildcard);
			if (error)
				return error;
			break;
		}
	}
	if (i == NPARSE) {
		fprintf(stderr, "rump_sp: invalid identifier ``%s''\n", p);
		return EINVAL;
	}

	*idxp = i;
	return 0;
}
