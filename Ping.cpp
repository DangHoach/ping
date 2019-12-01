/*
 * Ping.cpp
 *
 *  Created on: Nov 30, 2019
 *      Author: danghoach
 */
#include <unistd.h>
#include <signal.h>
#include <iostream>
#include <limits.h>
#include <sys/time.h>
#include <cstdint>
#include <arpa/inet.h>
#include <stdarg.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h> /* netinet/in.h needs it */
#include <netinet/in.h>
#include <net/if.h>
#include <sys/un.h>
#include "Ping.h"


void xdup2(int from, int to)
{
	if (dup2(from, to) != to)
		cout<<"can't duplicate file descriptor\n";
}

// "Renumber" opened fd
void xmove_fd(int from, int to)
{
	if (from == to)
		return;
	xdup2(from, to);
	close(from);
}

/* Die with an error message if sendto failed.
 * Return bytes sent otherwise  */
ssize_t xsendto(int s, const void *buf, size_t len, const struct sockaddr *to, socklen_t tolen)
{
	ssize_t ret = sendto(s, buf, len, 0, to, tolen);
	if (ret < 0) {
		if (ENABLE_FEATURE_CLEAN_UP)
			close(s);
		cout<<"sendto\n";
	}
	return ret;
}


unsigned long long monotonic_ns(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv.tv_sec * 1000000000ULL + tv.tv_usec * 1000;
}
unsigned long long monotonic_us(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv.tv_sec * 1000000ULL + tv.tv_usec;
}
unsigned long long monotonic_ms(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv.tv_sec * 1000ULL + tv.tv_usec / 1000;
}
unsigned  monotonic_sec(void)
{
	return time(NULL);
}


uint16_t inet_cksum(uint16_t *addr, int nleft)
{
	/*
	 * Our algorithm is simple, using a 32 bit accumulator,
	 * we add sequential 16 bit words to it, and at the end, fold
	 * back all the carry bits from the top 16 bits into the lower
	 * 16 bits.
	 */
	unsigned sum = 0;
	while (nleft > 1) {
		sum += *addr++;
		nleft -= 2;
	}

	/* Mop up an odd byte, if necessary */
	if (nleft == 1) {
		if (BB_LITTLE_ENDIAN)
			sum += *(uint8_t*)addr;
		else
			sum += *(uint8_t*)addr << 8;
	}

	/* Add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
	sum += (sum >> 16);                     /* add carry */

	return (uint16_t)~sum;
}

// Die with an error message if we can't bind a socket to an address.
void xbind(int sockfd, struct sockaddr *my_addr, socklen_t addrlen)
{
	if (bind(sockfd, my_addr, addrlen)) cout<<"bind\n";
}

int setsockopt_int(int fd, int level, int optname, int optval)
{
	return setsockopt(fd, level, optname, &optval, sizeof(int));
}
int setsockopt_1(int fd, int level, int optname)
{
	return setsockopt_int(fd, level, optname, 1);
}

int setsockopt_SOL_SOCKET_int(int fd, int optname, int optval)
{
	return setsockopt_int(fd, SOL_SOCKET, optname, optval);
}

int setsockopt_SOL_SOCKET_1(int fd, int optname)
{
	return setsockopt_SOL_SOCKET_int(fd, optname, 1);
}

int setsockopt_broadcast(int fd)
{
	return setsockopt_SOL_SOCKET_1(fd, SO_BROADCAST);
}


// Die with an error message if we can't malloc() enough space and do an
// sprintf() into that space.
char* xasprintf(const char *format, ...)
{
	va_list p;
	int r;
	char *string_ptr;

	va_start(p, format);
	r = vasprintf(&string_ptr, format, p);
	va_end(p);

	if (r < 0)
		cout<<"bb_die_memory_exhausted\n";
	return string_ptr;
}
// Die if we can't copy a string to freshly allocated memory.
char* xstrdup(const char *s)
{
	char *t;

	if (s == NULL)
		return NULL;

	t = strdup(s);

	if (t == NULL)
		cout<<"bb_die_memory_exhausted\n";

	return t;
}

/* We hijack this constant to mean something else */
/* It doesn't hurt because we will add this bit anyway */
#define IGNORE_PORT NI_NUMERICSERV
static char* sockaddr2str(const struct sockaddr *sa, int flags)
{
	char host[128];
	char serv[16];
	int rc;
	socklen_t salen;

	if (ENABLE_FEATURE_UNIX_LOCAL && sa->sa_family == AF_UNIX) {
		struct sockaddr_un *sun = (struct sockaddr_un *)sa;
		return xasprintf("local:%.*s",(int) sizeof(sun->sun_path), sun->sun_path);
	}

	salen = LSA_SIZEOF_SA;

	if (sa->sa_family == AF_INET)
		salen = sizeof(struct sockaddr_in);
	if (sa->sa_family == AF_INET6)
		salen = sizeof(struct sockaddr_in6);

	rc = getnameinfo(sa, salen,
			host, sizeof(host),
	/* can do ((flags & IGNORE_PORT) ? NULL : serv) but why bother? */
			serv, sizeof(serv),
			/* do not resolve port# into service _name_ */
			flags | NI_NUMERICSERV
	);
	if (rc)
		return NULL;
	if (flags & IGNORE_PORT)
		return xstrdup(host);

	if (sa->sa_family == AF_INET6) {
		if (strchr(host, ':')) /* heh, it's not a resolved hostname */
			return xasprintf("[%s]:%s", host, serv);
		/*return xasprintf("%s:%s", host, serv);*/
		/* - fall through instead */
	}
	/* For now we don't support anything else, so it has to be INET */
	/*if (sa->sa_family == AF_INET)*/
		return xasprintf("%s:%s", host, serv);
	/*return xstrdup(host);*/
}
#ifndef NI_NUMERICSCOPE
# define NI_NUMERICSCOPE 0
#endif
char* xmalloc_sockaddr2dotted_noport(const struct sockaddr *sa)
{
	return sockaddr2str(sa, NI_NUMERICHOST | NI_NUMERICSCOPE | IGNORE_PORT);
}

int setsockopt_bindtodevice(int fd, const char *iface)
{
	cout<<"SO_BINDTODEVICE is not supported on this system\n";
	return -1;
}

// Die if we can't allocate size bytes of memory.
void* xmalloc(size_t size)
{
	void *ptr = malloc(size);
	if (ptr == NULL && size != 0)
		cout <<"bb_die_memory_exhausted\n";
	return ptr;
}

// Die if we can't allocate and zero size bytes of memory.
void* xzalloc(size_t size)
{
	void *ptr = xmalloc(size);
	memset(ptr, 0, size);
	return ptr;
}

void setup_common_bufsiz(void)
{
	if (!bb_common_bufsiz1)
		*(char**)&bb_common_bufsiz1 = (char*)xzalloc(1024);
}

/*
 * Return NULL if string is not prefixed with key. Return pointer to the
 * first character in string after the prefix key. If key is an empty string,
 * return pointer to the beginning of string.
 */
char* is_prefixed_with(const char *string, const char *key)
{
#if 0	/* Two passes over key - probably slower */
	int len = strlen(key);
	if (strncmp(string, key, len) == 0)
		return string + len;
	return NULL;
#else	/* Open-coded */
	while (*key != '\0') {
		if (*key != *string)
			return NULL;
		key++;
		string++;
	}
	return (char*)string;
#endif
}
/* Keeping it separate allows to NOT pull in stdio for VERY small applets.
 * Try building busybox with only "true" enabled... */
uint8_t xfunc_error_retval = EXIT_FAILURE;
void (*die_func)(void);
void xfunc_die(void)
{
	if (die_func)
		die_func();
	exit(xfunc_error_retval);
}
void set_nport(struct sockaddr *sa, unsigned port)
{
	if (sa->sa_family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (sockaddr_in6*) sa;
		sin6->sin6_port = port;
		return;
	}
	if (sa->sa_family == AF_INET) {
		struct sockaddr_in *sin = (sockaddr_in*) sa;
		sin->sin_port = port;
		return;
	}
	/* What? UNIX socket? IPX?? :) */
}
/* Like strncpy but make sure the resulting string is always 0 terminated. */
char* safe_strncpy(char *dst, const char *src, size_t size)
{
	if (!size) return dst;
	dst[--size] = '\0';
	return strncpy(dst, src, size);
}
static unsigned long long ret_ERANGE(void)
{
	errno = ERANGE; /* this ain't as small as it looks (on glibc) */
	return ULLONG_MAX;
}

static unsigned long long handle_errors(unsigned long long v, char **endp)
{
	char next_ch = **endp;

	/* errno is already set to ERANGE by strtoXXX if value overflowed */
	if (next_ch) {
		/* "1234abcg" or out-of-range? */
		if (isalnum(next_ch) || errno)
			return ret_ERANGE();
		/* good number, just suspicious terminator */
		errno = EINVAL;
	}
	return v;
}

unsigned bb_strtou(const char *arg, char **endp, int base)
{
	unsigned long v;
	char *endptr;

	if (!endp) endp = &endptr;
	*endp = (char*) arg;

	if (!isalnum(arg[0])) return ret_ERANGE();
	errno = 0;
	v = strtoul(arg, endp, base);
	if (v > UINT_MAX) return ret_ERANGE();
	return handle_errors(v, endp);
}

/* We hijack this constant to mean something else */
/* It doesn't hurt because we will remove this bit anyway */
#define DIE_ON_ERROR AI_CANONNAME
#define ENABLE_FEATURE_IPV6 1
/* host: "1.2.3.4[:port]", "www.google.com[:port]"
 * port: if neither of above specifies port # */
static len_and_sockaddr* str2sockaddr(const char *host, int port, sa_family_t af, int ai_flags)
{
	//sa_family_t af = AF_INET;
	int rc;
	len_and_sockaddr *r;
	struct addrinfo *result = NULL;
	struct addrinfo *used_res;
	const char *org_host = host; /* only for error msg */
	const char *cp;
	struct addrinfo hint;

	if (ENABLE_FEATURE_UNIX_LOCAL && is_prefixed_with(host, "local:")) {
		struct sockaddr_un *sun;

		r = (len_and_sockaddr*)xzalloc(LSA_LEN_SIZE + sizeof(struct sockaddr_un));
		r->len = sizeof(struct sockaddr_un);
		r->u.sa.sa_family = AF_UNIX;
		sun = (struct sockaddr_un *)&r->u.sa;
		safe_strncpy(sun->sun_path, host + 6, sizeof(sun->sun_path));
		return r;
	}

	r = NULL;

	/* Ugly parsing of host:addr */
	if (ENABLE_FEATURE_IPV6 && host[0] == '[') {
		/* Even uglier parsing of [xx]:nn */
		host++;
		cp = strchr(host, ']');
		if (!cp || (cp[1] != ':' && cp[1] != '\0')) {
			/* Malformed: must be [xx]:nn or [xx] */
			cout<<"bad address "<< org_host;
			if (ai_flags & DIE_ON_ERROR)
				xfunc_die();
			return NULL;
		}
	} else {
		cp = strrchr(host, ':');
		if (ENABLE_FEATURE_IPV6 && cp && strchr(host, ':') != cp) {
			/* There is more than one ':' (e.g. "::1") */
			cp = NULL; /* it's not a port spec */
		}
	}
	if (cp) { /* points to ":" or "]:" */
		int sz = cp - host + 1;

		host = safe_strncpy((char*)alloca(sz), host, sz);
		if (ENABLE_FEATURE_IPV6 && *cp != ':') {
			cp++; /* skip ']' */
			if (*cp == '\0') /* [xx] without port */
				goto skip;
		}
		cp++; /* skip ':' */
		port = bb_strtou(cp, NULL, 10);
		if (errno || (unsigned)port > 0xffff) {
			cout<<"bad port spec "<< org_host;
			if (ai_flags & DIE_ON_ERROR)
				xfunc_die();
			return NULL;
		}
 skip: ;
	}

	/* Next two if blocks allow to skip getaddrinfo()
	 * in case host name is a numeric IP(v6) address.
	 * getaddrinfo() initializes DNS resolution machinery,
	 * scans network config and such - tens of syscalls.
	 */
	/* If we were not asked specifically for IPv6,
	 * check whether this is a numeric IPv4 */
	if(af != AF_INET6) {
		struct in_addr in4;
		if (inet_aton(host, &in4) != 0) {
			r = (len_and_sockaddr*)xzalloc(LSA_LEN_SIZE + sizeof(struct sockaddr_in));
			r->len = sizeof(struct sockaddr_in);
			r->u.sa.sa_family = AF_INET;
			r->u.sin.sin_addr = in4;
			goto set_port;
		}
	}

	/* If we were not asked specifically for IPv4,
	 * check whether this is a numeric IPv6 */
	if (af != AF_INET) {
		struct in6_addr in6;
		if (inet_pton(AF_INET6, host, &in6) > 0) {
			r = (len_and_sockaddr*)xzalloc(LSA_LEN_SIZE + sizeof(struct sockaddr_in6));
			r->len = sizeof(struct sockaddr_in6);
			r->u.sa.sa_family = AF_INET6;
			r->u.sin6.sin6_addr = in6;
			goto set_port;
		}
	}


	memset(&hint, 0 , sizeof(hint));
	hint.ai_family = af;
	/* Need SOCK_STREAM, or else we get each address thrice (or more)
	 * for each possible socket type (tcp,udp,raw...): */
	hint.ai_socktype = SOCK_STREAM;
	hint.ai_flags = ai_flags & ~DIE_ON_ERROR;
	rc = getaddrinfo(host, NULL, &hint, &result);
	if (rc || !result) {
		cout<<"bad address "<< org_host;
		if (ai_flags & DIE_ON_ERROR)
			xfunc_die();
		goto ret;
	}
	used_res = result;

	while (1) {
		if (used_res->ai_family == AF_INET)
			break;
		used_res = used_res->ai_next;
		if (!used_res) {
			used_res = result;
			break;
		}
	}

	r = (len_and_sockaddr*)xmalloc(LSA_LEN_SIZE + used_res->ai_addrlen);
	r->len = used_res->ai_addrlen;
	memcpy(&r->u.sa, used_res->ai_addr, used_res->ai_addrlen);

 set_port:
	set_nport(&r->u.sa, htons(port));
 ret:
	if (result)
		freeaddrinfo(result);
	return r;
}
//#define xstrtou(rest) xstrtou##rest
//
//unsigned type xstrtou(_range)(const char *numstr, int base, unsigned type lower, unsigned type upper)
//{
//	return xstrtou(_range_sfx)(numstr, base, lower, upper, NULL);
//}


len_and_sockaddr* host_and_af2sockaddr(const char *host, int port, sa_family_t af)
{
	return str2sockaddr(host, port, af, 0);
}

len_and_sockaddr* xhost_and_af2sockaddr(const char *host, int port, sa_family_t af)
{
	return str2sockaddr(host, port, af, DIE_ON_ERROR);
}

len_and_sockaddr* xdotted2sockaddr(const char *host, int port)
{
	return str2sockaddr(host, port, AF_UNSPEC, AI_NUMERICHOST | DIE_ON_ERROR);
}



void Ping::create_icmp_socket(len_and_sockaddr *lsa)
{
	int sock;
	if (lsa->u.sa.sa_family == AF_INET6)
		sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	else
		sock = socket(AF_INET, SOCK_RAW, 1); /* 1 == ICMP */
	if (sock < 0) {
		if (errno == EPERM)
			cout <<"bb_msg_perm_denied_are_you_root\n";
		cout <<"bb_msg_can_not_create_raw_socketssss\n";
	}

	xmove_fd(sock, pingsock);
}


void Ping::print_stats_and_exit(int junk)
{
	unsigned long ul;
	unsigned long nrecv;

	signal(SIGINT, SIG_IGN);

	nrecv = G.nreceived;
	printf("\n--- %s ping statistics ---\n"
		"%lu packets transmitted, "
		"%lu packets received, ",
		hostname, G.ntransmitted, nrecv
	);
	if (G.nrepeats)
		printf("%lu duplicates, ", G.nrepeats);
	ul = G.ntransmitted;
	if (ul != 0)
		ul = (ul - nrecv) * 100 / ul;
	printf("%lu%% packet loss\n", ul);
	if (tmin != UINT_MAX) {
		unsigned tavg = tsum / (nrecv + G.nrepeats);
		printf("round-trip min/avg/max = %u.%03u/%u.%03u/%u.%03u ms\n",
			tmin / 1000, tmin % 1000,
			tavg / 1000, tavg % 1000,
			tmax / 1000, tmax % 1000);
	}
	/* if condition is true, exit with 1 -- 'failure' */
	exit(nrecv == 0 || (G.deadline_us && nrecv < pingcount));
}

void Ping::sendping_tail(void (*sp)(int), int size_pkt)
{
	int sz;

	CLR((uint16_t)G.ntransmitted % MAX_DUP_CHK);
	G.ntransmitted++;

	size_pkt += datalen;

	if (G.deadline_us) {
		unsigned n = G.cur_us - G.deadline_us;
		if ((int)n >= 0)
			print_stats_and_exit(0);
	}

	/* sizeof(pingaddr) can be larger than real sa size, but I think
	 * it doesn't matter */
	sz = xsendto(pingsock, G.snd_packet, size_pkt, &pingaddr.sa, sizeof(pingaddr));
	if (sz != size_pkt)
	{
		cout<<"bb_msg_write_error\n";
	}

	if (pingcount == 0 || G.ntransmitted < pingcount) {
		/* Didn't send all pings yet - schedule next in -i SEC interval */
		struct itimerval i;
		signal(SIGALRM, sp);
		/*ualarm(G.interval_us, 0); - does not work for >=1sec on some libc */
		i.it_interval.tv_sec = 0;
		i.it_interval.tv_usec = 0;
		i.it_value.tv_sec = G.interval_us / 1000000;
		i.it_value.tv_usec = G.interval_us % 1000000;
		setitimer(ITIMER_REAL, &i, NULL);
	} else { /* -c NN, and all NN are sent */
		/* Wait for the last ping to come back.
		 * -W timeout: wait for a response in seconds.
		 * Affects only timeout in absence of any responses,
		 * otherwise ping waits for two RTTs. */
		unsigned expire = timeout;

		if (G.nreceived) {
			/* approx. 2*tmax, in seconds (2 RTT) */
			expire = tmax / (512*1024);
			if (expire == 0)
				expire = 1;
		}
		signal(SIGALRM, print_stats_and_exit);
		alarm(expire);
	}
}

void Ping::sendping4(int junk)
{
	struct icmp *pkt = (icmp*)G.snd_packet;

	memset(pkt, G.pattern, datalen + ICMP_MINLEN + 4);
	pkt->icmp_type = ICMP_ECHO;
	/*pkt->icmp_code = 0;*/
	pkt->icmp_cksum = 0; /* cksum is calculated with this field set to 0 */
	pkt->icmp_seq = htons(G.ntransmitted); /* don't ++ here, it can be a macro */
	pkt->icmp_id = myid;

	/* If datalen < 4, we store timestamp _past_ the packet,
	 * but it's ok - we allocated 4 extra bytes in xzalloc() just in case.
	 */
	/*if (datalen >= 4)*/
		/* No hton: we'll read it back on the same machine */
		*(uint32_t*)&pkt->icmp_dun = G.cur_us = monotonic_us();

	pkt->icmp_cksum = inet_cksum((uint16_t *) pkt, datalen + ICMP_MINLEN);

	sendping_tail(sendping4, ICMP_MINLEN);
}

void Ping::sendping6(int junk)
{
	struct icmp6_hdr *pkt = (icmp6_hdr*)G.snd_packet;

	memset(pkt, G.pattern, datalen + sizeof(struct icmp6_hdr) + 4);
	pkt->icmp6_type = ICMP6_ECHO_REQUEST;
	/*pkt->icmp6_code = 0;*/
	/*pkt->icmp6_cksum = 0;*/
	pkt->icmp6_seq = htons(G.ntransmitted); /* don't ++ here, it can be a macro */
	pkt->icmp6_id = myid;

	/*if (datalen >= 4)*/
		*(uint32_t*)(&pkt->icmp6_data8[4]) = G.cur_us = monotonic_us();

	//TODO? pkt->icmp_cksum = inet_cksum(...);

	sendping_tail(sendping6, sizeof(struct icmp6_hdr));
}


static const char *icmp_type_name(int id)
{
	switch (id) {
	case ICMP_ECHOREPLY:      return "Echo Reply";
	case ICMP_DEST_UNREACH:   return "Destination Unreachable";
	case ICMP_SOURCE_QUENCH:  return "Source Quench";
	case ICMP_REDIRECT:       return "Redirect (change route)";
	case ICMP_ECHO:           return "Echo Request";
	case ICMP_TIME_EXCEEDED:  return "Time Exceeded";
	case ICMP_PARAMETERPROB:  return "Parameter Problem";
	case ICMP_TIMESTAMP:      return "Timestamp Request";
	case ICMP_TIMESTAMPREPLY: return "Timestamp Reply";
	case ICMP_INFO_REQUEST:   return "Information Request";
	case ICMP_INFO_REPLY:     return "Information Reply";
	case ICMP_ADDRESS:        return "Address Mask Request";
	case ICMP_ADDRESSREPLY:   return "Address Mask Reply";
	default:                  return "unknown ICMP type";
	}
}

/* RFC3542 changed some definitions from RFC2292 for no good reason, whee!
 * the newer 3542 uses a MLD_ prefix where as 2292 uses ICMP6_ prefix */
#ifndef MLD_LISTENER_QUERY
# define MLD_LISTENER_QUERY ICMP6_MEMBERSHIP_QUERY
#endif
#ifndef MLD_LISTENER_REPORT
# define MLD_LISTENER_REPORT ICMP6_MEMBERSHIP_REPORT
#endif
#ifndef MLD_LISTENER_REDUCTION
# define MLD_LISTENER_REDUCTION ICMP6_MEMBERSHIP_REDUCTION
#endif
static const char *icmp6_type_name(int id)
{
	switch (id) {
	case ICMP6_DST_UNREACH:      return "Destination Unreachable";
	case ICMP6_PACKET_TOO_BIG:   return "Packet too big";
	case ICMP6_TIME_EXCEEDED:    return "Time Exceeded";
	case ICMP6_PARAM_PROB:       return "Parameter Problem";
	case ICMP6_ECHO_REPLY:       return "Echo Reply";
	case ICMP6_ECHO_REQUEST:     return "Echo Request";
	case MLD_LISTENER_QUERY:     return "Listener Query";
	case MLD_LISTENER_REPORT:    return "Listener Report";
	case MLD_LISTENER_REDUCTION: return "Listener Reduction";
	default:                     return "unknown ICMP type";
	}
}


void Ping::unpack_tail(int sz, uint32_t *tp, const char *from_str, uint16_t recv_seq, int ttl)
{
	unsigned char *b, m;
	const char *dupmsg = " (DUP!)";
	unsigned triptime = triptime; /* for gcc */

	if (tp) {
		/* (int32_t) cast is for hypothetical 64-bit unsigned */
		/* (doesn't hurt 32-bit real-world anyway) */
		triptime = (int32_t) ((uint32_t)monotonic_us() - *tp);
		tsum += triptime;
		if (triptime < tmin)
			tmin = triptime;
		if (triptime > tmax)
			tmax = triptime;
	}

	b = &BYTE(recv_seq % MAX_DUP_CHK);
	m = MASK(recv_seq % MAX_DUP_CHK);
	/*if TST(recv_seq % MAX_DUP_CHK):*/
	if (*b & m) {
		++G.nrepeats;
	} else {
		/*SET(recv_seq % MAX_DUP_CHK):*/
		*b |= m;
		++G.nreceived;
		dupmsg += 7;
	}

	if (option_mask32 & OPT_QUIET)
		return;

	printf("%d bytes from %s: seq=%u ttl=%d", sz,
		from_str, recv_seq, ttl);
	if (tp)
		printf(" time=%u.%03u ms", triptime / 1000, triptime % 1000);
	puts(dupmsg);
	fflush(NULL);
}

int Ping::unpack4(char *buf, int sz, struct sockaddr_in *from)
{
	struct icmp *icmppkt;
	struct iphdr *iphdr;
	int hlen;

	/* discard if too short */
	if (sz < (datalen + ICMP_MINLEN))
		return 0;

	/* check IP header */
	iphdr = (struct iphdr *) buf;
	hlen = iphdr->ihl << 2;
	sz -= hlen;
	icmppkt = (struct icmp *) (buf + hlen);
	if (icmppkt->icmp_id != myid)
		return 0;				/* not our ping */

	if (icmppkt->icmp_type == ICMP_ECHOREPLY) {
		uint16_t recv_seq = ntohs(icmppkt->icmp_seq);
		uint32_t *tp = NULL;

		if (sz >= ICMP_MINLEN + sizeof(uint32_t))
			tp = (uint32_t *) icmppkt->icmp_data;
		unpack_tail(sz, tp, inet_ntoa(*(struct in_addr *) &from->sin_addr.s_addr), recv_seq, iphdr->ttl);
		return 1;
	}
	if (icmppkt->icmp_type != ICMP_ECHO) {
		cout<< "warning: got ICMP " << icmppkt->icmp_type << "(" << icmp_type_name(icmppkt->icmp_type) <<")";
	}
	return 0;
}

int Ping::unpack6(char *packet, int sz, struct sockaddr_in6 *from, int hoplimit)
{
	struct icmp6_hdr *icmppkt;
	char buf[INET6_ADDRSTRLEN];

	/* discard if too short */
	if (sz < (datalen + sizeof(struct icmp6_hdr)))
		return 0;

	icmppkt = (struct icmp6_hdr *) packet;
	if (icmppkt->icmp6_id != myid)
		return 0;				/* not our ping */

	if (icmppkt->icmp6_type == ICMP6_ECHO_REPLY) {
		uint16_t recv_seq = ntohs(icmppkt->icmp6_seq);
		uint32_t *tp = NULL;

		if (sz >= sizeof(struct icmp6_hdr) + sizeof(uint32_t))
			tp = (uint32_t *) &icmppkt->icmp6_data8[4];
		unpack_tail(sz, tp, inet_ntop(AF_INET6, &from->sin6_addr, buf, sizeof(buf)),
			recv_seq, hoplimit);
		return 1;
	}
	if (icmppkt->icmp6_type != ICMP6_ECHO_REQUEST) {
		cout<<"warning: got ICMP "<< icmppkt->icmp6_type <<"(" <<icmp6_type_name(icmppkt->icmp6_type)<<")";
	}
	return 0;
}

void Ping::ping4(len_and_sockaddr *lsa)
{
	int sockopt;

	pingaddr.sin = lsa->u.sin;
	if (source_lsa) {
		if (setsockopt(pingsock, IPPROTO_IP, IP_MULTICAST_IF, &source_lsa->u.sa, source_lsa->len))
		{
			cout <<"can't set multicast source interface\n";
		}
		xbind(pingsock, &source_lsa->u.sa, source_lsa->len);
	}

	/* enable broadcast pings */
	setsockopt_broadcast(pingsock);

	/* set recv buf (needed if we can get lots of responses: flood ping,
	 * broadcast ping etc) */
	sockopt = (datalen * 2) + 7 * 1024; /* giving it a bit of extra room */
	setsockopt_SOL_SOCKET_int(pingsock, SO_RCVBUF, sockopt);

	if (opt_ttl != 0) {
		setsockopt_int(pingsock, IPPROTO_IP, IP_TTL, opt_ttl);
		/* above doesn't affect packets sent to bcast IP, so... */
		setsockopt_int(pingsock, IPPROTO_IP, IP_MULTICAST_TTL, opt_ttl);
	}

	signal(SIGINT, print_stats_and_exit);

	/* start the ping's going ... */
 send_ping:
	sendping4(0);

	/* listen for replies */
	while (1) {
		struct sockaddr_in from;
		socklen_t fromlen = (socklen_t) sizeof(from);
		int c;

		c = recvfrom(pingsock, G.rcv_packet, G.sizeof_rcv_packet, 0, (struct sockaddr *) &from, &fromlen);
		if (c < 0) {
			if (errno != EINTR){
				//cout<< "recvfrom ping 4\n";
			}
			continue;
		}
		c = unpack4(G.rcv_packet, c, &from);
		if (pingcount && G.nreceived >= pingcount)
			break;
		if (c && (option_mask32 & OPT_A)) {
			goto send_ping;
		}
	}
}

void Ping::ping6(len_and_sockaddr *lsa)
{
	int sockopt;
	struct msghdr msg;
	struct sockaddr_in6 from;
	struct iovec iov;
	char control_buf[CMSG_SPACE(36)];

	pingaddr.sin6 = lsa->u.sin6;
	if (source_lsa)
		xbind(pingsock, &source_lsa->u.sa, source_lsa->len);

#ifdef ICMP6_FILTER
	{
		struct icmp6_filter filt;
		if (!(option_mask32 & OPT_VERBOSE)) {
			ICMP6_FILTER_SETBLOCKALL(&filt);
			ICMP6_FILTER_SETPASS(ICMP6_ECHO_REPLY, &filt);
		} else {
			ICMP6_FILTER_SETPASSALL(&filt);
		}
		if (setsockopt(pingsock, IPPROTO_ICMPV6, ICMP6_FILTER, &filt,sizeof(filt)) < 0)
			cout<<"setsockopt ICMP6_FILTER";
	}
#endif /*ICMP6_FILTER*/

	/* enable broadcast pings */
	setsockopt_broadcast(pingsock);

	/* set recv buf (needed if we can get lots of responses: flood ping,
	 * broadcast ping etc) */
	sockopt = (datalen * 2) + 7 * 1024; /* giving it a bit of extra room */
	setsockopt_SOL_SOCKET_int(pingsock, SO_RCVBUF, sockopt);

	sockopt = offsetof(struct icmp6_hdr, icmp6_cksum);
	BUILD_BUG_ON(offsetof(struct icmp6_hdr, icmp6_cksum) != 2);
	setsockopt_int(pingsock, SOL_RAW, IPV6_CHECKSUM, sockopt);

	/* request ttl info to be returned in ancillary data */
	setsockopt_1(pingsock, SOL_IPV6, IPV6_HOPLIMIT);

	if (if_index)
		pingaddr.sin6.sin6_scope_id = if_index;

	signal(SIGINT, print_stats_and_exit);

	msg.msg_name = &from;
	msg.msg_namelen = sizeof(from);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control_buf;
	iov.iov_base = G.rcv_packet;
	iov.iov_len = G.sizeof_rcv_packet;

	/* start the ping's going ... */
 send_ping:
	sendping6(0);

	/* listen for replies */
	while (1) {
		int c;
		struct cmsghdr *mp;
		int hoplimit = -1;

		msg.msg_controllen = sizeof(control_buf);
		c = recvmsg(pingsock, &msg, 0);
		if (c < 0) {
			if (errno != EINTR){
				//cout<< "recvfrom ping 6\n";
			}
			continue;
		}
		for (mp = CMSG_FIRSTHDR(&msg); mp; mp = CMSG_NXTHDR(&msg, mp)) {
			if (mp->cmsg_level == SOL_IPV6
			 && mp->cmsg_type == IPV6_HOPLIMIT
			 /* don't check len - we trust the kernel: */
			 /* && mp->cmsg_len >= CMSG_LEN(sizeof(int)) */
			) {
				/*hoplimit = *(int*)CMSG_DATA(mp); - unaligned access */
				move_from_unaligned_int(hoplimit, CMSG_DATA(mp));
			}
		}
		c = unpack6(G.rcv_packet, c, &from, hoplimit);
		if (pingcount && G.nreceived >= pingcount)
			break;
		if (c && (option_mask32 & OPT_A)) {
			goto send_ping;
		}
	}
}


void Ping::ping(len_and_sockaddr *lsa)
{
	printf("PING %s (%s)", hostname, dotted);
	if (source_lsa) {
		printf(" from %s",xmalloc_sockaddr2dotted_noport(&source_lsa->u.sa));
	}
	printf(": %d data bytes\n", datalen);

	create_icmp_socket(lsa);
	/* untested whether "-I addr" really works for IPv6: */
	if (str_I)
		setsockopt_bindtodevice(pingsock, str_I);

	G.sizeof_rcv_packet = datalen + MAXIPLEN + MAXICMPLEN;
	G.rcv_packet = (char*)xzalloc(G.sizeof_rcv_packet);

	if (lsa->u.sa.sa_family == AF_INET6)
	{
		cout << "call ping6\n";
		/* +4 reserves a place for timestamp, which may end up sitting
		 * _after_ packet. Saves one if() - see sendping4/6() */
		G.snd_packet = xzalloc(datalen + sizeof(struct icmp6_hdr) + 4);
		ping6(lsa);
	}
	else
	{
		cout << "call ping4\n";
		G.snd_packet = xzalloc(datalen + ICMP_MINLEN + 4);
		ping4(lsa);
	}
}
//usage:# define ping_trivial_usage
//usage:       "[OPTIONS] HOST"
//usage:# define ping_full_usage "\n\n"
//usage:       "Send ICMP ECHO_REQUEST packets to network hosts\n"
//usage:	IF_PING6(
//usage:     "\n	-4,-6		Force IP or IPv6 name resolution"
//usage:	)
//usage:     "\n	-c CNT		Send only CNT pings"
//usage:     "\n	-s SIZE		Send SIZE data bytes in packets (default 56)"
//usage:     "\n	-i SECS		Interval"
//usage:     "\n	-A		Ping as soon as reply is recevied"
//usage:     "\n	-t TTL		Set TTL"
//usage:     "\n	-I IFACE/IP	Source interface or IP address"
//usage:     "\n	-W SEC		Seconds to wait for the first response (default 10)"
//usage:     "\n			(after all -c CNT packets are sent)"
//usage:     "\n	-w SEC		Seconds until ping exits (default:infinite)"
//usage:     "\n			(can exit earlier with -c CNT)"
//usage:     "\n	-q		Quiet, only display output at start"
//usage:     "\n			and when finished"
//usage:     "\n	-p HEXBYTE	Pattern to use for payload"
//usage:
//usage:# define ping6_trivial_usage
//usage:       "[OPTIONS] HOST"
//usage:# define ping6_full_usage "\n\n"
//usage:       "Send ICMP ECHO_REQUEST packets to network hosts\n"
//usage:     "\n	-c CNT		Send only CNT pings"
//usage:     "\n	-s SIZE		Send SIZE data bytes in packets (default 56)"
//usage:     "\n	-i SECS		Interval"
//usage:     "\n	-A		Ping as soon as reply is recevied"
//usage:     "\n	-I IFACE/IP	Source interface or IP address"
//usage:     "\n	-q		Quiet, only display output at start"
//usage:     "\n			and when finished"
//usage:     "\n	-p HEXBYTE	Pattern to use for payload"
//usage:
//usage:#endif
//usage:
//usage:#define ping_example_usage
//usage:       "$ ping localhost\n"
//usage:       "PING slag (127.0.0.1): 56 data bytes\n"
//usage:       "64 bytes from 127.0.0.1: icmp_seq=0 ttl=255 time=20.1 ms\n"
//usage:       "\n"
//usage:       "--- debian ping statistics ---\n"
//usage:       "1 packets transmitted, 1 packets received, 0% packet loss\n"
//usage:       "round-trip min/avg/max = 20.1/20.1/20.1 ms\n"
//usage:#define ping6_example_usage
//usage:       "$ ping6 ip6-localhost\n"
//usage:       "PING ip6-localhost (::1): 56 data bytes\n"
//usage:       "64 bytes from ::1: icmp6_seq=0 ttl=64 time=20.1 ms\n"
//usage:       "\n"
//usage:       "--- ip6-localhost ping statistics ---\n"
//usage:       "1 packets transmitted, 1 packets received, 0% packet loss\n"
//usage:       "round-trip min/avg/max = 20.1/20.1/20.1 ms\n"

/* -c NUM, -t NUM, -w NUM, -W NUM */
#define OPT_STRING "qvAc:+s:t:+w:+W:+I:np:i:4"//IF_PING6("6")


int Ping::common_ping_main()
{
	len_and_sockaddr *lsa;
	char *str_s, *str_p;
	char *str_i = (char*)"1";
	unsigned interval;

	INIT_G();
	pingcount = 5;
	opt_ttl = 255;
//	char *str_IA = (char*)"eth1";

//	opt |= getopt32(argv, "^"
//			OPT_STRING
//			/* exactly one arg; -v and -q don't mix */
//			"\0" "=1:q--v:v--q",
//			&pingcount, &str_s, &opt_ttl, &G.deadline_us, &timeout, &str_I, &str_p, &str_i
//	);

//	if (opt & OPT_s)
//		datalen = xatou16(str_s); // -s


//	if_index = if_nametoindex(str_IA);
//	if (!if_index) {
//		/* TODO: I'm not sure it takes IPv6 unless in [XX:XX..] format */
//		source_lsa = xdotted2sockaddr(str_IA, 0);
//		str_IA = NULL;  /* don't try to bind to device later */
//	}

//	if (opt & OPT_p)
//		G.pattern = xstrtou_range(str_p, 16, 0, 255);
	if (G.deadline_us) {
		unsigned d = G.deadline_us < INT_MAX/1000000 ? G.deadline_us : INT_MAX/1000000;
		G.deadline_us = 1 | ((d * 1000000) + monotonic_us());
	}
	//interval = parse_duration_str(str_i);
	interval = 1;
	if (interval > INT_MAX/1000000)
		interval = INT_MAX/1000000;
	G.interval_us = interval * 1000000;

	myid = (uint16_t) getpid();

	hostname = (char*)"www.google.com";
	{
		sa_family_t af = AF_UNSPEC;
		//if (OPT_IPV4)
			af = AF_INET;
		//if (OPT_IPV6)
//			af = AF_INET6;
		lsa = xhost_and_af2sockaddr(hostname, 0, af);
	}

	if (source_lsa && source_lsa->u.sa.sa_family != lsa->u.sa.sa_family){
		cout<< "source_lsa = NULL\n";
		source_lsa = NULL;
	}
	dotted = xmalloc_sockaddr2dotted_noport(&lsa->u.sa);
	ping(lsa);
	print_stats_and_exit(0);
	return EXIT_SUCCESS;
}

