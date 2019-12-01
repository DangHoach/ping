/*
 * Ping.h
 *
 *  Created on: Nov 30, 2019
 *      Author: danghoach
 */

#ifndef PING_H_
#define PING_H_
#include <iostream>
#include <assert.h>
#include <net/if.h>
#include <netinet/ip_icmp.h>
using namespace std;


#define ENABLE_FEATURE_CLEAN_UP 1
#define BB_LITTLE_ENDIAN 0


#ifdef __BIONIC__
/* should be in netinet/ip_icmp.h */
# define ICMP_DEST_UNREACH    3  /* Destination Unreachable  */
# define ICMP_SOURCE_QUENCH   4  /* Source Quench    */
# define ICMP_REDIRECT        5  /* Redirect (change route)  */
# define ICMP_ECHO            8  /* Echo Request      */
# define ICMP_TIME_EXCEEDED  11  /* Time Exceeded    */
# define ICMP_PARAMETERPROB  12  /* Parameter Problem    */
# define ICMP_TIMESTAMP      13  /* Timestamp Request    */
# define ICMP_TIMESTAMPREPLY 14  /* Timestamp Reply    */
# define ICMP_INFO_REQUEST   15  /* Information Request    */
# define ICMP_INFO_REPLY     16  /* Information Reply    */
# define ICMP_ADDRESS        17  /* Address Mask Request    */
# define ICMP_ADDRESSREPLY   18  /* Address Mask Reply    */
#endif

/* Some operating systems, like GNU/Hurd, don't define SOL_RAW, but do have
 * IPPROTO_RAW. Since the IPPROTO definitions are also valid to use for
 * setsockopt (and take the same value as their corresponding SOL definitions,
 * if they exist), we can just fall back on IPPROTO_RAW. */
#ifndef SOL_RAW
# define SOL_RAW IPPROTO_RAW
#endif

# include <netinet/icmp6.h>
/* I see RENUMBERED constants in bits/in.h - !!?
 * What a fuck is going on with libc? Is it a glibc joke? */
# ifdef IPV6_2292HOPLIMIT
#  undef IPV6_HOPLIMIT
#  define IPV6_HOPLIMIT IPV6_2292HOPLIMIT
# endif


enum {
	DEFDATALEN = 56,
	MAXIPLEN = 60,
	MAXICMPLEN = 76,
	MAX_DUP_CHK = (8 * 128),
	MAXWAIT = 10,
	PINGINTERVAL = 1, /* 1 second */
	pingsock = 0,
};

typedef struct len_and_sockaddr {
	socklen_t len;
	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} u;
} len_and_sockaddr;
enum {
	LSA_LEN_SIZE = offsetof(len_and_sockaddr, u),
	/*
	LSA_SIZEOF_SA = sizeof(
		union {
			struct sockaddr sa;
			struct sockaddr_in sin;
			struct sockaddr_in6 sin6;
		}
	)
	*/
	LSA_SIZEOF_SA = sizeof(((len_and_sockaddr *)0)->u)
};

/* We use it for "global" data via *(struct global*)bb_common_bufsiz1.
 * Since gcc insists on aligning struct global's members, it would be a pity
 * (and an alignment fault on some CPUs) to mess it up. */
#define ALIGNED(m) __attribute__ ((__aligned__(m)))
//char bb_common_bufsiz1[COMMON_BUFSIZE] ALIGNED(sizeof(long long));
inline char bb_common_bufsiz1[1024] ALIGNED(sizeof(long long));

#define BUILD_BUG_ON(condition) ((void)sizeof(char[1 - 2*!!(condition)]))
/*
 * It is not defined as a dummy macro.
 * It means we have to provide this function.
 */
void setup_common_bufsiz(void);

enum {
	OPT_QUIET = 1 << 0,
	OPT_VERBOSE = 1 << 1,
	OPT_A = 1 << 2,
	OPT_c = 1 << 3,
	OPT_s = 1 << 4,
	OPT_t = 1 << 5,
	OPT_w = 1 << 6,
	OPT_W = 1 << 7,
	OPT_I = 1 << 8,
	/*OPT_n = 1 << 9, - ignored */
	OPT_p = 1 << 10,
	OPT_i = 1 << 11,
	OPT_IPV4 = 1 << 12,
	OPT_IPV6 = 1 << 13,
};
struct globals {
	int if_index;
	char *str_I;
	len_and_sockaddr *source_lsa;
	unsigned datalen;
	unsigned pingcount; /* must be int-sized */
	unsigned opt_ttl;
	unsigned long ntransmitted, nreceived, nrepeats;
	uint16_t myid;
	uint8_t pattern;
	unsigned tmin, tmax; /* in us */
	unsigned long long tsum; /* in us, sum of all times */
	unsigned cur_us; /* low word only, we don't need more */
	unsigned deadline_us;
	unsigned interval_us;
	unsigned timeout;
	unsigned sizeof_rcv_packet;
	char *rcv_packet; /* [datalen + MAXIPLEN + MAXICMPLEN] */
	void *snd_packet; /* [datalen + ipv4/ipv6_const] */
	const char *hostname;
	const char *dotted;
	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} pingaddr;
	unsigned char rcvd_tbl[MAX_DUP_CHK / 8];
};
#define G (*(struct globals*)bb_common_bufsiz1)
#define if_index     (G.if_index    )
#define source_lsa   (G.source_lsa  )
#define str_I        (G.str_I       )
#define datalen      (G.datalen     )
#define pingcount    (G.pingcount   )
#define opt_ttl      (G.opt_ttl     )
#define myid         (G.myid        )
#define tmin         (G.tmin        )
#define tmax         (G.tmax        )
#define tsum         (G.tsum        )
#define timeout      (G.timeout     )
#define hostname     (G.hostname    )
#define dotted       (G.dotted      )
#define pingaddr     (G.pingaddr    )
#define rcvd_tbl     (G.rcvd_tbl    )
#define INIT_G() do { \
	setup_common_bufsiz(); \
	BUILD_BUG_ON(sizeof(G) > 1024); \
	datalen = DEFDATALEN; \
	timeout = MAXWAIT; \
	tmin = UINT_MAX; \
} while (0)


#define BYTE(bit)	rcvd_tbl[(bit)>>3]
#define MASK(bit)	(1 << ((bit) & 7))
#define SET(bit)	(BYTE(bit) |= MASK(bit))
#define CLR(bit)	(BYTE(bit) &= (~MASK(bit)))
#define TST(bit)	(BYTE(bit) & MASK(bit))

inline uint32_t option_mask32;
typedef int      bb__aliased_int;
# define move_from_unaligned_int(v, intp)  ((v) = *(bb__aliased_int*)(intp))
#define ENABLE_FEATURE_UNIX_LOCAL 0

class Ping
{
public:
	Ping(){};
	~Ping(){};
	static void create_icmp_socket(len_and_sockaddr *lsa);
	//void xmove_fd(int from, int to);
	//void xdup2(int from, int to);
	//ssize_t xsendto(int s, const void *buf, size_t len, const struct sockaddr *to, socklen_t tolen);
	static void print_stats_and_exit(int junk);
	static void sendping_tail(void (*sp)(int), int size_pkt);
	static void sendping4(int junk);
	static void sendping6(int junk);
	static void unpack_tail(int sz, uint32_t *tp, const char *from_str, uint16_t recv_seq, int ttl);
	static int unpack4(char *buf, int sz, struct sockaddr_in *from);
	static int unpack6(char *packet, int sz, struct sockaddr_in6 *from, int hoplimit);
	static void ping4(len_and_sockaddr *lsa);
	static void ping6(len_and_sockaddr *lsa);
	static void ping(len_and_sockaddr *lsa);
	static int common_ping_main();
};

#endif /* PING_H_ */
