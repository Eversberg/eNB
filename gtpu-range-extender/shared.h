#pragma once

#include <stdint.h>

#define ARR_SZ(x) (sizeof(x) / sizeof(x[0]))
#define _UNU __attribute__((unused))
extern __thread char threadn[20];
extern __thread int threadn_color;
extern __thread int threadn_par_color;


#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMAG  "\x1B[35m"
#define KCYN  "\x1B[36m"
#define KWHT  "\x1B[37m"
#define RESET "\x1B[0m"


typedef enum {
	NO_COLOR,
    BLACK,
    RED,
    GREEN,
    YELLOW,
    BLUE,
    MAGENTA,
    CYAN,
    WHITE
} cons_colors;


static const char* cons_color(cons_colors color) {
    switch(color) {
        case BLACK:
            return RESET;
        case RED:
            return KRED;
        case GREEN:
            return KGRN;
        case YELLOW:
            return KYEL;
        case BLUE:
            return KBLU;
        case MAGENTA:
            return KMAG;
        case CYAN:
            return KCYN;
        case WHITE:
            return KWHT;
        case NO_COLOR:
            return RESET;
        default:
            return "";
    }
}


#if 0
#define fdbg_printf(fmt, ...) fprintf(stderr, "%s%s:%s " fmt "%s", cons_color(threadn_par_color), threadn, cons_color(threadn_color) __VA_OPT__(,) __VA_ARGS__, cons_color(NO_COLOR))
#define fdbg_printf_nc(fmt, ...) fprintf(stderr, fmt __VA_OPT__(,) __VA_ARGS__)
#else
#define fdbg_printf(fmt, ...)
#define fdbg_printf_nc(fmt, ...)
#endif



#define PERR(str)                                                        \
	if (str)                                                               \
		fprintf(stderr,  "%s %d %s: %s\n", __FILE__ ,__LINE__, str, strerror(errno)); \
	else                                                                   \
		fprintf(stderr, "%s %d %s\n", __FILE__ ,__LINE__, strerror(errno));

#define PERR_LT0_EXIT(cond) if ((cond) < 0) {PERR("E:"); exit_group((errno)); }



#define socket_or_die(var, dom, type, prot) \
	var = socket(dom, type, prot);            \
	if (var == -1) {                          \
		PERR("socket");                       \
		return (void *)EXIT_FAILURE;            \
	}

#define bind_or_die(sockvar, addr)                                   \
	ret = bind(sockvar, (const struct sockaddr *)&addr, sizeof(addr)); \
	if (ret == -1) {                                                   \
		PERR("bind");                                                  \
		return (void *)EXIT_FAILURE;                                     \
	}

#define connect_or_die(sockvar, addr)                                   \
	ret = connect(sockvar, (const struct sockaddr *)&addr, sizeof(addr)); \
	if (ret == -1) {                                                      \
		PERR("connect");                                                  \
		return (void *)EXIT_FAILURE;                                        \
	}

#define listen_or_die(sockvar, qlen) \
	ret = listen(sockvar, qlen);       \
	if (ret == -1) {                   \
		PERR("listen");                \
		return (void *)EXIT_FAILURE;     \
	}

/*
 #define nb_or_die(sockvar)                                                      \
 	int nbret = fcntl(sockvar, F_SETFL, fcntl(sockvar, F_GETFL, 0) | O_NONBLOCK); \
 	if (nbret == -1) {                                                            \
 		PERR("nonblock");                                                         \
 		return;                                                                     \
 	}
*/
#define accept_or_die(var, sockvar, flags)   \
	var = accept4(sockvar, NULL, NULL, flags); \
	if (var == -1) {                           \
		PERR("accept");                        \
		return;                                  \
	}

#define read_or_die(...)                 \
	ret = recv(__VA_ARGS__, MSG_NOSIGNAL); \
	if (ret == -1) {                       \
		PERR("read");                      \
		return;                              \
	}

int set_tun_options(const char *ifname, const char *ip, const char *route, int rtprefix, int if_mtu, int route_path_mtu, int defroute, char *nsname);

int enter_netns(const char *nsname);
void exit_netns(void);

int init_gtp_sock(uint32_t saddr, uint32_t dstaddr, uint32_t teid);
int txgtp(uint8_t *data, int datalen);
int rxgtp(uint8_t **data);
void print_packet_header(uint8_t *header);
int enter_netns(const char *nsname);
void exit_netns(void);
void exit_group(int status);
