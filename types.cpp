#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

using addr_in6 = in6_addr;
using addr_in4 = in_addr;
/*
struct in4_addr {
	uint32_t		s4_addr;// IPv4 address
};
struct in6_addr {
	unsigned char	s6_addr[16];// IPv6 address
};
*/


using sockaddr = sockaddr;
/*
struct sockaddr {
	unsigned short	sa_family;		// address family, AF_xxx
	char			sa_data[14];	// 14 bytes of protocol address
};
*/

using sockaddr_storage = sockaddr_storage;
using sockaddr_in6 = sockaddr_in6;
using sockaddr_in4 = sockaddr_in;
/*
struct sockaddr_in4 {
	u_int16_t		sin4_family;	// Address family, AF_INET
	u_int16_t		sin4_port;		// Port number
	in4_addr		sin4_addr;		// Internet address
	unsigned char	sin4_zero[8];	// Padding to ensure same size as struct sockaddr
};
struct sockaddr_in6 {
	u_int16_t	sin6_family;	// address family, AF_INET6
	u_int16_t	sin6_port;		// port number, Network Byte Order
	u_int32_t	sin6_flowinfo;	// IPv6 flow information
	in6_addr	sin6_addr;		// IPv6 address
	u_int32_t	sin6_scope_id;	// Scope ID
};
*/


using addrinfo = addrinfo;
/*
struct addrinfo {
	int			ai_flags;		// AI_PASSIVE, AI_CANONNAME, etc.
	int			ai_family;		// AF_INET, AF_INET6, AF_UNSPEC
	int			ai_socket_type;	// SOCK_STREAM, SOCK_DGRAM
	int			ai_protocol;	// use 0 for "any"
	size_t		ai_addrlen;		// size of socket address struct (ai_addr) in bytes
	sockaddr*	ai_addr;		// sockaddr_in, sockaddr_in6.
	char*		ai_canonname;	// full canonical hostname
	addrinfo*	ai_next;		// linked list, next node
};
*/
