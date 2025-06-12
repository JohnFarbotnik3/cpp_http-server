#include <netinet/in.h>
#include <sys/socket.h>

// ============================================================
// send and receive functions - tcp.
// ------------------------------------------------------------

/*
returns number of bytes sent.

status == 1: message was sent successfully.
status == 0: connection closed.
status <  0: an error occurred.

if an error occurred, errno will be set.

see "send" manpage for more info.
*/
int send_all(int fd, void* msg, int len, int* status, int flags=0) {
	int x = 0;
	while(x < len) {
		int num_sent = send(fd, (char*)msg+x, len-x, flags);
		if(num_sent <= 0) {
			*status = num_sent;
			return x;
		}
		x += num_sent;
	}
	*status = 1;
	return x;
}

/*
returns number of bytes received.

status == 1: message was sent successfully.
status == 0: connection closed.
status <  0: an error occurred.

if an error occurred, errno will be set.

see "recv" manpage for more info.
*/
int recv_all(int fd, void* msg, int len, int* status, int flags=0) {
	int x = 0;
	while(x < len) {
		int num_recv = recv(fd, (char*)msg+x, len-x, flags);
		if(num_recv <= 0) {
			*status = num_recv;
			return x;
		}
		x += num_recv;
	}
	*status = 1;
	return x;
}

void send_int(int fd, int* status, int value) {
	int net_value = htonl(value);
	send_all(fd, &net_value, sizeof(net_value), status);
}

int recv_int(int fd, int* status) {
	int net_value = 0;
	recv_all(fd, &net_value, sizeof(net_value), status);
	return ntohl(net_value);
}







