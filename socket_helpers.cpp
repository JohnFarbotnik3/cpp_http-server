#include <netinet/in.h>
#include <sys/socket.h>

// ============================================================
// send and receive functions.
// ------------------------------------------------------------

/*
returns number of bytes sent.

status == 1: message was send successfully.
status == 0: connection closed.
status <  0: an error occurred.
*/
int send_all(int fd, void* buf, int n, int* status, int flags=0) {
	int x=0;
	while(x < n) {
		int len = send(fd, (char*)buf+x, n-x, flags);
		if(len <= 0) {
			*status = len;
			break;
		} else {
			x += len;
		}
	}
	*status = 1;
	return x;
}

/*
returns number of bytes received.

status == 1: message was send successfully.
status == 0: connection closed.
status <  0: an error occurred.
*/
int recv_all(int fd, void* buf, int n, int* status, int flags=0) {
	int x=0;
	while(x < n) {
		int len = recv(fd, (char*)buf+x, n-x, flags);
		if(len <= 0) {
			*status = len;
			break;
		} else {
			x += len;
		}
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






