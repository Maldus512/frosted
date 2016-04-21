#ifndef FROSTED_UN_SOCKETS_H_
#define FROSTED_UN_SOCKETS_H_

#include "frosted.h"
#include "scheduler.h"
#include <string.h>
#include <limits.h>
#include <stdint.h>
#include <sys/socket.h>

#define UNSIZE      1024
#define FRAMES_MAX  32

#define IPC_SOCKET_STATE_UNDEFINED      0x0000u
#define IPC_SOCKET_STATE_BOUND          0x0001u
#define IPC_SOCKET_STATE_CONNECTED      0x0002u
#define IPC_SOCKET_STATE_LISTEN         0x0004u

#define UNIX_SOCK_EV_RD                 0x01u
#define UNIX_SOCK_EV_WR                 0x02u
#define UNIX_SOCK_EV_CONN               0x04u
#define UNIX_SOCK_EV_CLOSE              0x08u
#define UNIX_SOCK_EV_FIN                0x10u
#define UNIX_SOCK_EV_ERR                0x20u

#define IS_LIST(s)                      (s->sock->state & IPC_SOCKET_STATE_LISTEN)
#define IS_CONN(s)                      (s->sock->state & IPC_SOCKET_STATE_CONNECTED)

#define AF_LOCAL    AF_UNIX

struct pending_conn {
    struct pending_conn *next;
    struct usocket *sock;
};

struct frame {
    struct frame *next;

    unsigned char *buffer;
    uint32_t buffer_len;

    unsigned char *start;
    uint32_t len;
    
    struct usocket *sock;

    struct frosted_unix_socket *sender;
};

struct usocket {
    uint32_t frames;
    uint32_t max_frames;
    struct frame *head;
    struct frame *tail;

    uint16_t state;

    struct usocket *connection;
    void *priv;
};

struct frosted_unix_socket {
    struct fnode *node;
    struct usocket *sock;
    uint16_t type;
    char path[PATH_MAX];
    uint16_t pid;
    int fd;

    struct pending_conn *q_head;
    struct pending_conn *q_tail;
    int backlog;
    int pending_conn_count;
    uint16_t events;
    uint16_t revents;
    int bytes;
};

#endif
