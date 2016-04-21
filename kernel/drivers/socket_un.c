#include "frosted.h"
#include "scheduler.h"
#include "socket_un.h"
#include <string.h>
#include <sys/types.h>

extern struct fnode *fno_create_socket(char *name);
extern struct fnode *fno_search(const char *path);

static struct module mod_socket_un;
struct fnode FNO_SOCKUN_STUB = {
    .owner = &mod_socket_un
};

static int add_connection(struct frosted_unix_socket *cli, struct frosted_unix_socket *ser)
{
    struct pending_conn *aux;
    if (ser->pending_conn_count >= ser->backlog)
        return -ECONNREFUSED;

    aux = kalloc(sizeof(struct pending_conn));
    aux->sock = cli->sock;
    aux->next = ser->q_head;
    ser->q_head = aux;
    ser->pending_conn_count++;

    return 0;
}

static struct frame *frame_alloc(struct usocket* s)
{
    struct frame *f = kalloc(sizeof(struct frame));
    f->len = 0;
    f->next = NULL;
    f->buffer_len = UNSIZE;
    f->start = f->buffer = kalloc(sizeof(char)*UNSIZE);
    f->sock = s; 
    return f;
}

void red_buf(struct frame *f, int len)
{
    int i, j;
    j = len;
    i = 0;
    while((f->buffer + j != f->start) && j < f->buffer_len){
        f->buffer[i] = f->buffer[j];
        j++;
        i++;
    }
    f->start = f->buffer + i;
}

/*function to read from a socket*/
static int unix_read(char *buf, int len, struct frosted_unix_socket *s, struct frosted_unix_socket *src)
{
    struct frame *f;
    int l;
    f = s->sock->head;
    if (!f)
        return 0;

    if (s->type == SOCK_STREAM){
        if (f->len == 0)
            return 0;
        if (len > f->len)
            len = f->len;
        strncpy(buf, f->buffer, len);
        red_buf(f, len);
        src = s->sock->connection->priv;
        return len;
    }
    else if (s->type == SOCK_DGRAM){
        if (f->len == 0)
            return 0;
        if (len > f->len)
            len = f->len;
        strncpy(buf, f->buffer, len);
        src = f->sender;
        
        s->sock->frames--;
        if (s->sock->head == s->sock->tail)
            s->sock->head = s->sock->tail = NULL;
        else
            s->sock->head = f->next;
        kfree(f->buffer);
        kfree(f);
        return len;
    }
}

static int unix_write(char *buf, int len, struct frosted_unix_socket *src, struct frosted_unix_socket *s)
{
    struct frame *f;
    if (s->type == SOCK_STREAM){
        f = s->sock->head;
        if (!f){
            f = frame_alloc(s->sock);
            f->sender = src;
            s->sock->head = s->sock->tail = f;
            s->sock->frames = 1;
        }
    }
    else if(s->type == SOCK_DGRAM){
        if (s->sock->frames + 1 > s->sock->max_frames)
            return -1;
        f = frame_alloc(s->sock);
        if (s->sock->tail){
            s->sock->tail->next = f;
            s->sock->tail = f;
        }
        else
            s->sock->head = s->sock->tail = f;
        f->sender = src;
        s->sock->frames++; 
    }
    while (f->len + len > f->buffer_len){
        if ((f->buffer = (char*) krealloc(f->buffer, f->buffer_len*2)) == NULL)
            return -1;
        f->buffer_len = f->buffer_len*2;
    }
    strncpy(f->start, buf, len);
    f->start += len;
    f->len += len;
    return len;
}

static int sock_check_fd(int fd, struct fnode **fno)
{
    *fno = task_filedesc_get(fd);
    
    if (!fno)
        return -1;

    if (fd < 0)
            return -1;
    if ((*fno)->owner != &mod_socket_un)
        return -1;

    return 0;
}



static struct frosted_unix_socket *unix_socket_new(void)
{
    struct frosted_unix_socket *s;
    s = kalloc(sizeof(struct frosted_unix_socket));
    if (!s)
        return NULL;
    s->node = kalloc(sizeof(struct fnode));
    if (!s->node){
        kfree(s);
        return NULL;
    }
    s->sock = kalloc(sizeof(struct usocket));
    if (!s->sock){
        kfree(s);
        return NULL;
    }
    s->sock->head = s->sock->tail = NULL;
    s->q_head = s->q_tail = NULL;
    s->sock->connection = NULL;
    s->sock->state = IPC_SOCKET_STATE_UNDEFINED;
    s->pending_conn_count = 0;
    return s;
}

static struct frosted_unix_socket *fd_sock(int fd)
{
    struct fnode *fno;
    struct frosted_unix_socket *s;
    if (sock_check_fd(fd, &fno) != 0)
        return NULL;

    s = (struct frosted_unix_socket *)fno->priv;
    return s;
}

static int sock_poll(int fd, uint16_t events, uint16_t *revents)
{
    *revents = events;
    return 1;
}


static int sock_close(int fd)
{
    struct frosted_unix_socket *s;
    struct fnode *fno;
    struct frame *aux, *tmp;
    
    s = fd_sock(fd);
    if (!s)
        return -1;

    aux = s->sock->head;
    while(aux != s->sock->tail){
        kfree(aux->buffer);
        tmp = aux->next;
        kfree(aux);
        aux = tmp;
    }
    kfree(s->sock);
    kfree(s);
    kprintf("## Closed UNIX socket!\n");
    return 0;
}

int sock_socket(int domain, int type, int protocol)
{
    int fd = -1;
    struct frosted_unix_socket *s;

    s = unix_socket_new();
    if (!s)
        return -ENOMEM;

    if (type == SOCK_STREAM){
        s->sock->frames = 0;
        s->sock->max_frames = 1;
    }
    else if (type == SOCK_DGRAM){
        s->sock->frames = 0;
        s->sock->max_frames = FRAMES_MAX;
    }
    s->type = type;

    if (domain != AF_UNIX && domain != AF_LOCAL)
        //domain = AF_UNIX;
        domain = 1;

    s->node->owner = &mod_socket_un;
    s->node->priv = s;
    s->sock->priv = s;
    kprintf("## Opened UNIX socket!\n");
    s->fd = task_filedesc_add(s->node);
    if (s->fd >= 0)
        task_fd_setmask(s->fd, O_RDWR);
    return s->fd;
}

int sock_recvfrom(int fd, void *buf, unsigned int len, int flags, struct sockaddr *addr, unsigned int *addrlen)
{
    struct frosted_unix_socket *s, *sender;
    s = fd_sock(fd);
    int ret;
    if (!s)
        return -EINVAL;
    if (!buf)
        return -EINVAL;

    ret = unix_read(buf, len, s, sender);

    if (ret == 0){
        s->events = UNIX_SOCK_EV_RD;
        s->pid = scheduler_get_cur_pid();
        task_suspend();
        return SYS_CALL_AGAIN;
    }
    if (addr && addrlen){
        addr = (struct sockaddr_un*) addr;
        ((struct sockaddr_un*)addr)->sun_family = AF_UNIX;
        strcpy(((struct sockaddr_un*)addr)->sun_path, sender->path);
        *addrlen = sizeof(*addr);
    }
    return ret;
}

int sock_sendto(int fd, const void *buf, unsigned int len, int flags, struct sockaddr *addr, unsigned int addrlen)
{
    struct frosted_unix_socket *s, *dest;
    struct fnode *fno;
    int ret;
    s = fd_sock(fd);
    if (!s)
        return -EINVAL;
    if (!buf)
        return -EINVAL;
    if (s->type == SOCK_STREAM){
        if (s->sock->state & IPC_SOCKET_STATE_CONNECTED == 0)
            return -ENOTCONN;
        if (!(addr == NULL && addrlen == 0))
            return -EISCONN;
        dest = s->sock->connection->priv;
    }
    else if (s->type == SOCK_DGRAM){
        if (!addr)
            return -EINVAL;
        
        fno = fno_search(((struct sockaddr_un*)addr)->sun_path);
        if (!fno)
            return -EINVAL;
        dest = fno->priv;
        //TODO
    }
    ret = unix_write(buf, len, s, dest);

    s->events != UNIX_SOCK_EV_WR;
    return ret;
}

int sock_bind(int fd, struct sockaddr_un *addr, unsigned int addrlen)
{
    struct frosted_unix_socket *s;
    int len = strlen(addr->sun_path);
    if (len == 0)
        return -EINVAL;
    s = fd_sock(fd);
    if (!s)
        return -EINVAL;

    kfree(s->node);
    s->node = fno_create_socket(addr->sun_path);
    if (!s->node)
        return -1;
    s->node->owner = &mod_socket_un;
    s->node->flags |= FL_RDWR;
    s->node->priv = s;

    s->sock->state |= IPC_SOCKET_STATE_BOUND;
    return 0;
}

int sock_accept(int fd, struct sockaddr *addr, unsigned int *addrlen)
{
    struct frosted_unix_socket *l, *s;
    struct pending_conn *tmp;
    struct usocket *cli;
    struct sockaddr paddr;

    l = fd_sock(fd);
    if (!l)
        return -EINVAL;

    if (l->type != SOCK_STREAM )
        return -EOPNOTSUPP;

    if (!IS_LIST(l))
        return -EINVAL;
    l->events = UNIX_SOCK_EV_CONN;

    s = unix_socket_new();
    if (!s)
        return -ENOMEM;

    if (l->q_head){
        tmp = l->q_head;
        l->q_head = tmp->next;
        cli = tmp->sock;
        l->pending_conn_count--;
        cli->connection = s->sock;
        s->sock->connection = cli;
        s->fd = task_filedesc_add(s->node);
        if (s->fd >= 0)
            task_fd_setmask(s->fd, O_RDWR);
        return s->fd;
    }
    else {
        l->pid = scheduler_get_cur_pid();
        task_suspend();
        return SYS_CALL_AGAIN;
    }
}

int sock_connect(int fd, struct sockaddr *addr, unsigned int addrlen)
{
    struct frosted_unix_socket *cli, *ser;
    struct fnode *fno;
    int ret;
    
    if (addr->sa_family != AF_UNIX)
        return -EAFNOSUPPORT;

    cli = fd_sock(fd);
    if (!cli || !addr)
        return -EINVAL;
    cli->events = UNIX_SOCK_EV_CONN;
    if ((cli->revents & UNIX_SOCK_EV_CONN) == 0) {
        fno = fno_search(((struct sockaddr_un*)addr)->sun_path);
        if (!fno)
            return -ECONNREFUSED;
         
        ser = fno->priv;
        if (ser->sock->state & IPC_SOCKET_STATE_LISTEN == 0)
            return -ECONNREFUSED;

        ret = add_connection(cli, ser);
        if (ret < 0)
            return ret;

        cli->sock->state |= IPC_SOCKET_STATE_CONNECTED;
        cli->revents |= UNIX_SOCK_EV_CONN;

        cli->pid = scheduler_get_cur_pid();
        task_suspend();
        return SYS_CALL_AGAIN;
    }
    cli->events &= (~UNIX_SOCK_EV_CONN);
    cli->revents &= ~(UNIX_SOCK_EV_CONN | UNIX_SOCK_EV_RD);
    return 0;
}

int sock_listen(int fd, int backlog)
{
    struct frosted_unix_socket *s;
    s = fd_sock(fd);
    if (!s)
        return -EINVAL;
    
    if (s->type != SOCK_STREAM)
        return -EOPNOTSUPP;

    if (IS_LIST(s) || IS_CONN(s))
        return -EINVAL;

    s->sock->state |= IPC_SOCKET_STATE_LISTEN;
    s->backlog = backlog;

    return 0;
}

int sock_shutdown(int fd, uint16_t how)
{
    return -1;
}


void socket_un_init(void)
{
    mod_socket_un.family = FAMILY_UNIX;
    strcpy(mod_socket_un.name,"un");
    mod_socket_un.ops.poll = sock_poll;
    mod_socket_un.ops.close = sock_close;

    mod_socket_un.ops.socket     = sock_socket;
    mod_socket_un.ops.connect    = sock_connect;
    mod_socket_un.ops.accept     = sock_accept;
    mod_socket_un.ops.bind       = sock_bind;
    mod_socket_un.ops.listen     = sock_listen;
    mod_socket_un.ops.recvfrom   = sock_recvfrom;
    mod_socket_un.ops.sendto     = sock_sendto;
    mod_socket_un.ops.shutdown   = sock_shutdown;

    register_module(&mod_socket_un);
    register_addr_family(&mod_socket_un, FAMILY_UNIX);
}



