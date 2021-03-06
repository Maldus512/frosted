#include "frosted.h"
#include "socket_in.h"
#include <string.h>
#include <sys/types.h>
#include <net/if.h>
#include <net/route.h>
#include <sys/ioctl.h>
#include <pico_device.h>

static struct module mod_socket_in;
static frosted_mutex_t *picotcp_lock = NULL;

struct frosted_inet_socket {
    struct fnode *node;
    struct pico_socket *sock;
    uint16_t pid;
    int fd;
    uint16_t events;
    uint16_t revents;
    int bytes;
};

#define SOCK_BLOCKING(s) (((s->node->flags & O_NONBLOCK) == 0))


void pico_lock(void)
{
    if (picotcp_lock)
        frosted_mutex_lock(picotcp_lock);
}

void pico_unlock(void)
{
    if (picotcp_lock)
        frosted_mutex_unlock(picotcp_lock);
}

static int sock_check_fd(int fd, struct fnode **fno)
{
    *fno = task_filedesc_get(fd);

    if (!fno)
        return -1;

    if (fd < 0)
        return -1;
    if ((*fno)->owner != &mod_socket_in)
        return -1;

    return 0;
}

static int sock_poll(struct fnode *f, uint16_t events, uint16_t *revents)
{
    struct frosted_inet_socket *s;
    s = (struct frosted_inet_socket *)f->priv;
    *revents = 0;
    *revents |= s->revents & (POLLIN | POLLOUT);


    if (s->revents & PICO_SOCK_EV_CLOSE)
        *revents |= POLLHUP;

    if (s->revents & PICO_SOCK_EV_FIN)
        *revents |= POLLERR;

    if (s->revents & PICO_SOCK_EV_CONN)
        *revents |= POLLIN;

    if ((*revents) & (POLLHUP | POLLERR) != 0) {
        return 1;
    }
    if ((events & *revents) != 0)
        return 1;

    s->events |= events;
    s->pid = scheduler_get_cur_pid();
    return 0;
}

static struct frosted_inet_socket *fd_inet(int fd)
{
    struct fnode *fno;
    struct frosted_inet_socket *s;
    if (sock_check_fd(fd, &fno) != 0)
        return NULL;

    s = (struct frosted_inet_socket *)fno->priv;
    return s;
}

static struct frosted_inet_socket *pico_inet(struct pico_socket *s)
{
    if (!s || !s->priv)
        return NULL;
    return (struct frosted_inet_socket *)(s->priv);
}

static void pico_socket_event(uint16_t ev, struct pico_socket *sock)
{
    struct frosted_inet_socket *s;
    s = pico_inet(sock);
    if (!s) {
        return;
    }
    s->revents |= ev;
    if ((s->revents & s->events) != 0) {
        task_resume(s->pid);
        s->events = 0;
    }
}

static int sock_close(struct fnode *fno)
{
    struct frosted_inet_socket *s;
    if (!fno)
        return -1;
    s = (struct frosted_inet_socket *)fno->priv;
    if (!s)
        return -1;
    pico_lock();
    pico_socket_close(s->sock);
    pico_unlock();
    //kprintf("## Closed INET socket!\n");
    kfree((struct fnode *)s->node);
    kfree(s);
    return 0;
}

static struct frosted_inet_socket *inet_socket_new(uint32_t flags)
{
    struct frosted_inet_socket *s;
    s = kcalloc(sizeof(struct frosted_inet_socket), 1);
    if (!s)
        return NULL;
    s->node = kcalloc(sizeof(struct fnode), 1);
    if (!s->node) {
        kfree(s);
        return NULL;
    }
    s->node->flags = FL_RDWR | flags;
    return s;
}

static int sock_socket(int domain, int type_flags, int protocol)
{
    int fd = -1;
    struct frosted_inet_socket *s;
    int type = type_flags & 0xFFFF;
    uint32_t fnode_flags = ((uint32_t)type_flags) & 0xFFFF0000u;

    s = inet_socket_new(fnode_flags);
    if (!s)
        return -ENOMEM;
    if (domain != PICO_PROTO_IPV4)
        domain = PICO_PROTO_IPV4;

    if (type == 1)
        type = PICO_PROTO_TCP;

    if (type == 2)
        type = PICO_PROTO_UDP;

    pico_lock();
    s->sock = pico_socket_open(domain, type, pico_socket_event);
    pico_unlock();
    if (!s->sock) {
        kfree((struct fnode *)s->node);
        kfree(s);
        return 0 - pico_err;
    }
    s->node->owner = &mod_socket_in;
    s->node->priv = s;
    s->sock->priv = s;
    //kprintf("## Open INET socket!\n");
    s->fd = task_filedesc_add(s->node);
    if (s->fd >= 0)
        task_fd_setmask(s->fd, O_RDWR);
    return s->fd;
}

static int sock_recvfrom(int fd, void *buf, unsigned int len, int flags, struct sockaddr *addr, unsigned int *addrlen)
{
    struct frosted_inet_socket *s;
    int ret;
    uint16_t port;
    struct pico_ip4 paddr;

    s = fd_inet(fd);
    if (!s)
        return -EINVAL;
    while (s->bytes < len) {
        if ((addr) && ((*addrlen) > 0)) {
            pico_lock();
            ret = pico_socket_recvfrom(s->sock, buf + s->bytes, len - s->bytes, &paddr, &port);
            pico_unlock();
        } else {
            pico_lock();
            ret = pico_socket_read(s->sock, buf + s->bytes, len - s->bytes);
            pico_unlock();
        }

        if (ret < 0)
            return 0 - pico_err;
        if ((ret == 0) && SOCK_BLOCKING(s))  {
            s->events = PICO_SOCK_EV_RD;
            s->pid = scheduler_get_cur_pid();
            task_suspend();
            return SYS_CALL_AGAIN;
        }
        s->bytes += ret;
        if (s->bytes > 0)
            break;
    }
    if (addr) {
        ((struct sockaddr_in *)addr)->sin_family = AF_INET;
        ((struct sockaddr_in *)addr)->sin_port = port;
        ((struct sockaddr_in *)addr)->sin_addr.s_addr = paddr.addr;
    }
    ret = s->bytes;
    s->bytes = 0;
    s->events  &= (~PICO_SOCK_EV_RD);
    s->revents &= (~PICO_SOCK_EV_RD);
    if ((ret == 0) && !SOCK_BLOCKING(s)) {
        ret = -EAGAIN;
    }
    return ret;
}

static int sock_sendto(int fd, const void *buf, unsigned int len, int flags, struct sockaddr *addr, unsigned int addrlen)
{
    struct frosted_inet_socket *s;
    uint16_t port;
    struct pico_ip4 paddr;
    int ret;
    s = fd_inet(fd);
    if (!s)
        return -EINVAL;

    while (len > s->bytes) {
        if ((addr) && (addrlen >0))
        {
            paddr.addr = ((struct sockaddr_in *)addr)->sin_addr.s_addr;
            port = ((struct sockaddr_in *)addr)->sin_port;
            pico_lock();
            ret = pico_socket_sendto(s->sock, buf + s->bytes, len - s->bytes, &paddr, port);
            pico_unlock();
        } else {
            pico_lock();
            ret = pico_socket_write(s->sock, buf + s->bytes, len - s->bytes);
            pico_unlock();
        }
        if ((ret == 0) && SOCK_BLOCKING(s)) {
            s->events = PICO_SOCK_EV_WR;
            s->pid = scheduler_get_cur_pid();
            task_suspend();
            return SYS_CALL_AGAIN;
        }

        if (ret < 0)
            return (0 - pico_err);

        s->bytes += ret;
        if ((s->sock->proto->proto_number) == PICO_PROTO_UDP && (s->bytes > 0))
            break;
    }
    ret = s->bytes;
    s->bytes = 0;
    s->events  &= (~PICO_SOCK_EV_WR);
    s->revents &= (~PICO_SOCK_EV_WR);
    if ((ret == 0) && !SOCK_BLOCKING(s)) {
        ret = -EAGAIN;
    }
    return ret;
}

static int sock_bind(int fd, struct sockaddr *addr, unsigned int addrlen)
{
    struct frosted_inet_socket *s;
    union pico_address paddr;
    uint16_t port;
    int ret;
    s = fd_inet(fd);
    if (!s)
        return -EINVAL;
    paddr.ip4.addr = ((struct sockaddr_in *)addr)->sin_addr.s_addr;
    port = ((struct sockaddr_in *)addr)->sin_port;
    pico_lock();
    ret = pico_socket_bind(s->sock, &paddr, &port);
    pico_unlock();
    if (ret == 0) {
        ((struct sockaddr_in *)addr)->sin_port = port;
        return 0;
    }
    return 0 - pico_err;
}

static int sock_accept(int fd, struct sockaddr *addr, unsigned int *addrlen)
{
    struct frosted_inet_socket *l, *s;
    struct pico_socket *cli;
    union pico_address paddr;
    uint16_t port;

    l = fd_inet(fd);
    if (!l)
        return -EINVAL;
    l->events = PICO_SOCK_EV_CONN;

    pico_lock();
    cli = pico_socket_accept(l->sock, &paddr, &port);
    pico_unlock();
    if ((cli == NULL) && (pico_err != PICO_ERR_EAGAIN))
        return 0 - pico_err;

    if (cli) {
        s = inet_socket_new(0);
        if (!s) {
            pico_lock();
            pico_socket_close(cli);
            pico_unlock();
            return -ENOMEM;
        }
        s->sock = cli;
        s->node->owner = &mod_socket_in;
        s->node->priv = s;
        s->sock->priv = s;
        s->fd = task_filedesc_add(s->node);
        if (s->fd >= 0)
            task_fd_setmask(s->fd, O_RDWR);
        return s->fd;
    } else {
        if (SOCK_BLOCKING(l)) {
            l->pid = scheduler_get_cur_pid();
            task_suspend();
            return SYS_CALL_AGAIN;
        } else {
            return -EAGAIN;
        }
    }
}

static int sock_connect(int fd, struct sockaddr *addr, unsigned int addrlen)
{
    struct frosted_inet_socket *s;
    int ret;
    union pico_address paddr;
    uint16_t port;
    s = fd_inet(fd);
    if (!s)
        return -EINVAL;
    s->events = PICO_SOCK_EV_CONN;
    if ((s->revents & PICO_SOCK_EV_CONN) == 0) {
        paddr.ip4.addr = ((struct sockaddr_in *)addr)->sin_addr.s_addr;
        port = ((struct sockaddr_in *)addr)->sin_port;
        pico_lock();
        ret = pico_socket_connect(s->sock, &paddr, port);
        pico_unlock();
        if (SOCK_BLOCKING(s)) {
            s->pid = scheduler_get_cur_pid();
            task_suspend();
            return SYS_CALL_AGAIN;
        } else {
            return -EAGAIN;
        }
    }
    s->events  &= (~PICO_SOCK_EV_CONN);
    s->revents &= ~(PICO_SOCK_EV_CONN | PICO_SOCK_EV_RD);
    return ret;
}

static int sock_listen(int fd, int backlog)
{
    struct frosted_inet_socket *s;
    int ret;
    s = fd_inet(fd);
    if (!s)
        return -EINVAL;
    pico_lock();
    ret = pico_socket_listen(s->sock, backlog);
    pico_unlock();
    s->events |= PICO_SOCK_EV_CONN;
    return ret;
}

static int sock_shutdown(int fd, uint16_t how)
{
    struct frosted_inet_socket *s;
    int ret;
    s = fd_inet(fd);
    if (!s)
        return -EINVAL;
    pico_lock();
    ret =  pico_socket_shutdown(s->sock, how);
    pico_unlock();
    return ret;
}


static int sock_io_setflags(struct pico_device *dev, struct ifreq *ifr)
{
    unsigned int flags = ifr->ifr_flags;
    if ((flags & IFF_UP) == 0)
        pico_device_destroy(dev);
	return 0;
}

static int sock_io_setaddr(struct pico_device *dev, struct ifreq *ifr)
{
    struct pico_ipv4_link *l;
    const struct pico_ip4 NM24 = {.addr = long_be(0xFFFFFF00)};
    struct sockaddr_in *if_addr = ((struct sockaddr_in *) &ifr->ifr_addr);
    struct pico_ip4 dev_addr = {};

    l = pico_ipv4_link_by_dev(dev);
    if (l) {
        pico_ipv4_link_del(dev, l->address);
    }
    dev_addr.addr = if_addr->sin_addr.s_addr;
    return pico_ipv4_link_add(dev, dev_addr, NM24);
}

static int sock_io_setnetmask(struct pico_device *dev, struct ifreq *ifr)
{
    struct pico_ipv4_link *l;
    struct sockaddr_in *if_nmask = ((struct sockaddr_in *) &ifr->ifr_netmask);
    struct pico_ip4 dev_addr = {};
    struct pico_ip4 dev_nm = {};

    l = pico_ipv4_link_by_dev(dev);
    if (!l)
        return -ENOTCONN;
    dev_addr.addr = l->address.addr;
    pico_ipv4_link_del(dev, l->address);
    dev_nm.addr = if_nmask->sin_addr.s_addr;
    return pico_ipv4_link_add(dev, dev_addr, dev_nm);
}

static int sock_io_getflags(struct pico_device *dev, struct ifreq *ifr)
{
    memset(ifr, 0, sizeof(struct ifreq));
    strncpy(ifr->ifr_name, dev->name, IFNAMSIZ);
    ifr->ifr_flags = IFF_UP|IFF_RUNNING|IFF_MULTICAST|IFF_BROADCAST;
	return 0;
}

static int sock_io_getaddr(struct pico_device *dev, struct ifreq *ifr)
{
    struct pico_ipv4_link *l;
    struct sockaddr_in *if_addr = ((struct sockaddr_in *) &ifr->ifr_addr);
    memset(ifr, 0, sizeof(struct ifreq));
    strncpy(ifr->ifr_name, dev->name, IFNAMSIZ);
    l = pico_ipv4_link_by_dev(dev);
    if (!l)
    	return 0;
    ifr->ifr_flags = IFF_UP|IFF_RUNNING|IFF_MULTICAST|IFF_BROADCAST;
    memset(if_addr, 0, sizeof(struct sockaddr_in));
    if_addr->sin_family = AF_INET;
    if_addr->sin_addr.s_addr = l->address.addr;
    return 0;
}

static int sock_io_gethwaddr(struct pico_device *dev, struct ifreq *eth)
{
    if (!dev->eth)
        return -EPROTONOSUPPORT;
    /* TODO
    memset(eth, 0, sizeof(struct ifreq));
    strncpy(eth->ifr_name, dev->name, IFNAMSIZ);
    eth->ifr_flags = IFF_UP|IFF_RUNNING|IFF_MULTICAST|IFF_BROADCAST;
    eth->ifr_hwaddr.sa_family = ARPHRD_ETHER;
    memcpy (&eth->ifr_hwaddr.sa_data, dev->eth, 6);
    */
	return 0;

}

static int sock_io_getbcast(struct pico_device *dev, struct ifreq *ifr)
{
    struct pico_ipv4_link *l;
    struct sockaddr_in *if_addr = ((struct sockaddr_in *) &ifr->ifr_broadaddr);

    memset(if_addr, 0, sizeof(struct sockaddr_in));
    if_addr->sin_addr.s_addr = 0xFFFFFFFF;
    l = pico_ipv4_link_by_dev(dev);
    if (!l)
    	return 0;
    if_addr->sin_family = AF_INET;
    if_addr->sin_addr.s_addr = (l->address.addr & l->netmask.addr) | (~l->netmask.addr);
    return 0;
}

static int sock_io_getnmask(struct pico_device *dev, struct ifreq *ifr)
{
    struct pico_ipv4_link *l;
    struct sockaddr_in *if_nmask = ((struct sockaddr_in *) &ifr->ifr_netmask);
    l = pico_ipv4_link_by_dev(dev);
    memset(if_nmask, 0, sizeof(struct sockaddr_in));
    if (!l)
    	return 0;
    if_nmask->sin_family = AF_INET;
    if_nmask->sin_addr.s_addr = l->netmask.addr;
    return 0;
}

static int sock_io_addroute(struct rtentry *rte)
{
  struct pico_ip4 a, g, n;
  struct pico_ipv4_link *link = NULL;
  int flags = 1;
  struct pico_device *dev;

  dev = pico_get_device((char *)rte->rt_dev);
  if (dev)
    link = pico_ipv4_link_by_dev(dev);

  memcpy(&a, &((struct sockaddr_in *)(&rte->rt_dst))->sin_addr.s_addr, sizeof(struct pico_ip4));
  memcpy(&g, &((struct sockaddr_in *)(&rte->rt_gateway))->sin_addr.s_addr, sizeof(struct pico_ip4));
  memcpy(&n, &((struct sockaddr_in *)(&rte->rt_genmask))->sin_addr.s_addr, sizeof(struct pico_ip4));
  a.addr &= n.addr;

  if (n.addr == 0)
      flags +=2;

  if (rte->rt_metric <= 0)
      rte->rt_metric = 1;

  if (pico_ipv4_route_add(a, n, g, rte->rt_metric, link) < 0)
    return 0 - pico_err;
  return 0;
}

static int sock_io_delroute(struct rtentry *rte)
{
  struct pico_ip4 a, g, n;
  int flags = 1;


  memcpy(&a, &((struct sockaddr_in *)(&rte->rt_dst))->sin_addr.s_addr, sizeof(struct pico_ip4));
  memcpy(&n, &((struct sockaddr_in *)(&rte->rt_genmask))->sin_addr.s_addr, sizeof(struct pico_ip4));
  a.addr &= n.addr;

  if (n.addr == 0)
      flags +=2;

  if (rte->rt_metric <= 0)
      rte->rt_metric = 1;

  if (pico_ipv4_route_del(a, n, rte->rt_metric) < 0)
    return 0 - pico_err;
  return 0;
}


static int sock_io_ethtool(struct pico_device *dev, struct ifreq *ifr)
{
	return 0;
}

static int sock_ioctl(struct fnode *fno, const uint32_t cmd, void *arg)
{

    struct frosted_inet_socket *s;
    struct ifreq *ifr;
    struct pico_device *dev;
    if (!fno || !arg)
        return -EINVAL;


    /* Check for route commands */
    if (cmd == SIOCADDRT)
    {
        struct rtentry *rte = (struct rtentry *)arg;
        return sock_io_addroute(rte);
    }
    if (cmd == SIOCDELRT)
    {
        struct rtentry *rte = (struct rtentry *)arg;
        return sock_io_delroute(rte);
    }

    /* Check for interface-related ioctl */
    ifr = (struct ifreq *)arg;
    dev = pico_get_device(ifr->ifr_name);
    if (!dev)
        return -ENOENT;

    switch(cmd) {
        case SIOCSIFFLAGS:
            return sock_io_setflags(dev, ifr);
        case SIOCSIFADDR:
            return sock_io_setaddr(dev, ifr);
        case SIOCSIFNETMASK:
            return sock_io_setnetmask(dev, ifr);
        case SIOCGIFFLAGS:
            return sock_io_getflags(dev, ifr);
        case SIOCGIFADDR:
            return sock_io_getaddr(dev, ifr);
        case SIOCGIFHWADDR:
            return sock_io_gethwaddr(dev, ifr);
        case SIOCGIFBRDADDR:
            return sock_io_getbcast(dev, ifr);
        case SIOCGIFNETMASK:
            return sock_io_getnmask(dev, ifr);
        case SIOCETHTOOL:
            return sock_io_ethtool(dev, ifr);
        default:
            return -ENOSYS;
    }
}


/* /sys/net hooks */
#define MAX_DEVNET_BUF 64
static int sysfs_net_dev_read(struct sysfs_fnode *sfs, void *buf, int len)
{
    char *res = (char *)buf;
    struct fnode *fno = sfs->fnode;
    static int off;
    static char *txt;
    int i;
    struct pico_device *dev;
    struct pico_tree_node *index;
    const char iface_banner[] = "Interface | \r\n";
    sysfs_lock();
    if (fno->off == 0) {
        txt = kcalloc(MAX_DEVNET_BUF, 1);
        off = 0;
        if (!txt) {
            len = -1;
            goto out;
        }
        strcpy(txt, iface_banner);
        off += strlen(iface_banner);
        pico_tree_foreach(index, &Device_tree){
            dev = index->keyValue;
            strcat(txt, dev->name);
            off += strlen(dev->name);
            txt[off++] = '\r';
            txt[off++] = '\n';
        }
    }
    if (off == fno->off) {
        kfree(txt);
        len = -1;
        goto out;
    }
    if (len > (off - fno->off)) {
       len = off - fno->off;
    }
    memcpy(res, txt + fno->off, len);
    fno->off += len;
out:
    sysfs_unlock();
    return len;
}

#define MAX_SYSFS_BUFFER 512
int sysfs_net_route_list(struct sysfs_fnode *sfs, void *buf, int len)
{
    char *res = (char *)buf;
    struct fnode *fno = sfs->fnode;
    static char *mem_txt;
    struct pico_ipv4_route *r;
    struct pico_tree_node *index;
    char dest[16];
    char mask[16];
    char gw[16];
    char metric[5];


    static int off;
    int i;
    if (fno->off == 0) {
        const char route_banner[] = "Kernel IP routing table\r\nDestination     Gateway         Genmask         Flags   Metric  Iface \r\n";
        sysfs_lock();
        mem_txt = kalloc(MAX_SYSFS_BUFFER);
        if (!mem_txt)
            return -1;
        off = 0;
        strcpy(mem_txt + off, route_banner);
        off += strlen(route_banner);
        pico_tree_foreach(index, &Routes){

            r = index->keyValue;

            /* Destination */
            pico_ipv4_to_string(dest, r->dest.addr);
            strcpy(mem_txt + off, dest);
            off+=strlen(dest);
            mem_txt[off++] = '\t';
            if (strlen(dest) < 8) 
                mem_txt[off++] = '\t';
            
            /* Gateway */
            pico_ipv4_to_string(gw, r->gateway.addr);
            strcpy(mem_txt + off, gw);
            off+=strlen(gw);
            mem_txt[off++] = '\t';
            if (strlen(gw) < 8) 
                mem_txt[off++] = '\t';
            
            /* Genmask */
            pico_ipv4_to_string(mask, r->netmask.addr);
            strcpy(mem_txt + off, mask);
            off+=strlen(mask);
            mem_txt[off++] = '\t';
            if (strlen(mask) < 8) 
                mem_txt[off++] = '\t';

            /* Flags */
            mem_txt[off++] = 'U';
            if (r->netmask.addr == 0)
                mem_txt[off++] = 'G';
            mem_txt[off++] = '\t';

            /* Metric */
            ul_to_str(r->metric, metric);
            strcpy(mem_txt + off, metric);
            off += strlen(metric);
            mem_txt[off++] = '\t';


            /* Iface */
            strcpy(mem_txt + off, r->link->dev->name);
            off+=strlen(r->link->dev->name);

            /* EOL */
            mem_txt[off++] = '\r';
            mem_txt[off++] = '\n';
        }
    }
    if (off == fno->off) {
        kfree(mem_txt);
        sysfs_unlock();
        return -1;
    }
    if (len > (off - fno->off)) {
       len = off - fno->off;
    }
    memcpy(res, mem_txt + fno->off, len);
    fno->off += len;
    sysfs_unlock();
    return len;
}

static int sock_getsockopt(int sd, int level, int optname, void *optval, unsigned int *optlen)
{
    struct frosted_inet_socket *s;
    int ret;
    if (*optlen < sizeof(int))
        return -EFAULT;
    s = fd_inet(sd);
    if (!s)
        return -EINVAL;
    ret = pico_socket_getoption(s->sock, optname, optval);
    if (ret < 0) 
        return 0 - pico_err;
    *optlen = sizeof(int);
    return ret;
}

static int sock_setsockopt(int sd, int level, int optname, void *optval, unsigned int optlen)
{
    struct frosted_inet_socket *s;
    int ret;
    if (optlen < sizeof(int))
        return -EFAULT;

    s = fd_inet(sd);
    if (!s)
        return -EINVAL;
    ret = pico_socket_setoption(s->sock, optname, optval);
    if (ret < 0) 
        return 0 - pico_err;
    return ret;
}

static int sock_getsockname(int sd, struct sockaddr *_addr, unsigned int *addrlen)
{
    struct pico_ip4 ip4a;
    struct frosted_inet_socket *s;
    struct sockaddr_in *addr = (struct sockaddr_in *)_addr;
    int r;
    uint16_t port, proto;
    s = fd_inet(sd);
    if (!s)
        return -EINVAL;

    if (*addrlen < sizeof(struct sockaddr_in))
        return -ENOBUFS;
    r = pico_socket_getname(s->sock, &ip4a, &port, &proto);
    if (r < 0) 
        return 0 - pico_err;

    if (proto != PICO_PROTO_IPV4)
        return -ENOENT;

    memset(addr, 0, *addrlen);
    *addrlen = sizeof(struct sockaddr_in);
    addr->sin_family = AF_INET;
    addr->sin_port = port;
    addr->sin_addr.s_addr = ip4a.addr;
    return 0;
}

static int sock_getpeername(int sd, struct sockaddr *_addr, unsigned int *addrlen)
{
    struct pico_ip4 ip4a;
    struct frosted_inet_socket *s;
    struct sockaddr_in *addr = (struct sockaddr_in *)addr;
    int r;
    uint16_t port, proto;
    s = fd_inet(sd);
    if (!s)
        return -EINVAL;

    if (*addrlen < sizeof(struct sockaddr_in))
        return -ENOBUFS;
    r = pico_socket_getpeername(s->sock, &ip4a, &port, &proto);
    if (r < 0) 
        return 0 - pico_err;

    if (proto != PICO_PROTO_IPV4)
        return -ENOTCONN;

    memset(addr, 0, *addrlen);
    *addrlen = sizeof(struct sockaddr_in);
    addr->sin_family = AF_INET;
    addr->sin_port = port;
    addr->sin_addr.s_addr = ip4a.addr;
    return 0;
}


static int sysfs_no_op(struct sysfs_fnode *sfs, void *buf, int len)
{
    return -1;
}


void socket_in_init(void)
{
    mod_socket_in.family = FAMILY_INET;
    strcpy(mod_socket_in.name,"picotcp");

    mod_socket_in.ops.poll = sock_poll;
    mod_socket_in.ops.close = sock_close;

    picotcp_lock = frosted_mutex_init();

    mod_socket_in.ops.socket     = sock_socket;
    mod_socket_in.ops.connect    = sock_connect;
    mod_socket_in.ops.accept     = sock_accept;
    mod_socket_in.ops.bind       = sock_bind;
    mod_socket_in.ops.listen     = sock_listen;
    mod_socket_in.ops.recvfrom   = sock_recvfrom;
    mod_socket_in.ops.sendto     = sock_sendto;
    mod_socket_in.ops.shutdown   = sock_shutdown;
    mod_socket_in.ops.ioctl      = sock_ioctl;
    mod_socket_in.ops.getsockopt   = sock_getsockopt;
    mod_socket_in.ops.setsockopt   = sock_setsockopt;
    mod_socket_in.ops.getsockname   = sock_getsockname;
    mod_socket_in.ops.getpeername   = sock_getpeername;

    register_module(&mod_socket_in);
    register_addr_family(&mod_socket_in, FAMILY_INET);

    /* Register /sys/net/dev */
    sysfs_register("dev", "/sys/net", sysfs_net_dev_read, NULL);

    /* Register /sys/net/route */
    sysfs_register("route", "/sys/net", sysfs_net_route_list, NULL);

}
