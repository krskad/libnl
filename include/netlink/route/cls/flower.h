#ifndef NETLINK_FLOWER_H_
#define NETLINK_FLOWER_H_

#include <netlink/netlink.h>
#include <netlink/cache.h>
#include <netlink/route/classifier.h>
#include <netlink/route/action.h>

#ifdef __cplusplus
extern "C" {
#endif

extern int rtnl_flower_set_dst_mac(struct rtnl_cls *, char*, char*);

extern int rtnl_flower_set_src_mac(struct rtnl_cls *, char*, char*);

extern int rtnl_flower_set_eth_type(struct rtnl_cls *, uint16_t);

extern int rtnl_flower_set_ip_proto(struct rtnl_cls *, uint8_t);

#ifdef __cplusplus
}
#endif

#endif
