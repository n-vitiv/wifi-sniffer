#include "include/logger.h"
#include "include/wifiscan.h"
#include "include/utils.h"
#include <iostream>
#include <string.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <linux/nl80211.h>

WiFiScan::WiFiScan(char* interface)
{
    strcpy(intf_name, interface);
}

void WiFiScan::start_scan()
{
    int if_index = interface_to_index(intf_name);
}

int WiFiScan::interface_to_index(char* interface)
{
    // Use this wireless interface for scanning.
    int if_index = if_nametoindex(interface);
    if (if_index == 0)
    {
        Logger::printLog(LOG_ERROR, (char*)"Error, entered wrong name of interface name.");
        std::cout << "Error, entered wrong name of interface name." << std::endl;
        exit(-2);
    }
    Logger::printLog(LOG_DEBUG, (char*)"Created index for interface %s = %d", interface, if_index);
    return if_index;
}

struct nl_sock* WiFiScan::open_socket()
{
    // Open socket to kernel.
    struct nl_sock *socket = nl_socket_alloc();  // Allocate new netlink socket in memory.
    genl_connect(socket);  // Create file descriptor and bind socket.
    return socket;
}

int WiFiScan::family_handler(struct nl_msg *msg, void *arg)
{
    struct handler_args *grp = (struct handler_args*)arg;
    struct nlattr *tb[CTRL_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = (struct genlmsghdr*)nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *mcgrp;
    int rem_mcgrp;

    nla_parse(tb, CTRL_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

    if (!tb[CTRL_ATTR_MCAST_GROUPS])
        return NL_SKIP;

    nla_for_each_nested(mcgrp, tb[CTRL_ATTR_MCAST_GROUPS], rem_mcgrp)
    {   // This is a loop.
        struct nlattr *tb_mcgrp[CTRL_ATTR_MCAST_GRP_MAX + 1];

        nla_parse(tb_mcgrp, CTRL_ATTR_MCAST_GRP_MAX, (nlattr*)nla_data(mcgrp), nla_len(mcgrp), NULL);

        if (!tb_mcgrp[CTRL_ATTR_MCAST_GRP_NAME] || !tb_mcgrp[CTRL_ATTR_MCAST_GRP_ID])
            continue;
        if (strncmp((const char*)nla_data(tb_mcgrp[CTRL_ATTR_MCAST_GRP_NAME]), grp->group, nla_len(tb_mcgrp[CTRL_ATTR_MCAST_GRP_NAME])))
            continue;

        grp->id = nla_get_u32(tb_mcgrp[CTRL_ATTR_MCAST_GRP_ID]);
        break;
    }

    return NL_SKIP;
}

int WiFiScan::nl_get_multicast_id(struct nl_sock *sock, const char *family, const char *group)
{
    struct nl_msg *msg;
    struct nl_cb *cb;
    int ret, ctrlid;
    struct handler_args grp;
    grp.group = group;
    grp.id = -ENOENT;

    msg = nlmsg_alloc();
    if (!msg) return -ENOMEM;

    cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!cb) {
        ret = -ENOMEM;
        goto out_fail_cb;
    }

    ctrlid = genl_ctrl_resolve(sock, "nlctrl");

    genlmsg_put(msg, 0, 0, ctrlid, 0, 0, CTRL_CMD_GETFAMILY, 0);

    ret = -ENOBUFS;
    NLA_PUT_STRING(msg, CTRL_ATTR_FAMILY_NAME, family);

    ret = nl_send_auto_complete(sock, msg);
    if (ret < 0) goto out;

    ret = 1;

    nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &ret);
    nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &ret);
    nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, family_handler, &grp);

    while (ret > 0) nl_recvmsgs(sock, cb);

    if (ret == 0) ret = grp.id;

    nla_put_failure:
        out:
            nl_cb_put(cb);
        out_fail_cb:
            nlmsg_free(msg);
            return ret;
}

void  WiFiScan::mac_addr_n2a(char *mac_addr, unsigned char *arg)
{
    int i, l;
    l = 0;
    for (i = 0; i < 6; i++)
    {
        if (i == 0)
        {
            sprintf(mac_addr+l, "%02x", arg[i]);
            l += 2;
        }
        else
        {
            sprintf(mac_addr+l, ":%02x", arg[i]);
            l += 3;
        }
    }
}


void  WiFiScan::print_ssid(unsigned char *ie, int ielen)
{
    uint8_t len;
    uint8_t *data;
    int i;

    while (ielen >= 2 && ielen >= ie[1])
    {
        if (ie[0] == 0 && ie[1] >= 0 && ie[1] <= 32)
        {
            len = ie[1];
            data = ie + 2;
            for (i = 0; i < len; i++)
            {
                if (isprint(data[i]) && data[i] != ' ' && data[i] != '\\')
                    printf("%c", data[i]);
                else if (data[i] == ' ' && (i != 0 && i != len -1))
                    printf(" ");
                else
                    printf("\\x%.2x", data[i]);
            }
            break;
        }
        ielen -= ie[1] + 2;
        ie += ie[1] + 2;
    }
}

// Called by the kernel when the scan is done or has been aborted.
int WiFiScan::callback_trigger(struct nl_msg *msg, void *arg)
{
    struct genlmsghdr *gnlh = (struct genlmsghdr*)nlmsg_data(nlmsg_hdr(msg));
    struct trigger_results *results = (struct trigger_results*)arg;

    if (gnlh->cmd == NL80211_CMD_SCAN_ABORTED)
    {
        printf("Got NL80211_CMD_SCAN_ABORTED.\n");
        results->done = 1;
        results->aborted = 1;
    }
    else if (gnlh->cmd == NL80211_CMD_NEW_SCAN_RESULTS)
    {
        printf("Got NL80211_CMD_NEW_SCAN_RESULTS.\n");
        results->done = 1;
        results->aborted = 0;
    }  // else probably an uninteresting multicast message.

    return NL_SKIP;
}
