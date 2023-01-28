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

// Called by the kernel with a dump of the successful scan's data. Called for each SSID.
int WiFiScan::callback_dump(struct nl_msg *msg, void *arg)
{
    struct genlmsghdr *gnlh = (struct genlmsghdr*)nlmsg_data(nlmsg_hdr(msg));
    char mac_addr[20];
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct nlattr *bss[NL80211_BSS_MAX + 1];
    static struct nla_policy bss_policy[NL80211_BSS_MAX + 1];
    bss_policy[NL80211_BSS_TSF].type = NLA_U64;
    bss_policy[NL80211_BSS_FREQUENCY].type = NLA_U32;
    bss_policy[NL80211_BSS_BSSID] = {};
    bss_policy[NL80211_BSS_BEACON_INTERVAL].type = NLA_U16;
    bss_policy[NL80211_BSS_CAPABILITY].type = NLA_U16;
    bss_policy[NL80211_BSS_INFORMATION_ELEMENTS] = {};
    bss_policy[NL80211_BSS_SIGNAL_MBM].type = NLA_U32;
    bss_policy[NL80211_BSS_SIGNAL_UNSPEC].type = NLA_U8;
    bss_policy[NL80211_BSS_STATUS].type = NLA_U32;
    bss_policy[NL80211_BSS_SEEN_MS_AGO].type = NLA_U32;
    bss_policy[NL80211_BSS_BEACON_IES] = {};

    // Parse and error check.
    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);
    if (!tb[NL80211_ATTR_BSS])
    {
        printf("bss info missing!\n");
        return NL_SKIP;
    }
    if (nla_parse_nested(bss, NL80211_BSS_MAX, tb[NL80211_ATTR_BSS], bss_policy))
    {
        printf("failed to parse nested attributes!\n");
        return NL_SKIP;
    }
    if (!bss[NL80211_BSS_BSSID])
        return NL_SKIP;
    if (!bss[NL80211_BSS_INFORMATION_ELEMENTS])
        return NL_SKIP;

    // Start printing.
    mac_addr_n2a(mac_addr, (unsigned char*)nla_data(bss[NL80211_BSS_BSSID]));
    printf("%s, ", mac_addr);
    printf("%d MHz, ", nla_get_u32(bss[NL80211_BSS_FREQUENCY]));
    print_ssid((unsigned char*)nla_data(bss[NL80211_BSS_INFORMATION_ELEMENTS]), nla_len(bss[NL80211_BSS_INFORMATION_ELEMENTS]));
    printf("\n");

    return NL_SKIP;
}

int WiFiScan::trigger_scan(struct nl_sock *socket, int if_index, int driver_id)
{
    // Starts the scan and waits for it to finish. Does not return until the scan is done or has been aborted.
    struct trigger_results results;
    results.done = 0;
    results.aborted = 0;
    struct nl_msg *msg;
    struct nl_cb *cb;
    struct nl_msg *ssids_to_scan;
    int err;
    int ret;
    int mcid = nl_get_multicast_id(socket, "nl80211", "scan");
    nl_socket_add_membership(socket, mcid);  // Without this, callback_trigger() won't be called.

    // Allocate the messages and callback handler.
    msg = nlmsg_alloc();
    if (!msg)
    {
        Logger::printLog(LOG_ERROR, (char*)"Failed to allocate netlink message for msg.");
        return -ENOMEM;
    }
    ssids_to_scan = nlmsg_alloc();
    if (!ssids_to_scan)
    {
        Logger::printLog(LOG_ERROR, (char*)"Failed to allocate netlink message for ssids_to_scan.");
        nlmsg_free(msg);
        return -ENOMEM;
    }
    cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!cb)
    {
        Logger::printLog(LOG_ERROR, (char*)"Failed to allocate netlink callbacks.");
        nlmsg_free(msg);
        nlmsg_free(ssids_to_scan);
        return -ENOMEM;
    }

    // Setup the messages and callback handler.
    genlmsg_put(msg, 0, 0, driver_id, 0, 0, NL80211_CMD_TRIGGER_SCAN, 0);  // Setup which command to run.
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_index);  // Add message attribute, which interface to use.
    nla_put(ssids_to_scan, 1, 0, "");  // Scan all SSIDs.
    nla_put_nested(msg, NL80211_ATTR_SCAN_SSIDS, ssids_to_scan);  // Add message attribute, which SSIDs to scan for.
    nlmsg_free(ssids_to_scan);  // Copied to `msg` above, no longer need this.
    nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, callback_trigger, &results);  // Add the callback.
    nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &err);
    nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
    nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err);
    nl_cb_set(cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, no_seq_check, NULL);  // No sequence checking for multicast messages.

    // Send NL80211_CMD_TRIGGER_SCAN to start the scan. The kernel may reply with NL80211_CMD_NEW_SCAN_RESULTS on
    // success or NL80211_CMD_SCAN_ABORTED if another scan was started by another process.
    err = 1;
    ret = nl_send_auto(socket, msg);  // Send the message.
    printf("NL80211_CMD_TRIGGER_SCAN sent %d bytes to the kernel.\n", ret);
    printf("Waiting for scan to complete...\n");
    while (err > 0)
        ret = nl_recvmsgs(socket, cb);  // First wait for ack_handler(). This helps with basic errors.

    if (err < 0)
    {
        printf("WARNING: err has a value of %d.\n", err);
    }
    if (ret < 0)
    {
        printf("ERROR: nl_recvmsgs() returned %d (%s).\n", ret, nl_geterror(-ret));
        return ret;
    }
    while (!results.done)
        nl_recvmsgs(socket, cb);  // Now wait until the scan is done or aborted.
    if (results.aborted)
    {
        printf("ERROR: Kernel aborted scan.\n");
        return 1;
    }
    printf("Scan is done.\n");

    // Cleanup.
    nlmsg_free(msg);
    nl_cb_put(cb);
    nl_socket_drop_membership(socket, mcid);  // No longer need this.
    return 0;
}
