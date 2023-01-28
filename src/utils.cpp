#include "include/utils.h"
#include "include/logger.h"

#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <linux/nl80211.h>

int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg) {
    // Callback for errors.+
    Logger::printLog(LOG_WARNING, (char*)"error_handler() called.");
    int *ret = (int*)arg;
    *ret = err->error;
    return NL_STOP;
}


int finish_handler(struct nl_msg *msg, void *arg) {
    // Callback for NL_CB_FINISH.
    Logger::printLog(LOG_WARNING, (char*)"finish_handler() called.");
    int *ret = (int*)arg;
    *ret = 0;
    return NL_SKIP;
}


int ack_handler(struct nl_msg *msg, void *arg) {
    // Callback for NL_CB_ACK.
    Logger::printLog(LOG_WARNING, (char*)"ack_handler() called.");
    int *ret = (int*)arg;
    *ret = 0;
    return NL_STOP;
}


int no_seq_check(struct nl_msg *msg, void *arg) {
    Logger::printLog(LOG_WARNING, (char*)"no_seq_check() called.");
    // Callback for NL_CB_SEQ_CHECK.
    return NL_OK;
}

// Called by the kernel when the scan is done or has been aborted.
int callback_trigger(struct nl_msg *msg, void *arg)
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

// Called by the kernel with a dump of the successful scan's data. Called for each SSID.
int callback_dump(struct nl_msg *msg, void *arg)
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

void mac_addr_n2a(char *mac_addr, unsigned char *arg)
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

void print_ssid(unsigned char *ie, int ielen)
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
