#include "include/utils.h"
#include "include/logger.h"

#include <netlink/genl/ctrl.h>
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
