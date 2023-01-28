#ifndef UTILS_H
#define UTILS_H

struct trigger_results
{
    int done;
    int aborted;
};

struct handler_args
{
    // For family_handler() and nl_get_multicast_id().
    const char *group;
    int id;
};

int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg);

int finish_handler(struct nl_msg *msg, void *arg);

int ack_handler(struct nl_msg *msg, void *arg);

int no_seq_check(struct nl_msg *msg, void *arg);

int callback_trigger(struct nl_msg *msg, void *arg);

#endif
