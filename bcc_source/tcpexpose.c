#include <uapi/linux/ptrace.h>
#define KBUILD_MODNAME "foo"
#include <linux/tcp.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct info_t {
    u64 ts;
    u64 pid;
    char task[TASK_COMM_LEN];
};
BPF_HASH(start, struct sock *, struct info_t);

// separate data structs for ipv4 and ipv6
struct ipv4_data_t {
    u64 ts_us;
    u64 pid;
    u64 saddr;
    u64 daddr;
    u64 ip;
    u64 dport;
    u64 delta_us;
    char task[TASK_COMM_LEN];

    // Throughput
    u64 rx_b;       /* How many inbound bytes were acked */
    u64 tx_b;       /* How many outbound bytes were acked */
    u64 segs_out;   /* How many outbound segments were acked */
    u64 segs_in;    /* How many inbound segments were acked */
	u64	rcv_tstamp;	/* timestamp of last received ACK (for keepalives) */
    u64	lsndtime;	/* timestamp of last sent data packet (for restart window) */

    // Windowing
	u64	snd_wl1;	/* Sequence for window update		*/
	u64	snd_wnd;	/* The window we expect to receive	*/
	u64	max_window;	/* Maximal window ever seen from peer	*/
	u64	mss_cache;	/* Cached effective mss, not including SACKS */
	u64	window_clamp;	/* Maximal window to advertise		*/
	u64	rcv_ssthresh;	/* Current window clamp			*/
	u64	packets_out;	/* Packets which are "in flight"	*/
	u64	retrans_out;	/* Retransmitted packets out		*/
	u64	max_packets_out;  /* max packets_out in last window */
	u64	max_packets_seq;  /* right edge of max_packets_out flight */

    // RTT
	u64	srtt_us;	/* smoothed round trip time << 3 in usecs */
	u64	mdev_us;	/* medium deviation			*/
	u64	mdev_max_us;	/* maximal mdev for the last rtt period	*/
};
BPF_PERF_OUTPUT(ipv4_events);

struct ipv6_data_t {
    u64 ts_us;
    u64 pid;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u64 ip;
    u64 dport;
    u64 delta_us;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ipv6_events);

int trace_connect(struct pt_regs *ctx, struct sock *sk)
{
    u32 pid = bpf_get_current_pid_tgid();
    struct info_t info = {.pid = pid};
    info.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&info.task, sizeof(info.task));
    start.update(&sk, &info);
    return 0;
};

int trace_tcp_rcv_established(struct pt_regs *ctx, struct sock *sk)
{
    // check start and calculate delta
    struct info_t *infop = start.lookup(&sk);
    if (infop == 0) {
        return 0;   // missed entry or filtered
    }
    u64 ts = infop->ts;
    u64 now = bpf_ktime_get_ns();

    // pull in details
    u16 family = 0, dport = 0;
    struct sock *skp = NULL;
    bpf_probe_read(&skp, sizeof(skp), &sk);
    bpf_probe_read(&family, sizeof(family), &skp->__sk_common.skc_family);
    bpf_probe_read(&dport, sizeof(dport), &skp->__sk_common.skc_dport);

    struct tcp_sock *tp = (struct tcp_sock *)sk;

    // emit to appropriate data path
    if (family == AF_INET) {
        struct ipv4_data_t data4 = {
            .pid = infop->pid, .ip = 4,

            // Throughput
            .rx_b = tp->bytes_received,
            .tx_b = tp->bytes_acked,
            .segs_out = tp->segs_out,
            .segs_in = tp->segs_in,
            .rcv_tstamp = tp->rcv_tstamp,
            .lsndtime = tp->lsndtime,

            // Windowing
            .snd_wl1 = tp->snd_wl1,
            .snd_wnd = tp->snd_wnd,
            .max_window = tp->max_window,
            .mss_cache = tp->mss_cache,
            .window_clamp = tp->window_clamp,
            .rcv_ssthresh = tp->rcv_ssthresh,
            .packets_out = tp->packets_out,
            .retrans_out = tp->retrans_out,
            .max_packets_out = tp->max_packets_out,
            .max_packets_seq = tp->max_packets_seq,

            // RTT
            .srtt_us = tp->srtt_us,
            .mdev_us = tp->mdev_us,
            .mdev_max_us = tp->mdev_max_us
        };
        data4.ts_us = now / 1000;
        bpf_probe_read(&data4.saddr, sizeof(u32),
            &skp->__sk_common.skc_rcv_saddr);
        bpf_probe_read(&data4.daddr, sizeof(u32),
            &skp->__sk_common.skc_daddr);
        data4.dport = ntohs(dport);
        data4.delta_us = (now - ts) / 1000;
        __builtin_memcpy(&data4.task, infop->task, sizeof(data4.task));
        ipv4_events.perf_submit(ctx, &data4, sizeof(data4));

    } else /* AF_INET6 */ {
        struct ipv6_data_t data6 = {.pid = infop->pid, .ip = 6};
        data6.ts_us = now / 1000;
        bpf_probe_read(&data6.saddr, sizeof(data6.saddr),
            &skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read(&data6.daddr, sizeof(data6.daddr),
            &skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        data6.dport = ntohs(dport);
        data6.delta_us = (now - ts) / 1000;
        __builtin_memcpy(&data6.task, infop->task, sizeof(data6.task));
        ipv6_events.perf_submit(ctx, &data6, sizeof(data6));
    }
    return 0;
};

int trace_tcp_set_state(struct pt_regs *ctx, struct sock *sk, int newstate)
{

    if (sk->__sk_common.skc_state != TCP_ESTABLISHED) {
        return 0;
    }

    // check start and calculate delta
    struct info_t *infop = start.lookup(&sk);
    if (infop == 0) {
        return 0;   // missed entry or filtered
    }
    u64 ts = infop->ts;
    u64 now = bpf_ktime_get_ns();

    // pull in details
    u16 family = 0, dport = 0;
    struct sock *skp = NULL;
    bpf_probe_read(&skp, sizeof(skp), &sk);
    bpf_probe_read(&family, sizeof(family), &skp->__sk_common.skc_family);
    bpf_probe_read(&dport, sizeof(dport), &skp->__sk_common.skc_dport);

    struct tcp_sock *tp = (struct tcp_sock *)sk;

    // emit to appropriate data path
    if (family == AF_INET) {
        struct ipv4_data_t data4 = {
            .pid = infop->pid, .ip = 3,

            // Throughput
            .rx_b = tp->bytes_received,
            .tx_b = tp->bytes_acked,
            .segs_out = tp->segs_out,
            .segs_in = tp->segs_in,
            .rcv_tstamp = tp->rcv_tstamp,
            .lsndtime = tp->lsndtime,

            // Windowing
            .snd_wl1 = tp->snd_wl1,
            .snd_wnd = tp->snd_wnd,
            .max_window = tp->max_window,
            .mss_cache = tp->mss_cache,
            .window_clamp = tp->window_clamp,
            .rcv_ssthresh = tp->rcv_ssthresh,
            .packets_out = tp->packets_out,
            .retrans_out = tp->retrans_out,
            .max_packets_out = tp->max_packets_out,
            .max_packets_seq = tp->max_packets_seq,

            // RTT
            .srtt_us = tp->srtt_us,
            .mdev_us = tp->mdev_us,
            .mdev_max_us = tp->mdev_max_us
        };
        data4.ts_us = now / 1000;
        bpf_probe_read(&data4.saddr, sizeof(u32),
            &skp->__sk_common.skc_rcv_saddr);
        bpf_probe_read(&data4.daddr, sizeof(u32),
            &skp->__sk_common.skc_daddr);
        data4.dport = ntohs(dport);
        data4.delta_us = (now - ts) / 100;
        __builtin_memcpy(&data4.task, infop->task, sizeof(data4.task));
        ipv4_events.perf_submit(ctx, &data4, sizeof(data4));

    } else /* AF_INET6 */ {
        struct ipv6_data_t data6 = {.pid = infop->pid, .ip = 6};
        data6.ts_us = now / 1000;
        bpf_probe_read(&data6.saddr, sizeof(data6.saddr),
            &skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read(&data6.daddr, sizeof(data6.daddr),
            &skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        data6.dport = ntohs(dport);
        data6.delta_us = (now - ts) / 1000;
        __builtin_memcpy(&data6.task, infop->task, sizeof(data6.task));
        ipv6_events.perf_submit(ctx, &data6, sizeof(data6));
    }

    return 0;
};