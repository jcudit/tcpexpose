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

struct event_data_t {
    u64 ts_us;
    u64 pid;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u64 ip;
    u64 ports;
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
BPF_PERF_OUTPUT(events);

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
    u16 family = 0;
    u16 dport = sk->__sk_common.skc_dport;
    u16 lport = sk->__sk_common.skc_num;

    struct sock *skp = NULL;
    bpf_probe_read(&skp, sizeof(skp), &sk);
    bpf_probe_read(&family, sizeof(family), &skp->__sk_common.skc_family);

    struct tcp_sock *tp = (struct tcp_sock *)sk;

    struct event_data_t event = {
        .pid = infop->pid, .ip = family,

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
    event.ts_us = now / 1000;
    bpf_probe_read(&event.saddr, sizeof(event.saddr),
        &skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
    bpf_probe_read(&event.daddr, sizeof(event.daddr),
        &skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);

    event.ports = ntohs(dport) + ((0ULL + lport) << 32);
    event.delta_us = (now - ts) / 1000;
    __builtin_memcpy(&event.task, infop->task, sizeof(event.task));
    events.perf_submit(ctx, &event, sizeof(event));

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
    u16 family = 0;
    u16 dport = sk->__sk_common.skc_dport;
    u16 lport = sk->__sk_common.skc_num;

    struct sock *skp = NULL;
    bpf_probe_read(&skp, sizeof(skp), &sk);
    bpf_probe_read(&family, sizeof(family), &skp->__sk_common.skc_family);


    struct tcp_sock *tp = (struct tcp_sock *)sk;

    struct event_data_t event = {
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
    event.ts_us = now / 1000;
    bpf_probe_read(&event.saddr, sizeof(event.saddr),
        &skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
    bpf_probe_read(&event.daddr, sizeof(event.daddr),
        &skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
    event.ports = ntohs(dport) + ((0ULL + lport) << 32);
    event.delta_us = (now - ts) / 1000;
    __builtin_memcpy(&event.task, infop->task, sizeof(event.task));
    events.perf_submit(ctx, &event, sizeof(event));

    return 0;
};
