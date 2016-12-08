#include <uapi/linux/ptrace.h>
#define KBUILD_MODNAME "foo"
#include <linux/tcp.h>
#include <net/sock.h>
#include <bcc/proto.h>

enum {
    REGISTER,
    UNREGISTER,
    PUBLISH,
};

struct event_data_t {
    u64 event_type;
    u64 ts_us;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u64 ports;

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

int trace_tcp_rcv_established(struct pt_regs *ctx, struct sock *sk)
{
    u64 now = bpf_ktime_get_ns();
    u16 dport = sk->__sk_common.skc_dport;
    u16 lport = sk->__sk_common.skc_num;

    // TODO: Filter on relevant traffic (dport?)
    if ((ntohs(dport) + ((0ULL + lport) << 32)) >> 32 == 22) {
        return 0;
    }

    struct sock *skp = NULL;
    bpf_probe_read(&skp, sizeof(skp), &sk);

    struct tcp_sock *tp = (struct tcp_sock *)sk;

    struct event_data_t event = {
        .event_type = PUBLISH,

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
    events.perf_submit(ctx, &event, sizeof(event));

    return 0;
};

int trace_tcp_set_state(struct pt_regs *ctx, struct sock *sk, int newstate)
{

    if (
        // Transitions out of ESTABLISHED are closing connections
        sk->__sk_common.skc_state != TCP_ESTABLISHED &&
        // Transitions to ESTABLISHED are opening connections
        newstate != TCP_ESTABLISHED
    ) {
        // Pass on event if neither opening or closing
        return 0;
    }

    u64 event_type;
    if (newstate == TCP_ESTABLISHED) {
        event_type = REGISTER;
    } else {
        event_type = UNREGISTER;
    }

    u16 dport = sk->__sk_common.skc_dport;
    u16 lport = sk->__sk_common.skc_num;
    u64 now = bpf_ktime_get_ns();

    // TODO: Filter for relevant traffic (dport?)
    if ((ntohs(dport) + ((0ULL + lport) << 32)) >> 32 == 22) {
        return 0;
    }

    struct sock *skp = NULL;
    bpf_probe_read(&skp, sizeof(skp), &sk);
    struct tcp_sock *tp = (struct tcp_sock *)sk;

    struct event_data_t event = {
        .event_type = event_type,

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
    events.perf_submit(ctx, &event, sizeof(event));

    return 0;
};
