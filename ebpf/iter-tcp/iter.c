//go:build ignore
// SPDX-License-Identifier: GPL-2.0
/* Copyright 2025 Leon Hwang */

#include "bpf_all.h"

SEC("iter/tcp")
int iter_tcp(struct bpf_iter__tcp *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct sock_common *skc = ctx->sk_common;
	struct tcp_sock *tp;
	struct sock *sk;
	struct sk_buff_head *queue;
	struct sk_buff *skb;
	int qlen, cnt = 0, cnt_pp = 0;

	if (!skc)
		return 0;

	tp = bpf_skc_to_tcp_sock(skc);
	if (!tp)
		return 0;

	sk   = (struct sock *)tp;
	queue = &sk->sk_receive_queue;

	qlen = BPF_CORE_READ(queue, qlen);

	skb = (struct sk_buff *)BPF_CORE_READ(queue, next);
	for (int i = 0; i < 100 && skb != (struct sk_buff *)queue; i++) {
		cnt++;
		cnt_pp += BPF_CORE_READ_BITFIELD_PROBED(skb, pp_recycle);

		skb = (struct sk_buff *)BPF_CORE_READ(skb, next);
	}

        if (cnt == 0)
                return 0;

	BPF_SEQ_PRINTF(seq, "state=%d src=%pI4:%u dst=%pI4:%u\n",
		       skc->skc_state,
		       &skc->skc_rcv_saddr, skc->skc_num,
		       &skc->skc_daddr, bpf_ntohs(skc->skc_dport));

	BPF_SEQ_PRINTF(seq, "  rx_queue: qlen=%d iterated=%d (pp_recycle=%d)\n",
		       qlen, cnt, cnt_pp);

	return 0;
}