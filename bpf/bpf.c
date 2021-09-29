#include "include/vmlinux.h"
#define AF_INET 2 // From <sys/socket.h>
#include "include/bpf/bpf_helpers.h"
#include "include/bpf/bpf_core_read.h"

#define TASK_COMM_LEN 16

extern int LINUX_KERNEL_VERSION __kconfig;

struct trace_event_raw_inet_sock_set_state___v56 {
	struct trace_entry ent;
	const void *skaddr;
	int oldstate;
	int newstate;
	__u16 sport;
	__u16 dport;
	__u16 family;
	__u8 protocol;
	__u8 saddr[4];
	__u8 daddr[4];
	__u8 saddr_v6[16];
	__u8 daddr_v6[16];
	char __data[0];
};

struct event_data {
	char comm_on_cpu[TASK_COMM_LEN];
	__u64 sock_addr;
	__u32 pid_on_cpu;
	__u32 sock_inode;
	__u32 sock_uid;
	__u32 sock_gid;
	__s32 old_state;
	__s32 new_state;
	__u16 src_port;
	__u16 dst_port;
	__u8 src_addr[4];
	__u8 dst_addr[4];	
	__u8 sock_state;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

__always_inline bool fill_event_old(struct trace_event_raw_inet_sock_set_state___v56 *ctx, struct event_data *event) {
	if (!(ctx->family == AF_INET && ctx->protocol == IPPROTO_TCP)) {
		return false;
	}

	__builtin_memset(event, 0, sizeof(struct event_data)); // https://github.com/iovisor/bcc/issues/2623
	event->pid_on_cpu = bpf_get_current_pid_tgid() >> 32;	
	bpf_get_current_comm(event->comm_on_cpu, TASK_COMM_LEN);
	__builtin_memcpy(event->src_addr, ctx->saddr, sizeof(event->src_addr));
	__builtin_memcpy(event->dst_addr, ctx->daddr, sizeof(event->dst_addr));	
	event->src_port = ctx->sport;
	event->dst_port = ctx->dport;
	event->old_state = ctx->oldstate;
	event->new_state = ctx->newstate;	
	event->sock_addr = (__u64)(ctx->skaddr);
	struct sock *sk = (struct sock *)(ctx->skaddr);
	event->sock_state = BPF_CORE_READ(sk, sk_socket, state);
	struct inode *inode = BPF_CORE_READ(sk, sk_socket, file, f_inode);
	event->sock_inode = BPF_CORE_READ(inode, i_ino);	
	event->sock_uid = BPF_CORE_READ(inode, i_uid.val);
	event->sock_gid = BPF_CORE_READ(inode, i_gid.val);

	return true;
}

__always_inline bool fill_event_new(struct trace_event_raw_inet_sock_set_state *ctx, struct event_data *event) {
	if (!(ctx->family == AF_INET && ctx->protocol == IPPROTO_TCP)) {
		return false;
	}

	__builtin_memset(event, 0, sizeof(struct event_data)); // https://github.com/iovisor/bcc/issues/2623
	event->pid_on_cpu = bpf_get_current_pid_tgid() >> 32;	
	bpf_get_current_comm(event->comm_on_cpu, TASK_COMM_LEN);
	__builtin_memcpy(event->src_addr, ctx->saddr, sizeof(event->src_addr));
	__builtin_memcpy(event->dst_addr, ctx->daddr, sizeof(event->dst_addr));	
	event->src_port = ctx->sport;
	event->dst_port = ctx->dport;
	event->old_state = ctx->oldstate;
	event->new_state = ctx->newstate;	
	event->sock_addr = (__u64)(ctx->skaddr);
	struct sock *sk = (struct sock *)(ctx->skaddr);
	event->sock_state = BPF_CORE_READ(sk, sk_socket, state);
	struct inode *inode = BPF_CORE_READ(sk, sk_socket, file, f_inode);
	event->sock_inode = BPF_CORE_READ(inode, i_ino);	
	event->sock_uid = BPF_CORE_READ(inode, i_uid.val);
	event->sock_gid = BPF_CORE_READ(inode, i_gid.val);
	
	return true;
}

SEC("tracepoint/sock/inet_sock_set_state")
int tracepoint__sock_inet_sock_set_state(void *ctx) {
	struct event_data event;

	if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(5, 6, 0)) {
		// char fmt[] = "newer kernel";
		// bpf_trace_printk(fmt, sizeof(fmt));
		if (!fill_event_new((struct trace_event_raw_inet_sock_set_state *)ctx, &event)) {
			return 0;
		}
	} else {
		// char fmt[] = "older kernel";
		// bpf_trace_printk(fmt, sizeof(fmt));
		if (!fill_event_old((struct trace_event_raw_inet_sock_set_state___v56 *)ctx, &event)) {
			return 0;
		}
	}	

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(struct event_data));
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";