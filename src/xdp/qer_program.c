#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "xdp/program_array.h"

SEC("upf_qer_program")
int upf_qer_program_func(struct xdp_md *ctx)
{
    bpf_printk("upf_qer_program start\n");

    bpf_debug("tail call to UPF_PROG_TYPE_FAR key\n");
    bpf_tail_call(ctx, &upf_program_array, UPF_PROG_TYPE_FAR);
    bpf_debug("tail call to UPF_PROG_TYPE_FAR key failed\n");
    return XDP_ABORTED;
}

char _license[] SEC("license") = "GPL";