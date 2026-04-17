#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

/* * Blacklist Map: 
 * Key: IPv4 address (__u32)
 * Value: Drop counter (__u64)
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u64);
} blacklist_map SEC(".maps");

/* * Config Map: 
 * Key: 0
 * Value: Mode (0 = Ghost, 1 = Honey)
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} config_map SEC(".maps");

SEC("xdp")
int xdp_specter_handler(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // 1. Parse Ethernet Header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // 2. Filter for IPv4 (0x0800)
    if (eth->h_proto != __constant_htons(ETH_P_IP)) 
        return XDP_PASS;

    // 3. Parse IP Header
    struct iphdr *iph = (void *)eth + sizeof(struct ethhdr);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    // 4. Extract Source IP
    __u32 src_ip = iph->saddr;
    
    // --- HARDCODED BLOCK TEST ---
    // Google IP 142.251.221.238 (Hex from your log: 0xeeddfb8e)
    if (src_ip == 0xeeddfb8e) {
        return XDP_DROP;
    }
    
    // Get mode from config map (Default to Ghost Mode = 0)
    __u32 config_key = 0;
    __u32 *mode = bpf_map_lookup_elem(&config_map, &config_key);
    __u32 current_mode = mode ? *mode : 0;

    // 5. Check the Nitro Blacklist Map
    __u64 *drop_count = bpf_map_lookup_elem(&blacklist_map, &src_ip);
    
    if (drop_count) {
        __sync_fetch_and_add(drop_count, 1);
        if (current_mode == 0) {
            // GHOST MODE: 0 response.
            return XDP_DROP;
        } else {
            // HONEY MODE: Pass for analysis
            return XDP_PASS;
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";