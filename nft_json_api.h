#ifndef NFT_JSON_API
#define NFT_JSON_API

#include <string.h>
#include <nftables/libnftables.h>
#include <jansson.h>

enum nft_nat_types {
	NFT_SNAT = 0,
	NFT_DNAT,
	NFT_MASQ,
};

#define NFT_POLICY_ACCEPT "accept"
#define NFT_POLICY_DROP "drop"

enum nft_cmds {
	NFT_CMD_ADD = 0,
	NFT_CMD_DELETE,
	NFT_CMD_REPLACE,
};

#define NFT_SRC_ADDR 0
#define NFT_DST_ADDR 1

#define NFT_SRC_PORT 0
#define NFT_DST_PORT 1

/**
 *  Chain context.
 *
 *  @property priority (uint8_t) chain priority.
 *  @property family   (const char*) nft IP family (ip, ip6)
 *  @property table    (const char*) nft table name.
 *  @property chain    (const char*) nft chain name.
 *  @property type     (const char*) nft chain type.
 *  @property hook     (const char*) nft chain hook.
 *  @property policy   (const char*) nft chain policy.
 *  @see man page libnftables-json(5)
 */
typedef struct nft_json_chain_ctx {
	uint32_t priority;
	const char *family, *table, *chain, *type, *hook, *policy;
} chain_ctx;

/**
 *  Ports context.
 *
 *  @property port_type  (uint8_t) define source | destination port.
 *  @property protocol   (int) protocol.
 *  @property port_begin (int) begin port.
 *  @property port_end   (int) end port.
 */
typedef struct nft_json_ports_ctx {
	uint8_t port_type;
	int protocol, port_begin, port_end;
} ports_ctx;

/**
 *  Address context.
 *
 *  @property addr_type (uint8_t) define source | destinasion address.
 *  @property family    (const char*) nft IP family (ip, ip6)
 *  @property addr      (const char*) IP address.
 */
typedef struct nft_json_addr_ctx {
	uint8_t addr_type;
	const char *family, *addr;
	int mask_len;
} addr_ctx;

/**
 *  Policy context.
 *
 *  @property policy     (const char*) policy accept/drop.
 *  @property iifname    (const char*) in interface name.
 *  @property saddr_ctx  (addr_ctx) source address context.
 *  @property daddr_ctx  (addr_ctx) destination address context.
 *  @property sports_ctx (ports_ctx) source ports context.
 *  @property dports_ctx (ports_ctx) destination ports context.
 *  @see nft_json_addr_ctx, nft_json_ports_ctx.
 */
typedef struct nft_json_policy_ctx {
	const char *policy, *iifname;
	addr_ctx saddr_ctx, daddr_ctx;
	ports_ctx sport_ctx, dport_ctx;
} policy_ctx;

/**
 *  NAT context.
 *
 *  @property nat_type  (nft_nat_types) NAT type.
 *  @property oif       (const char*) out interface name.
 *  @property iifname   (const char*) in interface name.
 *  @property nat_addr  (const char*) NAT IP address.
 *  @property saddr_ctx (addr_ctx) source address context.
 *  @property daddr_ctx (addr_ctx) destination address context.
 *  @see nft_json_addr_ctx, nft_json_ports_ctx.
 */
typedef struct nft_json_nat_ctx {
	uint8_t nat_type;
	const char *oif, *iifname, *nat_addr;
	addr_ctx saddr_ctx;
	addr_ctx daddr_ctx;
} nat_ctx;

/**
 *  Rule context.
 *
 *  @property nft_cmd   (nft_cmds) nft command.
 *  @property handle    (uint8_t) rule handle.
 *  @property comment   (const char*) rule discription.
 *  @property ch_ctx    (chain_ctx) chain context.
 *  @see nft_json_addr_ctx, nft_json_ports_ctx.
 */
typedef struct nft_json_rule_ctx {
	uint8_t nft_cmd, handle;
    const char *comment;
    chain_ctx ch_ctx;
} rule_ctx;

/**
 *  Print error message.
 *
 *  @param  err_msg - error message.
 *  @return NULL
 */
json_t *pfail(const char *err_msg);

/**
 *  Print nft output.
 *
 *  @param  nft - nft context.
 *  @return 0 if success or -1 if output NULL.
 */
int nft_get_output(struct nft_ctx *nft);

/**
 *  Build command list chain.
 *
 *  @param list_cmd - destination command string.
 *  @param max_len  - MAX of length command string.
 *  @param  ch_ctx  - chain context struct.
 * 
 *  @return 0 - success or -1 - fail.
 */
int nft_json_build_list_chain(char *list_cmd, int max_len, const chain_ctx *ch_ctx);

/**
 *  Extract nft_array from nft output.
 *
 *  @param nft      - nft context.
 *  @param list_cmd - list nftables commands.
 * 
 *  @return JSON nft command or NULL if fail.
 */
json_t *nft_json_extract_array(struct nft_ctx *nft, char *list_cmd);

/**
 *  Get handle by rule comment.
 * 
 *  @param nft      - nft context.
 *  @param ch_ctx   - chain context struct.
 *  @param rule_comment - rule comment.
 *  @param  err     - JSON error value.
 * 
 *  @return handle value or -1 if handle not found.
 */
int nft_json_get_rule_handle(struct nft_ctx *nft, const chain_ctx *ch_ctx, const char *rule_comment, json_error_t *err);

/**
 *  Build nft JSON command for add table.
 *
 *  @param  family  - nft IP family (ip | ip6)
 *  @param  table   - nft table name.
 *  @param  err     - JSON error value.
 *
 *  @return JSON nft command or NULL if fail.
 */
json_t *nft_json_add_table(const char *family, const char *table, json_error_t *err);

/**
 *  Build nft JSON command for add chain.
 *
 *  @param  ch_ctx  - chain context struct.
 *  @param  err     - JSON error value.
 *
 *  @return JSON nft command or NULL if fail.
 */
json_t *nft_json_add_chain(chain_ctx *ch_ctx, json_error_t *err);

/**
 *  Build nft JSON statement oifname.
 *
 *  @param  oifname - out interface name.
 *  @param  err     - JSON error value.
 *  @return JSON nft command or NULL if fail.
 */
json_t *nft_json_build_st_oifname(const char *oifname, json_error_t *err);

/**
 *  Build nft JSON statement iifname.
 *
 *  @param  iifname - out interface name.
 *  @param  err     - JSON error value.
 *  @return JSON nft statement or NULL if fail.
 */
json_t *nft_json_build_st_iif(const char *iifname, json_error_t *err);

/**
 *  Build nft JSON statement address.
 *
 *  @param  addr_ctx - address context struct.
 *  @param  err     - JSON error value.
 *  @return JSON nft statement or NULL if fail.
 */
json_t *nft_json_build_st_addr(const addr_ctx *addr_ctx, json_error_t *err);

/**
 *  Build nft JSON statement counter.
 *  @return JSON nft statement.
 */
json_t *nft_json_build_st_count(void);

/**
 *  Build nft JSON statement policy.
 *
 *  @param  policy - nft_policies value.
 *  @return JSON nft statement.
 */
json_t *nft_json_build_st_policy(const char *policy);

/**
 *  Build nft JSON statement NAT.
 *
 *  @param  nat_type    - nat_types SNAT, DNAT, masquerade.
 *  @param  addr        - NAT address.
 *  @return JSON nft statement or NULL if fail.
 */
json_t *nft_json_build_st_nat(uint8_t nat_type, const char *addr, json_error_t *err);

/**
 *  Build nft JSON ports set.
 *
 *  @param  port_begin  - begin port.
 *  @param  port_end    - end port.
 *  @return JSON nft statement or NULL if fail.
 */
json_t *nft_json_build_ports_set(const int port_begin, const int port_end,
                                 json_error_t *err);

/**
 *  Build nft JSON statement ports.
 *
 *  @param  p_ctx   - ports context struct.
 *  @param  port_end    - end port.
 *  @return JSON nft statement or NULL if fail.
 */
json_t *nft_json_build_st_ports(const ports_ctx *p_ctx, json_error_t *err);

/**
 *  Build nft JSON statement protocol.
 *  
 *  @param  family  - nft IP family (ip | ip6)
 *  @param  proto   - ip protocol(0-255).
 *  @return JSON nft statement or NULL if fail.
 */
json_t *nft_json_build_st_proto(const char *family, const int proto, json_error_t *err);

/**
 *  Build nft JSON exression masquerade.
 *
 *  @param  oifname - out interface name.
 *  @param  count   - 0 for disable byte/packet counter
 *  @param  err     - JSON error value.
 *  @return JSON nft expression or NULL if fail.
 */
json_t *nft_json_build_expr_msq(const char *oifname, const int count,
                                json_error_t *err);

/**
 *  Build nft JSON exression SNAT.
 *
 *  @param  nat_ctx - NAT context struct.
 *  @param  count   - 0 for disable byte/packet counter
 *  @param  err     - JSON error value.
 *  @return JSON nft expression or NULL if fail.
 */
json_t *nft_json_build_expr_snat(const nat_ctx *nat_ctx, const int count,
                                 json_error_t *err);

/**
 *  Build nft JSON exression DNAT(PAT).
 *
 *  @param  nat_ctx - NAT context struct.
 *  @param  p_ctx   - ports context struct.
 *  @param  count   - 0 for disable byte/packet counter
 *  @param  err     - JSON error value.
 *  @return JSON nft expression or NULL if fail.
 */
json_t *nft_json_build_expr_dnat(const nat_ctx *nat_ctx, const ports_ctx *p_ctx,
                                 const int count, json_error_t *err);

/**
 *  Build nft JSON exression policy.
 *
 *  @param  pol_ctx - policy context struct.
 *  @param  family  - nft IP family (ip | ip6)
 *  @param  count   - 0 for disable byte/packet counter
 *  @param  err     - JSON error value.
 *  @return JSON nft expression or NULL if fail.
 */
json_t *nft_json_build_expr_policy(policy_ctx *pol_ctx, const char *family,
                                   const uint8_t count, json_error_t *err);

/**
 *  Build nft JSON command (add, delete, replace) rule.
 *
 *  @param  rule_ctx - rule context struct.
 *  @param  expr     - rule expression.
 *  @param  err     - JSON error value.
 *  @return JSON nft command or NULL if fail.
 */
json_t *nft_json_build_rule(const rule_ctx *rule_ctx, json_t *expr,
                            json_error_t *err);

/**
 *  Build nft JSON command flush ruleset.
 *
 *  @return JSON nft command or NULL if fail.
 */
json_t *nft_json_build_flush(void);

/**
 *  Get char string from json_t array nftables.
 *
 *  @param  nft_array - JSON array nftables.
 *  @return char string nft JSON command.
 */
char *nft_json_get_cmd_string(json_t *nft_array);

/**
 *  Dump nft output in to file output.json.
 *
 *  @param nft - nft context.
 */
int nft_json_fprint_ruleset(struct nft_ctx *nft, const char *outfile);

/**
 *  Free nft context & output buffer.
 *  
 *  @param nft - nft context.
 */
void nft_json_free(struct nft_ctx *nft);

#endif // !1NFT_JSON_API