# openwrt-mcp -- 面向 OpenWrt 24.10 和 25.12 的 MCP 服务器

[English](README.md) · [Русский](README.ru.md) · **简体中文**

> **本文为机器翻译**,译自 [README.md](README.md),未经人工校对。如有出入,以英文原文为准。

[![CI](https://github.com/stanislav-testhub/openwrt-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/stanislav-testhub/openwrt-mcp/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/stanislav-testhub/openwrt-mcp)](https://github.com/stanislav-testhub/openwrt-mcp/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![OpenWrt 25.12+](https://img.shields.io/badge/OpenWrt-25.12%2B-00B5E2)
[![M8ven Score](https://m8ven.ai/badge/mcp/stanislav-testhub-openwrt-mcp-1sd9jd?v=be6459adc68e5b28e87e74e3326a9ab7&variant=verified)](https://m8ven.ai/mcp/stanislav-testhub-openwrt-mcp-1sd9jd?s=readme)

这是一个运行在 OpenWrt 路由器**上**的 [MCP](https://modelcontextprotocol.io) 服务器,让
Claude Code(或任何 MCP 客户端)可以查看并修改路由器 -- 受默认拒绝策略、审计日志和配置变更的
自动回滚保护。

**本地且私密。** 服务器自身不发起任何出站连接,也不发送遥测数据;它只监听回环地址和仅 root 可访问的
套接字,并通过您自己搭建的 SSH 会话与客户端通信。那些可能让路由器本身对外发起连接的工具
(`net_diag`、带 `refresh` 的 `pkg_query`、`pkg_change`、`sysupgrade check`、`uci_apply` 的探测
(probe)、`ubus_call`、`exec`)会在其 MCP 注解(`openWorldHint`)中声明这一点,并且每个工具都需要您的授权。
工具输出中的机密值默认被屏蔽,新的 WireGuard 密钥除非您要求,否则不会进入对话。

**体积。** 单个静态二进制文件,无依赖:各路由器架构为 9.1 至 11.3 MB(arm64 为 9.6 MB,发布压缩包中
约 3.7 MB),在 GL-MT6000 上刚启动时常驻内存约 10 MB,23 个工具的描述约 22 KB。每个发布文件都带有校验和
和构建证明(attestation)。

> **基于 Ian Williams 的 [GlassOnTin/openwrt-mcp](https://github.com/GlassOnTin/openwrt-mcp)**,
> 该项目面向 GL.iNet 固件 4.x(OpenWrt 21.02,`opkg`)。本项目是向**原生 OpenWrt 25.12**
> (`apk`、fw4/nftables、procd、netifd、LuCI JS)的移植。安全核心来自上游;哪些来自何处,
> 见[致谢](#致谢)。

## 要求

- **路由器:** 原生 OpenWrt **25.12**(`apk`)或 **24.10**(`opkg`),均带 fw4/nftables。事先无需在路由器上安装任何东西。
  软件包工具根据路由器上的可执行文件选择包管理器(先 `apk`,再 `opkg`);`system_status` 会说明找到的是哪一个以及哪种防火墙。
  - **24.10 上的区别:** `pkg_query` 没有 `policy` 和 `audit`(opkg 没有这两项,工具会说明)。`pkg_change` 用 `opkg --noaction` 模拟。
    软件包的新默认配置以 `<file>-opkg` 而非 `<file>.apk-new` 的形式出现,`pkg_config_diff` / `pkg_config_resolve` 两种都能处理
    (旧副本保留为 `.pre-opkg-new`)。`world` 列出 opkg 标记为“用户安装”的软件包。`system_status mode=doctor` 报告 `opkg-new-pending`;
    `mode=audit` 跳过软件包审计并说明原因。
  - **fw3(OpenWrt 21.02 及更早版本,或基于它的固件):** 尽力而为。`firewall_show` 支持 `ruleset`(`iptables-save`,IPv4)和
    `rendered`(`fw3 -q print`);`check`、`table` 和 `chain` 会被拒绝;防火墙的应用不做预先检查。
  - **测试环境:** GL-MT6000 上的 25.12.5(硬件);单元测试在模拟环境中运行两种包管理器;CI 在 24.10 和 25.12 的 `openwrt/rootfs`
    容器中运行软件包和 uci 工具(那里没有 ubus 和 netifd,因此网络、无线和防火墙路径未被覆盖)。基于 OpenWrt 的固件(GL.iNet、ImmortalWrt)尽力而为。
- **您的电脑:** OpenSSH(Windows 10 及更高版本、macOS 和 Linux 均自带)。从发布版安装不需要其他东西。
  从源码构建需要 Go 1.26+、`ssh` 和 `tar`(Linux、macOS,或 Windows 上的 Git Bash)。
- **OpenWrt 与 Go 共同支持的任何 CPU:** 发布版为每种架构提供二进制文件(arm64、armv5/v7、
  mips/mipsle softfloat、mips64/mips64le、x86、x86-64、riscv64);`install.sh` 读取路由器的
  `DISTRIB_ARCH` 并选择对应文件,从源码构建时则进行交叉编译。

已在 GL.iNet GL-MT6000(mediatek/filogic,`aarch64_cortex-a53`)和 OpenWrt 25.12.5 上测试。
代码中没有任何内容是专用于该开发板的。

---

## 与其他 OpenWrt MCP 服务器有何不同

依据各项目自己的 README(2026-10-07);"未说明"表示该 README 没有提及。欢迎指正。

| | 本项目 | [openwrt_ssh_mcp](https://github.com/jsebgiraldo/openwrt_ssh_mcp) | [paulomac1000/openwrt-mcp](https://github.com/paulomac1000/openwrt-mcp) | [openwrt-luci-mcp](https://github.com/JeffersonYoung/openwrt-luci-mcp) |
|---|---|---|---|---|
| 运行位置 | 路由器上 | 电脑上,在 Docker 中 | 电脑上,在 Docker 或 Python 中 | 电脑上,在 Node.js 中 |
| 连接路由器的方式 | 通过绑定密钥的强制命令走 SSH,或回环 HTTP | SSH | SSH | LuCI 的 HTTP `/ubus` |
| 修改配置 | 是,通过一个会先检查并启用回滚的工具 | 是,包括软件包和固件刷写 | 除非设置 `ENABLE_WRITE_OPERATIONS=1`,否则只读 | 否 |
| 对错误变更的自动回滚 | 是,且重启后仍然有效 | 未说明 | 未说明 | 不适用 |
| 访问控制与审计 | 按客户端授权,含范围、过期时间和速率限制,审计日志,可选 TOTP | 命令白名单,审计日志 | 审计日志 | 机密被隐藏,无审计日志 |
| 包管理器 | `apk`(25.12)或 `opkg`(24.10) | `opkg` | `opkg` | 列出已安装和可用的软件包 |
| 刷写固件 | 绝不 | 是 | 未说明 | 否 |
| 路由器上的需求 | 该二进制文件 | SSH | SSH | `uhttpd-mod-ubus`、`rpcd` |

---

## 相对上游的改动

| | 上游 0.5(21.02 / GL.iNet) | 本移植版(25.12) |
|---|---|---|
| 打包 | 用于 `opkg` 的 `.ipk` | `install.sh` 文件安装 + `keep.d`(25.12 的 apk 没有 `mkpkg`;见下文) |
| Web 界面 | GL.iNet oui-httpd 页面 | LuCI 页面,*Services -> MCP Server*(只读) |
| 传输 | 经 `ssh -L` 隧道的 HTTP | 同样支持,**另加经 SSH 的 stdio**,通过绑定密钥的强制命令 -- 无需维持隧道 |
| 回滚快照 | `/tmp`(重启即丢失) | **存于闪存**;未确认的变更会在下次启动时回滚,包括断电重启之后 |
| `uci_apply` | set / create / delete | **+ `add_list`、`del_list`、`set_list`、`dry_run`**,显示暂存的 `uci changes`,严格的名称校验。dry run 以建议结尾,即 `warnings from this change`。 |
| 重载 | `ubus call uci reload_config`(异步) | `/sbin/reload_config`,在它没有校验和时(开机后首次运行)另加显式的 `config.change` 事件 |
| WireGuard | GL 的 `wireguard_server` / `gl_ddns` | 标准的 `network.<iface>` + `wireguard_<iface>` 对端,来自 `ddns` 的 DDNS,CGNAT 警告,PSK,列出和删除 |
| 软件包 | -- | `pkg_query`、`pkg_change`(先模拟)、带设置级差异的 `.apk-new` 审阅 |
| 防火墙 | -- | `firewall_show`:nft 规则集、`fw4 print`、`fw4 check` |
| 服务 | -- | 通过 rpcd `rc` 的 `service_list` / `service_control` |
| 范围通配符 | `[0]` 曾是字符类 | 方括号按字面处理:`firewall.@rule[3].*` 就是字面意思 |
| 预设 | -- | `openwrt-mcp allow <client> @readonly|@operator <dur>` |

---

## 工具

| 工具 | 范围 | |
|---|---|---|
| `system_status` | tool | 型号、版本、运行时间、负载、内存、存储、温度、conntrack、每个接口(状态、地址、默认路由、错误)、无线电/SSID,以及待处理事项。请首先调用。`mode=doctor` 返回按严重程度排序的健康发现(无线电关闭、接口无地址、已启用的服务已崩溃、conntrack 和存储将满、待处理的 `.apk-new`、NTP 或未设置的时钟、已安装的内核比运行中的更新)。`mode=audit` 返回按严重程度排序的安全发现(防火墙允许从互联网进入的内容、SSH 和 LuCI 暴露情况、密码登录、UPnP、WPS、开放或弱 Wi-Fi、空的 root 密码、被修改的软件包文件、过期的 WireGuard 对端)。两者都仅供参考,每条发现都会指明下一步只读调用和一个 OpenWrt wiki 页面,并列出它们无法检查的内容。它们是独立的范围:`openwrt-mcp allow <client> system_status doctor`。 |
| `logread` | tool | 先对整个日志缓冲区做过滤(子串、RE2、最近 N 分钟),*然后*再应用行数限制;`offset` 从最新一行向前翻页。`mode=summary` 把日志折叠为不同的消息(数字、地址和 ID 变成占位符),带计数、首次和最后出现时间以及最高严重级别。`baseline=save` 返回一个令牌;`baseline=<token>` 只显示当时日志中没有的消息。基线保存的是指纹而非日志文本,且存于内存中。 |
| `network_clients` | tool | DHCP 租约 + 静态主机 + 邻居表 + 每个 AP 的关联列表,按 MAC 合并:名称、IP、SSID、信号、速率、连接时间、每个客户端占用其无线电空口时间的份额(来自 hostapd)、租约;每页 100 行,用 `offset` 翻页。 |
| `firewall_show` | tool | `nft list ruleset`、`fw4 print`、`fw4 check`,可指定一个表或链。 |
| `net_diag` | `<action>[.<target>]` | ping / traceroute / nslookup(可选从指定接口发出)、路由、策略规则、邻居。`wifi_survey` 按无线电报告它所在信道的繁忙程度(busy、rx 和 tx 空口时间、噪声);其他信道未被测量,因此它从不推荐信道。`traffic` 采样接口速率几秒钟,并按来源对 conntrack 表排序。`usage` 读取 nlbwmon 在一个计费周期(默认一个月)内按设备统计的总量。三者都只读。 |
| `uci_get` | `<config>[.<section>[.<option>]]`;`refs` 用于按名称搜索 | `uci show`,可选带稳定的 `cfgXXXXXX` ID。以该配置的**修订号**结尾。`history=list` / `diff:<id>` 显示每次已确认变更之前保留的版本。`refs=NAME` 查找各配置中定义并使用某个名称的位置。 |
| `uci_apply` | 每项变更 `<config>.<section>[.<option>]`;`restore` 用 `<config>`;每个探测 `probe.<kind>.<target>` | 暂存、检查、提交、重载,**回滚已启用**。`dry_run` 精确显示将要改变的内容以及该服务自身检查器的意见。`expected_revisions` 在配置期间被改动时拒绝执行,`probe` 在之后检查路由器,`restore=<id>` 恢复过去的版本。提交后会回读配置;路由器没有保留的变更为 `NOT_APPLIED`,且不会重载任何东西。 |
| `uci_confirm` / `uci_rollback` | tool | 使待定变更永久生效 / 立即撤销。 |
| `service_list` / `service_control` | tool,`<service>.detail` / `<service>.<action>` | procd 服务;`service_list detail=NAME` 返回已安装附加组件自身的状态(tailscale、AdGuard Home、podkop;普通列表会指出本机装了哪些);停止或禁用 dropbear、network、rpcd 或 openwrt-mcp 会被拒绝。`service_control` 等待状态稳定(`wait`),未稳定时会说明;与操作相矛盾的最终状态为 `NOT_APPLIED`。 |
| `pkg_query` | tool | installed、upgradable、search、info、files、owner、policy、`apk audit`、world;每页 200 行,用 `offset` 翻页。 |
| `pkg_change` | `<action>.<pkg>` / `upgrade` | apk add/del/upgrade;**除非 `commit=true`,否则只模拟**;报告新的 `.apk-new` 文件;之后检查 `/etc/apk/world`。 |
| `pkg_config_diff` | tool | 把每个 `.apk-new` 显示为与现用文件的差异 -- 对 `/etc/config/*` 按设置(`uci show`)比较,因此引号和缩进造成的噪声消失。 |
| `pkg_config_resolve` | 现用路径 | keep_current(丢弃新的默认值)或 use_new(安装它;对 UCI 配置会启用回滚)。 |
| `sysupgrade` | `<action>` | list(保留的文件)、test(验证 /tmp 中的镜像)、check(`owut`)、backup(模式 0600;该工具先前创建的归档会被删除)。**绝不刷写。** |
| `wg_list_clients` | tool | 对端及其握手时长、端点、流量、配置/内核不一致、重名。 |
| `wg_new_client` | `wireguard.<iface>`;`reveal=true` 用 `wireguard.<iface>.reveal` | 生成密钥对、下一个空闲地址,把对端保存到网络配置中;`uci_confirm` 才会保留它。私钥和配置写入仅 root 可读的文件;您用 `openwrt-mcp wg-show <name>` 取回(配置和二维码显示在您自己的终端中)。`reveal=true` 则直接在结果中返回它们。 |
| `wg_remove_client` | `wireguard.<iface>.<name>` | 按名称、密钥或配置段,从配置和接口中删除;已启用回滚(`uci_confirm` 才会保留)。拒绝删除最近 3 分钟内连接过的对端或本会话自身所用的对端,除非 `force=true`。 |
| `ubus_list` | *(不受限)* | 发现:每个对象、方法和参数签名。 |
| `ubus_call` | `<object>.<method>` | 总线上的其他一切。超过 8 KB 的回复会裁剪过长的数组。 |
| `exec` | `argv[0]` | 一个程序,无 shell。对 `sh`、`find`、`awk`、`env`、`ssh` 等的授权等同于 root shell:`allow` 在没有 `--shell-equivalent` 时会拒绝。 |
| `mfa_unlock` | *(不受限)* | 为受 MFA 保护的工具打开 TOTP 窗口。 |

**提示词(Prompts)。** 能显示 MCP 提示词的客户端(通常以斜杠命令形式)会得到五个配方:
`router-health`、`who-is-online`、`secure-my-router`、`wifi-doctor` 和 `upgrade-plan`。每个只有
几行,指明要调用的工具,并以报告或建议结尾,绝不做修改。它们只使用 `@readonly` 预设所授予的权限,
因此只读客户端也能执行到底,且在使用之前不产生任何开销。列出或获取一个提示词不会在路由器上运行任何东西,
因此不适用任何策略,也不会被审计。

### 警告、引用、对端和附加组件

**dry run 中的警告。** `uci_apply dry_run` 以 `warnings from this change` 结尾:列出该变更相对路由器当前状态会新增的发现,排序方式与审计相同,
每条都附有下一步和 OpenWrt wiki 页面。它们只是建议,绝不是拒绝。内容包括:向互联网开放的端口或端口转发、WAN 区域的 input 或 forward 被设为 `ACCEPT`、
启用 SSH 密码登录、未加密的 SSID、变更删除或拼错了某个名称而其他配置段仍在使用它(`ref-removed`、`ref-unknown`,大小写不一致时会提示“您是不是想写”),
以及关闭您自己会话所连接的 Wi-Fi 网络(`radio-in-use`)。变更之前就已存在的问题不会重复报告。真正的应用不会重复这些警告,因此请先运行 dry run。

**管理路径跟随您的会话。** 除了 LAN 及其网桥、SSH 监听器以及放行 SSH 的区域和规则之外,您自己的 SSH 连接所经过的接口也算管理路径
(守护进程用 `ip route get` 解析客户端地址),因此对您正在使用的 WireGuard 隧道做变更,与改动 LAN 一样需要探测(`probe`)或 `force=true`。

**重命名或删除接口、区域或设备之前。** `uci_get refs=lan` 列出定义该名称的对象(网络接口、防火墙区域、设备、无线电、mwan3 成员或策略)
以及使用它的每个引用字段:区域的 `network`,规则/转发/重定向的 `src` 和 `dest`,dhcp 的 `interface`,wireless 的 `network` 和 `device`,
network 的 `device` 和 `ports`,`route.interface`,以及已安装时的 `sqm` 和 `mwan3`。“defined as: nothing” 表示没有任何配置段叫这个名字
(拼写错误或大小写不一致)。只读取这些字段,因此无法借此搜索密钥。需要 `refs` 范围,`@readonly` 和 `@operator` 都包含它;
`config=firewall` 可把搜索缩小到一个配置。

**添加和删除 WireGuard 对端是普通的、已启用回滚的变更。** 对端写入 `/etc/config/network`,由 netifd 加载,因此其他对端的会话不会中断。
两个工具都会等待对端出现在(或离开)运行中的接口上,并说明验证了什么。在 `uci_confirm` 之前一切都不是永久的:否则超时或重启之后,
对端会被移除,新客户端的密钥文件也会被删除。同一时间只能有一个变更在等待确认。删除您自己会话所经过的对端需要 `force=true`。

**附加组件状态。** `service_list detail=NAME` 读取已安装的附加组件(其 init 脚本存在),并输出一组固定的只读字段:它从不回显配置文件或命令的原始输出,
因为其中含有登录哈希、代理链接、节点密钥和令牌。授权需要该服务的范围(`tailscale.detail`,或如 `@readonly` 中的 `*`);普通列表不需要。
别人选定的文本(例如 tailnet 对端的主机名)会被截断、清理并标记为不可信。

| 附加组件 | 报告内容 | 已验证 |
|---|---|---|
| tailscale | 状态、tailnet DNS 后缀、本节点地址、通告的路由、出口节点、健康状况、对端(在线、直连或中继、流量) | GL-MT6000,25.12 |
| AdGuard Home | 是否运行、监听地址、保护和过滤开关、上游(仅方案和主机)、bootstrap、过滤列表和规则数量、dnsmasq 是否转发给它 | GL-MT6000,25.12 |
| podkop | 版本、sing-box 是否运行、nft 表、dnsmasq 路径、设置、每个配置段一行(类型、接口、社区列表、动态列表大小) | GL-MT6000,25.12 |

刻意不读取:AdGuard Home 的 Web API(需要登录界面)、podkop 的 `proxy_string`、选择器和出站设置,以及用户的域名和子网列表。

---

## 安装

**在路由器上,从发布版安装**(默认的 25.12 镜像之外无需任何东西):

```sh
wget -O /tmp/install-router.sh https://github.com/stanislav-testhub/openwrt-mcp/releases/latest/download/install-router.sh
sh /tmp/install-router.sh
```

脚本会根据路由器的 `DISTRIB_ARCH` 选择压缩包,用该发布版的 `SHA256SUMS` 校验(不匹配则拒绝),然后安装。
`VERSION=v1.2.0` 可选择最新版以外的发布版。每个发布文件还带有构建证明:
`gh attestation verify <file> --repo stanislav-testhub/openwrt-mcp`。

**在电脑上从源码构建**(需要 Go、ssh 和 tar;Windows 上可用 Git Bash):

```sh
git clone https://github.com/stanislav-testhub/openwrt-mcp
cd openwrt-mcp
ROUTER=root@192.168.1.1 SSH_PORT=22 SSH_KEY=~/.ssh/id_ed25519 ./install.sh install
```

`ROUTER`、`SSH_PORT` 和 `SSH_KEY` 是您路由器的 root 登录信息(默认值:`root@192.168.1.1`、22、
您的 ssh 默认设置)。`./install.sh install --release [vX.Y.Z]` 跳过构建,改由路由器下载经过校验的发布版;
找不到 Go 工具链时也是这样处理。

两种方式最终都在路由器上运行同一个安装程序。
- 它会安装:
  - `/usr/bin/openwrt-mcp`;
  - init 脚本;
  - 默认配置,绝不覆盖已有配置;
  - `keep.d` 条目;
  - LuCI 页面。
- 然后启用并启动服务。
- 当有 `uci_apply` 正等待确认时,它拒绝重启守护进程(因为这会触发回滚),除非设置 `FORCE=1`。
- 它会先检查二进制文件能否放进 overlay。

`./install.sh uninstall [--purge]` 可撤销上述操作。

### LuCI 状态页面

安装后,LuCI 中的 *Services -> MCP Server* 会显示守护进程(运行或停止、版本、HTTP 监听器、stdio 套接字)、
带有自动回滚截止时间的待定 `uci_apply`、已配对的 HTTP 客户端、现行策略以及最近的审计条目。它被刻意设计为
只读:配对和授权保留在命令行中,因此网络上可达的任何东西都无法扩大代理的权限。

**为什么不做成 `.apk`:** 25.12 的软件包是 apk-tools v3 的 ADB 归档。构建它需要 OpenWrt SDK,或带有
`mkpkg` 的主机端 apk-tools(路由器上的 apk 没有 `mkpkg`),而且未签名的软件包仍需要 `--allow-untrusted`。
静态二进制文件以文件方式安装并不吃亏:`/etc/config` 本身就能在 sysupgrade 中保留,而
`/lib/upgrade/keep.d/openwrt-mcp` 负责保留二进制文件、init 脚本、rc.d 链接、状态和 LuCI 页面。
(`owut`/ASU 镜像重建的是*软件包*,而不是零散文件 -- 在其前后保留这些东西靠的是 keep.d 条目。)

---

## 连接

### `openwrt-mcp connect`(推荐)

发布版也为您的电脑提供了二进制文件(`openwrt-mcp_<version>_windows_amd64.zip`、`darwin_arm64.tar.gz`
等;Linux 电脑可用 `linux_` 压缩包)。把它解压到 `PATH` 中的任意位置;它需要 OpenSSH,Windows 10 及更高版本、
macOS 和 Linux 都自带。然后在电脑上:

```sh
openwrt-mcp connect --client claude-code --host 192.168.1.1          # or claude-desktop, codex, cursor, gemini, vscode
```

它会生成一个专用的 ed25519 密钥(`~/.ssh/openwrt_mcp`,绝不覆盖已有的),打印需要在路由器上运行一次的
两条命令,并显示要添加到客户端的条目。加上 `--write` 它就会执行最后一步:对 Claude Code 和 Codex 运行它们自己的
`mcp add`,对 Claude Desktop、Cursor、Gemini CLI 和 VS Code 则把一条 `openwrt` 条目合并进它们的 JSON 文件
(其他服务器保持不变;原文件会保留一份 `<file>.before-openwrt-mcp`;含注释的文件不会被改动,而是打印出片段)。
该条目把 `ssh` 及其参数存为列表,因此密钥路径中的空格无需转义,并设置了 keep-alive,以便发现路由器已重启。

```sh
openwrt-mcp connect doctor --host 192.168.1.1
```

按顺序检查整条链路,并在第一处断点停下,给出一个修复建议:

```
[ ok ] ssh reachable   192.168.1.1:22
[ ok ] host key
[ ok ] key accepted    /home/you/.ssh/openwrt_mcp
[FAIL] forced command  the key logged in, but nothing answered as an MCP server (...)
       fix: the key is probably authorized without its forced command ...
[skip] daemon socket
```

步骤依次为:SSH 可达、主机密钥、密钥被接受、强制命令、守护进程套接字、`initialize`、`tools/list`。
密钥错误、缺少强制命令、守护进程已停止以及套接字被禁用,各自会指向各自的步骤。

**重启路由器或守护进程之后。** 重启、通过 `install.sh` 升级或崩溃都会结束所有打开的会话:`openwrt-mcp stdio` 桥接以
`daemon closed the connection` 退出,客户端显示该服务器已断开。并非所有 MCP 客户端都会自动重连,请从客户端重新连接(其 MCP 菜单,或重启客户端)。
开机后 SSH 会比守护进程开始监听早几秒响应;桥接最多等待守护进程的套接字 10 秒,之后才以 `daemon not reachable ... after waiting 10s`
(以及 `[code: TIMEOUT; ...]`)失败,所以路由器恢复后立即重连通常没问题;若不行,请等几秒再重连。仍在等待 `uci_confirm` 的变更会在下次启动时回滚。
`openwrt-mcp status` 显示最近一次断开及其原因(`client closed the connection`、`connection error: ...` 或
`the daemon restarted (router reboot, upgrade or crash)`),信息取自审计日志;日志里每个会话还有一行 `stdio session closed after ...`,每次启动有一行 `daemon started`。

### 更窄的会话,以及 shell

**要求比密钥允许的更少。** 策略决定客户端能做什么;客户端也可以在一次会话中要求*更少*。

```sh
openwrt-mcp connect --client claude-code --host 192.168.1.1 --read-only            # 不做任何会改变路由器的事
openwrt-mcp connect --client claude-code --host 192.168.1.1 --toolset diag,pkg      # 只启用这些工具
```

工具集有 `diag`(`logread`、`network_clients`、`firewall_show`、`net_diag`、`service_list`、`ubus_list`、`ubus_call`)、
`config`(`uci_get`、`uci_apply`、`uci_confirm`、`uci_rollback`、`service_control`)、`pkg`(`pkg_query`、`pkg_change`、
`pkg_config_diff`、`pkg_config_resolve`、`sysupgrade`)和 `wg`(三个 WireGuard 工具)。`system_status` 始终存在;`exec` 不在任何工具集中。
`--read-only` 是 `@readonly` 预设与客户端授权的交集,因此只能减少权限,被隐藏的工具在调用时会被拒绝,而不只是从列表中去掉。
该配置以强制命令之后的若干单词传递(`SSH_ORIGINAL_COMMAND`),守护进程按固定语法解析:其余一切都会被拒绝并记入审计,语法中没有任何能扩大会话权限的词。

**从 shell 或脚本调用,无需 MCP 客户端。** 同一个 SSH 密钥一次运行一个工具:

```sh
ssh -T root@192.168.1.1 call --list
ssh -T root@192.168.1.1 call uci_get --help
ssh -T root@192.168.1.1 call uci_get '{"config":"network"}'
ssh -T root@192.168.1.1 -- --read-only call uci_get '{"config":"network"}'   # 在配置词之前,`--` 结束 ssh 自己的选项
```

结果以文本输出到 stdout;拒绝或错误输出到 stderr,附带 `allow` 行,退出码为 1。调用与 MCP 会话经过相同的策略、审计和脱敏。
`skills/openwrt-mcp/SKILL.md` 是现成的技能文件,适合偏好 shell 而非 MCP 的代理。

**限制。** 每个工具的截止时间都高于其自身的等待时间,且最多同时运行 8 个调用:其余的最多等待 30 秒,然后收到 `busy` 拒绝(`TIMEOUT`)。
客户端取消调用会杀掉它启动的命令。`uci_confirm`、`uci_rollback` 和 `mfa_unlock` 从不排队等位。

### 手动配置经 SSH 的 stdio

一个专用密钥,在路由器上只与 MCP 桥接绑定,别无他用:

```sh
ssh-keygen -t ed25519 -N '' -f ~/.ssh/openwrt_mcp
ssh root@router "openwrt-mcp authorize-key claude-code '$(cat ~/.ssh/openwrt_mcp.pub)'"
ssh root@router "openwrt-mcp allow claude-code @readonly 30d"
claude mcp add openwrt -- ssh -T -i ~/.ssh/openwrt_mcp -o BatchMode=yes root@router
```

`authorize-key` 会在 `/etc/dropbear/authorized_keys` 中写入类似下面的一行:
`command="/usr/bin/openwrt-mcp stdio --client claude-code",no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty ssh-ed25519 ...`
该密钥会以客户端名 `claude-code` 获得 MCP 服务器,既不能打开 shell,也不能转发端口。它会拒绝已经是 root 登录的密钥。

桥接把会话转入一个仅 root 可访问的 unix 套接字(`/var/run/openwrt-mcp/mcp.sock`,位于 0700 目录中,权限 0600)。
**守护进程**运行这些工具,所以在一个会话中启用的回滚在该会话结束后依然有效。套接字上的客户端名是声明而非证明 --
这是可行的,因为只有 root 能够连接,而 root 本来就可以编辑策略文件;真正的认证是 SSH 密钥。

在 Windows 上,内置的 OpenSSH 客户端(`ssh.exe`)可用于此;请使用密钥的完整路径。

### 经隧道的 HTTP

与上游相同:`openwrt-mcp pair <client>` 会一次性打印一个 bearer 令牌;
`ssh -N -L 8730:127.0.0.1:8730 root@router`;然后
`claude mcp add --transport http openwrt http://127.0.0.1:8730/mcp --header "Authorization: Bearer $TOK"`。
守护进程拒绝绑定到回环以外的任何地址。

### 让策略真正有意义

如果代理还能通过它的 shell 工具运行 `ssh root@router ...`,策略就只是建议性的。请在客户端中禁止这一点
(Claude Code:为 `Bash(ssh * root@<router>*)` 设置 `permissions.deny` 规则),或者把 root 密钥放在代理读不到的地方。

---

## 策略

默认拒绝。一条策略向一个客户端授予一组工具、范围通配符(`*` 和 `?` 是通配符;方括号按字面处理)、
每分钟调用次数上限和过期时间。对 `/etc/config/openwrt-mcp` 的修改无需重启即可生效。

```sh
openwrt-mcp allow claude-code @readonly 30d          # every read tool; ubus_call on an allow-list of read methods
openwrt-mcp allow claude-code @operator 7d           # + uci_apply/confirm/rollback, service_control, pkg_change,
                                                      #   pkg_config_resolve, wg_new/remove_client, sysupgrade backup
openwrt-mcp allow claude-code uci_apply 'dhcp.* wireless.*.disabled' 30d
openwrt-mcp allow claude-code service_control 'dnsmasq.restart adguardhome.*' 30d
openwrt-mcp revoke claude-code                        # remove every policy for the client
openwrt-mcp prune --older-than 7d                     # delete grants that expired over a week ago (audited)
openwrt-mcp policies | status [--all] | clients
```

再次授予相同的工具和范围,会替换该客户端已过期的授权,而不是追加一个块。`status` 用一行统计过期的授权;
`--all` 会列出它们。

两个预设都不包含 `exec` 或不受限的 `ubus_call`;二者都会绕过安全防护。只读的 ubus 列表由明确的
`object.method` 对组成,而不是 `*.list` 这类通配符,因为 `session.list` 会返回 LuCI 会话 ID。
`uci_get '*'` 会读取所有配置,但机密选项(Wi-Fi 密钥、WireGuard 密钥、密码、令牌)的值会以 `<redacted>` 返回;
见*安全模型*。`exec` 不做屏蔽。

拒绝信息会指出未被覆盖的范围,并打印出能够覆盖它的确切 `allow` 命令行。

`exec` 的范围就是字面意义上的 `argv[0]`,所以对 `find` 或 `awk` 的授权看似无害,实则等同于 root shell:二者都会运行其他程序,
各种 shell、`env`、`nice`、`flock`、`timeout`、`xargs`、`tar`、`ssh`、`lua`、`ucode`、`apk` 和 `opkg` 也是如此。
`allow` 会拒绝此类授权,除非您加上 `--shell-equivalent`,它按基本名称判断,所以 `/usr/bin/../bin/sh` 和 `/bin/*`
同样算数;能够到达 `file.exec` 的 `ubus_call` 授权也按同样方式处理。`openwrt-mcp policies` 和 `status` 会标出这些授权,
这也涵盖了手写的策略。该列表只是底线,而非保证:能写文件的授权(`wget`、`cp`、`dd`)或会启动不在列表中的解释器的授权,
仍可能被滥用。

### 第二因素

与上游相同:`openwrt-mcp mfa enrol <client>` 会打印一个 `otpauth://` URI;然后在策略中设置
`list mfa_tools 'uci_apply'`、`option mfa_window '15m'`。一个验证码打开一个限时窗口;验证码一次性有效;
解锁状态只保存在内存中。

错误验证码受到限制:在 `config server` 段中,连续 `option mfa_max_failures '5'` 次错误验证码会使该客户端在
`option mfa_lockout '300'` 秒内无法使用 `mfa_unlock`(`'5m'` 也可以),每次重复就加倍,最长一小时。
锁定期间的正确验证码会被拒绝且不会被消耗。没有密钥的客户端同样计数,因此该限制不会泄露注册情况,
计数器保存在内存中(重启、`mfa enrol` 或轮换密钥都会清除它们)。每个错误验证码在审计中记为 `ERROR`,
锁定记为 `DENIED`;验证码本身从不记录。代价是:持有某客户端令牌的人可以让该客户端被锁定长达一小时。

---

## 安全模型

- **在最可能发生的情况下仍然有效的回滚。** `uci_apply` 把涉及的配置快照到
  `/etc/openwrt-mcp/rollback/<token>/`(已 fsync),在提交*之前*写入待定记录,然后提交、重载,并启动计时器
  (默认 90 秒,最长 600 秒)。没有 `uci_confirm` -> 文件被原子地恢复,暂存的变更被撤销,服务被重载。
  如果路由器在窗口期内断电重启,procd 会在网络之后(S95)启动守护进程,守护进程在启动时执行回滚,
  并对每个被恢复的配置强制触发 `config.change`。
- **不碰别人的编辑。** 当某个提交类工具要提交的配置里存在来自其他会话的未提交变更,或有未确认的应用正在等待时,
  它拒绝运行。
- **重载之前先检查。** dry run 会在暂存的配置上运行各服务自己的检查器(若有;防火墙用 `fw4 check`),
  并只列出该变更*新增*的问题。真正的应用会拒绝这些问题,除非 `force=true`;本来就已损坏的配置仍可被修复。
  dnsmasq、dropbear 等没有能看到暂存变更的检查器:它们被报告为"未检查",而不是"通过"。
- **写入后回读。** `uci_apply` 在提交之后、任何重载之前重新读取每个配置;`wg_new_client`、`wg_remove_client`
  和 `pkg_change` 随后查看对端表、配置和 `/etc/apk/world`;`service_control` 把最终状态与操作比对。
  路由器接受了却没有保留的写入为 `NOT_APPLIED`,对 `uci_apply` 而言回滚仍保持启用。无法执行的回读会显示
  "Not verified"。位置型配置段(`@rule[3]`)无法比较,只做计数。
- **没有静默覆盖。** `uci_get` 以配置的修订号结尾。把它作为 `expected_revisions` 传回,如果配置在此期间改变
  (LuCI、另一个客户端),应用就会以 `CONFLICT` 被拒绝。
- **管理路径受到保护。** 对 LAN 接口或其网桥、SSH 监听器,或允许 SSH 进入的防火墙区域和规则的更改会被拒绝,
  除非调用指明了 `probe`(ping 网关、解析一个名称)或 `force=true`。探测在重载之后运行,并随结果一起报告;
  此类变更的回滚窗口默认为 180 秒。规则集是静态的(LAN 加上 dropbear 所指的),因此涵盖常见布局,而不是所有拓扑。
- **历史与恢复。** 确认一次变更会保留变更之前的配置版本(每个配置最新的 `history_keep` 个,默认 5,存于
  `/etc/openwrt-mcp/history/`)。`uci_get history=list` 列出它们,`history=diff:<id>` 把其中一个与现在比较,
  `uci_apply restore=<id>` 通过同样的快照、检查和回滚计时器把其中一个放回去。条目含有机密,与快照一样:
  `0600`,显示时被屏蔽,并包含在 `sysupgrade` 备份中。`option history_keep '0'` 可关闭此功能。
- **不能自我提权。** 无论授权如何,`uci_apply` 和 `pkg_config_resolve` 都拒绝操作 openwrt-mcp 策略配置,
  因此客户端无法给自己写一条更宽的策略。策略只能通过路由器上的 `openwrt-mcp allow` / `revoke` 更改。
- **`@operator` 权限很大。** 对 `*` 的 `uci_apply` 可触及每一个 UCI 配置,包括 `dropbear`、`rpcd` 和 `uhttpd`,
  而 `pkg_change` 以 root 身份安装软件包。只在一次工作会话期间授予它(`2h`),长期授权请限定在
  `'dhcp.* wireless.*.disabled'` 这样的窄范围。
- **名称按 UCI 语法校验**,因此像 `lan.ipaddr=x` 这样的配置段不能让 uci 去操作与策略所批准范围不同的键。
- **任何地方都没有 shell。** 每条命令都是 argv;可能被当作选项读取的目标和名称(`-f`)会被拒绝。
- **生命线。** `service_control` 不会停止或禁用 dropbear、network、rpcd 或 openwrt-mcp。`sysupgrade` 没有刷写操作 --
  用 `test` 验证镜像,手动刷写。`wg_remove_client` 不会删除最近 3 分钟内握手过的隧道,也不会删除本会话所经过的隧道,除非强制。
- **凭据不进入对话。** `wg_new_client` 把新客户端的配置(包括私钥)写入套接字旁边内存中仅 root 可读的文件,
  并返回公钥和要运行的命令。路由器上的 `openwrt-mcp wg-show <name>` 在您的终端中打印配置和二维码并删除该文件;
  未取走的文件会在 24 小时后或下次重启时消失。只有 `reveal=true` 会把密钥放进结果,从而进入模型的上下文和提供方的日志。
  `sysupgrade` 备份在写入任何内容之前就以 0600 创建,且只保留最新的一份。审计日志记录参数和摘要,从不记录工具输出,
  并屏蔽看起来像机密的字段。服务器私钥从 `wg show dump` 读取后即被丢弃。
- **工具输出中的机密会被屏蔽。** `uci_get`、`uci_apply`(差异和错误)、`pkg_config_diff`、`pkg_config_resolve`、
  `uci_confirm`、`uci_rollback`、`system_status` 和 `ubus_call` 保留行的形状,并把机密选项
  (`key`、`key1`..`key4`、`psk`、`password`、`sae_password`、`passphrase`、`private_key`、`preshared_key`、
  `token`、`pwd`、任何包含 `secret` 的名称……)的值替换为 `<redacted>`。审计日志使用同样的规则。`exec`、`logread`
  和诊断工具不做屏蔽,`wg_new_client` 是有意豁免的。在 `config server` 段中:`list redact_extra 'vendor_blob'`
  可增加名称;`option redact_output '0'` 会关闭屏蔽,且会被审计。被屏蔽的差异不会显示机密具体改了什么。
- **路由器的输出不可信。** 主机名、SSID、日志行和 DNS 应答由其他设备决定。每个结果都会去除终端转义序列、
  控制字符、双向文字(bidi)和零宽字符以及无效的 UTF-8,并把行截断为 1024 字节(`exec`、`ubus_call`、
  `wg_new_client` 和配置类工具除外)。`network_clients`、`logread` 和 `net_diag` 以一行
  `[untrusted text: ...]` 开头。这降低了模型服从此类文本的可能性,但不能消除,因此请不要让写入范围出现在会读取它的会话中。
- **状态不外露到 Web。** 如果状态目录、审计日志和套接字位于 `/www`、某个 `cgi-bin` 目录或 uhttpd 的 `home` 之下,
  即使通过符号链接,也会被拒绝。
- **威胁模型**见 [SECURITY.md](SECURITY.md)。
- **上游的结论依然成立:** rpcd 的 ACL 无法约束本地 ubus 套接字上的 root 进程,因此不依赖它们;rpcd 自带的
  apply/rollback 把状态保存在 rpcd 内存和 tmpfs 中,这就是快照由我们管理并存放在闪存上的原因。

---

## 已验证

在 GL-MT6000 上,原生 OpenWrt 25.12.5,按 `install.sh` 的步骤安装,并从 Windows 上完全像 Claude Code 那样驱动
(带强制命令密钥的 `ssh.exe`,stdio 桥接):

- **安装:** 带重启的 procd 服务、`S95`/`K10` 链接、位于 `0700` 目录中的 `0600` 套接字、仅 `127.0.0.1` 上的 HTTP、
  dropbear `authorized_keys` 中的强制命令行,`@readonly` + 限时 `@operator` 策略无需重启即被加载。
- **针对真实数据的读取:** 全部 23 个工具连同其模式和服务器说明被列出;`system_status`、`network_clients`、
  `wg_list_clients`(重名警告)、`service_list`、`pkg_query upgradable`、`pkg_config_diff`(11 个真实的 `.apk-new`
  文件,设置级差异)、`firewall_show check`、从 `br-WAN` 发出的 `net_diag ping`、`logread` 过滤、`uci_get`、
  `sysupgrade list`、`ubus_call`。
- **带回滚的写入**(在一个临时 UCI 配置上):包含 `set_list` 的 `uci_apply` -> 到期自动回滚,文件逐字节恢复且
  `pending.json` 被移除;已有一个待定时,第二次应用被拒绝;`uci_confirm`;按需 `uci_rollback`;`dry_run`。
- **WireGuard:** 带预共享密钥的 `wg_new_client`(下一个空闲地址、对端提交到 UCI 并热添加到内核、CGNAT 端点警告),
  列出,然后 `wg_remove_client` -- `/etc/config/network` 逐字节恢复,内核中的对端消失。1.3.0 的密钥交接(第二次运行,
  在一个为测试通过 `uci_apply` 启用、之后又被禁用的接口上,其配置修订号与之前相同):结果中不含私钥;配置是
  `/var/run` 下 `0700` 目录中仅 root 可读的 `0600` 文件;在运维人员终端中运行的 `openwrt-mcp wg-show` 打印了配置和二维码,
  并删除了该文件。1.4.0 的回读为 `uci_apply`、`wg_new_client` 和 `wg_remove_client` 打印了 `Verified: ...`,
  每次应用时都启用了回滚,随后予以确认。
- **崩溃恢复:** 在有未确认应用时用 `SIGKILL` 杀掉守护进程 -> procd 在 6 秒后重新拉起它,它在启动时回滚了该变更。
- **拒绝:** `exec`、`ubus_call session.list`、超出范围的 `uci_apply`(各自指出所需的授权命令行)、对策略配置的任何
  `uci_apply`、未经认证的 HTTP(已审计)。
- **输出安全(1.1.0),同一块板子:** `uci_get wireless` 和 `ubus_call network.wireless status` 对每个 Wi-Fi `key`
  返回 `<redacted>`,而 `ssid`、`encryption` 以及 `wpa_disable_eapol_key_retries` 这类相似名称保持不变(JSON 回复中的数字、
  布尔值和数组也一样)。设置密钥的 `uci_apply` dry run 显示的是被屏蔽的值,且不留下任何暂存内容。`network_clients` 和
  `logread` 以不可信文本标记开头。来自没有密钥的客户端的五个错误 `mfa_unlock` 验证码使其被锁定 5 分钟(第六个被拒绝并给出重试时间);
  审计日志记录了四条 `ERROR` 然后是 `DENIED`,提交的验证码一个都没有出现在其中。通过 `ubus call log write` 写入的一行 syslog,
  含有 CSI 和 OSC 序列、颜色码、BEL 和双向覆盖字符(这些在路由器自己的日志中都存在),经 `logread` 返回时只剩文本和制表符,
  过长的行在 1024 字节处被截断并附有 `[+N bytes]` 说明。`uci changes` 的语法(`+=`、`-=`、`'\''`、表示删除的裸 `-path`)
  是从路由器上抓取的,并成为测试夹具。
- **可靠的变更(1.2.0),同一块板子,经守护进程的 stdio 桥接驱动:** `fw4 check` 能看到 uci 中暂存的变更(对无效值它以 0 退出并打印
  `[!]` 行,校验读取的正是这些):对一个伪造的区域值做 dry run 会把它报告为新增问题,真正的应用被拒绝,且不留下暂存或快照。
  过期的 `expected_revisions` 为 `CONFLICT`;当前的则通过;针对该调用并不修改的配置给出的修订号会被拒绝。对 LAN 接口的 dry run 会指明管理路径,
  不带探测的真正应用被拒绝且没有暂存任何内容。对 `system.ntp.server` 中已有元素执行 `add_list` 会被跳过。在 `luci` 中的一个临时选项上:
  带 `ping` 和 `resolve` 探测的应用在重载后报告两者均 OK 并启用回滚;确认它会留下一条历史记录(`0700` 目录,`0600` 文件);
  `history=diff` 显示该变更增加了什么;`restore` 把文件逐字节连同其模式一起恢复,运行它的探测,并留下它自己的一条记录;
  探测失败的应用报告 `PROBE FAILED`,回滚仍保持启用,`uci_rollback` 把文件逐字节恢复。对一个守护进程执行 `service_control restart`
  会报告其状态的 "Settled after"。
- **采用与凭据(1.3.0),同一块板子:** 构建用 `install.sh` 安装,`openwrt-mcp version` 报告 1.3.0。从 Windows 电脑用其真实的 OpenSSH 运行的
  `connect doctor` 通过了全部七个步骤并列出 23 个工具;使用路由器不认识的密钥时它停在 *key accepted*,端口关闭时停在 *ssh reachable*,
  各自附有修复建议。针对 Cursor 的 `connect --write` 用电脑自带的 `ssh-keygen` 生成了密钥,把条目合并进一个 JSON 文件,
  第二次运行报告条目没有变化。`diag` 打印了版本、开发板、策略形态和审计行,SSH 客户端的地址显示为 `ip-1`,且没有审计参数;
  `--detail` 增加了被屏蔽的摘要。`sysupgrade backup` 创建的归档为 `-rw-------`(4.3 MB,所以 `sysupgrade -b` 会保留已存在文件的模式),
  第二次备份删除了第一次的。守护进程在重启后约占 10 MB 常驻内存。
- **会话清理(1.3.0),同一块板子:** 守护进程重启后,在新构建上启动的 stdio 桥接立即退出,客户端的下一次调用无错误地打开了新会话;
  仍运行旧构建的桥接会保留到其客户端的下一次请求。`status` 把 45 个过期授权折叠成一行;`prune` 将其移除,写入一条 `prune` 审计条目,
  守护进程重载后只剩现行授权。
- **诊断(1.4.0),同一块板子,使用 `@readonly` 客户端:** `system_status mode=doctor` 列出一条低级别发现,三个等待合并的 `.apk-new` 文件,
  这是真实的,没有任何不实内容。`mode=audit` 列出了允许 WireGuard 端口从 WAN 进入的防火墙规则(属实,且是有意为之)和 `uhttpd` 监听所有地址(属实),
  每条都附有 wiki 链接和下一步调用。`logread mode=summary` 把略多于一千行折叠成约五十条不同的消息。一个保存后在周期性任务运行之后做比较的基线,
  每次都把一行监控信息算作新的,因为它的运行时间字段变了;这就是持续时间变成 `<dur>` 的原因,修复后同样的往返报告没有任何新内容。
  `net_diag wifi_survey` 给出每个无线电所在信道的 busy、rx、tx 和噪声数值,与当天早些时候读取的 `iwinfo survey` 原始输出相差一个百分点以内;
  `traffic` 对接口采样三秒并按字节对 conntrack 来源排序;`usage` 列出了 nlbwmon 在当前月度周期内的设备;
  `network_clients` 显示了 `AIR` 列,每个无线电上的份额加起来约为 100%。
- **触达与韧性(1.5.0),同一块板子,25.12.5:** 按安装程序的步骤部署了该构建。`service_list detail=` 读取了 tailscale、AdGuard Home 和 podkop。
  dry run 警告和 WireGuard 写入工具在为测试创建的临时接口上运行(不是 LAN,也不是真实隧道),之后已删除:对端通过启用回滚的路径被添加和删除,
  回滚把对端放回了原处。`openwrt-mcp call` 和带 `--toolset diag --read-only` 的会话都从电脑经 SSH 运行成功。硬件运行发现:删除一个不是最后一个的对端后,
  出现了错误的 `NOT_APPLIED`(UCI 的匿名配置段 ID 按位置编号,回读看错了配置段);该问题已修复,测试中的模拟器现在也像 UCI 一样重新编号。

单元测试和端到端测试(真实的 MCP 客户端,经内存传输和经桥接握手)在任何操作系统上针对模拟路由器运行:apply/confirm/rollback/超时、
**窗口期内重启**、dry run、对他人暂存编辑的拒绝、列表操作、针对抓取的 25.12 配置的 WireGuard 添加/列出/删除、客户端加入、日志过滤、apk 模拟、
带回滚的 `.apk-new` 解析、预设内容、范围通配符语义。

**尚未在硬件上验证**(仅由模拟路由器测试覆盖):带 `commit` 的 `pkg_change`、LuCI 页面的渲染、真实 `/www` 路径或符号链接上的 Web 根目录保护、
真正的断电重启(恢复路径与 `SIGKILL` 测试所走的相同),以及真实 sysupgrade 过程中的 keep.d。对 1.2.0 还包括:带探测的管理路径变更(仅运行了
不带探测时的拒绝)、让回滚计时器而非 `uci_rollback` 处理探测失败,以及 sysupgrade 之后的历史。对 1.3.0 还包括:`connect --write` 针对真实的
Claude Code、Codex、Claude Desktop、Gemini 或 VS Code(仅测试了文件合并和命令行)、macOS 上的一切,以及路由器上安装程序的下载路径
(发布工作流已运行并发布了 1.2.0 和 1.3.0,但 `install-router.sh` 尚未针对它们运行过)。对 1.4.0 还包括:写入后的回读在硬件上只对
`uci_apply`、`wg_new_client` 和 `wg_remove_client` 运行过;`service_control` 和 `pkg_change` 是针对模拟路由器运行的,而日志摘要只见过一台路由器的日志。
WireGuard 密钥交接的文件权限由 CI 在 Linux 上断言。对 1.5.0 还包括:与 `opkg`(24.10)和 `fw3` 有关的一切,均由源码和软件包文档推导而来,从未在真实的 24.10 或 21.02 路由器上运行过(CI 的 `real-target` 任务在 24.10 和 25.12 容器中运行软件包和 uci 工具,那里没有 netifd、无线和防火墙);以及 `reveal` 范围,它只针对策略匹配器做过测试。欢迎提供其他开发板的报告。

---

## 致谢

- **[GlassOnTin/openwrt-mcp](https://github.com/GlassOnTin/openwrt-mcp)**(Ian Williams,MIT)-- 本项目的基础。从中保留的有:procd 下
  路由器上的静态 Go 守护进程、带范围通配符、速率限制和过期时间的长期默认拒绝策略、以摘要形式存储的 bearer 令牌、TOTP 窗口、
  带机密屏蔽的 JSONL 审计日志、仅回环的 HTTP、ubus 回复裁剪,以及 `uci_apply` 的"确认否则回滚"思路。上游项目的 git 历史保留在本仓库中。
- **[jsebgiraldo/openwrt_ssh_mcp](https://github.com/jsebgiraldo/openwrt_ssh_mcp)** -- 一个运行在路由器之外的 Python 服务器(每次调用走 SSH,
  正则命令白名单),为获取思路而审阅。其中四项被采纳并在此重新实现:
  1. 刷写之前验证固件镜像(`sysupgrade -T` -> `sysupgrade` 的 `test` 操作);
  2. 固件和开发板信息(`system_status` 的一部分);
  3. 软件包管理(为 `apk` 重写:`pkg_query`、`pkg_change`);
  4. ping / traceroute / nslookup(`net_diag`)。

  未采纳的有:OpenThread 边界路由器工具(与硬件相关)、`opkg` 和 `iptables` 命令(25.12 中已不存在)、刷写固件工具(不可逆,
  且无法远程恢复),以及对 shell 字符串的正则白名单(改用 argv + 策略范围)。

## 贡献与安全

欢迎提交缺陷报告和 pull request -- 见 [CONTRIBUTING.md](CONTRIBUTING.md)。请按 [SECURITY.md](SECURITY.md) 所述私下报告漏洞,
不要在公开 issue 中报告。计划中的工作见 [ROADMAP.md](ROADMAP.md)。

**报告缺陷:** 在路由器上运行 `openwrt-mcp diag`,并把输出粘贴到 issue 中。它会打印版本、开发板、守护进程状态、策略的形态和最后 20 行审计
(`--audit N`),其中每个 IPv4、IPv6 和 MAC 地址、主机名、DHCP 名称、SSID、域名和 WireGuard 对端名称都被替换为占位符(`ip-1`、`mac-1`、
`host-1`、`ssid-1`),同一个值对应的占位符始终相同。审计参数从不打印,条目的范围、摘要和错误文本仅在加 `--detail` 时打印,并以同样方式屏蔽。
名称是与路由器自己所说的名称相匹配的,所以粘贴前请通读一遍:只出现在自由文本中而不在路由器配置里的名称不会被识别。

## 许可证

MIT -- 见 [LICENSE](LICENSE)。Copyright (c) 2026 Ian Williams(上游)和 Stanislav Chupin(OpenWrt 25.12 移植版)。
