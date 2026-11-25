# 共享盘 SSH：只读 .ssh 环境部署助手

版本：0.2.0。适用场景：个人主机不能直接通过网络 SSH 到服务器，但双方可以读写同一个共享文件系统；服务器上的 `~/.ssh` 是只读挂载。

脚本在服务器本地创建独立的 SSH 配置、公钥文件和主机密钥，启动仅监听环回地址的专用 sshd，再启动共享盘桥接。个人主机使用独立 SSH 配置和 `dssh` 命令。身份验证、加密、远程命令和终端功能仍由 OpenSSH 完成。

## 1. 文件与运行条件

| 文件 | 用途 |
| --- | --- |
| `deploy.sh` | 统一入口，调用同目录下的 Python 部署助手 |
| `deploy.py` | 两端配置、服务器启动停止和状态管理 |
| `sharedfs_ssh.py` | 共享盘双向 SSH 字节通道 |
| `benchmark.py` | 实测建连时间与持续连接中的请求往返时间 |
| `tests/`、`TEST_RESULTS.md` | 测试与本次验证范围 |

服务器需要 Linux、Python 3.9+、已安装的 OpenSSH 服务端和 ssh-keygen，以及运行独立 sshd 的权限。本部署流程针对 root 管理环境；不会安装系统包、更改账号锁定状态或修改既有系统 sshd 配置。个人主机支持 macOS/Linux，需要 Python 3.9+ 和 OpenSSH 客户端。

共享目录必须已挂载且双方可读写，支持普通文件及同目录原子重命名。异步同步盘、对象存储挂载不能仅凭“能看到目录”就当作可靠共享文件系统。服务器至少需要一次已有控制台或其他合法执行入口来运行部署脚本。

## 2. 两端快速部署

以下使用环境变量 `SHARED_ROOT` 表示共享盘的挂载目录。两端的挂载路径可以不同，但必须指向同一个后端目录。第一台服务器节点名为 `gpu01`，登录账号为 `root`。

分别在两端设置各自的实际挂载路径，例如：

```bash
# 个人主机
export SHARED_ROOT="/Volumes/shared"

# 服务器（在服务器终端执行，替换成实际挂载路径）
export SHARED_ROOT="/mnt/shared"
```

以上设置只对当前 shell 及其子进程有效。要在之后打开的 Bash 终端中自动生效，请分别在两端将对应的 `export SHARED_ROOT="实际挂载路径"` 行写入各自的 `~/.bashrc`，然后执行 `source ~/.bashrc`；使用 Zsh 时写入 `~/.zshrc` 并执行 `source ~/.zshrc`。例如，服务器端可执行：

```bash
printf '%s\n' 'export SHARED_ROOT="/mnt/shared"' >> ~/.bashrc
source ~/.bashrc
```

请先把示例路径换成实际路径；个人主机也需在自己的配置文件中设置其挂载路径。若登录 shell 没有加载 `~/.bashrc`，请在它读取的配置文件（例如 `~/.bash_profile`）中加载 `~/.bashrc`，或将设置写入该文件。修改后可运行 `printf '%s\n' "$SHARED_ROOT"` 检查。以下命令由 shell 展开变量，因此路径即使包含空格也可以使用；每个运行部署命令的终端都需要先设置该变量。

### 2.1 准备目录和公钥

先确认共享盘已经挂载，在有权限的位置创建 `sshbus` 专用目录，并检查双方能互相看到测试文件。默认文件权限要求双方有一致的文件系统身份映射；组共享见第 8 节。

在个人主机把现有登录公钥放到共享盘：

```bash
cp ~/.ssh/id_ed25519.pub "$SHARED_ROOT/my_laptop.pub"
```

仅复制 `.pub` 公钥，私钥保留在个人主机。若使用其他密钥，替换公钥路径和后面的 `--identity-file`。

### 2.2 服务器端

解压并进入 `sharedfs_ssh` 目录。已有 root 终端可直接执行：

```bash
bash deploy.sh server \
  --share-root "$SHARED_ROOT/sshbus" \
  --node gpu01 \
  --public-key "$SHARED_ROOT/my_laptop.pub" \
  --login-user root
```

默认状态目录为 `/var/lib/sharedfs-ssh/gpu01`，专用 sshd 监听 `127.0.0.1:2222`。服务器只读 `~/.ssh` 不参与部署。若默认目录也只读，可用 `--state-dir` 选择受保护的本地可写目录；不要使用共享盘或公共临时目录。

可在相同命令末尾添加 `--dry-run` 先看计划。dry-run 不写文件、不生成密钥、不启动/停止服务，也不要求 root；它不能替代实际安装和运行检查。

### 2.3 个人主机端

同样解压并进入 `sharedfs_ssh` 目录：

```bash
bash deploy.sh client \
  --share-root "$SHARED_ROOT/sshbus" \
  --node gpu01 \
  --login-user root \
  --identity-file ~/.ssh/id_ed25519
```

默认生成独立配置 `~/.config/sharedfs-ssh/ssh_config` 和连接入口 `~/.local/bin/dssh`，不会改写已有 `~/.ssh/config`。直接测试：

```bash
~/.local/bin/dssh gpu01 'hostname; whoami; pwd'
~/.local/bin/dssh gpu01 'nvidia-smi'
~/.local/bin/dssh gpu01
```

若 `~/.local/bin` 已在 PATH，可直接使用 `dssh`。也可用原生 SSH：

```bash
ssh -F ~/.config/sharedfs-ssh/ssh_config gpu01 'hostname'
```

如果希望直接使用 `ssh gpu01`，在客户端部署命令中添加 `--use-default-ssh-config`：

```bash
bash deploy.sh client \
  --share-root "$SHARED_ROOT/sshbus" \
  --node gpu01 \
  --login-user root \
  --identity-file ~/.ssh/id_ed25519 \
  --use-default-ssh-config

ssh gpu01 'hostname'
```

该选项会在 `~/.ssh/config` 开头创建或更新带标记的托管区块，保留区块外的原有内容；托管区块内包含此客户端配置目录中的所有节点。放在开头使这些节点的选项优先于原有的 `Host *` 设置。`dssh` 也会使用默认 SSH 配置。私有的节点资料、桥接脚本和 `known_hosts` 仍保存在 `--config-dir` 中；此模式不生成独立的 `ssh_config`。更新这些节点时请继续带上此选项，否则将更新独立配置而不会同步默认配置。已有同名 Host 的其他设置仍可能影响未在托管区块中指定的选项。

添加第二个节点时，沿用同一个 `--config-dir`，把 `--node` 改成新节点名即可。如果脚本提示无法确定托管区块的边界，请按报错中的行号核对 `~/.ssh/config` 里的 `# BEGIN sharedfs-ssh managed hosts` 和 `# END sharedfs-ssh managed hosts` 是否成对，再加 `--dry-run` 预览合并结果。

### 2.4 核对服务器身份

服务器部署会输出主机公钥指纹。首次连接时，通过服务器控制台核对指纹后接受，后续沿用该身份。重复部署复用已有主机密钥，不应因再次安装而改变身份。

若希望预先固定主机密钥，个人主机部署命令支持同时指定 `--host-public-key PATH` 与 `--host-fingerprint SHA256:...`。预期指纹必须从可信服务器控制台取得，不能只信任共享盘中的同一份公钥文件。这是服务器的主机公钥，不是个人主机登录公钥。

### 2.5 Conda 等 Python 环境

服务器安装会检查将来常驻服务使用的解释器和 sshd 路径。如果当前 Conda Python 位于其他用户可写目录、共享盘或不可信的路径中，会拒绝安装。可选择系统中可信且满足版本要求的 Python，直接运行 `/usr/bin/python3 deploy.py server ...` 并带上相同参数。不要为了通过检查递归修改无关环境的权限；`/usr/bin/python3` 仅是常见位置，应以实际安装为准。

## 3. 多台服务器

第二台服务器重复相同的 server 命令，把 `--node` 改为 `gpu02`。个人主机也执行一次 client 命令加入 `gpu02`。已有其他节点会保留：

```bash
~/.local/bin/dssh gpu01 'hostname'
~/.local/bin/dssh gpu02 'hostname'
```

不同机器可以都使用各自本机的 2222 端口，但不能使用同一个共享节点名。如果在同一台机器运行多个节点实例，必须分配不同的本机端口和状态目录。

## 4. 设置项

以下是部署助手默认值；直接调用底层桥接时部分默认值不同，以其 --help 为准。时间参数单位均为秒。

| 参数 | 默认值 | 作用 |
| --- | --- | --- |
| `--poll` | `0.1` | 接收数据/等待确认的检查间隔；最小接受 `0.02` |
| `--scan-interval` | `0.25` | 服务器扫描新连接的间隔，不决定已建立连接的每次输入延迟 |
| `--control-interval` | `1` | 检查对端心跳、错误与服务重启状态的间隔 |
| `--heartbeat` | `2` | 写入活性标记的间隔 |
| `--peer-timeout` | `120` | 心跳不再变化多久后断开；须大于心跳及控制间隔较大值的两倍 |
| `--connect-timeout` | `120` | 共享盘通道建立等待时间 |
| `--chunk-size` | `65536` | 单分块最大有效载荷字节数；必须两端一致 |
| `--window` | `32` | 每个发送方向最多未确认分块数 |
| `--max-sessions` | `8` | 每台服务器允许的同时活动连接数 |
| `--ssh-port` | `2222` | 专用 sshd 的本机端口 |
| `--state-dir` | `/var/lib/sharedfs-ssh/节点名` | 服务器本地配置、密钥和运行状态目录 |
| `--service-manager` | `auto` | 优先可用的系统 systemd，否则使用 supervisor |
| `--pam` | `auto` | 尝试沿用当前 SSH/PAM 策略；不能判断时明确报错，不自动解锁账号 |
| `--group-share` | 关闭 | 使用组共享文件权限，需要先配置可信共享组/ACL |
| `--share-group` | 未指定 | 设置服务器桥接进程使用的主组，并开启组共享；不代替目录组/ACL 配置 |
| `--dry-run` | 关闭 | 显示计划，不部署 |

个人主机另有 `--config-dir`、`--bin-dir`、`--identity-file`、`--host-public-key`、`--host-fingerprint` 和 `--use-default-ssh-config`。精确适用参数：

```bash
bash deploy.sh server --help
bash deploy.sh client --help
```

## 5. 最短轮询间隔怎么选

不存在脱离环境仍能保证“性能没有损失”的通用最短值。更频繁轮询通常减少等待，也增加文件查询和 CPU 唤醒。认证和加密由 SSH 处理，不通过关闭安全检查提速。

| 数据间隔 | 建议 |
| --- | --- |
| 100 ms | 默认起点，先确认功能和负载 |
| 50 ms | 少量节点、响应及时的共享盘，作为第一档低延迟候选实测 |
| 20 ms | 当前允许的最小值；仅在负载与尾延迟可接受时使用，不代表所有环境都合适 |
| 小于 20 ms | 本版本拒绝，避免近乎忙等；这是工程下限，不是文件系统定律 |

0.2 版本拆开数据轮询、新连接扫描和控制检查，并减少不必要的 ACK 读取。一个空闲但已连接的会话，在控制间隔 1 秒时，两端合计文件读取尝试数可粗略估算为 `2 / poll + 5`：100 ms 约 25 次/秒，50 ms 约 45 次/秒，20 ms 约 105 次/秒。另有心跳写入、节点扫描和其他文件操作。这个数字是程序层面的估算，不是远程 RPC 或磁盘 IOPS；缓存会改变实际负载，并发连接会叠加。

没有自动闲时退避，因此空闲后第一次输入不会额外等待很长的退避周期，代价是空闲连接仍定时检查。完成会话 ID 会缓存以减少重复元数据检查，目录列举仍受历史会话数量影响。

NFS/SMB 缓存可能比 poll 更慢。如果 100 ms 改到 50 ms 没改善，应先看挂载和缓存；脚本不会自动修改挂载选项或只读策略。

## 6. 在你的共享盘上测速

在已部署客户端的机器上运行测速，先正常连接一次并核验主机身份。若私钥有口令，需要先让 ssh-agent 可以使用它；测速使用 BatchMode，不交互询问口令。

如果客户端使用 `--use-default-ssh-config` 部署，省略 `--config`，让 SSH 使用默认配置：

```bash
python3 benchmark.py --host gpu01 --samples 20 --label poll-100ms
```

如果使用默认生成的独立配置，指定实际配置文件路径：

```bash
python3 benchmark.py \
  --config ~/.config/sharedfs-ssh/ssh_config \
  --host gpu01 \
  --samples 20 \
  --label poll-100ms
```

若部署时指定过 `--config-dir`，将上面的路径换成该目录下的 `ssh_config`。例如 `~/.config/ssh_config` 并非默认生成路径。

结果分别报告建连时间，以及持续连接内小请求往返时间的中位数、P95 估计和最大值。`--label` 只是一段备注，不会修改参数。

然后在服务器重跑原 server 命令并加 `--poll 0.05`，个人主机重跑原 client 命令并加 `--poll 0.05`，再测一次。服务器重新部署可能中断现有连接，应从现有控制台执行。调优时建议两端一起改；并非协议要求 poll 必须相同。

同时观察两端 CPU、已有存储监控和 P95 波动。若收益小而负载增加明显，恢复 `--poll 0.1`。测速本身不会自动测量存储负载或保证安全，也不包含大文件吞吐测试。

远程测速使用非交互环境中的 `python3`。如果服务器仅在特定 Conda 环境中提供 Python，请先确认普通 SSH 命令能够找到它。

## 7. 启动模式和维护

- `auto`：首次安装自动选择 systemd 或 supervisor；重复安装沿用已选管理器。
- `systemd`：使用专用系统服务。
- `supervisor`：后台监督 sshd 与桥接子进程，提供日志和生命周期管理。
- `foreground`：在当前终端运行，便于排查。
- `none`：只生成并验证配置，不启动。

supervisor 不等同于容器重启后自动启动。终端断开通常不会结束独立后台会话，但平台清理进程、停止或重建容器仍会结束它。需要把 start 命令加入平台正式启动入口，并持久保存本地状态和主机密钥。

```bash
bash deploy.sh status --node gpu01
bash deploy.sh stop --node gpu01
bash deploy.sh start --node gpu01
```

自定义安装路径时，维护命令也传相同的 `--state-dir`。部署助手只管理自己的服务和可核实身份的进程；不会执行 killall/pkill。不要同时运行同名节点的手工旧实例和管理器实例。

supervisor 启动成功只表示监督进程已启动，不能证明两个子服务和共享盘已完全就绪。以 `dssh gpu01 hostname` 作为实际验收。排错查看本地状态目录中的 `sshd.log`、`bridge.log` 和 `supervisor.log`；systemd 模式查看对应专用服务日志。

start 使用已保存参数，不会将它们改回默认值。重新运行 server 或 client 安装命令时，要显式带上需要保留的非默认参数；省略的参数按该次命令默认值处理。

### 修改服务器节点设置

在服务器的 root 控制台运行 `edit`，只需传入要修改的设置；其他设置从该节点已保存的部署中恢复：

```bash
bash deploy.sh edit --node gpu01 --poll 0.05 --max-sessions 12
```

该命令会验证并更新配置，然后通过原有的 systemd 或 supervisor 管理器重启服务，已有连接可能中断。可先添加 `--dry-run` 查看修改后的配置，确认后去掉它执行。自定义状态目录时使用 `--state-dir`，查看全部可修改选项请运行 `bash deploy.sh edit --help`。`edit` 不修改登录用户或授权公钥；`foreground` 和 `none` 模式没有可由此命令重启的服务，需按原部署方式重新配置。客户端没有常驻服务，客户端参数仍通过重新执行 `client` 命令更新；例如修改轮询间隔时，建议两端使用相应设置。

## 8. 权限与使用边界

1. 服务器只读 .ssh 保持原状。授权公钥使用独立路径，主机私钥保留在本地。状态目录及其祖先不得被不可信用户写入，不允许通过符号链接指向其他位置。
   自动路径隔离检查以传入的 --share-root 为边界；不能全面识别其他共享挂载或同一后端的所有别名。你仍需确保 --state-dir、解释器和 --identity-file 实际位于可信本地存储。
2. 默认只允许指定账号公钥登录，不修改账号锁定状态，不启用密码登录。PAM 和账号策略仍可能拒绝登录，需要查看专用 sshd 日志。
3. NFS 的数字 UID/GID、SMB 挂载凭据和 ACL 必须正确映射；相同用户名不代表相同权限。默认 umask 0077。组共享时，先配置专用可信组和根目录 setgid/ACL，服务器使用 --share-group 或正确组环境，个人主机使用 --group-share。选项不会自动配置跨机器权限，也不会递归放宽已有文件。
4. 共享通信目录须受信任。SSH 能保护会话内容，但不能阻止其他共享目录写入者删除文件、伪造请求或耗尽资源。sshd 看到的网络来源是 127.0.0.1，原有基于源 IP 的规则需核对。
5. 连接断开不会重放命令，也不保证远程任务一定退出。长任务可用 `dssh -t gpu01 'tmux new -As work'` 或已有调度系统。
6. 已确认分块会删除，会话元数据可能保留。没有自动垃圾回收；停止对应服务且确认没有活动客户端后，再清理该节点的旧会话目录。
7. 挂载 I/O 卡在内核时，Python 超时不能强制取消它。当前没有真实 NFS/SMB 故障注入或生产级高可用保证。

## 9. 常见问题

**Read-only file system：**查看具体路径。如果本地状态目录只读，换一个可写的本地 --state-dir；不需要修改服务器 .ssh，不要直接重挂整个根文件系统。

**Permission denied (publickey)：**确认个人主机 identity 对应已安装公钥，查看独立 sshd 的账号/PAM 日志。不要将登录私钥复制到服务器。

**Missing privilege separation directory：**根据当前 sshd 报错准备对应运行目录，或由管理员完善 OpenSSH 安装。不能通过关闭安全检查解决。

**主机密钥变化：**确认是否换机或丢失了本地状态，核验新指纹。正常重复安装复用原密钥。

**dssh 找不到：**先用完整路径 ~/.local/bin/dssh，或把实际 --bin-dir 加入 PATH。

## 10. 验证与依据

本次环境可运行独立普通用户 sshd 与真实 SSH 集成，但不能执行 root 系统安装、systemd 生命周期或真实 NFS/SMB 挂载。准确测试结果和未验证事项见 TEST_RESULTS.md。

- ProxyCommand、主机身份校验：<https://man.openbsd.org/ssh_config.5>
- 独立 sshd 配置和检查：<https://man.openbsd.org/sshd.8>
- AuthorizedKeysFile、StrictModes、PAM：<https://manpages.debian.org/bookworm/openssh-server/sshd_config.5.en.html>
- NFS 缓存与 close-to-open：<https://man7.org/linux/man-pages/man5/nfs.5.html>
- inotify 的网络文件系统限制：<https://man7.org/linux/man-pages/man7/inotify.7.html>
