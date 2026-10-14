# xssi

XSSI 是 XCOS、XCZS、XOCS、XSCS、XSOS、XSZS 的独立安装和维护仓库，包含系统安装脚本、明确的离线产品辅助程序，以及协调 XSSC 的自动升级脚本。没有常驻服务，没有卸载命令。

server 仅以 `--root ROOT` 运行，不调用或探测安装升级工具，不识别反向代理。所有内部程序、配置、管理员凭证、密钥和日志默认位于一个 ROOT；文件、视频和实例业务数据可以明确外置，systemd 文件位于系统目录。

## 安装

运行环境为 Linux x86_64 GNU、systemd、Python 3.12 或更新版本及OpenSSL（仅 XCOS TLS 配置验证需要）。脚本使用独立的 Python 模块目录并禁止字节码缓存，维护操作不会向已校验程序目录写入未声明的缓存文件。

先验证发行包SHA256和包内完整清单、脚本与辅助程序，再执行包内脚本。密码通过终端隐藏输入或标准输入读取，不能放进命令参数或配置。

独立工具发行包为 `xssi-VERSION-linux-x86_64.tar.gz`，附带同名 `.sha256`。在下载目录中先执行 `sha256sum --check xssi-VERSION-linux-x86_64.tar.gz.sha256`，解包后执行 `python3 libexec/release_manifest.py verify /absolute/xssi-VERSION-linux-x86_64` 核对完整工具载荷。安装命令的 `--package` 指向对应 Server 的已校验发行包；工具自身的完整清单与业务包清单分别核验。

```sh
sudo ./install.sh --package /absolute/verified-package \
  --root /opt/isarmg/xocs --config /absolute/config.json \
  --username admin
sudo systemctl enable --now xocs.service
```

脚本负责服务账号、目录、权限、包校验和 systemd。已校验 setup 负责配置校验、首次初始化和真实数据检查。安装不自动启动服务。错误输入可以修正重试，已经初始化的数据不被重新初始化。

固定服务账号使用同名的非 root 主组，不允许额外 NSS 补充组，保证服务 UID 权限探测与 systemd 实际运行一致。安装、维护和升级都检查现有账号，不自动删除已有组成员关系；共享目录访问应通过服务 UID ACL 或主组授权。安装保留既有权限；XSSC 失败恢复精确保留 UID/GID、权限、修改时间和 Linux POSIX access/default ACL，包括原本无 ACL 的条目，不保证 `user.*` 或 SELinux 扩展属性。

## 维护和升级

```sh
sudo /opt/isarmg/xocs/maintenance.sh --root /opt/isarmg/xocs check
sudo /opt/isarmg/xocs/maintenance.sh --root /opt/isarmg/xocs admin-reset --username admin
sudo /opt/isarmg/xocs/upgrade.sh --root /opt/isarmg/xocs --version N.N.N
```

只读 `check` 要求写入服务已经停止；检查前后核对主进程、控制进程、待执行作业及 cgroup 后代，不改变服务或启动设置。辅助程序同时持有已声明的真实运行锁，并在私有副本中检查 SQLite。密码重置与媒体配置重建由管理员工具先持久记录操作，再为全部 writer 设置系统管理器启动条件并停止服务。密码重置从标准输入读取，成功后检查当前结构并移除本操作的启动限制，服务仍保持停止。中断时限制继续保持，可用 `--operation-id UUID` 按原事务身份重试。

升级先下载精确稳定版本并核对 HTTPS、大小、SHA256、哈希、权限、产品和平台。实际加载的 systemd 单元模板与路径也在停服前检查，单元合同变化会拒绝升级。XSSC 在 `ROOT/maintenance/upgrades/UUID/upgrade.json` 中记录全部 writer 的原状态和启动限制，完成系统管理器的实际加载验证后停止它们，再备份、执行源与目标当前结构只读检查、替换清单载荷、受控恢复启动、确认实际程序摘要与业务就绪。

失败与恢复由持久记录和实际状态判断。可能出现新业务写入后，恢复需要明确的数据损失授权。当前结构不匹配直接拒绝升级，不提供迁移、旧目录、旧 CLI 或旧版本兼容。服务程序不读取维护标记，也不参加工具锁交接。

安装、维护、升级、恢复、只读状态检查和材料回收都协调 `ROOT/maintenance/tool.lock`，专用 FD 在脚本、XSSC 和 root 辅助程序之间继承同一已持有锁。生成文件通过显式服务 UID/GID 设置所有者；不向服务用户暴露另一个可执行暂存区。

暂存清理只认本操作持久记录的父目录和目录设备/inode。创建目录后、保存 inode 前的极窄中断窗口会留下需管理员检查的未知目录；工具保留操作意图并停止，不按路径名称自动删除。

## 构建与验证

辅助程序是独立工程，仅使用产品中立的 XCSc 文件、SQLite 和密码原语。它不依赖 XCSS、整个 Server 或其业务依赖图。产品从实际配置定义、DDL、凭据策略及业务校验定义生成 `share/contracts/install.json` 与配套资产，完整SHA256清单绑定这些材料；辅助程序消费同一发行的材料，实现首次初始化、当前结构检查、密码重置及媒体配置重建。

```sh
python3 -m unittest discover -s tests -v
cargo fmt --all -- --check
cargo test --locked --all-targets
```

`scripts/build-package.sh PRODUCT SOURCE_ROOT STAGE` 将 setup、脚本和 systemd 模板放入新格式产品包，并生成唯一的 PackageManifest v1（`share/package.json`）与其`share/package.sha256`（64位小写摘要和换行）。资产名统一为 `{product}-{version}-linux-x86_64.tar.gz`。逐个验证载荷的大小、SHA256、权限、路径及完整库存。

正式构建使用 Node.js 26.7.0、cargo-cyclonedx 0.5.9 和 cargo-audit 0.22.2，依据锁定的真实 Cargo 依赖图生成 server 与 setup 各自的 CycloneDX 1.5 清单及第三方许可证原文，并对两份锁文件执行漏洞和撤回依赖检查。这些资产均包含在SHA256清单中；本地源码标识绑定完整 Git 提交，清单不发布临时构建路径。

本仓库自身的 Release 由 `scripts/stage-release.py` 与 `scripts/finalize-release.py` 生成。构建要求源码、版本和正式标签指向同一清洁提交；实际工具依赖图、SQLite 原始来源与许可、最终 ELF 运行前提及全部文件纳入物料清单和 SHA256 清单。发布前重新解包校验完整清单及实际辅助程序版本，同名已有资产拒绝覆盖。候选源码或测试夹具的通过记录不代表独立发行包已经发布。

完成升级材料的回收由 `xssc collect-upgrades --root ROOT --minimum-age-seconds N --keep-completed N` 先输出具体计划。明确加 `--execute` 才实施；未知、未完成、被引用或仍承担启动控制义务的对象保留。中断回收可通过 `--resume-collection UUID` 按原 inode 记录续行。

统一规范以本工作区根目录的《规范.md》为唯一来源，本仓库维护工具操作及实现说明。XSSC 负责升级事务，卸载完全由用户自行处理。

初次初始化要求安装器持久授权的同一 `--operation-id UUID`。辅助程序在 `ROOT/maintenance/install/UUID/created.json` 逐项记录新建文件、目录的父目录及 inode，写内容前持久保存；重试仅重建同一记录下的未完成初始化文件，保持实际运行锁 inode 和已有业务目录权限。记录前中断留下的未知对象保留，不能用名字补认。

下载、已完成离线维护及初始化辅助记录的回收使用 `maintenance.sh --root ROOT collect --minimum-age-seconds N --keep-completed N`，默认只给计划，明确加`--execute`才删除。引用它们的升级记录必须先通过 XSSC 的独立回收处理。完成清理的材料记录按同一明确策略在后续回收中删除；未完成、被引用、改变 inode/内容和未知对象保留。两类回收均不删除业务数据、应用日志或运行锁。
