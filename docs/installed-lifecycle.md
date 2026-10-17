# 已安装 Server 的生命周期验证

此检查使用真实安装器、systemd 和产品 HTTP API 验证已构建候选包。在可销毁的 GitHub 托管 Linux runner 上运行，要求 root 和 systemd；不要用于实际部署目录。

## 执行方法

使用产品固定的前端构建器生成 release 二进制及构建元数据。按产品 `config/xssi.lock` 检出精确 XSSI 修订；两个源码检出均须干净。

以 xscs 为例，直接使用已经构建的二进制生成候选包：

```sh
python3 -I -B "$XSSI/scripts/package-installed-candidate.py" xscs \
  "$SOURCE" "$BINARY" "$METADATA" "$OUTPUT"
```

所有路径均为绝对路径；`OUTPUT` 是源码目录外尚不存在的新目录。该命令复用 xscs 发行载荷整理函数，以及 XSSI 的辅助程序构建、SBOM 和包校验流程，生成 `xscs-VERSION-linux-x86_64.tar.gz` 与 `SHA256SUMS`。

在同一 runner 上执行生命周期检查：

```sh
sudo env GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted \
  LIFECYCLE_DIAGNOSTICS="$RUNNER_TEMP/lifecycle-diagnostics" \
  python3 -I -B "$XSSI/tests/installed_lifecycle.py" \
  --adapter "$SOURCE/scripts/installed-lifecycle-adapter.py" \
  "$OUTPUT/xscs-VERSION-linux-x86_64.tar.gz" "$SOURCE_SHA"
```

`SOURCE_SHA` 为产品完整提交 SHA，`VERSION` 替换为产品版本。候选包及其 `SHA256SUMS` 一起保留。

## 产品适配器

适配器位于产品受版本控制的 `scripts/` 内，提供以下参数和函数：

- `PRODUCT`、`ACCOUNT`、`SERVICES`：产品、服务账号及 systemd 单元元组。
- `RETAINED_FILES`：相对安装根目录、需要保留的状态文件路径元组。
- `configure(config, root, shared, port)`：生成 loopback 上的生产模式配置。
- `exercise(request, session, sensitive, require)`：执行经认证的业务操作并返回预期状态。
- `persisted(request, session, state, require)`：检查重启后会话及业务状态。
- `retained(root, shared, state, require)`：检查测试框架移除运行载荷后仍保留的数据。

框架提供 HTTPS 请求辅助函数和管理员会话。临时业务凭据加入 `sensitive`，供诊断脱敏；xscs 适配器覆盖设备创建、更名与授权。

## xcos 外部程序与 TLS 输入

xcos 使用同一命令，将产品参数改为 `xcos`。产品的 `stage-product.sh` 整理回执校验过的 Server 和固定 MediaMTX 载荷；候选包生成器保留上游原始归档，供正常发布回执校验。Cargo 版本取自 `[package]`，说明取自产品 `README.md`。

安装前，xcos 适配器的 `configuration_files(config, root, input_directory)` 在框架创建的 0700 目录中准备 `rtsp-cert.pem`、`rtsp-key.pem` 和 `mediamtx.env`。每项必须为单硬链接的普通文件，权限 0600。框架向真实安装器传入三项 `--configuration-file REL=SOURCE`，不直接改写已安装配置。安装导入文件及生成的 `mediamtx.yml` 必须由 root 持有、服务组可读，权限为 0640。

`xcos.service` 与 `xcos-mediamtx.service` 同时参与启动、重启、停止及已记录单元的移除。此检查验证控制面与录像目录保留，不证明真实摄像头接入和录像内容有效。

## 验收步骤与证据

1. 校验归档与精确源码身份。
2. 运行真实安装器，使用临时密码初始化管理员。
3. 检查服务身份及只读配置权限。
4. 启动 systemd 服务，经 loopback HTTPS 登录并执行产品操作。
5. 重启服务，检查会话和业务数据保持。
6. 停服并执行离线状态检查。
7. 由测试框架移除自身记录的服务注册和运行载荷，核对保留数据，再清理本次临时资源。

成功步骤在日志中输出 `PASS`。设置 `LIFECYCLE_DIAGNOSTICS` 后，在该目录写出已脱敏的 `lifecycle.jsonl`。只上传此诊断目录，不上传安装状态或临时凭据。测试清理不是产品提供的卸载入口。

共享回归命令：

```sh
python3 -B -m unittest discover -s tests -p 'test_installed_*.py' -v
```

这些回归验证测试框架与候选包边界；真实安装结果由 GitHub 托管 runner 上的生命周期任务提供。
