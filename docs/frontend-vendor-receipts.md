# 原生 Web 构建的 vendor 依赖追溯

Rust 资源构建器可以直接读取已纳入产品源码的 ESM、CSS、字体，不要求安装 `node_modules`。发布清单仍必须证明第三方输入的来源，不能把 `vendor` 路径当作产品自己的实现而略过。

`frontend_receipt.py` 同时支持已有 npm 锁文件流程和原生构建生成的相同版本模块清单。后者在每个资源包内保留 `SOURCE.json`，包含 `format/package/version/license/origin/files/npm`；`npm` 必须声明原包名、版本、许可证、发行档案 URL、SRI 和逐文件 `archive_files` 映射。源码目录每个文件（除清单自身）都必须登记，包括发布控制文件同名路径；目录中的链接、特殊文件、超量输入和未列出的文件均拒绝。

发布验证会重新获取原 npm 发行档案并验证 SRI、原包身份和原许可证，逐字节核对所有 vendor 文件对应的原档案文件。修改文件后同步修改本地摘要不能绕过原始归档核验。字体继续验证原字体 provenance、实际编译资源、Latin/CJK 上游档案摘要，并保留原许可证。重复字体来源会被拒绝。

模块、依赖边、交付资源和服务端二进制摘要仍沿用既有绑定合同；这一扩展不改变发布审批、安装、网络暴露或候选程序执行规则。Rust 前端构建不需要 Node；现有独立的发布脚本及浏览器测试工具链仍各自保留。

验证：`python3 -m unittest discover -s tests -p test_frontend_receipt.py`。测试使用真实 tar/SRI/源码摘要与模块图 fixture，只替换网络获取；这些 fixture 不是已编译产品的证明。
