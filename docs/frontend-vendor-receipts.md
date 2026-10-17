# 原生 Web 构建的 vendor 依赖追溯

Rust 资源构建器可以直接读取已纳入产品源码的 ESM、CSS、字体，不要求安装 `node_modules`。发布清单仍必须证明第三方输入的来源，不能把 `vendor` 路径当作产品自己的实现而略过。

`frontend_receipt.py` 同时支持已有 npm 锁文件流程和原生构建生成的相同版本模块清单。后者在每个资源包内保留 `SOURCE.json`，包含 `format/package/version/license/origin/files/npm`；`npm` 必须声明原包名、版本、许可证、发行档案 URL、SRI 和逐文件 `archive_files` 映射。源码目录每个文件（除清单自身）都必须登记，包括发布控制文件同名路径；目录中的链接、特殊文件、超量输入和未列出的文件均拒绝。

发布验证会重新获取原 npm 发行档案并验证 SRI、原包身份和原许可证，逐字节核对所有 vendor 文件对应的原档案文件。修改文件后同步修改本地摘要不能绕过原始归档核验。字体继续验证原字体 provenance、实际编译资源、Latin/CJK 上游档案摘要，并保留原许可证。重复字体来源会被拒绝。

模块、依赖边、交付资源和服务端二进制摘要仍沿用既有绑定合同；这一扩展不改变发布审批、安装、网络暴露或候选程序执行规则。Rust 前端构建不需要 Node；现有独立的发布脚本及浏览器测试工具链仍各自保留。

验证：`python3 -m unittest discover -s tests -p test_frontend_receipt.py`。测试使用真实 tar/SRI/源码摘要与模块图 fixture，只替换网络获取；这些 fixture 不是已编译产品的证明。

## Rust 与 WASM 运行依赖

六个 Server 的原生构建器在前端回执中记录 `rust`：实际 WASM 输出摘要、独立 Cargo manifest 与锁文件、全部本地 Rust 输入摘要、工具链、目标、构建配置和所选运行依赖图。同一构建定义也进入随 Server 嵌入的 `assets/xcss-web-build.json`；打包时两者必须一致。含 WASM 却没有 Rust 回执、遗漏输出或改变源码、锁文件、目标和依赖边，均拒绝打包。

工具只在私有源码快照中重新解析 `wasm32-unknown-unknown` 的正常依赖，排除 proc macro、build 和 dev 依赖，再与编译时图核对。复用已有 Cargo SBOM 和原始许可证生成器，额外保留 `share/wasm-sbom.cdx.json`、`share/wasm-Cargo.lock`、`share/THIRD_PARTY_WASM_LICENSES.txt`、本地依赖许可证和 `share/build-inputs/wasm/runtime.json`。最终发行 SBOM 将浏览器 Cargo 图绑定到实际嵌入资源的 Server 摘要。

运行图表达所选目标的依赖关系，不宣称每个依赖的全部代码都在优化后保留。边界回归为 `python3 -B -m unittest discover -s tests -p test_wasm_receipt.py`；实际产品构建和发行物验收另行记录。

原始许可文件缺失时，先检查与实际 crate 归档校验和、原始 manifest 和 VCS 身份绑定的上游精确修订，保留其中真实的许可及 NOTICE。`drain_filter_polyfill 0.1.3` 与 `erased 0.1.2` 的精确源码仅在 manifest 声明标准 SPDX 许可，因此现有 `upstream-licenses.json` 为这两项显式绑定原始 `Cargo.toml.orig` 声明与 SPDX 官方标准全文及摘要。生成材料分别标记 `publisher-declaration`、`standard-spdx`；原始字节和回执另外保存在 `share/licenses/wasm-upstream/`，便于直接核对摘要。不冒称标准全文是上游原始 LICENSE，不填造版权人或年份。未知包、含义冲突、自定义许可或摘要不符仍拒绝；此规则不自动为缺失文件套用通用 MIT 文本。
