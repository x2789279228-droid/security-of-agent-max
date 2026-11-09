# RAG 生成侧忠实度评测 — 检索增强是否让生成可信

- 查询数: 20(黄金集前 N, 同 RAG-EVAL 语料)
- 链路: BM25 top5 证据 → 平台 LLMClient(MiniMax-M3) 仅凭证据作答 → faithfulness_gate.compute_faithfulness(生产同款闸)
- 指标: **faithfulness=0.9875** / abstain 率=0.05 / 失败分布={'invalid_reference': 0, 'unsupported_claim': 1, 'wrong_conclusion': 0}

> 口径: 评的是「生成是否忠实于检索到的证据」—— 编造实体/无证据主张/
> 结论相反由 faithfulness_gate 逐断言判定(与线上 Copilot 同一实现)。
> abstain 是**正确行为**的证据: 黄金集含证据不足类问题时, 高 abstain
> 率+高 faithfulness = 系统不编造。LLM 换代/提示词变化都须重跑本评测。

## 逐查询明细(top 20)

| 查询 | abstain | faithfulness | 无证据主张 | 回答摘录 |
|---|---|---|---|---|
| Q001: 暴力破解怎么检测 | False | 1.0 | 0 | - 在登录接口检测短时间高频访问，例如同一 URL 在 5 分钟内请求超过 5 次，并经 Flink 窗口确认，以发现密 |
| Q002: password spraying credential | False | 1.0 | 0 | password spraying 与 credential stuffing 属于 T1110 暴力破解（Brute  |
| Q003: T1110 相关的缓解措施 | False | 1.0 | 0 | T1110 的相关缓解包括 **M1027 口令策略**、**M1036 账户使用策略**及登录防爆破限流，并可结合 M |
| Q004: PowerShell encoded command 执 | False | 1.0 | 0 | 该攻击可归类为 **T1059 命令与脚本解释器 (Command and Scripting Interpreter) |
| Q005: mimikatz lsass 凭证转储检测 | False | 1.0 | 0 | 依据[证据1]，可将 Mimikatz 访问 LSASS 内存按 **T1003 操作系统凭证转储**检测：重点采集进程 |
| Q006: C2 beacon 周期性外联怎么发现 | False | 1.0 | 0 | 通过时序分析外联流量，识别固定间隔、近似等间隔的周期性 beacon。结合 JA3/TLS 指纹异常、DNS 长随机子域 |
| Q007: 数据外泄的时序特征 | False | 1.0 | 0 | 数据外泄的时序特征包括：外发流量突增、上行流量远超基线，以及外传时段异常。平台可将近似同一时间窗口内的 EDR 进程事件 |
| Q008: webshell 检测规则 | False | 1.0 | 0 | 针对 **T1505.003 Web Shell (Server Software Component: Web She |
| Q009: Log4Shell CVE-2021-44228 | False | 1.0 | 0 | Log4Shell（CVE-2021-44228）是 **T1190 利用面向公众的应用（Exploit Public- |
| Q010: 有效账户滥用怎么排查 | False | 1.0 | 0 | 1. 围绕 **T1078 有效账户**，重点检测异常时段登录、异地登录及账户行为基线偏离。   2. 若怀疑凭证转储后 |
| Q011: 横向移动 SMB RDP 检测 | False | 1.0 | 0 | 横向移动中的 SMB/RDP 可归入 **T1021 远程服务横移**。重点检测单源对多主机的认证尝试、非常规时段的服务 |
| Q012: schtasks 计划任务持久化 | False | 0.75 | 1 | schtasks 计划任务持久化对应证据1中的 **T1053 计划任务/作业 (Scheduled Task/Job) |
| Q013: 钓鱼邮件检测通道有哪些 | False | 1.0 | 0 | 根据证据1，平台反钓鱼检测有 6 个通道：邮件头伪造与可解释性规则、BEC 话术、网站克隆、短信、二维码（quinjac |
| Q014: DGA 域名 fast-flux 检测 | True | 1.0 | 0 | 可依据 **T1568 动态解析 (Dynamic Resolution)** 检测 DGA/fast-flux，重点监 |
| Q015: 双重 URL 编码绕过怎么处理 | False | 1.0 | 0 | 将双重 URL 编码纳入检测输入规范化：使用 `normalization.py` 执行“受限 3 轮解码+稳定即停”， |
| Q016: 内网端口扫描告警 | False | 1.0 | 0 | 内网端口扫描告警对应 **T1046 网络服务发现 (Network Service Discovery)**，典型特征 |
| Q017: net user 账户枚举 | False | 1.0 | 0 | net user 属于账户发现（T1087），可通过 EDR 进程事件的 command_line 匹配 net.exe |
| Q018: 勒索软件前兆指标 | False | 1.0 | 0 | 勒索软件前兆指标包括：海量文件写入、进程批量文件 I/O，以及删除影子副本命令 `vssadmin delete sha |
| Q019: 外网资产漏洞利用初始访问 | False | 1.0 | 0 | 外网资产漏洞利用获取初始访问，对应 **MITRE ATT&CK T1190（利用面向公众的应用）**。典型案例包括 L |
| Q020: T1595 主动扫描和内网扫描区别 | False | 1.0 | 0 | T1595 主动扫描针对互联网暴露资产开展主动侦察，如漏洞扫描和爬虫指纹识别；T1046 网络服务发现则是在已进入内网后 |
