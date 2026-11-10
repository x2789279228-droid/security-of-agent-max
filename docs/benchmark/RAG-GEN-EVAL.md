# RAG 生成侧忠实度评测 — 检索增强是否让生成可信

- 查询数: 20(黄金集前 N, 同 RAG-EVAL 语料)
- 链路: BM25 top5 证据 → 平台 LLMClient(doubao-seed-2.1-lite) 仅凭证据作答 → faithfulness_gate.compute_faithfulness(生产同款闸)
- 指标: **faithfulness=1.0** / abstain 率=0.0 / 失败分布={'invalid_reference': 0, 'unsupported_claim': 0, 'wrong_conclusion': 0}

> 口径: 评的是「生成是否忠实于检索到的证据」—— 编造实体/无证据主张/
> 结论相反由 faithfulness_gate 逐断言判定(与线上 Copilot 同一实现)。
> abstain 是**正确行为**的证据: 黄金集含证据不足类问题时, 高 abstain
> 率+高 faithfulness = 系统不编造。LLM 换代/提示词变化都须重跑本评测。

## 逐查询明细(top 20)

| 查询 | abstain | faithfulness | 无证据主张 | 回答摘录 |
|---|---|---|---|---|
| Q001: 暴力破解怎么检测 | False | 1.0 | 0 | 根据提供的证据，暴力破解（T1110）的检测方式如下： 1. 检测登录接口高频访问，即URL聚合访问次数大于5次/5分钟 |
| Q002: password spraying credential | False | 1.0 | 0 | password spraying 与 credential stuffing 属于 T1110 暴力破解的子类型。可通 |
| Q003: T1110 相关的缓解措施 | False | 1.0 | 0 | T1110 暴力破解的相关缓解措施包括 M1036 账户使用策略、M1027 口令策略，以及登录防爆破限流。M1027  |
| Q004: PowerShell encoded command 执 | False | 1.0 | 0 | PowerShell 编码执行(-EncodedCommand)属于 T1059 命令与脚本解释器攻击范畴，是 Wind |
| Q005: mimikatz lsass 凭证转储检测 | False | 1.0 | 0 | 可通过Sysmon检测进程访问lsass.exe的事件，对应EventID 10、GrantedAccess为0x101 |
| Q006: C2 beacon 周期性外联怎么发现 | False | 1.0 | 0 | 可通过检测等间隔外联的 beacon 周期性特征发现 C2 beacon 周期性外联。结合 JA3/TLS 指纹异常、D |
| Q007: 数据外泄的时序特征 | False | 1.0 | 0 | 数据外泄的时序特征为外发流量突增、上行远超基线、时段异常。平台跨源关联(data_exfil)将 EDR 进程事件与网络 |
| Q008: webshell 检测规则 | False | 1.0 | 0 | webshell 检测规则可依据证据1的检测特征部署：监控上传目录可执行文件、带 eval/base64_decode  |
| Q009: Log4Shell CVE-2021-44228 | False | 1.0 | 0 | Log4Shell(CVE-2021-44228)属于T1190利用面向公众的应用的典型案例，该技术指利用暴露在互联网的 |
| Q010: 有效账户滥用怎么排查 | False | 1.0 | 0 | 有效账户滥用可从以下方面排查：检测异常时段登录、异地登录、账户行为基线偏离，需与 T1003 联合分析。账号新建/提权事 |
| Q011: 横向移动 SMB RDP 检测 | False | 1.0 | 0 | 可通过单源对多主机的认证尝试、非常规时段的服务访问、pth 特征(EventID 4624 LogonType 9)检测 |
| Q012: schtasks 计划任务持久化 | False | 1.0 | 0 | schtasks 计划任务持久化对应 ATT&CK 技术 T1053 计划任务/作业，可利用系统任务调度实现持久化或远程 |
| Q013: 钓鱼邮件检测通道有哪些 | False | 1.0 | 0 | 根据证据1，钓鱼邮件检测通道包括：邮件头伪造与可解释性规则、BEC话术、网站克隆、短信、二维码（quinjacking） |
| Q014: DGA 域名 fast-flux 检测 | False | 1.0 | 0 | 可通过以下方式检测：高频 NXDOMAIN、DGA 随机域熵值、新注册域名访问，同时可借助 Suricata EVE 的 |
| Q015: 双重 URL 编码绕过怎么处理 | False | 1.0 | 0 | 可通过平台规范化解码器处理双重 URL 编码绕过。该解码器为全平台唯一解码实现，采用受限 3 轮解码+稳定即停+%uXX |
| Q016: 内网端口扫描告警 | False | 1.0 | 0 | 内网端口扫描属于 T1046 网络服务发现，是横移前置动作。检测特征为单源短时间多目标多端口 SYN、非常见端口探测序列 |
| Q017: net user 账户枚举 | False | 1.0 | 0 | net user 账户枚举属于 T1087 账户发现，用于枚举域内账户与权限。单独出现时属于侦察行为，与 T1021/T |
| Q018: 勒索软件前兆指标 | False | 1.0 | 0 | 根据证据1，勒索软件前兆指标为海量文件写、删除影子副本（vssadmin delete shadows）。EDR融合进程 |
| Q019: 外网资产漏洞利用初始访问 | False | 1.0 | 0 | 外网资产漏洞利用初始访问对应ATT&CK技术T1190，即利用面向公众的应用，通过暴露在互联网的应用漏洞获取初始访问，典 |
| Q020: T1595 主动扫描和内网扫描区别 | False | 1.0 | 0 | T1595 主动扫描与内网扫描的核心区别在于目标侧不同。T1595 主动扫描针对互联网资产开展对外暴露面的主动侦察扫描， |
