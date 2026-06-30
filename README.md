# BW16-AirReapr
BW16-AirReapr
还可以扩展的功能
一、WiFi 攻击进阶
功能	难度	效果
MIC 破解攻击 (Michael MIC)	高	对 TKIP 网络注入已知明文 → 暴力破解 MIC 密钥 → 注入任意数据帧
KARMA 攻击	中	响应所有 Probe Request，伪装成客户端想连的任何网络
MANA 攻击 (KARMA 升级版)	中高	KARMA + 动态调整 SSID + 嗅探已知 Beacon
Caffe Latte 攻击	高	从孤立客户端窃取 WEP/WPA 密钥
WPS PIN 暴力破解	高	通过 802.11 认证帧暴力破解 WPS PIN
5GHz 频段探测	中	扩展扫描到 5GHz 信道 (36-165)
WiFi 干扰器 (全信道)	中	在所有 1-13 信道同时发送噪声/Deauth
自动反防御 (Anti-Mitigation)	中	检测 AP 是否开启 802.11w/Protected Management Frames，自动切换到广播模式
Ghost Tunnel (幽灵隧道攻击)	中	创建不广播 SSID 的隐藏 AP 隧道
SNMP/MQTT 劫持	中	对物联网设备发送伪造 MQTT/SNMP 指令
二、BLE 蓝牙扩展
功能	难度	效果
BLE 扫描器	低	扫描周边蓝牙设备并显示名称/RSSI/服务
BLE 洪水攻击	低	发送海量 ADV_IND / SCAN_RSP 数据包干扰蓝牙通信
BLE 连接洪水	中	向目标 BLE 设备发起大量连接请求耗尽资源
BadUSB BLE 键盘注入	中	伪装成蓝牙键盘向目标设备发送预定义按键序列
BLE 追踪器欺骗	低	伪造 AirTag/Tile 等追踪器坐标信息
Anchor Point 嗅探	高	破解 BLE 连接参数，在连接窗口期注入数据
Apple TV/HomePod 弹窗	低	新增 Apple 特定设备配对弹窗类型
三、射频物理层
功能	难度	效果
频谱分析仪	中	TFT 显示 2.4GHz 频谱信号强度热力图
信道利用率统计	低	扫描时统计每个信道 AP 数量及利用率比
信号强度排序	低	按 RSSI 排序 AP 列表并标注距离估算
WiFi 定位三角测量	高	利用多 AP 的 RSSI 三角定位目标设备位置
四、系统增强
功能	难度	效果
SD 卡日志记录	中	攻击/扫描/捕获结果自动保存到 SD 卡
RTC 时钟	低	利用 RTL8720 RTC 为日志添加时间戳
电池电量显示	低	外接电池分压电路 + ADC 读取
远程命令执行 (Telnet/MQTT 后门)	中	通过 WiFi 远程控制攻击模块
攻击序列宏 (Macro)	中	预设多步攻击流程，一键执行 (如：扫描→Deauth→抓包→钓鱼)
固件 OTA 远程升级	中	通过 Web 界面上传固件并自动重启
CLI 串口命令行	中	实现完整的类 metasploit 式串口交互界面
多语言界面	低	支持中/英文切换
WebUI 增强	中	添加攻击按钮、实时 AP 列表、图表统计
五、安全研究工具
功能	难度	效果
SSID 词表扫描 (Wordlist Scan)	低	从预设 SSID 词表逐信道探测隐藏网络
被动指纹识别	中	通过 Beacon 帧 IE 字段识别 AP 芯片/品牌/型号
MAC 厂商查询	低	根据 MAC OUI 前缀显示设备制造商
WPA3 降级攻击	中高	强制 WPA3-Transition 网络降级到 WPA2 再抓包
TCP/UDP 端口扫描	中	连接目标 AP 后扫描内网开放端口
ARP 欺骗	中高	对内网设备发 ARP 欺骗 → 中间人攻击
六、CSMA/CA 协议层高级攻击
功能	难度	效果
CTS-to-Self Flood	低	大量 CTS-to-Self 帧迫使所有设备退避
ACK 风暴	中	伪造大量 ACK 帧使信道争用窗口饱和
Block ACK 破坏	中	发送伪造 Block ACK Request 破坏聚合帧重传
PS-Poll 欺骗	低	伪造 PS-Poll 帧让 AP 因节能客户端频繁发送缓存数据
Duration 欺骗 (NAV 扩展版)	低	在多种帧类型中注入超大 Duration 字段独占信道
当前最有价值的扩展建议 (Top 5)
MANA/KARMA 攻击 — 响应所有 Probe Request，所有 WiFi 客户端会看到你伪造的网络并尝试连接，是 Evil Twin 的强力升级版
全信道干扰器 — 在 1-13 信道同时发送干扰信号，直接瘫痪整个 2.4GHz 频段
攻击序列宏 — 预设自动化攻击流程，一次触摸完成 "扫描→选目标→Deauth→抓包→Web 保存" 全流程
WPA3 降级攻击 — 利用 WPA3-Transition 模式漏洞，强制 AP 降级到 WPA2 后抓取握手包
CLI 交互终端 — 通过串口实现类 metasploit 的命令行界面，方便脚本化和远程操作
需要我实现其中某个功能吗？
