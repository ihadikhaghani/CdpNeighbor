# CdpNeighbor — دیده شدن ویندوز در `show cdp neighbors` سوئیچ سیسکو

> **Overview (English)**
>
> A tiny Windows utility that sends **CDP (Cisco Discovery Protocol)** frames from a selected network adapter, so a Cisco switch shows this PC as a neighbour in `show cdp neighbors` / `show cdp neighbors detail`. Useful for labs, tests and switch simulations.
>
> It calls **Npcap directly through `ctypes`** — no pip packages and no Windows/network configuration changes. Only raw layer-2 frames are sent; `Ctrl+C` stops the advertiser and the switch ages the neighbour out after the holdtime (180 s by default).
>
> A companion Linux/Raspberry Pi implementation (`cdp_advertiser_linux.py`) uses `AF_PACKET` instead of Npcap and builds byte-identical frames, verified by `selftest.py`. See `README-Linux.md`.
>
> **Use only on networks you own or are explicitly authorised to test.**

این پروژه یک ابزار کوچک ویندوزی است که فریم‌های **CDP (Cisco Discovery Protocol)** را از کارت شبکه‌ی انتخابی شما ارسال می‌کند تا سوئیچ سیسکو، این سیستم را به‌عنوان یک همسایه‌ی CDP نشان دهد.

- هیچ بسته‌ی پایتونی لازم نیست؛ Npcap مستقیماً با `ctypes` صدا زده می‌شود.
- هیچ تنظیمی در ویندوز یا کارت شبکه تغییر نمی‌کند؛ فقط فریم خام لایه ۲ ارسال می‌شود.
- با `Ctrl+C` متوقف می‌شود و سوئیچ بعد از اتمام Holdtime (پیش‌فرض ۱۸۰ ثانیه) همسایه را حذف می‌کند.

> **فقط در شبکه‌ای استفاده کنید که مالک آن هستید یا اجازه‌ی تست دارید.** این ابزار برای آزمایشگاه، تست و شبیه‌سازی دستگاه سیسکو است.

---

## پیش‌نیازها

| مورد | توضیح |
|---|---|
| ویندوز | Windows 10 / 11 |
| پایتون | Python 3.8 یا بالاتر (تست‌شده با 3.15) |
| Npcap | از <https://npcap.com/#download> نصب شود (روی این سیستم نصب و در حال اجراست) |
| دسترسی | Administrator برای ارسال فریم خام |

هنگام نصب Npcap گزینه‌ی **Install Npcap in WinPcap API-compatible Mode** را فعال کنید. (پشتیبانی از Loopback لازم نیست.)

بررسی نصب:

```bat
py -3 --version
sc query npcap
```

---

## اجرا (ساده‌ترین روش)

1. روی **`run.bat`** دوبار کلیک کنید.
2. پنجره‌ی UAC را تأیید کنید (دسترسی Administrator).
3. لیست کارت‌های شبکه نمایش داده می‌شود؛ شماره‌ی کارتی که به سوئیچ سیسکو وصل است را وارد کنید (یا بخشی از نام آن را بنویسید).
4. روی سوئیچ اجرا کنید:

```text
show cdp neighbors
show cdp neighbors detail
```

خروجی نمونه:

```text
Capability Codes: R - Router, T - Trans Bridge, B - Source Route Bridge
                  S - Switch, H - Host, I - IGMP, r - Repeater

Device ID        Local Intrfce     Holdtme    Capability  Platform  Port ID
MY-PC            Gig 0/1           175             S I      WS-C2960  GigabitEthernet0/1
```

برای توقف، `Ctrl+C` بزنید یا پنجره را ببندید.

> اگر روی سیستم Hyper-V فعال است، معمولاً باید کارت `vEthernet (LAN)` را انتخاب کنید، نه کارت فیزیکی Intel/Realtek را.

---

## گزینه‌های خط فرمان

| گزینه | پیش‌فرض | توضیح |
|---|---|---|
| `--list` | — | نمایش کارت‌های شبکه و خروج |
| `-i, --iface NAME` | پرسش تعاملی | نام، توضیح یا شماره‌ی کارت |
| `--hostname NAME` | نام کامپیوتر | مقدار Device ID در CDP |
| `--platform TEXT` | `cisco WS-C2960-24TT-L` | مقدار Platform |
| `--port TEXT` | `GigabitEthernet0/1` | مقدار Port ID |
| `--capabilities LIST` | `switch,igmp` | `router, switch, host, igmp, repeater, transparent-bridge, source-route-bridge` یا عدد (مثلاً `0x10`) |
| `--ip ADDR` | خودکار از کارت | آدرس IPv4 که در TLV آدرس اعلام می‌شود |
| `--no-address` | — | ارسال نکردن TLV آدرس |
| `--mac AA:BB:...` | MAC واقعی کارت | MAC مبدأ فریم |
| `--vlan N` | ارسال نمی‌شود | اعلام Native VLAN (برای جلوگیری از پیام mismatch، پیش‌فرض خاموش است) |
| `--vtp-domain NAME` | ارسال نمی‌شود | اعلام دامنه‌ی VTP |
| `--ttl SEC` | `180` | Holdtime در CDP (۱ تا ۲۵۵) |
| `--interval SEC` | `60` | فاصله‌ی ارسال هر فریم |
| `--count N` | `0` (بی‌نهایت) | توقف بعد از N فریم |
| `--half-duplex` | full | اعلام Half Duplex |
| `--dry-run` | — | فقط ساخت فریم و نمایش هکس، بدون ارسال |
| `-v, --verbose` | — | نمایش هکس هر فریم ارسالی |

---

## مثال‌ها

```bat
rem نمایش کارت‌ها
py -3 cdp_advertiser.py --list

rem اجرا روی کارت vEthernet (LAN) با نام پیش‌فرض کامپیوتر
py -3 cdp_advertiser.py --iface "vEthernet (LAN)"

rem شبیه‌سازی یک سوئیچ سیسکو با نام و IP مشخص
py -3 cdp_advertiser.py --iface "vEthernet (LAN)" ^
    --hostname LAB-SW2 --platform "cisco WS-C2960-24TT-L" ^
    --port "GigabitEthernet0/1" --ip 172.16.4.65 --interval 30

rem فقط یک فریم بفرست (برای تست سریع)
py -3 cdp_advertiser.py --iface "vEthernet (LAN)" --count 1

rem ساخت فریم بدون ارسال
py -3 cdp_advertiser.py --iface "vEthernet (LAN)" --dry-run --verbose
```

اگر `--capabilities host` بدهید، سوئیچ آن را به‌صورت `H` (Host) نشان می‌دهد؛ با مقدار پیش‌فرض `switch,igmp` به‌صورت `S I` نمایش داده می‌شود.

---

## تست بدون نیاز به دسترسی به CLI سوئیچ

```bat
rem تست آفلاین: ساخت فریم، بررسی TLVها و checksum
py -3 selftest.py

rem شنود پسیو CDPهای واقعی سوئیچ و اعتبارسنجی checksum آن‌ها
py -3 selftest.py --listen 70 --iface "vEthernet (LAN)"

rem ارسال یک فریم تست (این فریم برای ۳ دقیقه در سوئیچ دیده می‌شود)
py -3 selftest.py --send --iface "vEthernet (LAN)"
```

`--listen` هیچ چیزی ارسال نمی‌کند و فقط CDPهای سوئیچ را می‌خواند؛ برای اطمینان از درست بودن مسیر لایه ۲ و الگوریتم checksum مفید است. (سوئیچ‌های سیسکو معمولاً هر ۶۰ ثانیه CDP می‌فرستند، پس ۷۰ ثانیه صبر کنید.)

---

## عیب‌یابی

| مشکل | راه‌حل |
|---|---|
| در `show cdp neighbors` دیده نمی‌شود | مطمئن شوید CDP روی آن پورت فعال است: `show cdp interface GigabitEthernet0/1` و `show cdp neighbors detail`. کارت شبکه‌ی درست و VLAN درست را انتخاب کنید. |
| خطای `Cannot open adapter` | برنامه را با Administrator اجرا کنید (`run.bat`) و نصب Npcap را بررسی کنید. |
| خطای `could not read the MAC address` | کارت دیگری (مثلاً `vEthernet`) انتخاب کنید، یا MAC را دستی بدهید: `--mac A4:BB:6D:11:22:33` (MAC را با `Get-NetAdapter` ببینید). |
| Holdtme در سوئیچ کم می‌شود و صفر می‌شود | برنامه متوقف شده است؛ دوباره اجرا کنید یا `--interval` را کمتر از `--ttl` نگه دارید. |
| سوئیچ فقط LLDP دارد | CDP مخصوص سیسکو است؛ روی سوئیچ‌های غیرسیسکو یا حالت LLDP-only دیده نمی‌شود. |
| پیام `NATIVE_VLAN_MISMATCH` در لاگ سوئیچ | گزینه‌ی `--vlan` را ندهید (پیش‌فرض هم ارسال نمی‌شود). |
| آنتی‌ویروس/EDR مانع می‌شود | ارسال فریم خام L2 توسط برخی EDRها بلاک می‌شود؛ برای این فایل/پوشه استثنا بگذارید. |
| فایروال ویندوز | روی فریم‌های لایه ۲ اثری ندارد؛ نیازی به باز کردن پورت نیست. |
| پورت ترانک | فریم‌ها بدون تگ 802.1Q ارسال می‌شوند؛ روی پورت access یا Native VLAN ترانک تست کنید. |

---

## ساختار فایل‌ها

```text
CdpNeighbor/
├── cdp_advertiser.py        برنامه اصلی ویندوز (Npcap)
├── selftest.py              تست آفلاین و تست زنده (listen/send)
├── run.bat                  اجرای خودکار با دسترسی Administrator
├── README.md                همین راهنما
├── cdp_advertiser_linux.py  نسخه لینوکس، بدون Npcap (AF_PACKET)
├── run-linux.sh             اجرای خودکار با sudo
├── README-Linux.md          راهنمای نسخه لینوکس
└── SECURITY.md              توضیح رفتار و متن درخواست استثنا
```

> **اگر ESET اجرای نسخه‌ی ویندوزی را بلاک می‌کند:** نسخه‌ی لینوکسی را
> استفاده کنید (`README-Linux.md`). آن نسخه هیچ درایوری نصب نمی‌کند، Npcap
> نمی‌خواهد و چون روی لینوکس اجرا می‌شود، با ESET سیستم‌های ویندوزی کاری
> ندارد. فریم خروجی هر دو نسخه یکسان است.

## نکته‌ی فنی

فریم CDP به این صورت ساخته می‌شود:

```text
Ethernet 802.3 → dst 01:00:0C:CC:CC:CC
LLC/SNAP       → AA AA 03 | 00 00 0C | 20 00
CDP            → version 2 | TTL 180 | checksum | TLVs
```

TLVهای ارسالی: Device ID، Addresses، Port ID، Capabilities، Software Version، Platform، (اختیاری VTP/Native VLAN) و Duplex. checksum دقیقاً مطابق رفتار سوئیچ‌های سیسکو برای طول فرد محاسبه می‌شود و با فریم واقعی یک سوئیچ C2960S اعتبارسنجی شده است.
