# CdpNeighbor برای لینوکس / رزبری‌پای (بدون Npcap)

این نسخه همان فریم CDP را می‌سازد، اما با `AF_PACKET` لینوکس ارسال می‌کند.
یعنی:

- **بدون Npcap** — هیچ درایور بسته‌ای نصب نمی‌شود.
- **بدون libpcap** و بدون هیچ پکیج pip — فقط کتابخانه‌ی استاندارد پایتون.
- **بدون ارتباط با ESET** — کد روی لینوکس اجرا می‌شود، پس سیاست سازمانی
  ویندوز/آنتی‌ویروس اصلاً درگیر نمی‌شود.
- همان فریم بایت‌به‌بایت با نسخه‌ی ویندوزی یکسان است (با `--selftest` بررسی می‌شود).

> فقط روی شبکه‌ای استفاده کنید که مالک آن هستید یا اجازه‌ی تست دارید.

---

## ۱. پیش‌نیازها

| مورد | توضیح |
|---|---|
| سیستم | لینوکس (Ubuntu/Debian، Raspberry Pi OS، Alpine و…) |
| پایتون | `python3` نسخه ۳.۸ یا بالاتر (روی رزبری‌پای از قبل نصب است) |
| دسترسی | `root` یا `CAP_NET_RAW` (اسکریپت خودش `sudo` می‌زند) |
| بسته‌ی اضافی | **هیچ** |

بررسی نسخه:

```sh
python3 --version
```

## ۲. انتقال فایل‌ها

دو فایل لازم است:

```
cdp_advertiser_linux.py
run-linux.sh
```

از ویندوز با `scp`:

```powershell
scp .\cdp_advertiser_linux.py .\run-linux.sh pi@192.168.1.50:~/cdp/
```

روی دستگاه لینوکس:

```sh
chmod +x run-linux.sh
./run-linux.sh --selftest
```

اگر خروجی `Self-test passed.` بود، ساخت فریم درست است.

## ۳. دیدن کارت‌های شبکه

```sh
sudo python3 cdp_advertiser_linux.py --list
```

نمونه‌ی خروجی:

```
  #   Name             IPv4             MAC                State
  --- ---------------- ---------------- ------------------ ------------
  1   eth0             10.8.4.65        a0:36:bc:35:82:d2  up
  2   wlan0            10.8.4.90        3c:71:bf:11:22:33  up
```

> **نکته‌ی رزبری‌پای:** اگر می‌خواهید هم‌زمان با SSH وصل بمانید، از یک
> **آداپتور USB به Ethernet** برای پورت آزمایشی استفاده کنید و SSH را روی
> Wi-Fi یا پورت داخلی نگه دارید. سوئیچ، MAC همان آداپتور USB را می‌بیند.

## ۴. اجرا

```sh
sudo python3 cdp_advertiser_linux.py --iface eth0
```

یا با اسکریپت (خودش sudo می‌زند):

```sh
./run-linux.sh --iface eth0
```

خروجی:

```
CdpNeighbor (AF_PACKET) - CDP neighbor advertiser
  Interface   : eth0 (up=True)
  Source MAC  : A0:36:BC:35:82:D2
  Device ID   : rpi-lab
  Platform    : cisco WS-C2960-24TT-L
  ...
Sending to 01:00:0C:CC:CC:CC every 60s. Press Ctrl+C to stop.
[12:00:01] sent #1 (235 bytes)
```

روی سوئیچ سیسکو:

```
show cdp neighbors
show cdp neighbors detail
show cdp entry rpi-lab
```

## ۵. گزینه‌های پرکاربرد

```sh
# نام و هویت ساختگی
sudo python3 cdp_advertiser_linux.py --iface eth0 \
    --hostname LAB-SW2 --platform "cisco WS-C2960-24TT-L" \
    --port GigabitEthernet0/5 --capabilities switch,igmp

# تبلیغ یک IP مشخص (پیش‌فرض: IP خود کارت)
sudo python3 cdp_advertiser_linux.py --iface eth0 --ip 10.8.4.200

# روی ترانک، VLAN بومی را هم اعلام کن
sudo python3 cdp_advertiser_linux.py --iface eth0 --vlan 10

# فقط ۳ فریم بفرست و خارج شو (برای تست سریع)
sudo python3 cdp_advertiser_linux.py --iface eth0 --count 3 --interval 5

# فقط فریم را بساز و چاپ کن، هیچ چیز ارسال نشود
sudo python3 cdp_advertiser_linux.py --iface eth0 --dry-run

# MAC دلخواه در فریم (مثلاًMAC سوئیچ قدیمی)
sudo python3 cdp_advertiser_linux.py --iface eth0 --mac 00:1B:0C:11:22:33
```

| گزینه | کار |
|---|---|
| `--hostname` | Device ID در `show cdp neighbors` |
| `--platform` | متن Platform |
| `--port` | Port ID اعلامی |
| `--capabilities` | `switch,igmp` (پیش‌فرض)، `router`، `host`، … |
| `--ttl` | Holdtime، پیش‌فرض ۱۸۰ ثانیه |
| `--interval` | فاصله‌ی ارسال، پیش‌فرض ۶۰ ثانیه |
| `--count` | تعداد فریم، `0` = بی‌نهایت |
| `--vlan` | اعلام Native VLAN (به‌طور پیش‌فرض اعلام نمی‌شود) |
| `--no-address` | حذف کامل TLV آدرس |
| `--dry-run` | فقط ساخت و نمایش فریم |
| `-v` | هکس‌دامپ هر فریم |

## ۶. اجرای دائمی (اختیاری)

اگر می‌خواهید بعد از بستن SSH هم ادامه دهد:

```sh
sudo nohup python3 cdp_advertiser_linux.py --iface eth0 \
    > /var/log/cdpneighbor.log 2>&1 &
```

توقف:

```sh
sudo pkill -f cdp_advertiser_linux.py
```

> سرویس systemd نساختم چون ابزار آزمایشگاهی است. اگر لازم شد بگویید تا
> یک unit ساده اضافه کنم.

## ۷. عیب‌یابی

| نشانه | علت / راه‌حل |
|---|---|
| `ERROR: AF_PACKET requires root` | با `sudo` اجرا کنید یا `run-linux.sh` را استفاده کنید. |
| `Permission denied on eth0` | همان مورد بالا؛ یا `sudo setcap cap_net_raw+ep $(readlink -f $(command -v python3))` |
| `Interface 'eth0' disappeared` | نام کارت را با `--list` بررسی کنید (`ip link`). |
| فریم می‌رود ولی سوئیچ چیزی نشان نمی‌دهد | ۱) `cdp enable` روی پورت ۲) پورت در VLAN درست باشد ۳) کابل/لینک up باشد ۴) `show cdp interface` |
| همسایه بعد از مدتی محو می‌شود | `--interval` باید کمتر از `--ttl` باشد (پیش‌فرض ۶۰ < ۱۸۰). |
| سوئیچ `Native VLAN mismatch` می‌دهد | `--vlan` را حذف کنید (پیش‌فرض همین است) یا VLAN درست را بدهید. |
| فریم روی پورت ترانک دیده نمی‌شود | فریم بدون تگ ارسال می‌شود و در VLAN بومی می‌نشیند؛ پورت را access کنید یا VLAN بومی را درست تنظیم کنید. |
| روی VirtualBox/VMware کار نمی‌کند | در حالت Bridged باید کار کند؛ در NAT خیر. |

بررسی اینکه فریم واقعاً از کارت خارج می‌شود (در ترمینال دوم):

```sh
sudo tcpdump -i eth0 -n -e -c 5 ether dst 01:00:0c:cc:cc:cc
```

اگر tcpdump فریم‌ها را دید ولی سوئیچ نه، مشکل سمت سوئیچ/کابل/VLAN است.

## ۸. تفاوت با نسخه‌ی ویندوز

| | ویندوز (`cdp_advertiser.py`) | لینوکس (`cdp_advertiser_linux.py`) |
|---|---|---|
| ارسال فریم | Npcap (`wpcap.dll`) | `AF_PACKET` (کرنل) |
| نصب درایور | لازم | نه |
| دسترسی لازم | Administrator | root / CAP_NET_RAW |
| درگیری با ESET | دارد | ندارد |
| فریم خروجی | یکسان (۲۳۵ بایت در تست مرجع) | یکسان |

> نسخه‌ی لینوکسی فقط روی لینوکس ارسال می‌کند. `--selftest` روی ویندوز هم
> اجرا می‌شود و فقط ساخت فریم را بررسی می‌کند.
