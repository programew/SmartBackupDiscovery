# راهنمای کشف خودکار شبکه — SmartBackupDiscovery 3.6

## شروع خودکار جستجوی فایل‌ها در ۳٫۶

۱. در تب **Discover files**، نام کاربری، رمز و Shareهای ویندوز یا اطلاعات SSH، مسیرهای لینوکس و سیاست Host Key را وارد کنید.
۲. در تب **Network inventory** گزینهٔ **Start file discovery automatically after network discovery** را روشن کنید.
۳. **Discover network** را بزنید. پس از کشف موفق شبکه، جستجوی فایل‌ها روی میزبان‌های مناسب شروع می‌شود و نتیجه در داشبورد نمایش داده می‌شود.

این گزینه در فایل تنظیمات ذخیره می‌شود و پیش‌فرض خاموش است. فقط سرویس‌هایی استفاده می‌شوند که برایشان نام کاربری تنظیم کرده‌اید. میزبان باید در همین اجرا کشف شده باشد و پورت SMB یا پورت SSH تنظیم‌شده‌اش باز باشد. نام کاربری و دسترسی مشترک برای هر نوع اتصال استفاده می‌شود؛ تنظیمات اختصاصی هر میزبان در فایل hosts در حالت خودکار خوانده نمی‌شود.

مسیرهای محلی و فهرست‌های دستی قدیمی وارد جستجوی خودکار نمی‌شوند. اگر میزبان مناسب پیدا نشود یا کشف شبکه شکست بخورد/لغو شود، اسکن فایل اجرا نمی‌شود. دکمهٔ **Stop** اجرای فعال و مرحلهٔ بعدی را متوقف می‌کند. دو اسکن هم‌زمان از GUI شروع نمی‌شوند. دکمهٔ دستی **Start file discovery** هم باقی است.

```powershell
SmartBackupDiscovery.exe network-discover --config .\settings.json --auto-discover --config-passphrase 'your-long-passphrase'
SmartBackupDiscovery.exe network-discover --config .\settings.json --no-auto-discover
```

آرگومان اول حالت خودکار را فعال می‌کند و `--no-auto-discover` آن را فقط برای همان اجرا خاموش می‌کند. رمز SMB و SSH را همچنان می‌توانید با `--password` و `--linux-password` بدهید. Host Key همچنان بررسی می‌شود و اعتماد به کلید جدید بدون انتخاب قبلی TOFU فعال نمی‌شود.

در پوشهٔ `binaries/windows-x64` فایل اجرایی ویندوز قرار دارد؛ پوشه را کامل استخراج کنید و .NET 10 Desktop Runtime نصب باشد. نسخهٔ `binaries/linux-x64` به Runtime دات‌نت ۱۰ نیاز دارد. سورس کامل و اسکریپت‌های build در پوشهٔ `SmartBackupDiscovery` هستند.

## هدف و مرز عملکرد

مرحلهٔ نخست دستور `network-discover` موجودی میزبان‌های IPv4 خصوصی را می‌سازد. اگر گزینهٔ شروع خودکار فعال باشد، مرحلهٔ جستجوی فایل‌ها پس از اتمام موفق آن اجرا می‌شود. در این مرحله هیچ نام کاربری یا رمزی استفاده نمی‌شود، Shareهای SMB فهرست نمی‌شوند، اتصال SSH/SFTP برقرار نمی‌شود و هیچ فایلی اسکن یا کپی نمی‌شود.

خروجی این مرحله «پیشنهاد برای بازبینی» است. پس از بررسی، ادمین می‌تواند میزبان‌های تأییدشده را جداگانه وارد مرحلهٔ Discover کند و Share، مسیر، حساب و سیاست Host Key را صریحاً تعیین کند.

## اجرای معمول

در Windows از تب **Network inventory** استفاده کنید، یا در خط فرمان اجرا کنید:

```powershell
SmartBackupDiscovery.exe network-discover
```

بدون `--cidr`، برنامه رنج‌های خصوصی متصل به کارت‌های شبکه و Routeهای مستقیمِ دارای اندازهٔ معقول را پیدا می‌کند. برای هر IP، سیگنال‌های محدود زیر بررسی می‌شوند:

- پاسخ ICMP؛
- Reverse DNS، فقط برای میزبان پاسخ‌گو؛
- رکورد موجود در ARP/Neighbor Cache سیستم اجراکننده؛
- امکان اتصال TCP به پورت 22 و 445 (قابل تنظیم).

## رنج صریح و مجاز

برای رنجی که خودتان بررسی کرده‌اید و مجوز Inventory آن را دارید:

```powershell
SmartBackupDiscovery.exe network-discover `
  --cidr 192.168.20.0/24 `
  --authorized-scope
```

چند رنج و استثنا نیز قابل تعریف است:

```powershell
SmartBackupDiscovery.exe network-discover `
  --cidr 192.168.20.0/24 `
  --cidr 10.44.8.0/23 `
  --exclude-cidr 192.168.20.1/32 `
  --exclude-cidr 10.44.9.0/25 `
  --authorized-scope
```

رنج عمومی پذیرفته نمی‌شود. بدون `--authorized-scope` نیز CIDR صریح رد می‌شود.

## رنج دوم یا اصطلاحاً «پنهان»

اگر روی همان شبکهٔ فیزیکی یک رنج IP دیگر وجود داشته باشد ولی سیستم اجراکننده برای آن IP/Route نداشته باشد، سه حالت داریم:

1. **Route مستقیم در سیستم وجود دارد:** اگر رنج خصوصی و اندازهٔ آن معقول باشد، در Inventory فعال وارد می‌شود.
2. **Route از Next Hop می‌گذرد یا خیلی بزرگ است:** فقط در فایل پیشنهادها ثبت می‌شود و خودکار Probe نمی‌شود.
3. **IPای از آن رنج قبلاً در ARP/Neighbor Cache دیده شده است:** یک پیشنهاد محافظه‌کارانهٔ `/24` همراه با شواهد ساخته می‌شود؛ خود آن رنج Probe نمی‌شود.

فایل پیشنهادها:

```text
network-targets/suggested-private-scopes.generated.txt
```

برای فعال‌کردن یک پیشنهاد، ابتدا Route، مالکیت و مجوز را بررسی کنید و سپس CIDR دقیق را با `--authorized-scope` بدهید. برنامه برای این کار IP کارت شبکه، Mask، Route، Gateway، Firewall یا VLAN را تغییر نمی‌دهد.

اگر رنج دوم کاملاً ساکت باشد و هیچ Interface/Route، رکورد Neighbor، DNS یا تله‌متری مجاز دیگری دربارهٔ آن روی سیستم موجود نباشد، از یک میزبان عادی قابل کشف قطعی نیست. نبودن در خروجی به معنی نبودن چنین رنجی نیست.

## کنترل بار

پیش‌فرض‌ها محافظه‌کارانه‌اند. گزینه‌های مهم:

```text
--max-hosts 4096
--network-concurrency 32
--max-probes-per-second 64
--probe-timeout-ms 600
--max-cpu-percent 75
--network-limit-mbps 80
```

سقف سخت `--max-hosts` برابر 65,536 است. اگر حاصل رنج‌ها پس از اعمال استثناها از سقف بیشتر باشد، عملیات پیش از Probe متوقف می‌شود.

برای غیرفعال‌کردن یک سیگنال:

```text
--no-icmp
--no-dns
--no-neighbor-cache
--no-tcp-probes
```

برای افزودن پورت دلخواه، `--probe-port` را تکرار کنید. پورت باز صرفاً یک Hint است و تشخیص قطعی سیستم‌عامل محسوب نمی‌شود.

## خروجی‌ها

- `network-inventory.json`: موجودی کامل، Scope، Policy، هشدارها، پیشنهادها و Diff؛
- `network-inventory.csv`: جدول میزبان‌ها؛
- `windows-smb-hosts.generated.txt`: کاندیداهای SMB برای بازبینی؛
- `linux-sftp-hosts.generated.txt`: کاندیداهای SSH/SFTP برای بازبینی؛
- `unclassified-hosts.generated.txt`: میزبان‌های بدون Hint قطعی؛
- `suggested-private-scopes.generated.txt`: رنج‌های خصوصی پیشنهادی که فعالانه Probe نشده‌اند.

رکورد `NeighborCacheOnly` ممکن است قدیمی باشد. فایل‌های Generated را پیش از استفاده بازبینی کنید؛ Shareهای Windows، Rootهای Linux و سیاست SSH Host Key همچنان باید صریح باشند.
