# Sunucu Taşıma Kaydı — 30 Haziran 2026

Proje bir sunucudan diğerine taşındı. Bu belge, ileride dönüp bakıldığında ne
yapıldığını ve sistemin son halini anlatmak için tutulmuştur.

> Not: Parola / JWT secret / DB şifresi gibi gizli değerler **bilerek bu belgeye
> yazılmamıştır** (repo gizli bilgi içermesin diye). Tüm gizli değerler hedef
> sunucudaki `/home/nad/Emre-Ozel/.env` dosyasındadır.

---

## Özet

| | Kaynak (eski) | Hedef (yeni) |
|---|---|---|
| IP | `10.6.20.52` | `172.16.27.138` (Mac üzerinde VM) |
| Kullanıcı | `root` | `nad` (sudo yetkili) |
| Proje yolu | `/root/Emre-Ozel` | `/home/nad/Emre-Ozel` |
| OS | Ubuntu | Ubuntu 24.04.4 LTS |
| Disk | 824 GB (327 GB boş) | **9.8 GB (kısıtlı)** |
| Durum | **kapatıldı ve silindi** | **aktif, tek kopya** |

Çalıştırma: `docker compose -f docker-compose.prod.yml up -d` (5 servis).

---

## Verilen karar: "Sadece uygulama, veri yok"

Kaynak sunucudaki PostgreSQL veritabanı **131 GB** idi (`live_events` 113 GB,
`live_flows` 12 GB, `notifications` ~5.9 GB). Hedef sunucunun toplam diski sadece
**9.8 GB** olduğundan veritabanını taşımak fiziksel olarak mümkün değildi.

Bu yüzden yalnızca **uygulama kodu + yapılandırma** taşındı; hedef sunucu **boş
veritabanı** ile başladı. Kaynak sunucu sonradan **kapatılıp silindiği** için o
131 GB geçmiş veri **kalıcı olarak yok** (geri dönüşü yok).

---

## Yapılan adımlar

1. Proje dosyaları `10.6.20.52:/root/Emre-Ozel` → `172.16.27.138:/home/nad/Emre-Ozel`
   taşındı (Mac üzerinden `tar` pipe; `.git` ve `backups` hariç).
2. Hedef sunucuya **Docker 29.6.1 + Compose v5.2.0** kuruldu, `nad` docker grubuna eklendi.
3. `.env` yeni sunucuya göre güncellendi (aşağıdaki tablo).
4. Stack derlenip başlatıldı (`docker-compose.prod.yml`).
5. Şema oluşturulamadı sorunu çözüldü → `SKIP_MIGRATE=false` eklendi (aşağıda).
6. Build cache temizlendi (~2 GB geri kazanıldı).

### Yapılandırma değişiklikleri (eski → yeni)

| Ayar | Eski | Yeni | Sebep |
|---|---|---|---|
| `DOMAIN` (.env) | `10.6.20.52` | `172.16.27.138` | Yeni sunucu IP'si |
| `PACKET_INTERFACE` (.env) | `eth1` | `ens160` | Yeni sunucunun NIC adı |
| `SKIP_MIGRATE` (docker-compose.prod.yml, go-backend env) | (yok) | `false` | Bkz. aşağıdaki not |

### Neden `SKIP_MIGRATE=false` eklendi

Veritabanı şemasını eskiden (artık kaldırılan) Python backend oluşturuyordu. Go
backend, `SKIP_MIGRATE != false` olduğunda auto-migration'ı atlıyor. Boş yeni
veritabanında şema hiç oluşmadı; `users` tablosu yoktu, login "Invalid
credentials" veriyordu. `SKIP_MIGRATE=false` ile Go backend GORM auto-migration
çalıştırdı → **26 tablo** oluştu ve **admin** kullanıcısı seed edildi.

---

## Son durum (doğrulandı)

- 5/5 konteyner çalışıyor, 0 restart, kararlı: `pcap-postgres` (healthy),
  `pcap-go-backend` (healthy), `pcap-frontend`, `pcap-nginx`, `pcap-packet-engine`.
- `http://172.16.27.138/` → HTTP 200 (arayüz)
- `http://172.16.27.138/api/health` → `{"status":"ok","version":"3.0.0"}`
- Admin login → JWT token dönüyor; `/api/users` yetkili çağrı → HTTP 200
- Tüm servislerde restart policy `always`/`unless-stopped` → reboot sonrası otomatik başlar
- Disk: ~5.4 GB boş

### Giriş bilgileri
- Web arayüzü: kullanıcı `admin`, şifre = sunucudaki `.env` → `DEFAULT_PASS`
- Sunucu SSH ve `.env` içindeki diğer secret'lar repoya yazılmadı (yukarıdaki nota bakın).

---

## Bilinen sorun — packet-engine (canlı paket yakalama)

`pcap-packet-engine` paketleri yakalıyor ama go-backend'e **gönderemiyor**:

1. `network_mode: host` olduğundan Docker'ın `go-backend` DNS adını çözemiyor.
2. Daha önemlisi: hedef endpoint `/api/ingest/packet-events` Go backend'de
   **implemente edilmemiş** → `router.go` içinde `h.NotImplemented`, HTTP **501** dönüyor.

Bu, taşımadan kaynaklı bir regresyon **değil**; Python backend kaldırıldıktan
sonra Go tarafına taşınmamış bir özelliktir. Kaynak sunucuda da aynı durumdaydı.
Sürekli hata logu üretir ama diğer servisleri etkilemez.

> Çalışan veri yolu: syslog/netflow **collector** (go-backend doğrudan 5514/2055
> portlarını dinler). Canlı NIC paket yakalama özelliği kodda eksiktir.

---

## Uygulanmayan öneriler (kullanıcı isteğiyle "bu şekilde kalsın")

Aşağıdakiler bilerek **yapılmadı**, ileride gerekebilir diye not düşülmüştür:

- **Veritabanı yedeği yok:** Artık tek kopya. Düzenli `pg_dump` (compose'da
  `./backups` zaten postgres'e bağlı) önerilir.
- **Disk darlığı (9.8 GB):** Collector veri biriktirdikçe tablolar büyür ve
  diski doldurabilir. `.env` → `RETENTION_DAYS=30`; küçük disk için düşürmek
  (örn. 7) ya da diski büyütmek değerlendirilebilir.
- **packet-engine:** Devre dışı bırakılmadı; boşa hata logu üretmeye devam ediyor.
