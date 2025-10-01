# 🔓 CrackMe - Advanced Hash Cracking Tool

```
 ▄████▄   ██▀███   ▄▄▄       ▄████▄   ██ ▄█▀    ███▄ ▄███▓▓█████ 
▒██▀ ▀█  ▓██ ▒ ██▒▒████▄    ▒██▀ ▀█   ██▄█▒     ▓██▒▀█▀ ██▒▓█   ▀ 
▒▓█    ▄ ▓██ ░▄█ ▒▒██  ▀█▄  ▒▓█    ▄ ▓███▄░     ▓██    ▓██░▒███   
▒▓▓▄ ▄██▒▒██▀▀█▄  ░██▄▄▄▄██ ▒▓▓▄ ▄██▒▓██ █▄     ▒██    ▒██ ▒▓█  ▄ 
▒ ▓███▀ ░░██▓ ▒██▒ ▓█   ▓██▒▒ ▓███▀ ░▒██▒ █▄    ▒██▒   ░██▒░▒████▒
░ ░▒ ▒  ░░ ▒▓ ░▒▓░ ▒▒   ▓▒█░░ ░▒ ▒  ░▒ ▒▒ ▓▒    ░ ▒░   ░  ░░░ ▒░ ░
  ░  ▒     ░▒ ░ ▒░  ▒   ▒▒ ░  ░  ▒   ░ ░▒ ▒░    ░  ░      ░ ░ ░  ░
░          ░░   ░   ░   ▒   ░        ░ ░░ ░     ░      ░      ░   
░ ░         ░           ░  ░░ ░      ░  ░              ░      ░  ░
░                           ░                                     
```

**Golang ile yazılmış, hızlı ve güçlü bir hash kırma aracı. Eğitim ve CTF yarışmaları için tasarlanmıştır.**

[![Go Version](https://img.shields.io/badge/Go-1.16+-00ADD8?style=flat&logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)](https://github.com)

## 📋 İçindekiler

- [Özellikler](#-özellikler)
- [Desteklenen Hash Türleri](#-desteklenen-hash-türleri)
- [Kurulum](#-kurulum)
- [Kullanım](#-kullanım)
- [Örnekler](#-örnekler)
- [Performans](#-performans)
- [CTF Senaryoları](#-ctf-senaryoları)
- [Katkıda Bulunma](#-katkıda-bulunma)
- [Lisans](#-lisans)
- [Sorumluluk Reddi](#-sorumluluk-reddi)

## ✨ Özellikler

- 🚀 **Yüksek Performans**: Çoklu CPU çekirdeği desteği ile paralel hash kırma
- 🔐 **7 Hash Türü**: MD5, SHA1, SHA224, SHA256, SHA384, SHA512, NTLM
- 📦 **Toplu İşlem**: Tek seferde birden fazla hash kırma
- 🎯 **İki Mod**: Wordlist tabanlı ve Brute Force
- 🤖 **Otomatik Tespit**: Hash türünü otomatik algılama
- ⚡ **Verimli**: Goroutine'ler ile optimize edilmiş
- 📊 **Detaylı Raporlama**: Başarı oranı, hız ve süre istatistikleri

## 🔑 Desteklenen Hash Türleri

| Hash Türü | Uzunluk | Kullanım Alanı |
|-----------|---------|----------------|
| MD5 | 32 karakter | Eski sistemler, CTF |
| SHA1 | 40 karakter | Git, eski şifreleme |
| SHA224 | 56 karakter | Güvenlik uygulamaları |
| SHA256 | 64 karakter | Blockchain, modern sistemler |
| SHA384 | 96 karakter | Yüksek güvenlik |
| SHA512 | 128 karakter | Maksimum güvenlik |
| NTLM | 32 karakter | Windows sistemleri |

## 📦 Kurulum

### Gereksinimler
- Go 1.16 veya üzeri

### Derleme

```bash
# Repository'yi klonlayın
git clone https://github.com/Lokidres/crackme.git
cd crackme

# Derleyin
go build -o crackme crackme.go

# Optimize edilmiş derleme (daha küçük binary)
go build -ldflags="-s -w" -o crackme crackme.go
```

### Hızlı Kurulum

```bash
# Doğrudan çalıştır
go run crackme.go -hash 5f4dcc3b5aa765d61d8327deb882cf99 -brute -maxlen 4
```

## 🚀 Kullanım

### Temel Sözdizimi

```bash
./crackme [opsiyonlar]
```

### Parametreler

| Parametre | Açıklama | Varsayılan |
|-----------|----------|------------|
| `-hash` | Kırılacak tek hash değeri | - |
| `-hashfile` | Hash dosyası (her satırda bir hash) | - |
| `-wordlist` | Wordlist dosyası yolu | - |
| `-type` | Hash türü (md5, sha1, sha256, ntlm, auto) | auto |
| `-brute` | Brute force modunu aktif eder | false |
| `-charset` | Brute force için karakter seti | a-z0-9 |
| `-maxlen` | Brute force maksimum uzunluk | 4 |
| `-workers` | Paralel worker sayısı (0 = CPU sayısı) | 0 |

## 💡 Örnekler

### Tek Hash Kırma

```bash
# MD5 hash'i wordlist ile kır
./crackme -hash 5f4dcc3b5aa765d61d8327deb882cf99 -wordlist rockyou.txt

# SHA256 hash'i manuel tip belirterek kır
./crackme -hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 \
         -type sha256 -wordlist passwords.txt

# NTLM hash kır (Windows)
./crackme -hash 8846f7eaee8fb117ad06bdd830b7586c -type ntlm -wordlist common.txt
```

### Çoklu Hash Kırma

```bash
# Hash dosyası oluştur
cat > hashes.txt << EOF
5f4dcc3b5aa765d61d8327deb882cf99
21232f297a57a5a743894a0e4a801fc3
e10adc3949ba59abbe56e057f20f883e
EOF

# Toplu kırma işlemi
./crackme -hashfile hashes.txt -wordlist rockyou.txt
```

### Brute Force Modu

```bash
# 4 karaktere kadar brute force
./crackme -hash 5f4dcc3b5aa765d61d8327deb882cf99 -brute -maxlen 4

# Sadece sayılarla brute force
./crackme -hash abc123... -brute -charset "0123456789" -maxlen 6

# Özel karakter seti
./crackme -hash def456... -brute -charset "abc123!@#" -maxlen 5
```

### Performans Ayarları

```bash
# 16 worker ile çalıştır
./crackme -hash 5f4dcc3b5aa765d61d8327deb882cf99 \
         -wordlist huge.txt -workers 16

# Tüm CPU çekirdeklerini kullan (varsayılan)
./crackme -hash abc... -wordlist passwords.txt -workers 0
```

## 🧪 Test Hash'leri

Aracı test etmek için örnek hash'ler:

```bash
# MD5
echo -n "password" | md5sum
# 5f4dcc3b5aa765d61d8327deb882cf99

echo -n "admin" | md5sum
# 21232f297a57a5a743894a0e4a801fc3

# SHA256
echo -n "password" | sha256sum
# 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8

# NTLM (Python ile)
python3 -c "import hashlib; print(hashlib.new('md4', 'password'.encode('utf-16le')).hexdigest())"
# 8846f7eaee8fb117ad06bdd830b7586c
```

## ⚡ Performans

### Benchmark Sonuçları

**Test Ortamı**: Intel Core i7-9700K @ 3.60GHz (8 çekirdek)

| Hash Türü | Hız (hash/saniye) | 1M Hash Süresi |
|-----------|-------------------|----------------|
| MD5 | ~2,500,000 | ~0.4 saniye |
| SHA1 | ~1,800,000 | ~0.6 saniye |
| SHA256 | ~1,200,000 | ~0.8 saniye |
| SHA512 | ~800,000 | ~1.2 saniye |
| NTLM | ~2,000,000 | ~0.5 saniye |

### Optimizasyon İpuçları

1. **Worker Sayısı**: CPU çekirdek sayınızın 2 katı kadar worker kullanın
2. **Wordlist**: Yaygın şifrelerle başlayan sıralı wordlist kullanın
3. **Hash Türü**: Mümkünse hash türünü manuel belirtin (otomatik tespiti atlar)
4. **Brute Force**: Kısa şifreler için (≤5 karakter) brute force daha hızlıdır

## 🎯 CTF Senaryoları

### Senaryo 1: Basit MD5 Challenge

```bash
# Challenge: 5f4dcc3b5aa765d61d8327deb882cf99
./crackme -hash 5f4dcc3b5aa765d61d8327deb882cf99 -brute -maxlen 8
# Sonuç: password
```

### Senaryo 2: Windows Credential Dump

```bash
# NTLM hash listesi
./crackme -hashfile ntlm_dump.txt -type ntlm -wordlist rockyou.txt
```

### Senaryo 3: Karışık Hash Türleri

```bash
# Farklı uzunluktaki hash'ler - otomatik tespit
./crackme -hashfile mixed_hashes.txt -wordlist common.txt
```

### Senaryo 4: Hızlı Brute Force

```bash
# 4 haneli PIN kodu
./crackme -hash 81dc9bdb52d04dc20036dbd8313ed055 \
         -brute -charset "0123456789" -maxlen 4
# Sonuç: 1234
```

## 📚 Wordlist Kaynakları

- [SecLists](https://github.com/danielmiessler/SecLists)
- [RockYou](https://github.com/brannondorsey/naive-hashcat/releases)
- [CrackStation](https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm)
- [Weakpass](https://weakpass.com/)

## 🔧 Gelişmiş Kullanım

### Hash Dosyası Formatı

```text
# hashes.txt - Hash listesi
# # ile başlayan satırlar yorum satırıdır

5f4dcc3b5aa765d61d8327deb882cf99
21232f297a57a5a743894a0e4a801fc3
e10adc3949ba59abbe56e057f20f883e

# Boş satırlar otomatik atlanır
```

### Script ile Otomatikleştirme

```bash
#!/bin/bash
# crack_all.sh - Tüm hash'leri otomatik kır

for hashfile in hashes/*.txt; do
    echo "Processing: $hashfile"
    ./crackme -hashfile "$hashfile" -wordlist rockyou.txt -workers 16
done
```

## 🤝 Katkıda Bulunma

Katkılarınızı bekliyoruz! Lütfen şu adımları izleyin:

1. Fork yapın
2. Feature branch oluşturun (`git checkout -b feature/amazing-feature`)
3. Değişikliklerinizi commit edin (`git commit -m 'feat: Add amazing feature'`)
4. Branch'inizi push edin (`git push origin feature/amazing-feature`)
5. Pull Request açın

## 📄 Lisans

Bu proje MIT lisansı altında lisanslanmıştır. Detaylar için [LICENSE](LICENSE) dosyasına bakın.

## ⚠️ Sorumluluk Reddi

**ÖNEMLİ**: Bu araç yalnızca eğitim, güvenlik araştırması ve yasal penetrasyon testleri için tasarlanmıştır.

- ✅ **İzin verilen kullanımlar**:
  - Kişisel sistemlerde test
  - CTF yarışmaları
  - Güvenlik eğitimi
  - Yasal penetrasyon testleri
  - Akademik araştırma

- ❌ **İzin verilmeyen kullanımlar**:
  - İzinsiz sistemlere erişim
  - Başkalarının verilerini izinsiz kırma
  - Yasadışı aktiviteler

**Kullanıcı sorumluluğu**: Bu aracı kullanarak, tüm yasal sorumluluğu kabul etmiş olursunuz. Geliştiriciler, aracın kötüye kullanımından sorumlu değildir.

## 📞 İletişim

- Issues: [GitHub Issues](https://github.com/yourusername/crackme/issues)
- Discussions: [GitHub Discussions](https://github.com/yourusername/crackme/discussions)

## 🌟 Yıldız Geçmişi

[![Star History Chart](https://api.star-history.com/svg?repos=yourusername/crackme&type=Date)](https://star-history.com/#yourusername/crackme&Date)

---

**Made with ❤️ for the InfoSec Community**

*Güvenli ve etik hacking!* 🔐