# 🛡️ LKS CTF Toolkit

<p align="center">
  <img src="https://img.shields.io/badge/Version-2.0-blue?style=for-the-badge" alt="Version">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/Made%20with-❤️-red?style=for-the-badge" alt="Made with love">
</p>

<p align="center">
  <b>Cyber Security Red Team Competition Tools</b><br>
  All-in-one offline toolkit untuk kompetisi CTF (Capture The Flag)
</p>

---

## 🎯 Overview

LKS CTF Toolkit adalah kumpulan tools berbasis web yang dirancang untuk membantu peserta dalam kompetisi **LKS (Lomba Kompetensi Siswa)** bidang Cyber Security. Toolkit ini dapat digunakan secara **offline** tanpa perlu instalasi atau koneksi internet.

## ✨ Features

### 🔐 Cryptography
- Classical ciphers (Caesar, Vigenere, ROT13, Atbash, dll)
- RSA Calculator & Auto Attack (Small e, Fermat, Trial Division)
- PRNG Crackers (LCG, MT19937)
- Hash identifier & generators
- XOR bruteforce
- Base encoding/decoding

### 🌐 Web Exploitation
- SQLi payload generator & cheatsheet
- XSS polyglot generator
- SSTI detection & payloads
- SSRF bypass techniques
- File upload bypass
- JWT decoder
- IDOR testing guide
- cURL builder

### 🔍 Forensics
- File analyzer (magic bytes detection)
- Hex viewer/editor
- String extractor with flag filter
- LSB steganography analyzer
- Metadata viewer
- Command cheatsheets (Volatility, Binwalk, Steghide)

### 🔧 Reverse Engineering
- x86/x64 register reference
- Calling conventions (Linux/Windows)
- Assembly instructions cheatsheet
- ELF header analysis
- XOR decoder & base converter
- Android RE tools (APKTool, Frida, Smali)
- GDB commands reference

### 💣 Binary Exploitation
- Buffer overflow offset calculator
- ret2win payload generator
- Format string attack calculator
- ROP chain techniques
- Libc database links
- Shellcode encoder
- Protection bypass guide (NX, CANARY, PIE, ASLR, RELRO)
- Pwntools template

## 📁 File Structure

```
LKS-CTF-Toolkit/
├── index.html      # Dashboard utama
├── crypto.html     # Cryptography tools
├── website.html    # Web exploitation tools
├── forensic.html   # Forensics tools
├── reverse.html    # Reverse engineering tools
├── binary.html     # Binary exploitation tools
└── README.md       # Dokumentasi
```

## 🚀 Quick Start

1. Clone repository ini:
```bash
git clone https://github.com/vian0001/LKS-CTF-Toolkit.git
```

2. Buka `index.html` di browser:
```bash
# Windows
start index.html

# Linux/Mac
open index.html
# atau
xdg-open index.html
```

3. Pilih kategori yang dibutuhkan dan mulai gunakan!

## 💻 Usage

### Offline Mode
Semua tools berjalan di browser tanpa perlu server. Cukup buka file HTML langsung.

### Quick Links
Setiap halaman menyediakan quick links ke tools online populer:
- [CyberChef](https://gchq.github.io/CyberChef/) - Swiss army knife for crypto
- [FactorDB](https://factordb.com/) - RSA factorization
- [CrackStation](https://crackstation.net/) - Hash lookup
- [Aperi'Solve](https://www.aperisolve.com/) - Steganography analysis
- [Dogbolt](https://dogbolt.org/) - Online decompiler

## 📸 Screenshots

### Dashboard
![Dashboard](screenshots/dashboard.png)

### Cryptography Tools
![Crypto](screenshots/crypto.png)

### Binary Exploitation
![Binary](screenshots/binary.png)

## 🏆 For LKS Competition

Toolkit ini dibuat khusus untuk kategori:
- **Cryptography** - Classical & modern ciphers
- **Web Exploitation** - OWASP Top 10 vulnerabilities
- **Forensics** - File analysis & steganography
- **Reverse Engineering** - Binary analysis
- **Binary Exploitation** - Memory corruption attacks

## 🤝 Contributing

Kontribusi sangat diterima! Silakan:
1. Fork repository ini
2. Buat branch baru (`git checkout -b feature/AmazingFeature`)
3. Commit perubahan (`git commit -m 'Add some AmazingFeature'`)
4. Push ke branch (`git push origin feature/AmazingFeature`)
5. Buka Pull Request

## 📝 License

Distributed under the MIT License. See `LICENSE` for more information.

## 👤 Author

**Jovian**
- Portfolio: [jovian.my.id](https://jovian.my.id)
- GitHub: [@vian0001](https://github.com/vian0001)

---

<p align="center">
  Made with ❤️ for LKS Cyber Security Competition<br>
  Good luck finding those flags! 🚩
</p>
