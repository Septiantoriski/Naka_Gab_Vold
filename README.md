# Naka_Gab_Vold
Internal &amp; external use

## Customer Support Portal

Web app untuk mengelola inventaris customer support yang mencakup:

- Autentikasi pengguna (registrasi dan login) dengan SQLite.
- Dashboard input barang dengan visualisasi rak interaktif.
- Halaman profil untuk memperbarui data dan melihat statistik rak.

### Cara menjalankan

```bash
pip install -r requirements.txt
flask --app app.py run --debug
```

Secara otomatis basis data SQLite `support.db` akan dibuat di folder proyek saat aplikasi pertama kali dijalankan.
