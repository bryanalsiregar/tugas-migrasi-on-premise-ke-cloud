# Migrasi Apikasi IT Inventory Manager ke Cloud

Projek migrasi ini merupakan migrasi dari aplikasi _on-premise_ menjadi _cloud_ dengan cara sinkronisasi.

Aplikasi original dapat diakses di tautan ini: [https://github.com/shantonus/it_inventory_management](https://github.com/shantonus/it_inventory_management)

Cara menjalankan aplikasi _on-premise_ dapat dilakukan dengan melihat file [README.md](https://github.com/shantonus/it_inventory_management/blob/main/README.md)

File ini akan menjelaskan cara menjalankan aplikasi ini yang sudah dapat di migrasi ke _cloud_

Disclaimer: Aplikasi yang dimigrasi adalah aplikasi web sehingga gunakan aplikasi web

Prerequisites:
1. Python 3
2. git

Langkah-langkah menjalankan aplikasi yang sudah dimigrasi:

1. Lakukan clone repositori ini

Jalankan `git clone https://github.com/bryanalsiregar/tugas-migrasi-on-premise-ke-cloud.git`

2. Pergi ke folder clone

Jalankan `cd tugas-migrasi-on-premise-ke-cloud`

3. Lakukan cp .env.example .env

Terdapat sebuah _environment key_ bernama `IT_INVENTORY_PG_URL` yang harus diisi dengan PostgreSQL.

4. Buat virtual environments

Jalankan `python -m venv .venv` dan akses virtual environment

5. Install packages yang dibutuhkan

Jalankan `pip install -r requirements.txt`

6. Jalankan aplikasi

Jalankan `python app.py`

7. Akses aplikasi di sini

Buka browser dan ketikkan: [http://127.0.0.1:8000](http://127.0.0.1:8000)

Gunakan credential default sebagai berikut:

*username*: admin

*password*: admin