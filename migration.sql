-- 1. Tabel admin_users (Untuk manajemen admin tambahan jika diperlukan)
CREATE TABLE admin_users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    full_name TEXT NOT NULL,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT, -- Opsional jika menggunakan Supabase Auth
    role TEXT NOT NULL DEFAULT 'Admin',
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 2. Tabel lookup_values (Sesuai struktur di app (1).py)
CREATE TABLE lookup_values (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(kind, value)
);

-- 3. Tabel People
CREATE TABLE people (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    full_name TEXT NOT NULL,
    department TEXT NOT NULL,
    email TEXT,
    phone TEXT,
    location TEXT,
    notes TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 4. Tabel Assets (Dengan kolom Visibility)
CREATE TABLE assets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_tag TEXT NOT NULL UNIQUE,
    device_name TEXT NOT NULL,
    category TEXT NOT NULL,
    brand TEXT,
    model TEXT,
    serial_number TEXT,
    status TEXT NOT NULL DEFAULT 'Available',
    condition TEXT NOT NULL DEFAULT 'Good',
    location TEXT,
    visibility TEXT NOT NULL DEFAULT 'public', -- 'public' or 'private'
    current_holder_id UUID REFERENCES people(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    added_by_id UUID -- ID user yang menambah aset
);

-- ==========================================
-- IMPLEMENTASI ROLE ACCESS & VISIBILITY (RLS)
-- ==========================================

-- Aktifkan Row Level Security pada tabel assets
ALTER TABLE assets ENABLE ROW LEVEL SECURITY;

-- POLICY 1: Jika visibility 'public', semua user terautentikasi bisa melihat
CREATE POLICY "Public assets are viewable by everyone" 
ON assets FOR SELECT 
USING (visibility = 'public');

-- POLICY 2: Jika visibility 'private', hanya orang di department yang sama dengan holder yang bisa melihat
-- Logika: Cek apakah department user yang login sama dengan department current_holder aset tersebut
CREATE POLICY "Private assets viewable by same department" 
ON assets FOR SELECT 
USING (
    visibility = 'private' 
    AND 
    (SELECT department FROM people WHERE id = assets.current_holder_id) = 
    (SELECT department FROM people WHERE id = auth.uid())
);