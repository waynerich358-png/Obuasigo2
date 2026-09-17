create extension if not exists pgcrypto;

create table if not exists users (
  id uuid primary key default gen_random_uuid(),
  phone text unique not null,
  email text,
  full_name text,
  role text not null default 'customer'
    check (role in ('customer','rider','vendor','hotel','admin','superadmin')),
  status text not null default 'active',
  verified boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists orders (
  id text primary key,
  customer_phone text not null,
  customer_name text,
  vendor text not null,
  items jsonb not null default '[]',
  subtotal numeric(12,2) not null default 0,
  delivery_fee numeric(12,2) not null default 8,
  total numeric(12,2) not null default 0,
  currency text not null default 'GHS',
  status text not null default 'Order created',
  rider_phone text,
  pickup_code text not null default '4821',
  delivery_pin text not null default '7392',
  delivery_address jsonb,
  note text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists bookings (
  id text primary key,
  customer_phone text not null,
  customer_name text,
  hotel text not null,
  room text not null,
  check_in date,
  check_out date,
  nights int not null default 1,
  guests int not null default 1,
  total numeric(12,2) not null default 0,
  currency text not null default 'GHS',
  status text not null default 'BOOKED'
    check (status in ('BOOKED','CHECKED IN','CHECKED OUT','CANCELLED')),
  checkin_code text not null,
  checked_in_at timestamptz,
  checked_in_by text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists rider_earnings (
  id bigserial primary key,
  rider_phone text not null,
  order_id text not null,
  amount numeric(12,2) not null,
  day date not null default current_date,
  created_at timestamptz not null default now()
);

create index if not exists orders_customer_idx on orders(customer_phone, created_at desc);
create index if not exists orders_rider_idx on orders(rider_phone, updated_at desc);
create index if not exists bookings_hotel_idx on bookings(hotel, created_at desc);
create index if not exists bookings_code_idx on bookings(checkin_code);
create index if not exists earnings_rider_day_idx on rider_earnings(rider_phone, day);