const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const path = require('path');
const crypto = require('crypto');
const twilio = require('twilio');
const { Pool } = require('pg');
const multer = require('multer');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const webpush = require('web-push');
const QRCode = require('qrcode');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const SIGNING_SECRET = JWT_SECRET || crypto.randomBytes(32).toString('hex');
if (!JWT_SECRET) console.warn('WARNING: JWT_SECRET not set. Using ephemeral secret.');

app.set('trust proxy', 1);
const allowedOrigins = (process.env.ALLOWED_ORIGINS || '').split(',').map(x => x.trim()).filter(Boolean);

app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(cors({
  origin: (origin, cb) => {
    if (!origin || allowedOrigins.length === 0 || allowedOrigins.includes(origin)) return cb(null, true);
    cb(new Error('Origin not allowed'));
  },
  methods: ['GET','POST','PATCH','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization'],
  credentials: false
}));
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: false, limit: '2mb' }));

const apiLimiter = rateLimit({ windowMs: 60*1000, max: 200, standardHeaders: true, legacyHeaders: false });
app.use('/api/', apiLimiter);
const authLimiter = rateLimit({ windowMs: 15*60*1000, max: 30, standardHeaders: true, legacyHeaders: false });

app.use(express.static(path.join(__dirname, 'public'), { dotfiles: 'deny', index: false }));
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 6*1024*1024 } });

/* ---------------- Database ---------------- */
const pool = process.env.DATABASE_URL
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: process.env.DATABASE_SSL === 'false' ? false : { rejectUnauthorized: false }
    })
  : null;

async function q(text, params = []) {
  if (!pool) throw new Error('DATABASE_NOT_CONFIGURED');
  return (await pool.query(text, params)).rows;
}

async function initDb() {
  if (!pool) { console.warn('No DATABASE_URL — running in memory mode.'); return; }
  await pool.query(`
    create extension if not exists pgcrypto;
    create table if not exists users(id uuid primary key default gen_random_uuid(),phone text unique not null,email text,full_name text,role text default 'customer',verified boolean default false,status text default 'active',created_at timestamptz default now(),updated_at timestamptz default now());
    create table if not exists orders(id text primary key,customer_phone text not null,customer_name text,vendor text not null,items jsonb default '[]',subtotal numeric default 0,delivery_fee numeric default 8,total numeric default 0,currency text default 'GHS',status text default 'Order created',rider_phone text,pickup_code text default '4821',delivery_pin text default '7392',delivery_address jsonb,note text,created_at timestamptz default now(),updated_at timestamptz default now());
    create table if not exists bookings(id text primary key,customer_phone text not null,customer_name text,hotel text not null,room text not null,check_in date,check_out date,nights int default 1,guests int default 1,total numeric default 0,currency text default 'GHS',status text default 'BOOKED',checkin_code text not null,checked_in_at timestamptz,checked_in_by text,created_at timestamptz default now(),updated_at timestamptz default now());
    create table if not exists rider_earnings(id bigserial primary key,rider_phone text not null,order_id text not null,amount numeric default 0,day date default current_date,created_at timestamptz default now());
    create table if not exists audit_logs(id bigserial primary key,actor text,action text,entity_type text,entity_id text,meta jsonb,created_at timestamptz default now());
    create index if not exists orders_customer_idx on orders(customer_phone,created_at desc);
    create index if not exists orders_rider_idx on orders(rider_phone,updated_at desc);
    create index if not exists bookings_hotel_idx on bookings(hotel,created_at desc);
    create index if not exists bookings_code_idx on bookings(checkin_code);
    create index if not exists earnings_rider_day_idx on rider_earnings(rider_phone,day);
  `);
}

/* ---------------- Memory fallback ---------------- */
const mem = {
  users: new Map(), orders: new Map(), bookings: new Map(),
  earnings: [], audit: []
};

/* ---------------- Twilio / OTP ---------------- */
function normalizePhone(p) { return String(p || '').replace(/[\s()-]/g, ''); }
function validE164(p) { return /^\+[1-9]\d{7,14}$/.test(p); }

const twilioOk = !!(process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN && process.env.TWILIO_VERIFY_SERVICE_SID);
const twilioClient = twilioOk ? twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN) : null;

async function sendOtp(phone) {
  if (twilioOk) {
    const v = await twilioClient.verify.v2.services(process.env.TWILIO_VERIFY_SERVICE_SID)
      .verifications.create({ to: phone, channel: 'sms' });
    return { provider: 'twilio', status: v.status };
  }
  if (process.env.DEV_OTP === 'true') {
    global.devOtps = global.devOtps || new Map();
    const code = String(Math.floor(100000 + Math.random() * 900000));
    global.devOtps.set(phone, { code, expires: Date.now() + 300000 });
    console.log('[DEV OTP]', phone, code);
    return { provider: 'development', status: 'pending', devOtp: code };
  }
  throw Object.assign(new Error('OTP service not configured'), { statusCode: 503 });
}

async function verifyOtp(phone, code) {
  if (twilioOk) {
    return twilioClient.verify.v2.services(process.env.TWILIO_VERIFY_SERVICE_SID)
      .verificationChecks.create({ to: phone, code });
  }
  const r = global.devOtps?.get(phone);
  if (!r || Date.now() > r.expires) return { status: 'canceled' };
  global.devOtps.delete(phone);
  return { status: r.code === code ? 'approved' : 'pending' };
}

/* ---------------- Roles & auth ---------------- */
function configuredRole(phone) {
  const admins = (process.env.ADMIN_PHONES || '').split(',').map(normalizePhone).filter(Boolean);
  return admins.includes(phone) ? 'admin' : 'customer';
}

async function getUser(phone) {
  if (pool) {
    const r = await q('select * from users where phone=$1', [phone]);
    return r[0];
  }
  return mem.users.get(phone);
}

async function upsertUser(phone) {
  const role = configuredRole(phone);
  if (pool) {
    const r = await q(
      `insert into users(phone,role,verified) values($1,$2,true)
       on conflict(phone) do update set verified=true,
       role=case when $2='admin' then 'admin' else users.role end
       returning *`,
      [phone, role]
    );
    return r[0];
  }
  let u = mem.users.get(phone) || { phone, role, verified: true };
  u.verified = true;
  if (role === 'admin') u.role = 'admin';
  mem.users.set(phone, u);
  return u;
}

function auth(req, res, next) {
  try {
    const tok = (req.headers.authorization || '').replace(/^Bearer\s+/i, '').trim();
    req.user = jwt.verify(tok, SIGNING_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Authentication required' });
  }
}
function roles(...allowed) {
  return (req, res, next) => allowed.includes(req.user.role) ? next() : res.status(403).json({ error: 'Insufficient permissions' });
}
const adminOnly = roles('admin', 'superadmin');

async function audit(actor, action, type, id, meta = {}) {
  if (pool) {
    await q('insert into audit_logs(actor,action,entity_type,entity_id,meta) values($1,$2,$3,$4,$5)',
      [actor, action, type, id, JSON.stringify(meta)]).catch(() => {});
  } else {
    mem.audit.push({ actor, action, type, id, meta, at: new Date().toISOString() });
  }
}

/* ---------------- Health ---------------- */
app.get('/api/health', (req, res) => res.json({
  ok: true, service: 'ObuasiGo API',
  database: pool ? 'postgres' : 'memory',
  otp: twilioOk ? 'twilio-verify' : (process.env.DEV_OTP === 'true' ? 'development' : 'not-configured'),
  payments: process.env.FLW_SECRET_KEY ? 'flutterwave' : 'not-configured',
  push: process.env.VAPID_PUBLIC_KEY ? 'web-push' : 'not-configured',
  time: new Date().toISOString()
}));

/* ---------------- Auth ---------------- */
app.post('/api/auth/request-otp', authLimiter, async (req, res) => {
  const phone = normalizePhone(req.body.phone);
  if (!validE164(phone)) return res.status(400).json({ error: 'Use international format e.g. +233241234567' });
  try {
    const r = await sendOtp(phone);
    res.json({ ok: true, provider: r.provider, ...(r.devOtp ? { devOtp: r.devOtp } : {}) });
  } catch (e) {
    res.status(e.statusCode || 502).json({ error: 'Could not send OTP' });
  }
});

app.post('/api/auth/verify-otp', authLimiter, async (req, res) => {
  const phone = normalizePhone(req.body.phone);
  const code = String(req.body.code || '').trim();
  if (!validE164(phone) || !/^[0-9]{4,10}$/.test(code))
    return res.status(400).json({ error: 'Invalid phone or OTP' });
  try {
    const c = await verifyOtp(phone, code);
    if (c.status !== 'approved') return res.status(400).json({ error: 'Incorrect or expired OTP' });
    const user = await upsertUser(phone);
    const token = jwt.sign({ phone: user.phone, role: user.role || 'customer', verified: true },
      SIGNING_SECRET, { expiresIn: '7d' });
    res.json({ ok: true, token, user });
  } catch {
    res.status(502).json({ error: 'Could not verify OTP' });
  }
});

app.get('/api/me', auth, async (req, res) => {
  const u = await getUser(req.user.phone);
  res.json({ user: u || req.user });
});

app.patch('/api/me', auth, async (req, res) => {
  const fullName = String(req.body.fullName || '').slice(0, 120);
  const email = String(req.body.email || '').slice(0, 200);
  if (pool) {
    const r = await q('update users set full_name=$1,email=$2,updated_at=now() where phone=$3 returning *',
      [fullName, email, req.user.phone]);
    return res.json({ user: r[0] });
  }
  const u = mem.users.get(req.user.phone) || { phone: req.user.phone, role: 'customer' };
  u.full_name = fullName; u.email = email;
  mem.users.set(u.phone, u);
  res.json({ user: u });
});

/* ---------------- Catalog ---------------- */
const CATALOG = {
  restaurants: [
    { id: 'r1', name: 'Obuasi Kitchen', emoji: '🍗', tags: 'Jollof · Chicken', eta: '25–35 min',
      items: [
        { id: 'i1', name: 'Jollof + Chicken', price: 38, emoji: '🍗' },
        { id: 'i2', name: 'Fried Rice + Beef', price: 42, emoji: '🍛' },
        { id: 'i3', name: 'Chicken Wings (6pc)', price: 30, emoji: '🍗' },
        { id: 'i4', name: 'Soft Drink', price: 8, emoji: '🥤' }
      ]},
    { id: 'r2', name: 'Pizza Hub Obuasi', emoji: '🍕', tags: 'Pizza · Fast food', eta: '30–40 min',
      items: [
        { id: 'i5', name: 'Pepperoni Pizza', price: 65, emoji: '🍕' },
        { id: 'i6', name: 'Margherita', price: 55, emoji: '🍕' },
        { id: 'i7', name: 'Garlic Bread', price: 20, emoji: '🥖' }
      ]},
    { id: 'r3', name: 'Ashanti Chop Bar', emoji: '🥘', tags: 'Local food · Home style', eta: '20–30 min',
      items: [
        { id: 'i8', name: 'Fufu + Light Soup', price: 34, emoji: '🥘' },
        { id: 'i9', name: 'Banku + Tilapia', price: 48, emoji: '🐟' },
        { id: 'i10', name: 'Waakye Special', price: 32, emoji: '🍚' }
      ]}
  ],
  hotels: [
    { id: 'h1', name: 'Obuasi Royal Hotel', room: 'Executive Room', perks: 'Wi‑Fi · Breakfast', price: 450 },
    { id: 'h2', name: 'Golden View Lodge', room: 'Comfort Room', perks: 'Parking · Pool', price: 320 }
  ]
};
app.get('/api/catalog', (req, res) => res.json(CATALOG));

/* ---------------- Orders ---------------- */
const ORDER_FLOW = [
  'Order created','Payment confirmed','Restaurant accepted','Preparing','Food ready',
  'Rider assigned','Rider accepted','Rider arrived','Food picked up','Going to customer',
  'Arrived at customer','Customer PIN verified','Completed'
];

function makeId(prefix, n = 5) {
  return prefix + Math.floor(Math.pow(10, n - 1) + Math.random() * Math.pow(10, n) - Math.pow(10, n - 1));
}

app.post('/api/orders', auth, async (req, res) => {
  const items = Array.isArray(req.body.items) ? req.body.items : [];
  if (!items.length) return res.status(400).json({ error: 'Cart is empty' });
  const subtotal = items.reduce((n, i) => n + Number(i.price || 0) * Number(i.qty || 0), 0);
  const deliveryFee = Number(req.body.deliveryFee ?? 8);
  const total = Number(req.body.total ?? (subtotal + deliveryFee));
  const order = {
    id: makeId('OBU-'),
    customer_phone: req.user.phone,
    customer_name: req.body.customerName || null,
    vendor: String(req.body.vendor || 'Obuasi Kitchen').slice(0, 80),
    items,
    subtotal, delivery_fee: deliveryFee, total,
    currency: 'GHS',
    status: 'Order created',
    pickup_code: String(1000 + Math.floor(Math.random() * 9000)),
    delivery_pin: String(1000 + Math.floor(Math.random() * 9000)),
    delivery_address: req.body.deliveryAddress || { text: '' },
    note: String(req.body.note || '').slice(0, 300)
  };
  if (pool) {
    await q(
      `insert into orders(id,customer_phone,customer_name,vendor,items,subtotal,delivery_fee,total,status,pickup_code,delivery_pin,delivery_address,note)
       values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
      [order.id, order.customer_phone, order.customer_name, order.vendor, JSON.stringify(items),
       subtotal, deliveryFee, total, order.status, order.pickup_code, order.delivery_pin,
       JSON.stringify(order.delivery_address), order.note]
    );
  } else {
    mem.orders.set(order.id, order);
  }
  await audit(req.user.phone, 'order.created', 'order', order.id, { total });
  res.status(201).json(order);
});

app.get('/api/orders', auth, async (req, res) => {
  if (pool) return res.json(await q('select * from orders where customer_phone=$1 order by created_at desc', [req.user.phone]));
  res.json([...mem.orders.values()].filter(o => o.customer_phone === req.user.phone));
});

/* Customer can simulate next step in demo mode */
app.patch('/api/orders/:id/status', auth, async (req, res) => {
  const s = String(req.body.status || '').slice(0, 40);
  if (!ORDER_FLOW.includes(s)) return res.status(400).json({ error: 'Invalid status' });

  if (pool) {
    const existing = (await q('select * from orders where id=$1', [req.params.id]))[0];
    if (!existing) return res.status(404).json({ error: 'Order not found' });
    const canCustomer = existing.customer_phone === req.user.phone;
    const canRider = existing.rider_phone === req.user.phone && req.user.role === 'rider';
    const canOps = ['vendor', 'admin', 'superadmin'].includes(req.user.role);
    if (!canCustomer && !canRider && !canOps)
      return res.status(403).json({ error: 'Not allowed to update this order' });

    const r = await q(
      `update orders set status=$1, updated_at=now(),
        rider_phone=coalesce($2, rider_phone) where id=$3 returning *`,
      [s, canRider ? req.user.phone : (req.body.riderPhone || null), req.params.id]
    );

    if (s === 'Completed' && r[0].rider_phone) {
      await q('insert into rider_earnings(rider_phone,order_id,amount) values($1,$2,$3)',
        [r[0].rider_phone, r[0].id, 15]);
    }
    await audit(req.user.phone, 'order.status', 'order', req.params.id, { status: s });
    return res.json(r[0]);
  }

  const o = mem.orders.get(req.params.id);
  if (!o) return res.status(404).json({ error: 'Order not found' });
  if (o.customer_phone !== req.user.phone && !['vendor', 'rider', 'admin', 'superadmin'].includes(req.user.role))
    return res.status(403).json({ error: 'Not allowed' });
  o.status = s;
  if (req.user.role === 'rider') o.rider_phone = req.user.phone;
  if (s === 'Completed' && o.rider_phone) {
    mem.earnings.push({ rider_phone: o.rider_phone, order_id: o.id, amount: 15, day: new Date().toISOString().slice(0, 10) });
  }
  res.json(o);
});

/* ---------------- Bookings + QR ---------------- */
app.post('/api/bookings', auth, async (req, res) => {
  const hotel = String(req.body.hotel || '').slice(0, 80);
  const room = String(req.body.room || '').slice(0, 80);
  const checkIn = req.body.checkIn || null;
  const checkOut = req.body.checkOut || null;
  const guests = Math.max(1, Number(req.body.guests || 1));
  const total = Number(req.body.total || 0);
  const nights = Math.max(1, Math.round((new Date(checkOut) - new Date(checkIn)) / 86400000) || 1);
  const checkinCode = 'OBG-' + crypto.randomBytes(4).toString('hex').toUpperCase();
  const booking = {
    id: makeId('OBU-HL-'),
    customer_phone: req.user.phone,
    customer_name: req.body.customerName || null,
    hotel, room, check_in: checkIn, check_out: checkOut,
    nights, guests, total, currency: 'GHS',
    status: 'BOOKED', checkin_code: checkinCode
  };
  if (pool) {
    await q(
      `insert into bookings(id,customer_phone,customer_name,hotel,room,check_in,check_out,nights,guests,total,status,checkin_code)
       values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
      [booking.id, booking.customer_phone, booking.customer_name, hotel, room,
       checkIn, checkOut, nights, guests, total, 'BOOKED', checkinCode]
    );
  } else {
    mem.bookings.set(booking.id, booking);
  }
  await audit(req.user.phone, 'booking.created', 'booking', booking.id);
  res.status(201).json(booking);
});

app.get('/api/bookings', auth, async (req, res) => {
  if (pool) return res.json(await q('select * from bookings where customer_phone=$1 order by created_at desc', [req.user.phone]));
  res.json([...mem.bookings.values()].filter(b => b.customer_phone === req.user.phone));
});

/* QR payload endpoint — returns a PNG data URL */
app.get('/api/bookings/:id/qr', auth, async (req, res) => {
  let booking;
  if (pool) {
    const r = await q('select * from bookings where id=$1', [req.params.id]);
    booking = r[0];
  } else {
    booking = mem.bookings.get(req.params.id);
  }
  if (!booking) return res.status(404).json({ error: 'Booking not found' });
  if (booking.customer_phone !== req.user.phone && !['hotel','admin','superadmin'].includes(req.user.role))
    return res.status(403).json({ error: 'Not allowed' });

  const payload = {
    t: 'checkin',
    id: booking.id,
    code: booking.checkin_code,
    hotel: booking.hotel,
    exp: Date.now() + 1000 * 60 * 60 * 24 * 30
  };
  const token = jwt.sign(payload, SIGNING_SECRET);
  const png = await QRCode.toDataURL(token, { width: 512, margin: 1, errorCorrectionLevel: 'M' });
  res.json({ png, code: booking.checkin_code, bookingId: booking.id });
});

/* Portal: verify a scanned QR and check the guest in */
app.post('/api/portal/checkin', auth, roles('hotel','admin','superadmin'), async (req, res) => {
  const raw = String(req.body.qr || '').trim();
  const code = String(req.body.code || '').trim().toUpperCase();

  let booking = null;
  if (raw) {
    try {
      const decoded = jwt.verify(raw, SIGNING_SECRET);
      if (decoded.t !== 'checkin') return res.status(400).json({ error: 'Not a check-in code' });
      if (decoded.exp && decoded.exp < Date.now()) return res.status(400).json({ error: 'Code expired' });
      if (pool) {
        const r = await q('select * from bookings where id=$1 and checkin_code=$2', [decoded.id, decoded.code]);
        booking = r[0];
      } else {
        booking = mem.bookings.get(decoded.id);
      }
    } catch {
      return res.status(400).json({ error: 'Invalid QR' });
    }
  } else if (code) {
    if (pool) {
      const r = await q('select * from bookings where checkin_code=$1', [code]);
      booking = r[0];
    } else {
      booking = [...mem.bookings.values()].find(b => b.checkin_code === code);
    }
  } else {
    return res.status(400).json({ error: 'Send qr or code' });
  }

  if (!booking) return res.status(404).json({ error: 'Booking not found' });
  if (req.user.role === 'hotel' && booking.hotel && !booking.hotel.toLowerCase().includes((req.body.hotel || '').toLowerCase()) && req.body.hotel) {
    // optional hotel-scope check if hotel name supplied
  }
  if (booking.status === 'CHECKED IN') return res.json({ ok: true, alreadyCheckedIn: true, booking });

  if (pool) {
    const r = await q(
      `update bookings set status='CHECKED IN', checked_in_at=now(), checked_in_by=$1, updated_at=now()
       where id=$2 returning *`,
      [req.user.phone, booking.id]
    );
    booking = r[0];
  } else {
    booking.status = 'CHECKED IN';
    booking.checked_in_at = new Date().toISOString();
    booking.checked_in_by = req.user.phone;
  }
  await audit(req.user.phone, 'booking.checkin', 'booking', booking.id);
  res.json({ ok: true, booking });
});

/* ---------------- Rider ---------------- */
app.get('/api/rider/earnings', auth, roles('rider','admin','superadmin'), async (req, res) => {
  const phone = req.user.role === 'rider' ? req.user.phone : (req.query.rider || req.user.phone);

  // build last 7 days
  const days = [];
  for (let i = 6; i >= 0; i--) {
    const d = new Date(); d.setDate(d.getDate() - i);
    days.push(d.toISOString().slice(0, 10));
  }

  let rows = [];
  if (pool) {
    rows = await q(
      `select day::text as day, sum(amount)::float as amount, count(*)::int as deliveries
       from rider_earnings
       where rider_phone=$1 and day >= current_date - interval '6 days'
       group by day`,
      [phone]
    );
  } else {
    rows = mem.earnings.filter(e => e.rider_phone === phone && days.includes(e.day))
      .reduce((acc, e) => {
        const row = acc.find(x => x.day === e.day) || (acc.push({ day: e.day, amount: 0, deliveries: 0 }), acc[acc.length - 1]);
        row.amount += Number(e.amount); row.deliveries += 1;
        return acc;
      }, []);
  }

  const series = days.map(d => {
    const r = rows.find(x => x.day === d);
    return { day: d, amount: r ? Number(r.amount) : 0, deliveries: r ? r.deliveries : 0 };
  });
  const total = series.reduce((n, s) => n + s.amount, 0);
  const today = series[series.length - 1].amount;
  res.json({ series, total, today, currency: 'GHS' });
});

app.get('/api/rider/requests', auth, roles('rider','admin','superadmin'), async (req, res) => {
  if (pool) {
    const rows = await q(
      `select * from orders
       where (status in ('Food ready','Rider assigned','Restaurant accepted','Preparing') or rider_phone=$1)
         and status <> 'Completed'
       order by created_at desc limit 20`,
      [req.user.phone]
    );
    return res.json(rows);
  }
  res.json([...mem.orders.values()].filter(o => o.status !== 'Completed'));
});

/* ---------------- Portal: admin / vendor / hotel views ---------------- */
app.get('/api/portal/overview', auth, adminOnly, async (req, res) => {
  if (pool) {
    const [[customers],[riders],[vendors],[hotels],[orders],[bookings],[checkins],[revenue]] = await Promise.all([
      q("select count(*) n from users where role='customer'"),
      q("select count(*) n from users where role='rider'"),
      q("select count(*) n from users where role='vendor'"),
      q("select count(*) n from users where role='hotel'"),
      q("select count(*) n from orders"),
      q("select count(*) n from bookings"),
      q("select count(*) n from bookings where status='CHECKED IN'"),
      q("select coalesce(sum(total),0) n from orders where status='Completed'")
    ]);
    return res.json({
      customers:+customers.n, riders:+riders.n, vendors:+vendors.n, hotels:+hotels.n,
      orders:+orders.n, bookings:+bookings.n, checkedIn:+checkins.n, revenue:+revenue.n
    });
  }
  res.json({
    customers: 1, riders: 1, vendors: 1, hotels: 2,
    orders: mem.orders.size, bookings: mem.bookings.size,
    checkedIn: [...mem.bookings.values()].filter(b => b.status === 'CHECKED IN').length,
    revenue: [...mem.orders.values()].filter(o => o.status === 'Completed').reduce((n, o) => n + o.total, 0)
  });
});

app.get('/api/portal/orders', auth, roles('vendor','admin','superadmin'), async (req, res) => {
  // Vendors see ONLY orders for their vendor name
  if (req.user.role === 'vendor') {
    const vendorName = String(req.query.vendor || '').trim();
    if (!vendorName) return res.status(400).json({ error: 'vendor query required for vendors' });
    if (pool) return res.json(await q('select * from orders where vendor=$1 order by created_at desc limit 100', [vendorName]));
    return res.json([...mem.orders.values()].filter(o => o.vendor === vendorName));
  }
  if (pool) return res.json(await q('select * from orders order by created_at desc limit 200'));
  res.json([...mem.orders.values()]);
});

app.get('/api/portal/bookings', auth, roles('hotel','admin','superadmin'), async (req, res) => {
  const hotel = req.user.role === 'hotel' ? String(req.query.hotel || '').trim() : '';
  if (pool) {
    if (hotel) return res.json(await q('select * from bookings where hotel=$1 order by created_at desc limit 200', [hotel]));
    return res.json(await q('select * from bookings order by created_at desc limit 200'));
  }
  const list = [...mem.bookings.values()];
  res.json(hotel ? list.filter(b => b.hotel === hotel) : list);
});

/* ---------------- Payment (Flutterwave) ---------------- */
async function flw(pathname, body) {
  const r = await fetch('https://api.flutterwave.com/v3' + pathname, {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + process.env.FLW_SECRET_KEY, 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  const d = await r.json();
  if (!r.ok) throw new Error(d.message || 'Flutterwave error');
  return d;
}

app.post('/api/payments/checkout', auth, async (req, res) => {
  if (!process.env.FLW_SECRET_KEY) return res.status(503).json({ error: 'Flutterwave not configured' });
  const amount = Number(req.body.amount);
  if (!(amount > 0)) return res.status(400).json({ error: 'Invalid amount' });
  const tx_ref = 'OBG-' + Date.now() + '-' + crypto.randomBytes(3).toString('hex');
  const base = process.env.APP_URL || `${req.protocol}://background${req.get('host')}`;
  try:# {
    const d = await flw('/payments', {
      tx_ref, amount, currency: 'GHS',
      redirect_url: `${base}/payment-return`,
      customer: {
        email: req.body.email || `${req.user.phone.replace('+', '')}@obuasigo.app`,
        name: req.body.name || 'ObuasiGo Customer',
        phonenumber: req.user.phone
      },
      payment_options: 'card,ghanamobilemoney',
      customizations: { title: 'ObuasiGo', description: req.body.description || 'ObuasiGo order' },
      meta: { entity_type: req.body.entityType || 'order', entity_id: req.body.entityId || '' }
    });
    res.json({ ok: true, tx_ref, link: d.data?.link });
  } catch (e) {
    res.status(502).json({ error: e.message });
  }
});

app.post('/api/webhooks/flutterwave', express.raw({ type: 'application/json' }), async (req, res) => {
  const hash = req.headers['verif-hash'];
  if (!process.env.FLW_SECRET_HASH || hash !== process.env.FLW_SECRET_HASH) return res.status(401).end();
  let body; try { body = JSON.parse(req.body.toString()); } catch { return res.status(400).end(); }
  const tx = body.data || body;
  if (tx.tx_ref) {
    await audit('flutterwave', 'webhook', 'payment', tx.tx_ref, { status: tx.status }).catch(() => {});
  }
  res.json({ ok: true });
});

/* ---------------- WebSocket tracking ---------------- */
const sockets = new Map();
let WebSocket;
try { WebSocket = require('ws'); } catch {}
function broadcast(orderId, msg) {
  for (const ws of sockets.get(orderId) || []) {
    if (ws.readyState === 1) ws.send(JSON.stringify(msg));
  }
}

app.post('/api/tracking/:orderId', auth, roles('rider','admin','superadmin'), async (req, res) => {
  const lat = Number(req.body.lat), lng = Number(req.body.lng);
  if (!Number.isFinite(lat) || !Number.isFinite(lng)) return res.status(400).json({ error: 'Invalid coordinates' });
  const p = { orderId: req.params.orderId, lat, lng, accuracy: Number(req.body.accuracy || 0), at: new Date().toISOString() };
  broadcast(p.orderId, { type: 'location', ...p });
  res.json({ ok: true, p });
});

/* ---------------- Push ---------------- */
const vapidReady = !!(process.env.VAPID_PUBLIC_KEY && process.env.VAPID_PRIVATE_KEY && process.env.VAPID_SUBJECT);
if (vapidReady) webpush.setVapidDetails(process.env.VAPID_SUBJECT, process.env.VAPID_PUBLIC_KEY, process.env.VAPID_PRIVATE_KEY);

app.get('/api/push/public-key', (req, res) => res.json({ configured: vapidReady, publicKey: vapidReady ? process.env.VAPID_PUBLIC_KEY : null }));

/* ---------------- Documents (Supabase Storage) ---------------- */
app.post('/api/documents', auth, upload.single('document'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'File required' });
  const allowed = ['image/jpeg', 'image/png', 'application/pdf'];
  if (!allowed.includes(req.file.mimetype)) return res.status(400).json({ error: 'JPG, PNG or PDF only' });
  let url = null;
  if (process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY && process.env.SUPABASE_STORAGE_BUCKET) {
    const { createClient } = require('@supabase/supabase-js');
    const sb = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);
    const p = `documents/${req.user.phone.replace(/\W/g, '_')}/${Date.now()}-${req.file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_')}`;
    const up = await sb.storage.from(process.env.SUPABASE_STORAGE_BUCKET)
      .upload(p, req.file.buffer, { contentType: req.file.mimetype, upsert: false });
    if (up.error) return res.status(502).json({ error: 'Storage failed' });
    url = up.data.path;
  }
  res.status(201).json({ ok: true, url });
});

/* ---------------- SPA fallbacks ---------------- */
app.get('/payment-return', (req, res) => res.sendFile(path.join(__dirname, 'public', 'payment-return.html')));
app.get('/portal', (req, res) => res.sendFile(path.join(__dirname, 'public', 'portal.html')));
app.get('/portal.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'portal.html')));
app.get('/rider', (req, res) => res.sendFile(path.join(__dirname, 'public', 'rider.html')));
app.get('/rider.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'rider.html')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

/* ---------------- Boot ---------------- */
const httpServer = require('http').createServer(app);
if (WebSocket) {
  const wss = new WebSocket.Server({ server: httpServer, path: '/ws' });
  wss.on('connection', (ws, req) => {
    const u = new URL(req.url, 'http://localhost');
    const orderId = u.searchParams.get('orderId');
    const token = u.searchParams.get('token');
    try { jwt.verify(token || '', SIGNING_SECRET); } catch { return ws.close(1008, 'Unauthorized'); }
    if (!orderId) return ws.close(1008, 'Order required');
    if (!sockets.has(orderId)) sockets.set(orderId, new Set());
    sockets.get(orderId).add(ws);
    ws.on('close', () => sockets.get(orderId)?.delete(ws));
    ws.send(JSON.stringify({ type: 'connected', orderId }));
  });
}

initDb()
  .then(() => httpServer.listen(PORT, () => console.log(`ObuasiGo listening on ${PORT}`)))
  .catch(e => { console.error('DB init failed', e); process.exit(1); });