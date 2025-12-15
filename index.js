// index.js
require('dotenv').config(); // load .env (optional but recommended)

const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const crypto = require('crypto');
const axios = require('axios');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const User = require('./models/User'); // make sure path & filename match
const app = express();
const port = process.env.PORT || 4000;
const {google} = require('googleapis');
// index.js (add near the bottom, after routes and DB connection)
const cron = require('node-cron');

// Helper to lazily expire a single user
async function expirePremiumIfNeededForUser(user) {
  let changed = false;
  const now = Date.now();
  if (user.premiumUser && user.premiumUntil && user.premiumUntil <= now) {
    user.premiumUser = false;
    user.premiumPlanKey = undefined;
    user.premiumUntil = 0;
    user.adsOn = true;

    // revert conversion factor if we stored previousConversionFactor
    if (user.mining && typeof user.mining.previousConversionFactor === 'number') {
      user.mining.conversionFactor = user.mining.previousConversionFactor;
      delete user.mining.previousConversionFactor;
      changed = true;
    } else {
      // fallback to env default or keep as-is if not available
      const envDefault = process.env.MINING_CONVERSION_FACTOR ? Number(process.env.MINING_CONVERSION_FACTOR) : undefined;
      if (envDefault !== undefined && user.mining && user.mining.conversionFactor !== envDefault) {
        user.mining.conversionFactor = envDefault;
        changed = true;
      }
    }

    // optionally add a transaction/audit note
    user.transactions = user.transactions || [];
    user.transactions.push({
      type: 'purchase',
      note: 'Subscription expired — reverted to default (cron job)',
      createdAt: new Date()
    });

    changed = true;
  }
  if (changed) {
    await user.save();
  }
  return changed;
}

// Cron schedule: run at 00:00 every day in Asia/Kolkata
// node-cron supports a 'timezone' option.
cron.schedule('0 0 * * *', async () => {
  console.log('[cron] Running subscription expiry check (Asia/Kolkata) at', new Date().toISOString());
  try {
    // Find users who are marked premium and whose premiumUntil <= now
    const now = Date.now();
    const users = await User.find({ premiumUser: true, premiumUntil: { $lte: now } }).exec();

    if (!users || users.length === 0) {
      console.log('[cron] No expired premium users found.');
      return;
    }

    console.log(`[cron] Found ${users.length} expired premium users — updating...`);
    for (const user of users) {
      try {
        await expirePremiumIfNeededForUser(user);
        console.log(`[cron] Expired premium for user ${user._id} (${user.email})`);
      } catch (err) {
        console.error(`[cron] Failed to expire user ${user._id}:`, err);
      }
    }

    console.log('[cron] Subscription expiry check finished.');
  } catch (err) {
    console.error('[cron] Error during subscription expiry check:', err);
  }
}, {
  scheduled: true,
  timezone: 'Asia/Kolkata'
});


// Middleware
app.use(cors({
  origin: '*',          // Allow all domains
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: false }));

// MongoDB connection
const MONGO_URI =
  process.env.MONGODB_URI;

mongoose
  .connect(MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log('Connected to MongoDB'))
  .catch((err) => console.error('MongoDB connection error:', err));

// JWT secret — set this in .env for a stable secret
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
if (!process.env.JWT_SECRET) {
  console.warn(
    'WARNING: JWT_SECRET not set in .env. Using a random secret which will invalidate tokens on restart. Set JWT_SECRET in your .env to keep tokens valid across restarts.'
  );
}


/////////////////////////////////////////////   AUTH  /////////////////////////////////////////////


// Auth middleware
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ message: 'Authorization header missing' });

  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') {
    return res.status(401).json({ message: 'Invalid Authorization header format' });
  }

  const token = parts[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    // console.log("Auth middleware payload:", payload);
    req.userId = payload.userId;
    req.userEmail = payload.email;
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
}

/**
 * Register (email/password)
 * body: { name, email, password }
 */
app.post('/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password)
      return res.status(400).json({ message: 'name, email and password are required' });

    const existing = await User.findOne({ email });
    if (existing) {
      // If existing user has googleId but no password, inform them to use Google (or implement linking flow)
      if (existing.googleId && !existing.password) {
        return res.status(400).json({
          message:
            'An account with this email exists that uses Google sign-in. Please sign in with Google or link accounts in your app.',
        });
      }
      return res.status(400).json({ message: 'Email already registered' });
    }

    const user = new User({ name, email, password});
    await user.save();

    const token = jwt.sign({ userId: user._id, email: user.email }, JWT_SECRET, {
      expiresIn: '7d',
    });

    return res.status(201).json({ message: 'User registered', user: user.toJSON(), token });
  } catch (err) {
    console.error('Register error', err);
    return res.status(500).json({ message: 'Server error registering user' });
  }
});

/**
 * Login (email/password)
 * body: { email, password }
 */
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ message: 'email and password are required' });

    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ message: 'Invalid credentials' });

    // If user signed up with Google only and doesn't have a password
    if (user.googleId && !user.password) {
      return res.status(400).json({
        message: 'This account uses Google sign-in. Please sign in with Google.',
      });
    }


    const isMatch = await user.comparePassword(password);
    if (!isMatch) return res.status(401).json({ message: 'Invalid credentials' });

    const token = jwt.sign({ userId: user._id, email: user.email }, JWT_SECRET, {
      expiresIn: '7d',
    });

    return res.status(200).json({ message: 'Login successful', user: user.toJSON(), token });
  } catch (err) {
    console.error('Login error', err);
    return res.status(500).json({ message: 'Server error logging in' });
  }
});

/**
 * Google login
 * body: { idToken }
 * We verify idToken with Google's tokeninfo endpoint, then create or link a user.
 */
app.post('/google-login', async (req, res) => {
  console.log('Received /google-login request with body ...');
  const { idToken } = req.body;
  if (!idToken) return res.status(400).json({ message: 'idToken is required' });

  try {
    // Verify token with Google — returns token info including 'sub' (the Google user id)
    const response = await axios.get(`https://oauth2.googleapis.com/tokeninfo?id_token=${idToken}`);
    const data = response.data; // token info
    const { sub, email, name, picture } = data;

    if (!sub || !email) {
      return res.status(400).json({ message: 'Invalid Google token' });
    }

    // try find user by googleId or email (so we can link accounts)
    let user = await User.findOne({ $or: [{ googleId: sub }, { email }] });

    if (!user) {
      // create new user
      user = new User({
        googleId: sub,
        name,
        email,
        photo: picture,
      });
      await user.save();
    } else {
      // if found by email but googleId missing, link accounts
      let updated = false;
      if (!user.googleId) {
        user.googleId = sub;
        updated = true;
      }
      // update name/photo if they differ (optional)
      if (!user.name && name) {
        user.name = name;
        updated = true;
      }
      if (!user.photo && picture) {
        user.photo = picture;
        updated = true;
      }
      if (updated) await user.save();
    }

    const token = jwt.sign({ userId: user._id, email: user.email }, JWT_SECRET, {
      expiresIn: '7d',
    });

    // console.log('Google login successful for user:', user.toJSON());

    return res.status(200).json({ message: 'Google login successful', user: user.toJSON(), token });
  } catch (err) {
    console.error('Google login error', err?.response?.data || err.message || err);
    return res.status(400).json({ message: 'Google authentication failed', error: err.message || err });
  }
});


//////////////////////////////////////////////   ADMIN  /////////////////////////////////////////////


// --- Admin middleware: must be placed after authMiddleware definition ---
async function adminMiddleware(req, res, next) {
  try {
    // authMiddleware should already have set req.userId
    if (!req.userId) return res.status(401).json({ message: 'Not authenticated' });

    const adminUser = await User.findById(req.userId).select('role');
    if (!adminUser) return res.status(401).json({ message: 'User not found' });

    if (adminUser.role !== 'admin') {
      return res.status(403).json({ message: 'Admin access required' });
    }

    // attach small user object for handler convenience
    req.user = adminUser;
    next();
  } catch (err) {
    console.error('adminMiddleware error', err);
    return res.status(500).json({ message: 'Server error in admin check' });
  }
}

/**
 * GET /admin/users
 * Query params:
 *   - page (default 1)
 *   - limit (default 50)
 *   - search (optional) - searches name or email (case-insensitive)
 */
app.get('/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    // ✅ Pagination and search handling
    console.log("Got a hit here .....")
    const page = Math.max(1, parseInt(req.query.page || '1', 10));
    const limit = Math.min(200, Math.max(1, parseInt(req.query.limit || '50', 10)));
    const search = req.query.search?.trim();

    // ✅ Query for normal (non-admin) users
    const query = { role: 'user' };

    // <<< CHANGED: support flexible search (name, email, and _id)
    if (search) {
      query.$or = [
        { email: { $regex: search, $options: 'i' } },
        { name: { $regex: search, $options: 'i' } },
        { _id: mongoose.Types.ObjectId.isValid(search) ? new mongoose.Types.ObjectId(search) : null },
      ].filter(Boolean); // remove nulls
    }

    // ✅ Pagination skip/limit logic
    const skip = (page - 1) * limit;

    // <<< CHANGED: get both list and total count in parallel
    const [users, total] = await Promise.all([
      User.find(query)
        .select('-password') // <<< keep password excluded
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean(), // <<< CHANGED: lean() for better performance
      User.countDocuments(query),
    ]);

    // <<< CHANGED: normalize id field (to support frontend .map normalization)
    const normalizedUsers = users.map((u) => ({
      ...u,
      id: u._id || u.id || u.userId || null,
    }));

    // <<< CHANGED: ensure meta always consistent with frontend expectations
    return res.status(200).json({
      users: normalizedUsers,
      meta: {
        total,
        page,
        limit,
        pages: Math.ceil(total / limit) || 1,
      },
    });
  } catch (err) {
    console.error('GET /admin/users error', err);
    return res.status(500).json({ message: 'Server error fetching users' });
  }
});


// PATCH → /admin/users/global
app.patch('/admin/users/global', authMiddleware, adminMiddleware, async (req, res) => {
  console.log("Global patch request received ....")
  try {
    const allowed = ['referOn', 'disclaimerOn', 'adsOn', 'walletOn'];
    const updates = {};

    allowed.forEach((key) => {
      if (Object.prototype.hasOwnProperty.call(req.body, key)) {
        updates[key] = !!req.body[key];
      }
    });

    if (Object.keys(updates).length === 0) {
      return res.status(400).json({ message: 'No valid fields provided.' });
    }

    // 🔥 Update all documents in one query
    const result = await User.updateMany({}, { $set: updates });
    return res.status(200).json({
      message: 'Global user settings updated',
      modifiedCount: result.modifiedCount,
    });
  } catch (err) {
    console.error('PATCH /admin/users/global error', err);
    res.status(500).json({ message: 'Server error updating all users' });
  }
});


/**
 * PATCH /admin/user/:id
 * Body: { referOn?, disclaimerOn?, adsOn? }
 * Updates toggles.
 */
// routes/admin.js (or wherever you keep admin routes)
app.patch('/admin/users/:id', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    console.log("Patch request received ....")
    const { id } = req.params;

    // <<< CHANGED: only allow these toggle fields to be updated via this endpoint
    const allowed = ['referOn', 'rateUsOn', 'adsOn'];
    const updates = {};

    allowed.forEach((key) => {
      if (Object.prototype.hasOwnProperty.call(req.body, key)) {
        // cast to boolean (defensive)
        updates[key] = !!req.body[key];
      }
    });

    if (Object.keys(updates).length === 0) {
      return res.status(400).json({ message: 'No allowed fields provided to update.' });
    }

    // Update and return the new user object (runValidators ensures schema validation)
    const user = await User.findByIdAndUpdate(id, updates, { new: true, runValidators: true });

    if (!user) return res.status(404).json({ message: 'User not found' });

    // remove sensitive fields before sending (like password)
    const userObj = user.toObject({ virtuals: true });
    delete userObj.password;

    return res.status(200).json({ message: 'User settings updated', user: userObj });
  } catch (err) {
    console.error('PATCH /admin/users/:id error', err);
    return res.status(500).json({ message: 'Server error updating user settings' });
  }
});


////////////////////////////////////////////// USER ///////////////////////////////////////////////


/**
 * Protected route example — returns currently logged-in user
 * Authorization: Bearer <token>
 */
app.get('/user-info', authMiddleware, async (req, res) => {
  try {
    console.log("Getting user info .........");
    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ message: 'User not found' });

    // Prefer user's mining.conversionFactor, fall back to env default for legacy users
    const conversionFactor = (user.mining && typeof user.mining.conversionFactor === 'number')
      ? user.mining.conversionFactor
      : (process.env.MINING_CONVERSION_FACTOR ? Number(process.env.MINING_CONVERSION_FACTOR) : 0.000001);

    return res.status(200).json({ user: user.toJSON(), conversionFactor });
  } catch (err) {
    console.error('/me error', err);
    return res.status(500).json({ message: 'Server error' });
  }
});


app.get('/user-count', authMiddleware, async (req, res) => {
  console.log("User count request received ....")
  try {
    const totalUsers = await User.countDocuments({ role: 'user' });
    res.json({ totalUsers });
  } catch (err) {
    console.error('GET /admin/user-count error', err);
    res.status(500).json({ message: 'Server error fetching user count' });
  }
});


// ///////////////////////////////////////   Functioning /////////////////////////////////////////


// Example conversion factor from GH to BTC (set in config)
const GH_TO_BTC = 0.000001;

// start mining
app.post('/mining/start', authMiddleware, async (req, res) => {
  console.log("Mining start request received ....");
  const userId = req.userId;
  const now = Date.now();
  const sixtyMin = 60 * 60 * 1000;

  // 1️⃣ Load the user first (we need it to finalize previous session)
  const user = await User.findById(userId);
  if (!user) return res.status(404).json({ message: 'User not found' });

  // 2️⃣ If an old session was active or has just ended, finalize it
  if (user.mining?.isActive) {
    user.finalizeMiningSession(now, GH_TO_BTC);
    console.log('Finalized previous mining session, credited:', user.btcBalance);
  }

  // 3️⃣ Start new mining session from scratch
  user.mining.isActive = true;
  user.mining.startTimeMs = now;
  user.mining.endTimeMs = now + sixtyMin;
  user.mining.lastUpdatedMs = now;
  user.mining.accumulatedGh = 0;
  user.mining.speedGhPerSec = 30;
  user.mining.extensionMs = 0;
  user.mining.events = (user.mining.events || []).concat([{ type: 'start', at: now }]);

  // 4️⃣ Save and return the fully updated user (including btcBalance)
  await user.save();

  const snapshot = user.computeMiningSnapshot(now, GH_TO_BTC);
  return res.status(200).json({ user: user.toJSON(), mining: snapshot });
});


// in your api/index.js (or routes file)
app.post('/mining/extend', authMiddleware, async (req, res) => {
  console.log("Mining extend request received ....")
  try {
    console.log("Request body:", req.body);
    const userEmail = req.userEmail;
    console.log("User email from token:", userEmail);
    if (!userEmail) return res.status(401).json({ message: 'Unauthorized' });

    // extend minutes optionally provided by client (default 60)
    const minutesToAdd = Number(req.body?.minutes ?? 60);
    if (!Number.isFinite(minutesToAdd) || minutesToAdd <= 0) {
      return res.status(400).json({ message: 'Invalid minutes value' });
    }

    const now = Date.now();
    const addMs = minutesToAdd * 60 * 1000;

    // find user
    const user = await User.findOne({ email: userEmail });
    if (!user) return res.status(404).json({ message: 'User not found' });

    // ensure mining object
    user.mining = user.mining || {};

    // compute snapshot up to now to persist accumulatedGh (avoid double-counting)
    const snapshot = user.computeMiningSnapshot(now, GH_TO_BTC);

    // Determine new end time:
    // If session already has an endTime in the future, extend that; otherwise extend from now.
    const baseEnd = Math.max(user.mining.endTimeMs || now, now);
    const newEnd = baseEnd + addMs;

    // Persist changes
    user.mining.accumulatedGh = snapshot.accumulatedGh; // accumulate up to now
    user.mining.lastUpdatedMs = now;
    user.mining.endTimeMs = newEnd;
    user.mining.isActive = true; // if you want extensions to resume sessions
    user.mining.extensionMs = (user.mining.extensionMs || 0) + addMs;
    user.mining.extAdsWatched = (user.mining.extAdsWatched || 0) + 1;
    user.mining.events = user.mining.events || [];
    user.mining.events.push({ type: 'ad_extended', at: now, extraMinutes: minutesToAdd });

    await user.save();

    const newSnapshot = user.computeMiningSnapshot(now, GH_TO_BTC);
    return res.status(200).json({ user: user.toJSON(), mining: newSnapshot });
  } catch (err) {
    console.error('POST /mining/extend error', err);
    return res.status(500).json({ message: 'Server error' });
  }
});


// server route: POST /mining/speed
app.post('/mining/speed', authMiddleware, async (req, res) => {
  console.log("Mining speed boost request received ....")
  try {
    console.log("Request body:", req.body);
    
    const userEmail = req.userEmail;
    if (!userEmail) return res.status(401).json({ message: 'Unauthorized' });

    const targetSpeed = Number(req.body?.targetSpeed);
    const requiredAds = Number(req.body?.requiredAds || 0);

    if (![30, 45, 60].includes(targetSpeed)) {
      return res.status(400).json({ message: 'Invalid targetSpeed' });
    }
    if (targetSpeed === 45 && requiredAds < 1) {
      return res.status(400).json({ message: 'Option 1 requires 1 ad' });
    }
    if (targetSpeed === 60 && requiredAds < 2) {
      return res.status(400).json({ message: 'Option 2 requires 2 ads' });
    }

    const now = Date.now();

    // fetch user doc
    const user = await User.findOne({ email: userEmail });
    if (!user) return res.status(404).json({ message: 'User not found' });

    // ensure we have a mining object
    user.mining = user.mining || {};

    // require an active mining session (change this if you want to allow starting/resuming)
    if (!user.mining.isActive || (user.mining.endTimeMs && user.mining.endTimeMs <= now)) {
      return res.status(409).json({ message: 'No active mining session to boost' });
    }

    // compute snapshot up to now and persist accumulatedGh to avoid double-counting
    const snapshot = user.computeMiningSnapshot(now, GH_TO_BTC); // GH_TO_BTC defined in your config
    user.mining.accumulatedGh = snapshot.accumulatedGh;
    user.mining.lastUpdatedMs = now;

    // update speed and counters
    user.mining.speedGhPerSec = targetSpeed;
    user.mining.speedAdsWatched = (user.mining.speedAdsWatched || 0) + requiredAds;

    // push event
    user.mining.events = user.mining.events || [];
    user.mining.events.push({ type: 'ad_speed', at: now, newSpeed: targetSpeed, ads: requiredAds });

    await user.save();

    const newSnapshot = user.computeMiningSnapshot(now, GH_TO_BTC);
    return res.status(200).json({ user: user.toJSON(), mining: newSnapshot });
  } catch (err) {
    console.error('POST /mining/speed error', err);
    return res.status(500).json({ message: 'Server error' });
  }
});

// POST /rewards/surprise/claim
const SURPRISE_GIFT_INTERVAL_MS = 24 * 60 * 60 * 1000; // 24 hours
const SURPRISE_GIFT_MIN_COINS = 150;
const SURPRISE_GIFT_MAX_COINS = 250;

const randInt = (min, max) => Math.floor(Math.random() * (max - min + 1)) + min;
app.post('/rewards/surprise/claim', authMiddleware, async (req, res) => {
  console.log("Surprise gift claim request received ....")
  try {
    const userEmail = req.userEmail;
    if (!userEmail) return res.status(401).json({ message: 'Unauthorized' });
    const now = Date.now();
    const earliestAllowed = now - SURPRISE_GIFT_INTERVAL_MS;
    
    // Atomic check+update to avoid double-claim race conditions
    // const reward = randInt(SURPRISE_GIFT_MIN_COINS, SURPRISE_GIFT_MAX_COINS);
    let reward;
    const clientReward = req.body?.rewardCoins;

    if (typeof clientReward !== 'undefined') {
      // try to coerce to integer
      const parsed = parseInt(clientReward, 10);
      if (Number.isNaN(parsed)) {
        return res.status(400).json({ message: 'Invalid reward value' });
      }
      // validate range
      if (parsed < SURPRISE_GIFT_MIN_COINS || parsed > SURPRISE_GIFT_MAX_COINS) {
        return res.status(400).json({ message: 'Reward out of allowed range' });
      }
      reward = parsed;
    } else {
      // fallback to server-generated (if client didn't send)
      reward = randInt(SURPRISE_GIFT_MIN_COINS, SURPRISE_GIFT_MAX_COINS);
    }
    
    const updated = await User.findOneAndUpdate(
      {
        email: userEmail,
        $or: [
          { lastSurpriseGiftAt: { $exists: false } },
          { lastSurpriseGiftAt: { $lte: earliestAllowed } }
        ]
      },
      {
        $set: { lastSurpriseGiftAt: now },
        $inc: { coinsBalance: reward, totalCoinsEarned: reward, surpriseGiftClaims: 1 },
        $push: {
          transactions: {
            type: 'surprise_gift',
            amountBtc: 0,
            amountCoins: reward,
            note: 'Surprise gift reward',
            createdAt: new Date()
          }
        }
      },
      { new: true }
    );
    
    if (!updated) {
      // Not eligible yet — compute remaining
      const user = await User.findOne({ email: userEmail });
      const last = user?.lastSurpriseGiftAt ?? 0;
      const nextAvailableAt = last + SURPRISE_GIFT_INTERVAL_MS;
      const remainingMs = Math.max(nextAvailableAt - now, 0);
      return res.status(409).json({
        message: 'Surprise gift not ready yet.',
        remainingMs,
        nextAvailableAt,
        now
      });
    }
    
    const nextAvailableAt = now + SURPRISE_GIFT_INTERVAL_MS;
    return res.status(200).json({
      rewardCoins: reward,
      nextAvailableAt,
      now,
      user: updated.toJSON()
    });
  } catch (err) {
    console.error('POST /rewards/surprise/claim error', err);
    return res.status(500).json({ message: 'Server error' });
  }
});


// GET /rewards/surprise/status — so the app can show countdown without trying to claim
app.get('/rewards/surprise/status', authMiddleware, async (req, res) => {
  console.log("Surprise gift status request received ....")
  try {
    const userEmail = req.userEmail;
    if (!userEmail) return res.status(401).json({ message: 'Unauthorized' });
    const now = Date.now();
    const user = await User.findOne({ email: userEmail });
    if (!user) return res.status(404).json({ message: 'User not found' });
    
    const last = user?.lastSurpriseGiftAt ?? 0;
    const nextAvailableAt = last + SURPRISE_GIFT_INTERVAL_MS;
    const remainingMs = Math.max(nextAvailableAt - now, 0);
    const available = remainingMs <= 0;
    
    return res.status(200).json({ available, remainingMs, nextAvailableAt, now, user: user.toJSON() });
  } catch (err) {
    console.error('GET /rewards/surprise/status error', err);
    return res.status(500).json({ message: 'Server error' });
  }
});


const DAILY_BONUS_MAX_FLIPS = 4;
const DAILY_BONUS_CYCLE_MS  = 60 * 60 * 1000;  // 60 min
const DAILY_BONUS_MIN_COINS = 100;
const DAILY_BONUS_MAX_COINS = 999;
const randIntDaily = (a,b)=>Math.floor(Math.random()*(b-a+1))+a;

// GET /rewards/dailybonus/status
app.get('/rewards/dailybonus/status', authMiddleware, async (req, res) => {
  console.log("Daily bonus status request received ....")
  const user = await User.findOne({ email: req.userEmail });
  if (!user) return res.status(404).json({ message: 'User not found' });

  const now = Date.now();
  const { dailyBonus = {} } = user;
  let { lastCycleStart = 0, flipsOpened = 0 } = dailyBonus;

  // if cycle expired, the next claim should reset flipsOpened
  if (!lastCycleStart || now - lastCycleStart >= DAILY_BONUS_CYCLE_MS) {
    lastCycleStart = now;
    flipsOpened = 0;
    // optional: update user.dailyBonus on the spot
    user.dailyBonus.lastCycleStart = lastCycleStart;
    user.dailyBonus.flipsOpened = 0;
    await user.save();
  }

  const nextAvailableAt = lastCycleStart + DAILY_BONUS_CYCLE_MS;
  const available = flipsOpened < DAILY_BONUS_MAX_FLIPS;

  res.status(200).json({
    available,
    flipsOpened,
    maxFlips: DAILY_BONUS_MAX_FLIPS,
    nextAvailableAt,
    now,
    user: user.toJSON(),
  });
});

// 🟢 POST Claim — grants random coins if allowed
app.post('/rewards/dailybonus/claim',authMiddleware,async(req,res)=>{
  console.log("Daily bonus claim request received ....")
  const user=await User.findOne({email:req.userEmail});
  if(!user)return res.status(404).json({message:'User not found'});
  const now=Date.now();
  let {lastCycleStart=0,flipsOpened=0,totalFlipsClaimed=0}=user.dailyBonus||{};
  const elapsed=now-lastCycleStart;
  if(elapsed>=DAILY_BONUS_CYCLE_MS||!lastCycleStart){
     lastCycleStart=now; flipsOpened=0;
  }
  if(flipsOpened>=DAILY_BONUS_MAX_FLIPS){
    const nextAvailableAt=lastCycleStart+DAILY_BONUS_CYCLE_MS;
    return res.status(409).json({message:'Cycle full',remainingMs:nextAvailableAt-now,nextAvailableAt,now});
  }
  const reward=randIntDaily(DAILY_BONUS_MIN_COINS,DAILY_BONUS_MAX_COINS);
  user.coinsBalance+=reward;
  user.totalCoinsEarned+=reward;
  user.dailyBonus={
    lastCycleStart,
    flipsOpened:flipsOpened+1,
    totalFlipsClaimed:totalFlipsClaimed+1
  };
  user.transactions.push({
    type:'daily_bonus',
    amountCoins:reward,
    note:`Chest ${flipsOpened+1}/${DAILY_BONUS_MAX_FLIPS}`,
    createdAt:new Date()
  });
  await user.save();
  const nextAvailableAt=lastCycleStart+DAILY_BONUS_CYCLE_MS;
  res.status(200).json({
    rewardCoins:reward,
    flipsUsed:user.dailyBonus.flipsOpened,
    flipsRemaining:DAILY_BONUS_MAX_FLIPS-user.dailyBonus.flipsOpened,
    nextAvailableAt,now,user:user.toJSON()
  });
});


// constants
const CONVERSION_RATE = 0.00000001104; 
// 25,000 coins → 25 USDT → ~0.000276 BTC
const MIN_COINS_REQUIRED = 25_000;     // 25 k coins minimum


app.post('/wallet/convert', authMiddleware, async (req, res) => {
  console.log("Wallet convert request received ....")
  try {
    const userId = req.userId;
    const { coins } = req.body; // expecting { coins: number }

    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ message: 'User not found' });

    const coinsToConvert = Number(coins);
    if (!coinsToConvert || coinsToConvert <= 0) {
      return res.status(400).json({ message: 'Invalid amount of coins' });
    }
    if (coinsToConvert < MIN_COINS_REQUIRED) {
      return res.status(400).json({ message: `Minimum ${MIN_COINS_REQUIRED} coins required to convert` });
    }
    if (user.coinsBalance < coinsToConvert) {
      return res.status(400).json({ message: 'Insufficient coin balance' });
    }

    const btcToCredit = coinsToConvert * CONVERSION_RATE;

    // 💰 update balances
    user.coinsBalance -= coinsToConvert;
    user.btcBalance += btcToCredit;

    // 🧾 push transaction
    user.transactions.push({
      type: 'convert',
      amountBtc: btcToCredit,
      amountCoins: coinsToConvert,
      note: `Converted ${coinsToConvert} coins → ${btcToCredit} BTC`,
      createdAt: new Date()
    });

    await user.save();

    res.status(200).json({
      message: 'Conversion successful',
      convertedCoins: coinsToConvert,
      creditedBTC: btcToCredit,
      user: user.toJSON()
    });
  } catch (err) {
    console.error('/wallet/convert error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});


// Credits referral reward coins when user completes "Refer & Earn" tasks
app.post('/rewards/refer/claim', authMiddleware, async (req, res) => {
  console.log("Referral reward claim request received ....")
  try {
    const { rewardCoins } = req.body;   // e.g. { rewardCoins: 2999 }
    const userId = req.userId;          // from authMiddleware
    
    if (!userId) {
      return res.status(401).json({ message: 'Unauthorized' });
    }

    const user = await User.findById(userId);
    if (!user)
      return res.status(404).json({ message: 'User not found' });

    const coins = Number(rewardCoins) || 0;
    if (coins <= 0) {
      return res.status(400).json({ message: 'Invalid reward amount' });
    }

    // 🟩 credit 2999 coins (or dynamic rewardCoins)
    user.coinsBalance     += coins;
    user.totalCoinsEarned += coins;

    // 🟩 add transaction record (type referral_reward)
    user.transactions.push({
      type: 'referral_reward',
      amountBtc: 0,
      amountCoins: coins,
      note: `Refer & Earn reward credited (${coins} coins)`,
      createdAt: new Date()
    });

    // 🟩 optional analytics: increment referralsCount if you track invites
    if (user.referralsCount != null) user.referralsCount += 1;

    // 🟠 turn off refer feature after claim
    user.referOn = false;

    await user.save();

    return res.status(200).json({
      message: 'Reward claimed successfully',
      rewardCoins: coins,
      user: user.toJSON()
    });
  } catch (err) {
    console.error('/rewards/refer/claim error:', err);
    return res.status(500).json({ message: 'Server error' });
  }
});



const DAILY_STREAK_INTERVAL_MS = 24 * 60 * 60 * 1000;
const REGULAR_DAILY_REWARDS = [100, 200, 300, 400, 500, 600, 700]; // Days 1-7
const BONUS_REWARD_AMOUNT = 4000;
const STREAK_CYCLE_LENGTH = 7;
const STREAK_BREAK_CLAIM_THRESHOLD_MS = 2 * DAILY_STREAK_INTERVAL_MS;
const STREAK_BREAK_MINING_THRESHOLD_MS = 36 * 60 * 60 * 1000;

app.post('/rewards/daily-streak/claim', authMiddleware, async (req, res) => {
  try {
    const userEmail = req.userEmail;
    const now = Date.now();
    let user = await User.findOne({ email: userEmail });
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    if (!user.lastStreakClaimAt && user.dailyStreak === 0) {
      console.log(`New user ${userEmail} detected. Setting dailyStreak to 1.`);
      user.dailyStreak = 1; // Fix for new users with old schema default
    }

    // --- Cooldown Check ---
    const lastClaimAt = user.lastStreakClaimAt ? user.lastStreakClaimAt.getTime() : 0;
    const earliestNextClaimTime = lastClaimAt + DAILY_STREAK_INTERVAL_MS;

    if (now < earliestNextClaimTime) {
      return res.status(409).json({
        message: 'Daily streak reward not ready yet.',
        remainingMs: earliestNextClaimTime - now,
        nextAvailableAt: earliestNextClaimTime,
      });
    }

    // --- Determine last mining activity time ---
    let lastMiningActivityTime = 0;
    if (user.mining) {
      lastMiningActivityTime = Math.max(
        user.mining.lastUpdatedMs || 0,
        user.mining.endTimeMs || 0
      );
    }

    // --- Streak Break Check ---
    let isStreakBroken = false;
    if (user.dailyStreak > 1 && lastClaimAt > 0) { // Only if on Day 2+
      const hasMissedClaimWindow = (now - lastClaimAt) > STREAK_BREAK_CLAIM_THRESHOLD_MS;
      const hasMissedMiningWindow = lastMiningActivityTime > 0 && 
        (now - lastMiningActivityTime) > STREAK_BREAK_MINING_THRESHOLD_MS;

      if (hasMissedClaimWindow || hasMissedMiningWindow) {
        isStreakBroken = true;
        console.log(`Streak broken for ${userEmail}. Resetting to Day 1.`);
        user.dailyStreak = 1; // Reset to Day 1, NOT bonus
      }
    }

    // --- Calculate Reward ---
    let rewardCoins;
    let nextStreakDayToSet;
    const currentDay = user.dailyStreak;

    if (currentDay >= 1 && currentDay <= STREAK_CYCLE_LENGTH) {
      // Regular days 1-7
      rewardCoins = REGULAR_DAILY_REWARDS[currentDay - 1];
      nextStreakDayToSet = currentDay + 1;
      
      // After Day 7, move to bonus (represented as 8)
      if (nextStreakDayToSet > STREAK_CYCLE_LENGTH) {
        nextStreakDayToSet = 8; // Bonus day
      }
    } else if (currentDay === 8 || currentDay === 0) {
      // Bonus day (after Day 7, or legacy value of 0)
      rewardCoins = BONUS_REWARD_AMOUNT;
      nextStreakDayToSet = 1; // Back to Day 1
    } else {
      // Fallback for unexpected values
      console.warn(`Unexpected dailyStreak value: ${currentDay}. Resetting to Day 1.`);
      rewardCoins = REGULAR_DAILY_REWARDS[0]; // 100 coins
      nextStreakDayToSet = 2;
    }

    // --- Update user document ---
    user.coinsBalance += rewardCoins;
    user.totalCoinsEarned += rewardCoins;
    user.dailyStreak = nextStreakDayToSet;
    user.lastStreakClaimAt = new Date(now);

    // Transaction record
    const claimedDayText = currentDay === 8 || currentDay === 0 
      ? 'Bonus' 
      : `Day ${currentDay}`;

    user.transactions.push({
      type: 'daily_bonus',
      amountBtc: 0,
      amountCoins: rewardCoins,
      note: `Daily streak reward - ${claimedDayText} (${rewardCoins} coins)`,
      createdAt: new Date(now),
    });

    await user.save();

    console.log(`✅ Daily streak claimed by ${userEmail}: ${claimedDayText} = ${rewardCoins} coins. Next: Day ${nextStreakDayToSet === 8 ? 'Bonus' : nextStreakDayToSet}`);

    return res.status(200).json({
      rewardCoins,
      currentDailyStreak: user.dailyStreak,
      lastStreakClaimAt: user.lastStreakClaimAt.getTime(),
      nextAvailableAt: now + DAILY_STREAK_INTERVAL_MS,
      message: 'Daily streak reward claimed successfully!',
      user: user.toJSON(),
    });

  } catch (err) {
    console.error('POST /rewards/daily-streak/claim error', err);
    return res.status(500).json({ message: 'Server error' });
  }
});



// status
app.get('/status', async (req, res) => {
  const user = await User.findById(req.user.id);
  if (!user) return res.status(404).send('User not found');

  const snapshot = user.computeMiningSnapshot(Date.now(), GH_TO_BTC);
  // optionally finalize if expired
  if (snapshot.isActive && snapshot.remainingMs === 0) {
    // session expired: finalize
    user.finalizeMiningSession(Date.now(), GH_TO_BTC);
    await user.save();
    // recompute after finalize
    const after = user.computeMiningSnapshot(Date.now(), GH_TO_BTC);
    return res.json({ mining: after, message: 'Session finalized and credited' });
  }

  res.json({ mining: snapshot });
});

// ad-watched
app.post('/ad-watched', async (req, res) => {
  // body: { type: 'extend'|'speed' }
  const { type } = req.body;
  const user = await User.findById(req.user.id);
  if (!user) return res.status(404).send('User not found');
  if (!user.mining || !user.mining.isActive) {
    return res.status(400).json({ message: 'No active mining session' });
  }

  const now = Date.now();

  // catch-up before changing speed/extension
  const deltaMs = Math.max(0, now - user.mining.lastUpdatedMs);
  if (deltaMs > 0) {
    const deltaGh = (user.mining.speedGhPerSec || 0) * (deltaMs / 1000.0);
    user.mining.accumulatedGh = (user.mining.accumulatedGh || 0) + deltaGh;
    user.mining.lastUpdatedMs = now;
  }

  if (type === 'extend') {
    if ((user.mining.extAdsWatched || 0) >= 2) {
      return res.status(400).json({ message: 'Max extend ads reached' });
    }
    user.mining.extAdsWatched = (user.mining.extAdsWatched || 0) + 1;
    // add 30 minutes per ad (example)
    const addMs = 30 * 60 * 1000;
    user.mining.endTimeMs = (user.mining.endTimeMs || now) + addMs;
    user.mining.extensionMs = (user.mining.extensionMs || 0) + addMs;
    user.mining.events.push({ type: 'ad_extended', meta: { addedMs: addMs }, at: now });
  } else if (type === 'speed') {
    if ((user.mining.speedAdsWatched || 0) >= 2) {
      return res.status(400).json({ message: 'Max speed ads reached' });
    }
    user.mining.speedAdsWatched = (user.mining.speedAdsWatched || 0) + 1;
    // map to speeds: 0->30, 1->45, 2->60
    const level = user.mining.speedAdsWatched;
    const speeds = { 0: 30, 1: 45, 2: 60 };
    user.mining.speedGhPerSec = speeds[level] || 60;
    user.mining.events.push({ type: 'ad_speed', meta: { level }, at: now });
  } else {
    return res.status(400).json({ message: 'Unknown ad type' });
  }

  user.totalAdsWatched = (user.totalAdsWatched || 0) + 1;
  await user.save();
  const snapshot = user.computeMiningSnapshot(Date.now(), GH_TO_BTC);
  res.json({ mining: snapshot });
});

// stop / finalize manually
app.post('/stop', async (req, res) => {
  const user = await User.findById(req.user.id);
  if (!user) return res.status(404).send('User not found');

  if (!user.mining || !user.mining.isActive) {
    return res.status(400).json({ message: 'No active session' });
  }

  const result = user.finalizeMiningSession(Date.now(), GH_TO_BTC);
  await user.save();
  res.json({ message: 'Session finalized', addedBtc: result.addedBtc, btcBalance: user.btcBalance });
});





// Map productId or planKey -> config (multiplier, duration fallback)
const PLAN_DEFS = {
  'plan_7d': { days: 7, conversionMultiplier: 1.5, adsOn: false },
  'plan_30d': { days: 30, conversionMultiplier: 2.0, adsOn: false },
  'plan_12mo': { days: 365, conversionMultiplier: 3.0, adsOn: false },
  // NOTE: use your actual productIds from Play Console or map productId -> planKey
  // Example productId mapping:
  // 'com.yourapp.premium_7d': 'plan_7d',
};

// Helper: create google androidpublisher client
async function getAndroidPublisherClient() {
  // Provide a service account JSON file path in env, or set GOOGLE_APPLICATION_CREDENTIALS
  const auth = new google.auth.GoogleAuth({
    keyFilename: process.env.GOOGLE_PLAY_KEYFILE, // path to service account JSON
    scopes: ['https://www.googleapis.com/auth/androidpublisher']
  });
  const authClient = await auth.getClient();
  return google.androidpublisher({ version: 'v3', auth: authClient });
}

/**
 * POST /subscriptions/verify
 * Body: { productId, purchaseToken, packageName, planKey? }
 * Auth required (user must be logged in)
 */
app.post('/verify', authMiddleware, async (req, res) => {
  const { productId, purchaseToken, packageName, planKey: clientPlanKey } = req.body;
  if (!productId || !purchaseToken || !packageName) {
    return res.status(400).json({ message: 'productId, purchaseToken and packageName are required' });
  }

  try {
    const androidpublisher = await getAndroidPublisherClient();

    // Call Google Play API to validate subscription
    const resp = await androidpublisher.purchases.subscriptions.get({
      packageName,
      subscriptionId: productId,
      token: purchaseToken
    });

    const data = resp.data;
    // data contains fields like expiryTimeMillis, autoRenewing, orderId, purchaseType etc
    const expiryTimeMs = Number(data.expiryTimeMillis || Date.now());
    const startTimeMs  = Number(data.startTimeMillis || Date.now());
    const autoRenewing = !!data.autoRenewing;
    const orderId = data.orderId;

    // Determine planKey either from client or by mapping productId 
    const planKey = clientPlanKey || (Object.keys(PLAN_DEFS).includes(productId) ? productId : null)
      || (Object.values(PLAN_DEFS).find(k => false) ? null : null);

    // If you don't map productId -> planKey, derive multiplier from a separate mapping:
    // Example mapping:
    const productIdToPlan = {
      [`${process.env.PACKAGE_NAME}.premium_7d`]: 'plan_7d',
      [`${process.env.PACKAGE_NAME}.premium_30d`]: 'plan_30d',
      [`${process.env.PACKAGE_NAME}.premium_12mo`]: 'plan_12mo',
    };
    const resolvedPlanKey = productIdToPlan[productId] || clientPlanKey || 'plan_30d';

    // Fetch user
    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ message: 'User not found' });

    // Save subscription record in user's subscription history
    const subRecord = {
      platform: 'google_play',
      productId,
      purchaseToken,
      orderId,
      startTimeMs,
      expiryTimeMs,
      autoRenewing,
      status: 'active',
      planKey: resolvedPlanKey,
      rawResponse: data
    };

    user.subscriptions.push(subRecord);

    // Apply premium change: set premiumUntil, premiumUser, premiumPlanKey and disable ads
    user.premiumUntil = expiryTimeMs;
    user.premiumUser = expiryTimeMs > Date.now();
    user.premiumPlanKey = resolvedPlanKey;
    user.adsOn = PLAN_DEFS[resolvedPlanKey] ? PLAN_DEFS[resolvedPlanKey].adsOn : false;

    // Update user's mining.conversionFactor according to plan multiplier
    const baseConversion = (user.mining && typeof user.mining.conversionFactor === 'number')
      ? user.mining.conversionFactor
      : (process.env.MINING_CONVERSION_FACTOR ? Number(process.env.MINING_CONVERSION_FACTOR) : 0.000001);

    const planCfg = PLAN_DEFS[resolvedPlanKey] || PLAN_DEFS['plan_30d'];
    // store previous as audit if needed
    user.mining = user.mining || {};
    user.mining.previousConversionFactor = user.mining.conversionFactor || baseConversion;
    user.mining.conversionFactor = baseConversion * (planCfg.conversionMultiplier || 1);

    // Optionally create a transaction log entry
    user.transactions.push({
      type: 'purchase',
      note: `Subscription ${resolvedPlanKey} via Google Play, orderId:${orderId}`,
      createdAt: new Date()
    });

    await user.save();

    return res.status(200).json({
      message: 'Subscription verified and applied',
      subscription: subRecord,
      premiumUntil: user.premiumUntil,
      conversionFactor: user.mining.conversionFactor,
      adsOn: user.adsOn
    });

  } catch (err) {
    console.error('Subscription verify error', err?.response?.data || err);
    return res.status(500).json({ message: 'Failed to verify subscription with Google Play' });
  }
});










// Start server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});


