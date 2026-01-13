const express = require('express');
const cors = require('cors');
const path = require('path');
require('dotenv').config();

const app = express();

// Middleware
app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, '../public')));

// In-memory storage
const verificationData = new Map();
const quarantineData = new Map();
const ipDatabase = new Map();

// ==================== UTILITY: Get Client IP ====================

function getClientIp(req) {
  return (
    req.headers['x-forwarded-for']?.split(',')[0].trim() ||
    req.headers['cf-connecting-ip'] ||
    req.headers['x-real-ip'] ||
    req.connection.remoteAddress ||
    req.socket.remoteAddress ||
    req.ip ||
    '0.0.0.0'
  ).replace(/^::ffff:/, '');
}

// ==================== HCAPTCHA VERIFICATION ====================

async function verifyHcaptcha(token, remoteIp) {
  try {
    const response = await fetch('https://hcaptcha.com/siteverify', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        secret: process.env.HCAPTCHA_SECRET,
        response: token,
        remoteip: remoteIp || '0.0.0.0',
      }),
    });

    const data = await response.json();
    return data.success;
  } catch (error) {
    console.error('❌ hCaptcha verification error:', error);
    return false;
  }
}

// ==================== AUTHORIZATION MIDDLEWARE ====================

function validateBotSecret(req, res, next) {
  const secret = req.headers['x-bot-secret'];
  if (secret !== process.env.BOT_API_SECRET) {
    return res.status(401).json({
      success: false,
      error: 'Unauthorized - Invalid bot secret',
    });
  }
  next();
}

// ==================== LOCAL VPN DETECTION ====================

function isVPNorNonResidential(ip) {
  // Check if IP looks like localhost or private
  if (ip === 'localhost' || ip === '127.0.0.1' || ip === '::1') {
    return false;
  }

  if (ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('172.')) {
    return false;
  }

  const ipNum = ip.split('.').map(Number);
  
  // Known VPN/Cloud provider IP ranges
  
  // AWS: 52.0.0.0/8, 54.0.0.0/8
  if ((ipNum[0] === 52 || ipNum[0] === 54) && ipNum[1] < 256) {
    return true;
  }
  
  // Azure: 13.64.0.0/11, 13.96.0.0/13
  if (ipNum[0] === 13 && ((ipNum[1] >= 64 && ipNum[1] <= 95) || (ipNum[1] >= 96 && ipNum[1] <= 103))) {
    return true;
  }

  // Google Cloud: 35.184.0.0/13, 35.192.0.0/11, 34.64.0.0/10
  if (ipNum[0] === 35 && ((ipNum[1] >= 184 && ipNum[1] <= 191) || (ipNum[1] >= 192 && ipNum[1] <= 223))) {
    return true;
  }
  if (ipNum[0] === 34 && ipNum[1] >= 64 && ipNum[1] <= 127) {
    return true;
  }

  // DigitalOcean: 104.131.0.0/16, 159.65.0.0/16
  if ((ipNum[0] === 104 && ipNum[1] === 131) || (ipNum[0] === 159 && ipNum[1] === 65)) {
    return true;
  }

  // Linode: 139.162.0.0/16, 45.33.0.0/16
  if ((ipNum[0] === 139 && ipNum[1] === 162) || (ipNum[0] === 45 && ipNum[1] === 33)) {
    return true;
  }

  // Vultr: 45.76.0.0/16, 45.77.0.0/16
  if (ipNum[0] === 45 && (ipNum[1] === 76 || ipNum[1] === 77)) {
    return true;
  }

  // Hetzner: 88.198.0.0/16, 159.69.0.0/16
  if ((ipNum[0] === 88 && ipNum[1] === 198) || (ipNum[0] === 159 && ipNum[1] === 69)) {
    return true;
  }

  // Heroku: 50.19.0.0/16
  if (ipNum[0] === 50 && ipNum[1] === 19) {
    return true;
  }

  // OVH: 15.235.0.0/16, 54.36.0.0/16
  if ((ipNum[0] === 15 && ipNum[1] === 235) || (ipNum[0] === 54 && ipNum[1] === 36)) {
    return true;
  }

  // Fastly: 151.101.0.0/16
  if (ipNum[0] === 151 && ipNum[1] === 101) {
    return true;
  }

  // Akamai: 1.2.3.0/24 (simplified, they use many ranges)
  if (ipNum[0] === 23 || ipNum[0] === 60 || ipNum[0] === 95 || ipNum[0] === 184) {
    return true;
  }

  // ProtonVPN known ranges
  if (ipNum[0] === 185 && (ipNum[1] === 10 || ipNum[1] === 107 || ipNum[1] === 217)) {
    return true;
  }

  // NordVPN known ranges
  if (ipNum[0] === 37 || (ipNum[0] === 185 && ipNum[1] === 242)) {
    return true;
  }

  // ExpressVPN known ranges
  if (ipNum[0] === 141 || (ipNum[0] === 185 && ipNum[1] === 135)) {
    return true;
  }

  // Surfshark
  if (ipNum[0] === 185 && (ipNum[1] === 228 || ipNum[1] === 229)) {
    return true;
  }

  // Private Internet Access
  if (ipNum[0] === 185 && ipNum[1] === 241) {
    return true;
  }

  // CyberGhost
  if (ipNum[0] === 46 && (ipNum[1] === 29 || ipNum[1] === 30)) {
    return true;
  }

  // PrivateVPN
  if (ipNum[0] === 185 && ipNum[1] === 108) {
    return true;
  }

  return false;
}

function trackIP(ip, userId, guildId) {
  if (!ipDatabase.has(ip)) {
    ipDatabase.set(ip, {
      users: [],
      firstSeen: Date.now(),
      riskScore: 0,
    });
  }

  const ipData = ipDatabase.get(ip);
  if (!ipData.users.includes(userId)) {
    ipData.users.push(userId);
  }

  return ipData;
}

function getIPRiskScore(ip, guildId) {
  const ipData = ipDatabase.get(ip);
  if (!ipData) return 0;

  const recentVerifications = [];
  for (const userId of ipData.users) {
    const userData = verificationData.get(userId);
    if (userData && userData.guildId === guildId) {
      const timeDiff = Date.now() - userData.timestamp;
      if (timeDiff < 5 * 60 * 1000) {
        recentVerifications.push(userData);
      }
    }
  }

  if (recentVerifications.length >= 3) {
    return 85;
  }

  if (recentVerifications.length >= 2) {
    return 60;
  }

  return 0;
}

function checkGuildIPComposition(guildId) {
  const guildUsers = [];
  const nonResIPs = new Set();

  for (const [userId, userData] of verificationData.entries()) {
    if (userData.guildId === guildId) {
      guildUsers.push(userData);
      if (userData.isVPN) {
        nonResIPs.add(userData.ip);
      }
    }
  }

  if (guildUsers.length < 3) {
    return { suspicious: false, nonResPercent: 0 };
  }

  const nonResPercent = (nonResIPs.size / guildUsers.length) * 100;

  return {
    suspicious: nonResPercent > 70,
    nonResPercent: Math.round(nonResPercent),
    totalUsers: guildUsers.length,
    nonResCount: nonResIPs.size,
  };
}

// ==================== VERIFICATION ENDPOINTS ====================

/**
 * GET /api/verification-status/:userId
 * Check if a user has completed verification
 */
app.get('/api/verification-status/:userId', (req, res) => {
  try {
    const userId = req.params.userId;
    const userData = verificationData.get(userId);

    if (!userData) {
      return res.json({
        userId,
        verified: false,
        reason: 'No verification record found',
      });
    }

    const isExpired = Date.now() - userData.timestamp > 24 * 60 * 60 * 1000;

    return res.json({
      userId,
      verified: !isExpired && userData.verified,
      verificationTime: userData.timestamp,
      guildId: userData.guildId,
      isExpired,
      expiresIn: Math.max(0, 24 * 60 * 60 * 1000 - (Date.now() - userData.timestamp)),
    });
  } catch (error) {
    console.error('❌ Error checking verification status:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * POST /api/verify
 * Verify a user with hCaptcha token
 * Body: { userId, guildId, token }
 */
app.post('/api/verify', async (req, res) => {
  try {
    const { userId, guildId, token } = req.body;
    const clientIp = getClientIp(req);

    if (!userId || !guildId || !token) {
      return res.status(400).json({
        success: false,
        error: 'Missing required fields: userId, guildId, token',
      });
    }

    console.log(`🔄 Verifying user ${userId} in guild ${guildId} from IP ${clientIp}`);

    // Validate hCaptcha token
    const isValid = await verifyHcaptcha(token, clientIp);

    if (!isValid) {
      console.log(`❌ hCaptcha failed for user ${userId}`);
      return res.status(400).json({
        success: false,
        error: 'hCaptcha verification failed',
      });
    }

    // Check for VPN/Non-residential IP locally
    const isVPN = isVPNorNonResidential(clientIp);
    console.log(`📊 IP ${clientIp} - VPN/Cloud: ${isVPN}`);

    if (isVPN) {
      console.log(`🚫 VPN/Cloud IP detected for user ${userId}`);
      return res.status(403).json({
        success: false,
        error: 'VPN/Proxy/Cloud usage is not allowed during verification',
      });
    }

    // Check for duplicate IPs
    const ipData = trackIP(clientIp, userId, guildId);
    const ipRiskScore = getIPRiskScore(clientIp, guildId);

    if (ipRiskScore >= 80) {
      console.log(`🚫 Multiple users from same IP detected: ${clientIp}`);
      return res.status(403).json({
        success: false,
        error: 'Multiple verification attempts from same IP detected',
      });
    }

    // Check guild IP composition
    const guildComposition = checkGuildIPComposition(guildId);
    if (guildComposition.suspicious) {
      console.log(`🚨 Guild ${guildId} has ${guildComposition.nonResPercent}% non-residential IPs`);
      return res.status(403).json({
        success: false,
        error: 'Guild verification blocked - suspicious IP patterns detected',
        details: {
          nonResidentialPercent: guildComposition.nonResPercent,
          reason: 'Majority of verifications from non-residential IPs',
        },
      });
    }

    // Mark user as verified
    verificationData.set(userId, {
      verified: true,
      timestamp: Date.now(),
      guildId,
      ip: clientIp,
      isVPN,
      notified: false,
    });

    // Remove from quarantine if present
    if (quarantineData.has(userId)) {
      quarantineData.delete(userId);
      console.log(`✅ Removed ${userId} from quarantine`);
    }

    console.log(`✅ User ${userId} verified successfully from IP ${clientIp}`);

    return res.json({
      success: true,
      message: 'Verification successful! You can now use the server.',
      userId,
      guildId,
      verifiedAt: Date.now(),
    });
  } catch (error) {
    console.error('❌ Error during verification:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
    });
  }
});

// ==================== QUARANTINE ENDPOINTS ====================

/**
 * GET /api/quarantine/:userId
 * Check if a user is in quarantine
 */
app.get('/api/quarantine/:userId', (req, res) => {
  try {
    const userId = req.params.userId;
    const quarantineInfo = quarantineData.get(userId);
    const verificationInfo = verificationData.get(userId);

    if (!quarantineInfo) {
      return res.json({
        userId,
        quarantined: false,
        verified: verificationInfo?.verified || false,
      });
    }

    return res.json({
      userId,
      quarantined: quarantineInfo.quarantined,
      reason: quarantineInfo.reason,
      violations: quarantineInfo.violations || 0,
      quarantinedAt: quarantineInfo.timestamp,
      guildId: quarantineInfo.guildId,
      verified: verificationInfo?.verified || false,
    });
  } catch (error) {
    console.error('❌ Error checking quarantine status:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * POST /api/quarantine
 * Add a user to quarantine (called by bot)
 * Body: { userId, guildId, reason }
 */
app.post('/api/quarantine', validateBotSecret, (req, res) => {
  try {
    const { userId, guildId, reason } = req.body;

    if (!userId || !reason) {
      return res.status(400).json({
        success: false,
        error: 'Missing required fields: userId, reason',
      });
    }

    quarantineData.set(userId, {
      quarantined: true,
      reason,
      violations: 0,
      timestamp: Date.now(),
      guildId,
    });

    console.log(`🔒 User ${userId} quarantined: ${reason}`);

    return res.json({
      success: true,
      message: 'User quarantined',
      userId,
      guildId,
    });
  } catch (error) {
    console.error('❌ Error quarantining user:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
    });
  }
});

/**
 * POST /api/quarantine/:userId/violation
 * Record a violation for a quarantined user
 */
app.post('/api/quarantine/:userId/violation', validateBotSecret, (req, res) => {
  try {
    const userId = req.params.userId;
    const quarantineInfo = quarantineData.get(userId);

    if (!quarantineInfo) {
      return res.status(404).json({
        success: false,
        error: 'User not in quarantine',
      });
    }

    quarantineInfo.violations++;
    console.log(`⚠️ Violation recorded for ${userId}. Count: ${quarantineInfo.violations}`);

    return res.json({
      success: true,
      userId,
      violations: quarantineInfo.violations,
      shouldBan: quarantineInfo.violations >= 2,
    });
  } catch (error) {
    console.error('❌ Error recording violation:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
    });
  }
});

/**
 * POST /api/quarantine/:userId/release
 * Release a user from quarantine
 */
app.post('/api/quarantine/:userId/release', validateBotSecret, (req, res) => {
  try {
    const userId = req.params.userId;
    quarantineData.delete(userId);
    console.log(`✅ User ${userId} released from quarantine`);

    return res.json({
      success: true,
      message: 'User released from quarantine',
      userId,
    });
  } catch (error) {
    console.error('❌ Error releasing user:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
    });
  }
});

// ==================== RAID STATUS ENDPOINTS ====================

/**
 * GET /api/raid-status/:guildId
 * Get quarantined users for a guild
 */
app.get('/api/raid-status/:guildId', validateBotSecret, (req, res) => {
  try {
    const guildId = req.params.guildId;
    const quarantinedUsers = [];

    for (const [userId, info] of quarantineData.entries()) {
      if (info.guildId === guildId) {
        quarantinedUsers.push({
          userId,
          reason: info.reason,
          violations: info.violations,
          quarantinedAt: info.timestamp,
        });
      }
    }

    return res.json({
      guildId,
      quarantinedCount: quarantinedUsers.length,
      quarantinedUsers,
      timestamp: Date.now(),
    });
  } catch (error) {
    console.error('❌ Error getting raid status:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * GET /api/get-verified-users/:guildId
 * Get list of users who just verified (for polling)
 */
app.get('/api/get-verified-users/:guildId', validateBotSecret, (req, res) => {
  try {
    const guildId = req.params.guildId;
    const verifiedUsers = [];

    for (const [userId, userData] of verificationData.entries()) {
      if (userData.guildId === guildId && userData.verified && !userData.notified) {
        verifiedUsers.push({
          userId,
          verifiedAt: userData.timestamp,
        });
        userData.notified = true;
      }
    }

    return res.json({
      guildId,
      verifiedUsers,
      count: verifiedUsers.length,
    });
  } catch (error) {
    console.error('❌ Error getting verified users:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ==================== HEALTH CHECK ====================

app.get('/api/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: Date.now(),
    uptime: process.uptime(),
  });
});

/**
 * GET /api/test-ip
 * Test the user's current IP
 */
app.get('/api/test-ip', (req, res) => {
  try {
    const ip = getClientIp(req);
    console.log(`🔍 Testing IP: ${ip}`);
    
    const isVPN = isVPNorNonResidential(ip);
    
    res.json({
      ip,
      isVPN,
      message: isVPN ? '🚫 VPN/Cloud IP detected' : '✅ Residential IP (allowed)',
    });
  } catch (error) {
    console.error('Error testing IP:', error);
    res.status(500).json({ 
      error: 'Internal server error',
      message: error.message 
    });
  }
});

// ==================== SERVE VERIFICATION PAGE ====================

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

// ==================== ERROR HANDLING ====================

app.use((req, res) => {
  res.status(404).json({
    error: 'Endpoint not found',
  });
});

app.use((err, req, res, next) => {
  console.error('❌ Unhandled error:', err);
  res.status(500).json({
    error: 'Internal server error',
  });
});

// ==================== START SERVER ====================

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`\n╔═══════════════════════════════════════╗`);
  console.log(`║  🔐 Verification API Running 🛡️    ║`);
  console.log(`╚═══════════════════════════════════════╝\n`);
  console.log(`📍 Port: ${PORT}`);
  console.log(`🔗 Local: http://localhost:${PORT}`);
  console.log(`💚 Health: http://localhost:${PORT}/api/health\n`);
});

module.exports = app;
