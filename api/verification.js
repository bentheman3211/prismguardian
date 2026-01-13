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
const ipDatabase = new Map(); // Track IPs and their risk scores

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

// ==================== IP & VPN DETECTION ====================

async function checkIPReputation(ip) {
  try {
    // Use AbuseIPDB API (free tier with demo key)
    const response = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90`, {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
        'Key': 'demo',
      },
    });
    
    const data = await response.json();

    if (!data.data) {
      return { safe: true, risk: 0, reason: 'Could not verify IP' };
    }

    let risk = 0;
    let reasons = [];
    const abuseScore = data.data.abuseConfidenceScore || 0;

    // High abuse score = likely malicious
    if (abuseScore >= 75) {
      risk += 100;
      reasons.push(`High abuse score: ${abuseScore}%`);
    } else if (abuseScore >= 50) {
      risk += 70;
      reasons.push(`Medium abuse score: ${abuseScore}%`);
    } else if (abuseScore >= 25) {
      risk += 40;
      reasons.push(`Low abuse score: ${abuseScore}%`);
    }

    // Check usage type for VPN/Proxy
    const usageType = (data.data.usageType || '').toLowerCase();
    if (usageType.includes('vpn') || usageType.includes('proxy') || usageType.includes('hosting')) {
      risk += 85;
      reasons.push(`VPN/Proxy detected (${usageType})`);
    }

    // Check if datacenter
    const isp = (data.data.isp || '').toLowerCase();
    const domain = (data.data.domain || '').toLowerCase();
    const datacenterKeywords = ['datacenter', 'hosting', 'cloud', 'aws', 'azure', 'linode', 'digital ocean', 'vps'];
    
    if (datacenterKeywords.some(kw => isp.includes(kw) || domain.includes(kw))) {
      risk += 70;
      reasons.push('Datacenter/Hosting IP');
    }

    return {
      safe: risk < 50,
      risk,
      reasons,
      isVPN: risk >= 85,
      abuseScore,
      usageType: data.data.usageType,
      isp: data.data.isp,
      domain: data.data.domain,
      countryCode: data.data.countryCode,
    };
  } catch (error) {
    console.error('❌ IP reputation check error:', error);
    // If API fails, allow verification (better than blocking legitimate users)
    return { safe: true, risk: 0, reason: 'Could not verify IP - allowing' };
  }
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

  // If same IP has multiple users in same guild within 5 minutes, it's suspicious
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

  // If more than 3 users from same IP in 5 minutes, high risk
  if (recentVerifications.length >= 3) {
    return 85;
  }

  if (recentVerifications.length >= 2) {
    return 60;
  }

  return 0;
}

function checkGuildIPComposition(guildId) {
  // Check if majority of verified users in guild are using non-residential IPs
  const guildUsers = [];
  const nonResIPs = new Set();
  const resIPs = new Set();

  for (const [userId, userData] of verificationData.entries()) {
    if (userData.guildId === guildId && userData.ipReputation) {
      guildUsers.push(userData);
      if (userData.ipReputation.isVPN || userData.ipReputation.risk >= 60) {
        nonResIPs.add(userData.ip);
      } else {
        resIPs.add(userData.ip);
      }
    }
  }

  if (guildUsers.length < 3) {
    return { suspicious: false, nonResPercent: 0 };
  }

  const nonResPercent = (nonResIPs.size / guildUsers.length) * 100;

  // If more than 70% are non-residential IPs, it's a coordinated attack
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

    // Check if verification expired (24 hours)
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
    const clientIp = req.headers['x-forwarded-for'] || req.connection.remoteAddress;

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

    // Check IP reputation
    const ipReputation = await checkIPReputation(clientIp);
    console.log(`📊 IP Reputation for ${clientIp}:`, ipReputation);

    // If VPN detected, reject
    if (ipReputation.isVPN) {
      console.log(`🚫 VPN detected for user ${userId}`);
      return res.status(403).json({
        success: false,
        error: 'VPN/Proxy usage is not allowed during verification',
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
      ipReputation,
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
        // Mark as notified so we don't return it again
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
 * GET /api/test-ip/:ip
 * Test IP reputation (debug endpoint)
 */
app.get('/api/test-ip/:ip', async (req, res) => {
  try {
    const ip = req.params.ip;
    const reputation = await checkIPReputation(ip);
    
    res.json({
      ip,
      ...reputation,
    });
  } catch (error) {
    console.error('Error testing IP:', error);
    res.status(500).json({ error: 'Internal server error' });
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
