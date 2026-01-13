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

// ==================== MULTI-SOURCE VPN/PROXY DETECTION ====================

async function checkIPWithAbuseIPDB(ip) {
  try {
    const apiKey = process.env.ABUSEIPDB_API_KEY;
    
    if (!apiKey) {
      console.warn('⚠️ ABUSEIPDB_API_KEY not set');
      return { isVPN: false, isProxy: false, isHosting: false, abuseScore: 0, source: 'none' };
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);

    const response = await fetch('https://api.abuseipdb.com/api/v2/check', {
      method: 'POST',
      headers: {
        'Key': apiKey,
        'Accept': 'application/json',
      },
      body: new URLSearchParams({
        ipAddress: ip,
        maxAgeInDays: '90',
      }),
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      console.warn(`⚠️ AbuseIPDB returned ${response.status}`);
      return { isVPN: false, isProxy: false, isHosting: false, abuseScore: 0, source: 'none' };
    }

    const data = await response.json();
    const ipData = data.data || {};
    
    const result = {
      isVPN: ipData.isVpn || ipData.isProxy || false,
      isHosting: ipData.isHosting || false,
      abuseScore: ipData.abuseConfidenceScore || 0,
      isp: ipData.isp || 'Unknown',
      domain: ipData.domain || 'Unknown',
      usageType: ipData.usageType || 'Unknown',
      source: 'abuseipdb'
    };

    console.log(`📊 AbuseIPDB for ${ip}:`, result);
    return result;
  } catch (error) {
    console.error('❌ AbuseIPDB check error:', error.message);
    return { isVPN: false, isProxy: false, isHosting: false, abuseScore: 0, source: 'error' };
  }
}

// Fallback: Check against known residential ISPs (no API calls)
function isResidentialISP(isp) {
  const residentialISPs = [
    'comcast', 'verizon', 'at&t', 'cox', 'spectrum', 'charter',
    'centurylink', 'frontier', 'optimum', 'suddenlink', 'windstream',
    'rural electric', 'tribal', 'dsl', 'cable', 'fiber', 'broadband'
  ];
  const lowerISP = isp.toLowerCase();
  return residentialISPs.some(r => lowerISP.includes(r));
}

// ==================== IP TRACKING & RISK ANALYSIS ====================

function trackIP(ip, userId, guildId) {
  if (!ipDatabase.has(ip)) {
    ipDatabase.set(ip, {
      users: [],
      firstSeen: Date.now(),
      accounts: {},
      isVPN: false,
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

  // Count recent verifications from same IP in this guild
  const recentVerifications = [];
  for (const userId of ipData.users) {
    const userData = verificationData.get(userId);
    if (userData && userData.guildId === guildId) {
      const timeDiff = Date.now() - userData.timestamp;
      // Within last 10 minutes = suspicious
      if (timeDiff < 10 * 60 * 1000) {
        recentVerifications.push(userData);
      }
    }
  }

  // Multiple accounts from same IP in short time = raid indicator
  if (recentVerifications.length >= 5) return 95;
  if (recentVerifications.length >= 4) return 85;
  if (recentVerifications.length >= 3) return 75;
  if (recentVerifications.length >= 2) return 60;

  return 0;
}

function checkGuildIPComposition(guildId) {
  const guildUsers = [];
  const vpnIPs = new Set();
  const residentialIPs = new Set();

  for (const [userId, userData] of verificationData.entries()) {
    if (userData.guildId === guildId) {
      guildUsers.push(userData);
      if (userData.isVPN) {
        vpnIPs.add(userData.ip);
      } else {
        residentialIPs.add(userData.ip);
      }
    }
  }

  if (guildUsers.length < 3) {
    return { suspicious: false, vpnPercent: 0 };
  }

  const vpnPercent = (vpnIPs.size / guildUsers.length) * 100;
  const isSuspicious = vpnPercent > 60 || vpnIPs.size >= 5;

  return {
    suspicious: isSuspicious,
    vpnPercent: Math.round(vpnPercent),
    totalUsers: guildUsers.length,
    vpnCount: vpnIPs.size,
    residentialCount: residentialIPs.size,
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
      wasVPN: userData.isVPN || false,
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

    // Check IP with AbuseIPDB
    const ipQuality = await checkIPWithAbuseIPDB(clientIp);
    console.log(`📊 IP Quality for ${clientIp}:`, ipQuality);

    // Track this IP
    const ipData = trackIP(clientIp, userId, guildId);
    const ipRiskScore = getIPRiskScore(clientIp, guildId);

    // Determine if VPN/Proxy
    const isVPN = ipQuality.isVPN || ipQuality.isHosting;

    // HIGH RISK: VPN + multiple accounts from same IP
    if (isVPN && ipRiskScore >= 60) {
      console.log(`🚫 RAID DETECTED: VPN + multiple accounts from ${clientIp}`);
      return res.status(403).json({
        success: false,
        error: 'Cannot verify: Suspicious activity detected (VPN + multiple accounts)',
        riskScore: ipRiskScore,
      });
    }

    // BLOCK pure VPNs during raids (but allow if guild is calm)
    if (isVPN) {
      const guildComposition = checkGuildIPComposition(guildId);
      // Only block VPN if guild already has 60%+ VPN or 5+ VPN accounts
      if (guildComposition.suspicious) {
        console.log(`🚫 VPN blocked due to guild raid pattern: ${guildComposition.vpnPercent}% VPN`);
        return res.status(403).json({
          success: false,
          error: 'VPN/Proxy usage is not allowed during raid conditions',
          riskLevel: 'high',
        });
      }

      // Allow VPN but mark it
      console.log(`⚠️ VPN detected for user ${userId} but guild is calm - allowing`);
    }

    // Mark user as verified
    verificationData.set(userId, {
      verified: true,
      timestamp: Date.now(),
      guildId,
      ip: clientIp,
      isVPN: isVPN,
      abuseScore: ipQuality.abuseScore || 0,
      isp: ipQuality.isp,
      usageType: ipQuality.usageType,
      ipRiskScore: ipRiskScore,
      notified: false,
    });

    // Update IP database
    if (!ipData.accounts[guildId]) {
      ipData.accounts[guildId] = [];
    }
    ipData.accounts[guildId].push(userId);
    ipData.isVPN = isVPN;

    // Remove from quarantine if present
    if (quarantineData.has(userId)) {
      quarantineData.delete(userId);
      console.log(`✅ Removed ${userId} from quarantine`);
    }

    console.log(`✅ User ${userId} verified successfully from IP ${clientIp}${isVPN ? ' (VPN)' : ''}`);

    return res.json({
      success: true,
      message: 'Verification successful! You can now use the server.',
      userId,
      guildId,
      verifiedAt: Date.now(),
      riskLevel: isVPN ? 'medium' : 'low',
      usingVPN: isVPN,
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
 * Get comprehensive raid status for a guild
 */
app.get('/api/raid-status/:guildId', validateBotSecret, (req, res) => {
  try {
    const guildId = req.params.guildId;
    const quarantinedUsers = [];
    const guildComposition = checkGuildIPComposition(guildId);

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
      composition: guildComposition,
      raidDetected: guildComposition.suspicious,
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
          riskLevel: userData.ipRiskScore >= 60 ? 'medium' : 'low',
          usingVPN: userData.isVPN,
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
app.get('/api/test-ip', async (req, res) => {
  try {
    const ip = getClientIp(req);
    console.log(`🔍 Testing IP: ${ip}`);
    
    const ipQuality = await checkIPWithAbuseIPDB(ip);
    
    res.json({
      ip,
      isVPN: ipQuality.isVPN,
      isHosting: ipQuality.isHosting,
      abuseScore: ipQuality.abuseScore,
      isp: ipQuality.isp,
      domain: ipQuality.domain,
      usageType: ipQuality.usageType,
      message: ipQuality.isVPN ? '🚫 VPN/Proxy detected' : '✅ Residential IP (allowed)',
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
const server = app.listen(PORT, () => {
  console.log(`\n╔═══════════════════════════════════════╗`);
  console.log(`║  🔐 Verification API Running 🛡️    ║`);
  console.log(`╚═══════════════════════════════════════╝\n`);
  console.log(`📍 Port: ${PORT}`);
  console.log(`🔗 Local: http://localhost:${PORT}`);
  console.log(`💚 Health: http://localhost:${PORT}/api/health\n`);
  
  if (!process.env.ABUSEIPDB_API_KEY) {
    console.warn('⚠️  ABUSEIPDB_API_KEY not set! Get one free at https://www.abuseipdb.com/register');
  } else {
    console.log('✅ AbuseIPDB API key loaded');
  }
});

module.exports = app;
