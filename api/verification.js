// ==================== MULTI-SOURCE VPN DETECTION (FREE & UNLIMITED) ====================

async function checkIPWithMultipleSources(ip) {
  const results = {
    isVPN: false,
    isProxy: false,
    isHosting: false,
    abuseScore: 0,
    isp: 'Unknown',
    domain: 'Unknown',
    usageType: 'Unknown',
    source: 'none',
    detectionMethods: []
  };

  // Try multiple free sources in parallel with short timeouts
  const checks = [
    checkIPQualityScore(ip),
    checkIPHub(ip),
    checkIPQualityScoreFree(ip),
    checkAbuseIPDB(ip)
  ];

  const responses = await Promise.allSettled(checks);

  for (const response of responses) {
    if (response.status === 'fulfilled' && response.value) {
      const data = response.value;
      if (data.isVPN || data.isProxy) {
        results.isVPN = true;
        results.detectionMethods.push(data.source);
      }
      if (data.isHosting) {
        results.isHosting = true;
      }
      if (data.abuseScore > results.abuseScore) {
        results.abuseScore = data.abuseScore;
      }
      if (data.isp && data.isp !== 'Unknown') {
        results.isp = data.isp;
      }
      if (data.usageType && data.usageType !== 'Unknown') {
        results.usageType = data.usageType;
      }
      if (data.source) {
        results.source = data.source;
      }
    }
  }

  // Fallback: Check ISP against known datacenter patterns
  if (!results.isVPN && results.isp) {
    if (isDatacenterISP(results.isp)) {
      results.isVPN = true;
      results.detectionMethods.push('isp-pattern');
    }
  }

  console.log(`📊 VPN Detection for ${ip}:`, {
    isVPN: results.isVPN,
    detectionMethods: results.detectionMethods,
    isp: results.isp,
    usageType: results.usageType
  });

  return results;
}

// ==================== METHOD 1: IPQualityScore (Free) ====================
async function checkIPQualityScore(ip) {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);

    const response = await fetch(`https://ipqualityscore.com/api/json/ip/${ip}?strictness=1`, {
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    if (!response.ok) return null;

    const data = await response.json();

    return {
      isVPN: data.vpn === true,
      isProxy: data.is_crawler === true || data.proxy === true,
      isHosting: data.is_crawler === true,
      abuseScore: data.fraud_score || 0,
      isp: data.isp || 'Unknown',
      usageType: data.usage_type || 'Unknown',
      source: 'ipqualityscore'
    };
  } catch (error) {
    console.warn('⚠️ IPQualityScore check failed:', error.message);
    return null;
  }
}

// ==================== METHOD 2: IPHub (Free) ====================
async function checkIPHub(ip) {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);

    const response = await fetch(`https://v2.api.iphub.info/?ip=${ip}`, {
      headers: {
        'X-IPHub-Api-Key': process.env.IPHUB_API_KEY || 'free', // Free tier
      },
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    if (!response.ok) return null;

    const data = await response.json();
    // block: 0 = residential, 1 = non-residential (VPN/Proxy/etc), 2 = datacenter

    return {
      isVPN: data.block === 1 || data.block === 2,
      isProxy: data.block === 1,
      isHosting: data.block === 2,
      abuseScore: 0,
      isp: 'Unknown',
      usageType: data.block === 0 ? 'residential' : 'non-residential',
      source: 'iphub'
    };
  } catch (error) {
    console.warn('⚠️ IPHub check failed:', error.message);
    return null;
  }
}

// ==================== METHOD 3: IP-API (Free) ====================
async function checkIPQualityScoreFree(ip) {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);

    const response = await fetch(`http://ip-api.com/json/${ip}?fields=isp,org,reverse,mobile,proxy`, {
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    if (!response.ok) return null;

    const data = await response.json();

    // Detect VPN by checking org/isp against known patterns
    const orgLower = (data.org || '').toLowerCase();
    const ispLower = (data.isp || '').toLowerCase();

    const vpnKeywords = ['vpn', 'proxy', 'hosting', 'datacenter', 'cloud', 'server'];
    const isVPN = vpnKeywords.some(keyword => 
      orgLower.includes(keyword) || ispLower.includes(keyword)
    );

    return {
      isVPN: isVPN || data.mobile === true,
      isProxy: isVPN,
      isHosting: false,
      abuseScore: 0,
      isp: data.isp || 'Unknown',
      usageType: 'Unknown',
      source: 'ip-api'
    };
  } catch (error) {
    console.warn('⚠️ IP-API check failed:', error.message);
    return null;
  }
}

// ==================== METHOD 4: AbuseIPDB (Free - Fallback) ====================
async function checkAbuseIPDB(ip) {
  try {
    const apiKey = process.env.ABUSEIPDB_API_KEY;
    if (!apiKey) return null;

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

    if (!response.ok) return null;

    const data = await response.json();
    const ipData = data.data || {};

    return {
      isVPN: ipData.isVpn || ipData.isProxy || false,
      isProxy: ipData.isProxy || false,
      isHosting: ipData.isHosting || false,
      abuseScore: ipData.abuseConfidenceScore || 0,
      isp: ipData.isp || 'Unknown',
      usageType: ipData.usageType || 'Unknown',
      source: 'abuseipdb'
    };
  } catch (error) {
    console.warn('⚠️ AbuseIPDB check failed:', error.message);
    return null;
  }
}

// ==================== FALLBACK: ISP Pattern Detection ====================
function isDatacenterISP(isp) {
  const datacenterPatterns = [
    // Cloud providers
    'aws', 'amazon', 'azure', 'google cloud', 'digitalocean', 'linode', 'vultr',
    'hetzner', 'ovh', 'scaleway', 'oracle cloud', 'ibm cloud', 'akamai',
    
    // VPN/Hosting providers
    'expressvpn', 'nordvpn', 'surfshark', 'cyberghost', 'windscribe', 'private internet access',
    'protonvpn', 'hide.me', 'ipvanish', 'hotspot shield', 'tunnelbear',
    
    // Hosting companies
    'linode', 'softlayer', 'zenlayer', 'equinix', 'arin', 'fastly', 'cloudflare',
    'servermania', 'ipxo', 'cogent', 'telia', 'as209',
    
    // Generic datacenters
    'hosting', 'datacenter', 'server', 'cloud', 'vps', 'dedicated',
    'colocation', 'colo', 'isp - vps', 'reseller'
  ];

  const lowerIsp = isp.toLowerCase();
  return datacenterPatterns.some(pattern => lowerIsp.includes(pattern));
}

// ==================== USAGE IN YOUR VERIFICATION ====================
// Replace your existing checkIPWithAbuseIPDB call with this:

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

    // ✅ USE THE NEW MULTI-SOURCE VPN DETECTION
    const ipQuality = await checkIPWithMultipleSources(clientIp);
    console.log(`📊 IP Quality for ${clientIp}:`, ipQuality);

    // Track this IP
    const ipData = trackIP(clientIp, userId, guildId);
    const ipRiskScore = getIPRiskScore(clientIp, guildId);

    // Determine if VPN/Proxy
    const isVPN = ipQuality.isVPN || ipQuality.isHosting;

    // REST OF YOUR CODE REMAINS THE SAME...
    if (isVPN && ipRiskScore >= 60) {
      console.log(`🚫 RAID DETECTED: VPN + multiple accounts from ${clientIp}`);
      return res.status(403).json({
        success: false,
        error: 'Cannot verify: Suspicious activity detected (VPN + multiple accounts)',
        riskScore: ipRiskScore,
      });
    }

    if (isVPN) {
      const guildComposition = checkGuildIPComposition(guildId);
      if (guildComposition.suspicious) {
        console.log(`🚫 VPN blocked due to guild raid pattern: ${guildComposition.vpnPercent}% VPN`);
        return res.status(403).json({
          success: false,
          error: 'VPN/Proxy usage is not allowed during raid conditions',
          riskLevel: 'high',
        });
      }
      console.log(`⚠️ VPN detected for user ${userId} but guild is calm - allowing`);
    }

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
      detectionMethods: ipQuality.detectionMethods,
      notified: false,
    });

    if (!ipData.accounts[guildId]) {
      ipData.accounts[guildId] = [];
    }
    ipData.accounts[guildId].push(userId);
    ipData.isVPN = isVPN;

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
      detectionMethods: ipQuality.detectionMethods,
    });
  } catch (error) {
    console.error('❌ Error during verification:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
    });
  }
});
