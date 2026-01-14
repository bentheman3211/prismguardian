// ==================== TRULY FREE VPN DETECTION (IP-API ONLY) ====================

async function checkIPWithMultipleSources(ip) {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);

    // IP-API: 45 req/min, 144,000/day - most generous free tier
    const response = await fetch(
      `http://ip-api.com/json/${ip}?fields=status,isp,org,reverse,mobile,proxy,query`,
      { signal: controller.signal }
    );
    clearTimeout(timeoutId);

    if (!response.ok) {
      return {
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
    }

    const data = await response.json();

    if (data.status !== 'success') {
      console.warn(`⚠️ IP-API failed for ${ip}: ${data.message}`);
      return {
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
    }

    const detectionMethods = [];
    const orgLower = (data.org || '').toLowerCase();
    const ispLower = (data.isp || '').toLowerCase();

    // VPN/Proxy indicators
    let isVPN = data.proxy === true; // IP-API has a built-in proxy field
    let isHosting = false;

    // Pattern matching for VPN services
    const vpnPatterns = [
      'expressvpn', 'nordvpn', 'surfshark', 'cyberghost', 'windscribe',
      'private internet access', 'protonvpn', 'hide.me', 'ipvanish',
      'hotspot shield', 'tunnelbear', 'mullvad', 'wireguard'
    ];

    // Pattern matching for hosting/datacenter
    const hostingPatterns = [
      'aws', 'amazon', 'azure', 'google cloud', 'digitalocean', 'linode',
      'vultr', 'hetzner', 'ovh', 'scaleway', 'oracle', 'ibm cloud',
      'fastly', 'cloudflare', 'akamai', 'softlayer', 'equinix'
    ];

    if (vpnPatterns.some(p => orgLower.includes(p) || ispLower.includes(p))) {
      isVPN = true;
      detectionMethods.push('vpn-pattern');
    }

    if (hostingPatterns.some(p => orgLower.includes(p) || ispLower.includes(p))) {
      isHosting = true;
      detectionMethods.push('hosting-pattern');
      isVPN = true; // Treat hosting as VPN
    }

    // Generic datacenter keywords
    const datacenterKeywords = ['datacenter', 'hosting', 'vps', 'server', 'cloud', 'reseller'];
    if (datacenterKeywords.some(k => ispLower.includes(k) || orgLower.includes(k))) {
      isVPN = true;
      detectionMethods.push('datacenter-keyword');
    }

    const result = {
      isVPN,
      isProxy: data.proxy === true,
      isHosting,
      abuseScore: 0,
      isp: data.isp || 'Unknown',
      domain: data.reverse || 'Unknown',
      usageType: isVPN ? 'non-residential' : 'residential',
      org: data.org || 'Unknown',
      source: 'ip-api',
      detectionMethods: detectionMethods.length > 0 ? detectionMethods : ['native-proxy-field']
    };

    console.log(`📊 IP-API Check for ${ip}:`, {
      isVPN: result.isVPN,
      methods: result.detectionMethods,
      isp: result.isp,
      org: result.org,
      proxy: data.proxy
    });

    return result;

  } catch (error) {
    console.error('❌ IP-API check error:', error.message);
    return {
      isVPN: false,
      isProxy: false,
      isHosting: false,
      abuseScore: 0,
      isp: 'Unknown',
      domain: 'Unknown',
      usageType: 'Unknown',
      source: 'error',
      detectionMethods: []
    };
  }
}

// ==================== USAGE IN YOUR VERIFICATION ====================

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

    // ✅ Single source VPN detection (truly unlimited free)
    const ipQuality = await checkIPWithMultipleSources(clientIp);
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

    // BLOCK VPNs during raids
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
      detectionMethods: ipQuality.detectionMethods,
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

app.get('/api/test-ip', async (req, res) => {
  try {
    const ip = getClientIp(req);
    console.log(`🔍 Testing IP: ${ip}`);
    
    const ipQuality = await checkIPWithMultipleSources(ip);
    
    res.json({
      ip,
      isVPN: ipQuality.isVPN,
      isHosting: ipQuality.isHosting,
      abuseScore: ipQuality.abuseScore,
      isp: ipQuality.isp,
      org: ipQuality.org,
      domain: ipQuality.domain,
      usageType: ipQuality.usageType,
      detectionMethods: ipQuality.detectionMethods,
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
