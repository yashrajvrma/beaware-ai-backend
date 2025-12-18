// URL Structure Analysis Utility
// Detects suspicious patterns, typosquatting, and malicious indicators

interface URLAnalysisResult {
    score: number; // 0-20
    max_score: number;
    issues: string[];
    warnings: string[];
}

// Common brand names for typosquatting detection
const POPULAR_BRANDS = [
    'google', 'facebook', 'amazon', 'microsoft', 'apple', 'netflix', 'paypal',
    'instagram', 'twitter', 'linkedin', 'github', 'dropbox', 'adobe', 'oracle',
    'salesforce', 'zoom', 'slack', 'spotify', 'youtube', 'whatsapp', 'telegram',
    'bank', 'chase', 'wellsfargo', 'citibank', 'americanexpress', 'visa', 'mastercard'
];

// Suspicious keywords commonly used in phishing
const SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'account', 'update', 'secure', 'banking',
    'confirm', 'suspended', 'locked', 'urgent', 'alert', 'warning', 'security',
    'validation', 'authenticate', 'password', 'credential', 'billing', 'payment'
];

// Suspicious TLDs often used for malicious purposes
const SUSPICIOUS_TLDS = [
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', '.click',
    '.link', '.download', '.stream', '.loan', '.win', '.bid', '.racing'
];

// Trusted TLDs
const TRUSTED_TLDS = [
    '.com', '.org', '.net', '.edu', '.gov', '.mil', '.co', '.io', '.ai'
];

export function analyzeURL(url: string, hostname: string): URLAnalysisResult {
    let score = 20; // Start with max score
    const issues: string[] = [];
    const warnings: string[] = [];

    // 1. Check for suspicious TLD
    const tld = hostname.substring(hostname.lastIndexOf('.'));
    if (SUSPICIOUS_TLDS.includes(tld.toLowerCase())) {
        score -= 8;
        issues.push(`Suspicious TLD: ${tld} (commonly used in phishing)`);
    }

    // 2. Check for typosquatting (brand name misspellings)
    const domainParts = hostname.toLowerCase().replace(/\./g, '');
    for (const brand of POPULAR_BRANDS) {
        if (domainParts.includes(brand) && !hostname.toLowerCase().includes(`${brand}.com`)) {
            // Check if it's trying to impersonate
            if (domainParts !== brand && domainParts.includes(brand)) {
                score -= 10;
                issues.push(`Potential brand impersonation: contains "${brand}" but not official domain`);
                break;
            }
        }
    }

    // 3. Check for suspicious keywords in domain
    const domainLower = hostname.toLowerCase();
    let suspiciousKeywordCount = 0;
    for (const keyword of SUSPICIOUS_KEYWORDS) {
        if (domainLower.includes(keyword)) {
            suspiciousKeywordCount++;
            warnings.push(`Domain contains suspicious keyword: "${keyword}"`);
        }
    }
    if (suspiciousKeywordCount > 0) {
        score -= Math.min(suspiciousKeywordCount * 3, 10);
    }

    // 4. Check for excessive subdomains (e.g., login.secure.paypal.verify.com)
    const subdomainCount = hostname.split('.').length - 2; // -2 for domain and TLD
    if (subdomainCount > 2) {
        score -= 5;
        warnings.push(`Excessive subdomains (${subdomainCount}) - potential obfuscation`);
    }

    // 5. Check for suspicious characters or patterns
    if (hostname.includes('--') || hostname.includes('..')) {
        score -= 5;
        issues.push('Domain contains suspicious character patterns');
    }

    // 6. Check for IP address instead of domain
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
        score -= 15;
        issues.push('Using IP address instead of domain name (highly suspicious)');
    }

    // 7. Check for very long domain names (often used in phishing)
    if (hostname.length > 40) {
        score -= 3;
        warnings.push('Unusually long domain name');
    }

    // 8. Check for numbers in domain (can be suspicious)
    const numberCount = (hostname.match(/\d/g) || []).length;
    if (numberCount > 3) {
        score -= 2;
        warnings.push('Domain contains many numbers (potentially suspicious)');
    }

    // Ensure score doesn't go below 0
    score = Math.max(0, score);

    return {
        score,
        max_score: 20,
        issues,
        warnings
    };
}

// Calculate domain age score
export function calculateDomainAgeScore(creationDate?: string): { score: number; max_score: number; reason: string } {
    if (!creationDate) {
        return { score: 0, max_score: 20, reason: 'Domain age unknown' };
    }

    const created = new Date(creationDate);
    const now = new Date();
    const ageInDays = Math.floor((now.getTime() - created.getTime()) / (1000 * 60 * 60 * 24));
    const ageInMonths = ageInDays / 30;
    const ageInYears = ageInDays / 365;

    if (ageInDays < 30) {
        return { score: 0, max_score: 20, reason: `Domain is very new (${ageInDays} days old) - HIGH RISK` };
    } else if (ageInMonths < 6) {
        return { score: 5, max_score: 20, reason: `Domain is ${Math.floor(ageInMonths)} months old - relatively new` };
    } else if (ageInMonths < 12) {
        return { score: 10, max_score: 20, reason: `Domain is ${Math.floor(ageInMonths)} months old` };
    } else if (ageInYears < 2) {
        return { score: 15, max_score: 20, reason: `Domain is ${Math.floor(ageInYears)} year(s) old` };
    } else {
        return { score: 20, max_score: 20, reason: `Domain is ${Math.floor(ageInYears)} years old - well established` };
    }
}

// Calculate SSL score
export function calculateSSLScore(ssl: any): { score: number; max_score: number; reason: string } {
    if (!ssl) {
        return { score: 0, max_score: 20, reason: 'No SSL certificate found' };
    }

    if (!ssl.valid) {
        return { score: 0, max_score: 20, reason: 'SSL certificate is invalid or expired' };
    }

    // Check if SSL is from a trusted issuer
    const trustedIssuers = ['Amazon', 'Let\'s Encrypt', 'DigiCert', 'Cloudflare', 'Google', 'Microsoft'];
    const issuerName = ssl.issuer?.O || ssl.issuer?.CN || '';
    const isTrusted = trustedIssuers.some(issuer => issuerName.includes(issuer));

    if (isTrusted) {
        return { score: 20, max_score: 20, reason: `Valid SSL from trusted CA: ${issuerName}` };
    } else {
        return { score: 10, max_score: 20, reason: `Valid SSL but from unknown CA: ${issuerName}` };
    }
}

// Calculate hosting score
export function calculateHostingScore(hosting: any): { score: number; max_score: number; reason: string } {
    if (!hosting || !hosting.ip) {
        return { score: 5, max_score: 10, reason: 'Hosting information unavailable' };
    }

    const reverse = hosting.reverse?.toLowerCase() || '';

    // Check for known good hosting providers
    const goodProviders = ['cloudfront', 'amazonaws', 'googleusercontent', 'azure', 'cloudflare'];
    const isGoodProvider = goodProviders.some(provider => reverse.includes(provider));

    if (isGoodProvider) {
        return { score: 10, max_score: 10, reason: `Hosted on reputable provider: ${hosting.reverse}` };
    } else {
        return { score: 5, max_score: 10, reason: 'Unknown hosting provider' };
    }
}
