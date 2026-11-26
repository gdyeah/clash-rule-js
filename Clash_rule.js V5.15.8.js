
// ============================================================
// Clash_rule.js V5.15.8
// 基于 V5.15.6
// 修复方向：WebRTC/STUN 规则优先级与国内 UDP 直连兼容
// STUN 规则提前，避免国内 STUN 被国内域名/IP DIRECT 规则抢先匹配
// 其他未命中的 UDP 仍按设置交给主代理
// 保留原有 DNS、广告拦截、国内分流、App 分流、代理组及订阅迁移逻辑
// 仅支持节点平铺形式，不支持原生 proxy-providers
// DNS：主解析/直连解析/代理节点解析优先使用 HTTPS DoH；
// default-nameserver 保留 IP 引导解析，避免 DoH 域名启动时循环依赖。
// ============================================================

// ── 可调参数（集中维护） ──
const CONFIG = {
    DEFAULT_IP_VERSION: "dual",
    IPV6_ENABLED: false,
    REGION_MIN_NODES: 1,
    RS_INTERVAL: 604800,
    PREFER_H3: false,
    BLOCK_QUIC: false,
    WEBRTC_STUN_PROXY: true,
    WEBRTC_UDP_PROXY_ALL: true,
    TEST_URL_PROXY: "https://www.gstatic.com/generate_204",
    TEST_INTERVAL: 300,
    CN_DNS_DOH: [
        "https://223.5.5.5/dns-query",
        "https://doh.pub/dns-query"
    ],
    CN_DNS_PLAIN: ["223.5.5.5", "119.29.29.29"],
    FOREIGN_DNS_DOH: [
        "https://cloudflare-dns.com/dns-query#主代理",
        "https://dns.google/dns-query#主代理"
    ]
};

const warnLog = (...args) => {
    if (typeof console === "undefined") return;
    if (typeof console.warn === "function") console.warn(...args);
    else if (typeof console.log === "function") console.log(...args);
};

const isPlainObject = value =>
    value && typeof value === "object" && !Array.isArray(value);

function main(params) {
    if (!isPlainObject(params)) params = {};
    if (!Array.isArray(params.proxies)) params.proxies = [];

    params.proxies = params.proxies.filter(
        proxy => proxy &&
            typeof proxy.name === "string" &&
            proxy.name.trim() !== ""
    );
    params.proxies.forEach(proxy => {
        proxy.name = proxy.name.trim();
    });

    if (Object.keys(params["proxy-providers"] || {}).length > 0) {
        throw new Error(
            "[Clash_rule.js] 检测到 proxy-providers 订阅，本脚本仅支持节点平铺形式。"
        );
    }

    params.profile = Object.assign(
        { "store-selected": true, "store-fake-ip": true },
        isPlainObject(params.profile) ? params.profile : {}
    );

    const subRuleProviders = Object.assign(
        {},
        params["rule-providers"] || {}
    );

    const basicOptions = {
        "unified-delay": true,
        "tcp-concurrent": true,
        "find-process-mode": "off",
        "keep-alive-idle": 300,
        "keep-alive-interval": 30
    };

    const ipv6Enabled =
        CONFIG.IPV6_ENABLED === true &&
        params.ipv6 !== false &&
        !(isPlainObject(params.dns) && params.dns.ipv6 === false);

    params.ipv6 = ipv6Enabled;
    Object.assign(params, basicOptions);
    delete params["global-client-fingerprint"];

    params.sniffer = {
        enable: true,
        "force-dns-mapping": true,
        "parse-pure-ip": true,
        "override-destination": true,
        sniff: {
            HTTP: {
                ports: [80, "8080-8880"],
                "override-destination": true
            },
            TLS: { ports: [443, 8443] },
            QUIC: { ports: [443, 8443] }
        },
        "skip-domain": [
            "Mijia Cloud",
            "+.apple.com",
            "+.openai.com",
            "+.oaistatic.com",
            "+.oaiusercontent.com",
            "+.chatgpt.com"
        ]
    };

    const EXCLUDE_KEYWORDS = [
        "剩余", "官网", "套餐", "已用", "到期", "过期", "重置", "更新", "刷新", "订阅",
        "通知", "本站", "网址", "客服", "欢迎", "Expire", "Traffic", "Reset",
        "有效期", "有效至", "加群", "入群", "群聊", "群号", "群组", "群链接",
        "防失联", "防走丢"
    ];

    const EXCLUDE_COMPLEX = [
        "(剩余|已用|可用|查询|超出|总)流量",
        "流量([:：]|\\s*(剩余|已用|可用|重置|耗尽|不足|提醒|查询|统计|清零))",
        "(到期|过期|剩余|重置|更新|刷新|有效)时间",
        "时间[:：]",
        "(官网|最新|发布|永久|备用|防失联|防走丢)地址",
        "地址[:：]",
        "(QQ|TG|Telegram|电报|交流|官方|通知|用户)群",
        "群([:：|｜\\s]|$)",
        "加入(我们|群|TG|电报|频道|Telegram|QQ)",
        "(^|[^A-Za-z0-9])(\\d+\\s*Days?|(Data|Used|Left|Remain|Quota)\\s*[:：\\s]*\\d+(\\.\\d+)?\\s*(GB|TB)|\\d+(\\.\\d+)?\\s*(GB|TB)\\s*/\\s*\\d+(\\.\\d+)?\\s*(GB|TB))([^A-Za-z0-9]|$)"
    ];

    const excludeFilter =
        "(?i)(" +
        EXCLUDE_KEYWORDS.map(k =>
            k.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
        ).join("|") +
        "|" + EXCLUDE_COMPLEX.join("|") + ")";

    const QURE_ICON_BASE =
        "https://cdn.jsdmirror.com/gh/Koolson/Qure@master/IconSet/Color";
    const qureIcon = name => `${QURE_ICON_BASE}/${name}`;

    const FLAG_ICON_BASE =
        "https://cdn.jsdmirror.com/gh/open-assets-hub/country-flag-collection@main/circle/128";
    const flagIcon = code => `${FLAG_ICON_BASE}/${code}.png`;

    const regions = [
        { name: "AE", regex: "(?i)(阿联酋|阿聯酋|迪拜|阿布扎比|🇦🇪|(^|[^A-Za-z])UAE([^A-Za-z]|$)|Emirates|Dubai|Abu[ -]?Dhabi)", icon: flagIcon("ae") },
        { name: "AR", regex: "(?i)(阿根廷|布宜诺斯艾利斯|🇦🇷|(^|[^A-Za-z])AR([^A-Za-z]|$)|(^|[^A-Za-z])ARG([^A-Za-z]|$)|Argentina|Buenos[ -]?Aires)", icon: flagIcon("ar") },
        { name: "AU", regex: "(?i)(澳大利亚|澳大利亞|澳洲|悉尼|墨尔本|墨爾本|🇦🇺|(^|[^A-Za-z])AU([^A-Za-z]|$)|(^|[^A-Za-z])AUS([^A-Za-z]|$)|Australia|Sydney|Melbourne|Brisbane|Perth|Adelaide)", icon: flagIcon("au") },
        { name: "BD", regex: "(?i)(孟加拉|孟加拉國|达卡|達卡|🇧🇩|(^|[^A-Za-z])BD([^A-Za-z]|$)|(^|[^A-Za-z])BGD([^A-Za-z]|$)|Bangladesh|Dhaka)", icon: flagIcon("bd") },
        { name: "BR", regex: "(?i)(巴西|圣保罗|聖保羅|🇧🇷|(^|[^A-Za-z])BR([^A-Za-z]|$)|(^|[^A-Za-z])BRA([^A-Za-z]|$)|Brazil|Brasil|(Sao|São)[ -]?Paulo|Rio[ -]?de[ -]?Janeiro|(^|[^A-Za-z])Rio([^A-Za-z]|$))", icon: flagIcon("br") },
        { name: "CA", regex: "(?i)(加拿大|多伦多|多倫多|温哥华|溫哥華|🇨🇦|(^|[^A-Za-z])CA([^A-Za-z]|$)|(^|[^A-Za-z])CAN([^A-Za-z]|$)|Canada|Toronto|Vancouver|Montreal|Calgary)", icon: flagIcon("ca") },
        { name: "DE", regex: "(?i)(德国|德國|法兰克福|法蘭克福|🇩🇪|(^|[^A-Za-z])DE([^A-Za-z]|$)|(^|[^A-Za-z])DEU([^A-Za-z]|$)|Germany|Frankfurt|Berlin|Munich|Düsseldorf|Dusseldorf|Nuremberg)", icon: flagIcon("de") },
        { name: "FR", regex: "(?i)(法国|法國|巴黎|🇫🇷|(^|[^A-Za-z])FR([^A-Za-z]|$)|(^|[^A-Za-z])FRA([^A-Za-z]|$)|France|Paris|Marseille|Lyon)", icon: flagIcon("fr") },
        { name: "GB", regex: "(?i)(英国|英國|伦敦|倫敦|🇬🇧|(^|[^A-Za-z])UK([^A-Za-z]|$)|(^|[^A-Za-z])GB([^A-Za-z]|$)|(^|[^A-Za-z])GBR([^A-Za-z]|$)|United[ -]?Kingdom|England|London|Manchester|Edinburgh)", icon: flagIcon("gb") },
        { name: "HK", regex: "(?i)(香港|九龙|🇭🇰|(^|[^A-Za-z])HK([^A-Za-z]|$)|(^|[^A-Za-z])HKG([^A-Za-z]|$)|Hong[ -]?Kong|Kowloon|Tsuen[ -]?Wan)", icon: flagIcon("hk") },
        { name: "ID", regex: "(?i)(印度尼西亚|印度尼西亞|印尼|雅加达|雅加達|🇮🇩|Indonesia|Jakarta|Surabaya|(^|[^A-Za-z])ID([^A-Za-z]|$)|(^|[^A-Za-z])IDN([^A-Za-z]|$))", icon: flagIcon("id") },
        { name: "IN", regex: "(?i)(印度([^尼]|$)|新德里|孟买|孟買|班加罗尔|班加羅爾|🇮🇳|(^|[^A-Za-z])India([^A-Za-z]|$)|Mumbai|(New[ -]?)?Delhi|Bangalore|Chennai|Hyderabad|(^|[^A-Za-z])IN([^A-Za-z]|$)|(^|[^A-Za-z])IND([^A-Za-z]|$))", icon: flagIcon("in") },
        { name: "JP", regex: "(?i)(日本|东京|東京|大阪|名古屋|福冈|🇯🇵|(^|[^A-Za-z])JP([^A-Za-z]|$)|(^|[^A-Za-z])JPN([^A-Za-z]|$)|Japan|Tokyo|Osaka|Narita|Haneda|Kyoto|Fukuoka|Nagoya|Sapporo)", icon: flagIcon("jp") },
        { name: "KR", regex: "(?i)(韩国|韓國|南韩|南韓|首尔|首爾|🇰🇷|(^|[^A-Za-z])KR([^A-Za-z]|$)|(^|[^A-Za-z])KOR([^A-Za-z]|$)|Korea|Seoul|Busan|Incheon|Chuncheon)", icon: flagIcon("kr") },
        { name: "MY", regex: "(?i)(马来西亚|馬來西亞|吉隆坡|🇲🇾|(^|[^A-Za-z])MY([^A-Za-z]|$)|(^|[^A-Za-z])MYS([^A-Za-z]|$)|Malaysia|Kuala[ -]?Lumpur|Johor[ -]?Bahru|Cyberjaya)", icon: flagIcon("my") },
        { name: "NL", regex: "(?i)(荷兰|荷蘭|阿姆斯特丹|🇳🇱|(^|[^A-Za-z])NL([^A-Za-z]|$)|(^|[^A-Za-z])NLD([^A-Za-z]|$)|Netherlands|Amsterdam|Rotterdam)", icon: flagIcon("nl") },
        { name: "PH", regex: "(?i)(菲律宾|菲律賓|马尼拉|馬尼拉|宿务|宿霧|🇵🇭|(^|[^A-Za-z])PH([^A-Za-z]|$)|(^|[^A-Za-z])PHL([^A-Za-z]|$)|Philippines|Manila|Cebu)", icon: flagIcon("ph") },
        { name: "SG", regex: "(?i)(新加坡|狮城|獅城|🇸🇬|(^|[^A-Za-z])SG([^A-Za-z]|$)|(^|[^A-Za-z])SGP([^A-Za-z]|$)|Singapore)", icon: flagIcon("sg") },
        { name: "TH", regex: "(?i)(泰国|泰國|曼谷|🇹🇭|Thailand|Bangkok|Pattaya|Chiang[ -]?Mai|(^|[^A-Za-z])TH([^A-Za-z]|$)|(^|[^A-Za-z])THA([^A-Za-z]|$))", icon: flagIcon("th") },
        { name: "TR", regex: "(?i)(土耳其|伊斯坦布尔|🇹🇷|(^|[^A-Za-z])TR([^A-Za-z]|$)|(^|[^A-Za-z])TUR([^A-Za-z]|$)|Turkey|Türkiye|Istanbul|Ankara)", icon: flagIcon("tr") },
        { name: "TW", regex: "(?i)(台湾|台灣|台北|新北|台中|高雄|🇹🇼|(^|[^A-Za-z])TW([^A-Za-z]|$)|(^|[^A-Za-z])TWN([^A-Za-z]|$)|Taiwan|Taipei|Kaohsiung|Taichung|Hsinchu)", icon: flagIcon("tw") },
        { name: "US", regex: "(?i)(美国|美國|美西|美东|达拉斯|芝加哥|拉斯维加斯|洛杉矶|洛杉磯|圣何塞|聖何塞|硅谷|矽谷|西雅图|西雅圖|纽约|紐約|🇺🇸|(^|[^A-Za-z])US([^A-Za-z]|$)|(^|[^A-Za-z])USA([^A-Za-z]|$)|United[ -]?States|Los[ -]?Angeles|San[ -]?Jose|Silicon[ -]?Valley|New[ -]?York|Seattle|Dallas|Chicago|Fremont|Phoenix|Denver|Atlanta|Miami)", icon: flagIcon("us") },
        { name: "VN", regex: "(?i)(越南|河内|河內|胡志明|🇻🇳|(^|[^A-Za-z])VN([^A-Za-z]|$)|(^|[^A-Za-z])VNM([^A-Za-z]|$)|Viet[ -]?Nam|Hanoi|Ho[ -]?Chi[ -]?Minh)", icon: flagIcon("vn") }
    ];

    const apps = [
        { name: "AI", icon: "ChatGPT.png" },
        { name: "Apple", icon: "Apple.png" },
        { name: "GitHub", icon: "GitHub.png" },
        { name: "Google", icon: "Google_Search.png" },
        { name: "Microsoft", icon: "Microsoft.png" },
        { name: "PayPal", icon: "PayPal.png" },
        { name: "Spotify", icon: "Spotify.png" },
        { name: "Steam", icon: "Steam.png" },
        { name: "Telegram", icon: "Telegram_X.png" },
        { name: "TikTok", icon: "TikTok_1.png" },
        { name: "TV", icon: "Netflix.png" },
        { name: "X", icon: "X.png" },
        { name: "YouTube", icon: "YouTube.png" }
    ];

    const OWN_GROUPS = [
        "主代理", "自动选择", "静态", "直连", "兜底",
        ...apps.map(app => app.name)
    ];

    const BUILTIN_POLICIES = new Set([
        "DIRECT", "REJECT", "REJECT-DROP", "COMPATIBLE",
        "PASS", "PASS-RULE", "GLOBAL", "RULES"
    ]);

    const RESERVED_NAMES = new Set([
        ...OWN_GROUPS,
        ...regions.map(region => region.name),
        ...BUILTIN_POLICIES
    ]);

    const usedProxyNames = new Set();
    const proxyRenames = new Map();

    params.proxies.forEach(proxy => {
        let name = proxy.name;
        const originalName = name;

        if (RESERVED_NAMES.has(name) || usedProxyNames.has(name)) {
            const reservedHit = RESERVED_NAMES.has(name);
            let candidate = name;
            let suffix = 0;

            do {
                suffix++;
                candidate = reservedHit
                    ? "节点·" + name + (suffix > 1 ? "·" + suffix : "")
                    : name + "·" + suffix;
            } while (
                RESERVED_NAMES.has(candidate) ||
                usedProxyNames.has(candidate)
            );

            name = candidate;
            proxy.name = name;
        }

        if (name !== originalName && !proxyRenames.has(originalName)) {
            proxyRenames.set(originalName, name);
        }

        usedProxyNames.add(name);
    });

    const finalProxyNames = new Set(params.proxies.map(proxy => proxy.name));
    [...proxyRenames.keys()].forEach(oldName => {
        if (finalProxyNames.has(oldName)) proxyRenames.delete(oldName);
    });

    const naturalCompare = (a, b) => {
        const chunk = s => {
            const parts = [];
            const chunkRe = /(\d+)|(\D+)/g;
            let m;
            while ((m = chunkRe.exec(s)) !== null) {
                parts.push(m[1] !== undefined ? Number(m[1]) : m[2]);
            }
            return parts;
        };
        const pa = chunk(a), pb = chunk(b);
        for (let i = 0; i < Math.min(pa.length, pb.length); i++) {
            const x = pa[i], y = pb[i];
            if (x === y) continue;
            if (typeof x === "number" && typeof y === "number") return x - y;
            return String(x) < String(y) ? -1 : 1;
        }
        return pa.length - pb.length;
    };

    const toJsRegex = goStyleRegex =>
        new RegExp(goStyleRegex.replace(/^\(\?i\)/, ""), "i");

    const allProxies = params.proxies.filter(
        proxy => proxy.type !== "direct" && proxy.type !== "reject"
    );

    const excludeRe = toJsRegex(excludeFilter);
    const usableProxies = allProxies.filter(
        proxy => !excludeRe.test(proxy.name)
    );
    const usableNames = usableProxies.map(proxy => proxy.name);

    const filteredCount = allProxies.length - usableProxies.length;
    if (filteredCount > 0) {
        warnLog(
            `[Clash_rule.js] 已过滤 ${filteredCount} 个信息类节点，实际可用节点 ${usableProxies.length} 个。`
        );
    }

    const minRegionNodes = Math.max(1, CONFIG.REGION_MIN_NODES);
    const regionNodeNames = new Map();

    const activeRegions = regions.filter(region => {
        const regex = toJsRegex(region.regex);
        const matched = usableProxies
            .filter(proxy => regex.test(proxy.name))
            .map(proxy => proxy.name);

        if (matched.length >= minRegionNodes) {
            regionNodeNames.set(region.name, matched);
            return true;
        }
        return false;
    });

    const hasActiveRegions = activeRegions.length > 0;
    const activeRegionNames = activeRegions.map(region => region.name);

    if (activeRegionNames.length > 0) {
        warnLog(
            `[Clash_rule.js] 已创建地区组：${activeRegionNames.join("、")}`
        );
    }

    const REGION_NAMES = new Set(activeRegionNames);
    const PROXY_NAMES = new Set(
        allProxies.map(proxy => proxy && proxy.name).filter(Boolean)
    );

    const refValid = ref =>
        BUILTIN_POLICIES.has(ref) ||
        OWN_GROUPS.indexOf(ref) !== -1 ||
        REGION_NAMES.has(ref) ||
        PROXY_NAMES.has(ref);

    const asPlainObject = value =>
        isPlainObject(value) ? value : {};

    const stringList = value => {
        if (value === undefined || value === null) return [];
        const list = Array.isArray(value) ? value : [value];
        return list
            .filter(item => typeof item === "string")
            .map(item => item.trim())
            .filter(Boolean);
    };

    const isCatchAllDomain = pattern =>
        pattern === "*" || pattern === "+" || pattern === "+." || pattern === ".";

    const parsePolicyKey = key => {
        const parts = String(key).split(",").map(part => part.trim()).filter(Boolean);
        const out = [];
        let activePrefix = null;
        for (const part of parts) {
            const rsMatch = /^rule-set:(.*)$/i.exec(part);
            if (rsMatch) {
                activePrefix = "rule-set";
                const name = rsMatch[1].trim();
                if (name) out.push({ kind: "rule-set", value: name });
                continue;
            }
            if (/^(geosite|geoip):/i.test(part)) {
                activePrefix = "geo";
                out.push({ kind: "geo", value: part });
                continue;
            }
            if (activePrefix === "rule-set" &&
                Object.prototype.hasOwnProperty.call(subRuleProviders, part)) {
                out.push({ kind: "rule-set", value: part });
                continue;
            }
            if (activePrefix && !/[.*+:]/.test(part)) {
                out.push({ kind: activePrefix, value: part });
                continue;
            }
            activePrefix = null;
            out.push({ kind: "domain", value: part });
        }
        return out;
    };

    const ruleSetNames = key => parsePolicyKey(key)
        .filter(segment => segment.kind === "rule-set")
        .map(segment => segment.value);

    const toRealIpRules = pattern => {
        const value = String(pattern).trim();
        if (!value || value.includes(",") || isCatchAllDomain(value) ||
            /^(rule-set|geosite|geoip):/i.test(value)) return [];
        if (value.startsWith("+.")) {
            const rest = value.slice(2);
            if (!rest || rest.startsWith(".") || rest.includes("+") || isCatchAllDomain(rest)) return [];
            if (/[*?]/.test(rest)) return [
                `DOMAIN-WILDCARD,${rest},real-ip`,
                `DOMAIN-WILDCARD,*.${rest},real-ip`
            ];
            return [`DOMAIN-SUFFIX,${rest},real-ip`];
        }
        if (value.includes("+")) return [];
        if (value.startsWith(".")) {
            const rest = value.slice(1);
            if (!rest || rest.startsWith(".") || isCatchAllDomain(rest)) return [];
            return [`DOMAIN-WILDCARD,*.${rest},real-ip`];
        }
        if (/[*?]/.test(value)) return [`DOMAIN-WILDCARD,${value},real-ip`];
        return [`DOMAIN,${value},real-ip`];
    };

    const sanitizeFakeIpRule = rule => {
        const value = String(rule).trim();
        const lastComma = value.lastIndexOf(",");
        if (lastComma < 0) return null;
        const action = value.slice(lastComma + 1).trim().toLowerCase();
        if (action !== "fake-ip" && action !== "real-ip") return null;
        const head = value.slice(0, lastComma).trim();
        const firstComma = head.indexOf(",");
        if (firstComma < 0) return null;
        const type = head.slice(0, firstComma).trim().toUpperCase();
        const payload = head.slice(firstComma + 1).trim();
        if (!payload || !["DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD"].includes(type)) return null;
        if (isCatchAllDomain(payload) || /^(rule-set|geosite|geoip):/i.test(payload)) return null;
        if (type === "DOMAIN-WILDCARD" && (payload.includes("+") || payload.startsWith("."))) return null;
        if (type === "DOMAIN" && /[*?]/.test(payload)) return null;
        return `${type},${payload},${action}`;
    };

    const isSpecialDnsScheme = s =>
        /^(system|rcode|dhcp):\/\//i.test(s) ||
        s.toLowerCase() === "system";

    const stripDanglingRef = (entry, respectRules = false) => {
        const s = String(entry).trim();
        const hash = s.indexOf("#");

        if (hash === -1) {
            return respectRules && !isSpecialDnsScheme(s)
                ? s + "#RULES"
                : s;
        }

        const base = s.slice(0, hash);
        const rawParts = s.slice(hash + 1)
            .split("&").map(part => part.trim()).filter(Boolean);

        const paramParts = rawParts.filter(part => part.includes("="));
        const targetParts = rawParts.filter(part => !part.includes("="));
        const validTargets = targetParts.filter(refValid);

        const needRulesFallback =
            (targetParts.length > 0 && validTargets.length === 0) ||
            (targetParts.length === 0 &&
                respectRules &&
                !isSpecialDnsScheme(base));

        const finalTargets = needRulesFallback ? ["RULES"] : validTargets;
        const finalParts = [...finalTargets, ...paramParts];

        return finalParts.length > 0
            ? base + "#" + finalParts.join("&")
            : base;
    };

    const stripProxyRefs = entry => {
        const s = String(entry);
        const hash = s.indexOf("#");
        if (hash === -1) return s;

        const params = s.slice(hash + 1)
            .split("&")
            .map(part => part.trim())
            .filter(part => part !== "" && part.includes("="));

        return params.length > 0
            ? s.slice(0, hash) + "#" + params.join("&")
            : s.slice(0, hash);
    };

    const stripProxyRefsPolicy = policy => {
        const out = {};
        for (const key of Object.keys(policy)) {
            out[key] = stringList(policy[key]).map(stripProxyRefs);
        }
        return out;
    };

    const isCarriableProvider = (name, provider) => {
        if (!isPlainObject(provider)) {
            warnLog(`[Clash_rule.js] 规则集 "${name}" 不是有效对象，已丢弃。`);
            return false;
        }

        const type = provider.type;
        if (typeof type !== "string" || !type.trim()) {
            warnLog(`[Clash_rule.js] 规则集 "${name}" 缺少有效 type，已丢弃。`);
            return false;
        }

        if (type === "file") {
            warnLog(`[Clash_rule.js] 规则集 "${name}" 是本地 file 类型，已丢弃。`);
            return false;
        }

        if (type === "http" &&
            (typeof provider.url !== "string" || !provider.url.trim())) {
            warnLog(`[Clash_rule.js] 规则集 "${name}" 缺少 url，已丢弃。`);
            return false;
        }

        return true;
    };

    const deriveSubDNS = rawDNS => {
        const subDNS = isPlainObject(rawDNS) ? rawDNS : {};
        const subRespectRules = subDNS["respect-rules"] === true;

        const hasFallbackComplexity =
            subDNS.fallback !== undefined ||
            subDNS["fallback-filter"] !== undefined;

        if (hasFallbackComplexity) {
            warnLog(
                "[Clash_rule.js] 检测到订阅 fallback / fallback-filter：不搬运这两个字段，主上游使用脚本默认代理 DoH；保留有效特定域名策略和显式 proxy-server-nameserver。"
            );
        }

        const cleanWithRules = item =>
            stripDanglingRef(item, subRespectRules);

        const isHttpsDoH = value =>
            typeof value === "string" && /^https:\/\//i.test(value.trim());

        const subPSN = stringList(
            subDNS["proxy-server-nameserver"]
        ).map(stripProxyRefs).filter(isHttpsDoH);

        const subNS = stringList(subDNS.nameserver)
            .map(cleanWithRules)
            .filter(isHttpsDoH);

        const rawPolicy = asPlainObject(subDNS["nameserver-policy"]);
        const subPolicy = {};
        const mergePolicyEntry = (target, key, values) => {
            if (!key || !values || values.length === 0) return;
            target[key] = [...new Set([...(stringList(target[key])), ...values])];
        };

        const modeRaw = subDNS["fake-ip-filter-mode"];
        const mode = typeof modeRaw === "string"
            ? modeRaw.trim().toLowerCase()
            : "";

        let subFilter = [];
        if (mode === "" || mode === "blacklist") {
            subFilter = stringList(subDNS["fake-ip-filter"]).flatMap(toRealIpRules);
        } else if (mode === "rule") {
            subFilter = stringList(subDNS["fake-ip-filter"])
                .map(sanitizeFakeIpRule).filter(Boolean);
        } else if (mode === "whitelist") {
            warnLog("[Clash_rule.js] 订阅 fake-ip-filter-mode 为 whitelist，与脚本 rule 模式语义相反；已跳过订阅 fake-ip-filter。");
        } else if (mode) {
            warnLog(`[Clash_rule.js] 不识别订阅 fake-ip-filter-mode：${mode}；已跳过订阅 fake-ip-filter。`);
        }

        const policyCarriedProviders = {};

        for (const key of Object.keys(rawPolicy)) {
            const servers = stringList(rawPolicy[key]).map(cleanWithRules);
            if (servers.length === 0) continue;
            const domainKeys = [];
            const validNames = [];
            for (const segment of parsePolicyKey(key)) {
                if (segment.kind === "geo") continue;
                if (segment.kind === "rule-set") {
                    const name = segment.value;
                    if (Object.prototype.hasOwnProperty.call(subRuleProviders, name) &&
                        isCarriableProvider(name, subRuleProviders[name])) {
                        if (!validNames.includes(name)) validNames.push(name);
                        policyCarriedProviders[name] = subRuleProviders[name];
                    }
                    continue;
                }
                if (!isCatchAllDomain(segment.value)) domainKeys.push(segment.value);
            }
            if (domainKeys.length > 0) {
                mergePolicyEntry(subPolicy, domainKeys.join(","), servers);
            }
            for (const name of validNames) {
                mergePolicyEntry(subPolicy, `rule-set:${name}`, servers);
            }
            if (domainKeys.length === 0 && validNames.length === 0) {
                warnLog(`[Clash_rule.js] nameserver-policy "${key}" 没有可迁移的有效域名或规则集键，已跳过。`);
            }
        }

        for (const key of Object.keys(subPolicy)) {
            subPolicy[key] = stringList(subPolicy[key]).filter(value =>
                isHttpsDoH(value) || /^rcode:\/\//i.test(value)
            );
            if (subPolicy[key].length === 0) delete subPolicy[key];
        }

        const rawPSNPolicy = asPlainObject(
            subDNS["proxy-server-nameserver-policy"]
        );

        const subPSNPolicy = {};
        const psnCarriedProviders = {};

        for (const key of Object.keys(rawPSNPolicy)) {
            const servers = stringList(rawPSNPolicy[key]).map(stripProxyRefs);
            if (servers.length === 0) continue;
            const domainKeys = [];
            const validNames = [];
            for (const segment of parsePolicyKey(key)) {
                if (segment.kind === "geo") continue;
                if (segment.kind === "rule-set") {
                    const name = segment.value;
                    if (Object.prototype.hasOwnProperty.call(subRuleProviders, name) &&
                        isCarriableProvider(name, subRuleProviders[name])) {
                        if (!validNames.includes(name)) validNames.push(name);
                        psnCarriedProviders[name] = subRuleProviders[name];
                    }
                    continue;
                }
                if (!isCatchAllDomain(segment.value)) domainKeys.push(segment.value);
            }
            if (domainKeys.length > 0) {
                mergePolicyEntry(subPSNPolicy, domainKeys.join(","), servers.filter(isHttpsDoH));
            }
            for (const name of validNames) {
                mergePolicyEntry(subPSNPolicy, `rule-set:${name}`, servers);
            }
        }

        const carriedRuleProviders = Object.assign(
            {},
            policyCarriedProviders,
            psnCarriedProviders
        );

        let proxyServerNameserver;
        let proxyServerNameserverPolicy;

        if (subPSN.length > 0) {
            proxyServerNameserver = [...new Set(subPSN)];
            proxyServerNameserverPolicy = subPSNPolicy;
        } else {
            for (const key of Object.keys(psnCarriedProviders)) {
                if (!policyCarriedProviders[key]) {
                    delete carriedRuleProviders[key];
                }
            }

            if (hasFallbackComplexity) {
                proxyServerNameserver = [...CONFIG.CN_DNS_DOH];
                proxyServerNameserverPolicy = undefined;
            } else if (
                subNS.length > 0 ||
                Object.keys(subPolicy).length > 0
            ) {
                proxyServerNameserver = subNS.length > 0
                    ? [...new Set(subNS.map(stripProxyRefs))]
                    : [...CONFIG.CN_DNS_DOH];

                proxyServerNameserverPolicy =
                    Object.keys(subPolicy).length > 0
                        ? stripProxyRefsPolicy(subPolicy)
                        : undefined;
            } else {
                proxyServerNameserver = [...CONFIG.CN_DNS_DOH];
                proxyServerNameserverPolicy = undefined;
            }
        }

        return {
            subDNS,
            subNS,
            subPolicy,
            subFilter,
            hasFallbackComplexity,
            carriedRuleProviders,
            proxyServerNameserver,
            proxyServerNameserverPolicy
        };
    };

    let dnsInfo;

    try {
        const rawDNS = params.dns;
        if (rawDNS !== undefined &&
            rawDNS !== null &&
            !isPlainObject(rawDNS)) {
            throw new Error("dns 字段不是对象");
        }
        dnsInfo = deriveSubDNS(rawDNS);
    } catch (error) {
        warnLog(
            "[Clash_rule.js] 读取订阅 DNS 出错：" +
            (error && error.message ? error.message : String(error)) +
            "，改用脚本默认配置。"
        );
        dnsInfo = deriveSubDNS(null);
    }

    const {
        subDNS,
        subNS,
        subPolicy,
        subFilter,
        hasFallbackComplexity,
        carriedRuleProviders,
        proxyServerNameserver,
        proxyServerNameserverPolicy
    } = dnsInfo;

    params.dns = {
        enable: true,
        listen: "127.0.0.1:1053",
        ipv6: ipv6Enabled,
        "prefer-h3": CONFIG.PREFER_H3,
        "enhanced-mode": "fake-ip",
        "fake-ip-range": "198.18.0.1/16",
        ...(ipv6Enabled ? { "fake-ip-range6": "fdfe:dcba:9876::/64" } : {}),
        "cache-algorithm": "arc",
        "fake-ip-filter-mode": "rule",
        "use-hosts": typeof subDNS["use-hosts"] === "boolean"
            ? subDNS["use-hosts"] : true,
        "use-system-hosts": typeof subDNS["use-system-hosts"] === "boolean"
            ? subDNS["use-system-hosts"] : true,
        "fake-ip-filter": [
            ...new Set([
                "DOMAIN-SUFFIX,lan,real-ip",
                "DOMAIN-SUFFIX,local,real-ip",
                "DOMAIN-SUFFIX,home.arpa,real-ip",
                "DOMAIN,localhost.ptlogin2.qq.com,real-ip",
                "DOMAIN,localhost.sec.qq.com,real-ip",
                "DOMAIN,localhost.work.weixin.qq.com,real-ip",
                "DOMAIN-SUFFIX,msftconnecttest.com,real-ip",
                "DOMAIN-SUFFIX,msftncsi.com,real-ip",
                "DOMAIN-SUFFIX,ntp.org,real-ip",
                "DOMAIN-SUFFIX,xboxlive.com,real-ip",
                "DOMAIN-SUFFIX,playstation.net,real-ip",
                "DOMAIN-SUFFIX,xbox.com,real-ip",
                "DOMAIN,xbox.ipv6.microsoft.com,real-ip",
                "DOMAIN-SUFFIX,srv.nintendo.net,real-ip",
                "DOMAIN,time.windows.com,real-ip",
                "DOMAIN,time.apple.com,real-ip",
                "DOMAIN,time.asia.apple.com,real-ip",
                "DOMAIN,time.android.com,real-ip",
                "DOMAIN,time.nist.gov,real-ip",
                "DOMAIN,ntp.aliyun.com,real-ip",
                "DOMAIN,ntp.tencent.com,real-ip",
                "DOMAIN,ntp.ntsc.ac.cn,real-ip",
                "DOMAIN-WILDCARD,stun.*,real-ip",
                "DOMAIN-WILDCARD,*.stun.*,real-ip",
                "RULE-SET,apple-domain,fake-ip",
                "RULE-SET,google-domain,fake-ip",
                "RULE-SET,microsoft-domain,fake-ip",
                "RULE-SET,ai-domain,fake-ip",
                ...subFilter,
                "RULE-SET,private-domain,real-ip",
                "RULE-SET,cn-domain,real-ip",
                "RULE-SET,fakeip-filter,real-ip",
                "MATCH,fake-ip"
            ])
        ],
        "default-nameserver": [...CONFIG.CN_DNS_PLAIN],
        "proxy-server-nameserver": proxyServerNameserver,
        ...(proxyServerNameserverPolicy &&
            Object.keys(proxyServerNameserverPolicy).length > 0
            ? { "proxy-server-nameserver-policy": proxyServerNameserverPolicy }
            : {}),
        nameserver: [...CONFIG.FOREIGN_DNS_DOH],
        "direct-nameserver": [...CONFIG.CN_DNS_DOH],
        "direct-nameserver-follow-policy": true,
        "nameserver-policy": Object.assign({}, subPolicy)
    };

    if (isPlainObject(subDNS.hosts) && Object.keys(subDNS.hosts).length > 0) {
        params.hosts = Object.assign(
            {},
            subDNS.hosts,
            isPlainObject(params.hosts) ? params.hosts : {}
        );
    }

    const RS_BASE =
        "https://cdn.jsdmirror.com/gh/MetaCubeX/meta-rules-dat@meta/geo";

    const domainProvider = name => ({
        type: "http",
        behavior: "domain",
        format: "mrs",
        url: `${RS_BASE}/geosite/${name}.mrs`,
        path: `./ruleset/geosite-${name}.mrs`,
        interval: CONFIG.RS_INTERVAL
    });

    const ipProvider = name => ({
        type: "http",
        behavior: "ipcidr",
        format: "mrs",
        url: `${RS_BASE}/geoip/${name}.mrs`,
        path: `./ruleset/geoip-${name}.mrs`,
        interval: CONFIG.RS_INTERVAL
    });

    const DOMAIN_SETS = {
        "private-domain": "private",
        "synology-domain": "synology",
        "ads-domain": "category-ads-all",
        "youtube-domain": "youtube",
        "twitter-domain": "twitter",
        "tiktok-domain": "tiktok",
        "telegram-domain": "telegram",
        "github-domain": "github",
        "ai-domain": "category-ai-!cn",
        "netflix-domain": "netflix",
        "disney-domain": "disney",
        "primevideo-domain": "primevideo",
        "appletv-domain": "apple-tvplus",
        "hbo-domain": "hbo",
        "spotify-domain": "spotify",
        "steam-domain": "steam",
        "paypal-domain": "paypal",
        "google-domain": "google",
        "apple-domain": "apple",
        "microsoft-domain": "microsoft",
        "proxy-domain": "geolocation-!cn",
        "cn-domain": "cn"
    };

    const IP_SETS = {
        "private-ip": "private",
        "telegram-ip": "telegram",
        "cn-ip": "cn"
    };

    params["rule-providers"] = {};

    Object.keys(DOMAIN_SETS).forEach(key => {
        params["rule-providers"][key] = domainProvider(DOMAIN_SETS[key]);
    });

    Object.keys(IP_SETS).forEach(key => {
        params["rule-providers"][key] = ipProvider(IP_SETS[key]);
    });

    params["rule-providers"]["fakeip-filter"] = {
        type: "http",
        behavior: "domain",
        format: "mrs",
        url: "https://cdn.jsdmirror.com/gh/wwqgtxx/clash-rules@release/fakeip-filter.mrs",
        path: "./ruleset/fakeip-filter.mrs",
        interval: CONFIG.RS_INTERVAL
    };

    const hasOwn = (object, key) =>
        Object.prototype.hasOwnProperty.call(object, key);

    const renamedRS = Object.create(null);
    const droppedCarriedRS = new Set();

    Object.keys(carriedRuleProviders).forEach(name => {
        const provider = carriedRuleProviders[name];

        if (!isCarriableProvider(name, provider)) {
            droppedCarriedRS.add(name);
            return;
        }

        let finalName = name;

        if (hasOwn(params["rule-providers"], name)) {
            let suffix = 1;
            finalName = "sub-" + name;
            while (
                hasOwn(params["rule-providers"], finalName) ||
                hasOwn(carriedRuleProviders, finalName)
            ) {
                suffix++;
                finalName = "sub-" + name + "-" + suffix;
            }
            renamedRS[name] = finalName;
        }

        const finalProvider = Object.assign({}, provider);

        if (typeof finalProvider.path === "string" &&
            finalProvider.path.length > 0) {
            const segs = finalProvider.path.split(/[\\/]/);
            const base = segs[segs.length - 1];
            const dot = base.lastIndexOf(".");
            const ext = dot > 0 ? base.slice(dot) : "";
            const filePrefix = finalName.startsWith("sub-")
                ? finalName : "sub-" + finalName;

            segs[segs.length - 1] = filePrefix + ext;
            finalProvider.path = segs.join("/");
        }

        params["rule-providers"][finalName] = finalProvider;
    });

    const rewritePolicyRuleSets = policy => {
        if (!policy || typeof policy !== "object") return policy;

        const newPolicy = {};
        const seenKeys = new Set();

        Object.keys(policy).forEach(key => {
            const names = ruleSetNames(key);

            if (names.length === 0) {
                if (seenKeys.has(key)) {
                    warnLog(`[Clash_rule.js] 策略键 "${key}" 重复，保留首次值。`);
                    return;
                }
                seenKeys.add(key);
                newPolicy[key] = policy[key];
                return;
            }

            const keptNames = names.filter(
                name => !droppedCarriedRS.has(name)
            );
            if (keptNames.length === 0) return;

            const rewrittenNames = keptNames.map(
                name => renamedRS[name] || name
            );
            const newKey = "rule-set:" + rewrittenNames.join(",");

            if (seenKeys.has(newKey)) {
                warnLog(`[Clash_rule.js] 策略键 "${newKey}" 冲突，保留首次值。`);
                return;
            }

            seenKeys.add(newKey);
            newPolicy[newKey] = policy[key];
        });

        return newPolicy;
    };

    if (Object.keys(renamedRS).length > 0 || droppedCarriedRS.size > 0) {
        params.dns["nameserver-policy"] = rewritePolicyRuleSets(
            params.dns["nameserver-policy"]
        );

        if (params.dns["proxy-server-nameserver-policy"]) {
            params.dns["proxy-server-nameserver-policy"] =
                rewritePolicyRuleSets(
                    params.dns["proxy-server-nameserver-policy"]
                );
        }
    }

    params.dns["nameserver-policy"] = Object.assign(
        {},
        params.dns["nameserver-policy"],
        {
            "rule-set:private-domain": ["system://"],
            "rule-set:ads-domain": ["rcode://name_error"],
            "rule-set:cn-domain": [...CONFIG.CN_DNS_DOH]
        }
    );

    const FP_OK = ["vless", "vmess", "trojan"];

    params.proxies.forEach(proxy => {
        if (proxy.type !== "direct" && !("ip-version" in proxy)) {
            proxy["ip-version"] = CONFIG.DEFAULT_IP_VERSION;
        }

        if (FP_OK.indexOf(proxy.type) !== -1 &&
            !proxy["client-fingerprint"]) {
            const usesTLS =
                proxy.type === "trojan" ||
                proxy.tls === true ||
                proxy["reality-opts"];

            if (usesTLS) proxy["client-fingerprint"] = "chrome";
        }
    });

    const groups = [];

    groups.push({
        name: "主代理",
        type: "select",
        icon: qureIcon("Proxy.png"),
        proxies: hasActiveRegions
            ? ["自动选择", ...activeRegionNames, "静态"]
            : ["自动选择", "静态"],
        url: CONFIG.TEST_URL_PROXY,
        interval: CONFIG.TEST_INTERVAL,
        timeout: 5000,
        "expected-status": 204
    });

    groups.push({
        name: "自动选择",
        type: "url-test",
        icon: qureIcon("Auto.png"),
        proxies: usableNames.length > 0 ? usableNames : ["REJECT"],
        "empty-fallback": "REJECT",
        url: CONFIG.TEST_URL_PROXY,
        interval: CONFIG.TEST_INTERVAL,
        tolerance: 50,
        lazy: false,
        timeout: 5000,
        "max-failed-times": 5,
        "expected-status": 204
    });

    groups.push({
        name: "静态",
        type: "select",
        icon: qureIcon("Static.png"),
        proxies: usableNames.length > 0 ? usableNames : ["REJECT"],
        "empty-fallback": "REJECT"
    });

    groups.push({
        name: "直连",
        type: "select",
        hidden: true,
        icon: qureIcon("Direct.png"),
        proxies: ["DIRECT"]
    });

    const appProxiesList = [
        "主代理",
        "自动选择",
        "直连",
        ...activeRegionNames
    ];

    apps.forEach(app => {
        groups.push({
            name: app.name,
            type: "select",
            icon: qureIcon(app.icon),
            proxies: [...appProxiesList, ...usableNames]
        });
    });

    activeRegions.forEach(region => {
        groups.push({
            name: region.name,
            type: "url-test",
            hidden: true,
            icon: region.icon,
            proxies: regionNodeNames.get(region.name),
            "empty-fallback": "REJECT",
            url: CONFIG.TEST_URL_PROXY,
            interval: CONFIG.TEST_INTERVAL,
            tolerance: 30,
            lazy: false,
            timeout: 5000,
            "max-failed-times": 5,
            "expected-status": 204
        });
    });

    groups.push({
        name: "兜底",
        type: "select",
        icon: qureIcon("Final.png"),
        proxies: [...appProxiesList, ...usableNames]
    });

    if (usableNames.length === 0) {
        warnLog(
            "[Clash_rule.js] 所有节点均被过滤，自动选择和静态组使用 REJECT 占位。"
        );
    }

    const fixDialerProxies = (proxies, groupList) => {
        const known = new Set([
            ...proxies.map(proxy => proxy.name),
            ...groupList.map(group => group.name),
            ...BUILTIN_POLICIES
        ]);

        proxies.forEach(proxy => {
            const target = proxy["dialer-proxy"];
            if (typeof target !== "string" || target === "") return;

            const renamed = proxyRenames.get(target);
            if (!known.has(target) && renamed !== undefined) {
                proxy["dialer-proxy"] = renamed;
            }

            if (!known.has(proxy["dialer-proxy"])) {
                delete proxy["dialer-proxy"];
            }
        });

        const byName = new Map(proxies.map(proxy => [proxy.name, proxy]));
        const done = new Set();

        proxies.forEach(proxy => {
            if (done.has(proxy.name)) return;

            const path = [];
            const onPath = new Set();
            let cur = proxy.name;

            while (byName.has(cur) && !done.has(cur)) {
                if (onPath.has(cur)) {
                    for (let i = path.indexOf(cur); i < path.length; i++) {
                        delete byName.get(path[i])["dialer-proxy"];
                    }
                    break;
                }

                onPath.add(cur);
                path.push(cur);

                const next = byName.get(cur)["dialer-proxy"];
                if (typeof next !== "string" || next === "") break;
                cur = next;
            }

            path.forEach(name => done.add(name));
        });
    };

    fixDialerProxies(params.proxies, groups);
    params["proxy-groups"] = groups;

    params.rules = [
        "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
        "IP-CIDR,0.0.0.0/32,REJECT,no-resolve",
        "IP-CIDR6,::1/128,DIRECT,no-resolve",
        "IP-CIDR6,::/128,REJECT,no-resolve",
        "AND,((IN-TYPE,TUN),(DST-PORT,853)),REJECT",

        // 局域网和本机流量先保留直连，避免影响局域网设备发现及访问。
        "RULE-SET,private-domain,DIRECT",
        "RULE-SET,private-ip,DIRECT,no-resolve",
        "AND,((DST-PORT,123),(NETWORK,udp)),DIRECT",

        // V5.15.7 修复：
        // WebRTC/STUN 专用规则始终优先于国内域名和国内 IP 直连规则。
        // 避免 STUN 流量先命中 cn-domain / cn-ip 而绕过主代理。
        ...(CONFIG.WEBRTC_STUN_PROXY
            ? [
                "AND,((DST-PORT,3478/5349/19302-19309),(NETWORK,udp)),主代理",
                "AND,((DST-PORT,3478/5349),(NETWORK,tcp)),主代理",
                "AND,((DOMAIN-KEYWORD,stun),(NETWORK,udp)),主代理",
                "DOMAIN-KEYWORD,stun,主代理"
            ]
            : []),

        // 指定域名直连
        "DOMAIN-SUFFIX,snssdk.com,DIRECT",
        "DOMAIN-SUFFIX,bdurl.net,DIRECT",

        "DOMAIN-SUFFIX,hatch-api.meta.ai,主代理",
        "DOMAIN-SUFFIX,hatch.metaaivm.com,主代理",
        "DOMAIN-SUFFIX,apple-relay.cloudflare.com,主代理",
        "DOMAIN-SUFFIX,mask.icloud.com,主代理",
        "DOMAIN-SUFFIX,mask-h2.icloud.com,主代理",
        "DOMAIN-SUFFIX,graph.facebook.com,主代理",

        "RULE-SET,ads-domain,REJECT",
        "RULE-SET,synology-domain,DIRECT",

        ...(CONFIG.BLOCK_QUIC
            ? ["AND,((DST-PORT,443),(NETWORK,udp)),REJECT"]
            : []),

        "RULE-SET,youtube-domain,YouTube",
        "RULE-SET,twitter-domain,X",
        "RULE-SET,tiktok-domain,TikTok",
        "RULE-SET,telegram-domain,Telegram",
        "RULE-SET,telegram-ip,Telegram,no-resolve",
        "RULE-SET,spotify-domain,Spotify",
        "RULE-SET,ai-domain,AI",
        "RULE-SET,github-domain,GitHub",
        "RULE-SET,steam-domain,Steam",
        "RULE-SET,paypal-domain,PayPal",

        "RULE-SET,netflix-domain,TV",
        "RULE-SET,disney-domain,TV",
        "RULE-SET,primevideo-domain,TV",
        "RULE-SET,appletv-domain,TV",
        "RULE-SET,hbo-domain,TV",

        "RULE-SET,google-domain,Google",
        "RULE-SET,apple-domain,Apple",
        "RULE-SET,microsoft-domain,Microsoft",

        "RULE-SET,proxy-domain,主代理",

        // 国内域名和国内 IP 直连。
        // 普通国内 UDP 可以在这里命中 DIRECT。
        "RULE-SET,cn-domain,DIRECT",
        "RULE-SET,cn-ip,DIRECT",

        // 其他尚未命中的 UDP 再统一走主代理。
        // STUN 已在前面单独处理，不会被国内直连规则抢先匹配。
        // 所选节点必须支持 UDP；不支持时相关连接可能失败，而不是自动直连。
        ...(CONFIG.WEBRTC_UDP_PROXY_ALL
            ? ["NETWORK,udp,主代理"]
            : []),

        "MATCH,兜底"
    ];

    return params;
}

if (typeof module !== "undefined") {
    module.exports = main;
    module.exports.main = main;
}
