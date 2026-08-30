# smart_rules.py - موتور قوانین هوشمند برای X4G Gateway
# پشتیبانی از مسیریابی بر اساس دامنه، IP، کشور و لیست‌های خارجی

import asyncio
import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Set
from datetime import datetime
import httpx
import logging

logger = logging.getLogger("X4G.Rules")

# ── ساختار داده‌ها ─────────────────────────────────────────────────────────────

class RuleType:
    DOMAIN = "domain"
    DOMAIN_SUFFIX = "domain_suffix"
    DOMAIN_KEYWORD = "domain_keyword"
    IP_CIDR = "ip_cidr"
    GEOIP = "geoip"
    FINAL = "final"

class RuleAction:
    PROXY = "proxy"      # استفاده از پروکسی
    DIRECT = "direct"    # اتصال مستقیم
    REJECT = "reject"    # رد کردن

class SmartRule:
    """یک قانون هوشمند برای مسیریابی ترافیک"""
    
    def __init__(self, rule_id: str, rule_type: str, pattern: str, 
                 action: str, country: Optional[str] = None,
                 description: str = "", enabled: bool = True):
        self.rule_id = rule_id
        self.rule_type = rule_type
        self.pattern = pattern
        self.action = action
        self.country = country  # برای GEOIP
        self.description = description
        self.enabled = enabled
        self.hit_count = 0
        self.last_hit: Optional[datetime] = None
        
    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "rule_type": self.rule_type,
            "pattern": self.pattern,
            "action": self.action,
            "country": self.country,
            "description": self.description,
            "enabled": self.enabled,
            "hit_count": self.hit_count,
            "last_hit": self.last_hit.isoformat() if self.last_hit else None,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'SmartRule':
        rule = cls(
            rule_id=data["rule_id"],
            rule_type=data["rule_type"],
            pattern=data["pattern"],
            action=data["action"],
            country=data.get("country"),
            description=data.get("description", ""),
            enabled=data.get("enabled", True),
        )
        rule.hit_count = data.get("hit_count", 0)
        last_hit = data.get("last_hit")
        rule.last_hit = datetime.fromisoformat(last_hit) if last_hit else None
        return rule
    
    def match_domain(self, domain: str) -> bool:
        """بررسی تطابق قانون با یک دامنه"""
        if not self.enabled:
            return False
            
        if self.rule_type == RuleType.DOMAIN:
            return domain.lower() == self.pattern.lower()
        elif self.rule_type == RuleType.DOMAIN_SUFFIX:
            return domain.lower().endswith("." + self.pattern.lower())
        elif self.rule_type == RuleType.DOMAIN_KEYWORD:
            return self.pattern.lower() in domain.lower()
        
        return False
    
    def match_ip(self, ip: str) -> bool:
        """بررسی تطابق قانون با یک IP (برای CIDR و GEOIP)"""
        if not self.enabled:
            return False
            
        if self.rule_type == RuleType.IP_CIDR:
            return self._ip_in_cidr(ip, self.pattern)
        elif self.rule_type == RuleType.GEOIP and self.country:
            return self._ip_in_country(ip, self.country)
        
        return False
    
    def _ip_in_cidr(self, ip: str, cidr: str) -> bool:
        """بررسی قرارگیری IP در یک بازه CIDR"""
        try:
            import ipaddress
            network = ipaddress.ip_network(cidr, strict=False)
            ip_addr = ipaddress.ip_address(ip)
            return ip_addr in network
        except Exception:
            return False
    
    def _ip_in_country(self, ip: str, country: str) -> bool:
        """بررسی تعلق IP به یک کشور (نیاز به دیتابیس GeoIP دارد)"""
        # TODO: پیاده‌سازی با استفاده از دیتابیس GeoIP
        # فعلاً همیشه False برمی‌گرداند
        return False
    
    def record_hit(self):
        """ثبت یک بار استفاده از این قانون"""
        self.hit_count += 1
        self.last_hit = datetime.now()


class SmartRulesEngine:
    """موتور مدیریت قوانین هوشمند"""
    
    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.rules_file = data_dir / "smart_rules.json"
        self.geoip_dir = data_dir / "geoip"
        self.rules: Dict[str, SmartRule] = {}
        self.external_lists: Dict[str, Set[str]] = {}  # لیست‌های خارجی دانلود شده
        self._lock = asyncio.Lock()
        self.http_client: Optional[httpx.AsyncClient] = None
        
    async def initialize(self):
        """بارگذاری قوانین از فایل و راه‌اندازی موتور"""
        await self._load_rules()
        await self._init_http_client()
        logger.info(f"Smart Rules Engine initialized with {len(self.rules)} rules")
    
    async def _init_http_client(self):
        """راه‌اندازی کلاینت HTTP برای دانلود لیست‌های خارجی"""
        limits = httpx.Limits(max_connections=10, max_keepalive_connections=5)
        timeout = httpx.Timeout(30.0, connect=10.0)
        self.http_client = httpx.AsyncClient(limits=limits, timeout=timeout)
    
    async def _load_rules(self):
        """بارگذاری قوانین از فایل JSON"""
        try:
            self.data_dir.mkdir(parents=True, exist_ok=True)
            if self.rules_file.exists():
                async with asyncio.Lock():
                    with open(self.rules_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    
                    for rule_data in data.get("rules", []):
                        rule = SmartRule.from_dict(rule_data)
                        self.rules[rule.rule_id] = rule
                    
                    self.external_lists = data.get("external_lists", {})
                    
                logger.info(f"Loaded {len(self.rules)} rules from file")
        except Exception as e:
            logger.warning(f"Could not load rules: {e}")
    
    async def save_rules(self):
        """ذخیره قوانین در فایل JSON"""
        async with self._lock:
            try:
                self.data_dir.mkdir(parents=True, exist_ok=True)
                data = {
                    "rules": [rule.to_dict() for rule in self.rules.values()],
                    "external_lists": self.external_lists,
                    "updated_at": datetime.now().isoformat(),
                }
                
                tmp_file = self.rules_file.with_suffix(".tmp")
                with open(tmp_file, 'w', encoding='utf-8') as f:
                    json.dump(data, f, ensure_ascii=False, indent=2)
                tmp_file.replace(self.rules_file)
                
                logger.debug("Rules saved successfully")
            except Exception as e:
                logger.warning(f"Could not save rules: {e}")
    
    async def add_rule(self, rule_type: str, pattern: str, action: str,
                       country: Optional[str] = None, description: str = "",
                       rule_id: Optional[str] = None) -> str:
        """افزودن یک قانون جدید"""
        async with self._lock:
            if rule_id is None:
                rule_id = f"rule_{len(self.rules) + 1}_{datetime.now().timestamp()}"
            
            rule = SmartRule(
                rule_id=rule_id,
                rule_type=rule_type,
                pattern=pattern,
                action=action,
                country=country,
                description=description,
            )
            
            self.rules[rule_id] = rule
            await self.save_rules()
            
            logger.info(f"Added rule: {rule_id} ({rule_type}: {pattern} -> {action})")
            return rule_id
    
    async def remove_rule(self, rule_id: str) -> bool:
        """حذف یک قانون"""
        async with self._lock:
            if rule_id in self.rules:
                del self.rules[rule_id]
                await self.save_rules()
                logger.info(f"Removed rule: {rule_id}")
                return True
            return False
    
    async def update_rule(self, rule_id: str, **kwargs) -> bool:
        """به‌روزرسانی یک قانون"""
        async with self._lock:
            if rule_id not in self.rules:
                return False
            
            rule = self.rules[rule_id]
            
            for key, value in kwargs.items():
                if hasattr(rule, key):
                    setattr(rule, key, value)
            
            await self.save_rules()
            logger.info(f"Updated rule: {rule_id}")
            return True
    
    async def get_rules(self) -> List[dict]:
        """دریافت لیست تمام قوانین"""
        async with self._lock:
            return [rule.to_dict() for rule in self.rules.values()]
    
    async def evaluate_domain(self, domain: str) -> Optional[str]:
        """
        ارزیابی یک دامنه بر اساس قوانین و برگرداندن اکشن مناسب
        اولویت با قوانینی است که زودتر تعریف شده‌اند (First Match)
        """
        async with self._lock:
            for rule in self.rules.values():
                if rule.match_domain(domain):
                    rule.record_hit()
                    await self.save_rules()  # ذخیره آمار
                    logger.debug(f"Domain {domain} matched rule {rule.rule_id} -> {rule.action}")
                    return rule.action
            
            # اگر هیچ قانونی تطابق نداشت، بررسی می‌کنیم آیا قانون FINAL وجود دارد
            for rule in self.rules.values():
                if rule.rule_type == RuleType.FINAL and rule.enabled:
                    rule.record_hit()
                    await self.save_rules()
                    return rule.action
        
        return None  # بدون عمل خاص
    
    async def evaluate_ip(self, ip: str) -> Optional[str]:
        """ارزیابی یک IP بر اساس قوانین"""
        async with self._lock:
            for rule in self.rules.values():
                if rule.match_ip(ip):
                    rule.record_hit()
                    await self.save_rules()
                    logger.debug(f"IP {ip} matched rule {rule.rule_id} -> {rule.action}")
                    return rule.action
        
        return None
    
    async def download_external_list(self, list_name: str, url: str) -> bool:
        """دانلود یک لیست خارجی (مثل لیست دامنه‌های تحریمی)"""
        try:
            if not self.http_client:
                await self._init_http_client()
            
            response = await self.http_client.get(url, timeout=60.0)
            response.raise_for_status()
            
            lines = response.text.strip().split('\n')
            domains = set()
            
            for line in lines:
                line = line.strip()
                if line and not line.startswith('#'):
                    domains.add(line.lower())
            
            async with self._lock:
                self.external_lists[list_name] = domains
                
                # ایجاد قوانین خودکار از لیست
                for domain in domains:
                    rule_id = f"ext_{list_name}_{domain.replace('.', '_')}"
                    if rule_id not in self.rules:
                        await self.add_rule(
                            rule_type=RuleType.DOMAIN,
                            pattern=domain,
                            action=RuleAction.PROXY,
                            description=f"External list: {list_name}",
                            rule_id=rule_id,
                        )
                
                await self.save_rules()
            
            logger.info(f"Downloaded external list '{list_name}' with {len(domains)} entries")
            return True
            
        except Exception as e:
            logger.error(f"Failed to download external list '{list_name}': {e}")
            return False
    
    async def refresh_external_lists(self):
        """به‌روزرسانی تمام لیست‌های خارجی"""
        tasks = []
        async with self._lock:
            for list_name, url in list(self.external_lists.items()):
                if isinstance(url, str) and url.startswith('http'):
                    tasks.append(self.download_external_list(list_name, url))
        
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            success_count = sum(1 for r in results if r is True)
            logger.info(f"Refreshed {success_count}/{len(tasks)} external lists")
    
    async def get_statistics(self) -> dict:
        """دریافت آمار قوانین"""
        async with self._lock:
            total_hits = sum(r.hit_count for r in self.rules.values())
            enabled_count = sum(1 for r in self.rules.values() if r.enabled)
            
            return {
                "total_rules": len(self.rules),
                "enabled_rules": enabled_count,
                "disabled_rules": len(self.rules) - enabled_count,
                "total_hits": total_hits,
                "external_lists_count": len(self.external_lists),
                "by_type": self._count_by_type(),
                "by_action": self._count_by_action(),
            }
    
    def _count_by_type(self) -> dict:
        """تعداد قوانین بر اساس نوع"""
        counts = {}
        for rule in self.rules.values():
            counts[rule.rule_type] = counts.get(rule.rule_type, 0) + 1
        return counts
    
    def _count_by_action(self) -> dict:
        """تعداد قوانین بر اساس اکشن"""
        counts = {}
        for rule in self.rules.values():
            counts[rule.action] = counts.get(rule.action, 0) + 1
        return counts


# نمونه‌ای از استفاده
if __name__ == "__main__":
    import asyncio
    
    async def test():
        engine = SmartRulesEngine(Path("/tmp/x4g_test"))
        await engine.initialize()
        
        # افزودن چند قانون نمونه
        await engine.add_rule(
            rule_type=RuleType.DOMAIN_SUFFIX,
            pattern="google.com",
            action=RuleAction.PROXY,
            description="Google services"
        )
        
        await engine.add_rule(
            rule_type=RuleType.DOMAIN_KEYWORD,
            pattern="instagram",
            action=RuleAction.PROXY,
            description="Instagram"
        )
        
        await engine.add_rule(
            rule_type=RuleType.FINAL,
            pattern="*",
            action=RuleAction.DIRECT,
            description="Default to direct"
        )
        
        # تست ارزیابی
        result = await engine.evaluate_domain("www.google.com")
        print(f"www.google.com -> {result}")
        
        result = await engine.evaluate_domain("instagram.com")
        print(f"instagram.com -> {result}")
        
        result = await engine.evaluate_domain("example.ir")
        print(f"example.ir -> {result}")
        
        stats = await engine.get_statistics()
        print(f"\nStatistics: {json.dumps(stats, indent=2)}")
    
    asyncio.run(test())
