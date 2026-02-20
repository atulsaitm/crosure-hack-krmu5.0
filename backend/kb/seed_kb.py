"""
Seed the Knowledge Base with real-world CVE/exploit data.
Run once on startup if the DB is empty.
"""

import asyncio
import logging
from kb.database import get_session, Exploit
from kb.embeddings import embed_exploit
from sqlalchemy import select, func

logger = logging.getLogger("crosure.seed")

SEED_EXPLOITS = [
    # --- SQL Injection ---
    {
        "cve_id": "CVE-2023-36884",
        "title": "SQL Injection via unsanitized user input in PHP applications",
        "description": "Applications that directly interpolate user input into SQL queries without parameterized statements are vulnerable to SQL injection. Attackers can extract database contents, bypass authentication, or execute administrative operations. Common in PHP/MySQL stacks using mysql_query() or string concatenation.",
        "attack_type": "sqli",
        "severity": "critical",
        "affected_software": "PHP, MySQL, MariaDB, WordPress plugins",
        "steps": "1. Identify input fields reflected in SQL queries\n2. Test with single quote (') for error-based detection\n3. Use UNION SELECT to extract schema\n4. Escalate with stacked queries or INTO OUTFILE",
    },
    {
        "cve_id": "CVE-2024-1071",
        "title": "WordPress Ultimate Member Plugin SQL Injection",
        "description": "The Ultimate Member plugin for WordPress is vulnerable to SQL Injection via the 'sorting' parameter due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query. This makes it possible for unauthenticated attackers to append additional SQL queries.",
        "attack_type": "sqli",
        "severity": "critical",
        "affected_software": "WordPress, Ultimate Member < 2.8.3",
        "steps": "1. Send crafted sorting parameter to user listing endpoint\n2. Use time-based blind injection to extract data\n3. Retrieve admin password hash\n4. Login as administrator",
    },
    # --- XSS ---
    {
        "cve_id": "CVE-2023-29489",
        "title": "cPanel Reflected XSS in Error Pages",
        "description": "cPanel before 11.109.9999.116 allows reflected XSS via error page URL manipulation. The vulnerability exists because user-supplied URL parameters are reflected in HTML error responses without proper encoding. This affects all cPanel installations and does not require authentication.",
        "attack_type": "xss",
        "severity": "high",
        "affected_software": "cPanel < 11.109.9999.116",
        "steps": "1. Craft URL with JavaScript payload in path\n2. Error page reflects payload without encoding\n3. Steal session cookies or redirect users\n4. Escalate to account takeover",
    },
    {
        "cve_id": "CVE-2024-21388",
        "title": "Stored XSS via innerHTML in modern web frameworks",
        "description": "Applications using dangerouslySetInnerHTML (React), v-html (Vue), or [innerHTML] (Angular) with unsanitized user content are vulnerable to stored XSS. Attackers can inject persistent scripts that execute for every visitor. Common in blog platforms, forums, and CMS applications.",
        "attack_type": "xss",
        "severity": "high",
        "affected_software": "React, Vue.js, Angular, Express.js, Node.js",
        "steps": "1. Find user input stored and rendered as HTML\n2. Inject <img onerror=...> or <svg onload=...> payloads\n3. Bypass CSP using script gadgets or trusted types\n4. Exfiltrate data via fetch() to attacker server",
    },
    # --- SSTI ---
    {
        "cve_id": "CVE-2023-46747",
        "title": "Server-Side Template Injection in Jinja2/Twig/Freemarker",
        "description": "When user input is directly embedded into server-side templates without sandboxing, attackers can execute arbitrary code on the server. Jinja2 (Python), Twig (PHP), and Freemarker (Java) are commonly affected. The {{7*7}} test payload returning 49 confirms SSTI vulnerability.",
        "attack_type": "ssti",
        "severity": "critical",
        "affected_software": "Jinja2, Flask, Django, Twig, Freemarker, Mako",
        "steps": "1. Test with {{7*7}} or ${7*7} depending on engine\n2. Identify template engine via error messages\n3. Use __class__.__mro__ chain for Jinja2 RCE\n4. Execute os.popen() or subprocess for shell access",
    },
    # --- CSRF ---
    {
        "cve_id": "CVE-2023-40000",
        "title": "Cross-Site Request Forgery in state-changing endpoints",
        "description": "Web applications that do not validate CSRF tokens on state-changing requests (POST/PUT/DELETE) allow attackers to forge requests from authenticated users. This is especially critical for password change, email update, and administrative endpoints. Same-site cookie attribute can mitigate but is not sufficient alone.",
        "attack_type": "csrf",
        "severity": "high",
        "affected_software": "PHP, Django, Express.js, Spring Boot",
        "steps": "1. Identify state-changing forms without CSRF tokens\n2. Create auto-submitting form on attacker site\n3. Trick authenticated user into visiting attacker page\n4. Forged request executes with victim's session",
    },
    # --- Open Redirect ---
    {
        "cve_id": "CVE-2024-22243",
        "title": "Open Redirect via unvalidated redirect parameters",
        "description": "Applications that use user-controlled parameters (url=, redirect=, next=, return=) for HTTP redirects without validating the target domain are vulnerable. Attackers can redirect users to phishing sites or malware. This is commonly used in OAuth flows and login redirects.",
        "attack_type": "redirect",
        "severity": "medium",
        "affected_software": "Spring Framework, Django, Express.js, PHP",
        "steps": "1. Find redirect parameters in login/logout flows\n2. Test with //evil.com or https://evil.com\n3. Bypass filters using @, \\, or unicode tricks\n4. Chain with OAuth for token theft",
    },
    # --- CORS Misconfiguration ---
    {
        "cve_id": "CVE-2023-CORS-GENERIC",
        "title": "CORS Misconfiguration allowing credential theft",
        "description": "APIs that reflect the Origin header in Access-Control-Allow-Origin or use wildcard (*) with credentials allow cross-origin data theft. Attackers can read authenticated API responses from any website. This is critical for APIs handling sensitive user data or authentication tokens.",
        "attack_type": "cors",
        "severity": "high",
        "affected_software": "Express.js, Django REST, Flask-CORS, Spring Boot",
        "steps": "1. Send request with Origin: https://evil.com\n2. Check if ACAO reflects attacker origin\n3. Verify Access-Control-Allow-Credentials: true\n4. Use XMLHttpRequest to steal API responses",
    },
    # --- Path Traversal / LFI ---
    {
        "cve_id": "CVE-2024-4577",
        "title": "Path Traversal and Local File Inclusion",
        "description": "Applications that use user input to construct file paths without proper sanitization are vulnerable to directory traversal. Using sequences like ../ or encoded variants (%2e%2e%2f), attackers can read sensitive files (/etc/passwd, web.config) or include malicious files for RCE.",
        "attack_type": "path_traversal",
        "severity": "critical",
        "affected_software": "PHP, Apache, Nginx, Node.js, Java",
        "steps": "1. Find file download/include parameters\n2. Test with ../../etc/passwd\n3. Try encoded bypasses: %2e%2e%2f, ..%252f\n4. Escalate to RCE via log poisoning or PHP filter chains",
    },
    # --- IDOR / BOLA ---
    {
        "cve_id": "CVE-2023-BOLA-GENERIC",
        "title": "Broken Object Level Authorization (IDOR)",
        "description": "APIs that use predictable resource IDs (numeric, sequential) without verifying the requesting user's authorization allow attackers to access other users' data by manipulating IDs in API requests. This is the #1 API security risk per OWASP API Security Top 10.",
        "attack_type": "idor",
        "severity": "high",
        "affected_software": "REST APIs, GraphQL, Django REST, Express.js, Spring Boot",
        "steps": "1. Identify API endpoints with resource IDs\n2. Change ID from own resource to another user's\n3. Compare response to detect unauthorized access\n4. Enumerate IDs to mass-extract user data",
    },
    # --- Security Headers ---
    {
        "cve_id": "CVE-2023-HEADERS-GENERIC",
        "title": "Missing Security Headers enabling client-side attacks",
        "description": "Web applications missing critical security headers (Content-Security-Policy, X-Frame-Options, Strict-Transport-Security, X-Content-Type-Options) are more susceptible to XSS, clickjacking, MIME sniffing, and downgrade attacks. These headers provide defense-in-depth layers.",
        "attack_type": "headers",
        "severity": "medium",
        "affected_software": "Apache, Nginx, IIS, Express.js, Django",
        "steps": "1. Check response headers for missing protections\n2. Test clickjacking with iframe embedding\n3. Test MIME sniffing with uploaded files\n4. Verify HSTS for downgrade attack prevention",
    },
    # --- Command Injection ---
    {
        "cve_id": "CVE-2024-3400",
        "title": "OS Command Injection via unsanitized system calls",
        "description": "Applications that pass user input directly to system commands (os.system, subprocess, exec, shell_exec) without sanitization allow Remote Code Execution. Attackers use shell metacharacters (;, |, &&, ``) to chain arbitrary commands. This vulnerability is critical and often leads to full server compromise.",
        "attack_type": "rce",
        "severity": "critical",
        "affected_software": "PHP, Python, Node.js, Java, Perl",
        "steps": "1. Find parameters passed to system commands\n2. Test with ; sleep 5 for time-based detection\n3. Use | or && to chain commands\n4. Establish reverse shell for persistent access",
    },
    # --- Insecure Deserialization ---
    {
        "cve_id": "CVE-2023-34362",
        "title": "Insecure Deserialization leading to RCE",
        "description": "Applications that deserialize untrusted data (Java ObjectInputStream, Python pickle, PHP unserialize, .NET BinaryFormatter) can be exploited for Remote Code Execution. Attackers craft serialized payloads that execute arbitrary code during deserialization. This affects many enterprise Java and .NET applications.",
        "attack_type": "rce",
        "severity": "critical",
        "affected_software": "Java, Python, PHP, .NET, Ruby",
        "steps": "1. Identify serialized data in cookies/parameters\n2. Determine serialization format (Base64 Java, pickle headers)\n3. Generate payload with ysoserial or custom gadget chain\n4. Send crafted payload to trigger code execution",
    },
    # --- JWT Weaknesses ---
    {
        "cve_id": "CVE-2023-JWT-GENERIC",
        "title": "JWT Algorithm Confusion and Weak Signing",
        "description": "Applications using JWT tokens with algorithm confusion (accepting 'none'), weak secrets (brute-forceable HMAC keys), or no signature verification allow authentication bypass and privilege escalation. Attackers can forge admin tokens or change user claims.",
        "attack_type": "auth_bypass",
        "severity": "critical",
        "affected_software": "Node.js jsonwebtoken, PyJWT, java-jwt, Auth0",
        "steps": "1. Decode JWT and check algorithm/claims\n2. Test alg:none bypass\n3. Brute-force HMAC secret with hashcat\n4. Forge token with admin role claim",
    },
    # --- Emerging / Supply Chain ---
    {
        "cve_id": "CVE-2024-EMERGING",
        "title": "Prototype Pollution in JavaScript applications",
        "description": "JavaScript applications that merge user-controlled objects into prototypes (__proto__, constructor.prototype) can be exploited to modify application behavior. This can lead to XSS, authentication bypass, or denial of service. Affects lodash.merge, jQuery.extend, and custom deep-merge implementations.",
        "attack_type": "emerging",
        "severity": "high",
        "affected_software": "Node.js, Express.js, lodash, jQuery",
        "steps": "1. Find JSON merge operations accepting user input\n2. Send {'__proto__': {'admin': true}} payload\n3. Check if polluted property affects application logic\n4. Chain with template engines for XSS via pollution",
    },
]


async def seed_knowledge_base():
    """Seed KB with CVE data if the database is empty."""
    try:
        async with get_session() as session:
            result = await session.execute(select(func.count(Exploit.id)))
            count = result.scalar()

            if count and count >= len(SEED_EXPLOITS):
                logger.info(f"KB already has {count} exploits, skipping seed.")
                return count

        logger.info(f"Seeding KB with {len(SEED_EXPLOITS)} exploits...")

        seeded = 0
        for data in SEED_EXPLOITS:
            try:
                async with get_session() as session:
                    exploit = Exploit(
                        cve_id=data.get("cve_id"),
                        title=data["title"],
                        description=data["description"],
                        attack_type=data.get("attack_type"),
                        severity=data.get("severity", "medium"),
                        affected_software=data.get("affected_software"),
                        steps=data.get("steps"),
                    )
                    session.add(exploit)
                    await session.commit()
                    await session.refresh(exploit)

                    # Embed in ChromaDB
                    embed_text = f"{data['title']} {data['description']} {data.get('steps', '')}"
                    embed_exploit(
                        exploit_id=exploit.id,
                        text=embed_text,
                        metadata={
                            "attack_type": data.get("attack_type", ""),
                            "severity": data.get("severity", "medium"),
                            "cve_id": data.get("cve_id", ""),
                            "affected_software": data.get("affected_software", ""),
                        },
                    )
                    seeded += 1
            except Exception as e:
                logger.warning(f"Failed to seed exploit '{data['title'][:40]}': {e}")

        logger.info(f"KB seeded with {seeded}/{len(SEED_EXPLOITS)} exploits successfully.")
        return seeded

    except Exception as e:
        logger.error(f"KB seeding failed: {e}")
        return 0
