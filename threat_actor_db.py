"""
threat_actor_db.py - Phase 3.4 Threat Actor Intelligence

Local knowledge base of major APT groups, ransomware operators, and cybercrime actors.
Supplemented by live OTX pulse search and VT threat labels.

Usage:
    actor = lookup_actor("APT28")
    group = lookup_actor("Lazarus")
"""
from typing import Optional

# ═══════════════════════════════════════════════════════════════════════════════
#  Threat Actor Knowledge Base
# ═══════════════════════════════════════════════════════════════════════════════

_ACTORS = {
    # ── Nation-State APTs ─────────────────────────────────────────────────────
    "apt28": {
        "name":         "APT28",
        "aliases":      ["Fancy Bear", "Sofacy", "Sednit", "STRONTIUM", "Pawn Storm"],
        "category":     "Nation-State APT",
        "origin":       "Russia (GRU)",
        "motivation":   "Espionage",
        "target_sectors":["Government", "Military", "Defense", "Media", "Political"],
        "tools":        ["X-Agent", "Zebrocy", "LoJax", "Sofacy", "Komplex"],
        "techniques":   ["T1566.001", "T1078", "T1036", "T1027", "T1203"],
        "mitre_group":  "G0007",
        "since":        "2004",
        "active":       True,
        "risk":         "Critical",
        "description":  "Russian GRU-linked group known for high-profile political and espionage operations including DNC hack (2016).",
    },
    "apt29": {
        "name":         "APT29",
        "aliases":      ["Cozy Bear", "The Dukes", "YTTRIUM", "Midnight Blizzard", "Nobelium"],
        "category":     "Nation-State APT",
        "origin":       "Russia (SVR)",
        "motivation":   "Espionage",
        "target_sectors":["Government", "Think Tanks", "Healthcare", "Technology"],
        "tools":        ["WellMess", "WellMail", "CobaltStrike", "SolarWinds backdoor", "SUNBURST"],
        "techniques":   ["T1195.002", "T1133", "T1078", "T1053"],
        "mitre_group":  "G0016",
        "since":        "2008",
        "active":       True,
        "risk":         "Critical",
        "description":  "Russian SVR-linked group responsible for the SolarWinds supply chain attack and sustained healthcare espionage.",
    },
    "lazarus": {
        "name":         "Lazarus Group",
        "aliases":      ["Hidden Cobra", "Zinc", "APT38", "TEMP.Hermit", "Labyrinth Chollima"],
        "category":     "Nation-State APT",
        "origin":       "North Korea (RGB)",
        "motivation":   "Financial Crime, Espionage",
        "target_sectors":["Cryptocurrency", "Banking", "Defense", "Media"],
        "tools":        ["BLINDINGCAN", "HOPLIGHT", "BADCALL", "FASTCash", "AppleJeus"],
        "techniques":   ["T1055", "T1059.001", "T1105", "T1071.001", "T1041"],
        "mitre_group":  "G0032",
        "since":        "2009",
        "active":       True,
        "risk":         "Critical",
        "description":  "DPRK RGB-linked group responsible for SWIFT banking heists, WannaCry, and $1.5B+ in crypto theft.",
    },
    "apt41": {
        "name":         "APT41",
        "aliases":      ["Double Dragon", "Winnti", "Barium", "Wicked Panda"],
        "category":     "Nation-State APT",
        "origin":       "China (MSS)",
        "motivation":   "Espionage + Financial Crime",
        "target_sectors":["Healthcare", "Telecom", "Technology", "Gaming"],
        "tools":        ["ShadowPad", "Speculoos", "Winnti", "PlugX", "KeyPlug"],
        "techniques":   ["T1195", "T1078", "T1190", "T1036.003"],
        "mitre_group":  "G0096",
        "since":        "2012",
        "active":       True,
        "risk":         "Critical",
        "description":  "Chinese MSS-linked group conducting both state espionage and financially motivated intrusions.",
    },
    "kimsuky": {
        "name":         "Kimsuky",
        "aliases":      ["Velvet Chollima", "Thallium", "TA406", "Black Banshee"],
        "category":     "Nation-State APT",
        "origin":       "North Korea",
        "motivation":   "Espionage",
        "target_sectors":["Government", "Think Tanks", "Media", "Nuclear"],
        "tools":        ["Gold Dragon", "BabyShark", "PowerShell backdoors", "AppleSeed"],
        "techniques":   ["T1566.001", "T1598.003", "T1547.001"],
        "mitre_group":  "G0094",
        "since":        "2012",
        "active":       True,
        "risk":         "High",
        "description":  "North Korean APT focused on intelligence collection and reconnaissance against policy and nuclear targets.",
    },
    "sandworm": {
        "name":         "Sandworm",
        "aliases":      ["Voodoo Bear", "ELECTRUM", "Telebots", "BlackEnergy"],
        "category":     "Nation-State APT",
        "origin":       "Russia (GRU Unit 74455)",
        "motivation":   "Sabotage, Disruption",
        "target_sectors":["Energy", "Critical Infrastructure", "Ukraine"],
        "tools":        ["NotPetya", "Industroyer", "CaddyWiper", "Cyclops Blink"],
        "techniques":   ["T1561", "T1498", "T1040", "T1190"],
        "mitre_group":  "G0034",
        "since":        "2009",
        "active":       True,
        "risk":         "Critical",
        "description":  "Destructive Russian GRU group responsible for BlackEnergy grid attacks and NotPetya ($10B+ in damages).",
    },
    "volt_typhoon": {
        "name":         "Volt Typhoon",
        "aliases":      ["Bronze Silhouette", "Dev-0391", "UNC3236"],
        "category":     "Nation-State APT",
        "origin":       "China (PLA)",
        "motivation":   "Pre-positioning, Espionage",
        "target_sectors":["Critical Infrastructure", "Military", "Communications", "Energy"],
        "tools":        ["Living-off-the-Land", "Impacket", "Cobalt Strike (limited)"],
        "techniques":   ["T1078", "T1133", "T1021.001", "T1560"],
        "mitre_group":  "G1017",
        "since":        "2021",
        "active":       True,
        "risk":         "Critical",
        "description":  "Chinese APT pre-positioning in US critical infrastructure using living-off-the-land techniques for minimal footprint.",
    },
    "muddy_water": {
        "name":         "MuddyWater",
        "aliases":      ["MERCURY", "Static Kitten", "Seedworm", "TA450"],
        "category":     "Nation-State APT",
        "origin":       "Iran (MOIS)",
        "motivation":   "Espionage, Influence",
        "target_sectors":["Government", "Telecom", "Oil & Gas", "Academia"],
        "tools":        ["POWERSTATS", "PowGoop", "PhonyC2", "BugSleep"],
        "techniques":   ["T1059.001", "T1566.001", "T1071.001", "T1027"],
        "mitre_group":  "G0069",
        "since":        "2017",
        "active":       True,
        "risk":         "High",
        "description":  "Iranian MOIS-linked group targeting Middle East and South Asian governments with spear-phishing campaigns.",
    },
    # ── Ransomware Groups ─────────────────────────────────────────────────────
    "lockbit": {
        "name":         "LockBit",
        "aliases":      ["LockBit 2.0", "LockBit 3.0", "LockBit Black", "ABCD Ransomware"],
        "category":     "Ransomware",
        "origin":       "Unknown (RaaS)",
        "motivation":   "Financial Crime",
        "target_sectors":["Healthcare", "Finance", "Manufacturing", "Government"],
        "tools":        ["LockBit ransomware", "StealBit exfiltration tool", "Cobalt Strike"],
        "techniques":   ["T1486", "T1490", "T1048", "T1078", "T1027"],
        "mitre_group":  "G0125",
        "since":        "2019",
        "active":       True,
        "risk":         "Critical",
        "description":  "Most prolific RaaS operation 2021-2024. Takedown in 2024 (Operation Cronos) but fragments remain active.",
    },
    "blackcat": {
        "name":         "BlackCat",
        "aliases":      ["ALPHV", "Noberus"],
        "category":     "Ransomware",
        "origin":       "Unknown (RaaS)",
        "motivation":   "Financial Crime",
        "target_sectors":["Healthcare", "Energy", "Finance", "Legal"],
        "tools":        ["BlackCat ransomware (Rust)", "ExMatter exfiltration", "Cobalt Strike"],
        "techniques":   ["T1486", "T1490", "T1078", "T1070"],
        "mitre_group":  "",
        "since":        "2021",
        "active":       False,
        "risk":         "Critical",
        "description":  "Sophisticated Rust-based RaaS responsible for MGM Resorts and Change Healthcare attacks. Shut down in 2024.",
    },
    "clop": {
        "name":         "Cl0p",
        "aliases":      ["TA505", "Clop Ransomware"],
        "category":     "Ransomware",
        "origin":       "Ukraine/Russia",
        "motivation":   "Financial Crime",
        "target_sectors":["Finance", "Healthcare", "Technology", "Education"],
        "tools":        ["Cl0p ransomware", "SDBOT", "GRACEWIRE", "FlawedAmmyy"],
        "techniques":   ["T1190", "T1486", "T1491", "T1048"],
        "mitre_group":  "G0092",
        "since":        "2019",
        "active":       True,
        "risk":         "Critical",
        "description":  "TA505-linked group known for mass exploitation of MFT vulnerabilities (MOVEit, GoAnywhere).",
    },
    "black_basta": {
        "name":         "Black Basta",
        "aliases":      ["BlackBasta"],
        "category":     "Ransomware",
        "origin":       "Russia",
        "motivation":   "Financial Crime",
        "target_sectors":["Healthcare", "Manufacturing", "Finance"],
        "tools":        ["Black Basta ransomware", "Qakbot", "Cobalt Strike", "Brute Ratel"],
        "techniques":   ["T1566.001", "T1078", "T1486", "T1490"],
        "mitre_group":  "",
        "since":        "2022",
        "active":       True,
        "risk":         "Critical",
        "description":  "Suspected Conti splinter group responsible for 500+ attacks on critical infrastructure.",
    },
    "scattered_spider": {
        "name":         "Scattered Spider",
        "aliases":      ["Scatter Swine", "UNC3944", "0ktapus", "Octo Tempest"],
        "category":     "Cybercrime",
        "origin":       "USA/UK (native English speakers)",
        "motivation":   "Financial Crime, Data Theft",
        "target_sectors":["Hospitality", "Gaming", "Finance", "Technology"],
        "tools":        ["Social Engineering", "SIM Swapping", "ALPHV/BlackCat"],
        "techniques":   ["T1621", "T1539", "T1078.004", "T1657"],
        "mitre_group":  "",
        "since":        "2022",
        "active":       True,
        "risk":         "High",
        "description":  "English-speaking group known for SMS phishing and social engineering of IT helpdesks (MGM, Caesars).",
    },
    # ── Commodity Malware Groups ──────────────────────────────────────────────
    "ta505": {
        "name":         "TA505",
        "aliases":      ["Graceful Spider"],
        "category":     "Cybercrime",
        "origin":       "Eastern Europe",
        "motivation":   "Financial Crime",
        "target_sectors":["Finance", "Retail", "Healthcare"],
        "tools":        ["Dridex", "FlawedAmmyy", "Philadelphia Ransomware", "Get2"],
        "techniques":   ["T1566.001", "T1204.002", "T1055"],
        "mitre_group":  "G0092",
        "since":        "2014",
        "active":       True,
        "risk":         "High",
        "description":  "High-volume spam campaigns distributing Dridex banking trojan and ransomware payloads.",
    },
    "fin7": {
        "name":         "FIN7",
        "aliases":      ["Carbanak", "Navigator Group", "GOLD NIAGARA"],
        "category":     "Cybercrime",
        "origin":       "Ukraine/Russia",
        "motivation":   "Financial Crime",
        "target_sectors":["Retail", "Hospitality", "Finance", "Restaurant"],
        "tools":        ["Carbanak", "BIRDWATCH", "GRIFFON", "SQLRat"],
        "techniques":   ["T1566.001", "T1204.002", "T1059.005"],
        "mitre_group":  "G0046",
        "since":        "2015",
        "active":       True,
        "risk":         "High",
        "description":  "Prolific financially motivated group targeting POS systems; responsible for $1B+ in banking fraud.",
    },
}


# ═══════════════════════════════════════════════════════════════════════════════
#  Lookup Functions
# ═══════════════════════════════════════════════════════════════════════════════

def lookup_actor(query: str) -> Optional[dict]:
    """
    Search the knowledge base by name or alias (case-insensitive).
    Returns the actor dict or None.
    """
    q = query.strip().lower().replace(" ", "_").replace("-", "_")
    # Direct key match
    if q in _ACTORS:
        return _ACTORS[q]
    # Alias search
    for actor in _ACTORS.values():
        name_lower = actor["name"].lower()
        if q in name_lower or query.lower() in name_lower:
            return actor
        for alias in actor["aliases"]:
            if q in alias.lower() or query.lower() in alias.lower():
                return actor
    return None


def search_actors(keyword: str) -> list[dict]:
    """Return all actors matching a keyword (name, alias, tool, or sector)."""
    kw = keyword.strip().lower()
    results = []
    for actor in _ACTORS.values():
        haystack = (
            actor["name"].lower() + " "
            + " ".join(a.lower() for a in actor["aliases"]) + " "
            + " ".join(t.lower() for t in actor["tools"]) + " "
            + " ".join(s.lower() for s in actor["target_sectors"])
        )
        if kw in haystack:
            results.append(actor)
    return results


def get_all_actors(category: Optional[str] = None) -> list[dict]:
    """Return all actors, optionally filtered by category."""
    actors = list(_ACTORS.values())
    if category:
        cat_lower = category.lower()
        actors = [a for a in actors if cat_lower in a["category"].lower()]
    return actors


def _risk_emoji(risk: str) -> str:
    return {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}.get(risk, "⚪")


def format_actor_report(actor: dict) -> str:
    """Format an actor profile as HTML for Telegram."""
    risk_em = _risk_emoji(actor["risk"])
    active_str = "✅ Active" if actor["active"] else "🚫 Inactive / Disrupted"
    aliases_str = ", ".join(actor["aliases"][:4]) if actor["aliases"] else "None"
    tools_str   = ", ".join(actor["tools"][:4]) if actor["tools"] else "Unknown"
    sectors_str = ", ".join(actor["target_sectors"][:4]) if actor["target_sectors"] else "Unknown"
    mitre_url   = f"https://attack.mitre.org/groups/{actor['mitre_group']}/" if actor["mitre_group"] else ""
    mitre_str   = f'<a href="{mitre_url}">{actor["mitre_group"]}</a>' if mitre_url else "N/A"

    report = (
        f"🎭 <b>Threat Actor Intelligence</b>\n"
        f"<code>━━━━━━━━━━━━━━━━━━━━━━━━━━</code>\n\n"
        f"🏷 <b>Name:</b> <b>{actor['name']}</b>\n"
        f"🔤 <b>Aliases:</b> <i>{aliases_str}</i>\n"
        f"📁 <b>Category:</b> {actor['category']}\n"
        f"🌍 <b>Origin:</b> {actor['origin']}\n"
        f"🎯 <b>Motivation:</b> {actor['motivation']}\n"
        f"📅 <b>Active Since:</b> {actor['since']}\n"
        f"📡 <b>Status:</b> {active_str}\n"
        f"{risk_em} <b>Threat Level:</b> <b>{actor['risk']}</b>\n\n"
        f"🏭 <b>Target Sectors:</b>\n<i>{sectors_str}</i>\n\n"
        f"🛠 <b>Known Tools:</b>\n<i>{tools_str}</i>\n\n"
        f"📖 <b>Description:</b>\n<i>{actor['description']}</i>\n\n"
        f"🔗 <b>MITRE ATT&amp;CK:</b> {mitre_str}\n"
        f"<code>━━━━━━━━━━━━━━━━━━━━━━━━━━</code>"
    )
    return report
