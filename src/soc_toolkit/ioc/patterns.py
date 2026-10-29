"""Регулярные выражения и справочные множества для поиска индикаторов."""

from __future__ import annotations

import re

# Популярные gTLD и все национальные двухбуквенные домены (проверяются по длине)
COMMON_TLDS = frozenset(
    """com net org info biz io co xyz top site online club shop app dev cloud live pro link click icu vip
    gov edu mil int onion space tech store website online fun buzz monster rest cam bond sbs cfd qpon
    support help services digital network systems solutions agency email zone today world host
    local lan corp internal""".split()
)

# Зоны, которые используются только внутри сетей: их не отправляем во внешние сервисы
INTERNAL_TLDS = frozenset({"local", "lan", "corp", "internal", "intranet", "home", "localdomain", "ad", "test"})

# Расширения файлов, которые выглядят как TLD, но доменами не являются
FILE_EXTENSIONS = frozenset(
    """exe dll bat cmd ps1 psm1 vbs vbe js jse wsf wsh jar zip rar 7z gz tar doc docx docm xls xlsx xlsm
    ppt pptx pptm pdf txt log csv json xml html htm php asp aspx jsp png jpg jpeg gif bmp lnk iso img vhd vhdx
    msi msix sys tmp dat ini cfg conf py sh hta scr cpl chm one url reg inf sct ocx drv evtx eml msg rtf""".split()
)

# Расширения, которые стоит выделять как вложения/полезную нагрузку
SUSPICIOUS_EXTENSIONS = frozenset(
    """exe dll scr bat cmd ps1 vbs vbe js jse wsf hta lnk iso img vhd vhdx msi jar docm xlsm pptm one chm cpl
    sct reg""".split()
)

DEFANG_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bh[xX]{2}p(s?)\b", re.I), r"http\1"),
    (re.compile(r"\bf[xX]p\b", re.I), "ftp"),
    (re.compile(r"\[\s*:\s*//\s*\]|\[://\]"), "://"),
    (re.compile(r"\[\s*:\s*\]"), ":"),
    (re.compile(r"\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\[dot\]|\(dot\)|\s\[dot\]\s", re.I), "."),
    (re.compile(r"\[\s*@\s*\]|\[at\]|\(at\)", re.I), "@"),
    (re.compile(r"\[\s*/\s*\]"), "/"),
]

URL = re.compile(r"\b(?:https?|ftp|sftp|smb|ldap)://[^\s\"'<>\]\)\}\|`^]+", re.I)
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24}\b")
_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
# Не часть более длинной последовательности цифр и точек (номера версий вроде 10.0.19045.1)
IPV4 = re.compile(rf"(?<![\d.])(?:{_OCTET}\.){{3}}{_OCTET}(?![\d.]*\d)")
# Кандидаты в IPv6: окончательная проверка делается модулем ipaddress
IPV6 = re.compile(r"(?<![\w:.])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?:%\w+)?(?![\w:])")
DOMAIN = re.compile(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z][A-Za-z0-9-]{1,23}\b")
MD5 = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{32}(?![0-9A-Fa-f])")
SHA1 = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{40}(?![0-9A-Fa-f])")
SHA256 = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{64}(?![0-9A-Fa-f])")
SHA512 = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{128}(?![0-9A-Fa-f])")
CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
MITRE = re.compile(r"\bT1\d{3}(?:\.\d{3})?\b")
WIN_PATH = re.compile(
    r"(?:\b[A-Za-z]:\\|\\\\[\w.$-]+\\|%\w+%\\)"
    # промежуточные папки могут содержать одиночные пробелы ("Program Files"), последний сегмент нет
    r"(?:[^\\/:*?\"<>|\s,;%']+(?: [^\\/:*?\"<>|\s,;%']+)*\\)*[^\\/:*?\"<>|\s,;%']*"
)
REG_KEY = re.compile(
    r"\b(?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS)"
    r"(?:\\[^\\\s\"'<>|]+(?: [^\\\s\"'<>|/-][^\\\s\"'<>|]*)*)+",
    re.I,
)
FILENAME = re.compile(
    r"(?<![\w\\/.-])[\w][\w.()-]{0,120}\.(?:" + "|".join(sorted(SUSPICIOUS_EXTENSIONS)) + r")\b", re.I
)

# Base64: длинные последовательности, кратность 4 проверяется при декодировании
BASE64 = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")
PS_ENCODED = re.compile(
    r"-(?:e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedcommand)\s+([A-Za-z0-9+/=]{16,})", re.I
)
