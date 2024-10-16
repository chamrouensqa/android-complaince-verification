import os
import re
from androguard.misc import AnalyzeAPK
from bs4 import BeautifulSoup
import requests

# List of permissions considered sensitive for GDPR/PCI-DSS compliance
SENSITIVE_PERMISSIONS = [
    "android.permission.READ_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.READ_SMS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.WRITE_EXTERNAL_STORAGE"
]

# Keywords to detect GDPR/PCI-DSS in privacy policies or code
GDPR_KEYWORDS = ["GDPR", "General Data Protection Regulation", "data privacy"]
PCI_DSS_KEYWORDS = ["PCI-DSS", "Payment Card Industry", "credit card", "financial data"]


def analyze_apk(apk_path):
    print(f"Analyzing APK: {apk_path}")
    apk, dex, dx = AnalyzeAPK(apk_path)

    # Check permissions
    permissions = apk.get_permissions()
    sensitive_permissions = [perm for perm in permissions if perm in SENSITIVE_PERMISSIONS]
    print("\nSensitive Permissions Detected:")
    for perm in sensitive_permissions:
        print(f"- {perm}")

    # Search for sensitive SDKs/libraries
    smali_files = apk.get_files_types()
    sdk_issues = check_sdk_compliance(smali_files)
    if sdk_issues:
        print("\nPotential non-compliant SDKs detected:")
        for issue in sdk_issues:
            print(f"- {issue}")

    # Check for privacy policy file inside the APK
    privacy_policy_url = check_privacy_policy(apk)
    if privacy_policy_url:
        analyze_privacy_policy(privacy_policy_url)
    else:
        print("\nNo privacy policy detected inside the APK.")


def check_sdk_compliance(files):
    # Example pattern match for SDK names or libraries
    non_compliant_sdks = []
    sdk_patterns = ["com.google.ads", "com.facebook.ads", "com.firebase", "com.flurry"]

    for file, file_type in files.items():
        if file_type == "smali":
            with open(file, 'r', encoding='utf-8') as smali_code:
                content = smali_code.read()
                for pattern in sdk_patterns:
                    if re.search(pattern, content):
                        non_compliant_sdks.append(pattern)
    return non_compliant_sdks


def check_privacy_policy(apk):
    # Look for privacy policy URL in manifest
    privacy_policy_url = None
    manifest = apk.get_android_manifest_xml()
    if manifest.find(".privacy"):
        privacy_policy_url = manifest.find(".privacy").text
    return privacy_policy_url


def analyze_privacy_policy(privacy_policy_url):
    print(f"\nFetching privacy policy from: {privacy_policy_url}")
    try:
        response = requests.get(privacy_policy_url)
        soup = BeautifulSoup(response.text, 'html.parser')
        privacy_text = soup.get_text()
        check_compliance_keywords(privacy_text)
    except Exception as e:
        print(f"Failed to fetch privacy policy: {e}")


def check_compliance_keywords(text):
    gdpr_issues = any(keyword in text for keyword in GDPR_KEYWORDS)
    pci_issues = any(keyword in text for keyword in PCI_DSS_KEYWORDS)

    print("\nCompliance Analysis:")
    if gdpr_issues:
        print("GDPR compliance detected in privacy policy.")
    else:
        print("GDPR compliance NOT detected in privacy policy.")

    if pci_issues:
        print("PCI-DSS compliance detected in privacy policy.")
    else:
        print("PCI-DSS compliance NOT detected in privacy policy.")


if __name__ == "__main__":
    # Set your APK path here
    apk_path = r"D:\ResearchLab\sample apk\Bakong.apk"

    if os.path.exists(apk_path):
        analyze_apk(apk_path)
    else:
        print("APK file not found.")
