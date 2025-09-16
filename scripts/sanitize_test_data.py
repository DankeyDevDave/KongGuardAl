#!/usr/bin/env python3
"""
Kong Guard AI - Test Data Sanitization Script
Replaces hardcoded IP addresses and sensitive data with placeholder values
"""

import re
from pathlib import Path
from typing import Union


class TestDataSanitizer:
    """Sanitizes test data by replacing hardcoded IPs and sensitive information"""

    def __init__(self, project_root: str = "."):
        self.project_root = Path(project_root)
        self.changes_made: list[dict[str, str]] = []

        # IP address patterns to replace
        self.ip_patterns = [
            # Private IP ranges
            r"192\.168\.\d{1,3}\.\d{1,3}",  # 192.168.x.x
            r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}",  # 10.x.x.x
            r"172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}",  # 172.16-31.x.x
            # Specific hardcoded IPs found in audit
            r"192\.168\.0\.201",
            r"192\.168\.0\.202",
            r"192\.168\.0\.225",
            r"192\.168\.1\.100",
            r"192\.168\.1\.101",
            r"192\.168\.1\.102",
            r"192\.168\.100\.200",
            r"192\.168\.50\.10",
            r"192\.168\.50\.11",
            r"192\.168\.50\.12",
            r"192\.168\.100\.50",
            r"192\.168\.100\.51",
            r"192\.168\.100\.52",
            r"192\.168\.100\.53",
            r"192\.168\.100\.60",
        ]

        # File patterns to process
        self.file_patterns = [
            "*.py",
            "*.lua",
            "*.yaml",
            "*.yml",
            "*.json",
            "*.sh",
            "*.conf",
            "*.html",
            "*.js",
            "*.ts",
            "*.md",
        ]

        # Directories to exclude
        self.exclude_dirs = {
            "node_modules",
            "__pycache__",
            ".git",
            "supabase_env",
            "venv",
            ".venv",
            "env",
            ".env",
            "test-results",
            "playwright-report",
            "archived-plugins",
        }

        # Files to exclude
        self.exclude_files = {
            "package-lock.json",
            "yarn.lock",
            "poetry.lock",
            "requirements.txt",
            "requirements-ollama.txt",
            "env_example",
            ".gitignore",
            "LICENSE",
            "README.md",
            "COPYRIGHT_HEADER.txt",
        }

    def should_process_file(self, file_path: Path) -> bool:
        """Determine if a file should be processed"""
        # Check if file is in excluded directories
        for part in file_path.parts:
            if part in self.exclude_dirs:
                return False

        # Check if file is in excluded files list
        if file_path.name in self.exclude_files:
            return False

        # Check if file matches patterns
        for pattern in self.file_patterns:
            if file_path.match(pattern):
                return True

        return False

    def get_replacement_ip(self, original_ip: str) -> str:
        """Get a replacement IP address based on the original"""
        # Map specific IPs to test-friendly replacements
        ip_mapping = {
            # Database hosts
            "198.51.100.201": "198.51.100.201",
            "198.51.100.202": "198.51.100.202",
            "198.51.100.225": "198.51.100.225",
            # Test client IPs
            "203.0.113.100": "203.0.113.100",
            "203.0.113.101": "203.0.113.101",
            "203.0.113.102": "203.0.113.102",
            "203.0.113.200": "203.0.113.200",
            # Test network ranges
            "203.0.113.200": "203.0.113.200",
            "203.0.113.10": "203.0.113.10",
            "203.0.113.11": "203.0.113.11",
            "203.0.113.12": "203.0.113.12",
            # Test threat IPs
            "203.0.113.50": "203.0.113.50",
            "203.0.113.51": "203.0.113.51",
            "203.0.113.52": "203.0.113.52",
            "203.0.113.53": "203.0.113.53",
            "203.0.113.60": "203.0.113.60",
        }

        # Use mapping if available, otherwise use RFC 5737 test IPs
        if original_ip in ip_mapping:
            return ip_mapping[original_ip]

        # For other private IPs, use RFC 5737 test IPs
        if original_ip.startswith("192.168."):
            return f"203.0.113.{original_ip.split('.')[-1]}"
        elif original_ip.startswith("10."):
            return f"198.51.100.{original_ip.split('.')[-1]}"
        elif original_ip.startswith("172."):
            return f"233.252.0.{original_ip.split('.')[-1]}"

        return original_ip

    def sanitize_file(self, file_path: Path) -> bool:
        """Sanitize a single file"""
        try:
            # Read file content
            with open(file_path, encoding="utf-8", errors="ignore") as f:
                content = f.read()

            original_content = content
            modified = False

            # Replace IP addresses
            for pattern in self.ip_patterns:
                matches = re.finditer(pattern, content)
                for match in matches:
                    original_ip = match.group()
                    replacement_ip = self.get_replacement_ip(original_ip)
                    if original_ip != replacement_ip:
                        content = content.replace(original_ip, replacement_ip)
                        modified = True
                        self.changes_made.append(
                            {
                                "file": str(file_path),
                                "type": "ip_address",
                                "original": original_ip,
                                "replacement": replacement_ip,
                            }
                        )

            # Replace hardcoded passwords (simple pattern)
            password_patterns = [
                (r'password\s*=\s*["\']kongpass["\']', 'password = "test_password"'),
                (r'password\s*=\s*["\']kongapass["\']', 'password = "test_konga_password"'),
                (r'POSTGRES_PASSWORD\s*=\s*["\']kongpass["\']', 'POSTGRES_PASSWORD = "test_password"'),
                (r'POSTGRES_PASSWORD\s*=\s*["\']kongapass["\']', 'POSTGRES_PASSWORD = "test_konga_password"'),
                (r'KONG_PG_PASSWORD\s*=\s*["\']kongpass["\']', 'KONG_PG_PASSWORD = "test_password"'),
                (r'DB_PASSWORD\s*=\s*["\']kongapass["\']', 'DB_PASSWORD = "test_konga_password"'),
            ]

            for pattern, replacement in password_patterns:
                if re.search(pattern, content):
                    content = re.sub(pattern, replacement, content)
                    modified = True
                    self.changes_made.append(
                        {
                            "file": str(file_path),
                            "type": "password",
                            "original": "hardcoded_password",
                            "replacement": "test_password",
                        }
                    )

            # Write back if modified
            if modified:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(content)
                print(f"✅ Sanitized: {file_path}")
                return True

            return False

        except Exception as e:
            print(f"❌ Error processing {file_path}: {e}")
            return False

    def find_files(self) -> list[Path]:
        """Find all files that should be processed"""
        files = []

        for pattern in self.file_patterns:
            pattern_files = self.project_root.rglob(pattern)
            for file_path in pattern_files:
                if self.should_process_file(file_path):
                    files.append(file_path)

        return files

    def sanitize_all(self) -> dict[str, Union[int, list[dict[str, str]]]]:
        """Sanitize all files in the project"""
        print("🔍 Scanning for files to sanitize...")
        files = self.find_files()
        print(f"Found {len(files)} files to process")

        processed = 0
        modified = 0

        for file_path in files:
            processed += 1
            if self.sanitize_file(file_path):
                modified += 1

        return {
            "total_files": len(files),
            "processed_files": processed,
            "modified_files": modified,
            "changes": self.changes_made,
        }

    def generate_report(self, results: dict[str, Union[int, list[dict[str, str]]]]) -> str:
        """Generate a sanitization report"""
        report = f"""
# Test Data Sanitization Report

## Summary
- Total files scanned: {results['total_files']}
- Files processed: {results['processed_files']}
- Files modified: {results['modified_files']}

## Changes Made
"""

        # Group changes by type
        changes_by_type: dict[str, list[dict[str, str]]] = {}
        changes = results.get("changes", [])
        if isinstance(changes, list):
            for change in changes:
                change_type = change["type"]
                if change_type not in changes_by_type:
                    changes_by_type[change_type] = []
                changes_by_type[change_type].append(change)

        for change_type, changes in changes_by_type.items():
            report += f"\n### {change_type.title()} Changes ({len(changes)})\n"
            for change in changes:
                report += f"- **{change['file']}**: `{change['original']}` → `{change['replacement']}`\n"

        return report


def main():
    """Main function"""
    print("🔒 Kong Guard AI - Test Data Sanitization")
    print("=" * 50)

    sanitizer = TestDataSanitizer()
    results = sanitizer.sanitize_all()

    print("\n📊 Sanitization Complete!")
    print(f"   Files processed: {results['processed_files']}")
    print(f"   Files modified: {results['modified_files']}")
    print(f"   Total changes: {len(results['changes'])}")

    # Generate and save report
    report = sanitizer.generate_report(results)
    report_path = Path("test-results/sanitization-report.md")
    report_path.parent.mkdir(exist_ok=True)

    with open(report_path, "w") as f:
        f.write(report)

    print(f"\n📄 Report saved to: {report_path}")

    if results["modified_files"] > 0:
        print("\n⚠️  IMPORTANT: Review the changes and update any documentation!")
        print("   Some IP addresses may need to be updated in configuration files.")


if __name__ == "__main__":
    main()
