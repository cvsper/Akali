#!/usr/bin/env python3
"""
Feed Aggregator - Aggregate security RSS feeds and advisories
"""

import json
import os
from datetime import datetime, timedelta
from typing import Dict, List
import requests
import xml.etree.ElementTree as ET


class FeedAggregator:
    """Aggregate security threat intelligence feeds"""

    def __init__(self):
        """Initialize feed aggregator"""
        self.cache_file = os.path.expanduser("~/akali/intelligence/threat_hub/feed_cache.json")
        self.config_file = os.path.expanduser("~/akali/intelligence/feeds/feed_config.json")
        self.cache = self._load_cache()
        self.feeds = self._load_config()

    def _load_cache(self) -> Dict:
        """Load feed cache from disk"""
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Warning: Failed to load cache: {e}")
        return {"entries": [], "last_updated": None}

    def _save_cache(self):
        """Save feed cache to disk"""
        os.makedirs(os.path.dirname(self.cache_file), exist_ok=True)
        with open(self.cache_file, 'w') as f:
            json.dump(self.cache, f, indent=2)

    def _load_config(self) -> List[Dict]:
        """Load feed configuration"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    return config.get("feeds", [])
            except Exception as e:
                print(f"Warning: Failed to load config: {e}")

        # Default feeds if config doesn't exist
        return self._default_feeds()

    def _default_feeds(self) -> List[Dict]:
        """Default security feeds"""
        return [
            {
                "name": "US-CERT",
                "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
                "type": "rss",
                "enabled": True,
            },
            {
                "name": "GitHub Security",
                "url": "https://github.blog/category/security/feed/",
                "type": "rss",
                "enabled": True,
            },
            {
                "name": "Krebs on Security",
                "url": "https://krebsonsecurity.com/feed/",
                "type": "rss",
                "enabled": True,
            },
            {
                "name": "Schneier on Security",
                "url": "https://www.schneier.com/feed/",
                "type": "rss",
                "enabled": True,
            },
        ]

    def fetch_all_feeds(self, since_hours: int = 24) -> List[Dict]:
        """
        Fetch entries from all enabled feeds

        Args:
            since_hours: Only return entries from last N hours

        Returns:
            List of feed entry dictionaries
        """
        print("Fetching security feeds...")

        entries = []
        cutoff = datetime.now() - timedelta(hours=since_hours)

        for feed in self.feeds:
            if not feed.get("enabled", True):
                continue

            print(f"  Fetching: {feed['name']}")

            try:
                feed_entries = self._fetch_rss_feed(feed["url"])

                # Filter by time
                for entry in feed_entries:
                    if entry["published"] > cutoff:
                        entry["source"] = feed["name"]
                        entries.append(entry)

            except Exception as e:
                print(f"    Error: {e}")

        # Deduplicate by URL
        unique_entries = {}
        for entry in entries:
            unique_entries[entry["url"]] = entry

        entries = list(unique_entries.values())

        # Sort by published date (newest first)
        entries.sort(key=lambda x: x["published"], reverse=True)

        # Update cache
        self.cache["entries"] = entries
        self.cache["last_updated"] = datetime.now().isoformat()
        self._save_cache()

        print(f"Fetched {len(entries)} entries from {len(self.feeds)} feeds")

        return entries

    def _fetch_rss_feed(self, url: str) -> List[Dict]:
        """
        Fetch and parse RSS feed

        Args:
            url: Feed URL

        Returns:
            List of entry dictionaries
        """
        response = requests.get(url, timeout=30)
        response.raise_for_status()

        # Parse XML
        root = ET.fromstring(response.content)

        entries = []

        # RSS 2.0 format
        for item in root.findall(".//item"):
            title = item.find("title")
            link = item.find("link")
            description = item.find("description")
            pub_date = item.find("pubDate")

            if title is not None and link is not None:
                # Parse pub date
                published = datetime.now()
                if pub_date is not None:
                    try:
                        # RFC 2822 format: "Wed, 02 Oct 2024 12:00:00 +0000"
                        from email.utils import parsedate_to_datetime
                        published = parsedate_to_datetime(pub_date.text)
                    except Exception:
                        pass

                entries.append({
                    "title": title.text,
                    "url": link.text,
                    "description": description.text if description is not None else "",
                    "published": published,
                })

        # Atom format
        for entry in root.findall(".//{http://www.w3.org/2005/Atom}entry"):
            title = entry.find("{http://www.w3.org/2005/Atom}title")
            link = entry.find("{http://www.w3.org/2005/Atom}link")
            summary = entry.find("{http://www.w3.org/2005/Atom}summary")
            updated = entry.find("{http://www.w3.org/2005/Atom}updated")

            if title is not None and link is not None:
                # Parse updated date
                published = datetime.now()
                if updated is not None:
                    try:
                        # ISO 8601 format
                        published = datetime.fromisoformat(updated.text.replace('Z', '+00:00'))
                    except Exception:
                        pass

                entries.append({
                    "title": title.text,
                    "url": link.get("href"),
                    "description": summary.text if summary is not None else "",
                    "published": published,
                })

        return entries

    def get_recent_entries(self, hours: int = 24) -> List[Dict]:
        """
        Get recent feed entries from cache

        Args:
            hours: Hours to look back

        Returns:
            List of entry dictionaries
        """
        cutoff = datetime.now() - timedelta(hours=hours)

        recent = []
        for entry in self.cache.get("entries", []):
            pub_date = entry["published"]
            if isinstance(pub_date, str):
                pub_date = datetime.fromisoformat(pub_date)
            if pub_date > cutoff:
                recent.append(entry)

        return recent

    def search_entries(self, keywords: List[str]) -> List[Dict]:
        """
        Search feed entries by keywords

        Args:
            keywords: List of keywords to search for

        Returns:
            Matching entries
        """
        results = []

        for entry in self.cache.get("entries", []):
            title = entry.get("title", "").lower()
            description = entry.get("description", "").lower()

            for keyword in keywords:
                if keyword.lower() in title or keyword.lower() in description:
                    if entry not in results:
                        results.append(entry)
                    break

        return results


def main():
    """CLI for feed aggregation"""
    import sys

    aggregator = FeedAggregator()

    if len(sys.argv) < 2:
        print("Usage:")
        print("  python feed_aggregator.py fetch [hours]      # Fetch feeds")
        print("  python feed_aggregator.py recent [hours]     # Show recent entries")
        print("  python feed_aggregator.py search <keywords>  # Search entries")
        sys.exit(1)

    command = sys.argv[1]

    if command == "fetch":
        hours = int(sys.argv[2]) if len(sys.argv) > 2 else 24
        entries = aggregator.fetch_all_feeds(since_hours=hours)

        print(f"\n{'='*80}")
        print(f"Security Feed Entries (last {hours} hours)")
        print(f"{'='*80}\n")

        for entry in entries:
            pub_date = entry["published"]
            if isinstance(pub_date, datetime):
                pub_date = pub_date.strftime("%Y-%m-%d %H:%M")
            else:
                pub_date = pub_date[:16]  # Truncate ISO string

            print(f"[{entry['source']}] {entry['title']}")
            print(f"  Published: {pub_date}")
            print(f"  URL: {entry['url']}")
            if entry.get("description"):
                desc = entry["description"][:150]
                print(f"  {desc}...")
            print()

    elif command == "recent":
        hours = int(sys.argv[2]) if len(sys.argv) > 2 else 24
        entries = aggregator.get_recent_entries(hours)

        print(f"\n{'='*80}")
        print(f"Recent Security News (last {hours} hours)")
        print(f"{'='*80}\n")

        if not entries:
            print("No recent entries. Run 'fetch' first.")
        else:
            for entry in entries:
                print(f"[{entry['source']}] {entry['title']}")
                print(f"  {entry['url']}")
                print()

    elif command == "search":
        if len(sys.argv) < 3:
            print("Error: Keywords required")
            sys.exit(1)

        keywords = sys.argv[2:]
        entries = aggregator.search_entries(keywords)

        print(f"\n{'='*80}")
        print(f"Search Results: {', '.join(keywords)}")
        print(f"{'='*80}\n")

        if not entries:
            print("No matching entries found.")
        else:
            print(f"Found {len(entries)} matching entries:\n")

            for entry in entries:
                print(f"[{entry['source']}] {entry['title']}")
                print(f"  {entry['url']}")
                print()

    else:
        print(f"Unknown command: {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()
