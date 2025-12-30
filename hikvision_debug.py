#!/usr/bin/env python3
"""
Hikvision ISAPI Debug Tool (v3)
===============================
Tests all ISAPI endpoints of a Hikvision camera.
Auth logic EXACTLY like in the real hikvision_next code (isapi.py).

Usage:
    python hikvision_debug.py

Requirements:
    pip install httpx xmltodict
"""

import asyncio
import json
import sys
from datetime import datetime
from typing import Any, Optional

try:
    import httpx
except ImportError:
    print("Error: httpx is not installed. Please run: pip install httpx")
    sys.exit(1)

try:
    import xmltodict
except ImportError:
    print("Error: xmltodict is not installed. Please run: pip install xmltodict")
    sys.exit(1)


# ============================================================================
# CONFIGURATION - EDIT HERE
# ============================================================================

CAMERA_HOST = "https://192.168.123.123"
USERNAME = "admin"
PASSWORD = "xxxxxx"
VERIFY_SSL = False

# ============================================================================
# CONSTANTS FROM THE REAL CODE (const.py)
# ============================================================================

EVENT_BASIC = "basic"
EVENT_IO = "io"
EVENT_SMART = "smart"
EVENT_PIR = "pir"

EVENTS = {
    "motiondetection": {"type": EVENT_BASIC, "slug": "motionDetection"},
    "tamperdetection": {"type": EVENT_BASIC, "slug": "tamperDetection"},
    "videoloss": {"type": EVENT_BASIC, "slug": "videoLoss"},
    "scenechangedetection": {"type": EVENT_SMART, "slug": "SceneChangeDetection"},
    "fielddetection": {"type": EVENT_SMART, "slug": "FieldDetection"},
    "linedetection": {"type": EVENT_SMART, "slug": "LineDetection"},
    "regionentrance": {"type": EVENT_SMART, "slug": "regionEntrance"},
    "regionexiting": {"type": EVENT_SMART, "slug": "regionExiting"},
    "io": {"type": EVENT_IO, "slug": "inputs"},
    "pir": {"type": EVENT_PIR, "slug": "WLAlarm/PIR"},
}

EVENTS_ALTERNATE_ID = {
    "vmd": "motiondetection",
    "thermometry": "motiondetection",
    "shelteralarm": "tamperdetection",
    "vmdhuman": "motiondetection",
    "vmdhuman vehicle": "motiondetection",
}

STREAM_TYPE = {1: "Main Stream", 2: "Sub-stream", 3: "Third Stream", 4: "Transcoded Stream"}

# Endpoints from diagnostics.py
BASE_ENDPOINTS = [
    "System/deviceInfo",
    "System/capabilities",
    "System/IO/inputs/1/status",
    "System/IO/outputs/1/status",
    "System/Holidays",
    "System/Video/inputs/channels",
    "ContentMgmt/InputProxy/channels",
    "ContentMgmt/Storage",
    "Security/adminAccesses",
    "Event/triggers",
    "Event/channels/capabilities",
    "Event/triggers/scenechangedetection-1",
    "Event/notification/httpHosts",
    "Streaming/channels",
]


def deep_get(dictionary: dict, path: str, default: Any = None) -> Any:
    """Safe access to nested dictionaries."""
    keys = path.split(".")
    result = dictionary
    for key in keys:
        if isinstance(result, dict):
            result = result.get(key, default)
        else:
            return default
    if default == [] and not isinstance(result, list):
        return [result] if result else []
    return result


def translate_event_id(event_type: str) -> str:
    """Translate an event type to a normalized event ID."""
    if not event_type:
        return ""
    event_id = event_type.lower()
    return EVENTS_ALTERNATE_ID.get(event_id, event_id)


def generate_event_url(event_id: str, channel_id: int, io_port_id: int = 0, is_proxy: bool = False) -> Optional[str]:
    """Generate an event state URL (like isapi.py:335-360)."""
    if event_id not in EVENTS:
        return None

    event_type = EVENTS[event_id]["type"]
    slug = EVENTS[event_id]["slug"]

    if event_type == EVENT_BASIC:
        if is_proxy:
            return f"ContentMgmt/InputProxy/channels/{channel_id}/video/{slug}"
        return f"System/Video/inputs/channels/{channel_id}/{slug}"
    elif event_type == EVENT_IO:
        if is_proxy:
            return f"ContentMgmt/IOProxy/{slug}/{io_port_id}"
        return f"System/IO/{slug}/{io_port_id}"
    elif event_type == EVENT_PIR:
        return slug
    else:  # EVENT_SMART
        return f"Smart/{slug}/{channel_id}"


class HikvisionDebugger:
    """Debug tool for Hikvision ISAPI - EXACTLY like the real code."""

    def __init__(self, host: str, username: str, password: str, verify_ssl: bool = False):
        self.host = host.rstrip("/")
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl

        # EXACTLY like in the real code (isapi.py)
        self.isapi_prefix = "ISAPI"
        self.timeout = 30.0
        self._auth_method: Optional[httpx.Auth] = None
        self._session: Optional[httpx.AsyncClient] = None

        self.results: dict[str, Any] = {}
        self.device_model: str = "unknown"
        self.stats = {"success": 0, "failed": 0}
        self.channel_ids: list[int] = []
        self.events: list[dict] = []

    def get_isapi_url(self, relative_url: str) -> str:
        """Build full ISAPI URL - EXACTLY like isapi.py:766-768."""
        return f"{self.host}/{self.isapi_prefix}/{relative_url}"

    async def _detect_auth_method(self):
        """Detect auth method - EXACTLY like isapi.py:745-764."""
        # Lines 747-748:
        if not self._session:
            self._session = httpx.AsyncClient(timeout=self.timeout, verify=self.verify_ssl)

        # Line 750: build URL
        url = f"{self.host}/{self.isapi_prefix}/System/deviceInfo"

        print(f"\n[AUTH] --- [WWW-Authenticate detection] {self.host}")
        print(f"[AUTH] URL: {url}")

        # Line 752: GET without auth
        response = await self._session.get(url)

        print(f"[AUTH] Response Status: {response.status_code}")

        # Lines 753-759:
        if response.status_code == 401:
            www_authenticate = response.headers.get("WWW-Authenticate", "")
            print(f"[AUTH] WWW-Authenticate: {www_authenticate[:100]}...")

            # IMPORTANT: Prefer Digest! (Hikvision default)
            if "Digest" in www_authenticate:
                print("[AUTH] -> Set DigestAuth")
                self._auth_method = httpx.DigestAuth(self.username, self.password)
            elif "Basic" in www_authenticate:
                print("[AUTH] -> Set BasicAuth")
                self._auth_method = httpx.BasicAuth(self.username, self.password)

            # CRITICAL: Create a new session after auth detection!
            # The old session has state from the 401 which can break httpx DigestAuth.
            await self._session.aclose()
            self._session = httpx.AsyncClient(timeout=self.timeout, verify=self.verify_ssl)
            print("[AUTH] -> New session created")

        # Lines 761-764:
        if not self._auth_method:
            print(f"\033[91m[ERROR] Auth method not detected! Status: {response.status_code}\033[0m")
            print(f"[AUTH] Headers: {dict(response.headers)}")

    async def request(self, method: str, relative_url: str, category: str = "") -> tuple[int, Optional[dict]]:
        """Send ISAPI request - EXACTLY like isapi.py:770-807."""
        full_url = self.get_isapi_url(relative_url)

        try:
            # Lines 780-781: auth detection if needed
            if not self._auth_method:
                await self._detect_auth_method()

            # Lines 783-789: request with auth
            response = await self._session.request(
                method,
                full_url,
                auth=self._auth_method,
                timeout=self.timeout,
            )

            status_code = response.status_code

            # Parse response
            data = None
            if status_code == 200:
                try:
                    data = json.loads(json.dumps(xmltodict.parse(response.text)))
                except Exception:
                    data = {"_raw": response.text[:500]}

            # Store
            self.results[relative_url] = {
                "status_code": status_code,
                "response": data,
                "category": category,
            }

            # Statistics
            if status_code == 200:
                self.stats["success"] += 1
            else:
                self.stats["failed"] += 1

            # Output
            self._print_result(relative_url, status_code, category)
            return (status_code, data)

        except Exception as e:
            self.results[relative_url] = {"status_code": -1, "error": str(e), "category": category}
            self.stats["failed"] += 1
            self._print_result(relative_url, -1, category, str(e))
            return (-1, None)

    def _print_result(self, path: str, status: int, category: str = "", error: str = ""):
        """Formatted output of one test result."""
        if status == 200:
            sym, stat = "\033[92m✓\033[0m", f"\033[92m[{status}]\033[0m"
        elif status == 401:
            sym, stat = "\033[91m✗\033[0m", f"\033[91m[{status} AUTH]\033[0m"
        elif status == 403:
            sym, stat = "\033[93m✗\033[0m", f"\033[93m[{status}]\033[0m"
        elif status == 404:
            sym, stat = "\033[90m-\033[0m", f"\033[90m[{status}]\033[0m"
        elif status > 0:
            sym, stat = "\033[91m✗\033[0m", f"\033[91m[{status}]\033[0m"
        else:
            sym, stat = "\033[91m✗\033[0m", "\033[91m[ERR]\033[0m"

        path_display = path[:50].ljust(50)
        extra = f" {error}" if error else ""
        print(f"  {stat} {path_display} {sym}{extra}")

    # =========================================================================
    # DYNAMIC URL EXTRACTION
    # =========================================================================

    def extract_channel_ids(self) -> list[int]:
        """Extract channel IDs from the Streaming/channels response."""
        data = self.results.get("Streaming/channels", {}).get("response")
        if not data:
            return []

        channels = deep_get(data, "StreamingChannelList.StreamingChannel", [])
        if not isinstance(channels, list):
            channels = [channels] if channels else []

        ids = set()
        for ch in channels:
            vid = deep_get(ch, "Video.videoInputChannelID")
            if vid:
                try:
                    ids.add(int(vid))
                except (ValueError, TypeError):
                    pass
        return sorted(ids)

    def extract_events(self) -> list[dict]:
        """Extract events from the Event/triggers response."""
        data = self.results.get("Event/triggers", {}).get("response")
        if not data:
            return []

        event_notification = data.get("EventNotification")
        if event_notification:
            triggers = deep_get(event_notification, "EventTriggerList.EventTrigger", [])
        else:
            triggers = deep_get(data, "EventTriggerList.EventTrigger", [])

        if not isinstance(triggers, list):
            triggers = [triggers] if triggers else []

        events = []
        for trigger in triggers:
            event_id = trigger.get("id", "")
            event_type = trigger.get("eventType", "")

            # Handle case where id/eventType are lists (firmware V5.5.338+)
            # e.g. "id": ["VMD-1", "vmd-1"] -> use first element "VMD-1"
            if isinstance(event_id, list):
                event_id = event_id[0] if event_id else ""
            if isinstance(event_type, list):
                event_type = event_type[0] if event_type else ""

            channel_id = trigger.get("videoInputChannelID") or trigger.get("dynVideoInputChannelID") or "0"
            io_port = trigger.get("inputIOPortID") or trigger.get("dynInputIOPortID") or "0"
            is_proxy = bool(trigger.get("dynVideoInputChannelID") or trigger.get("dynInputIOPortID"))

            events.append(
                {
                    "id": event_id,
                    "eventType": event_type,
                    "channel_id": int(channel_id) if channel_id else 0,
                    "io_port": int(io_port) if io_port else 0,
                    "is_proxy": is_proxy,
                }
            )
        return events

    # =========================================================================
    # MAIN TEST FLOW
    # =========================================================================

    async def run_all_tests(self):
        """Run all tests."""
        print("\n" + "=" * 65)
        print("\033[1m        HIKVISION ISAPI DEBUG TOOL v3\033[0m")
        print("=" * 65)
        print(f"  Host: {self.host}")
        print(f"  User: {self.username}")
        print(f"  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 65)

        # Phase 1: base endpoints (auth happens automatically on the first request)
        print("\n\033[1m=== PHASE 1: BASE ENDPOINTS ===\033[0m")
        for endpoint in BASE_ENDPOINTS:
            await self.request("GET", endpoint, "base")

            # After the first request, check whether auth succeeded
            if endpoint == "System/deviceInfo":
                result = self.results.get("System/deviceInfo", {})
                if result.get("status_code") == 401:
                    print("\n\033[91m[ABORT] Authentication failed!\033[0m")
                    print("[DEBUG] Check username/password and auth method")
                    return

        # Device model
        device_info = self.results.get("System/deviceInfo", {}).get("response", {})
        self.device_model = deep_get(device_info, "DeviceInfo.model", "unknown")
        if self.device_model != "unknown":
            print(f"\n  Camera model: \033[1m{self.device_model}\033[0m")

        # Phase 2: streaming channels
        print("\n\033[1m=== PHASE 2: STREAMING CHANNELS ===\033[0m")
        self.channel_ids = self.extract_channel_ids()
        if self.channel_ids:
            print(f"  Found channels: {self.channel_ids}")
            for ch_id in self.channel_ids:
                for stream_type_id in STREAM_TYPE.keys():
                    await self.request("GET", f"Streaming/channels/{ch_id}0{stream_type_id}", "streaming")
        else:
            print("  [SKIP] No channels found")

        # Phase 3: event triggers
        print("\n\033[1m=== PHASE 3: EVENT TRIGGERS ===\033[0m")
        self.events = self.extract_events()
        if self.events:
            print(f"  Found events: {len(self.events)}")

            # Event IDs (original IDs as returned by the camera)
            print("\n  \033[1mEvent IDs (original):\033[0m")
            for event in self.events:
                if event["id"]:
                    await self.request("GET", f"Event/triggers/{event['id']}", "event_orig")

            # Event state URLs
            print("\n  \033[1mEvent state URLs:\033[0m")
            tested_urls = set()
            for event in self.events:
                translated = translate_event_id(event["eventType"])
                if translated in EVENTS:
                    url = generate_event_url(translated, event["channel_id"] or 1, event["io_port"], event["is_proxy"])
                    if url and url not in tested_urls:
                        tested_urls.add(url)
                        await self.request("GET", url, "event_state")
        else:
            print("  [SKIP] No events found")

        # Show camera capabilities
        self._show_camera_capabilities()

    def _show_camera_capabilities(self):
        """Show which event endpoints the camera supports."""
        print("\n\033[1m=== CAMERA CAPABILITIES ===\033[0m")

        working = []
        failed = []
        for event in self.events:
            orig_id = event["id"]
            if not orig_id:
                continue
            status = self.results.get(f"Event/triggers/{orig_id}", {}).get("status_code")
            if status == 200:
                working.append({"id": orig_id, "type": event["eventType"]})
            else:
                failed.append({"id": orig_id, "type": event["eventType"], "status": status})

        if working:
            print(f"\n  \033[92mSupported events: {len(working)}\033[0m")
            for e in working[:15]:
                translated = translate_event_id(e["type"])
                print(f"    ✓ {e['id']} → {translated}")

        if failed:
            print(f"\n  \033[93mNot reachable: {len(failed)}\033[0m")
            for e in failed[:5]:
                print(f"    ✗ {e['id']} (Status: {e['status']})")

    def print_summary(self):
        """Summary."""
        print("\n" + "=" * 65)
        print("\033[1m        SUMMARY\033[0m")
        print("=" * 65)
        print(f"  Camera:     {self.device_model}")
        print(f"  Channels:   {self.channel_ids}")
        print(f"  Events:     {len(self.events)}")
        print(f"\n  \033[92mSuccessful: {self.stats['success']}\033[0m")
        print(f"  \033[91mFailed:     {self.stats['failed']}\033[0m")
        print("=" * 65)

    def export_json(self, output_path: Optional[str] = None) -> str:
        """Export as JSON."""
        if not output_path:
            model_safe = self.device_model.replace("/", "-").replace(" ", "_")
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = f"camera_debug_{model_safe}_{ts}.json"

        export = {"data": {"ISAPI": {}}}
        for path, result in self.results.items():
            if result.get("status_code") == 200 and result.get("response"):
                export["data"]["ISAPI"][path] = {"response": result["response"]}
            else:
                export["data"]["ISAPI"][path] = {
                    "status_code": result.get("status_code"),
                    "error": result.get("error"),
                }

        export["data"]["_meta"] = {
            "model": self.device_model,
            "channels": self.channel_ids,
            "events_count": len(self.events),
            "timestamp": datetime.now().isoformat(),
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(export, f, indent=2, ensure_ascii=False)

        print(f"\n  Export: {output_path}")
        return output_path

    async def close(self):
        if self._session:
            await self._session.aclose()


async def main():
    import argparse

    parser = argparse.ArgumentParser(description="Hikvision ISAPI Debug Tool")
    parser.add_argument("-e", "--endpoint", help="Query a single endpoint (e.g. 'Event/triggers/VMD-1')")
    args = parser.parse_args()

    debugger = HikvisionDebugger(
        host=CAMERA_HOST,
        username=USERNAME,
        password=PASSWORD,
        verify_ssl=VERIFY_SSL,
    )

    try:
        if args.endpoint:
            # Single-endpoint mode
            print(f"\n[SINGLE] Query: {args.endpoint}")
            status, data = await debugger.request("GET", args.endpoint, "single")
            print(f"[SINGLE] Status: {status}")
            if data:
                print("[SINGLE] Response:")
                print(json.dumps(data, indent=2, ensure_ascii=False))
            else:
                print("[SINGLE] No data received")
        else:
            # Normal mode
            await debugger.run_all_tests()
            debugger.print_summary()
            debugger.export_json()
    except KeyboardInterrupt:
        print("\n\nAborted.")
    except Exception as e:
        print(f"\n\033[91mError: {e}\033[0m")
        import traceback

        traceback.print_exc()
    finally:
        await debugger.close()


if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
