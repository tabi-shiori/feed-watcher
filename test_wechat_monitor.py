#!/usr/bin/env python3
import datetime
import unittest

import wechat_monitor as wm


class TestWeChatMonitor(unittest.TestCase):
    def test_monitored_accounts_filter_and_exclusion(self):
        cfg = {
            "monitored_accounts": ["AlphaFeed", "BetaFeed"],
            "excluded_accounts": ["ExcludedFeed"],
        }
        self.assertTrue(wm.is_account_monitored("AlphaFeed", cfg))
        self.assertTrue(wm.is_account_monitored("BetaFeed", cfg))
        self.assertFalse(wm.is_account_monitored("ExcludedFeed", cfg))
        self.assertFalse(wm.is_account_monitored("UnrelatedFeed", cfg))

    def test_bark_silent_pin_payload(self):
        cfg = dict(wm.DEFAULT_CONFIG)
        cfg["bark_key"] = "https://api.day.app/TestDeviceKey123/"
        cfg["bark_mode"] = "silent_pin"
        article = {
            "account": "AlphaFeed",
            "title": "Sample Title",
            "published_at": "2026-11-21 08:31",
            "url": "https://mp.weixin.qq.com/s/test_article_123",
            "summary": "<p>Sample summary text</p>",
        }
        payload = wm.build_bark_payload(article, cfg)
        self.assertEqual(payload["device_key"], "TestDeviceKey123")
        self.assertEqual(payload["level"], "timeSensitive")
        self.assertEqual(payload["sound"], "silence")
        self.assertNotIn("call", payload)
        self.assertNotIn("volume", payload)
        self.assertEqual(payload["url"], "https://mp.weixin.qq.com/s/test_article_123")

    def test_bark_wechat_app_click_action(self):
        cfg = dict(wm.DEFAULT_CONFIG)
        cfg["bark_key"] = "MyKey999"
        cfg["click_action"] = "wechat_app"
        article = {
            "account": "BetaFeed",
            "title": "Another Title",
            "published_at": "2026-09-18 11:21",
            "url": "https://mp.weixin.qq.com/s/xyz987",
            "summary": "Body",
        }
        payload = wm.build_bark_payload(article, cfg)
        self.assertEqual(payload["url"], "weixin://")
        self.assertEqual(payload["copy"], "https://mp.weixin.qq.com/s/xyz987")
        self.assertEqual(payload["level"], "timeSensitive")
        self.assertEqual(payload["sound"], "silence")

    def test_golden_window_interval(self):
        bj = datetime.timezone(datetime.timedelta(hours=8))
        morning_dt = datetime.datetime(2026, 11, 21, 9, 30, tzinfo=bj)
        sec, _ = wm.get_poll_interval_seconds(morning_dt)
        self.assertEqual(sec, 180)

    def test_sha20_hashing(self):
        h1 = wm.sha20("item_123")
        self.assertEqual(len(h1), 20)
        self.assertEqual(h1, wm.sha20("item_123"))


if __name__ == "__main__":
    unittest.main()
