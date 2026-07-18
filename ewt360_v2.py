#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EWT360 (升学e网通) 自动化学习脚本 v2.1
========================================
基于 Burp + Fiddler 2026-07-18 抓包分析

核心功能:
  - 账号密码自动登录 (AES-256-CBC + MD5签名)
  - Token 登录 / 自动续期
  - 自动发现作业列表 (进行中/已截止/未开始)
  - 遍历所有日期获取全部未完成课程
  - 获取真实 courseId (getLessonDetailV2)
  - 模拟观看并通过 monitor/collect/batch 上报进度
    (HMAC-SHA1 签名, 逆向自 mstplayer-v3.0.37.min.js)
  - 交互式选择：按序号/科目/日期筛选
  - --debug 模式打印所有 API 请求/响应

原理说明:
  - 真正更新服务端 playTime 的接口是 bfe.ewt360.com 的
    /monitor/web/collect/batch (心跳上报), 而非 playbackProgress / record/submit
  - 该接口使用 HMAC-SHA1 签名: 对排序后的参数串用会话级 secret 做 HMAC
  - 每批上报使用固定的 stay_time (默认 12000ms), 服务端按 report_time - begin_time
    独立校验 (≈ stay_time / speed) 并自动累加 playTime

依赖:
  pip install -r requirements.txt   # requests, pycryptodomex
"""

import hashlib
import json
import math
import os
import random
import string
import sys
import time
import traceback
from datetime import datetime, timedelta
from typing import Optional

import requests

# pycryptodome 在部分环境用 Crypto 命名空间, 冲突时换 pycryptodomex 用 Cryptodome
try:
    from Crypto.Cipher import AES
except ImportError:
    from Cryptodome.Cipher import AES

# ============================================================
# 常量
# ============================================================
GATEWAY_BASE = "https://gateway.ewt360.com"
BFE_BASE = "https://bfe.ewt360.com"
TEACHER_BASE = "https://teacher.ewt360.com"

# AES 加密参数
AES_KEY = b"20171109124536982017110912453698"
AES_IV = b"2017110912453698"

# 旧版签名密钥 (仅用于登录接口)
SIGN_SECRET = "bdc739ff2dcf"

# 科目映射
SUBJECT_MAP = {
    1: "语文", 2: "数学", 3: "英语", 4: "物理",
    5: "化学", 6: "生物", 7: "政治", 8: "历史",
    9: "地理", 10: "心灵成长", 11: "生涯规划",
    12: "综合素养", 13: "信息技术", 14: "心理", 15: "生涯规划"
}


# ============================================================
# 工具函数
# ============================================================

def aes_encrypt(text: str) -> str:
    """AES-256-CBC 加密 (PKCS7填充), 返回大写hex"""
    text_bytes = text.encode("utf-8")
    pad_len = 16 - len(text_bytes) % 16
    text_bytes += bytes([pad_len] * pad_len)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv=AES_IV)
    return cipher.encrypt(text_bytes).hex().upper()


def md5_upper(data: str) -> str:
    return hashlib.md5(data.encode("utf-8")).hexdigest().upper()


def sha1_lower(data: str) -> str:
    return hashlib.sha1(data.encode("utf-8")).hexdigest()


def rand_ip() -> str:
    return f"{random.randint(59,61)}.{random.randint(0,230)}." \
           f"{random.randint(0,230)}.{random.randint(0,230)}"


def rand_uuid(prefix: str = "") -> str:
    rand = "".join(random.sample(string.ascii_letters + string.digits, 8))
    return f"{rand}_{prefix}" if prefix else rand


def ts_to_date(ts_ms: int) -> str:
    return datetime.fromtimestamp(ts_ms / 1000).strftime("%m-%d")


# ============================================================
# EWT360 客户端
# ============================================================

class EWT360Client:
    """EWT360 API 客户端 (v2.0)"""

    def __init__(self, account: str = "", password: str = "",
                 token: str = "", speed: float = 2.0,
                 subject_filter: list = None, debug: bool = False):
        self.account = account
        self.password = password
        self.token = token
        self.speed = speed
        self.subject_filter = subject_filter or []
        self.debug = debug
        self.user_id = ""
        self.school_id = ""
        self.user_name = ""
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/150.0.0.0 Safari/537.36",
            "Accept-Language": "zh-CN,zh;q=0.9",
        })
        self._last_req = 0.0
        # Set token as cookie (critical for gateway API auth)
        if self.token:
            self.session.cookies.set("token", self.token, domain=".ewt360.com")
            # 从 token 中解析 user_id (格式: userId-platform-hash)
            if not self.user_id:
                parts = self.token.split("-")
                if parts and parts[0].isdigit():
                    self.user_id = parts[0]

    def log(self, msg: str, level: str = "INFO"):
        ts = datetime.now().strftime("%H:%M:%S")
        prefix = {"INFO": "[*]", "OK": "[+]", "WARN": "[!]", "ERR": "[-]", "DBG": "[.]"}.get(level, "[*]")
        print(f"{ts} {prefix} {msg}")

    def _rate_limit(self, min_s: float = 0.5):
        elapsed = time.time() - self._last_req
        if elapsed < min_s:
            time.sleep(min_s - elapsed + random.uniform(0, 0.3))
        self._last_req = time.time()

    def _dlog(self, msg: str):
        """debug 日志"""
        if self.debug:
            print(f"  [DEBUG] {msg}")

    def _get(self, url: str, **kw) -> requests.Response:
        self._rate_limit()
        self._dlog(f"GET {url[:100]}")
        r = self.session.get(url, timeout=30, **kw)
        self._dlog(f"  ← {r.status_code} {r.text[:200]}")
        return r

    def _post(self, url: str, **kw) -> requests.Response:
        self._rate_limit()
        body_preview = ""
        if "json" in kw:
            body_preview = json.dumps(kw["json"], ensure_ascii=False)[:200]
        elif "data" in kw:
            body_preview = str(kw["data"])[:200]
        self._dlog(f"POST {url[:100]} body={body_preview}")
        r = self.session.post(url, timeout=30, **kw)
        self._dlog(f"  ← {r.status_code} {r.text[:300]}")
        return r

    def _post_json(self, url: str, data, headers: dict = None) -> dict:
        """发送JSON POST请求, 返回解析后的dict"""
        h = self._auth_headers()
        if headers:
            h.update(headers)
        r = self._post(url, json=data, headers=h)
        return r.json()

    def _auth_headers(self) -> dict:
        """新版鉴权头 (token方式, 用于 teacher.ewt360.com API)
        关键: 必须同时设置 token header + Cookie token + referUrl"""
        return {
            "Content-Type": "application/json",
            "token": self.token,
            "Origin": "https://teacher.ewt360.com",
            "Referer": "https://teacher.ewt360.com/",
            "referUrl": "https://teacher.ewt360.com/ewtbend/bend/index/index.html",
        }

    def _login_headers(self, ts: int) -> dict:
        """登录接口专用签名的请求头"""
        sign = md5_upper(f"{ts}{SIGN_SECRET}")
        return {
            "Content-Type": "application/json;charset=UTF-8",
            "Origin": "https://web.ewt360.com",
            "Referer": "https://web.ewt360.com/",
            "Platform": "1",
            "Secretid": "2",
            "Timestamp": str(ts),
            "Sign": sign,
            "Token": "0",
        }

    # ---- 登录 ----

    def login(self) -> bool:
        """账号密码登录"""
        if not self.account or not self.password:
            self.log("未配置账号密码", "ERR")
            return False

        self.log(f"登录中: {self.account}...")
        ts = int(time.time() * 1000)
        encrypted_pwd = aes_encrypt(self.password)

        try:
            r = self._post(
                f"{GATEWAY_BASE}/api/authcenter/v2/oauth/login/account",
                json={
                    "platform": 1,
                    "userName": self.account,
                    "password": encrypted_pwd,
                    "autoLogin": False,
                    "webVersion": "pc_20250101"
                },
                headers=self._login_headers(ts)
            )
            data = r.json()
            if data.get("success") and data["code"] == "200":
                self.token = data["data"]["token"]
                self.user_id = data["data"]["userId"]
                # 关键: 设置Cookie token
                self.session.cookies.set("token", self.token, domain=".ewt360.com")
                self.log(f"登录成功! userId={self.user_id}", "OK")
                self._fetch_user_info()
                return True
            else:
                self.log(f"登录失败: [{data.get('code')}] {data.get('msg')}", "ERR")
                return False
        except Exception as e:
            self.log(f"登录异常: {e}", "ERR")
            return False

    def verify_token(self) -> bool:
        """验证token是否有效"""
        if not self.token:
            return False
        try:
            r = self._get(
                f"{GATEWAY_BASE}/api/usercenter/user/login/getUser",
                params={"platform": "1"},
                headers={
                    "token": self.token,
                    "Referer": "https://teacher.ewt360.com/",
                    "Content-Type": "application/json"
                }
            )
            data = r.json()
            return data.get("success") and data["data"].get("isLogin")
        except:
            return False

    def _fetch_user_info(self):
        """获取用户信息"""
        try:
            r = self._get(
                f"{GATEWAY_BASE}/api/usercenter/user/baseinfo",
                headers={
                    "token": self.token,
                    "Referer": "https://teacher.ewt360.com/",
                },
                params={"_": int(time.time() * 1000)}
            )
            data = r.json()
            if data.get("success"):
                info = data["data"]
                self.user_name = info.get("realName", "")
                self.school_id = str(info.get("schoolId", ""))
                self.log(f"用户: {self.user_name} | 学校: {info.get('schoolName','')} | "
                         f"会员: {info.get('memberTypeName','')}")
        except Exception as e:
            self.log(f"获取用户信息失败: {e}", "WARN")

    # ---- 场景和作业 ----

    def get_scenes(self) -> list:
        """获取所有假期场景"""
        try:
            data = self._post_json(
                f"{GATEWAY_BASE}/api/holidayprod/scene/student/study/getStudentValidSceneList",
                {"schoolId": int(self.school_id), "clientType": 1, "onlyNeedLearnGroup": 1}
            )
            if data.get("success"):
                return data["data"]
            return []
        except Exception as e:
            self.log(f"获取场景失败: {e}", "ERR")
            return []

    def get_homework_ids(self, scene_id: str) -> list:
        """获取场景下的作业ID列表"""
        try:
            r = self._get(
                f"{GATEWAY_BASE}/api/holidayprod/scene/student/study/checkHoliday",
                params={
                    "schoolId": self.school_id,
                    "clientType": "1",
                    "timestamp": int(time.time() * 1000)
                },
                headers=self._auth_headers()
            )
            data = r.json()
            if data.get("success"):
                # 通过 getStudentHomeworkInfo 获取作业详情
                scenes = data["data"].get("sceneList", [])
                hw_ids = []
                for s in scenes:
                    if str(s.get("id")) == str(scene_id):
                        # 获取场景下的所有homework
                        pass
                return hw_ids
            return []
        except:
            return []

    def get_homework_info(self, homework_id) -> dict:
        """获取作业基本信息"""
        try:
            data = self._post_json(
                f"{GATEWAY_BASE}/api/homeworkprod/student/homework/task/getStudentHomeworkInfo",
                {
                    "schoolId": int(self.school_id),
                    "homeworkId": str(homework_id),
                    "queryMustLearnSubject": 1
                }
            )
            return data.get("data", {}) if data.get("success") else {}
        except Exception as e:
            self.log(f"获取作业信息失败: {e}", "ERR")
            return {}

    def get_day_subject_stat(self, homework_id) -> dict:
        """获取作业的日期和科目统计 (包含所有dayId)"""
        try:
            data = self._post_json(
                f"{GATEWAY_BASE}/api/homeworkprod/student/homework/task/getStudentHomeworkDaySubjectStat",
                {
                    "schoolId": int(self.school_id),
                    "homeworkId": str(homework_id),
                    "mustLearnSubjectList": list(range(1, 13))
                }
            )
            return data.get("data", {}) if data.get("success") else {}
        except Exception as e:
            self.log(f"获取统计失败: {e}", "ERR")
            return {}

    def get_courses_by_day(self, homework_id, day_id: str) -> list:
        """获取指定日期的课程列表"""
        try:
            data = self._post_json(
                f"{GATEWAY_BASE}/api/homeworkprod/student/homework/task/pageHomeworkTasks",
                {
                    "schoolId": int(self.school_id),
                    "homeworkId": homework_id,
                    "mustLearnSubjectList": list(range(1, 13)),
                    "queryMustLearn": 1,
                    "dayId": day_id,
                    "pageIndex": 1,
                    "pageSize": 50
                }
            )
            if data.get("success"):
                return data["data"].get("data", [])
            return []
        except Exception as e:
            self.log(f"获取课程列表失败 day={day_id}: {e}", "ERR")
            return []

    def get_lesson_detail(self, lesson_id: str, homework_id) -> dict:
        """
        获取课程详情 (包含真实的 courseId)
        API: POST /api/homeworkprod/player/getLessonDetailV2
        关键: 返回的 courseId 用于 record/submit, 不是 parentContentId!
        """
        try:
            data = self._post_json(
                f"{GATEWAY_BASE}/api/homeworkprod/player/getLessonDetailV2",
                {
                    "schoolId": int(self.school_id),
                    "lessonId": str(lesson_id),
                    "homeworkId": homework_id
                }
            )
            return data.get("data", {}) if data.get("success") else {}
        except Exception as e:
            self.log(f"获取课程详情失败: {e}", "DBG")
            return {}

    def get_course_task_info(self, homework_id, lesson_id: str) -> dict:
        """获取课程任务的播放信息 (playTime, finishPlayTime等)"""
        try:
            data = self._post_json(
                f"{GATEWAY_BASE}/api/homeworkprod/homework/student/getUserHomeworkLessonTaskInfo",
                {
                    "schoolId": int(self.school_id),
                    "homeworkId": homework_id,
                    "lessonId": lesson_id,
                    "contentType": 1
                }
            )
            return data.get("data", {}) if data.get("success") else {}
        except Exception as e:
            self.log(f"获取课程任务信息失败: {e}", "DBG")
            return {}

    def discover_homeworks(self) -> list:
        """
        自动发现所有作业 (包括进行中、未开始、已截止)
        API: POST /api/homeworkprod/homework/student/getStudentHomeworkInfo
        status: 1=未开始, 2=进行中, 3=已截止, 4=已撤回
        """
        if not self.school_id:
            self._fetch_user_info()
        if not self.school_id:
            self.log("无法获取schoolId, 请先登录", "ERR")
            return []
        all_homeworks = []
        for status in [2, 1, 3]:  # 进行中 > 未开始 > 已截止
            try:
                data = self._post_json(
                    f"{GATEWAY_BASE}/api/homeworkprod/homework/student/getStudentHomeworkInfo",
                    {
                        "schoolId": int(self.school_id),
                        "subject": None,
                        "type": None,
                        "status": status,
                        "pageIndex": 1,
                        "pageSize": 50,
                        "notClassSetting": 0
                    }
                )
                if data.get("success") and data.get("data"):
                    items = data["data"] if isinstance(data["data"], list) else []
                    for hw in items:
                        hw["_status"] = status
                    all_homeworks.extend(items)
            except Exception as e:
                self.log(f"发现作业失败 (status={status}): {e}", "DBG")
        return all_homeworks

    # ---- 获取所有课程 ----

    def get_all_courses(self, scene_id: str = None) -> list:
        """
        获取所有未完成的课程。
        遍历所有场景 -> 所有日期 -> 所有课程。
        """
        all_courses = []

        # Step 1: 获取场景
        scenes = self.get_scenes()
        if not scenes:
            self.log("未找到任何课程场景", "WARN")
            return []

        for scene in scenes:
            sid = scene["id"]
            if scene_id and str(sid) != str(scene_id):
                continue

            scene_title = scene.get("title", "")
            self.log(f"场景: [{sid}] {scene_title}")

            # Step 2: 获取 scene 下的作业
            check_data = self._post_json(
                f"{GATEWAY_BASE}/api/holidayprod/scene/student/study/checkHoliday",
                {"schoolId": int(self.school_id), "clientType": 1}
            ) if not scene_id else {"data": {"sceneList": [scene]}}
            # 使用更简单的方式: 从 getStudentHomeworkInfo 获取 homeworkId
            # 先通过场景信息获取 homework
            try:
                r = self._get(
                    f"{GATEWAY_BASE}/api/holidayprod/scene/student/study/checkHoliday",
                    params={
                        "schoolId": self.school_id,
                        "clientType": "1",
                        "timestamp": int(time.time() * 1000)
                    },
                    headers=self._auth_headers()
                )
                holiday_data = r.json()
                if not holiday_data.get("success"):
                    continue

                # 从checkHoliday响应中获取作业列表
                scene_list = holiday_data["data"].get("sceneList", [])
                homework_ids_for_scene = []
                for sl in scene_list:
                    if str(sl.get("id")) == str(sid):
                        # 直接遍历时间范围内的日期是另一种方法
                        pass

                # 更直接的方法: 从 day_subject_stat 获取所有日期
                # 但我们需要先知道 homeworkId
                # 使用另一个 API 路径
            except:
                continue

            # 简化方式: 遍历场景中的日期范围
            # 获取日期统计需要先有 homeworkId, 从 checkHoliday 中获取
            # 这里使用一个新的方法
            try:
                # 尝试从 checkHoliday 返回中提取 homework 相关数据
                # 如果有报错, 使用已知的 homeworkId
                homework_hint = holiday_data["data"].get("homeworkIds", [])
                if not homework_hint:
                    # 回退: 遍历时间范围
                    self.log(f"  无法直接获取场景 {sid} 的作业列表, 跳过", "WARN")
                    continue
            except:
                continue

        return all_courses

    def get_all_courses_simple(self, homework_id) -> list:
        """
        简化版: 通过已知 homework_id 获取所有未完成课程。
        遍历所有 dayId。
        """
        all_courses = []

        # 获取作业信息
        hw_info = self.get_homework_info(homework_id)
        if not hw_info:
            return []
        hw_title = hw_info.get("homeworkTitle", "")
        self.log(f"作业: {hw_title} (ID={homework_id})")

        # 获取日期和科目统计
        stat = self.get_day_subject_stat(homework_id)
        date_stat = stat.get("dateStat", [])
        total_finish = stat.get("homeworkStat", {}).get("finishCount", 0)
        total_count = stat.get("homeworkStat", {}).get("count", 0)
        self.log(f"  总任务: {total_count}, 已完成: {total_finish}, "
                 f"未完成: {total_count - total_finish}")

        # 遍历所有日期
        for day_info in date_stat:
            day_id = day_info.get("dateId", "")
            day_date = ts_to_date(day_info.get("date", 0))
            day_finished = day_info.get("finishCount", 0)
            day_total = day_info.get("taskCount", 0)

            if day_total == day_finished:
                continue  # 该日期全部完成

            # 获取该日期的课程列表
            courses = self.get_courses_by_day(homework_id, day_id)
            for c in courses:
                # 只处理视频课程 (contentType=1)
                if c.get("contentType") != 1:
                    continue
                # 跳过已完成的
                if c.get("finished") or c.get("ratio", 0) >= 1.0:
                    continue
                # 科目过滤
                subj_id = c.get("subjectId", 0)
                if self.subject_filter and subj_id in self.subject_filter:
                    continue

                c["_homework_id"] = homework_id
                c["_day_id"] = day_id
                c["_day_date"] = day_date
                c["_hw_title"] = hw_title
                all_courses.append(c)

        return all_courses

    # ---- 进度上报 ----

    def report_playback_progress(self, lesson_id: str, progress_seconds: float) -> bool:
        """
        bfe 播放进度上报 (核心进度API)
        POST https://bfe.ewt360.com/video/playbackProgress
        Content-Type: multipart/form-data
        """
        try:
            boundary = f"----WebKitFormBoundary{''.join(random.choices(string.ascii_letters + string.digits, k=16))}"
            body_parts = [
                f"--{boundary}",
                'Content-Disposition: form-data; name="userId"',
                "",
                str(self.user_id),
                f"--{boundary}",
                'Content-Disposition: form-data; name="lessonId"',
                "",
                str(lesson_id),
                f"--{boundary}",
                'Content-Disposition: form-data; name="playedProgress"',
                "",
                str(progress_seconds),
                f"--{boundary}",
                'Content-Disposition: form-data; name="videoBizCode"',
                "",
                "1013",
                f"--{boundary}--",
                ""
            ]
            body = "\r\n".join(body_parts)

            headers = {
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "Origin": "https://teacher.ewt360.com",
                "Referer": "https://teacher.ewt360.com/",
            }

            r = self._post(f"{BFE_BASE}/video/playbackProgress",
                           data=body, headers=headers)
            data = r.json()
            return data.get("success", False)
        except Exception as e:
            self.log(f"playbackProgress上报失败: {e}", "DBG")
            return False

    def _get_player_config(self) -> dict:
        """获取播放器全局配置 (secret, sessionId 等), 每次看课需要刷新"""
        try:
            ts = int(time.time() * 1000)
            r = self._get(
                f"{GATEWAY_BASE}/api/videoplayerprod/videoplayer/getPlayerGlobalConf",
                params={"videoBizCode": "1013", "sdkVersion": "3.0.37", "_": ts},
                headers={"token": self.token, "Origin": "https://teacher.ewt360.com"}
            )
            data = r.json()
            if data.get("code") == "200":
                info = data["data"]["globalInfo"]
                self._dlog(f"player config: secret={info['secret'][:16]}... sessionId={info['sessionId']}")
                return {"secret": info["secret"], "sessionId": info["sessionId"],
                        "ts": info["ts"], "intervalTime": info.get("intervalTime", 60)}
            return {}
        except Exception as e:
            self.log(f"获取播放器配置失败: {e}", "WARN")
            return {}

    def _make_monitor_sign(self, action: int, stay_time_ms: int,
                           report_time: int, secret: str) -> str:
        """HMAC-SHA1 签名 (破解自 mstplayer-v3.0.37.min.js makeSecretKey)"""
        import hmac as _hmac
        from hashlib import sha1 as _sha1
        params = {
            "action": str(action), "duration": str(stay_time_ms),
            "mstid": self.token, "signatureMethod": "HMAC-SHA1",
            "signatureVersion": "1.0", "timestamp": str(report_time),
            "version": "2022-08-02"
        }
        qs = "&".join(f"{k}={params[k]}" for k in sorted(params.keys()))
        return _hmac.new(secret.encode(), qs.encode(), _sha1).hexdigest()

    def report_monitor_batch(self, lesson_id: str, course_id: str,
                             action: int, stay_ms: int,
                             total_duration_ms: int,
                             secret: str, session_id: str) -> bool:
        """
        bfe monitor 批量上报
        stay_ms: 本批上报的播放时长 (固定值, 非累加)
        begin_time 内部基于 stay/speed 自动计算
        """
        try:
            now_ms = int(time.time() * 1000)
            report_time = now_ms
            uuid = f"{rand_uuid()}_a{action}"

            # begin_time = now - stay/speed - 随机偏移
            # 每批独立计算, 保证 report - begin ≈ stay / speed
            begin_time = now_ms - int(stay_ms / self.speed) - random.randint(1000, 3000)

            point_time_id = max(1, (stay_ms + 60000 - 1) // 60000)
            point_num = max(1, (total_duration_ms + 60000 - 1) // 60000)

            payload = {
                "CommonPackage": {
                    "userid": int(self.user_id),
                    "ip": rand_ip(),
                    "os": "Windows",
                    "resolution": "1920*1080",
                    "mstid": self.token,
                    "browser": "Chrome",
                    "browser_ver": "5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36",
                    "playerType": 1,
                    "sdkVersion": "3.0.37",
                    "videoBizCode": "1013",
                    "memberProvinceCode": "510000",
                    "schoolId": str(self.school_id),
                    "schoolProvinceCode": "510000"
                },
                "EventPackage": [{
                    "lesson_id": str(lesson_id),
                    "course_id": str(course_id),
                    "stay_time": stay_ms,
                    "media_time": stay_ms,
                    "status": 1 if action != 3 else 3,
                    "begin_time": begin_time,       # 固定不变！
                    "report_time": report_time,
                    "point_time_id": point_time_id,
                    "point_time": 60000,
                    "point_num": point_num,
                    "video_type": 1,
                    "speed": self.speed,
                    "quality": "高清",
                    "action": action,
                    "fallback": 0,
                    "uuid": uuid
                }],
                "sn": "ewt_web_video_detail",
                "_": now_ms
            }
            payload["signature"] = self._make_monitor_sign(
                action, stay_ms, report_time, secret)

            url = (f"{BFE_BASE}/monitor/web/collect/batch"
                   f"?TrVideoBizCode=1013"
                   f"&TrFallback=0"
                   f"&TrUserId={self.user_id}"
                   f"&TrLessonId={lesson_id}"
                   f"&TrUuId={uuid}"
                   f"&sdkVersion=3.0.37"
                   f"&_={now_ms}")

            r = self._post(url, json=payload, headers={
                "Content-Type": "application/json",
                "token": self.token,
                "x-bfe-session-id": session_id,
                "Origin": "https://teacher.ewt360.com",
                "Referer": "https://teacher.ewt360.com/",
            })
            data = r.json()
            success = data.get("success", False)
            if not success:
                self.log(f"monitor失败: [{data.get('code','')}] {data.get('msg','')[:60]}", "WARN")
            return success
        except Exception as e:
            self.log(f"monitor异常: {e}", "WARN")
            return False

    def submit_course_record(self, lesson_id: str, course_id: str,
                             process_time: int, finished: int = 0) -> bool:
        """
        提交课程学习记录
        POST /api/studyprod/course/lesson/record/submit
        """
        try:
            data = self._post_json(
                f"{GATEWAY_BASE}/api/studyprod/course/lesson/record/submit",
                {
                    "schoolId": int(self.school_id),
                    "recordList": [{
                        "courseId": str(course_id),
                        "lessonId": str(lesson_id),
                        "processTime": process_time,
                        "finished": finished
                    }]
                }
            )
            return data.get("success", False)
        except Exception as e:
            self.log(f"提交学习记录失败: {e}", "DBG")
            return False

    # ---- 刷课核心 ----

    def watch_course(self, course: dict, callback=None) -> bool:
        """模拟观看单个课程 (含正确的 HMAC-SHA1 签名)"""
        lesson_id = str(course.get("contentId", ""))
        duration_sec = int(course.get("duration", 0))
        title = course.get("title", "未知")
        homework_id = course.get("_homework_id", "")
        day_date = course.get("_day_date", "")
        subject = course.get("subjectName", "")

        self.log(f"\n{'='*55}")
        self.log(f"课程: {title}")
        self.log(f"  lessonId={lesson_id} | 时长={duration_sec}s | "
                 f"倍速={self.speed}x | 日期={day_date} | {subject}")

        if duration_sec == 0:
            self.log("  时长为0, 跳过", "WARN")
            return False

        # Step 1: 获取真实 courseId + 播放器配置 (secret/sessionId)
        lesson_detail = self.get_lesson_detail(lesson_id, homework_id)
        real_course_id = lesson_detail.get("courseId", "")
        if not real_course_id:
            self.log(f"  无法获取真实courseId, 回退", "WARN")
            real_course_id = str(course.get("parentContentId", ""))
        self._dlog(f"  real_courseId={real_course_id}")

        player_config = self._get_player_config()
        secret = player_config.get("secret", "")
        session_id = player_config.get("sessionId", "")
        if not secret:
            self.log(f"  无法获取播放器密钥, 无法上报进度!", "ERR")
            return False
        self._dlog(f"  secret={secret[:12]}... sessionId={session_id}")

        # 获取课程任务信息 (完成阈值)
        task_info = self.get_course_task_info(homework_id, lesson_id)
        finish_play_time = task_info.get("finishPlayTime", int(duration_sec * 1000 * 0.8))
        finish_percent = task_info.get("finishPercent", 0.8)
        lesson_time_ms = task_info.get("lessonTime", duration_sec * 1000)
        needed_play_ms = max(finish_play_time, int(lesson_time_ms * finish_percent))
        needed_play_sec = needed_play_ms / 1000
        existing_play = task_info.get("playTime", 0)  # 服务器端已有的播放时长
        self.log(f"  需播放: {needed_play_sec:.0f}s (阈值{finish_percent*100:.0f}%, "
                 f"已有{existing_play/1000:.0f}s)")

        # Step 2: 初始上报
        self.submit_course_record(lesson_id, real_course_id, 0, 0)
        self.report_monitor_batch(lesson_id, real_course_id, 1, 1000,
                                  needed_play_ms, secret, session_id)

        # Step 3: 分批独立上报
        # 每批发送固定 stay=12s (非累加), begin_time 自成一体验证
        # 服务端按 report-begin 独立校验, 自动累加 playTime
        chunk_ms = 12000
        batch_count = (needed_play_ms + chunk_ms - 1) // chunk_ms
        self._dlog(f"  策略: {batch_count}x{chunk_ms/1000}s batches, "
                   f"~{needed_play_ms/1000/self.speed:.0f}s real time")

        for batch in range(1, batch_count + 1):
            wait_s = chunk_ms / (self.speed * 1000)
            time.sleep(wait_s)

            ok = self.report_monitor_batch(lesson_id, real_course_id, 2, chunk_ms,
                                           needed_play_ms, secret, session_id)
            if not ok:
                self.log(f"  monitor上报中断 (batch {batch}/{batch_count})", "WARN")
                break

            # 每 5 批查一次服务器真实 playTime 用于显示
            if batch % 5 == 0 or batch == batch_count:
                try:
                    real_info = self.get_course_task_info(homework_id, lesson_id)
                    real_pt = real_info.get("playTime", 0)
                    progress_ms = max(0, real_pt - existing_play)
                    real_pct = min(100, progress_ms / needed_play_ms * 100)
                    print(f"\r  进度: {real_pct:.0f}% (playTime+{progress_ms/1000:.0f}s/{needed_play_sec:.0f}s)",
                          end="", flush=True)
                except:
                    pass

        print()  # 换行, 覆盖进度百分比

        # Step 4: 播放结束 — 以服务器真实 playTime 为准
        try:
            final_info = self.get_course_task_info(homework_id, lesson_id)
            real_pt = final_info.get("playTime", 0)
            progress_ms = real_pt - existing_play
            if progress_ms >= needed_play_ms * 0.9:
                self.log(f"  服务器确认: playTime {existing_play}→{real_pt} (+{progress_ms}ms)", "OK")
                time.sleep(random.uniform(0.5, 1.5))
                self.report_monitor_batch(lesson_id, real_course_id, 3, chunk_ms,
                                          needed_play_ms, secret, session_id)
                record_ok = self.submit_course_record(lesson_id, real_course_id,
                                                      int(needed_play_ms), 1)
                if record_ok:
                    self.log(f"  完成 ✓", "OK")
                else:
                    self.log(f"  提交记录失败", "WARN")
            else:
                self.log(f"  未达到阈值: 实际+{progress_ms/1000:.0f}s/需{needed_play_sec:.0f}s", "WARN")
                record_ok = False
        except Exception as e:
            self.log(f"  检查进度失败: {e}, 按批次完成判断", "WARN")
            if batch_count >= 9:
                time.sleep(random.uniform(0.5, 1.5))
                self.report_monitor_batch(lesson_id, real_course_id, 3, chunk_ms,
                                          needed_play_ms, secret, session_id)
                record_ok = self.submit_course_record(lesson_id, real_course_id,
                                                      int(needed_play_ms), 1)
            else:
                record_ok = False

        if callback:
            callback(course, record_ok)
        return record_ok

    def watch_selected_courses(self, courses: list) -> dict:
        """刷已选择的课程"""
        stats = {"total": len(courses), "success": 0, "failed": 0}
        for i, course in enumerate(courses, 1):
            self.log(f"\n[{i}/{len(courses)}]")
            try:
                ok = self.watch_course(course)
                if ok:
                    stats["success"] += 1
                else:
                    stats["failed"] += 1
            except KeyboardInterrupt:
                self.log("\n用户中断", "WARN")
                break
            except Exception as e:
                self.log(f"异常: {e}", "ERR")
                stats["failed"] += 1
            # 课间延迟
            if i < len(courses):
                d = random.uniform(2, 5)
                time.sleep(d)
        return stats


# ============================================================
# 交互式界面
# ============================================================

def interactive_select(client: EWT360Client):
    """交互式选择课程并刷课"""
    # Step 1: 获取场景
    scenes = client.get_scenes()
    if not scenes:
        print("未找到任何课程场景")
        return

    print("\n可用的课程场景:")
    for i, s in enumerate(scenes, 1):
        print(f"  {i}. [{s['id']}] {s['title']}")

    choice = input("\n选择场景序号 (直接回车=全部): ").strip()
    selected_scenes = []
    if choice == "":
        selected_scenes = scenes
    else:
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(scenes):
                selected_scenes = [scenes[idx]]
        except ValueError:
            pass

    if not selected_scenes:
        print("未选择有效场景")
        return

    # Step 2: 自动发现所有作业
    print("\n正在发现作业列表...")
    all_homeworks = client.discover_homeworks()
    if not all_homeworks:
        print("未找到任何作业, 尝试手动输入...")
        hw_id = input("请输入作业ID (homeworkId): ").strip()
        if not hw_id:
            return
        all_homeworks = [{"homeworkId": hw_id, "title": "手动输入", "sceneId": "", "status": 2, "sceneTypeName": ""}]

    STATUS_MAP = {1: "未开始", 2: "进行中", 3: "已截止", 4: "已撤回"}
    print(f"\n找到 {len(all_homeworks)} 个作业:\n")
    print(f"{'#':<4} {'状态':<8} {'场景':<12} {'作业名称'}")
    print("-" * 80)
    for i, hw in enumerate(all_homeworks, 1):
        st = STATUS_MAP.get(hw.get("status", 0), "?")
        sid = hw.get("sceneId", "")
        title = hw.get("title", "")[:50]
        cnt = hw.get("studentHomeworkStaticsInfo", {})
        info = f"(going={cnt.get('onGoing',0)}, closed={cnt.get('closed',0)})"
        print(f"{i:<4} {st:<8} [{sid}] {title} {info}")

    if len(all_homeworks) == 1:
        hw_choice = "1"
    else:
        hw_choice = input("\n选择作业序号 (多选用逗号分隔, 直接回车=全部): ").strip()

    if hw_choice == "":
        selected_hws = all_homeworks
    else:
        indices = set()
        for part in hw_choice.split(","):
            part = part.strip()
            if "-" in part:
                a, b = part.split("-", 1)
                indices.update(range(int(a.strip()), int(b.strip()) + 1))
            else:
                indices.add(int(part))
        selected_hws = [all_homeworks[i - 1] for i in sorted(indices)
                        if 1 <= i <= len(all_homeworks)]

    # Step 3: 获取所选作业的所有课程
    all_courses = []
    for hw in selected_hws:
        hw_id = hw.get("homeworkId", "")
        hw_title = hw.get("title", "")
        print(f"\n获取作业 [{hw_id}] {hw_title} ...")
        courses = client.get_all_courses_simple(hw_id)
        for c in courses:
            c["_hw_title"] = hw_title
        all_courses.extend(courses)

    if not all_courses:
        print("\n未找到任何未完成课程!")
        return

    # Step 3: 显示课程列表让用户选择
    print(f"\n找到 {len(all_courses)} 个未完成课程:\n")
    print(f"{'#':<4} {'日期':<8} {'科目':<10} {'时长':<8} {'课程'}")
    print("-" * 65)
    for i, c in enumerate(all_courses, 1):
        day = c.get("_day_date", "")
        subj = c.get("subjectName", "")
        dur = f"{c.get('duration',0)}s"
        title = c.get("title", "")[:35]
        print(f"{i:<4} {day:<8} {subj:<10} {dur:<8} {title}")

    total_dur = sum(int(c.get("duration", 0)) for c in all_courses)
    print(f"\n总时长: {total_dur}s ({total_dur // 60}分{total_dur % 60}秒)")

    # 选择模式
    print("\n选择模式:")
    print("  1. 全部刷完")
    print("  2. 按序号选择 (如: 1,3,5-8)")
    print("  3. 按科目筛选")
    print("  0. 退出")

    mode = input("\n请选择: ").strip()

    if mode == "0":
        return
    elif mode == "1":
        selected = all_courses
    elif mode == "2":
        sel = input("输入序号 (逗号或短横线分隔): ").strip()
        indices = set()
        for part in sel.split(","):
            part = part.strip()
            if "-" in part:
                a, b = part.split("-", 1)
                for j in range(int(a.strip()), int(b.strip()) + 1):
                    indices.add(j)
            else:
                indices.add(int(part))
        selected = [all_courses[i - 1] for i in sorted(indices)
                    if 1 <= i <= len(all_courses)]
    elif mode == "3":
        print("\n科目列表:")
        subjects_seen = {}
        for c in all_courses:
            sid = c.get("subjectId", 0)
            sname = c.get("subjectName", "")
            if sid not in subjects_seen:
                subjects_seen[sid] = sname
        for sid, sname in sorted(subjects_seen.items()):
            print(f"  {sid}. {sname}")
        sel = input("\n输入科目ID (逗号分隔): ").strip()
        selected = [c for c in all_courses
                    if str(c.get("subjectId")) in sel.split(",")]
    else:
        return

    if not selected:
        print("未选择任何课程")
        return

    print(f"\n确认: 即将刷 {len(selected)} 个课程")
    confirm = input("确认开始? (y/n): ").strip().lower()
    if confirm != "y":
        print("已取消")
        return

    # Step 4: 开始刷课
    stats = client.watch_selected_courses(selected)
    print(f"\n{'='*55}")
    print(f"完成! 总计={stats['total']} 成功={stats['success']} 失败={stats['failed']}")


# ============================================================
# 快速模式 (非交互)
# ============================================================

def quick_watch(client: EWT360Client, homework_id: str):
    """快速模式: 指定作业ID刷完所有未完成课程"""
    courses = client.get_all_courses_simple(homework_id)
    if not courses:
        print("无未完成课程")
        return

    print(f"\n找到 {len(courses)} 个未完成课程:")
    total_dur = 0
    for i, c in enumerate(courses, 1):
        day = c.get("_day_date", "")
        dur = int(c.get("duration", 0))
        total_dur += dur
        print(f"  {i}. [{day}] {c.get('subjectName','')} {c.get('title','')[:30]} ({dur}s)")

    print(f"\n总时长: {total_dur}s ({total_dur // 60}分)")
    confirm = input("\n开始刷课? (y/n): ").strip().lower()
    if confirm != "y":
        return

    stats = client.watch_selected_courses(courses)
    print(f"\n完成! 总计={stats['total']} 成功={stats['success']} 失败={stats['failed']}")


# ============================================================
# 主入口
# ============================================================

def main():
    print("""
    ╔═══════════════════════════════════════╗
    ║   EWT360 自动化学习脚本 v2.0          ║
    ║   基于 2026-07-18 Fiddler 抓包分析    ║
    ╚═══════════════════════════════════════╝
    """)

    # 加载配置
    config = {}
    if os.path.exists("config.json"):
        with open("config.json", "r", encoding="utf-8") as f:
            config = json.load(f)

    account = config.get("account", "")
    password = config.get("password", "")
    token = config.get("token", "")
    speed = float(config.get("speed", 2.0))
    subject_filter = config.get("subject_filter", [])
    debug_mode = "--debug" in sys.argv

    # 命令行参数
    args = sys.argv[1:]
    if "--account" in args:
        idx = args.index("--account")
        account = args[idx + 1] if idx + 1 < len(args) else account
    if "--speed" in args:
        idx = args.index("--speed")
        speed = float(args[idx + 1]) if idx + 1 < len(args) else speed
    if "--token" in args:
        idx = args.index("--token")
        token = args[idx + 1] if idx + 1 < len(args) else token

    client = EWT360Client(account=account, password=password,
                          token=token, speed=speed,
                          subject_filter=subject_filter,
                          debug=debug_mode)

    # 登录
    if client.token:
        if not client.verify_token():
            print("Token已过期, 重新登录...")
            if not client.login():
                sys.exit(1)
        else:
            print("Token有效, 跳过登录")
    # 确保用户信息已获取 (schoolId, userName 等)
    if not client.school_id:
        client._fetch_user_info()
    else:
        if not client.login():
            sys.exit(1)

    # 保存token
    config["token"] = client.token
    with open("config.json", "w", encoding="utf-8") as f:
        json.dump(config, f, ensure_ascii=False, indent=2)

    # 命令路由
    command = args[0] if args else "menu"

    if command == "quick" or command == "watch":
        # 快速模式: 需要 homeworkId
        hw_id = None
        if "--hw" in args:
            idx = args.index("--hw")
            hw_id = args[idx + 1] if idx + 1 < len(args) else None
        if not hw_id:
            hw_id = input("请输入作业ID (homeworkId): ").strip()
        if hw_id:
            quick_watch(client, hw_id)

    elif command == "list":
        # 列出所有科目统计
        hw_id = None
        if "--hw" in args:
            idx = args.index("--hw")
            hw_id = args[idx + 1] if idx + 1 < len(args) else None
        if not hw_id:
            hw_id = input("请输入作业ID (homeworkId): ").strip()
        if hw_id:
            stat = client.get_day_subject_stat(hw_id)
            hw_info = client.get_homework_info(hw_id)
            print(f"\n作业: {hw_info.get('homeworkTitle','')}")
            print(f"总任务: {stat.get('homeworkStat',{}).get('count',0)} | "
                  f"已完成: {stat.get('homeworkStat',{}).get('finishCount',0)}")
            print(f"\n科目统计:")
            for s in stat.get("subjectStat", []):
                pct = f"{s['finishCount']}/{s['taskCount']}"
                print(f"  {s['subjectName']:<10} {pct:<10}"
                      f"({'必学' if s.get('mustLearn') else '选学'})")
            print(f"\n日期统计:")
            for d in stat.get("dateStat", []):
                remaining = d.get("taskCount", 0) - d.get("finishCount", 0)
                if remaining > 0:
                    date_str = ts_to_date(d.get("date", 0))
                    print(f"  {date_str}  {d['finishCount']}/{d['taskCount']} "
                          f"剩余{remaining}个")

    elif command == "menu" or command == "interactive":
        interactive_select(client)

    elif command == "help":
        print("用法:")
        print("  python ewt360_v2.py menu      交互式选择 (默认)")
        print("  python ewt360_v2.py watch     快速模式 (需要--hw)")
        print("  python ewt360_v2.py list      课程统计 (需要--hw)")
        print("  python ewt360_v2.py help      帮助")
        print("\n参数:")
        print("  --hw ID       作业ID")
        print("  --speed 2.0   播放倍速 (默认2.0)")
        print("  --debug       打印API请求/响应详情")
        print("  --token XXX   直接使用token")
        print("  --account XXX 账号")
    else:
        print(f"未知命令: {command}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n已中断")
    except Exception as e:
        print(f"\n错误: {e}")
        traceback.print_exc()
