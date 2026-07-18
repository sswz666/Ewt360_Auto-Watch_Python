#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
⚠️ 已废弃 (DEPRECATED)
=======================
本文件是早期原型版本 (v1), 依赖的 dlog.ewt360.com 上报接口已被官方下线,
进度上报不会生效。请改用同目录下的 ewt360_v2.py (已逆向 bfe.ewt360.com
monitor/collect/batch 心跳接口, 进度上报真实有效)。

EWT360 (升学e网通) 自动化学习脚本
===================================
功能:
  1. 账号密码自动登录 (支持Token复用)
  2. 获取课程列表、章节结构及完成进度
  3. 模拟课程观看行为,自动上报学习进度
  4. 异常处理、重试机制、速率控制
  5. 完整的操作日志输出

API逆向分析结果:
  - 签名算法: Sign = MD5(Timestamp + "bdc739ff2dcf")
  - 密码加密: AES-256-CBC (Key: 20171109124536982017110912453698, IV: 2017110912453698)
  - 进度上报签名: MD5("log=" + payload_json + "&key=eo^nye1j#!wt2%v)")

依赖安装:
  pip install requests pycryptodome

配置文件 config.json 示例:
  {
    "account": "your_account",
    "password": "your_password",
    "speed": 1.5,
    "subject_filter": [],
    "max_advance_days": 3,
    "retry_times": 3,
    "retry_delay": 5,
    "min_interval": 1.0
  }
"""

import hashlib
import json
import logging
import math
import os
import random
import string
import sys
import time
import traceback
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any, Tuple

import requests
from Crypto.Cipher import AES

# ============================================================
# 常量定义
# ============================================================

# API 基础 URL
GATEWAY_BASE = "https://gateway.ewt360.com"
WEB_BASE = "https://web.ewt360.com"
DLOG_BASE = "https://dlog.ewt360.com"

# 签名密钥
SIGN_SECRET = "bdc739ff2dcf"
DLOG_SIGN_KEY = "eo^nye1j#!wt2%v)"

# AES 加密参数
AES_KEY = b"20171109124536982017110912453698"  # 32 bytes
AES_IV = b"2017110912453698"  # 16 bytes

# 默认配置
DEFAULT_CONFIG = {
    "account": "",
    "password": "",
    "token": "",  # 可选: 直接使用已有token跳过登录
    "speed": 1.5,  # 播放倍速
    "subject_filter": [],  # 要跳过的科目ID列表, 空列表=全部科目
    "max_advance_days": 3,  # 最大提前天数 (用于假期课程)
    "target_course_ids": [],  # 目标课程ID列表, 空=全部未完成课程
    "retry_times": 3,  # 失败重试次数
    "retry_delay": 5,  # 重试等待秒数
    "min_interval": 1.0,  # API请求最小间隔(秒), 防风控
    "log_level": "INFO",  # 日志级别
    "log_file": "ewt360_auto.log",  # 日志文件
}

# 科目ID映射
SUBJECT_MAP = {
    1: "语文", 2: "数学", 3: "英语", 4: "物理",
    5: "化学", 6: "生物", 7: "政治", 8: "历史",
    9: "地理", 10: "信息技术", 11: "通用技术",
    14: "心理", 15: "生涯规划"
}


# ============================================================
# 日志配置
# ============================================================

def setup_logging(level: str = "INFO", log_file: str = "ewt360_auto.log") -> logging.Logger:
    """配置日志系统"""
    logger = logging.getLogger("ewt360")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # 控制台输出
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.INFO)
    console_fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S"
    )
    console.setFormatter(console_fmt)
    logger.addHandler(console)

    # 文件输出
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    file_handler.setFormatter(file_fmt)
    logger.addHandler(file_handler)

    return logger


# ============================================================
# 加密工具
# ============================================================

class CryptoUtils:
    """加密工具类"""

    @staticmethod
    def aes_encrypt(text: str) -> str:
        """AES-256-CBC 加密, 返回大写十六进制字符串"""
        text_bytes = text.encode("utf-8")
        cryptor = AES.new(AES_KEY, AES.MODE_CBC, iv=AES_IV)
        # PKCS7 padding
        pad_len = 16 - len(text_bytes) % 16
        text_bytes += bytes([pad_len] * pad_len)
        ciphertext = cryptor.encrypt(text_bytes)
        return ciphertext.hex().upper()

    @staticmethod
    def sign_md5(data: str) -> str:
        """MD5签名, 返回大写十六进制"""
        return hashlib.md5(data.encode("utf-8")).hexdigest().upper()

    @staticmethod
    def generate_sign(timestamp: int) -> str:
        """生成API请求签名"""
        return CryptoUtils.sign_md5(f"{timestamp}{SIGN_SECRET}")

    @staticmethod
    def generate_dlog_sign(payload: dict) -> str:
        """生成进度上报签名"""
        payload_str = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
        return CryptoUtils.sign_md5(f"log={payload_str}&key={DLOG_SIGN_KEY}")

    @staticmethod
    def generate_uuid(index: int) -> str:
        """生成进度上报UUID"""
        rand_str = "".join(random.sample(string.ascii_letters + string.digits, 8))
        return f"{rand_str}_{index}"


# ============================================================
# HTTP 客户端
# ============================================================

class EWT360Client:
    """EWT360 API 客户端"""

    def __init__(self, config: dict, logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.token: str = config.get("token", "")
        self.user_id: str = ""
        self.school_id: str = ""
        self.user_info: dict = {}
        self.last_request_time: float = 0
        self.session = requests.Session()

        # 设置基础请求头
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/120.0.0.0 Safari/537.36",
            "Accept-Language": "zh-CN,zh;q=0.9",
        })

    # ---- 请求控制 ----

    def _rate_limit(self):
        """速率控制, 确保请求间隔不小于 min_interval"""
        elapsed = time.time() - self.last_request_time
        min_interval = self.config.get("min_interval", 1.0)
        if elapsed < min_interval:
            time.sleep(min_interval - elapsed + random.uniform(0, 0.5))
        self.last_request_time = time.time()

    def _request(self, method: str, url: str, **kwargs) -> requests.Response:
        """通用请求方法, 包含重试和速率控制"""
        retry_times = self.config.get("retry_times", 3)
        retry_delay = self.config.get("retry_delay", 5)

        for attempt in range(retry_times):
            try:
                self._rate_limit()
                resp = self.session.request(method, url, timeout=30, **kwargs)
                return resp
            except requests.exceptions.Timeout:
                self.logger.warning(f"请求超时 (尝试 {attempt + 1}/{retry_times}): {url}")
                if attempt < retry_times - 1:
                    time.sleep(retry_delay * (attempt + 1))
            except requests.exceptions.ConnectionError as e:
                self.logger.warning(f"连接错误 (尝试 {attempt + 1}/{retry_times}): {e}")
                if attempt < retry_times - 1:
                    time.sleep(retry_delay * (attempt + 1))
            except Exception as e:
                self.logger.error(f"请求异常: {e}")
                raise

        raise ConnectionError(f"请求失败, 已重试 {retry_times} 次: {url}")

    def _get_server_timestamp(self) -> int:
        """获取服务器时间戳"""
        t = int(time.time() * 1000)
        resp = self._request("GET",
                             f"{GATEWAY_BASE}/api/commondata/server/gettime",
                             params={"t": t},
                             headers={"Referurl": "https://www.ewt360.com/"})
        data = resp.json()
        if data.get("success"):
            return data["data"]["timestamp"]
        return t

    def _make_signed_headers(self, extra: dict = None) -> dict:
        """生成带签名的请求头"""
        ts = self._get_server_timestamp()
        sign = CryptoUtils.generate_sign(ts)
        headers = {
            "Content-Type": "application/json",
            "Referurl": "https://www.ewt360.com/",
            "Token": self.token,
            "Platform": "1",
            "Timestamp": str(ts),
            "Sign": sign,
            "Secretid": "2",
            "Origin": "https://www.ewt360.com",
        }
        if extra:
            headers.update(extra)
        return headers

    # ---- 登录模块 ----

    def login(self, account: str = None, password: str = None) -> bool:
        """
        登录获取Token
        如果已有token, 先验证是否有效
        """
        account = account or self.config.get("account", "")
        password = password or self.config.get("password", "")

        # 如果已有token, 先尝试验证
        if self.token:
            self.logger.info("检测到已有Token, 验证有效性...")
            if self._verify_token():
                self.logger.info("Token有效, 跳过登录")
                return True
            self.logger.info("Token已过期, 重新登录")

        if not account or not password:
            self.logger.error("未提供账号或密码")
            return False

        self.logger.info(f"正在登录: {account}")
        self.token = "0"  # 登录时使用空token

        encrypted_pwd = CryptoUtils.aes_encrypt(password)
        headers = self._make_signed_headers()
        body = {
            "platform": 1,
            "userName": account,
            "password": encrypted_pwd,
            "autoLogin": False,
            "webVersion": "pc_20250101"
        }

        try:
            resp = self._request("POST",
                                 f"{GATEWAY_BASE}/api/authcenter/v2/oauth/login/account",
                                 json=body, headers=headers)
            data = resp.json()

            if data.get("success") and data["code"] == "200":
                self.token = data["data"]["token"]
                self.user_id = data["data"]["userId"]
                self.logger.info(f"登录成功! userId={self.user_id}")
                self.logger.info(f"Token={self.token[:20]}...")

                # 获取用户详细信息
                self._get_user_info()
                return True
            else:
                msg = data.get("msg", "未知错误")
                code = data.get("code", "")
                self.logger.error(f"登录失败: [{code}] {msg}")
                return False

        except Exception as e:
            self.logger.error(f"登录异常: {e}")
            return False

    def _verify_token(self) -> bool:
        """验证Token是否有效"""
        try:
            headers = self._make_signed_headers()
            resp = self._request("GET",
                                 f"{GATEWAY_BASE}/api/usercenter/user/login/getUser",
                                 params={"platform": "1"}, headers=headers)
            data = resp.json()
            return data.get("success") and data["data"].get("isLogin")
        except Exception:
            return False

    def _get_user_info(self) -> dict:
        """获取用户详细信息"""
        try:
            headers = self._make_signed_headers()
            resp = self._request("GET",
                                 f"{GATEWAY_BASE}/api/usercenter/user/baseinfo",
                                 headers=headers,
                                 params={"_": int(time.time() * 1000)})
            data = resp.json()
            if data.get("success"):
                self.user_info = data["data"]
                self.user_id = data["data"].get("userId", self.user_id)
                self.school_id = data["data"].get("schoolId", "")
                self.logger.info(
                    f"用户信息: {data['data'].get('realName', 'N/A')} | "
                    f"学校: {data['data'].get('schoolName', 'N/A')} | "
                    f"会员: {data['data'].get('memberTypeName', 'N/A')}"
                )
            return self.user_info
        except Exception as e:
            self.logger.warning(f"获取用户信息失败: {e}")
            return {}

    # ---- 课程列表模块 ----

    def get_scenes(self) -> List[dict]:
        """获取假期课程场景列表"""
        try:
            headers = self._make_signed_headers()
            ts = int(time.time() * 1000)
            resp = self._request("GET",
                                 f"{GATEWAY_BASE}/api/holidayprod/scene/student/study/checkHoliday",
                                 params={
                                     "clientType": "1",
                                     "preview": "0",
                                     "schoolId": self.school_id,
                                     "timestamp": ts
                                 },
                                 headers=headers)
            data = resp.json()
            if data.get("success"):
                scenes = data["data"]["sceneList"]
                self.logger.info(f"获取到 {len(scenes)} 个课程场景")
                for s in scenes:
                    self.logger.info(f"  - [{s['id']}] {s['title']}")
                return scenes
            return []
        except Exception as e:
            self.logger.error(f"获取课程场景失败: {e}")
            return []

    def get_homework_ids(self, scene_id: str) -> List[str]:
        """获取指定场景的作业ID列表"""
        try:
            headers = self._make_signed_headers()
            ts = int(time.time() * 1000)
            resp = self._request("GET",
                                 f"{GATEWAY_BASE}/api/homeworkprod/homework/student/holiday/getHomeworkSummaryInfo",
                                 params={
                                     "schoolId": self.school_id,
                                     "timestamp": ts,
                                     "sceneId": scene_id
                                 },
                                 headers=headers)
            data = resp.json()
            if data.get("success"):
                hw_ids = data["data"]["homeworkIds"]
                self.logger.info(f"场景 {scene_id}: {len(hw_ids)} 个作业")
                return hw_ids
            return []
        except Exception as e:
            self.logger.error(f"获取作业ID失败: {e}")
            return []

    def get_day_list(self, homework_id: str, scene_id: str) -> List[dict]:
        """获取作业的天数分布"""
        try:
            headers = self._make_signed_headers()
            body = {
                "homeworkIds": [homework_id],
                "isSelfTask": "false",
                "userOptionTaskId": "null",
                "schoolId": self.school_id,
                "sceneId": str(scene_id)
            }
            resp = self._request("POST",
                                 f"{GATEWAY_BASE}/api/homeworkprod/homework/student/holiday/getHomeworkDistribution",
                                 params={"sceneId": scene_id},
                                 json=body, headers=headers)
            data = resp.json()
            if data.get("success"):
                return data["data"]["days"]
            return []
        except Exception as e:
            self.logger.error(f"获取天数分布失败: {e}")
            return []

    def get_course_list(self, homework_id: str, day_data: dict,
                        scene_id: str) -> List[dict]:
        """获取某一天的课程列表"""
        try:
            headers = self._make_signed_headers()
            body = {
                "dayId": [str(day_data["dayId"][0])],
                "day": int(day_data["day"]),
                "status": 0,
                "homeworkIds": [int(homework_id)],
                "isSelfTask": "false",
                "userOptionTaskId": "null",
                "pageIndex": 1,
                "pageSize": 30,
                "missionType": 0,
                "schoolId": self.school_id,
                "sceneId": str(scene_id)
            }
            resp = self._request("POST",
                                 f"{GATEWAY_BASE}/api/homeworkprod/homework/student/holiday/pageHomeworkTasks",
                                 params={"sceneId": scene_id},
                                 json=body, headers=headers)
            data = resp.json()
            if data.get("success"):
                return data["data"]["data"]
            return []
        except Exception as e:
            self.logger.error(f"获取课程列表失败: {e}")
            return []

    def get_all_courses(self, scene_id: str = None,
                        max_advance_days: int = None) -> List[dict]:
        """
        获取所有未完成课程
        返回课程列表, 每个课程包含:
          - contentId, parentContentId, title, duration
          - subjectId, subjectName, ratio (完成比例)
          - day, day_show (日期), sceneid, homeworkid
        """
        if max_advance_days is None:
            max_advance_days = self.config.get("max_advance_days", 3)

        all_courses = []
        scenes = [{"id": scene_id}] if scene_id else self.get_scenes()

        if not scenes:
            self.logger.warning("未找到任何课程场景")
            return []

        # 计算最大提前时间
        now = datetime.now()
        max_time = int((now + timedelta(days=max_advance_days))
                       .replace(hour=0, minute=0, second=0, microsecond=0)
                       .timestamp() * 1000)

        for scene in scenes:
            sid = scene["id"]
            hw_ids = self.get_homework_ids(sid)
            for hw_id in hw_ids:
                days = self.get_day_list(hw_id, sid)
                for day_data in days:
                    # 检查是否超过最大提前天数
                    if day_data.get("day", 0) > max_time:
                        self.logger.debug(f"跳过未来日期: {day_data.get('day_show', '')}")
                        continue

                    courses = self.get_course_list(hw_id, day_data, sid)
                    for course in courses:
                        if course.get("contentType") != 1:
                            continue  # 跳过非视频课程

                        ratio = round(course.get("ratio", 0), 7)
                        if ratio >= 1.0:
                            continue  # 跳过已完成课程

                        # 科目过滤
                        subject_id = int(course.get("subjectId", 0))
                        subject_filter = self.config.get("subject_filter", [])
                        if subject_filter and subject_id not in subject_filter:
                            continue

                        # 目标课程过滤
                        target_ids = self.config.get("target_course_ids", [])
                        if target_ids and str(course.get("contentId")) not in [str(x) for x in target_ids]:
                            continue

                        course["_homeworkid"] = hw_id
                        course["_sceneid"] = sid
                        course["_day"] = day_data.get("day")
                        course["_dayid"] = day_data.get("dayId", [0])[0]
                        course["_day_show"] = day_data.get("day_show", "")
                        all_courses.append(course)

        self.logger.info(f"共找到 {len(all_courses)} 个未完成课程")
        return all_courses

    # ---- 进度上报模块 ----

    def get_player_config(self) -> Tuple[str, str, int]:
        """获取视频播放器配置 (secret, sessionId, beginTs)"""
        try:
            ts = int(time.time() * 1000)
            resp = self._request("GET",
                                 f"{WEB_BASE}/api/videoplayerprod/videoplayer/getPlayerGlobalConf",
                                 params={
                                     "videoBizCode": "1001",
                                     "sdkVersion": "3.0.8",
                                     "_": ts
                                 },
                                 headers={"Token": self.token})
            data = resp.json()
            if data.get("code") == "200":
                info = data["data"]["globalInfo"]
                return info["secret"], info["sessionId"], info["ts"]
            return "", "", ts
        except Exception as e:
            self.logger.warning(f"获取播放器配置失败: {e}")
            return "", "", int(time.time() * 1000)

    def report_progress(self, lesson_id: str, course_id: str,
                        duration_ms: int, speed: float = 1.0) -> bool:
        """
        上报课程观看进度 (模拟完整观看)
        """
        try:
            self.logger.info(f"上报进度: lesson={lesson_id}, course={course_id}, "
                             f"时长={duration_ms / 1000:.0f}s")

            # 计算各阶段时间
            now_ms = int(time.time() * 1000)
            speed_factor = speed
            actual_duration = int(duration_ms / speed_factor)  # 实际需要的时间
            report_begin_time = now_ms - actual_duration - random.randint(10000, 30000)

            # 模拟视频观看: 分多次上报
            index = 1
            progress_ms = 0

            # 1. 开始播放 (action=1)
            self._upload_dlog(lesson_id, course_id, report_begin_time,
                              report_begin_time + random.randint(1000, 3000),
                              index, 1, 0, speed)
            index += 1

            # 2. 分段上报 (action=2)
            while progress_ms < actual_duration:
                chunk = min(60000, actual_duration - progress_ms)
                time.sleep(random.uniform(0.3, 1.0))
                self._upload_dlog(lesson_id, course_id, report_begin_time,
                                  report_begin_time + progress_ms,
                                  index, 2, chunk, speed)
                progress_ms += chunk
                index += 1

            # 3. 播放完成 (action=3)
            time.sleep(random.uniform(0.5, 1.5))
            self._upload_dlog(lesson_id, course_id, report_begin_time,
                              report_begin_time + actual_duration
                              + random.randint(1, 15),
                              index, 3, 0, speed)

            self.logger.info(f"进度上报完成: lesson={lesson_id}")
            return True

        except Exception as e:
            self.logger.error(f"上报进度失败: lesson={lesson_id}, error={e}")
            return False

    def _upload_dlog(self, lesson_id: str, course_id: str,
                     begin_time: int, report_time: int,
                     index: int, action: int, duration_ms: int,
                     speed: float):
        """上传单次播放日志到 dlog.ewt360.com"""
        uuid = CryptoUtils.generate_uuid(index)
        ts = int(time.time() * 1000)
        ip = f"{random.randint(59, 61)}.{random.randint(0, 230)}." \
             f"{random.randint(0, 230)}.{random.randint(0, 230)}"

        payload = {
            "CommonPackage": {
                "userid": int(self.user_id),
                "ip": ip,
                "os": "Windows",
                "resolution": "1920*1080",
                "mstid": self.token,
                "browser": "Chrome",
                "browser_ver": "5.0 (Windows NT 10.0; Win64; x64) "
                               "AppleWebKit/537.36",
                "playerType": 1,
                "sdkVersion": "3.0.8",
                "videoBizCode": "1013"
            },
            "EventPackage": [{
                "lesson_id": str(lesson_id),
                "course_id": str(course_id),
                "stay_time": duration_ms,
                "status": 1 if action != 3 else 3,
                "begin_time": str(begin_time),
                "report_time": report_time,
                "point_time_id": 1,
                "point_time": 60000,
                "point_num": 25,
                "video_type": 1,
                "speed": speed,
                "quality": "标清",
                "action": action,
                "fallback": 1,
                "uuid": uuid
            }]
        }

        signature = CryptoUtils.generate_dlog_sign(payload)
        payload_str = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)

        url = (f"{DLOG_BASE}/?sn=ewt_web_video_detail"
               f"&log={payload_str}"
               f"&sign={signature}"
               f"&ts={ts}"
               f"&TrVideoBizCode=1013"
               f"&TrFallback=1"
               f"&TrUserId={self.user_id}"
               f"&TrLessonId={lesson_id}"
               f"&TrUuId={uuid}"
               f"&sdkVersion=3.0.8"
               f"&_={ts}")

        headers = {
            "Content-Type": "application/json",
            "Origin": "https://web.ewt360.com",
            "Referer": "https://web.ewt360.com/",
        }

        self._request("POST", url, data=payload_str, headers=headers)
        self.logger.debug(f"dlog上报: action={action}, duration={duration_ms}ms, "
                          f"index={index}")

    # ---- 批量刷课 ----

    def watch_course(self, course: dict,
                     speed: float = None,
                     callback=None) -> bool:
        """
        模拟观看单个课程
        """
        if speed is None:
            speed = self.config.get("speed", 1.5)

        lesson_id = str(course.get("contentId", ""))
        course_id = str(course.get("parentContentId", ""))
        duration = int(course.get("duration", 0))  # 秒
        title = course.get("title", "未知")

        self.logger.info(f"\n{'='*50}")
        self.logger.info(f"开始学习: {title}")
        self.logger.info(f"  lessonId={lesson_id}, courseId={course_id}")
        self.logger.info(f"  时长={duration}s, 倍速={speed}x, "
                         f"预计耗时={duration / speed:.0f}s")
        self.logger.info(f"  日期: {course.get('_day_show', 'N/A')} | "
                         f"科目: {course.get('subjectName', 'N/A')}")

        if duration <= 0:
            self.logger.warning(f"课程时长为0, 跳过: {title}")
            return False

        duration_ms = duration * 1000
        success = self.report_progress(lesson_id, course_id, duration_ms, speed)

        if success:
            self.logger.info(f"✓ 完成: {title}")
        else:
            self.logger.error(f"✗ 失败: {title}")

        if callback:
            callback(course, success)

        return success

    def watch_all_courses(self, scene_id: str = None,
                          speed: float = None,
                          callback=None) -> dict:
        """
        自动刷完所有未完成课程
        返回统计: {"total": int, "success": int, "failed": int, "skipped": int}
        """
        courses = self.get_all_courses(scene_id)
        stats = {"total": len(courses), "success": 0, "failed": 0, "skipped": 0}

        if not courses:
            self.logger.info("没有需要学习的课程")
            return stats

        for i, course in enumerate(courses, 1):
            self.logger.info(f"\n[{i}/{len(courses)}] 处理课程...")
            try:
                if self.watch_course(course, speed, callback):
                    stats["success"] += 1
                else:
                    stats["failed"] += 1
            except Exception as e:
                self.logger.error(f"课程处理异常: {e}")
                stats["failed"] += 1

            # 课程间随机延迟
            if i < len(courses):
                delay = random.uniform(2.0, 5.0)
                self.logger.debug(f"等待 {delay:.1f}s 后继续...")
                time.sleep(delay)

        return stats

    def list_courses(self, scene_id: str = None) -> None:
        """列出所有课程信息"""
        courses = self.get_all_courses(scene_id)
        if not courses:
            self.logger.info("未找到课程")
            return

        self.logger.info(f"\n{'='*80}")
        self.logger.info(f"{'序号':<4} {'日期':<12} {'科目':<8} {'进度':<8} {'课程名称'}")
        self.logger.info(f"{'-'*80}")

        for i, c in enumerate(courses, 1):
            day = c.get("_day_show", "")
            subject = c.get("subjectName", "")
            title = c.get("title", "")
            ratio = f"{c.get('ratio', 0) * 100:.0f}%"
            duration = c.get("duration", 0)
            self.logger.info(
                f"{i:<4} {day:<12} {subject:<8} {ratio:<8} "
                f"{title[:40]} ({duration}s)"
            )

        total_duration = sum(int(c.get("duration", 0)) for c in courses)
        self.logger.info(f"\n共 {len(courses)} 个未完成课程, 总时长 {total_duration}s "
                         f"({total_duration / 60:.0f}分)")


# ============================================================
# 配置管理
# ============================================================

class ConfigManager:
    """配置管理类"""

    DEFAULT_CONFIG_PATH = "config.json"

    @staticmethod
    def load(config_path: str = None) -> dict:
        """加载配置"""
        path = config_path or ConfigManager.DEFAULT_CONFIG_PATH
        config = DEFAULT_CONFIG.copy()

        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    user_config = json.load(f)
                config.update(user_config)
            except json.JSONDecodeError as e:
                print(f"配置文件解析错误: {e}, 使用默认配置")
            except Exception as e:
                print(f"读取配置文件失败: {e}, 使用默认配置")
        else:
            # 创建默认配置文件
            ConfigManager.save(config, path)
            print(f"已创建默认配置文件: {path}")

        return config

    @staticmethod
    def save(config: dict, config_path: str = None):
        """保存配置"""
        path = config_path or ConfigManager.DEFAULT_CONFIG_PATH
        with open(path, "w", encoding="utf-8") as f:
            json.dump(config, f, ensure_ascii=False, indent=2)


# ============================================================
# 主程序
# ============================================================

def print_banner():
    """打印程序横幅"""
    banner = r"""
    ╔══════════════════════════════════════════════════╗
    ║        EWT360 升学e网通 自动化学习脚本              ║
    ║        Version 1.0                               ║
    ╚══════════════════════════════════════════════════╝
    """
    print(banner)


def print_usage():
    """打印使用说明"""
    print("""
使用方法:
  python ewt360_auto.py [命令] [参数]

命令:
  login               仅登录并保存Token
  list                列出所有未完成课程
  watch               自动刷完所有未完成课程
  watch --scene ID    刷指定场景的课程
  watch --speed 2.0   以2倍速刷课
  watch --id COURSE_ID  只刷指定课程

配置文件 (config.json):
  account:           登录账号
  password:          登录密码
  speed:             播放倍速 (默认 1.5)
  subject_filter:    要跳过的科目ID列表 (如 [1,2,3,4,5,6,7,8,9])
  max_advance_days:  最大提前天数 (默认 3)
  target_course_ids: 目标课程ID列表 (空=全部)
  retry_times:       重试次数 (默认 3)
  min_interval:      API请求间隔/秒 (默认 1.0)

科目ID对照:
  1=语文 2=数学 3=英语 4=物理 5=化学 6=生物
  7=政治 8=历史 9=地理 10=信息技术 11=通用技术
  14=心理 15=生涯规划
""")


def main():
    """主函数"""
    print_banner()

    # 加载配置
    config = ConfigManager.load()
    logger = setup_logging(config.get("log_level", "INFO"),
                           config.get("log_file", "ewt360_auto.log"))

    # 解析命令行参数
    args = sys.argv[1:]
    command = args[0] if args else "help"

    # 解析额外参数
    extra = {}
    i = 1
    while i < len(args):
        if args[i] == "--scene" and i + 1 < len(args):
            extra["scene_id"] = args[i + 1]
            i += 2
        elif args[i] == "--speed" and i + 1 < len(args):
            extra["speed"] = float(args[i + 1])
            i += 2
        elif args[i] == "--id" and i + 1 < len(args):
            extra["target_course_ids"] = [args[i + 1]]
            i += 2
        elif args[i].startswith("--"):
            i += 1
        else:
            i += 1

    # 创建客户端
    client = EWT360Client(config, logger)

    try:
        if command == "help" or command == "--help" or command == "-h":
            print_usage()
            return

        elif command == "login":
            if not client.login():
                logger.error("登录失败")
                sys.exit(1)
            # 保存token到配置
            config["token"] = client.token
            ConfigManager.save(config)
            logger.info("Token已保存到配置文件")

        elif command == "list":
            if not client.login():
                sys.exit(1)
            scene_id = extra.get("scene_id")
            client.list_courses(scene_id)

        elif command == "watch":
            if not client.login():
                sys.exit(1)

            speed = extra.get("speed", config.get("speed", 1.5))
            scene_id = extra.get("scene_id")
            target_ids = extra.get("target_course_ids", [])
            if target_ids:
                config["target_course_ids"] = target_ids

            logger.info(f"开始刷课: speed={speed}x")
            stats = client.watch_all_courses(scene_id, speed)

            logger.info(f"\n{'='*50}")
            logger.info(f"刷课完成! 统计: "
                        f"总计={stats['total']}, "
                        f"成功={stats['success']}, "
                        f"失败={stats['failed']}")

        else:
            logger.error(f"未知命令: {command}")
            print_usage()
            sys.exit(1)

    except KeyboardInterrupt:
        logger.info("\n用户中断操作")
        # 保存当前token
        if client.token and client.token != "0":
            config["token"] = client.token
            ConfigManager.save(config)
            logger.info("Token已保存")
        sys.exit(0)

    except Exception as e:
        logger.error(f"程序异常: {e}")
        logger.debug(traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    main()
