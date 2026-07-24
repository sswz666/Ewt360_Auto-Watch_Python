# EWT360 自动化学习脚本（升学 e 网通）

基于流量抓包（Burp Suite / Fiddler）逆向分析 **升学 e 网通（ewt360.com）** 客户端 API 后编写的 Python 自动化脚本，可自动登录、发现作业与课程、模拟观看并真实上报学习进度。

> ⚠️ **免责声明**
> 本项目仅供学习 **HTTP / 签名算法逆向分析** 与 **Python 自动化** 技术使用。
> 请遵守所在学校 / 平台的使用条款，勿用于违规刷课、代刷等违反诚信原则的行为。
> 使用本脚本产生的任何后果由使用者自行承担。

---

## 目录结构

```
githubfiles/
├── ewt360_v2.py        # 主脚本（维护版本，进度上报真实有效）
├── ewt360_auto.py      # 早期原型 v1（已废弃，见文件头注释）
├── config.json         # 配置模板（填入自己的账号密码）
├── requirements.txt    # Python 依赖
├── .gitignore          # 忽略真实 config.json 与日志
└── README.md           # 本文件
```

---

## 环境要求

- Python 3.8+

## 安装

```bash
# 1. 安装依赖
pip install -r requirements.txt
#   依赖：requests、pycryptodomex

# 2. 准备配置文件
编辑 config.json，填入你的账号/密码
```

---

## 配置说明（config.json）

| 字段 | 说明 | 默认值 |
|------|------|--------|
| `account` | 登录账号（学号 / 手机号） | 必填 |
| `password` | 登录密码（明文，仅本地存储） | 必填 |
| `token` | 登录令牌；留空则自动账号密码登录并写入 | 可选 |
| `speed` | 播放倍速（影响 begin_time 计算，不影响上报时长） | `2.0` |
| `subject_filter` | 跳过的科目 ID 列表（见代码 `SUBJECT_MAP`） | `[]` |
| `max_advance_days` | 向前预读天数 | `3` |
| `target_course_ids` | 仅刷指定 contentId 列表 | `[]` |
| `retry_times` | 失败重试次数 | `3` |
| `retry_delay` | 重试间隔（秒） | `5` |
| `min_interval` | 请求最小间隔（秒，含随机抖动） | `1.0` |
| `log_level` | 日志级别 | `INFO` |
| `log_file` | 日志文件名 | `ewt360_auto.log` |

> 🔒 切勿把含真实账号密码的 `config.json` 提交到 Git（已被 `.gitignore` 忽略）。

---

## 使用方法

主脚本：`ewt360_v2.py`

### 1. 交互式模式（默认，推荐）

```bash
python ewt360_v2.py menu
```

按提示依次选择：场景 → 作业 → 课程（支持按序号、科目、日期筛选），最后确认开始刷课。

### 2. 快速模式（指定作业，非交互）

```bash
python ewt360_v2.py watch --hw <作业ID>
python ewt360_v2.py quick --hw <作业ID>      # 同 watch
```

### 3. 查看课程统计

```bash
python ewt360_v2.py list --hw <作业ID>
```

输出作业总任务数、各科目完成度、各日期剩余任务数。

### 4. 命令行参数

| 参数 | 作用 |
|------|------|
| `--hw <ID>` | 指定作业 homeworkId |
| `--speed 2.0` | 覆盖播放倍速 |
| `--debug` | 打印所有请求 / 响应原始内容（排错用） |
| `--token <T>` | 直接使用 token 登录（跳过账号密码） |
| `--account <A>` | 覆盖命令行账号 |
| `help` | 查看帮助 |

示例：

```bash
python ewt360_v2.py watch --hw 123456 --speed 1.5 --debug
```

---

## 工作原理（API 逆向分析）

### 涉及的域名

| 域名 | 用途 |
|------|------|
| `gateway.ewt360.com` | 业务网关（登录、作业、课程、学习记录） |
| `bfe.ewt360.com` | 播放器心跳 / 进度上报（**真正更新 playTime 的地方**） |
| `teacher.ewt360.com` | 网页端 Origin / Referer 来源（鉴权头需要） |

### 签名与加密算法

1. **登录签名**（`authcenter` 接口）
   ```
   Sign = MD5( Timestamp(ms) + "bdc739ff2dcf" )
   ```
   放入请求头 `Sign`，并配合 `Timestamp` / `Secretid` / `Platform` 等头。

2. **密码加密**（AES-256-CBC，PKCS7 填充，输出大写 Hex）
   ```
   Key  = 20171109124536982017110912453698
   IV   = 2017110912453698
   pwd  = AES_encrypt(password)
   ```

3. **播放器心跳签名**（monitor/collect/batch，**关键**）
   ```
   params = {
     action, duration, mstid(=token),
     signatureMethod="HMAC-SHA1", signatureVersion="1.0",
     timestamp, version="2022-08-02"
   }
   query_string = "&".join(f"{k}={params[k]}" for k in sorted(params))
   signature    = HMAC-SHA1( secret, query_string ).hexdigest()
   ```
   `secret` / `sessionId` 来自 `getPlayerGlobalConf`（每次看课需刷新）。
   该签名逆向自前端 `mstplayer-v3.0.37.min.js` 的 `makeSecretKey`。

### 进度上报机制（核心结论）

- `playbackProgress` 与 `record/submit` 服务端会接收，但 **不会** 真正更新 `playTime`。
- 真正生效的是 **`bfe.ewt360.com/monitor/web/collect/batch`** 心跳上报。
- 服务端按每批独立校验：`report_time - begin_time ≈ stay_time / speed`（容忍 ±2~5s）。
- **每批必须发送固定的 `stay_time`（默认 12000ms，而非累加值）**，服务端自动累加 `playTime`。
- `begin_time = now_ms - stay_time / speed - random(1000, 3000)`，使校验通过。
- 进度显示以服务端真实 `playTime`（接口 `getUserHomeworkLessonTaskInfo`）为准。

---

## 相关 API 速查表

> 基础路径：`GATEWAY_BASE = https://gateway.ewt360.com`
> `BFE_BASE = https://bfe.ewt360.com`

### 登录 / 用户

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/authcenter/v2/oauth/login/account` | 账号密码登录，返回 token / userId |
| GET  | `/api/usercenter/user/login/getUser` | 验证 token 是否有效 |
| GET  | `/api/usercenter/user/baseinfo` | 获取用户信息（realName / schoolId / 会员） |

### 场景 / 作业

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/holidayprod/scene/student/study/getStudentValidSceneList` | 获取假期场景列表 |
| GET  | `/api/holidayprod/scene/student/study/checkHoliday` | 假期检查（场景 / 作业提示） |
| POST | `/api/homeworkprod/student/homework/task/getStudentHomeworkInfo` | **发现作业**（按 status: 1未开始/2进行中/3已截止） |
| POST | `/api/homeworkprod/student/homework/task/getStudentHomeworkDaySubjectStat` | 作业日期 / 科目统计（含 dayId） |
| POST | `/api/homeworkprod/student/homework/task/pageHomeworkTasks` | 指定 dayId 的课程列表 |

### 课程 / 播放

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/homeworkprod/player/getLessonDetailV2` | 课程详情，**返回真实 courseId** |
| POST | `/api/homeworkprod/homework/student/getUserHomeworkLessonTaskInfo` | 课程播放信息（playTime / finishPlayTime） |
| GET  | `/api/videoplayerprod/videoplayer/getPlayerGlobalConf` | 播放器配置（secret / sessionId） |

### 进度上报

| 方法 | 域名 / 路径 | 说明 |
|------|------|------|
| POST | `bfe/video/playbackProgress` | 播放进度上报（multipart，仅展示用） |
| POST | `bfe/monitor/web/collect/batch` | **心跳上报（HMAC-SHA1），真正更新 playTime** |
| POST | `/api/studyprod/course/lesson/record/submit` | 提交学习完成记录 |

---

## 已知限制 / 注意事项

- `ewt360_auto.py` 为早期原型，**进度上报依赖的 `dlog.ewt360.com` 已下线，请勿使用**。
- `monitor/collect/batch` 的 `secret` 会随会话刷新，脚本每次看课前都会重新获取。
- 错误码 `699001`（"检测到网络不稳定或开启了第三方辅助工具"）通常源于 `stay_time` 非固定值或 `begin_time` 计算偏差，已通过固定 12s 批处理规避。
- 调用频率受 `min_interval` 与重试机制控制，请合理使用，避免对服务器造成压力。
- 平台接口随时可能变动，若登录 / 上报失败，先用 `--debug` 对比最新抓包。

---

## License

本项目仅用于技术学习与研究。请遵守相关法律法规与平台条款。

## 题外话

以上为AI生成，以下为作者留言：
用了一下午来搞这个代码，没招了，就这样吧，也能用。
只是不知道有没有泄露我的隐私数据。
这些API，估计这个暑假应该是不会“过期”的。“过期”了就算了。
搞这些代码的时间，都够我直接把课放完了。。。无所谓了。。。。。。
不保证能用->你可以自行(找AI)修改一下。
要不是网上那些刷课的，真TM恶心。。。
不说了
。。。。。。

## 补充

2026.7.24 [ ：（ ]
今天登录API好像是强制要求滑块验证码了？亦或者，是我登录的太频繁，给我风控了？不清楚。
如果有人要使用这个脚本，自己去ewt360.com网页端，用开发者工具抓包token，手动写入进config.json吧，也不难。
