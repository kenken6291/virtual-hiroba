// ============================================================
// Virtual Hiroba — GAS バックエンド (セキュア版)
// 公開URL: https://kenken6291.github.io/virtual-hiroba/
// ============================================================

const CFG = {
  MAX_USERS:          20,
  SESSION_TIMEOUT_MS: 60000,
  TOKEN_TTL_MS:       86400000,
  RATE_LIMIT_MS:      800,
  MAX_NAME_LEN:       16,
  MAX_COMMENT_LEN:    60,
  COMMENT_TTL_MS:     20000,
  MAX_COORD:          50,
  SECRET_KEY:         'OFFICE_SECRET',
  PEPPER_KEY:         'OFFICE_PEPPER',
  SALT_BYTES:         16,
  TEMP_PASSWORD_LEN:  10,
  MIN_PASSWORD_LEN:   8,
  AUTH_RATE_LIMIT_SEC: 3,
  GEMINI_API_KEY_PROP: 'GEMINI_API_KEY',
  GEMINI_MODEL:       'gemini-3.6-flash',
  MAX_AUDIO_BASE64_LEN: 4000000, // 約3MB相当（15秒程度の音声を想定）
  MAP_IDS:            ['bright', 'park', 'cafe', 'dark'], // マップ（別空間）
  DEFAULT_MAP_ID:     'bright',
  SITE_NAME:          'Virtual Hiroba',
  SITE_URL:           'https://kenken6291.github.io/virtual-hiroba/',
};

const SHEETS = {
  USERS:   'users',
  MEMBERS: 'members',
};

function initSecret() {
  const props = PropertiesService.getScriptProperties();
  if (props.getProperty(CFG.SECRET_KEY)) {
    Logger.log('⚠️  シークレットは既に設定されています。');
    return;
  }
  const secret = generateRandomHex(32);
  props.setProperty(CFG.SECRET_KEY, secret);
  Logger.log('✅ シークレットを生成しました: ' + secret.slice(0, 8) + '...');
}

function resetSecret() {
  const secret = generateRandomHex(32);
  PropertiesService.getScriptProperties().setProperty(CFG.SECRET_KEY, secret);
  Logger.log('✅ シークレットをリセットしました。');
}

// 会員パスワードのハッシュ用ペッパー（SECRET_KEYとは別に保持）
function initPepper() {
  const props = PropertiesService.getScriptProperties();
  if (props.getProperty(CFG.PEPPER_KEY)) {
    Logger.log('⚠️  ペッパーは既に設定されています。');
    return;
  }
  const pepper = generateRandomHex(32);
  props.setProperty(CFG.PEPPER_KEY, pepper);
  Logger.log('✅ ペッパーを生成しました: ' + pepper.slice(0, 8) + '...');
}

function generateRandomHex(bytes) {
  const arr = new Uint8Array(bytes);
  for (let i = 0; i < bytes; i++) arr[i] = Math.floor(Math.random() * 256);
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

function hmacSign(secret, message) {
  const sig = Utilities.computeHmacSha256Signature(message, secret, Utilities.Charset.UTF_8);
  return sig.map(b => (b < 0 ? b + 256 : b).toString(16).padStart(2, '0')).join('');
}

function issueToken(userId) {
  const secret = PropertiesService.getScriptProperties().getProperty(CFG.SECRET_KEY);
  if (!secret) throw new Error('サーバー設定が未完了です。initSecret() を実行してください。');
  const ts      = Date.now().toString();
  const payload = userId + ':' + ts;
  const sig     = hmacSign(secret, payload);
  return Utilities.base64EncodeWebSafe(payload + ':' + sig);
}

function verifyToken(token) {
  if (!token || typeof token !== 'string') return null;
  let decoded;
  try {
    decoded = Utilities.newBlob(Utilities.base64DecodeWebSafe(token)).getDataAsString();
  } catch (e) { return null; }

  const parts = decoded.split(':');
  if (parts.length !== 3) return null;
  const [userId, ts, sig] = parts;
  const now = Date.now();
  const issuedAt = parseInt(ts, 10);
  if (isNaN(issuedAt) || now - issuedAt > CFG.TOKEN_TTL_MS) return null;
  const secret   = PropertiesService.getScriptProperties().getProperty(CFG.SECRET_KEY);
  const expected = hmacSign(secret, userId + ':' + ts);
  if (!constantTimeEqual(sig, expected)) return null;
  return userId;
}

function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// ── レート制限: シグナル系POSTは除外 ──────────────────────────
function checkRateLimit(userId) {
  return checkRateLimitKey('rl:' + userId, Math.ceil(CFG.RATE_LIMIT_MS / 1000));
}

// 汎用レート制限（会員登録・ログイン・パスワード再発行に使用）
function checkRateLimitKey(key, windowSec) {
  const cache = CacheService.getScriptCache();
  if (cache.get(key)) return false;
  cache.put(key, '1', windowSec);
  return true;
}

function sanitizeName(name) {
  if (typeof name !== 'string') return null;
  const trimmed = name.trim().replace(/[<>&"']/g, '');
  if (trimmed.length === 0 || trimmed.length > CFG.MAX_NAME_LEN) return null;
  return trimmed;
}

function normalizeEmail(email) {
  if (typeof email !== 'string') return null;
  const trimmed = email.trim().toLowerCase();
  if (trimmed.length === 0 || trimmed.length > 254) return null;
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(trimmed)) return null;
  return trimmed;
}

function validateCoord(v) {
  const n = Number(v);
  return Number.isInteger(n) && n >= 0 && n <= CFG.MAX_COORD ? n : null;
}

function validateColor(c) {
  return typeof c === 'string' && /^#[0-9a-fA-F]{6}$/.test(c) ? c : '#5faaef';
}

function validateMapId(m) {
  return CFG.MAP_IDS.indexOf(m) >= 0 ? m : CFG.DEFAULT_MAP_ID;
}

function validateComment(text) {
  if (typeof text !== 'string') return null;
  const trimmed = text.trim().replace(/[<>&"']/g, '');
  if (trimmed.length === 0) return '';
  return trimmed.slice(0, CFG.MAX_COMMENT_LEN);
}

function getOrCreateSheet(name, headers) {
  const ss    = SpreadsheetApp.getActiveSpreadsheet();
  let   sheet = ss.getSheetByName(name);
  if (!sheet) {
    sheet = ss.insertSheet(name);
    sheet.appendRow(headers);
    sheet.setFrozenRows(1);
  }
  return sheet;
}

function getUsersSheet() {
  const sheet = getOrCreateSheet(SHEETS.USERS, ['userId','name','x','y','avatarColor','lastSeen','comment','commentAt','mapId']);
  // 既存シートに mapId 列の見出しを1回だけ追加
  const cache = CacheService.getScriptCache();
  if (!cache.get('users_hdr_mapId')) {
    if (sheet.getRange(1, 9).getValue() !== 'mapId') sheet.getRange(1, 9).setValue('mapId');
    cache.put('users_hdr_mapId', '1', 21600);
  }
  return sheet;
}

function getMembersSheet() {
  return getOrCreateSheet(SHEETS.MEMBERS, [
    'id','email','nickname','avatarColor','passwordHash','salt',
    'mustChangePassword','createdAt','updatedAt',
  ]);
}

function jsonResponse(data) {
  return ContentService.createTextOutput(JSON.stringify(data)).setMimeType(ContentService.MimeType.JSON);
}

function errorResponse(msg, code) {
  return jsonResponse({ ok: false, error: msg, code: code || 400 });
}

// ============================================================
// GET ルーター
// ============================================================
function doGet(e) {
  const p      = e.parameter;
  const action = p.action;
  try {
    if (action === 'join') return handleJoin(p);
    const userId = verifyToken(p.token);
    if (!userId) return errorResponse('認証失敗', 401);
    switch (action) {
      case 'getUsers':    return jsonResponse(getActiveUsers(userId));
      case 'getRoomLink': return jsonResponse(handleGetRoomLink(p));
      default:           return errorResponse('不明なアクション: ' + action);
    }
  } catch (err) {
    console.error('doGet error:', err);
    return errorResponse('サーバーエラー', 500);
  }
}

// ============================================================
// POST ルーター
// ============================================================
function doPost(e) {
  let body;
  try { body = JSON.parse(e.postData.contents); }
  catch (err) { return errorResponse('JSONが不正です'); }

  const action = body.action;

  try {
    // ── 会員登録関連（未ログインでも呼べる） ──
    if (action === 'register')       return handleRegister(body);
    if (action === 'login')          return handleLogin(body);
    if (action === 'forgotPassword') return handleForgotPassword(body);
    if (action === 'join')           return handleJoin(body); // トークンは handleJoin 内で検証

    const userId = verifyToken(body.token);
    if (!userId) return errorResponse('認証失敗', 401);

    // 読み取り系（ポーリング）はレート制限の対象外
    if (action === 'getUsers')    return jsonResponse(getActiveUsers(userId));
    if (action === 'getRoomLink') return jsonResponse(handleGetRoomLink(body));

    // 会議リンク保存は位置更新と別枠のレート制限
    if (action === 'setRoomLink') {
      if (!checkRateLimitKey('rl_room:' + userId, 2)) return errorResponse('リクエストが速すぎます', 429);
      return jsonResponse(handleSetRoomLink(body));
    }

    if (!checkRateLimit(userId)) {
      return errorResponse('リクエストが速すぎます', 429);
    }

    switch (action) {
      case 'updatePosition':  return jsonResponse(updateUserPosition(userId, body));
      case 'sendComment':     return jsonResponse(handleSendComment(userId, body));
      case 'transcribeAudio': return handleTranscribeAudio(userId, body);
      case 'leave':           return jsonResponse(removeUser(userId));
      case 'changePassword':  return handleChangePassword(userId, body);
      case 'updateNickname':  return handleUpdateNickname(userId, body);
      default:                return errorResponse('不明なアクション: ' + action);
    }
  } catch (err) {
    console.error('doPost error:', err);
    return errorResponse('サーバーエラー', 500);
  }
}

// ============================================================
// ACTION: join （会員ログイン済みトークンが必須）
// ============================================================
function handleJoin(p) {
  const userId = verifyToken(p.token);
  if (!userId) return errorResponse('ログインが必要です', 401);

  const member = findMemberById(userId);
  if (!member) return errorResponse('アカウントが見つかりません', 401);
  if (member.mustChangePassword) return errorResponse('パスワードの変更が必要です', 428);

  const sheet = getUsersSheet();
  const data  = sheet.getDataRange().getValues();
  const now   = Date.now();
  let activeCount = 0;
  for (let i = 1; i < data.length; i++) {
    if (data[i][0] !== userId && now - new Date(data[i][5]).getTime() < CFG.SESSION_TIMEOUT_MS) activeCount++;
  }
  if (activeCount >= CFG.MAX_USERS) return errorResponse('サーバーが満員です', 503);

  const token = issueToken(userId);
  return jsonResponse({
    ok: true, userId, token,
    name: member.nickname, avatarColor: member.avatarColor,
  });
}

// ============================================================
// ACTION: updatePosition
// ============================================================
function updateUserPosition(userId, body) {
  const name  = sanitizeName(body.name);
  const x     = validateCoord(body.x);
  const y     = validateCoord(body.y);
  const color = validateColor(body.avatarColor);
  const mapId = validateMapId(body.mapId);
  if (!name || x === null || y === null) return { ok: false, error: '座標/名前が不正' };
  const sheet = getUsersSheet();
  const data  = sheet.getDataRange().getValues();
  const now   = new Date().toISOString();
  for (let i = 1; i < data.length; i++) {
    if (data[i][0] === userId) {
      // コメント欄（列7-8）は上書きしない
      sheet.getRange(i + 1, 1, 1, 6).setValues([[userId, name, x, y, color, now]]);
      if (data[i][8] !== mapId) sheet.getRange(i + 1, 9).setValue(mapId);
      return { ok: true };
    }
  }
  sheet.appendRow([userId, name, x, y, color, now, '', '', mapId]);
  return { ok: true, created: true };
}

// ============================================================
// ACTION: sendComment（コメント吹き出し）
// ============================================================
function handleSendComment(userId, body) {
  const comment = validateComment(body.text);
  if (comment === null) return { ok: false, error: 'コメントが不正です' };
  const sheet = getUsersSheet();
  const data  = sheet.getDataRange().getValues();
  const now   = new Date().toISOString();
  for (let i = 1; i < data.length; i++) {
    if (data[i][0] === userId) {
      sheet.getRange(i + 1, 7, 1, 2).setValues([[comment, now]]);
      return { ok: true };
    }
  }
  return { ok: false, error: '入室してください' };
}

// ============================================================
// ACTION: getUsers
// ============================================================
function getActiveUsers(requesterId) {
  const sheet = getUsersSheet();
  const data  = sheet.getDataRange().getValues();
  const now   = Date.now();
  const users = [];
  for (let i = 1; i < data.length; i++) {
    if (now - new Date(data[i][5]).getTime() < CFG.SESSION_TIMEOUT_MS) {
      const commentAt = data[i][7] ? new Date(data[i][7]).getTime() : 0;
      const fresh = commentAt && (now - commentAt < CFG.COMMENT_TTL_MS);
      users.push({
        userId:      data[i][0],
        name:        data[i][1],
        x:           Number(data[i][2]),
        y:           Number(data[i][3]),
        avatarColor: data[i][4],
        isSelf:      data[i][0] === requesterId,
        comment:     fresh ? data[i][6] : '',
        commentAt:   fresh ? new Date(data[i][7]).toISOString() : '',
        mapId:       validateMapId(data[i][8]),
      });
    }
  }
  return { ok: true, users };
}

// ============================================================
// ACTION: leave
// ============================================================
function removeUser(userId) {
  const sheet = getUsersSheet();
  const data  = sheet.getDataRange().getValues();
  for (let i = data.length - 1; i >= 1; i--) {
    if (data[i][0] === userId) { sheet.deleteRow(i + 1); return { ok: true }; }
  }
  return { ok: true };
}

// ============================================================
// 会員: パスワードハッシュ (SHA-256 + salt + pepper)
// ============================================================
function hashPassword(password, salt) {
  const pepper = PropertiesService.getScriptProperties().getProperty(CFG.PEPPER_KEY);
  if (!pepper) throw new Error('サーバー設定が未完了です。initPepper() を実行してください。');
  const raw = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, password + salt + pepper, Utilities.Charset.UTF_8);
  return raw.map(b => (b < 0 ? b + 256 : b).toString(16).padStart(2, '0')).join('');
}

function generateTempPassword() {
  // 見間違えやすい文字 (0/O, 1/l/I) を除いた文字セット
  const chars = 'ABCDEFGHJKMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789';
  let out = '';
  for (let i = 0; i < CFG.TEMP_PASSWORD_LEN; i++) {
    out += chars[Math.floor(Math.random() * chars.length)];
  }
  return out;
}

function findMemberRowById(userId) {
  const sheet = getMembersSheet();
  const data  = sheet.getDataRange().getValues();
  for (let i = 1; i < data.length; i++) {
    if (data[i][0] === userId) return { rowIndex: i + 1, row: data[i] };
  }
  return null;
}

function findMemberRowByEmail(email) {
  const sheet = getMembersSheet();
  const data  = sheet.getDataRange().getValues();
  for (let i = 1; i < data.length; i++) {
    if (String(data[i][1]).toLowerCase() === email) return { rowIndex: i + 1, row: data[i] };
  }
  return null;
}

function rowToMember(row) {
  return {
    id: row[0], email: row[1], nickname: row[2], avatarColor: row[3],
    passwordHash: row[4], salt: row[5], mustChangePassword: !!row[6],
    createdAt: row[7], updatedAt: row[8],
  };
}

function findMemberById(userId) {
  const found = findMemberRowById(userId);
  return found ? rowToMember(found.row) : null;
}

function sendTempPasswordEmail(email, nickname, tempPassword) {
  const subject = '【' + CFG.SITE_NAME + '】仮パスワードのお知らせ';
  const body =
    nickname + ' 様\n\n' +
    CFG.SITE_NAME + ' の仮パスワードです。以下でログインし、\n' +
    '初回ログイン後に新しいパスワードを設定してください。\n\n' +
    '仮パスワード: ' + tempPassword + '\n' +
    'ログインページ: ' + CFG.SITE_URL + '\n\n' +
    '※ このメールに心当たりがない場合は破棄してください。';
  MailApp.sendEmail(email, subject, body);
}

// ============================================================
// ACTION: transcribeAudio（音声コメントの文字起こし・Gemini API）
// ============================================================
function handleTranscribeAudio(userId, body) {
  const audioBase64 = body.audioBase64;
  const mimeType = typeof body.mimeType === 'string' ? body.mimeType : 'audio/webm';
  if (!audioBase64 || typeof audioBase64 !== 'string') {
    return errorResponse('音声データがありません');
  }
  if (audioBase64.length > CFG.MAX_AUDIO_BASE64_LEN) {
    return errorResponse('音声が長すぎます（15秒以内にしてください）');
  }
  const apiKey = PropertiesService.getScriptProperties().getProperty(CFG.GEMINI_API_KEY_PROP);
  if (!apiKey) return errorResponse('サーバー側でGemini APIキーが未設定です。setGeminiApiKey()を実行してください。');

  const url = 'https://generativelanguage.googleapis.com/v1beta/models/' +
    CFG.GEMINI_MODEL + ':generateContent?key=' + apiKey;
  const payload = {
    contents: [{
      parts: [
        { inline_data: { mime_type: mimeType, data: audioBase64 } },
        { text: 'この音声の内容を日本語で文字起こししてください。文字起こしした内容だけを、説明や記号を付けずに出力してください。60文字以内に短くまとめてください。' },
      ],
    }],
  };

  try {
    const res = UrlFetchApp.fetch(url, {
      method: 'post',
      contentType: 'application/json',
      payload: JSON.stringify(payload),
      muteHttpExceptions: true,
    });
    const code = res.getResponseCode();
    if (code !== 200) {
      console.error('Gemini API error:', code, res.getContentText());
      return errorResponse('文字起こしに失敗しました');
    }
    const data = JSON.parse(res.getContentText());
    const text = data?.candidates?.[0]?.content?.parts?.[0]?.text;
    if (!text || !text.trim()) return errorResponse('文字起こし結果が空でした');
    return jsonResponse({ ok: true, text: text.trim().slice(0, CFG.MAX_COMMENT_LEN) });
  } catch (err) {
    console.error('transcribeAudio error:', err);
    return errorResponse('文字起こし中にエラーが発生しました');
  }
}

// Gemini APIキーを設定する（1回だけ手動実行）。
// 実行前にYOUR_API_KEY_HEREを実際のAPIキーに書き換えてください。
function setGeminiApiKey() {
  const YOUR_API_KEY_HERE = 'ここに取得したGemini APIキーを貼り付け';
  PropertiesService.getScriptProperties().setProperty(CFG.GEMINI_API_KEY_PROP, YOUR_API_KEY_HERE);
  Logger.log('✅ Gemini APIキーを保存しました');
}

// ============================================================
// ACTION: register（会員登録・未ログインで呼び出し可）
// ============================================================
function handleRegister(body) {
  if (!checkRateLimitKey('rl_reg:' + (body.email || ''), CFG.AUTH_RATE_LIMIT_SEC)) {
    return errorResponse('リクエストが速すぎます', 429);
  }
  const nickname = sanitizeName(body.nickname);
  const email    = normalizeEmail(body.email);
  if (!nickname) return errorResponse('ニックネームが不正です');
  if (!email)    return errorResponse('メールアドレスが不正です');

  if (findMemberRowByEmail(email)) {
    return errorResponse('このメールアドレスは既に登録されています');
  }

  const userId       = 'm_' + Utilities.getUuid().replace(/-/g, '').slice(0, 12);
  const tempPassword = generateTempPassword();
  const salt         = generateRandomHex(CFG.SALT_BYTES);
  const passwordHash = hashPassword(tempPassword, salt);
  const now          = new Date().toISOString();

  getMembersSheet().appendRow([
    userId, email, nickname, '#5faaef', passwordHash, salt, true, now, now,
  ]);

  try {
    sendTempPasswordEmail(email, nickname, tempPassword);
  } catch (err) {
    console.error('sendTempPasswordEmail error:', err);
    return errorResponse('登録は完了しましたが、メール送信に失敗しました。管理者にご連絡ください。');
  }

  return jsonResponse({ ok: true });
}

// ============================================================
// ACTION: login（未ログインで呼び出し可）
// ============================================================
function handleLogin(body) {
  const email = normalizeEmail(body.email);
  const password = body.password;
  if (!email || !password) return errorResponse('メールアドレスとパスワードを入力してください');
  if (!checkRateLimitKey('rl_login:' + email, CFG.AUTH_RATE_LIMIT_SEC)) {
    return errorResponse('リクエストが速すぎます', 429);
  }

  const found = findMemberRowByEmail(email);
  if (!found) return errorResponse('メールアドレスまたはパスワードが違います');
  const member = rowToMember(found.row);
  const hash = hashPassword(password, member.salt);
  if (!constantTimeEqual(hash, member.passwordHash)) {
    return errorResponse('メールアドレスまたはパスワードが違います');
  }

  const token = issueToken(member.id);
  return jsonResponse({
    ok: true, token, userId: member.id,
    nickname: member.nickname, avatarColor: member.avatarColor,
    mustChangePassword: member.mustChangePassword,
  });
}

// ============================================================
// ACTION: forgotPassword（未ログインで呼び出し可）
// ============================================================
function handleForgotPassword(body) {
  const email = normalizeEmail(body.email);
  if (!email) return errorResponse('メールアドレスが不正です');
  if (!checkRateLimitKey('rl_forgot:' + email, CFG.AUTH_RATE_LIMIT_SEC)) {
    return errorResponse('リクエストが速すぎます', 429);
  }

  const found = findMemberRowByEmail(email);
  if (found) {
    const member = rowToMember(found.row);
    const tempPassword = generateTempPassword();
    const salt = generateRandomHex(CFG.SALT_BYTES);
    const passwordHash = hashPassword(tempPassword, salt);
    const now = new Date().toISOString();
    const sheet = getMembersSheet();
    sheet.getRange(found.rowIndex, 5, 1, 5).setValues([[passwordHash, salt, true, member.createdAt, now]]);
    try {
      sendTempPasswordEmail(email, member.nickname, tempPassword);
    } catch (err) {
      console.error('sendTempPasswordEmail error:', err);
    }
  }
  // メール存在有無に関わらず同じレスポンス（アカウント存在の推測を防ぐ）
  return jsonResponse({ ok: true });
}

// ============================================================
// ACTION: changePassword（要ログイン）
// ============================================================
function handleChangePassword(userId, body) {
  const newPassword = body.newPassword;
  if (typeof newPassword !== 'string' || newPassword.length < CFG.MIN_PASSWORD_LEN) {
    return errorResponse('パスワードは' + CFG.MIN_PASSWORD_LEN + '文字以上にしてください');
  }
  const found = findMemberRowById(userId);
  if (!found) return errorResponse('アカウントが見つかりません', 401);

  const salt = generateRandomHex(CFG.SALT_BYTES);
  const passwordHash = hashPassword(newPassword, salt);
  const now = new Date().toISOString();
  getMembersSheet().getRange(found.rowIndex, 5, 1, 5).setValues([[passwordHash, salt, false, found.row[7], now]]);
  return jsonResponse({ ok: true });
}

// ============================================================
// ACTION: updateNickname（要ログイン）
// ============================================================
function handleUpdateNickname(userId, body) {
  const nickname = sanitizeName(body.nickname);
  if (!nickname) return errorResponse('ニックネームが不正です');
  const found = findMemberRowById(userId);
  if (!found) return errorResponse('アカウントが見つかりません', 401);
  const sheet = getMembersSheet();
  sheet.getRange(found.rowIndex, 3, 1, 1).setValues([[nickname]]);
  sheet.getRange(found.rowIndex, 9, 1, 1).setValues([[new Date().toISOString()]]);
  return jsonResponse({ ok: true });
}

// ============================================================
// ACTION: getRoomLink / setRoomLink（エリアごとのZoom/Meetリンク共有）
//   スクリプトプロパティに room_<roomId> で保存（旧 rooms-code.gs を統合）
// ============================================================
function validateRoomId(id) {
  const s = String(id || '');
  return /^[a-z0-9_]{1,30}$/.test(s) ? s : null;
}

function handleGetRoomLink(p) {
  const roomId = validateRoomId(p.roomId);
  if (!roomId) return { ok: false, error: 'roomIdが不正です' };
  const link = PropertiesService.getScriptProperties().getProperty('room_' + roomId) || '';
  return { ok: true, link };
}

function handleSetRoomLink(body) {
  const roomId = validateRoomId(body.roomId);
  if (!roomId) return { ok: false, error: 'roomIdが不正です' };
  const link = String(body.link || '').trim().slice(0, 500);
  if (link && /[<>"'\s]/.test(link)) return { ok: false, error: 'リンクの形式が不正です' };
  const props = PropertiesService.getScriptProperties();
  if (link) props.setProperty('room_' + roomId, link);
  else      props.deleteProperty('room_' + roomId);
  return { ok: true };
}

// ============================================================
// 定期クリーンアップ
// ============================================================
function cleanupExpired() {
  const now      = Date.now();
  const usrSheet = getUsersSheet();
  const usrData  = usrSheet.getDataRange().getValues();
  const usrCut   = now - CFG.SESSION_TIMEOUT_MS * 2;
  for (let i = usrData.length - 1; i >= 1; i--) {
    if (new Date(usrData[i][5]).getTime() < usrCut) usrSheet.deleteRow(i + 1);
  }
  console.log('cleanup done at ' + new Date().toISOString());
}
