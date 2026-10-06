/**
 * Virtual Hiroba - 会議室リンク共有用GAS
 * 既存の Code.gs（入退室・位置更新・シグナリング）とは別の
 * 新規Apps Scriptプロジェクトとしてデプロイしてください。
 * index.html 側の config.js に ROOMS_URL としてデプロイURLを設定します。
 *
 * データはスプレッドシート不要、PropertiesService（スクリプトプロパティ）に
 * room_<roomId> というキーでリンク文字列を保存するだけのシンプルな構成です。
 */

function doGet(e) {
  const action = e.parameter.action;
  if (action === 'getRoomLink') {
    const roomId = String(e.parameter.roomId || '');
    if (!roomId) return jsonOut({ ok: false, error: 'roomId is required' });
    const link = PropertiesService.getScriptProperties().getProperty('room_' + roomId) || '';
    return jsonOut({ ok: true, link });
  }
  return jsonOut({ ok: false, error: 'invalid action' });
}

function doPost(e) {
  let body;
  try {
    body = JSON.parse(e.postData.contents);
  } catch (err) {
    return jsonOut({ ok: false, error: 'invalid body' });
  }
  if (body.action === 'setRoomLink') {
    const roomId = String(body.roomId || '');
    if (!roomId) return jsonOut({ ok: false, error: 'roomId is required' });
    const link = String(body.link || '').slice(0, 500); // 念のため長さ制限
    PropertiesService.getScriptProperties().setProperty('room_' + roomId, link);
    return jsonOut({ ok: true });
  }
  return jsonOut({ ok: false, error: 'invalid action' });
}

function jsonOut(obj) {
  return ContentService.createTextOutput(JSON.stringify(obj))
    .setMimeType(ContentService.MimeType.JSON);
}
