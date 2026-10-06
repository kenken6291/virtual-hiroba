# Virtual Hiroba セットアップ
公開URL: https://kenken6291.github.io/virtual-hiroba/

GASは1つだけ（会議リンク共有も統合済み）。GitHub Secrets・config.js は不要です。

## 1. GAS（code.gs）
1. Googleスプレッドシートを新規作成（名前例：`virtual-hiroba-data`）
2. 「拡張機能 → Apps Script」を開き、`gas/code.gs` を貼り付けて保存
3. 関数を選んで1回ずつ実行（権限の許可を求められたら許可）
   - `initSecret`
   - `initPepper`
   - `setGeminiApiKey`（実行前にAPIキーを書き込む）
4. トリガー追加：`cleanupExpired` / 時間主導型 / 10分おき
5. デプロイ → 新しいデプロイ → ウェブアプリ
   - 次のユーザーとして実行：自分
   - アクセスできるユーザー：全員
6. 発行されたURLをコピー

## 2. index.html にURLを貼る（最初の1回だけ）
`github/index.html` の次の行を、手順1-6のURLに書き換えます。

```js
const GAS_URL = 'ここにGASのウェブアプリURLを貼り付け';
```

## 3. GitHub
1. リポジトリ `virtual-hiroba` を作成（Public）
2. `github/` フォルダの中身を置く（index.html / .gitignore / .github/workflows/deploy.yml）
3. Settings → Pages → Source を「GitHub Actions」
4. main に push

## 今後 code.gs を更新するとき
**デプロイ → デプロイを管理 → 鉛筆（編集）→ バージョン「新バージョン」→ デプロイ**
この方法ならURLは変わらないので、index.html の書き換えは不要です。
（「新しいデプロイ」を作るとURLが変わるので注意）

## 顔（表情）機能
- プロフィール画面の「😊 顔（表情）を登録する」から、普通・笑った・驚いた・困った の4つの顔写真を登録できます。
  写真を選ぶと丸く切り抜く画面が出るので、ドラッグで位置、スライダーで大きさを調整して「決定」→「保存する」。
- 普通の顔だけの登録でもOK。無い表情は普通の顔＋絵文字（😊😲😥）で表します。
- 顔を登録していない人は、ドット絵の顔が表情に合わせて変わります。
- コメントの内容から表情を自動判定します（まずキーワード、判断できないときは Gemini）。
  表情はコメントの吹き出しが出ている間（20秒）続き、その後は普通の顔に戻ります。
- 顔画像はスプレッドシートの `faces` シートに保存されます（自動作成）。
- アバターは移動するとなめらかに歩き、表情が変わるとリアクション（驚きはジャンプ）します。

### 更新手順
1. code.gs を貼り替えて保存
2. デプロイ → デプロイを管理 → 編集 → 新バージョン → デプロイ（URLは変わりません）
3. index.html を push
