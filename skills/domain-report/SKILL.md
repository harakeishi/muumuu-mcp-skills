---
name: domain-report
description: 保有ドメインのセキュリティ・健全性レポートを生成する。DNS設定チェック(SPF/DMARC/CAA)、サブドメインテイクオーバー検知、類似ドメイン監視(タイポスクワッティング/ホモグラフ攻撃)。「ドメインレポート」「ドメイン診断」「DNS健全性」「ドメインセキュリティ」で自動適用
---

# Domain Report - ドメインセキュリティ & 健全性レポート

## Overview

保有ドメインに対してセキュリティ・健全性の包括的チェックを行い、Markdownレポートを生成する。
muumuu-domain MCP + dig/curl/openssl コマンドを組み合わせて診断する。

### 前提条件

- [muumuu-domain MCP Server](https://github.com/because0/muumuu-domain-mcp-server) がClaude Codeに設定済みであること
- `dig`, `curl`, `openssl` コマンドが利用可能であること

## When to Use

- 保有ドメインのセキュリティ状態を確認したいとき
- DNS設定に問題がないか定期チェックしたいとき
- 類似ドメインが第三者に取得されていないか監視したいとき
- 「ドメインレポート」「ドメイン診断」「DNS健全性チェック」と言われたとき

## 実行フロー

### Phase 1: 対象ドメインの特定

1. ユーザーが対象ドメインを指定 → そのまま使用
2. 指定なし → `mcp__muumuu-domain__list-me-domains` で保有ドメイン一覧を取得し、ユーザーに選択を求める
3. 「全部」と言われたら全ドメインを対象にする（ただし10件以上なら確認）

### Phase 2: 情報収集（並列実行）

対象ドメインごとに以下を**サブエージェントで並列実行**する:

#### 2-A: ドメイン基本情報
```
mcp__muumuu-domain__get-me-domain(domain-id)
```
- ドメイン状態、有効期限を取得

#### 2-B: DNSレコード全取得
```
mcp__muumuu-domain__list-me-dns-records(domain-id, page-size: 100)
```
- 全レコードを取得（ページネーション対応）

#### 2-C: DNS伝播確認（Bashで実行）
```bash
# 各レコードタイプの実際の応答を確認
dig +short example.com A
dig +short example.com AAAA
dig +short example.com MX
dig +short example.com TXT
dig +short example.com NS
dig +short example.com CAA
dig +short _dmarc.example.com TXT
```

#### 2-D: 類似ドメイン検索
後述の「Phase 4: 類似ドメイン監視」で使用するドメイン候補を生成し、search-domains で検索。

### Phase 3: DNS健全性チェック

取得した情報に対して以下のチェックを実行する。

#### 3-1: メール認証チェック

| チェック項目 | 判定方法 | 重大度 |
|------------|---------|--------|
| SPF未設定 | TXTレコードに `v=spf1` が存在しない | Critical |
| SPF が `+all` | SPF値の末尾が `+all` | Critical |
| DMARC未設定 | `_dmarc.{domain}` のTXTレコードが存在しない | Warning |
| DMARCポリシーが `none` | `p=none` のまま運用 | Info |
| DKIM未確認 | TXTレコードにDKIMセレクタが見つからない | Info（検出困難なため参考情報） |

**SPFチェックの詳細**:
```
v=spf1 include:_spf.google.com ~all  → OK
v=spf1 include:_spf.google.com -all  → OK（厳格）
v=spf1 +all                           → 全許可（危険）
SPFレコードなし                         → なりすまし可能
```

**DMARCチェックの詳細**:
```
v=DMARC1; p=reject; ...    → 最も安全
v=DMARC1; p=quarantine; ... → 推奨レベル
v=DMARC1; p=none; ...      → 監視のみ（強化推奨）
DMARCレコードなし            → メール認証の最終防衛線なし
```

#### 3-2: SSL/CA認証チェック

| チェック項目 | 判定方法 | 重大度 |
|------------|---------|--------|
| CAAレコード未設定 | CAAレコードが存在しない | Warning |
| SSL証明書の有効期限 | `openssl s_client` で確認 | 30日以内ならWarning |

```bash
# SSL証明書確認
echo | openssl s_client -servername example.com -connect example.com:443 2>/dev/null | openssl x509 -noout -dates -issuer 2>/dev/null
```

#### 3-3: サブドメインテイクオーバーリスク

| チェック項目 | 判定方法 | 重大度 |
|------------|---------|--------|
| CNAMEの参照先が解決不能 | CNAMEレコードの値に対して `dig` → NXDOMAIN | Critical |
| Aレコードの向き先がHTTP応答なし | `curl -sI --max-time 5 http://{ip}` → タイムアウト | Warning |

**サブドメインテイクオーバーの判定ロジック**:
```
1. CNAMEレコードを全取得
2. 各CNAMEの参照先を dig で解決
3. NXDOMAIN or SERVFAIL → テイクオーバーリスクあり
4. 特にクラウドサービスのCNAME（*.herokuapp.com, *.azurewebsites.net 等）は要注意
```

既知の危険なCNAMEパターン:
- `*.herokuapp.com` → Heroku
- `*.azurewebsites.net` → Azure
- `*.cloudfront.net` → CloudFront
- `*.s3.amazonaws.com` → S3
- `*.github.io` → GitHub Pages
- `*.netlify.app` → Netlify
- `*.vercel.app` → Vercel (ただしVercelは自動保護あり)
- `*.shopify.com` → Shopify

#### 3-4: その他のチェック

| チェック項目 | 判定方法 | 重大度 |
|------------|---------|--------|
| ワイルドカードDNSレコード | `*.domain` のA/CNAMEレコード存在 | Info |
| 未使用のAレコード疑い | Aレコードの向き先にHTTP接続できない | Info |

### Phase 4: 類似ドメイン監視（ホモグラフ / タイポスクワッティング）

対象ドメインの SLD（セカンドレベルドメイン）に対して類似ドメイン候補を生成し、取得状況を確認する。

#### 4-1: 類似ドメイン候補の生成

対象ドメインが `example.com` の場合:

**タイポスクワッティング**（文字入れ替え・脱落・追加）:
```
examlpe.com    # 隣接文字入れ替え
exmple.com     # 文字脱落
examplle.com   # 文字重複
exampke.com    # 隣接キー誤打（l→k）
```
生成ルール:
- 隣接2文字の入れ替え（全パターン）
- 1文字脱落（全位置）
- 1文字重複（全位置）
- 隣接キー置換（QWERTYレイアウト、主要文字のみ）
- ただし候補が多すぎる場合は代表的なものに絞る（最大15件）

**数字/文字置換（ホモグラフ的）**:
```
examp1e.com    # l→1
exarnple.com   # m→rn
examp|e.com    # l→|（パイプ）
```
置換テーブル:
| 元文字 | 置換候補 |
|--------|---------|
| l | 1, i |
| o | 0 |
| i | 1, l |
| a | 4 |
| e | 3 |
| s | 5 |
| m | rn |

**TLD違い**:
```
example.net, example.org, example.jp, example.co.jp, example.info
```

#### 4-2: 空き状況確認

生成した候補を `mcp__muumuu-domain__search-domains` で検索:
```
mcp__muumuu-domain__search-domains(q: "examlpe.com")
mcp__muumuu-domain__search-domains(q: "examp1e", tlds: ["com", "net", "jp"])
```

**注意**: search-domains API の呼び出し回数が多くなるため、候補は厳選する。TLD違いは1回のAPI呼び出しでまとめて検索できる。

#### 4-3: リスク分類

| 状況 | リスク | アクション |
|------|--------|----------|
| 第三者が取得済み | High | フィッシングサイトの可能性。実際にアクセスして内容確認を推奨 |
| 空き（取得可能） | Medium | 防御的取得を検討 |
| あなたが保有 | Safe | 問題なし |
| 検索不可（プレミアム等） | Unknown | 手動確認を推奨 |

### Phase 5: レポート生成

以下のテンプレートに従ってMarkdownレポートを生成し、ファイルに保存する。

保存先: `domain-report-{domain}-{YYYYMMDD}.md`

```markdown
# Domain Security Report - {domain}

Generated: {YYYY-MM-DD HH:MM}

## Summary

| 項目 | 結果 |
|------|------|
| ドメイン | {domain} |
| 状態 | {active/inactive} |
| 有効期限 | {expiry_date} |
| DNSレコード数 | {count}件 |
| 問題検出数 | Critical: {n}, Warning: {n}, Info: {n} |

## DNS Health Check

### Critical

- **[CRITICAL] SPF未設定**: なりすましメールのリスクがあります
  - 推奨: `v=spf1 include:{適切なSPFソース} ~all` のTXTレコードを追加

### Warning

- **[WARNING] DMARC未設定**: メール認証の最終防衛線がありません
  - 推奨: `v=DMARC1; p=none; rua=mailto:dmarc@{domain}` から段階的に導入

### Info

- **[INFO] CAAレコード未設定**: 任意のCAからSSL証明書を発行可能な状態です
  - 推奨: 使用しているCAのみを許可するCAAレコードを追加

## Subdomain Takeover Risk

| サブドメイン | レコードタイプ | 参照先 | 状態 | リスク |
|------------|-------------|--------|------|--------|
| staging.example.com | CNAME | old-app.herokuapp.com | NXDOMAIN | Critical |

## Similar Domain Monitoring

### Typosquatting

| ドメイン | タイプ | 状況 | リスク |
|---------|--------|------|--------|
| examp1e.com | 数字置換 (l→1) | 第三者取得済み | High |
| examlpe.com | 文字入れ替え | 空き | Medium |

### TLD Variants

| ドメイン | 状況 | リスク |
|---------|------|--------|
| example.net | 空き | Medium |
| example.org | 第三者取得済み | High |

## Recommendations

1. **[即時対応]** SPFレコードを設定してください
2. **[推奨]** DMARCを `p=quarantine` 以上に設定してください
3. **[推奨]** staging.example.com のCNAMEを削除してください（テイクオーバーリスク）
4. **[検討]** example.net の防御的取得を検討してください

## DNS Records (Reference)

| FQDN | Type | Value | TTL |
|------|------|-------|-----|
| example.com. | A | 76.76.21.21 | 300 |
| ... | ... | ... | ... |
```

## 実装上の注意

### API呼び出し効率

- `list-me-dns-records` は `page-size: 100` で一度に取得
- 類似ドメイン検索は `tlds` パラメータで1回にまとめる
- 複数ドメイン対象時はサブエージェントで並列実行

### dig コマンドのフォールバック

dig が使えない環境では `nslookup` または `host` コマンドを使用:
```bash
# dig が使えない場合
nslookup -type=TXT _dmarc.example.com
host -t MX example.com
```

### エラーハンドリング

- MCP認証エラー → ユーザーに再認証を案内
- ドメインが見つからない → FQDN指定で `list-me-domains` を再試行
- dig タイムアウト → 3秒タイムアウトで `dig +time=3` を使用
- 類似ドメイン検索でAPIエラー → スキップしてレポートに「検索不可」と記載

### 複数ドメインの場合

10件以上のドメインを対象にする場合:
1. AskUserQuestion で本当に全件実行するか確認
2. 各ドメインのレポートを個別ファイルで生成
3. サマリーレポートを別途生成:

```markdown
# Domain Portfolio Summary - {YYYY-MM-DD}

| ドメイン | 有効期限 | Critical | Warning | Info |
|---------|---------|----------|---------|------|
| example.com | 2027/03/15 | 1 | 2 | 1 |
| example.jp | 2026/06/01 | 0 | 0 | 1 |
```
