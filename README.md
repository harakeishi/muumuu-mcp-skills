# muumuu-mcp-skills

[Muumuu Domain MCP Server](https://github.com/because0/muumuu-domain-mcp-server) と連携する Claude Code スキル集です。

## Skills

### `/domain-report` - ドメインセキュリティ & 健全性レポート

保有ドメインに対してセキュリティ・健全性の包括的チェックを行い、Markdownレポートを生成します。

**チェック項目:**

- **DNS健全性**: SPF / DMARC / CAA レコードの設定状況
- **SSL証明書**: 有効期限・発行者の確認
- **サブドメインテイクオーバー**: CNAME参照先の生存確認
- **類似ドメイン監視**: タイポスクワッティング・ホモグラフ攻撃の検知

**使い方:**

```
/domain-report example.com
```

**出力例:**

```
Domain Security Report - example.com

問題検出: Critical 1 / Warning 2 / Info 1

- [CRITICAL] SPF未設定: なりすましメールのリスク
- [WARNING] DMARC未設定: メール認証の最終防衛線なし
- [WARNING] CAA未設定: 任意のCAからSSL証明書発行可能
```

## 前提条件

1. [Claude Code](https://docs.anthropic.com/en/docs/claude-code) がインストール済みであること
2. [Muumuu Domain MCP Server](https://github.com/because0/muumuu-domain-mcp-server) が設定済みであること

## インストール

```bash
claude plugin add harakeishi/muumuu-mcp-skills
```

## License

MIT
