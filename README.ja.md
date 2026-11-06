# opencti-lookup

手元の OpenCTI を読み取り専用で照会する CLI とローカル MCP サーバです。脅威分析を
行うエージェントが、外部の lookup（otx-lookup・gti-lookup・cve-lookup など
cybersecurity-series の各ツール）と並べて、自分たちのインスタンスに蓄積された情報を
参照できるようにします。

IP・ドメイン・URL・メールアドレス・ファイルのハッシュを渡すと、インスタンスにある
observable と indicator、その目撃情報（誤検知としての目撃かどうかも）、それに触れた
レポート、指している先を返します。名前・別名・ATT&CK ID を渡すと、攻撃者・マルウェア・
手法・レポートを見つけ、その関係をたどります。

照会先は利用を許されたインスタンスで、支給されたキーを使うので、調査対象には何も
通信が届きません。書き込みは一切しません。

[English README](README.md)

## 状態

[RFP](docs/ja/opencti-lookup-rfp.ja.md) の Phase 1 と Phase 2 を実装し、OpenCTI 6.7.4 で
試験済みです。版の履歴は [CHANGELOG.md](CHANGELOG.md) にあります。

## 必要なもの

- OpenCTI のインスタンス（**6.7.4 で検証済み**。ほかの版では問い合わせが拒否される
  ことがあります。インスタンスの版は `server_status` で分かります）、その URL、API キー
- ビルドには Go 1.25 以上

## 導入

```bash
brew install nlink-jp/tap/opencti-lookup   # macOS（Apple シリコン）
```

または [リリース](https://github.com/nlink-jp/opencti-lookup/releases) から各プラットフォームの
アーカイブを取得するか、ソースからビルドします:

```bash
make build   # → dist/opencti-lookup
```

## 設定

[config.example.toml](config.example.toml) を `~/.config/opencti-lookup/config.toml`
に写し、`url` と `token` を設定して `chmod 600` してください。設定ファイルは
`$XDG_CONFIG_HOME/opencti-lookup/`、`~/.config/opencti-lookup/`、macOS では
`~/Library/Application Support/opencti-lookup/` の順に探します。`--config <path>` で
明示もできます。

| 設定 | 環境変数 | 意味 |
|---|---|---|
| `[opencti] url` | `OPENCTI_LOOKUP_URL` | インスタンスのベース URL（必須） |
| `[opencti] token` | `OPENCTI_LOOKUP_TOKEN` | 支給された API キー（必須） |
| `[opencti] ca_file` | `OPENCTI_LOOKUP_CA_FILE` | 信頼する証明書（PEM。自己署名・社内 CA 用） |
| `[opencti] insecure_skip_verify` | `OPENCTI_LOOKUP_INSECURE_SKIP_VERIFY` | TLS の検証を省く（下記） |
| `[opencti] timeout_seconds` | `OPENCTI_LOOKUP_TIMEOUT_SECONDS` | 1 回の問い合わせの上限時間 1〜600 秒（既定 30） |
| `[query] default_limit` | — | 一覧の既定の件数（25） |
| `[query] max_limit` | — | 1 回で頼める最大件数 1〜5000（500） |

未知のキー・空の値・範囲外の数値はエラーです。ほかの利用者が読める設定ファイルには
警告を出します。

**証明書.** 自己署名・社内 CA の証明書なら、まず `ca_file` にその証明書を指定して
ください。ただし `ca_file` が解決するのは「発行者が信頼されていない」ことだけです。
証明書には、接続先の名前が subjectAltName（IP アドレスなら `IP:…`、名前なら `DNS:…`）
として入っていて、期限内である必要があります。名前を Common Name にしか持たない証明書
（`openssl req` の既定で作るとこうなります）は、誰が発行していても受け入れられません。
インスタンスの運用者に subjectAltName 付きの証明書を頼んでください。どれもできない
場合に限り `insecure_skip_verify = true` にします。このとき、通信経路上の第三者が
トークンを読めるようになります。起動のたびに警告が出て、`status` にも表示されます。
エラーの文面が、どの場合に当たるかを示します。

**平文の http** も受け付けます。同じく、トークンが暗号化されずに送られる旨を警告します。

## コマンド

```bash
opencti-lookup ioc 192.0.2.10 bad.example.com 491fc027…   # 最大 50 値
opencti-lookup search "Fancy Bear"                         # 名前・別名・ATT&CK ID の完全一致、無ければ全文検索
opencti-lookup search T1566 --type attack-pattern
opencti-lookup entity <id>
opencti-lookup related <id> --relationship uses --target-type Attack-Pattern
opencti-lookup reports <id>
opencti-lookup recent --days 7                             # このインスタンスに新しく入ったレポート
opencti-lookup recent --type indicator --by created --days 30
opencti-lookup file <id> fixture-report.pdf --out ~/cases/42   # 添付ファイルの保存（名前は entity の一覧どおり）
opencti-lookup status
```

`--json` で JSON を出します。フラグは引数の前後どちらに置いても構いません。一覧は
続きを取るための `--cursor` の行を表示します。

`recent --by` で日付の軸を選びます。`created_at`（既定）はこのインスタンスに取り込まれた
日時、`created` は出典が作った日時、`published` はレポートの公開日です。`file` は
`--out`（既定はカレントディレクトリ）に `opencti-lookup-<id>-<ハッシュ>-<安全な名前>` として
保存します。添付ファイル自身の名前は第三者の文字列なので、パスは一切残しません。ハッシュで、
名前が同じ形に縮む 2 つの添付も別のファイルになります。システムの場所、資格情報の
ディレクトリ、このツールの設定ディレクトリへの保存は拒否します。

### 終了コード

| コード | 意味 |
|---|---|
| 0 | 答えた（「見つからない」も空の一覧も答え） |
| 1 | インスタンスに問い合わせられなかった、または一部しか問い合わせられなかった（出力に `INCONCLUSIVE`） |
| 2 | 入力・設定の誤り、キーの拒否、権限の不足。`file` では、何も保存しなかったとき（このキーで見える添付が無い） |

## 答えの読み方

- **空の答えは「このキーで見える範囲には無い」です。** OpenCTI は「登録されていない」と
  「このキーでは見えない」を同じ形で返します。TLP:RED の物は、TLP:RED を持たない
  キーからは存在しないように見えます。キーで見える公開範囲は `status` で分かります。
- **判定はしません。** スコア・確度・公開範囲の印はインスタンスの値そのものです。確度は
  出典の値ではなく、取り込んだユーザーの既定値のことがあります。
- **indicator は減衰します。** OpenCTI は時間とともにスコアを下げ、`valid_until` を
  動かし、期限が来ると失効扱いにします。失効した indicator も表示し、現在のスコアと
  元のスコアを並べます。
- **値は別の形で保存されていることがあります。** 展開形で保存された IPv6、大文字の
  ドメインなども見つけ、`equivalent` と示します。
- **文章は第三者の記述です。** 名前・説明・パターン・ファイル名は、インスタンスに
  取り込んだ誰かが書いたものです。CLI は表示の前に制御文字を目に見える形に直します。

## MCP サーバ

```json
{
  "mcpServers": {
    "opencti-lookup": { "command": "/path/to/opencti-lookup", "args": ["mcp"] }
  }
}
```

`args` に `"--config", "/path/to/config.toml"` を足すと、クライアントごとに別の設定
（たとえば見える範囲の狭いキー）を渡せます。

ツール: `lookup_ioc`、`search_threats`、`get_entity`、`get_related`、`get_reports`、
`list_recent`、`get_report_file`、`server_status`、`get_usage`。`get_report_file` は
呼び出し側の作業ディレクトリ（`work_dir` 引数、無ければ要求の `_meta` の
`jp.nlink/work_dir`。組織 ADR-021）に書き、そのパスを返します。最初に `get_usage` を呼んでください。全体の説明と
エラーへの対処表を返します。結果は 128 KB まで丸ごと返し、長い一覧は `limit` で抑え、
総数は常に示します。128 KB を超えた結果は、切れ目のきれいな所（末尾の値・行・外部参照、または
いちばん長い文章）で詰め、何を詰めたかを `notes` に書きます。ページ送りのある一覧だけは、
詰めずに `limit` を下げるよう求めます。大きな結果をファイルに退避するのはクライアントの役目です
（gem-agent・lagent・Claude Code はいずれも行います）。CLI の `--json` は常に全体を返します。

## 開発

OpenCTI 6.7.4 で実測した振る舞いは [Phase 0 実測記録](docs/ja/opencti-lookup-phase0.ja.md)
にあります。実環境のテストの手順:

```bash
make dev-up                                  # Podman 上の OpenCTI 6.7.4（VM のメモリを約 5 GB 使う）
dev/seed/push.sh                             # 架空データ
python3 -I dev/seed/readonly_user.py         # 試験用の読み取り専用ユーザー
python3 -I dev/seed/attach.py                # レポートの添付ファイル
make e2e                                     # 実環境のテスト（トークンは dev/.env から読む）
make dev-down
```

MinIO の公開イメージは消えているので、`make dev-minio` が 6.7.4 の構成が固定して
いた版を公式ソースからビルドします。

## 文書

- [RFP](docs/ja/opencti-lookup-rfp.ja.md) — 設計の記録
- [Phase 0 実測記録](docs/ja/opencti-lookup-phase0.ja.md)
- [AGENTS.md](AGENTS.md) — 開発者・コーディングエージェント向け

## ライセンス

MIT。OpenCTI は Filigran の製品です。本ツールは Filigran と提携しておらず、
推奨も受けていません。
