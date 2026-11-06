# RFP: opencti-lookup

> Generated: 2026-11-06
> Status: Draft（Phase 0 の実測を反映済み — [opencti-lookup-phase0.ja.md](opencti-lookup-phase0.ja.md)）

## 1. Problem Statement

脅威分析を行うエージェントが参照できる情報源を増やすため、常時運用されている
OpenCTI インスタンスに蓄積された脅威インテリジェンス（indicator・observable・
レポート・攻撃者・intrusion set・マルウェア・ATT&CK 手法とそれらの関係）を、
MCP 経由で**読み取り専用**で検索できるようにする。otx-lookup・gti-lookup などの
外部インデックスと並ぶ情報源であり、問い合わせ先は自分たちが参照するインスタンスなので、
調査対象にパケットは届かない。

- **想定利用者**: 脅威分析を行うエージェント（gem-agent・lagent・Claude Code）とその操作者
- **利用者の事前準備**: OpenCTI の URL と、提供元から支給される読み取り用 API キーを
  設定ファイルに書くことだけ。OpenCTI 自体の構築・運用は利用者の負担にならない
  （本番インスタンスは別環境で常時稼働している）
- **利用環境**: 本番利用は開発機とは**完全に別の環境の Mac** から行う。開発機から
  本番インスタンスへは到達できない

## 2. Functional Specification

### Commands / API Surface

CLI と MCP サーバの二面を持ち、同じエンジンを共有する（兄弟の lookup 群と同じ構成）。
本番の Mac で問題が起きたとき、CLI で同じ問い合わせを打って切り分けられるようにする。

**Phase 1 の MCP ツール**

| ツール | 答える問い |
|---|---|
| `lookup_ioc` | IP・ドメイン・URL・ハッシュ・メールアドレスの値（複数可、上限あり）について、一致する observable と indicator を返す。**observable からと indicator からの両方で引き**、値ごとに束ねる（observable を持たない indicator がある）。score・confidence・labels・markings（TLP 等）・作成者・有効期間、sighting（いつ・どこで・何回観測されたか、誤検知としての目撃 `x_opencti_negative`）、それを含むレポートと `indicates` 等の関係先の要約を含む。**未登録は正常な結果**として返し、「このキーで見える範囲には無い」と表現する（未登録と不可視は区別できない） |
| `search_threats` | 攻撃者・intrusion set・campaign・malware・tool・attack pattern・vulnerability・report を検索する。**名前・別名・ATT&CK ID の完全一致を先に試し**（一致は複数件あり得る。ATT&CK ID は attack-pattern にしか使えない）、無ければ全文検索（関連度順・件数上限つき、総数は該当件数として見せない）。種別は enum で指定 |
| `get_entity` | 1 件の詳細（説明・別名・外部参照・markings・作成者・indicator ならパターン本文） |
| `get_related` | 1 件から関係をたどる。関係種別・相手種別（enum で検査）で絞り込み、件数指定とカーソルによるページ送り。起点の物は 1 度だけ返し、毎行に繰り返さない。関係ごとの説明文は既定で省き、引数で求められたときに付ける（APT28 の手法 93 件・約 78 KB のうち、説明文 32%・起点と相手の繰り返し 34%）。存在しない ID には 0 件ではなく not_found を返す |
| `get_reports` | その対象を含むコンテナ（report・note・grouping）の一覧。OpenCTI では関係ではなく収録（`objects`）なので `get_related` と分ける。入れ子の `containers` はページ送りできないので、ルートの `containers(filters: objects)` を使う |
| `server_status` | 接続確認。OpenCTI の版、検証済みの版（6.7.4）との一致、キーのユーザー名・capabilities・見える markings、TLS 検証の有無、平文の http か、実際に読んだ設定ファイルのパス |
| `get_usage` | エージェントが最初に読む操作説明（ツール・引数・エラーコード・引き方の例） |

**Phase 2 の MCP ツール**

| ツール | 答える問い |
|---|---|
| `list_recent` | 直近 N 日のレポートや indicator。日付の軸を選べる: 取り込まれた日時 `created_at`（既定、「このインスタンスに新しく入った物」）／出典の作成日時 `created`／公開日 `published`。型ごとに使える軸を検査する（型に無い軸はエラーにならず 0 件を返すため） |
| `get_report_file` | レポートの添付ファイル（PDF 等）を保存し、サイズ・種類と保存先を返す。作業場の概念を持たないので ADR-021 §5 に従い `<work_dir>` 直下に、サーバー名入りのファイル名で書く。結果には §6 の `work_dir`・`path`・`abs_path` を返す。ファイル名は第三者の文字列として扱い、保存名はツール側で作り直す |

ATT&CK 手法の一覧・標的業種・CVE を悪用する主体などは `get_related` の絞り込みで取れるため
専用ツールは作らず、`get_usage` に引き方の例として書く。

CLI のサブコマンドは各ツールに対応させる（名前は Phase 1 で兄弟ツールに揃えて決める）。
すべてのサブコマンド（`mcp` を含む）が `--config <path>` を受け付ける。

### Input / Output

- 結果は JSON。CLI はテキスト表示と `--json` を持つ
- **応答は全件を返し、明示的な上限を持つ**（ADR-021 §3）。件数上限は呼び出し引数と
  設定の既定値・上限で決め、上限に当たったら `truncated: true` と全体件数を計上する。
  黙って切り詰めない。大きな応答のファイル退避は呼び出し側のランタイムが行う
  （gem-agent ADR-0058、lagent ADR-0039、Claude Code の MCP 出力上限）
- 集約・参照リストも含めて**応答全体**に上限を引く（otx-lookup 162 KB の教訓）。上限は 3 段:
  1. 一覧の件数（呼び出し引数・設定の既定値と上限。OpenCTI の 1 ページの上限 5000 より小さくする）
  2. 長すぎる文字列（説明文など）は短縮し、短縮したことと元の長さを付ける
  3. 応答全体の天井。超えたら末尾の項目から落とし、落とした件数を計上する
- **欠けの判定は総数と受け取った件数の比較で行う**。OpenCTI は `first` が 5000 を超えると
  黙って 5000 件で切り、`hasNextPage` も false にする（`hasNextPage` は信用しない）
- どの結果にも markings・作成者・confidence を付ける。**判定（悪性/無害）は作らない**。
  OpenCTI の score はそのまま渡す
- エラーは構造化（`{code, message}`）。権限不足（`forbidden`）・認証失敗・未登録・
  接続失敗・版不一致を区別する
- **OpenCTI のエラーはほとんどが HTTP 200** で、種類は本文の `errors[].extensions.code`
  （`AUTH_REQUIRED`・`FORBIDDEN_ACCESS`・`FUNCTIONAL_ERROR`・`UNSUPPORTED_ERROR`・`DATABASE_ERROR`・
  `GRAPHQL_PARSE_FAILED`・`GRAPHQL_VALIDATION_FAILED` 等）に出る。HTTP 状態と `extensions.code` の
  両方で振り分ける。ストレージは `HTTP 503` + `File not found or restricted` を「無い、または見えない」、
  `HTTP 403` を認証の失敗として返すので、どちらも接続障害と区別する
- `extensions.cause` などの内部情報（Elasticsearch の照会本文・内部 ID を含む）は利用者に渡さない
- **部分的な成功を完全な答えにしない**。`errors` が 1 件でもあれば構造化エラーとして返す
  （権限の無い欄だけが `null` になり、ほかの欄は返ることがある）
- **黙って 0 件を返す誤入力を事前に止める**。存在しない ID・存在しない型名・型に無い日付の軸は、
  OpenCTI ではエラーにならず 0 件が返る。送る値は enum と範囲で検査し、ID を受け取るツールは
  対象の存在を先に確かめて、無ければ not_found を返す
- 失敗した問い合わせを「該当なし」として返さない

**CLI の終了コード**（兄弟の lookup 群と同じ）

| コード | 意味 |
|---|---|
| 0 | 問い合わせに答えた（空の答えも正しい答え） |
| 1 | 上流の失敗で一部を問い合わせられなかった（出力に `INCONCLUSIVE`、成功した分は表示） |
| 2 | 入力・設定の誤り |

空の結果を「該当なし」と表示するのは、すべての問い合わせが成功したときだけ。

**`lookup_ioc` の照会規則**（Phase 0 の実測による）

- **2 つの経路で引いて値ごとに束ねる**
  - observable: `stixCyberObservables` の `value`（ハッシュは `hashes.<アルゴリズム>`）の完全一致（`eq`）
  - indicator: `indicators` の `pattern` に値を含む物（`contains`）を候補として引き、返ったパターンを
    ツール側で解析して、値が完全に一致するものだけを残す（`contains` は部分一致で当たる）。
    observable を持たない indicator はこの経路でしか見つからない
- 全文検索は前方一致のように当たるので使わない
- **OpenCTI は保存時に値を正規化しない**。IPv4 / IPv6 は入力どおりの形と `net/netip` の正規形
  （IPv6 は展開形も）のすべてを `or` で問い合わせる。大文字小文字は OpenCTI 側が区別しない
  （URL のパス部分も区別しない）
- 入力と違う形で一致したとき（大文字小文字・IP の表記）は、一致した保存形をその旨とともに返す
- ハッシュは長さで MD5（32）/ SHA-1（40）/ SHA-256（64）/ SHA-512（128）を判別する（`value` では当たらない）
- 複数値の照会では、返った物を正規化した値で入力に突き合わせる
- sighting は indicator と observable の ID の配列で `stixSightingRelationships(filters: fromId)` を 1 回引く
- **decay を解釈せずに渡す**。OpenCTI は indicator の `valid_until`・`x_opencti_score`・`revoked` を
  減衰規則で書き換える。失効した indicator も隠さず、`revoked`・現在の点数・`decay_base_score`・
  `valid_until` を並べる。observable と indicator の点数は別物として返す
- confidence は出典の値とは限らない（取り込んだユーザーの既定値で埋まることがある）と `get_usage` に書く
- MCP のツールスキーマは閉じる（`additionalProperties: false`）

### Configuration

- 既定の場所は次の順に探し、最初に存在したものを使う（knowledge config-and-io）:
  `$XDG_CONFIG_HOME/opencti-lookup/config.toml` → `~/.config/opencti-lookup/config.toml` →
  `~/Library/Application Support/opencti-lookup/config.toml`。`server_status` と CLI の診断は
  実際に読んだパスを表示し、無ければ探したパスの一覧を出す
- 設定ファイルの権限が 0600 でなければ、標準エラーに警告する（CONVENTIONS）
- `--config <path>` で切り替え可能。**明示したファイルが存在しなければ、そのパスを
  名指ししてエラーで止める**（兄弟ツールは黙って「設定なし」として進むが、本番環境での
  切り分けを難しくするため変える）。既定の場所に無いのは問題にしない
- 優先順位: フラグ > 環境変数（`OPENCTI_LOOKUP_*`） > 設定ファイル > 既定値
- 設定項目
  - `url`（必須）。`https://` を推奨するが、**`http://` も受け付ける**（利用者の判断）。
    平文の http では、トークンが暗号化されずに送られる旨を CLI が起動時に 1 行警告し、
    `server_status` も報告する（CONVENTIONS「資格情報を平文 HTTP で送るツールは警告する」）
  - `token`（必須。`OPENCTI_LOOKUP_TOKEN` でも可。表示・ログ・URL に出さない）
  - `ca_file`（自己署名・社内 CA の証明書を信頼する）
  - `insecure_skip_verify`（既定 false。`--insecure` でも可）
  - タイムアウト、既定の件数・上限
- 設定ファイルは資格情報を含むため `.gitignore` 対象。`config.example.toml` を同梱
- キャッシュは持たない（自インスタンスに利用回数上限はなく、connector が継続的に
  更新しているので古い答えの害が大きい）

### External Dependencies

- OpenCTI 6.7.4 の GraphQL API（`/graphql`、`Authorization: Bearer <token>`）のみ
- 開発用: Podman 上の OpenCTI 6.7.4 一式（platform・worker・Elasticsearch・Redis・
  RabbitMQ・MinIO・STIX 取り込み connector・MITRE connector）。MinIO は公式イメージが
  消えたため、6.7.4 の構成が固定していた版を公式ソースから自前でビルドする

## 3. Design Decisions

- **言語は Go、標準ライブラリのみ**。兄弟の lookup 群と揃える。pycti（Filigran 公式）は
  Python 用で、Go からは GraphQL を net/http で直接呼ぶ
- **組織の共通部品を使う**
  - 設定ファイルの読み込みは `nlink-jp/toml`（ADR-026）
  - リリース・署名の配線は CONVENTIONS のテンプレートの写しで行う（ADR-028 の共通キット案は
    取り下げ済みで、写しの方式が現行）
  - `get_report_file` のパス判定は `nlink-jp/pathguard`（ADR-022、ADR-021 §4・§7・§10 の改訂）
  - MCP の骨格は最新の兄弟（パッケージ単位の `git log` で選ぶ）から移植
- **既製の OpenCTI MCP サーバは採用しない**。Filigran 公式の MCP サーバは見つからず、
  コミュニティ製（DarkAngel-agents/opencti-mcp、MIT）のみだったため、組織のサプライチェーン
  方針に従い自前で実装する
- **補完する既存ツール**: otx-lookup・gti-lookup（外部の脅威インテリジェンス）、
  cve-lookup（脆弱性の深刻度・悪用状況。OpenCTI 側では重複させない）
- **制御の置き場所**: 何が見えるかはキー（OpenCTI のユーザー・グループ）が決める。
  ツール側で markings による絞り込みはしない
- **TLS 検証の無効化は、理由つきで受け入れた危険**。本番インスタンスは自己ホスティングで
  証明書が正しく整っていない。検証を切ると経路上の第三者にトークンを盗まれ得るが、
  利用者の環境内の経路であり、利用者の判断で受け入れる。既定は検証あり。まず `ca_file` を
  試すことを README で案内する。有効時は `server_status` が報告し、CLI は起動時に 1 行警告
  する（毎回の結果には付けない）
- **範囲外（恒久）**
  - 書き込みのすべて（エンティティ・関係の作成、エンリッチメントの起動、ケース作成）
  - リアルタイムストリーム（SSE）
  - 自組織のインシデント対応ケース・RFI の読み取り
  - STIX バンドルの一括エクスポート

## 4. Development Plan

### Phase 0: 開発環境と実測（コードより先）— 2026-11-06 実施済み

結果は [opencti-lookup-phase0.ja.md](opencti-lookup-phase0.ja.md)。以下は計画時の内容。

- OpenCTI 6.7.4 の開発用環境を、リポジトリ内の compose ファイルと `make dev-up` /
  `make dev-down` で起動・停止できるようにする（公式 docker 構成を元にする）
- 起動確認: Podman machine（16 GB）で全体が起動するか。MITRE connector（6.7.4 は amd64 のみ）
  が qemu エミュレーションで動いて取り込めるか
- 実測して記録するもの（ADR-023）
  - 各ツールに使う GraphQL クエリと実際の応答の形
  - IOC 値の完全一致での引き方（全文検索ではなくフィルタで）
  - 1 回の問い合わせで取れる件数の上限
  - 添付ファイルの取得経路と必要な capability
  - `me` で取れる capabilities・markings
- 開発用環境に本番と同じ形の読み取り専用ユーザーを作る
- **レビュー点**: 実測結果を確認してから Phase 1 に進む。ここで設計を確定し、
  サブエージェントによる独立検証を行う

### Phase 1: 中核機能とテスト

- config（`--config`・`ca_file`・`insecure_skip_verify`）、GraphQL クライアント、
  エンジン、Phase 1 の 7 ツール、CLI
- オフラインテスト（`make test`）: 開発用環境から採った応答をフィクスチャにし、
  `httptest` サーバに対して実行。TLS は自己署名の `httptest.NewTLSServer` で、
  検証あり失敗・`ca_file` で成功・`insecure` で成功を確かめる。`usage.md` と
  コードの一致をメタテストで固定する
- 実環境テスト（`make e2e`、`e2e` ビルドタグ）: 開発用コンテナに対して実行

### Phase 2: 追加機能

- `list_recent`
- `get_report_file`（ADR-021 の `work_dir` 契約、pathguard）

### Phase 3: 文書とリリース

- README.md / README.ja.md、AGENTS.md、CHANGELOG.md
- リリース（署名・公証・zip・Homebrew tap）、cybersecurity-series への組み込み、
  org profile 更新、knowledge への還元、check-org
- リリース前のサブエージェント独立検証
- **本番確認**: 本番の Mac で利用者が `server_status` と数件の照会を実行し、結果
  （とくに capabilities・markings）を記録する。開発機から本番に届かないため、
  ここは利用者の作業になる

### 独立してレビューできる区切り

Phase 0 の実測記録、Phase 1、Phase 2、Phase 3 はそれぞれ独立にレビューできる。

### この計画に含めないもの

- mcp-tactics スキルへの追記（skills-series 側の作業）。リリース時に skills-series に
  issue を起こし、そちらで判断する

## 5. Required API Scopes / Permissions

- **提供元から支給される読み取り用 API キー 1 本**。利用者はユーザーやグループを作れず、
  キーで何が見えるかは提供元が決める
- LLM（クラウド・ローカルとも）へ結果を送ることは利用者が了承済み
- ツールはキーの権限を何も前提にしない
  - 権限不足は構造化エラー `forbidden` として返し、「該当なし」と区別する
  - `server_status` がキーのユーザー名・capabilities・見える markings を返す
- 開発用環境では、本番で `server_status` が返した capabilities を写した読み取り専用
  ユーザーを作って試験する
- 開発用環境の読み取り専用ユーザー（ロールは `KNOWLEDGE` のみ）で、`about`・`me`・知識の照会・
  添付ファイルの一覧と取得（`/storage/get/`）がすべて通ることを確認済み。管理用の照会と書き込みは
  `FORBIDDEN_ACCESS`
- **残る危険**: 本番の支給キーの権限は開発用の形と同じとは限らない。とくに `get_report_file` が
  使えるかは本番確認（Phase 3）で確かめる。使えなければ `forbidden` を返す機能になる

## 6. Series Placement

Series: cybersecurity-series
Reason: 脅威インテリジェンスを読み取り専用で照会する lookup 群（otx-lookup・gti-lookup・
cve-lookup 等）と同種のツールであり、命名もそれに揃える。

## 7. External Platform Constraints

- **版への依存**: GraphQL スキーマは OpenCTI の版で変わる。検証対象は本番と同じ 6.7.4 のみ。
  `server_status` が版の不一致を警告する
- **Phase 0 で実測した事項**（詳細は実測記録）
  - 1 ページの上限は 5000 件。超えて頼むと黙って 5000 件で切られ、`hasNextPage` も false になる。
    負の `first` は `DATABASE_ERROR`
  - スキーマ全体の introspection（`__schema`）は HTTP 500 で拒否される（`__type` は通る）。
    スキーマは OpenCTI リポジトリの 6.7.4 タグから読む（indicator など一部の型は `src/modules/` 側にしか無い）
  - エラーはほとんど HTTP 200 で `extensions.code` に出る。ストレージは「無い/見えない」を 503、
    認証の失敗を 403 で返す
  - 存在しない ID・型名・型に無い絞り込みの軸は、エラーにならず 0 件を返す
  - OpenCTI は保存時に値を正規化しない（展開形で保存された IPv6 は正規形では当たらない）
  - 「未登録」と「このキーでは見えない」は区別できない
  - 全文検索は関連度順で、総数は該当件数として使えない
- **問い合わせ回数の制限**: OpenCTI 本体の既定の制限は未確認。前段のリバースプロキシで
  制限される可能性もあるため、429 等は構造化エラーで返す
- **connector のイメージ**: platform・worker の 6.7.4 は amd64/arm64 の両方があるが、
  MITRE connector の 6.7.4 は amd64 のみ（2026-11-06 に Docker Hub で確認）。
  開発用環境では qemu で動かす（Podman machine は Rosetta 無効・qemu-x86_64 登録済み）
- **接続経路**: 本番の Mac から本番インスタンスへの経路は開発機から確認できない。
  自己署名・不完全な証明書のため `ca_file` と `insecure_skip_verify` を用意する
- **データは第三者の記述を含む**: OpenCTI の内容は外部フィードやレポートから取り込まれた
  文章であり、誰が書いたものでも入り得る。指示に見える文章もデータとして扱うよう
  `get_usage` に明記する
- **開発機の制約**: Podman machine は data-toolbox-mcp・pcap-analyzer-mcp と共用。
  16 GB（VM 内で利用可能 約 14 GB）・6 CPU・`vm.max_map_count = 1048576`（既定で十分）。
  開発用環境の稼働中は約 5 GB を使う
- **開発用環境の部品**: minio/minio は 2026-04-24 にアーカイブされ、公開イメージは取得できない。
  OpenCTI 公式の compose はコミュニティ製フォーク（pgsty/silo）に移ったが、本プロジェクトは
  公式ソースから自前でビルドする。podman-compose は取得できないイメージでエラーを出さずに止まる
- **worker は拒否された要素を記録せずに再試行する**。架空データの投入が遅いときは、まず
  投入データが拒否されていないかを疑う（実例: `x_opencti_main_observable_type` は OpenCTI の
  型名 `IPv4-Addr` を要求し、STIX 綴りは拒否される）

---

## Discussion Log

1. **実現可能性**: Podman での OpenCTI 開発環境は公式ドキュメントで対応が明記されている。
   当初の懸念は arm64 イメージの有無とメモリ。`podman manifest inspect` で platform・
   worker・MITRE connector の latest に arm64 があることを確認した
2. **用途の向き**: 「OpenCTI から検索」か「OpenCTI へ投入」かを確認し、検索（読み取り）に決定
3. **インスタンスの所在**: 本番は別環境で常時稼働しているインスタンス。開発用コンテナは
   試験専用。OpenCTI 自体の運用負担は利用者にかからないため、準備の重さ
   （gdrive-collector の中止理由）は問題にならないと判断した
4. **版**: 本番は 6.7.4（利用者が確認）。開発用環境を揃える。6.7.4 の platform・worker は
   arm64 ありだが MITRE connector は amd64 のみと判明。新しい connector を古い platform と
   組み合わせる案は版を揃える目的に反するため却下し、qemu エミュレーションを採った
5. **利用環境**: 本番利用は完全に別環境の Mac から。配布はリリース zip / Homebrew tap。
   本番での確認は利用者が行う
6. **ツール名**: `opencti-lookup`（兄弟の lookup 群に揃える）。`opencti-mcp` も候補だった
7. **機能の追加検討**: 利用者の「他に提供できる機能は」に応じて洗い出した。sighting と
   複数値照会を Phase 1 の `lookup_ioc` に、`list_recent` を Phase 2 に採用。ATT&CK・標的・
   CVE 悪用主体は `get_related` で足りるため専用ツールにしない
8. **大きな応答**: 当初「大きいので添付ファイルは対象外」としたが、利用者の指摘どおり
   サーバ側スピルは廃止方針で、退避はランタイムが担う（ADR-021 §3）。gem-agent・lagent・
   Claude Code の 3 つとも退避機構を持つことを確認した（Claude Code は 25,000 トークン /
   50,000 文字超を成功結果のみファイル化）。添付ファイルは「産物がファイル」なので
   `work_dir` 契約で Phase 2 に入れた
9. **ADR-021 の有効性**: 利用者の問いを受けて確認。Accepted のままで、ADR-022 が §4・§7・§10 を
   改訂しているのみ。§3 は有効
10. **キャッシュ・CLI**: キャッシュなし、CLI と MCP の両面で確定
11. **権限**: キーは提供元から支給され利用者は作れない。LLM へ送ることは了承済み。
    ツールは権限を前提にせず、`server_status` で何ができるかを示す
12. **`--config`**: 利用者の提案で採用。兄弟ツール（gti-lookup・shodan-lookup）に揃えるが、
    明示パスが無いときは黙って進まずエラーにする点を変えた。兄弟側の同じ挙動は本件の範囲外
13. **TLS 検証の無効化**: 自己ホスティングで証明書が整っていないため利用者が要望。
    トークン漏洩の危険を理由つきで受け入れ、既定は検証あり・`ca_file` を先に案内する形にした
14. **MinIO の代替**（Phase 0）: 公式イメージの消失を受け、OpenCTI 公式が採ったコミュニティ製フォーク
    （digest 固定で使う案）と、公式ソースからの自前ビルドを比べ、利用者の判断で自前ビルドにした
15. **Phase 0 の反映**: 実測記録の「RFP への反映候補」7 項目を利用者の承認で反映した
    （エラー分類、`lookup_ioc` の照会規則と decay、`search_threats` の完全一致優先、
    `get_related` の説明文省略、`list_recent` の日付の軸、権限の確認結果、外部の制約）
16. **独立検証**（設計確定時）: サブエージェントが実測を応答と実環境から数え直し、記録済みの教訓と
    突き合わせた。指摘のうち重いもの（1 ページの上限 5000 で黙って切られ `hasNextPage` も偽になる、
    取り下げ済みの ADR-028 を根拠にしていた）を含め、全件を応答の採り直しで確かめたうえで採用した。
    実測記録は第 2 版として訂正し（同記録 §11）、RFP には次を加えた: 2 経路の照会と保存形の扱い、
    応答の 3 段の上限と欠けの判定、エラー分類の拡張と内部情報の秘匿、誤入力の事前検査、
    CLI の終了コード、設定ファイルの探索順と 0600 警告、`get_report_file` の ADR-021 §5・§6 への準拠
17. **平文 http**: 検証者は shodan-lookup に倣ってループバック以外の http を拒否する案を出したが、
    利用者の判断で受け付け、警告する形にした（CONVENTIONS が求めるのは警告）
