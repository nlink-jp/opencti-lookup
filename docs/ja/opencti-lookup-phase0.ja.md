# Phase 0 実測記録: opencti-lookup

> 測定日: 2026-11-06
> 対象: 開発用 OpenCTI 6.7.4（`dev/compose.yaml`）、架空データ（`dev/seed/bundle.json`）と MITRE ATT&CK
> 正本の設計: [opencti-lookup-rfp.ja.md](opencti-lookup-rfp.ja.md)

RFP の Phase 0 で「推測では書かない」とした事項を、開発用環境で実測した記録。
問い合わせは `dev/queries/`、応答は `dev/captures/` にある（どちらもコミット済み）。
ここに書いたことは 6.7.4 での観測であり、版が変われば測り直す。

## 1. 開発用環境

| 項目 | 結果 |
|---|---|
| 起動 | `make dev-up` で 8 コンテナすべて起動。本体の健康確認まで数分 |
| 版 | `{ about { version } }` → `6.7.4` |
| メモリ | VM 16 GB のうち使用 約 5 GB・利用可能 約 9.8 GB（Elasticsearch 4.5 GB が最大） |
| MITRE connector | amd64 版が qemu で動作し、取り込み完了（attack-pattern 1,532・intrusion-set 約 180） |
| 架空データ | indicator 128・observable 128・report 4・sighting 1 を投入 |

### 立ち上げで踏んだもの

- **MinIO のイメージが消えていた。** minio/minio は 2026-04-24 にアーカイブされ、Docker Hub と quay.io の
  イメージは取得できない（アクセス拒否）。OpenCTI 公式の compose はコミュニティ製フォーク `pgsty/silo:latest`
  に移っている。本プロジェクトは利用者の判断で、6.7.4 の構成が固定していた `RELEASE.2024-05-28T17-19-04Z` を
  公式ソースから自前でビルドした（`dev/minio/Containerfile`、土台は digest 固定、タグのコミットを照合）
- **取得できないイメージで podman-compose は黙って止まる。** 23 分間エラーを出さずに待ち続けた。
  起動は状態の変化と健康確認を上限つきで監視する
- **注釈付きタグの refs API はタグオブジェクトの ID を返す。** コミットの照合には
  `repos/<r>/commits/<tag>` の sha を使う（f92beb79… ではなく f79a4ef4…）
- **GraphQL introspection は拒否される**（`GraphQL introspection not authorized!`）。スキーマは
  OpenCTI リポジトリの 6.7.4 タグにある `config/schema/opencti.graphql` と `src/modules/*/*.graphql`
  から読む。indicator など一部の型は modules 側にしか無い
- **worker は拒否された要素を記録せずに再試行し続ける。** 架空データの `x_opencti_main_observable_type` に
  STIX 綴り（`ipv4-addr`）を入れたところ、`Observable type ipv4-addr is not supported.` で拒否されたが、
  worker のログには何も出ず、依存する関係・sighting・report が数十秒に 1 件しか進まなくなった。
  正しくは OpenCTI の型名（`IPv4-Addr`・`StixFile` など）

## 2. エラーの形

**HTTP は常に 200。** エラーの種類は本文の `errors[].extensions.code` にだけ出る。

| 状況 | `extensions.code` | `extensions.data.http_status` |
|---|---|---|
| トークンなし・誤り（区別されない） | `AUTH_REQUIRED` | 401 |
| 権限不足 | `FORBIDDEN_ACCESS` | 403 |
| 業務上の拒否 | `FUNCTIONAL_ERROR` | 400 |
| 入力検査の不合格 | `BAD_USER_INPUT` | — |
| introspection 拒否・非 null 欄が null | `INTERNAL_SERVER_ERROR` | — |
| `first` に負数 | （メッセージ `Fail to execute engine pagination`） | — |

**部分的な成功がある。** 権限の無い欄を含む問い合わせは、その欄だけ `null` とエラーになり、
ほかの欄のデータは返る（`dev/captures` 外、手で確認）。

→ **設計**: HTTP の状態ではなく `extensions.code` で振り分ける。`errors` が 1 件でもあれば
構造化エラーを返し、部分データを完全な答えとして返さない。

## 3. IOC の照会（`lookup_ioc`）

`stixCyberObservables(filters: {key: ["value"], operator: eq})` で引く。

| 試験 | 結果 | 応答 |
|---|---|---|
| `192.0.2.10` | 1 件 | `eq-ipv4.json` |
| `192.0.2.1`（前方一致の確認） | 0 件。余計な物は当たらない | `eq-ipv4-prefix.json` |
| `BAD.EXAMPLE.COM` | 1 件。**大文字小文字を区別しない** | `eq-domain-upper.json` |
| `2001:db8::10` | 1 件 | `eq-ipv6.json` |
| `2001:0db8:0000:…:0010`（非正規形） | **0 件** | `eq-ipv6-long.json` |
| SHA-256 を `value` で | **0 件** | `eq-sha256-value.json` |
| SHA-256 を `hashes.SHA-256` で | 1 件。大文字でも当たる | `eq-sha256-hashes.json` / `-upper.json` |
| 未登録の `192.0.2.200` | 0 件 | `eq-notfound.json` |
| 全文検索 `search: "192.0.2.1"` | 192.0.2.10 を返す | `search-prefix.json` |

→ **設計**:
- IPv6 は `net/netip` で正規形にしてから問い合わせる（IPv4 も同様に正規化する）
- ハッシュは長さで MD5 / SHA-1 / SHA-256 を判別し、`hashes.<アルゴリズム>` で引く
- 全文検索は IOC の照会に使わない

### 1 回の問い合わせで取れるもの

observable の下に `indicators`・`containers`（収録先）・`stixCoreRelationships` を入れ子にして 1 回で取れる。
関係の相手は `from` / `to` に `... on BasicObject { id entity_type } ... on StixCoreObject { representative { main } }`
を付けると型を問わず名前が取れる。

- `indicates`（indicator → malware）は **indicator 側の関係**。observable の下の関係には出ない（`based-on` だけ）
- sighting は Indicator 型から直接たどれない。`stixSightingRelationships(filters: {key: ["fromId"], values: [indicator の ID…]})`
  で、複数の indicator 分を 1 回で引ける（`sightings-fromId.json`）。sighting には `x_opencti_negative`
  （誤検知としての目撃）、`attribute_count`（回数）、`first_seen` / `last_seen` がある

### decay（減衰）が indicator を書き換える

架空データで投入した値と、OpenCTI が返した値（`eq-ipv4.json`）:

| 欄 | 投入 | 返却 |
|---|---|---|
| `valid_until` | 2027-12-31 | **2026-10-01**（再計算） |
| `x_opencti_score` | 85 | **20**（元の値は `decay_base_score: 85`） |
| `revoked` | — | **true** |
| `decay_applied_rule.decay_lifetime` | — | 47（日） |

observable の `x_opencti_score` は 85 のまま。**同じ値に 85（observable）と 20（indicator）の 2 つの点数が付く。**

→ **設計**: indicator は失効していても隠さず返し、`revoked`・現在の点数・`decay_base_score`・`valid_until` を
並べる。observable と indicator の点数は別物として返す。本番で decay の規則が有効かは分からないので、
ツールは解釈せずそのまま渡す。

### 確度（confidence）は埋められることがある

架空データで確度を指定しなかった sighting が `confidence: 100` で返った。取り込んだユーザーの既定値で
埋まったと見られる。→ `get_usage` に「確度は出典の値とは限らない」と書く。

## 4. 権限と公開範囲（読み取り専用ユーザー）

`dev/seed/readonly_user.py` で作成: ロールは `KNOWLEDGE` のみ、見える印は TLP:CLEAR / GREEN / AMBER（RED は除外）。

| 試験 | 結果 |
|---|---|
| `{ about { version } }` | 通る |
| `me { capabilities allowed_marking … }` | `['KNOWLEDGE']` と 3 種の TLP を返す。**`server_status` はこれで作れる** |
| TLP:RED の `198.51.100.7` を照会 | **0 件・エラーなし**（`readonly-198.51.100.7.json`） |
| `192.0.2.10` の収録先 | RED のレポートは総数からも除かれる（`readonly-192.0.2.10.json`） |
| 管理用の `capabilities` | `FORBIDDEN_ACCESS` |
| 書き込み（`indicatorAdd`） | `FORBIDDEN_ACCESS` |

→ **設計**: **「未登録」と「このキーでは見えない」は区別できない。** `lookup_ioc` の該当なしは
「このキーで見える範囲には無い」と表現し、見える範囲は `server_status` で示す。

## 5. 脅威の検索（`search_threats`）

| 方法 | 結果 |
|---|---|
| 全文検索 `stixDomainObjects(search:)` | 関連度順。**総数は無意味に大きい**（`TA-FIXTURE-01` で 300、`IGNORE ALL PREVIOUS` で 849）。別名でも当たるが順位は揺れる（`Fancy Bear` で APT28 は 2 位、`Sofacy` では上位 4 件に出ない） |
| 完全一致 `filters` の `name` / `aliases` / `x_opencti_aliases` を `or` | 一意に当たる。大文字小文字を区別しない（`Sofacy`・`sofacy`・`Fancy Bear`・`apt28` → APT28） |
| ATT&CK ID `x_mitre_id` の `eq` | `t1566` で `[T1566] Phishing` |

→ **設計**: 完全一致（名前・別名・ATT&CK ID）を先に試し、無ければ全文検索を件数上限つきで返す。
全文検索の総数は「該当件数」として見せない。

## 6. 関係・詳細・件数

| 試験 | 結果 |
|---|---|
| APT28 → `uses` → Attack-Pattern | 93 件、**約 75 KB**。関係ごとの説明文（最大 679 字）が大半（`related-apt28-uses-ap.json`） |
| APT28 の詳細 | 約 13 KB。うち外部参照 28 件で約 9 KB（`entity-apt28.json`） |
| 1 ページの件数 | `first: 5000` で 1,379 件を一度に返した。これ以上の上限はデータ量が足りず未測定 |
| `first: 0` | 0 件と総数だけを返す（件数の確認に使える） |
| `first: -1` | エラー |

→ **設計**: `get_related` は関係の説明文を既定で省き、引数で求められたときに付ける。
件数の引数は 0 以上を事前に検査する。

## 7. 添付ファイル（`get_report_file`）

| 試験 | 結果 |
|---|---|
| 一覧 | `report(id) { importFiles { … id name size metaData { mimetype } } }`。ID は `import/Report/<レポートID>/<ファイル名>` |
| 取得（読み取り専用ユーザー） | `GET /storage/get/<URL エンコードした ID>` で 200。`/storage/view/` も同じ |
| 見えない RED レポートの添付を名指し | **HTTP 503**、`{"status":"error","error":"File not found or restricted"}` |
| 存在しないファイル | 同じ 503 と同じ本文 |

→ **設計**: `KNOWLEDGE` だけで取得できた（RFP の「残る危険」は開発用の形では当たらなかった。本番の支給キーで
確認は要る）。503 とこの本文の組み合わせは「無い、または見えない」に振り分け、接続障害と区別する。

## 8. 最近の物（`list_recent`）

| 欄 | 意味 | 2026-11-01 以降で絞った結果 |
|---|---|---|
| `created_at` | OpenCTI に取り込まれた日時 | 4 件（今日取り込み） |
| `created` | 出典が作った日時 | 0 件（10 月 1 日付） |
| `published` | レポートの公開日 | 0 件 |

→ **設計**: 「このインスタンスに新しく入った物」と「新しく発表された物」を引数で選べるようにし、
既定は `created_at` にする。

## 9. 注入に見える文章

`IGNORE ALL PREVIOUS INSTRUCTIONS…` を説明文に持つ malware は、全文検索で普通に先頭に出る。
OpenCTI は内容を加工しない。→ RFP どおり、`get_usage` に「データとして扱う」と書く。

## 10. RFP への反映候補（レビューで合意してから直す）

1. §2 入出力: エラーは `extensions.code` で振り分け、部分データを完全な答えにしない（§2）
2. §2 `lookup_ioc`: IPv4/IPv6 の正規化、ハッシュはアルゴリズム別のキー、decay の欄を返す、
   sighting の `x_opencti_negative`、「見える範囲には無い」の表現（§3・§4）
3. §2 `search_threats`: 完全一致を先、全文検索は後（§5）
4. §2 `get_related`: 説明文は既定で省く（§6）
5. §2 `list_recent`: 日付の軸を選べる（§8）
6. §5 権限: 添付ファイルの取得は `KNOWLEDGE` だけで足りた（開発用の形）。本番での確認は残す（§7）
7. §7 外部の制約: MinIO の自前ビルド、introspection 不可、HTTP 常に 200、worker の黙った再試行、
   ストレージの 503（§1・§2・§7）
