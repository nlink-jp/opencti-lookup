# Phase 0 実測記録: opencti-lookup

> 測定日: 2026-11-06（第 2 版: 独立検証の指摘を受けて採り直し）
> 対象: 開発用 OpenCTI 6.7.4（`dev/compose.yaml`）、架空データ（`dev/seed/`）と MITRE ATT&CK
> 正本の設計: [opencti-lookup-rfp.ja.md](opencti-lookup-rfp.ja.md)

RFP の Phase 0 で「推測では書かない」とした事項を、開発用環境で実測した記録。

- **再現の手順**: `make dev-up` → `dev/seed/push.sh` → `python3 -I dev/seed/readonly_user.py` →
  `python3 -I dev/seed/attach.py` → `python3 -I dev/capture.py`
- **根拠**: 各主張の「根拠」欄は `dev/captures/<名前>.json`。どのファイルにも問い合わせ・変数・
  実行ユーザー・HTTP 状態・応答と、加工した場合はその内容（`trimmed`）が入っている
- ここに書いたことは 6.7.4 での観測であり、版が変われば測り直す

## 1. 開発用環境

| 項目 | 結果 |
|---|---|
| 起動 | `make dev-up` で 8 コンテナすべて起動。本体の健康確認まで数分 |
| 版 | `about.version` = `6.7.4`（根拠: `me-admin`） |
| メモリ | VM 16 GB のうち使用 約 5 GB・利用可能 約 9.8 GB（Elasticsearch 4.5 GB が最大） |
| MITRE connector | amd64 版が qemu で動作し、取り込み完了（attack-pattern 1,532・intrusion-set 190） |
| 架空データ | indicator 130・observable 130・report 4・note 1・grouping 1・sighting 3・vulnerability 1 |

### 立ち上げで踏んだもの

- **MinIO のイメージが消えていた。** minio/minio は 2026-04-24 にアーカイブされ、Docker Hub と quay.io の
  イメージは取得できない（アクセス拒否）。OpenCTI 公式の compose はコミュニティ製フォーク `pgsty/silo:latest`
  に移っている。本プロジェクトは利用者の判断で、6.7.4 の構成が固定していた `RELEASE.2024-05-28T17-19-04Z` を
  公式ソースから自前でビルドした（`dev/minio/Containerfile`、土台は digest 固定、タグのコミットを照合）
- **取得できないイメージで podman-compose は黙って止まる。** 23 分間エラーを出さずに待ち続けた。
  起動は状態の変化と健康確認を上限つきで監視する
- **注釈付きタグの refs API はタグオブジェクトの ID を返す。** コミットの照合には
  `repos/<r>/commits/<tag>` の sha を使う（f92beb79… ではなく f79a4ef4…）
- **スキーマ全体の introspection（`__schema`）は HTTP 500 で拒否される**（本体のログには
  `GraphQL introspection not authorized!`、応答は `INTERNAL_SERVER_ERROR`。根拠: `err-introspection-schema`）。
  型ひとつの `__type(name:)` は通る（根拠: `err-introspection-type`）。スキーマは OpenCTI リポジトリの
  6.7.4 タグにある `config/schema/opencti.graphql` と `src/modules/*/*.graphql` から読む。indicator など
  一部の型は modules 側にしか無い
- **worker は拒否された要素を記録せずに再試行し続ける。** 架空データの `x_opencti_main_observable_type` に
  STIX 綴り（`ipv4-addr`）を入れたところ、`Observable type ipv4-addr is not supported.` で拒否されたが、
  worker のログには何も出ず、依存する関係・sighting・report が数十秒に 1 件しか進まなくなった。
  正しくは OpenCTI の型名（`IPv4-Addr`・`StixFile` など）
- **sighting の対象に observable を指定しても受け付けられる**（STIX 2.1 の仕様外だが取り込まれた。
  根拠: `sightings-of-observable`）

## 2. エラーの形

ほとんどのエラーは **HTTP 200** で返り、種類は本文の `errors[].extensions.code` に出る。例外として
`__schema` は HTTP 500、ストレージ（§7）は 403 / 503 を返す。

| 状況 | HTTP | `extensions.code` | 根拠 |
|---|---|---|---|
| トークンなし・誤り（区別されない） | 200 | `AUTH_REQUIRED` | `err-no-token`・`err-bad-token` |
| 権限不足（読み取り・書き込みとも） | 200 | `FORBIDDEN_ACCESS` | `err-forbidden-read`・`err-forbidden-write` |
| 業務上の拒否 | 200 | `FUNCTIONAL_ERROR` | 架空データ修正時に手で確認（§1） |
| 未知の絞り込みキー | 200 | `UNSUPPORTED_ERROR` | `err-unknown-filter-key` |
| 負の `first` | 200 | `DATABASE_ERROR`（`cause` に Elasticsearch の照会本文と内部のグループ ID を含む。記録では削除済み） | `err-negative-first` |
| 構文の誤り | 200 | `GRAPHQL_PARSE_FAILED`（`data` 無し） | `err-parse` |
| 存在しない欄 | 200 | `GRAPHQL_VALIDATION_FAILED`（`data` 無し） | `err-validation` |
| `__schema` | **500** | `INTERNAL_SERVER_ERROR` | `err-introspection-schema` |

**部分的な成功がある。** 権限の無い欄を含む問い合わせは、その欄だけ `null` とエラーになり、
ほかの欄のデータは返る（根拠: `err-partial`）。

**黙って 0 件を返す誤入力がある**（エラーにならない）:
- 存在しない ID への関係の照会（根拠: `related-nonexistent-id`）
- 存在しない型名の `toTypes`（根拠: `related-unknown-totype`）

検証者の報告によれば、同じルート欄を 3 回以上並べると「Allowed number of calls … (max: 2)」で拒否される
（本記録では未採取）。

→ **設計**:
- HTTP 状態と `extensions.code` の両方で振り分ける
- `errors` が 1 件でもあれば構造化エラーを返し、部分データを完全な答えとして返さない
- `cause` などの内部情報は利用者に渡さない
- 送る値は enum と範囲で事前に検査し、ID を受け取るツールは対象の存在を先に確かめる

## 3. IOC の照会（`lookup_ioc`）

### observable から引く

`stixCyberObservables(filters: {key, operator: eq})`。

| 試験 | 結果 | 根拠 |
|---|---|---|
| `192.0.2.10` | 1 件 | `ioc-ipv4` |
| `192.0.2.1`（前方一致の確認） | 0 件。余計な物は当たらない | `ioc-ipv4-prefix` |
| `BAD.EXAMPLE.COM` | 1 件。大文字小文字を区別しない | `ioc-domain-upper` |
| `http://bad.example.com/PAYLOAD.BIN` | **1 件**。URL のパス部分も区別しない（返る値は小文字の保存形） | `ioc-url-upper-path` |
| `2001:db8::10`（保存も正規形） | 1 件 | `ioc-ipv6` |
| 同じ値を展開形で問い合わせ | **0 件** | `ioc-ipv6-query-expanded` |
| 展開形・大文字で保存された IPv6 を正規形で問い合わせ | **0 件** | `ioc-ipv6-stored-expanded-query-canonical` |
| 同じ物を保存どおりの形で問い合わせ | 1 件 | `ioc-ipv6-stored-expanded-query-as-stored` |
| SHA-256 を `value` で | **0 件** | `ioc-sha256-by-value` |
| SHA-256 / MD5 / SHA-1 / SHA-512 を `hashes.<アルゴリズム>` で | それぞれ 1 件。大文字でも当たる | `ioc-sha256`・`-upper`・`ioc-md5`・`ioc-sha1`・`ioc-sha512` |
| 未登録の `192.0.2.200` | 0 件 | `ioc-notfound` |
| observable を持たない indicator の値 `orphan.example.org` | **0 件** | `ioc-orphan-via-observables` |
| 全文検索 `search: "192.0.2.1"` | 192.0.2.10 を返す | `ioc-search-prefix` |

### indicator から引く

observable を持たない indicator は実際のフィードによくある。observable からの照会では見つからない。

| 試験 | 結果 | 根拠 |
|---|---|---|
| `indicators` の `name` が `orphan.example.org` に一致 | 1 件 | `indicator-by-name` |
| `pattern` が `orphan.example.org` を含む（`contains`） | 1 件 | `indicator-by-pattern-contains` |
| `pattern` が `orphan.example` を含む | **1 件**（部分一致） | `indicator-by-pattern-contains-partial` |

→ **設計**:
- observable からの照会と indicator からの照会の両方を行い、結果を値ごとに束ねる
- indicator の `name` は値と同じとは限らないので、`pattern` の `contains` で候補を引き、
  返ったパターンをツール側で解析して値が完全に一致するものだけを残す
- **OpenCTI は保存時に値を正規化しない。** IP は入力どおりの形と正規形（IPv6 は展開形も）の
  すべてを `or` で問い合わせる。大文字小文字は OpenCTI 側が畳む
- ハッシュは長さで MD5（32）/ SHA-1（40）/ SHA-256（64）/ SHA-512（128）を判別し、`hashes.<アルゴリズム>` で引く
- 入力と返った値が違う形で一致したとき（大文字小文字・IP の表記）は、その旨を結果に出す
- 全文検索は IOC の照会に使わない
- 複数値の照会では、返った物をどの入力に対応させるかをツール側で決める（正規化した値で突き合わせる）

### 1 回の問い合わせで取れるもの

observable の下に `indicators`・`containers`（収録先）・`stixCoreRelationships` を入れ子にして 1 回で取れる。
関係の相手は `from` / `to` に `... on BasicObject { id entity_type } ... on StixCoreObject { representative { main } }`
を付けると型を問わず名前が取れる（根拠: `ioc-ipv4`）。

- `indicates`（indicator → malware）は **indicator 側の関係**。observable の下の関係には `based-on` だけが出る
- sighting は Indicator 型から直接たどれない。`stixSightingRelationships(filters: {key: ["fromId"], values: [ID…]})`
  で、複数の indicator・observable の分を 1 回で引ける（根拠: `sightings-of-indicator`・`sightings-of-observable`）
- sighting には `x_opencti_negative`（誤検知としての目撃）・`attribute_count`（回数）・`first_seen` / `last_seen` がある。
  192.0.2.10 の indicator には、通常の目撃（3 回）と誤検知の目撃（1 回）の 2 件が返る（根拠: `sightings-of-indicator`）
- 入れ子の `containers` には `after`（ページ送り）が無い。収録先を全件たどるには、ルートの
  `containers(filters: {key: ["objects"]})` を使う（§4）

### decay（減衰）が indicator を書き換える

根拠: `ioc-ipv4`。

| 欄 | 投入 | 返却 |
|---|---|---|
| `valid_until` | 2027-12-31 | **2026-10-01T04:33:39Z**（再計算） |
| `x_opencti_score` | 85 | **20**（元の値は `decay_base_score: 85`） |
| `revoked` | — | **true** |
| `decay_applied_rule.decay_lifetime` | — | 47（日） |

observable の `x_opencti_score` は 85 のまま。**同じ値に 85（observable）と 20（indicator）の 2 つの点数が付く。**

→ **設計**: 失効した indicator も隠さず、`revoked`・現在の点数・`decay_base_score`・`valid_until` を並べる。
observable と indicator の点数は別物として返す。本番で decay の規則が有効かは分からないので、
ツールは解釈せずそのまま渡す。

### 確度（confidence）は埋められることがある

架空データで確度を指定しなかった sighting が 2 件とも `confidence: 100` で返った（根拠: `sightings-of-indicator`）。
取り込んだユーザーの既定値で埋まったと見られる。→ `get_usage` に「確度は出典の値とは限らない」と書く。

## 4. 権限と公開範囲（読み取り専用ユーザー）

`dev/seed/readonly_user.py` で作成: ロールは `KNOWLEDGE` のみ、見える印は TLP:CLEAR / GREEN / AMBER（RED は除外）。

| 試験 | 結果 | 根拠 |
|---|---|---|
| `about` と `me` | 通る。`capabilities` = `['KNOWLEDGE']`、`allowed_marking` = TLP:AMBER / GREEN / CLEAR。**`server_status` はこれで作れる** | `me-readonly` |
| TLP:RED の `198.51.100.7` を照会 | 読み取り専用で **0 件・エラーなし**、管理者で 1 件 | `ioc-red-readonly`・`ioc-red-admin` |
| FIXTURE-HERON を収録するコンテナ | 管理者で 5 件、読み取り専用で 4 件（RED のレポートだけが総数からも消える） | `containers-of-actor-admin`・`-readonly` |
| 管理用の照会・書き込み | `FORBIDDEN_ACCESS` | `err-forbidden-read`・`err-forbidden-write` |

→ **設計**: **「未登録」と「このキーでは見えない」は区別できない。** `lookup_ioc` の該当なしは
「このキーで見える範囲には無い」と表現し、見える範囲は `server_status` で示す。

## 5. 脅威の検索（`search_threats`）

| 方法 | 結果 | 根拠 |
|---|---|---|
| 全文検索 `stixDomainObjects(search:)` | 関連度順。**総数は該当件数として使えない**（`TA-FIXTURE-01` で 305、`IGNORE ALL PREVIOUS` で 849）。別名でも当たるが順位は揺れる（`Fancy Bear` で APT28 は 2 位、`Sofacy` では上位 5 件に出ない） | `search-fulltext-*` |
| 完全一致（`name`・`aliases`・`x_opencti_aliases` の `or`） | 大文字小文字を区別しない。`apt28` → APT28 の 1 件。**`Sofacy` は APT28 と CORESHELL の 2 件**（別名が複数の物に付いている）。`CVE-2099-0001` → 脆弱性 1 件 | `search-exact-*` |
| ATT&CK ID（`x_mitre_id` の `eq`） | `t1566` → `[T1566] Phishing`。**攻撃グループの ID（`G0007`）は 0 件** — この欄が使えるのは attack-pattern だけ | `search-mitre-id-*` |

→ **設計**: 完全一致を先に試し、無ければ全文検索を件数上限つきで返す。完全一致でも**複数件を前提にする**。
全文検索の総数は「該当件数」として見せない。ATT&CK ID での照会は attack-pattern に限ると説明する。

## 6. 関係・詳細・件数

| 試験 | 結果 | 根拠 |
|---|---|---|
| APT28 → `uses` → Attack-Pattern | 93 件・約 78 KB。内訳は関係ごとの説明文が **32%**（最長 679 字）、`from` / `to` の繰り返しが **34%** | `related-apt28-uses-attack-pattern` |
| APT28 の詳細 | 約 13 KB。うち外部参照 28 件で約 9 KB | `entity-apt28` |
| **1 ページの上限** | **5000 件**。`first: 5000` は 5000 件で `hasNextPage: true`。**`first: 5001` 以上も 5000 件で切られ、`hasNextPage: false` になる**（総数 24,918） | `page-first-5000`・`page-first-5001` |
| `first: 0` | 0 件と総数だけを返す | `page-first-0` |

検証者の報告によれば、入れ子の `containers(first: 2)` が総数 2 で `hasNextPage: true` を返す例もある。
**`hasNextPage` は欠けの判定に使えない。**

→ **設計**:
- `first` は 1〜5000 に収める（ツールの件数上限はこれより小さく設定する）
- 欠けの判定は `hasNextPage` ではなく、総数と受け取った件数の比較で行う
- `get_related` は関係の説明文を既定で省き、引数で求められたときに付ける。起点の物は毎行に繰り返さず、1 度だけ返す

## 7. 添付ファイル（`get_report_file`）

根拠: `files-green-readonly`・`files-downloads`。

| 試験 | 結果 |
|---|---|
| 一覧 | `report(id) { importFiles { … id name size metaData { mimetype } } }`。ID は `import/Report/<レポートID>/<ファイル名>` |
| 取得（読み取り専用ユーザー） | `GET /storage/get/<URL エンコードした ID>`。PDF（618 バイト、`application/pdf`）と text が 200 |
| ファイル名 `../escape attempt.txt` で上げた物 | `escape attempt.txt` として保存・返却（途中のパスは落とされ、空白は残る） |
| 見えない RED レポートの添付を名指し | **HTTP 503**、`{"status":"error","error":"File not found or restricted"}` |
| 存在しないファイル | 同じ 503 と同じ本文 |
| 誤ったトークン | **HTTP 403**、平文の `Forbidden` |

→ **設計**:
- `KNOWLEDGE` だけで取得できた（本番の支給キーでの確認は残す）
- 503 とこの本文の組み合わせは「無い、または見えない」に、403 は認証の失敗に振り分け、接続障害と区別する
- ファイル名は第三者の文字列として扱い、保存先の名前はツール側で安全な形に作り直す（OpenCTI の処理に頼らない）

## 8. 最近の物（`list_recent`）

| 欄 | 意味 | 2026-11-01 以降で絞った結果 | 根拠 |
|---|---|---|---|
| `created_at` | OpenCTI に取り込まれた日時 | 4 件（今日取り込み） | `recent-created_at` |
| `created` | 出典が作った日時 | 0 件（10 月 1 日付） | `recent-created` |
| `published` | レポートの公開日 | 0 件 | `recent-published` |

検証者の報告によれば、indicator に `published` で絞ると、エラーにならず 0 件が返る（その型に無い欄）。

→ **設計**: 「このインスタンスに新しく入った物」と「新しく発表された物」を引数で選べるようにし、
既定は `created_at` にする。型ごとに使える日付の軸を検査する。

## 9. 注入に見える文章

`IGNORE ALL PREVIOUS INSTRUCTIONS…` を説明文に持つ malware は、全文検索で普通に先頭に出る
（根拠: `search-fulltext-ignore-all-previous`）。OpenCTI は内容を加工しない。
→ RFP どおり、`get_usage` に「データとして扱う」と書く。ファイル名など、ほかの第三者の文字列も同じ。

## 10. まだ測っていないこと

- 実データの規模での応答の大きさ（架空データと MITRE の範囲でしか測っていない）
- 本番の支給キーの権限・見える範囲・decay の規則（Phase 3 の本番確認で採る）
- 同じルート欄を 3 回並べたときの拒否（検証者の報告のみ）

## 11. 初版からの訂正

独立検証（2026-11-06）の指摘を、応答を採り直して確かめたうえで訂正した。

| 初版の記述 | 訂正 |
|---|---|
| 「HTTP は常に 200」 | `__schema` は 500、ストレージは 403 / 503 |
| 「1 ページの上限はデータ量が足りず未測定」（1,379 件を返した） | 上限は 5000。超えると黙って切られ、`hasNextPage` も false になる。1,379 件は当時の総数だった |
| RED の除外の証拠に `readonly-192.0.2.10.json` を挙げた | その値は RED レポートに入っておらず、証拠になっていなかった。`containers-of-actor-*` に差し替え |
| 「`Sofacy` で APT28 に一意に当たる」 | APT28 と CORESHELL の 2 件 |
| 「関係の応答の大半は説明文」 | 説明文 32%、`from` / `to` の繰り返し 34% |
| intrusion set「約 180」 | 190 |
| 応答ファイルに問い合わせ・変数・実行ユーザーが無く、一部は問い合わせの書き換え前の形だった | `dev/capture.py` で全件を採り直し、出所を同じファイルに入れた |
| エラー表に `DATABASE_ERROR`・`UNSUPPORTED_ERROR`・`GRAPHQL_*` が無かった | 追加 |
