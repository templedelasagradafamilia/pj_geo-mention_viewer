import os
import json
import ast
import csv
import re
from urllib.parse import urlparse
from io import StringIO

import pandas as pd
import streamlit as st
import yaml
import streamlit_authenticator as stauth
from collections.abc import Mapping


# ======================================
# 認証まわり（secrets.toml / config.yaml 読み込み）
# ======================================

def _secrets_to_dict(obj):
    """
    st.secrets のネストされたオブジェクトを
    再帰的に通常の dict / 値に変換するヘルパー
    """
    if isinstance(obj, Mapping):
        return {k: _secrets_to_dict(v) for k, v in obj.items()}
    return obj


def load_config(path: str = "config.yaml") -> dict:
    """認証設定を読み込む。

    1. .streamlit/secrets.toml の [credentials], [cookie] を優先して使用
    2. 見つからなければ従来どおり config.yaml を読む
    """
    # 1) Streamlit secrets 優先
    try:
        if "credentials" in st.secrets and "cookie" in st.secrets:
            return {
                "credentials": _secrets_to_dict(st.secrets["credentials"]),
                "cookie": _secrets_to_dict(st.secrets["cookie"]),
            }
    except Exception:
        # secrets が使えない環境では YAML にフォールバック
        pass

    # 2) 従来どおり config.yaml を読む
    try:
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        st.error(
            "認証設定が見つかりません。\n"
            "Streamlit Cloud では .streamlit/secrets.toml に [credentials] と [cookie] を、"
            "ローカルでは config.yaml を用意してください。"
        )
        st.stop()
    except Exception as e:
        st.error(f"config.yaml の読み込みでエラーが発生しました: {e}")
        st.stop()


def create_authenticator(config: dict) -> stauth.Authenticate:
    """streamlit-authenticator のインスタンス生成"""
    credentials = config["credentials"]
    cookie = config["cookie"]

    # パスワードは create_yaml.py 側でハッシュ済みなので auto_hash=False
    authenticator = stauth.Authenticate(
        credentials,
        cookie["name"],
        cookie["key"],
        cookie["expiry_days"],
        auto_hash=False,
    )
    return authenticator


# ======================================
# 共通ユーティリティ（CSV / JSON / 判定）
# ======================================
def safe_read_csv(source) -> pd.DataFrame:
    """CSV 読み込み（アップロードファイル or パス）。文字コードの違いにも対応。"""
    try:
        return pd.read_csv(source)
    except UnicodeDecodeError:
        if hasattr(source, "seek"):
            source.seek(0)
        return pd.read_csv(source, encoding="utf-8-sig")


def get_domain(url: str) -> str:
    """URL から正規化したドメイン (www.除去) を取得"""
    try:
        netloc = urlparse(url).netloc.lower()
        if netloc.startswith("www."):
            netloc = netloc[4:]
        return netloc
    except Exception:
        return ""


def safe_isna(value):
    """安全な NaN チェック"""
    if value is None:
        return True
    if isinstance(value, (list, dict, tuple)):
        return False
    if isinstance(value, float):
        return pd.isna(value)
    if isinstance(value, str):
        return value.strip() == "" or value.strip().lower() == "nan"
    return False


def safe_csv_text(text: str) -> str:
    """CSV が壊れないよう、危険な文字をエスケープ・整形"""
    if text is None:
        return ""
    s = str(text)
    s = s.replace("\n", " ").replace("\r", "")
    s = s.replace('"', "'")
    s = s.replace("<br>", " ").replace("<br/>", " ")
    s = " ".join(s.split())
    return s


def safe_json_parse(x):
    """
    CSV から読み込んだ文字列を安全にリスト/辞書に戻す関数。
    JSON -> ast.literal_eval -> [] の順で試行。
    """
    if pd.isna(x) or str(x).strip() == "":
        return []
    s_val = str(x)
    # JSON を試す
    try:
        return json.loads(s_val)
    except Exception:
        pass
    # Python リテラルを試す
    try:
        return ast.literal_eval(s_val)
    except Exception:
        return []


def check_mentions_specific(text, source_list, target_brands, target_domains):
    """
    特定のブランド群・ドメイン群だけを対象にチェックを行う。
    app_correct.py のロジックを移植。
    """
    found_brands = []
    if text:
        for brand in target_brands:
            b = brand.strip()
            if not b:
                continue
            escaped_brand = re.escape(b)
            pattern = r"(?<!\w)" + escaped_brand + r"(?!\w)"
            try:
                if re.search(pattern, text, re.IGNORECASE):
                    if b not in found_brands:
                        found_brands.append(b)
            except re.error:
                if b.lower() in text.lower():
                    if b not in found_brands:
                        found_brands.append(b)

    found_domains = []
    normalized_targets = {
        d.strip().lower(): d.strip()
        for d in target_domains
        if d and d.strip()
    }

    for source in source_list or []:
        if not isinstance(source, dict):
            continue

        uri = source.get("uri", "") or ""
        title = source.get("title", "") or ""
        raw_uri = uri.lower()
        dom = get_domain(uri)

        for norm, original in normalized_targets.items():
            hit = False
            # ドメイン一致 or サブドメイン一致
            if dom and (dom == norm or dom.endswith("." + norm)):
                hit = True
            elif norm in raw_uri:
                hit = True
            elif title and norm in title.lower():
                hit = True

            if hit and original not in found_domains:
                found_domains.append(original)

    brand_res = ", ".join(found_brands) if found_brands else "-"
    domain_res = ", ".join(found_domains) if found_domains else "-"

    return {
        "mentioned_brands_str": brand_res,
        "cited_domains_str": domain_res,
    }


def detect_domains_from_citations(citations, target_domains):
    """
    ChatGPT annotations 由来の citations から、
    target_domains と一致（またはサブドメイン）のものだけ抽出して列挙。
    """
    if not isinstance(citations, list):
        return "-"

    normalized_targets = {
        d.strip().lower(): d.strip()
        for d in target_domains
        if d and d.strip()
    }
    found_norm = []

    for cit in citations:
        if not isinstance(cit, dict):
            continue
        url = cit.get("url", "") or ""
        if not url:
            continue

        title = cit.get("title", "") or ""
        dom = get_domain(url)
        raw_url = url.lower()

        for norm, original in normalized_targets.items():
            matched = False
            if dom and (dom == norm or dom.endswith("." + norm)):
                matched = True
            elif norm in raw_url:
                matched = True
            elif title and norm in title.lower():
                matched = True

            if matched and norm not in found_norm:
                found_norm.append(norm)

    if not found_norm:
        return "-"

    return ", ".join(normalized_targets[n] for n in found_norm)


def format_cits(citations, target_domains):
    """
    指定されたドメインリストに関連する citation だけを抽出して整形。
    {text}（{URL}）形式で、複数あれば改行区切り。
    """
    if not isinstance(citations, list):
        return "-"

    lines = []
    targets_norm = {d.strip().lower() for d in target_domains if d and d.strip()}

    for cit in citations:
        if not isinstance(cit, dict):
            continue

        url = cit.get("url", "") or ""
        title = cit.get("title", "") or ""
        text = cit.get("text", "") or ""
        if not url:
            continue

        url_dom = get_domain(url)
        matched = False

        if url_dom:
            for norm in targets_norm:
                if url_dom == norm or url_dom.endswith("." + norm):
                    matched = True
                    break

        if not matched and title:
            t_low = title.lower()
            for norm in targets_norm:
                if norm in t_low:
                    matched = True
                    break

        if matched:
            clean_text = text.replace("\n", " ").replace("\r", " ")
            lines.append(f"{clean_text}（{url}）")

    return "\n".join(lines) if lines else "-"


# ======================================
# Brands & Domains 入力 UI（自社／競合）
# ======================================
def render_brand_domain_inputs():
    """自社・競合のブランド名 / ドメイン名入力 UI（app_correct.py と同じ）"""
    st.markdown("### 1-2. Brands & Domains")
    entities_config = {}

    if "competitor_count" not in st.session_state:
        st.session_state["competitor_count"] = 3

    col_header_l, col_header_r = st.columns(2)
    with col_header_l:
        st.markdown("**ブランド名** (カンマ区切り)")
    with col_header_r:
        st.markdown("**ドメイン名** (カンマ区切り)")

    # 自社
    c1, c2 = st.columns(2)
    with c1:
        val_b = st.text_input(
            "自社",
            value="ファストマーケティング,fastmarketing",
            key="input_brand_company",
        )
    with c2:
        val_d = st.text_input(
            "自社 (ドメイン)",
            value="fastmarketing-pro.com",
            key="input_domain_company",
        )

    if val_b or val_d:
        entities_config["company"] = {
            "brands": [b.strip() for b in val_b.split(",") if b.strip()],
            "domains": [d.strip() for d in val_d.split(",") if d.strip()],
        }

    # 競合
    def add_comp():
        st.session_state.competitor_count += 1

    def remove_comp():
        if st.session_state.competitor_count > 0:
            st.session_state.competitor_count -= 1

    for i in range(st.session_state.competitor_count):
        comp_key = f"competitor{i+1}"
        c1, c2 = st.columns(2)
        with c1:
            val_b = st.text_input(f"競合{i+1}", key=f"input_brand_{comp_key}")
        with c2:
            val_d = st.text_input(f"競合{i+1} (ドメイン)", key=f"input_domain_{comp_key}")

        if val_b or val_d:
            entities_config[comp_key] = {
                "brands": [b.strip() for b in val_b.split(",") if b.strip()],
                "domains": [d.strip() for d in val_d.split(",") if d.strip()],
            }

    b_col1, b_col2, _ = st.columns([1, 1, 8])
    with b_col1:
        st.button("＋ 追加", on_click=add_comp)
    with b_col2:
        st.button("− 削除", on_click=remove_comp)

    return entities_config


# ======================================
# Viewer 用・再判定ロジック
# ======================================
def recheck_viewer(df: pd.DataFrame, settings: dict) -> pd.DataFrame:
    """Viewer 用の再判定ロジック（app_correct.py と同じ構造）"""
    if df is None or df.empty:
        return df

    df_rechecked = df.copy()
    entities = settings["entities"]
    progress_bar = st.progress(0)
    total = len(df_rechecked)

    for idx, row in df_rechecked.iterrows():
        # --- Gemini の再評価 ---
        if "Gemini_generated_answer" in row:
            ans = str(row.get("Gemini_generated_answer", ""))
            src = row.get("Gemini_web_sources_raw", [])
            cits = row.get("Gemini_citations_raw", [])

            if isinstance(src, str):
                src = safe_json_parse(src)
            if isinstance(cits, str):
                cits = safe_json_parse(cits)

            for ek, data in entities.items():
                res = check_mentions_specific(
                    ans, src, data["brands"], data["domains"]
                )
                df_rechecked.loc[
                    idx, f"Gemini_brand_mentioned_{ek}"
                ] = res["mentioned_brands_str"]

                domain_cits = detect_domains_from_citations(
                    cits, data["domains"]
                )
                df_rechecked.loc[idx, f"Gemini_domain_cited_{ek}"] = (
                    domain_cits if domain_cits != "-" else res["cited_domains_str"]
                )

                df_rechecked.loc[
                    idx, f"Gemini_citations_url_{ek}"
                ] = format_cits(cits, data["domains"])

        # --- ChatGPT の再評価 ---
        if "ChatGPT_generated_answer" in row:
            ans = str(row.get("ChatGPT_generated_answer", ""))
            cits = row.get("ChatGPT_citations_raw", [])
            if isinstance(cits, str):
                cits = safe_json_parse(cits)

            for ek, data in entities.items():
                res = check_mentions_specific(ans, [], data["brands"], [])
                df_rechecked.loc[
                    idx, f"ChatGPT_brand_mentioned_{ek}"
                ] = res["mentioned_brands_str"]
                df_rechecked.loc[
                    idx, f"ChatGPT_domain_cited_{ek}"
                ] = detect_domains_from_citations(cits, data["domains"])
                df_rechecked.loc[
                    idx, f"ChatGPT_citations_url_{ek}"
                ] = format_cits(cits, data["domains"])

        progress_bar.progress((idx + 1) / total)

    return df_rechecked


# ======================================
# ビューワー UI（app_correct.py のビューワーモード準拠）
# ======================================
def show_viewer():
    st.title("📊 ブランドチェック結果ビューワー")

    # Session State 初期化
    if "results_df" not in st.session_state:
        st.session_state["results_df"] = None
    if "competitor_count" not in st.session_state:
        st.session_state["competitor_count"] = 3
    if "entities_config" not in st.session_state:
        st.session_state["entities_config"] = {}

    # -------- 1. Viewer Settings --------
    st.header("1. Viewer Settings")

    viewer_file = st.file_uploader(
        "以前の結果CSVをアップロード", type=["csv"], key="viewer_file_uploader"
    )

    entities_settings = render_brand_domain_inputs()

    col_v1, col_v2 = st.columns(2)
    with col_v1:
        if st.button("結果を読み込む"):
            if viewer_file:
                try:
                    v_df = safe_read_csv(viewer_file)

                    # JSON カラムをパース
                    for col in v_df.columns:
                        if col.endswith("_web_sources_raw") or col.endswith(
                            "_citations_raw"
                        ):
                            v_df[col] = v_df[col].apply(safe_json_parse)

                    # id ソート（あれば）
                    if "id" in v_df.columns:
                        try:
                            v_df = v_df.sort_values(
                                by="id",
                                key=lambda x: pd.to_numeric(x, errors="coerce"),
                            )
                        except Exception:
                            v_df = v_df.sort_values(by="id")

                    settings = {"entities": entities_settings}
                    v_df_rechecked = recheck_viewer(v_df, settings)

                    st.session_state["results_df"] = v_df_rechecked
                    st.session_state["entities_config"] = entities_settings

                    st.success("読み込み & 再判定 完了！")
                    st.rerun()
                except Exception as e:
                    st.error(f"CSV読み込みエラー: {e}")
            else:
                st.warning("CSVファイルをアップロードしてください。")

    with col_v2:
        if st.button("現在の設定で再判定を実行"):
            if st.session_state["results_df"] is not None:
                settings = {"entities": entities_settings}
                st.session_state["results_df"] = recheck_viewer(
                    st.session_state["results_df"], settings
                )
                st.session_state["entities_config"] = entities_settings
                st.rerun()
            else:
                st.warning("先に結果CSVを読み込んでください。")

    # -------- 2. Results --------
    if st.session_state["results_df"] is not None:
        st.markdown("---")
        st.header("2. Results")
        df_res = st.session_state["results_df"]

        # ==== CSV ダウンロード用カラム並び ==== 
        csv_export_df = df_res.copy()
        existing_keys = set()
        for c in csv_export_df.columns:
            if "_brand_mentioned_" in c:
                existing_keys.add(c.split("_brand_mentioned_")[-1])

        sorted_keys = []
        if "company" in existing_keys:
            sorted_keys.append("company")
        comp_keys = sorted(
            [k for k in existing_keys if k.startswith("competitor")],
            key=lambda x: int(x.replace("competitor", ""))
            if x.replace("competitor", "").isdigit()
            else 999,
        )
        sorted_keys.extend(comp_keys)
        sorted_keys.extend([k for k in existing_keys if k not in sorted_keys])

        def create_service_column_order(prefix, entities):
            cols = [f"{prefix}_used_model", f"{prefix}_generated_answer"]
            for k in entities:
                cols.append(f"{prefix}_brand_mentioned_{k}")
            cols.append(f"{prefix}_search_queries")
            for k in entities:
                cols.append(f"{prefix}_domain_cited_{k}")
                cols.append(f"{prefix}_citations_url_{k}")
            cols.extend(
                [
                    f"{prefix}_reference_links",
                    f"{prefix}_web_sources_raw",
                    f"{prefix}_citations_raw",
                ]
            )
            return cols

        base_cols = ["id", "category", "stage", "prompt"]
        final_base = [c for c in base_cols if c in csv_export_df.columns]
        gemini_cols = [
            c
            for c in create_service_column_order("Gemini", sorted_keys)
            if c in csv_export_df.columns
        ]
        chatgpt_cols = [
            c
            for c in create_service_column_order("ChatGPT", sorted_keys)
            if c in csv_export_df.columns
        ]

        final_export_cols = final_base + gemini_cols + chatgpt_cols

        # ==== CSV データ生成 ====
        output = StringIO()
        writer = csv.DictWriter(
            output,
            fieldnames=final_export_cols,
            quoting=csv.QUOTE_ALL,
            lineterminator="\n",
        )
        writer.writeheader()

        for _, row in csv_export_df.iterrows():
            row_dict = {}
            for col in final_export_cols:
                value = row.get(col, "")
                if value is None:
                    row_dict[col] = ""
                elif isinstance(value, (list, dict)):
                    row_dict[col] = json.dumps(
                        value, ensure_ascii=False
                    ).replace("\n", " ").replace("\r", "")
                elif isinstance(value, float) and pd.isna(value):
                    row_dict[col] = ""
                else:
                    if col.endswith("_generated_answer"):
                        row_dict[col] = str(value)
                    else:
                        row_dict[col] = safe_csv_text(value)
            writer.writerow(row_dict)

        csv_data = output.getvalue().encode("utf-8-sig")
        output.close()

        file_name = (
            f"brand_check_results_viewer_"
            f"{pd.Timestamp.now().strftime('%Y%m%d_%H%M%S')}.csv"
        )
        st.download_button(
            label="📥 統合結果CSVをダウンロード",
            data=csv_data,
            file_name=file_name,
            mime="text/csv",
        )

        display_cols = [
            c
            for c in final_export_cols
            if "web_sources_raw" not in c
            and "citations_raw" not in c
            and "reference_links" not in c
        ]
        st.dataframe(
            df_res[display_cols].astype(str),
            use_container_width=True,
            height=300,
        )

        # ==== 個別詳細 ====
        st.markdown("---")
        st.subheader("🔍 個別の回答詳細")

        options = list(range(len(df_res)))

        def format_option(i: int) -> str:
            row = df_res.iloc[i]
            prompt_val = row.get("prompt", "")
            if not prompt_val and len(row) > 3:
                try:
                    prompt_val = str(row.iloc[3])
                except Exception:
                    prompt_val = "No Prompt"
            id_val = row.get("id", i + 1)
            return f"ID {id_val}: {str(prompt_val)[:40]}..."

        selected_idx = st.selectbox(
            "詳細を表示する行を選択",
            options=options,
            format_func=format_option,
        )

        if selected_idx is not None:
            row = df_res.iloc[selected_idx]
            current_entities = st.session_state.get("entities_config", {})

            # 対象（自社／競合）選択
            if current_entities:
                entity_options = list(current_entities.keys())

                def format_entity_label(key: str) -> str:
                    brands = ",".join(current_entities[key].get("brands", []))
                    return f"{key} ({brands})" if brands else key

                selected_entity_key = st.selectbox(
                    "確認する対象（自社・競合）を選択してください",
                    options=entity_options,
                    format_func=format_entity_label,
                )
                target_domains_hl = [
                    d.strip().lower()
                    for d in current_entities[selected_entity_key]
                    .get("domains", [])
                    if d.strip()
                ]
            else:
                st.warning(
                    "詳細表示用の設定が見つかりません。「結果を読み込む」ボタン実行時の設定を使用します。"
                )
                selected_entity_key = "company"
                target_domains_hl = []

            tab1, tab2 = st.tabs(["Gemini 結果", "ChatGPT 結果"])

            def render_detail_view(container, row, prefix, entity_key, domains_hl):
                with container:
                    # その行で prefix 側が実行されていない場合
                    if (
                        f"{prefix}_used_model" not in row
                        or safe_isna(row.get(f"{prefix}_used_model"))
                    ):
                        st.warning(f"{prefix} の実行結果はこの行に含まれていません。")
                        return

                    # 基本情報
                    st.markdown("#### 📌 基本情報")
                    with st.container(border=True):
                        c1, c2, c3 = st.columns(3)
                        c1.markdown(
                            f"**Model**: {row.get(f'{prefix}_used_model', '-')}"
                        )
                        c2.markdown(f"**Category**: {row.get('category', '-')}")
                        c3.markdown(f"**Stage**: {row.get('stage', '-')}")

                    # 入力プロンプト
                    st.markdown("#### 📝 入力プロンプト")
                    with st.container(border=True):
                        prompt_val = (
                            row.get("prompt", "")
                            if row.get("prompt", "")
                            else str(row.iloc[3])
                            if len(row) > 3
                            else ""
                        )
                        st.markdown(prompt_val)

                    # 生成された回答
                    st.markdown("#### 💬 生成された回答")
                    with st.expander("回答テキストを展開して表示", expanded=False):
                        st.write(row.get(f"{prefix}_generated_answer", ""))

                    # 判定結果
                    st.markdown(f"#### 📊 判定結果: {entity_key}")
                    rc1, rc2 = st.columns(2)
                    with rc1:
                        with st.container(border=True):
                            st.markdown("**ブランド言及**")
                            val = row.get(
                                f"{prefix}_brand_mentioned_{entity_key}", "-"
                            )
                            if val != "-":
                                st.success(f"✅ あり ({val})")
                            else:
                                st.write("❌ なし")
                    with rc2:
                        with st.container(border=True):
                            st.markdown("**ドメイン引用**")
                            val = row.get(
                                f"{prefix}_domain_cited_{entity_key}", "-"
                            )
                            if val != "-":
                                st.success(f"✅ あり ({val})")
                            else:
                                st.write("❌ なし")

                    # 検索クエリ
                    st.markdown("#### 🔎 検索クエリ")
                    with st.container(border=True):
                        queries = row.get(f"{prefix}_search_queries", "")
                        if queries and str(queries).strip().lower() != "nan":
                            for q in str(queries).split(","):
                                q = q.strip()
                                if q:
                                    st.markdown(f"- {q}")
                        else:
                            st.caption("（検索クエリ情報なし）")

                    # 引用詳細
                    st.markdown(f"#### 🎯 引用詳細 ({entity_key})")
                    raw_citations = row.get(f"{prefix}_citations_raw", [])
                    if isinstance(raw_citations, str):
                        raw_citations = safe_json_parse(raw_citations)

                    found_citation = False
                    if raw_citations and isinstance(raw_citations, list):
                        for cit in raw_citations:
                            if not isinstance(cit, dict):
                                continue
                            url = cit.get("url", "") or ""
                            text = cit.get("text", "") or ""
                            title = cit.get("title", "") or ""

                            matched_keyword = None
                            for d in domains_hl:
                                if (d in url.lower()) or (d in title.lower()):
                                    matched_keyword = d
                                    break

                            if matched_keyword:
                                found_citation = True
                                with st.container(border=True):
                                    st.markdown(
                                        f"**引用元のページ**: [{title}]({url})"
                                    )
                                    st.markdown("**引用された文章**: ")
                                    if text:
                                        st.info(f'"{text}"')
                                    else:
                                        st.caption(
                                            "（引用テキストを特定できませんでした）"
                                        )
                                    st.markdown(
                                        f"`検知キーワード: {matched_keyword}`"
                                    )

                    if not found_citation:
                        st.caption(
                            "この対象ドメインからの具体的なテキスト引用は見つかりませんでした。"
                        )

                    # Web ソース全件
                    st.markdown("#### 🔗 参照されたWebソース (全件)")
                    st.caption(
                        f"※ {entity_key} のドメインが含まれるものをハイライトしています"
                    )

                    raw_sources = row.get(f"{prefix}_web_sources_raw", [])
                    if isinstance(raw_sources, str):
                        raw_sources = safe_json_parse(raw_sources)

                    if raw_sources and isinstance(raw_sources, list):
                        for idx, s in enumerate(raw_sources, start=1):
                            if not isinstance(s, dict):
                                continue
                            title = s.get("title") or "No Title"
                            uri = s.get("uri") or ""

                            if prefix == "ChatGPT":
                                dom = get_domain(uri)
                                if dom:
                                    head = f"{idx}.{dom}:{title}"
                                else:
                                    head = f"{idx}.{title}"
                            else:
                                head = f"{idx}.{title}"

                            matched_keyword = None
                            for d in domains_hl:
                                if (d in uri.lower()) or (d in title.lower()):
                                    matched_keyword = d
                                    break

                            if matched_keyword:
                                warning_text = f"**{head}**\n\nURL: {uri}\n\n"
                                st.warning(warning_text, icon="🎯")
                            else:
                                with st.container(border=True):
                                    st.markdown(f"**{head}**")
                                    st.markdown(f"URL: {uri}")
                    else:
                        st.caption("（Webソース情報なし）")

            if current_entities:
                render_detail_view(
                    tab1, row, "Gemini", selected_entity_key, target_domains_hl
                )
                render_detail_view(
                    tab2, row, "ChatGPT", selected_entity_key, target_domains_hl
                )


# ======================================
# メインエントリ（ログイン＋ビューワー）
# ======================================
def main():
    st.set_page_config(
        page_title="ブランドチェック結果ビューワー",
        page_icon="📊",
        layout="wide",
    )

    config = load_config()
    authenticator = create_authenticator(config)

    # ログインフォーム
    try:
        authenticator.login(
            location="main",
            fields={
                "Form name": "ログイン",
                "Username": "ユーザー名",
                "Password": "パスワード",
                "Login": "ログイン",
            },
        )
    except Exception as e:
        st.error(f"ログイン処理でエラーが発生しました: {e}")
        return

    auth_status = st.session_state.get("authentication_status", None)
    name = st.session_state.get("name", "")

    if auth_status:
        authenticator.logout("ログアウト", "sidebar")
        if name:
            st.sidebar.markdown(f"👤 ログイン中: **{name}**")
        show_viewer()
    elif auth_status is False:
        st.error("ユーザー名またはパスワードが違います。")
    else:
        st.info("ユーザー名とパスワードを入力してください。")


if __name__ == "__main__":
    main()
