---
hide:
  - navigation
  - toc
---

<div class="hb-hero" markdown>

![Mecha Hayabusa](assets/mecha_hayabusa_logo.png){ .hb-logo }

<p class="hb-tagline">
<strong>Mecha Hayabusa</strong> は、<a href="https://github.com/Yamato-Security">Yamato Security</a>
によって作られた、<a href="https://github.com/Yamato-Security/hayabusa">Hayabusa</a> の結果を解析する
<strong>AI 解析・DFIR タイムライン・レポート生成ツール</strong>です。Model Context Protocol を通じて
Hayabusa の結果を AI アシスタント（Claude など）に渡し、自然言語で調査できます。
</p>

<div class="hb-cta" markdown>
[はじめる :material-rocket-launch:](getting-started/index.md){ .md-button .md-button--primary }
[機能 :material-feature-search:](overview/features.md){ .md-button }
[GitHub で見る :fontawesome-brands-github:](https://github.com/Yamato-Security/mecha-hayabusa){ .md-button }
</div>

<p class="hb-badges">
<a href="https://github.com/Yamato-Security/mecha-hayabusa/releases"><img src="https://img.shields.io/github/v/release/Yamato-Security/mecha-hayabusa?color=blue&label=Stable%20Version&style=flat"/></a>
<a href="https://github.com/Yamato-Security/mecha-hayabusa/stargazers"><img src="https://img.shields.io/github/stars/Yamato-Security/mecha-hayabusa?style=flat&label=GitHub%F0%9F%A6%85Stars"/></a>
<a href="https://github.com/Yamato-Security/mecha-hayabusa/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-AGPLv3-blue.svg?style=flat"/></a>
<a href="https://blackhat.com/us-26/arsenal/schedule/index.html#mecha-hayabusa-by-yamato-security-52897"><img src="https://img.shields.io/badge/Black%20Hat%20Arsenal%20USA-2026-blue"></a>
<a href="https://twitter.com/SecurityYamato"><img src="https://img.shields.io/twitter/follow/SecurityYamato?style=social"/></a>
</p>

</div>

---

## なぜ Mecha Hayabusa なのか？

<div class="grid cards" markdown>

-   :material-robot:{ .lg .middle } __AI による調査__

    ---

    [Hayabusa](https://github.com/Yamato-Security/hayabusa) の結果を、**Model Context Protocol** 経由で
    AI アシスタント（Claude など）と自然言語で調査できます。

-   :material-database-cog:{ .lg .middle } __データセット操作__

    ---

    Hayabusa の結果データセットを読み込み・管理・操作し、AI が推論できるようにします。

-   :material-magnify:{ .lg .middle } __クエリと検索__

    ---

    結果全体に対してクエリや検索を行い、重要なイベントを絞り込みます。

-   :material-timeline-clock:{ .lg .middle } __タイムラインと分析__

    ---

    タイムラインを構築し、分析を実行してインシデントの全体像を把握します。

-   :material-shield-bug:{ .lg .middle } __詳細と IOC 分析__

    ---

    イベントの詳細を掘り下げ、アーティファクト（Base64 PowerShell など）をデコードし、IOC を抽出します。

-   :material-file-document-edit:{ .lg .middle } __レポート生成__

    ---

    Hayabusa の結果から DFIR タイムラインやレポートを生成します。

</div>

## クイックリンク

<div class="grid cards" markdown>

-   __:material-book-open-variant: はじめての方へ__

    まずは[概要](overview/index.md)を読み、[はじめる](getting-started/index.md)で
    実行して Claude に追加しましょう。

-   __:material-feature-search-outline: できること__

    [機能](overview/features.md)をご覧ください — データセット操作、クエリと検索、
    タイムラインと分析、詳細と IOC 分析。

-   __:material-puzzle: さらに活用する__

    [コントリビュータ](resources/contributing.md)や、本体の
    [Hayabusa](https://github.com/Yamato-Security/hayabusa) プロジェクトを見てみましょう。

</div>
