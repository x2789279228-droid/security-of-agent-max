# -*- coding: utf-8 -*-
"""生成《系统设计说明书》参赛稿。

封面版式复刻自竞赛模板：
  湖南科技大学第4届大学生计算机程序设计竞赛暨
  湖南省第22届大学生计算机程序设计竞赛
  应用开发类竞赛（2026）
  竖排「系统设计说明书」

正文规范（用户指定）：
  一级标题 黑体；二级标题 楷体；主要内容 仿宋；颜色仅黑色。
  西文/数字 Times New Roman。三级标题用仿宋加粗。

内容依据项目《设计文档》及工程实现整理，面向应用开发类竞赛。
"""
from pathlib import Path

from docx import Document
from docx.enum.section import WD_SECTION
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_LINE_SPACING, WD_TAB_ALIGNMENT, WD_TAB_LEADER
from docx.enum.table import WD_CELL_VERTICAL_ALIGNMENT, WD_TABLE_ALIGNMENT
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import qn, nsdecls
from docx.shared import Cm, Pt, RGBColor, Emu, Twips

BASE = Path(__file__).resolve().parent
FIG = BASE / "figures"
ROOT = BASE.parents[2]
OUT_PATH = ROOT / "系统设计说明书.docx"
OUT_COPY = BASE / "系统设计说明书.docx"

LATIN, FANGSONG, HEITI, KAITI = "Times New Roman", "仿宋", "黑体", "楷体"
COVER_FANG = "仿宋_GB2312"
BLACK = RGBColor(0, 0, 0)
CONTENT_DXA = 8312  # A4 宽 11906 - 左右 1797*2

PPR_ORDER = [
    "pStyle", "keepNext", "keepLines", "pageBreakBefore", "framePr", "widowControl",
    "numPr", "suppressLineNumbers", "pBdr", "shd", "tabs", "suppressAutoHyphens",
    "kinsoku", "wordWrap", "overflowPunct", "topLinePunct", "autoSpaceDE", "autoSpaceDN",
    "bidi", "adjustRightInd", "snapToGrid", "spacing", "ind", "contextualSpacing",
    "mirrorIndents", "suppressOverlap", "jc", "textDirection", "textAlignment",
    "textboxTightWrap", "outlineLvl", "divId", "cnfStyle", "rPr", "sectPr", "pPrChange",
]
TBLPR_ORDER = [
    "tblStyle", "tblpPr", "tblOverlap", "bidiVisual", "tblStyleRowBandSize",
    "tblStyleColBandSize", "tblW", "jc", "tblCellSpacing", "tblInd", "tblBorders",
    "shd", "tblLayout", "tblCellMar", "tblLook", "tblCaption", "tblDescription",
]
TCPR_ORDER = [
    "cnfStyle", "tcW", "gridSpan", "hMerge", "vMerge", "tcBorders", "shd", "noWrap",
    "tcMar", "textDirection", "tcFitText", "vAlign", "hideMark", "headers",
]
SECTPR_ORDER = [
    "headerReference", "footerReference", "footnotePr", "endnotePr", "type", "pgSz",
    "pgMar", "paperSrc", "pgBorders", "lnNumType", "pgNumType", "cols", "formProt",
    "vAlign", "noEndnote", "titlePg", "textDirection", "bidi", "rtlGutter", "docGrid",
    "printerSettings", "sectPrChange",
]


def _local(tag):
    return tag.split("}")[-1] if tag else ""


def insert_el(parent, element, order):
    tag = _local(element.tag)
    if tag not in order:
        parent.append(element)
        return
    target = order.index(tag)
    insert_at = len(list(parent))
    for i, child in enumerate(list(parent)):
        ctag = _local(child.tag)
        if ctag in order and order.index(ctag) > target:
            insert_at = i
            break
    parent.insert(insert_at, element)


def _tbl_w(dxa):
    el = OxmlElement("w:tblW")
    el.set(qn("w:w"), str(dxa))
    el.set(qn("w:type"), "dxa")
    return el


def _tbl_jc(val):
    el = OxmlElement("w:jc")
    el.set(qn("w:val"), val)
    return el


def _tbl_layout():
    el = OxmlElement("w:tblLayout")
    el.set(qn("w:type"), "fixed")
    return el


def add_bottom_border(paragraph):
    pPr = paragraph._p.get_or_add_pPr()
    old = pPr.find(qn("w:pBdr"))
    if old is not None:
        pPr.remove(old)
    pBdr = OxmlElement("w:pBdr")
    bottom = OxmlElement("w:bottom")
    bottom.set(qn("w:val"), "single")
    bottom.set(qn("w:sz"), "6")
    bottom.set(qn("w:space"), "1")
    bottom.set(qn("w:color"), "000000")
    pBdr.append(bottom)
    insert_el(pPr, pBdr, PPR_ORDER)


def add_top_border(paragraph):
    pPr = paragraph._p.get_or_add_pPr()
    old = pPr.find(qn("w:pBdr"))
    if old is not None:
        pPr.remove(old)
    pBdr = OxmlElement("w:pBdr")
    top = OxmlElement("w:top")
    top.set(qn("w:val"), "single")
    top.set(qn("w:sz"), "6")
    top.set(qn("w:space"), "1")
    top.set(qn("w:color"), "000000")
    pBdr.append(top)
    insert_el(pPr, pBdr, PPR_ORDER)


def set_run_fonts(run, east, size, bold=False, ascii_font=None):
    west = ascii_font or LATIN
    run.font.name = west
    run.font.size = Pt(size)
    run.font.bold = bold
    run.font.color.rgb = BLACK
    rPr = run._element.get_or_add_rPr()
    rFonts = rPr.find(qn("w:rFonts"))
    if rFonts is None:
        rFonts = OxmlElement("w:rFonts")
        rPr.insert(0, rFonts)
    rFonts.set(qn("w:ascii"), west)
    rFonts.set(qn("w:hAnsi"), west)
    rFonts.set(qn("w:eastAsia"), east)
    rFonts.set(qn("w:cs"), west)
    color = rPr.find(qn("w:color"))
    if color is None:
        color = OxmlElement("w:color")
        rPr.append(color)
    color.set(qn("w:val"), "000000")
    # 禁止主题色/自动着色落到蓝链
    for tag in ("w:u",):
        pass
    return run


def add_run(p, text, east=FANGSONG, size=12, bold=False, ascii_font=None):
    run = p.add_run(text)
    return set_run_fonts(run, east, size, bold, ascii_font=ascii_font)


def fmt_para(p, align=None, before=0, after=0, line=1.5, first=None, outline=None, keep=False):
    pf = p.paragraph_format
    if align is not None:
        p.alignment = align
    pf.space_before = Pt(before)
    pf.space_after = Pt(after)
    pf.line_spacing = line
    if first is not None:
        pf.first_line_indent = Cm(first) if isinstance(first, float) else Pt(first)
    else:
        pf.first_line_indent = Pt(0)
    if keep:
        pf.keep_with_next = True
    if outline is not None:
        pPr = p._p.get_or_add_pPr()
        existing = pPr.find(qn("w:pStyle"))
        if existing is not None:
            pPr.remove(existing)
        style = OxmlElement("w:pStyle")
        style.set(qn("w:val"), f"Heading{outline}")
        insert_el(pPr, style, PPR_ORDER)
        old = pPr.find(qn("w:outlineLvl"))
        if old is not None:
            pPr.remove(old)
        ol = OxmlElement("w:outlineLvl")
        ol.set(qn("w:val"), str(outline - 1))
        insert_el(pPr, ol, PPR_ORDER)
    return p


def p_body(doc, text, first=24):
    p = doc.add_paragraph()
    add_run(p, text, FANGSONG, 12)
    return fmt_para(p, align=WD_ALIGN_PARAGRAPH.JUSTIFY, before=0, after=6, line=1.5, first=first)


def p_center(doc, text, east=FANGSONG, size=12, bold=False, before=6, after=6):
    p = doc.add_paragraph()
    add_run(p, text, east, size, bold)
    return fmt_para(p, align=WD_ALIGN_PARAGRAPH.CENTER, before=before, after=after, line=1.5)


def h1(doc, text):
    p = doc.add_paragraph()
    add_run(p, text, HEITI, 16, True)
    return fmt_para(p, align=WD_ALIGN_PARAGRAPH.CENTER, before=18, after=12, line=1.5, outline=1, keep=True)


def h2(doc, text):
    p = doc.add_paragraph()
    add_run(p, text, KAITI, 14, True)
    return fmt_para(p, align=WD_ALIGN_PARAGRAPH.LEFT, before=14, after=8, line=1.5, outline=2, keep=True)


def h3(doc, text):
    p = doc.add_paragraph()
    add_run(p, text, FANGSONG, 12, True)
    return fmt_para(p, align=WD_ALIGN_PARAGRAPH.LEFT, before=10, after=6, line=1.5, outline=3, keep=True)


def caption(doc, text):
    p = doc.add_paragraph()
    add_run(p, text, HEITI, 10.5, True)
    return fmt_para(p, align=WD_ALIGN_PARAGRAPH.CENTER, before=6, after=10, line=1.2)


def set_cell_border(cell, sz="4"):
    tc = cell._tc
    tcPr = tc.get_or_add_tcPr()
    old = tcPr.find(qn("w:tcBorders"))
    if old is not None:
        tcPr.remove(old)
    borders = OxmlElement("w:tcBorders")
    for edge in ("top", "left", "bottom", "right"):
        el = OxmlElement(f"w:{edge}")
        el.set(qn("w:val"), "single")
        el.set(qn("w:sz"), sz)
        el.set(qn("w:space"), "0")
        el.set(qn("w:color"), "000000")
        borders.append(el)
    insert_el(tcPr, borders, TCPR_ORDER)
    old_shd = tcPr.find(qn("w:shd"))
    if old_shd is not None:
        tcPr.remove(old_shd)
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), "FFFFFF")
    insert_el(tcPr, shd, TCPR_ORDER)


def add_table(doc, headers, rows, widths=None, title=None):
    if title:
        caption(doc, title)
    n = len(headers)
    if widths is None:
        w = CONTENT_DXA // n
        widths = [w] * (n - 1) + [CONTENT_DXA - w * (n - 1)]
    assert sum(widths) == CONTENT_DXA
    data = [headers] + rows
    t = doc.add_table(rows=len(data), cols=n)
    t.alignment = WD_TABLE_ALIGNMENT.CENTER
    t.autofit = False
    tbl = t._tbl
    tblPr = tbl.tblPr
    if tblPr is None:
        tblPr = OxmlElement("w:tblPr")
        tbl.insert(0, tblPr)
    for tag, builder in (
        ("tblW", lambda: _tbl_w(CONTENT_DXA)),
        ("jc", lambda: _tbl_jc("center")),
        ("tblLayout", lambda: _tbl_layout()),
    ):
        old = tblPr.find(qn(f"w:{tag}"))
        if old is not None:
            tblPr.remove(old)
        insert_el(tblPr, builder(), TBLPR_ORDER)
    grid = tbl.find(qn("w:tblGrid"))
    if grid is None:
        grid = OxmlElement("w:tblGrid")
        tbl.insert(0, grid)
    for child in list(grid):
        grid.remove(child)
    for w in widths:
        gc = OxmlElement("w:gridCol")
        gc.set(qn("w:w"), str(w))
        grid.append(gc)
    for ri, row in enumerate(data):
        for ci, txt in enumerate(row):
            cell = t.cell(ri, ci)
            cell.width = Twips(widths[ci])
            cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER
            set_cell_border(cell)
            p = cell.paragraphs[0]
            for r in list(p.runs):
                r._r.getparent().remove(r._r)
            east = KAITI if ri == 0 else FANGSONG
            add_run(p, str(txt), east, 10.5, bold=(ri == 0))
            fmt_para(p, align=WD_ALIGN_PARAGRAPH.CENTER if ri == 0 else WD_ALIGN_PARAGRAPH.LEFT,
                     before=2, after=2, line=1.15)
            tc = cell._tc
            tcPr = tc.get_or_add_tcPr()
            oldw = tcPr.find(qn("w:tcW"))
            if oldw is not None:
                tcPr.remove(oldw)
            tcW = OxmlElement("w:tcW")
            tcW.set(qn("w:w"), str(widths[ci]))
            tcW.set(qn("w:type"), "dxa")
            insert_el(tcPr, tcW, TCPR_ORDER)
            oldm = tcPr.find(qn("w:tcMar"))
            if oldm is not None:
                tcPr.remove(oldm)
            mar = OxmlElement("w:tcMar")
            for edge, val in (("top", "80"), ("left", "80"), ("bottom", "80"), ("right", "80")):
                e = OxmlElement(f"w:{edge}")
                e.set(qn("w:w"), val)
                e.set(qn("w:type"), "dxa")
                mar.append(e)
            insert_el(tcPr, mar, TCPR_ORDER)
    p = doc.add_paragraph()
    fmt_para(p, after=4, line=1.0)
    return t


def add_figure(doc, filename, caption_text, width_cm=14.5):
    path = FIG / filename
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = p.add_run()
    # 1280x720 -> 保持 16:9
    w = Cm(width_cm)
    h = Cm(width_cm * 720 / 1280)
    run.add_picture(str(path), width=w, height=h)
    fmt_para(p, align=WD_ALIGN_PARAGRAPH.CENTER, before=8, after=2, line=1.0)
    caption(doc, caption_text)


def add_toc_field(paragraph):
    """插入 TOC 域，打开 Word 后右键更新域即可生成页码。"""
    def fld(kind, extra=None, text=None):
        r = paragraph.add_run()
        set_run_fonts(r, FANGSONG, 12)
        if kind == "begin":
            el = OxmlElement("w:fldChar")
            el.set(qn("w:fldCharType"), "begin")
            r._r.append(el)
        elif kind == "instr":
            el = OxmlElement("w:instrText")
            el.set(qn("xml:space"), "preserve")
            el.text = extra
            r._r.append(el)
        elif kind == "sep":
            el = OxmlElement("w:fldChar")
            el.set(qn("w:fldCharType"), "separate")
            r._r.append(el)
        elif kind == "text":
            r.text = text
        elif kind == "end":
            el = OxmlElement("w:fldChar")
            el.set(qn("w:fldCharType"), "end")
            r._r.append(el)
    fld("begin")
    fld("instr", extra=r' TOC \o "1-2" \h \z \u ')
    fld("sep")
    fld("text", text="（请在 Microsoft Word 中右键本目录，选择“更新域”以生成页码）")
    fld("end")


def set_header_footer(section, header_text, show_page=True):
    header = section.header
    header.is_linked_to_previous = False
    hp = header.paragraphs[0]
    for r in list(hp.runs):
        r._r.getparent().remove(r._r)
    if header_text:
        add_run(hp, header_text, FANGSONG, 9)
        fmt_para(hp, align=WD_ALIGN_PARAGRAPH.CENTER, line=1.0)
        add_bottom_border(hp)
    else:
        fmt_para(hp, align=WD_ALIGN_PARAGRAPH.CENTER, line=1.0)

    footer = section.footer
    footer.is_linked_to_previous = False
    fp = footer.paragraphs[0]
    for r in list(fp.runs):
        r._r.getparent().remove(r._r)
    if show_page:
        fmt_para(fp, align=WD_ALIGN_PARAGRAPH.CENTER, line=1.0)
        add_top_border(fp)
        add_run(fp, "第", FANGSONG, 10.5)
        r1 = fp.add_run()
        set_run_fonts(r1, FANGSONG, 10.5)
        fc1 = OxmlElement("w:fldChar")
        fc1.set(qn("w:fldCharType"), "begin")
        r1._r.append(fc1)
        r2 = fp.add_run()
        set_run_fonts(r2, FANGSONG, 10.5)
        instr = OxmlElement("w:instrText")
        instr.set(qn("xml:space"), "preserve")
        instr.text = " PAGE "
        r2._r.append(instr)
        r3 = fp.add_run()
        set_run_fonts(r3, FANGSONG, 10.5)
        fc2 = OxmlElement("w:fldChar")
        fc2.set(qn("w:fldCharType"), "end")
        r3._r.append(fc2)
        add_run(fp, "页", FANGSONG, 10.5)
    else:
        fmt_para(fp, align=WD_ALIGN_PARAGRAPH.CENTER, line=1.0)


def setup_styles(doc):
    normal = doc.styles["Normal"]
    normal.font.name = LATIN
    normal.font.size = Pt(12)
    normal.font.color.rgb = BLACK
    rPr = normal.element.get_or_add_rPr()
    rFonts = rPr.find(qn("w:rFonts"))
    if rFonts is None:
        rFonts = OxmlElement("w:rFonts")
        rPr.append(rFonts)
    rFonts.set(qn("w:ascii"), LATIN)
    rFonts.set(qn("w:hAnsi"), LATIN)
    rFonts.set(qn("w:eastAsia"), FANGSONG)
    for sid, east, size, bold in (
        ("Heading 1", HEITI, 16, True),
        ("Heading 2", KAITI, 14, True),
        ("Heading 3", FANGSONG, 12, True),
    ):
        st = doc.styles[sid]
        st.font.name = LATIN
        st.font.size = Pt(size)
        st.font.bold = bold
        st.font.color.rgb = BLACK
        rp = st.element.get_or_add_rPr()
        rf = rp.find(qn("w:rFonts"))
        if rf is None:
            rf = OxmlElement("w:rFonts")
            rp.append(rf)
        rf.set(qn("w:ascii"), LATIN)
        rf.set(qn("w:hAnsi"), LATIN)
        rf.set(qn("w:eastAsia"), east)
        col = rp.find(qn("w:color"))
        if col is None:
            col = OxmlElement("w:color")
            rp.append(col)
        col.set(qn("w:val"), "000000")
        theme = rp.find(qn("w:sz"))
        # 超链接样式改为黑色
    try:
        hyper = doc.styles["Hyperlink"]
        hyper.font.color.rgb = BLACK
        hyper.font.underline = False
        hrp = hyper.element.get_or_add_rPr()
        hcol = hrp.find(qn("w:color"))
        if hcol is None:
            hcol = OxmlElement("w:color")
            hrp.append(hcol)
        hcol.set(qn("w:val"), "000000")
    except KeyError:
        pass


def apply_page(section, header_cm=2.54, footer_cm=2.54):
    section.page_width = Cm(21.0)
    section.page_height = Cm(29.7)
    section.top_margin = Cm(header_cm)
    section.bottom_margin = Cm(footer_cm)
    section.left_margin = Cm(3.17)
    section.right_margin = Cm(3.17)
    section.header_distance = Cm(1.5)
    section.footer_distance = Cm(1.75)


def cover_info_table(doc):
    labels = ["作品名称：", "作品类别：", "作　　者：", "指导老师："]
    values = [
        "守望——基于多智能体编排的安全运营平台",
        "应用开发类",
        "",
        "",
    ]
    t = doc.add_table(rows=4, cols=2)
    t.alignment = WD_TABLE_ALIGNMENT.CENTER
    t.autofit = False
    widths = [1758, 5200]
    tbl = t._tbl
    tblPr = tbl.tblPr
    for tag, builder in (
        ("tblW", lambda: _tbl_w(sum(widths))),
        ("jc", lambda: _tbl_jc("center")),
        ("tblLayout", lambda: _tbl_layout()),
    ):
        old = tblPr.find(qn(f"w:{tag}"))
        if old is not None:
            tblPr.remove(old)
        insert_el(tblPr, builder(), TBLPR_ORDER)
    grid = tbl.find(qn("w:tblGrid"))
    for child in list(grid):
        grid.remove(child)
    for w in widths:
        gc = OxmlElement("w:gridCol")
        gc.set(qn("w:w"), str(w))
        grid.append(gc)
    for i, (lab, val) in enumerate(zip(labels, values)):
        left, right = t.cell(i, 0), t.cell(i, 1)
        left.width = Twips(widths[0])
        right.width = Twips(widths[1])
        left.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER
        right.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER
        # 左侧无框，右侧仅下边线
        for cell, bottom_only in ((left, False), (right, True)):
            tc = cell._tc
            tcPr = tc.get_or_add_tcPr()
            oldb = tcPr.find(qn("w:tcBorders"))
            if oldb is not None:
                tcPr.remove(oldb)
            borders = OxmlElement("w:tcBorders")
            for edge in ("top", "left", "bottom", "right"):
                el = OxmlElement(f"w:{edge}")
                if bottom_only and edge == "bottom":
                    el.set(qn("w:val"), "single")
                    el.set(qn("w:sz"), "4")
                    el.set(qn("w:color"), "000000")
                else:
                    el.set(qn("w:val"), "nil")
                el.set(qn("w:space"), "0")
                borders.append(el)
            insert_el(tcPr, borders, TCPR_ORDER)
            oldw = tcPr.find(qn("w:tcW"))
            if oldw is not None:
                tcPr.remove(oldw)
            tcW = OxmlElement("w:tcW")
            tcW.set(qn("w:w"), str(widths[0] if cell is left else widths[1]))
            tcW.set(qn("w:type"), "dxa")
            insert_el(tcPr, tcW, TCPR_ORDER)
        lp = left.paragraphs[0]
        add_run(lp, lab, HEITI, 15, True)
        fmt_para(lp, align=WD_ALIGN_PARAGRAPH.CENTER, line=1.5)
        rp = right.paragraphs[0]
        if val:
            add_run(rp, val, FANGSONG, 11 if i == 0 else 14, True)
        fmt_para(rp, align=WD_ALIGN_PARAGRAPH.CENTER, line=1.5)


def build_cover(doc):
    for text in (
        "湖南科技大学第4届大学生计算机程序设计竞赛暨",
        "湖南省第22届大学生计算机程序设计竞赛",
    ):
        p = doc.add_paragraph()
        add_run(p, text, HEITI, 16, True, ascii_font=HEITI)
        fmt_para(p, align=WD_ALIGN_PARAGRAPH.CENTER, before=2, after=2, line=1.8)
    p = doc.add_paragraph()
    add_run(p, "应用开发类竞赛（2026）", HEITI, 16, True, ascii_font=HEITI)
    fmt_para(p, align=WD_ALIGN_PARAGRAPH.CENTER, before=4, after=18, line=1.8)

    # 竖排大标题
    for ch in "系统设计说明书":
        p = doc.add_paragraph()
        add_run(p, ch, COVER_FANG, 26, True)
        fmt_para(p, align=WD_ALIGN_PARAGRAPH.CENTER, before=4, after=4, line=1.15, keep=True)

    p = doc.add_paragraph()
    fmt_para(p, before=18, after=6, line=1.0)
    cover_info_table(doc)

    p = doc.add_paragraph()
    add_run(p, "湖南科技大学", HEITI, 14, True)
    fmt_para(p, align=WD_ALIGN_PARAGRAPH.CENTER, before=36, after=0, line=1.5)
    p = doc.add_paragraph()
    add_run(p, "2026年9月", FANGSONG, 14, ascii_font=FANGSONG)
    fmt_para(p, align=WD_ALIGN_PARAGRAPH.CENTER, before=6, after=0, line=1.5)


# ---------------------------------------------------------------------------
# 正文
# ---------------------------------------------------------------------------

def ch_abstract(doc):
    p = doc.add_paragraph()
    add_run(p, "摘  要", HEITI, 16, True)
    fmt_para(p, align=WD_ALIGN_PARAGRAPH.CENTER, before=12, after=16, line=1.5, outline=1, keep=True)

    paras = [
        "本作品面向网络安全运营中告警规模大、数据来源分散、复杂事件研判依赖人工、普通大模型 Agent 工具调用缺乏约束等问题，设计并实现“守望”——基于多智能体编排的安全运营平台。系统从 syslog、API 等入口接入安全事件，经 Kafka 消息总线与 Flink 流处理完成数据源认证、Schema 校验、字段标准化、时间窗口去重、异常评分和 CEP 攻击链关联，再由 FastAPI 业务层完成事件存储、智能审计、自动响应和全链路可观测。",
        "在智能研判侧，系统将单次大模型调用拆解为 Decomposer、ToolBuilder、Executor、Reviewer 四层 Audit-LLM 流水线，使“问题拆解—工具规划—证据获取—结果复核”各阶段均形成结构化产物。针对 Agent 工具调用不稳定、越权、危险序列与证据幻觉问题，系统构建 Stabilizer、MCP Guard、SecurityGuard、Grounding Verifier 与 CAD 独立监督组成的多层可信控制体系，并通过审批、命令与资产双白名单、TTL 与 rollback_token 约束真实响应执行。",
        "在领域知识增强与持续演进方面，系统构建基于 MITRE ATT&CK、CAPEC、Playbook、安全基线与 CVE 等内容的 Hybrid RAG，采用 Qdrant 与 pgvector 双存储、RRF 融合、重排与知识审批状态控制；同时设计隔离式 Self-Play 红蓝对抗模块，将漏报样本转化为候选检测规则，经多道审核、影子期和复检后再进入规则体系。工程以 Docker Compose 组织 Kafka、Flink、FastAPI、React、PostgreSQL、Qdrant、Redis 及可观测性组件，形成从威胁发现、智能研判、受控工具调用到安全处置与反馈演进的端到端闭环。",
    ]
    for t in paras:
        p_body(doc, t)
    p = doc.add_paragraph()
    add_run(p, "关键词：", HEITI, 12, True)
    add_run(p, "安全智能体；安全运营；多智能体编排；MCP Guard；RAG；Flink CEP；Grounding；CAD；Self-Play", FANGSONG, 12)
    fmt_para(p, align=WD_ALIGN_PARAGRAPH.JUSTIFY, before=12, after=6, line=1.5, first=24)


def ch_toc(doc):
    p = doc.add_paragraph()
    add_run(p, "目  录", HEITI, 16, True)
    fmt_para(p, align=WD_ALIGN_PARAGRAPH.CENTER, before=12, after=16, line=1.5, outline=1, keep=True)
    p.paragraph_format.page_break_before = True
    items = [
        (0, "摘  要"),
        (0, "一、项目概述"),
        (1, "1.1  项目背景"),
        (1, "1.2  现有安全运营痛点"),
        (1, "1.3  项目定位"),
        (1, "1.4  设计目标"),
        (1, "1.5  项目主要贡献"),
        (0, "二、需求分析"),
        (1, "2.1  赛题任务分析"),
        (1, "2.2  功能需求"),
        (1, "2.3  非功能需求"),
        (1, "2.4  模型与平台接入要求"),
        (0, "三、系统总体设计"),
        (1, "3.1  总体设计思想"),
        (1, "3.2  系统总体架构"),
        (1, "3.3  事件生命周期"),
        (1, "3.4  关键技术取舍"),
        (0, "四、多源安全事件感知与实时检测"),
        (0, "五、安全审计智能体设计"),
        (0, "六、Agent 可信工具调用与自审计机制"),
        (0, "七、安全领域知识增强"),
        (0, "八、自动响应与安全处置闭环"),
        (0, "九、SuperAgent 自主闭环设计"),
        (0, "十、Self-Play 红蓝对抗与持续演进"),
        (0, "十一、数据与状态设计"),
        (0, "十二、系统工程实现与部署"),
        (0, "十三、系统测试与实验验证"),
        (0, "十四、项目创新点"),
        (0, "十五、同类方案对比"),
        (0, "十六、总结与展望"),
        (0, "参考文献"),
    ]
    for level, title in items:
        p = doc.add_paragraph()
        add_run(p, title, FANGSONG, 12)
        indent = 0 if level == 0 else 21
        fmt_para(p, before=2, after=2, line=1.5, first=0)
        p.paragraph_format.left_indent = Pt(indent)


def ch1(doc):
    h1(doc, "一、项目概述")
    h2(doc, "1.1  项目背景")
    p_body(doc, "赛题强调从场景化安全智能体、领域知识增强与工具扩展，进一步发展到具备复杂逻辑推理、跨域协同、工具调用、观测反馈与重新规划能力的 SuperAgent。网络安全场景天然具有数据来源多、事件速度快、分析链路长和处置风险高等特点，仅依赖规则检测或单次大模型问答，难以同时满足实时性、专业性与执行可信性。")
    p_body(doc, "本项目以安全运营为核心场景，将传统检测流水线与 Agent 自主研判机制结合：前端由 Kafka 与 Flink 负责稳定接入和实时流式处理，中间由 Audit-LLM 负责复杂事件研判，后端由受控工具调用、响应执行、独立监督和持续学习机制形成闭环。项目关注的重点并非替代成熟 SIEM 的大规模检索能力，而是探索“AI 原生、可审计、可回滚、可熔断”的安全智能体工程形态。")
    p_body(doc, "从安全运营流程看，传统系统更擅长完成采集、规则匹配和告警展示，复杂事件仍需分析人员在多个系统之间切换，手工查询资产、历史告警、攻击技战术和处置记录。大模型具备较强的语义理解与任务规划能力，能够补足这一环节；但如果缺乏数据约束、工具权限和结果验证，大模型的灵活性也可能转化为新的执行风险。因此，本项目将智能化能力和安全控制能力作为同等重要的设计对象。")
    p_body(doc, "总体思路是让不同技术承担各自适合的任务：确定性组件负责高吞吐、可重复的实时处理，Agent 负责需要上下文理解和多步骤判断的复杂研判，Guard 与监督模块负责限制不确定输出对真实环境的影响。这样的职责划分既保留传统安全工程的稳定性，又使系统具备更高层次的自主分析和闭环处置能力。")

    h2(doc, "1.2  现有安全运营痛点")
    p_body(doc, "第一类痛点是告警与日志规模持续增长，高价值告警仍需人工完成上下文拼接、证据查询和风险判断。传统规则适合识别已知模式，但对跨阶段攻击链、复杂上下文和多工具协同能力有限。")
    p_body(doc, "第二类痛点来自 Agent 自身。大模型能够生成分析与操作计划，但输出可能出现 JSON 结构错误、工具名幻觉、参数类型异常、角色越权、危险调用序列以及“结论有语义但证据不足”等问题。如果将大模型输出直接连接到具有真实执行能力的防火墙或 SSH 工具，系统风险会被进一步放大。")
    p_body(doc, "第三类痛点是“发现”与“处置”之间缺少可信桥梁。许多系统可以产生告警，也可以通过脚本完成封禁或隔离，但从告警结论到真实动作之间往往缺少统一的权限判断、参数检查、审批和回滚机制。对 AI Agent 而言，这一问题更加突出：一旦错误结论直接转化为高权限操作，影响范围会从一次错误回答扩大为真实业务中断。")
    p_body(doc, "第四类痛点是安全能力更新依赖人工。攻击模式、规则和知识库持续变化，仅依靠固定规则集会出现漏报，而直接让模型自动修改生产规则又会引入规则退化、误报扩大和知识污染风险。由此，本项目将持续演进能力设计为“候选—审核—影子—提升”的受控生命周期，而不是让学习结果直接进入生产。")

    h2(doc, "1.3  项目定位")
    p_body(doc, "守望是一个端到端的可信安全运营智能体平台。从安全日志接入开始，事件依次经历“校验 → 异常检测 → 攻击链关联 → LLM 深度审计 → 独立监督 → 受控响应 → 反馈演进”，使 Agent 在具备行动能力的同时保持可审计、可回滚与可熔断。")
    p_body(doc, "在产品形态上，平台同时具有“安全运营底座”和“可信 Agent 控制平面”两种属性。前者负责把多源事件转换为可分析、可追踪的统一安全对象，后者负责把大模型产生的分析计划限制在已注册工具、合法权限和可验证证据范围内。二者通过 eventId、trace_id、evidence_trail 与 audit_trail 等标识和记录连接，使每一次结论与动作都能够追溯到原始事实。")
    p_body(doc, "因此，本项目的差异化重点不是简单增加一个聊天式安全助手，而是让 Agent 真正进入安全运营链路，同时为其行动能力设置工程级边界。系统既允许低风险、可验证、可回滚的动作自动闭环，又为超出策略范围的操作保留审批和拒绝路径，从而在自动化效率与生产可控性之间建立可解释的平衡。")

    h2(doc, "1.4  设计目标")
    add_table(
        doc,
        ["目标", "核心要求", "对应实现"],
        [
            ["实时感知", "稳定接入多源日志并进行实时分流", "Kafka + Flink + Sigma + CEP"],
            ["自主研判", "将复杂事件拆解为可验证的分析任务", "Decomposer + ToolBuilder + Executor + Reviewer"],
            ["受控行动", "工具调用满足注册、权限、参数、策略和上下文要求", "Stabilizer + MCP Guard + SecurityGuard"],
            ["证据可信", "结论可回溯到事件字段、工具结果和知识证据", "Evidence Trail + Grounding + CAD"],
            ["安全处置", "响应动作经过策略、审批、白名单和结果验证", "Response Engine + Approval + TTL/Rollback"],
            ["持续演进", "从漏报中学习候选规则并经审核再进入生产", "Self-Play + Reviewer + Shadow/Promotion"],
        ],
        widths=[1400, 3600, 3312],
        title="表1-1  项目设计目标",
    )
    p_body(doc, "设计目标按照“感知—研判—行动—验证—恢复—演进”逐级展开。实时感知保证上游数据可用，自主研判解决复杂事件的语义分析问题，受控行动限制工具使用边界，证据可信保证结论可核验，安全处置保证动作可验证和可恢复，持续演进则负责将运行过程中发现的新问题反哺到规则体系。六类目标并非独立功能，而是同一事件生命周期中的连续控制点。")
    p_body(doc, "由表1-1可知，每个目标都对应明确的工程模块，避免仅以概念性“智能”作为实现依据。评审时可沿着任一安全事件验证目标是否真正落地：事件能否被实时接入、是否形成结构化研判、工具是否被 Guard 约束、结论是否有 Evidence、响应是否可回滚，以及新发现的漏报是否能够进入受控学习流程。")

    h2(doc, "1.5  项目主要贡献")
    p_body(doc, "项目的主要贡献可以概括为五点。第一，将 Kafka/Flink 的流式安全检测与 LLM Agent 研判连接为统一事件生命周期。第二，将单次 LLM 调用拆解为四层可审计流水线。第三，构建面向工具调用和结论使用的多层可信控制体系。第四，将响应决策与真实执行分离，并支持审批、TTL 与回滚。第五，在隔离环境中引入 Self-Play，使漏报能够转化为候选规则并通过多阶段审核形成持续演进闭环。")
    p_body(doc, "上述五项贡献形成了一个共同特征，即把 Agent 的可用性与可信性同时工程化。传统 Agent 原型往往证明模型能够完成某个任务即可，而本项目更关注模型在异常输出、工具调用失败、证据不足、外部组件不可用等情况下系统是否仍能保持明确状态和安全边界。为此，多个模块均设置降级、拒绝、审批或熔断路径，使系统不依赖一次模型生成的绝对正确。")


def ch2(doc):
    h1(doc, "二、需求分析")
    h2(doc, "2.1  赛题任务分析")
    p_body(doc, "赛题采用“基础任务—进阶任务—挑战任务”的分层递进方式。基础任务重点考察场景化安全智能体是否解决具体安全运营问题；进阶任务强调领域知识增强与工具扩展；挑战任务要求 SuperAgent 具备复杂逻辑推理、跨域协同、自主规划、工具调用、观测反馈和重新规划能力。基于此，本项目采用“检测底座负责实时确定性处理，智能体负责复杂不确定性研判，可信控制层约束行动与结论”的总体需求分解方式。")
    p_body(doc, "针对基础任务，本项目选择“安全事件自动研判与处置”作为明确场景，而不是构建泛化问答助手。其输入是经过校验和富化的真实安全事件对象，输出是结构化研判、证据、风险结论和响应建议。针对进阶任务，RAG 和工具调用把安全知识与外部行动能力纳入 Agent，而不是只依靠模型参数记忆。针对挑战任务，项目将复杂逻辑推理转化为可记录的子问题、工具计划、工具证据和复核结论，将跨域协同落实为日志、资产、知识和可对接安全数据的联合上下文，将观测—规划—行动—复核落实为可重规划循环。")

    h2(doc, "2.2  功能需求")
    add_table(
        doc,
        ["编号", "功能需求", "说明"],
        [
            ["F01", "日志接入与认证", "支持 syslog/API/模拟器进入 Kafka，并携带 API Key 完成来源识别"],
            ["F02", "实时校验与分流", "完成 JSON、Schema、字段标准化、去重、异常评分和分级路由"],
            ["F03", "攻击链检测", "利用 Flink CEP 识别多阶段攻击模式"],
            ["F04", "安全智能审计", "对高价值事件执行问题拆解、工具规划、证据获取和结论复核"],
            ["F05", "领域知识检索", "通过 Hybrid RAG 提供安全知识上下文"],
            ["F06", "受控工具调用", "拦截幻觉工具、越权、非法参数、危险序列和超频调用"],
            ["F07", "自动响应", "根据策略执行自动、审批或拒绝三类处置路径"],
            ["F08", "证据与监督", "记录 evidence_trail、audit_trail，并由 Grounding/CAD 独立复核"],
            ["F09", "持续学习", "Self-Play 将漏报转为候选规则并经审核、影子期、复检后提升"],
        ],
        widths=[900, 2000, 5412],
        title="表2-1  核心功能需求",
    )
    p_body(doc, "功能需求的设计原则是覆盖一条安全事件从进入平台到处置结束的全部关键节点，而不是按前后端页面拆分。F01—F03 构成确定性检测主干，负责保证进入 Agent 的事件已经具备合法来源、标准字段和基础风险信息；F04—F06 构成智能研判与可信工具调用主干；F07—F09 则负责响应、审计和持续演进，使系统形成闭环。")

    h2(doc, "2.3  非功能需求")
    p_body(doc, "系统的非功能需求重点围绕可靠性、可审计性、可恢复性、可扩展性和安全边界展开。Kafka 与 Flink 提供背压、重放与流处理能力；trace_id、evidence_trail 与 response_logs 提供跨模块追踪；安全响应通过 rollback_token 与 TTL 保留恢复路径；RAG 采用 Qdrant 与 pgvector 双路径以支持降级；关键后台任务由 health monitor 与 watchdog 提供运行状态检查。")
    p_body(doc, "可靠性方面，系统要求单个处理组件异常时尽量不破坏完整事件链。Kafka 提供消息缓冲与重放，Flink 通过状态与 Checkpoint 支持流处理恢复，RAG 在 Qdrant 不可用时保留 pgvector 兜底路径。安全性与可审计性方面，平台要求“输入有来源、调用有权限、结论有证据、执行有记录、异常可恢复”。因此，认证、Guard、Evidence、Response Log、Trace 与 CAD 并不是附属功能，而是非功能需求的核心实现。")

    h2(doc, "2.4  模型与平台接入要求")
    p_body(doc, "当前工程的 LLM 层采用 OpenAI 兼容 API 进行封装。该封装方式使上层 Decomposer、ToolBuilder、Reviewer 等组件与具体模型提供方解耦。面向比赛环境，模型接入层应保持接口稳定，在不改变 Agent 编排与 Guard 逻辑的前提下完成对指定安全大模型底座的适配与验证。")
    p_body(doc, "适配时需要重点验证三类兼容性：一是结构化输出是否稳定满足现有 Schema；二是工具调用语义能否被 Stabilizer 和 MCP Guard 正确处理；三是安全领域知识与提示词在新模型上的表现是否保持一致。模型能力变化不能绕过 Guard 逻辑，所有模型均应遵循相同的权限、参数、证据和响应边界。")


def ch3(doc):
    h1(doc, "三、系统总体设计")
    h2(doc, "3.1  总体设计思想")
    p_body(doc, "系统采用“确定性流处理 + 智能体研判 + 受控执行 + 独立监督”的分层思想。实时日志校验、阈值评分、规则匹配和 CEP 关联由流处理与规则引擎承担；需要语义理解、证据补全和策略推理的任务交由 Audit-LLM；具有真实影响的工具操作统一进入 Guard 与 Response Engine；最终结论由 Grounding 与 CAD 进行独立监督。这样的分工避免将所有职责压给单个大模型，也降低了大模型不稳定性直接扩散到生产执行面的风险。")
    p_body(doc, "这种分层设计本质上遵循“确定性优先、不确定性受控”的原则。能够由规则、状态机、Schema 或白名单确定的内容优先交给程序完成，例如字段合法性、工具是否注册、参数类型、角色权限和命令白名单；只有需要理解上下文、归纳证据或生成分析计划的部分才交给大模型。")
    p_body(doc, "同时，系统避免把监督完全交给同一个 Agent。Reviewer 属于主工作流内部复核，Grounding 负责证据约束，CAD 位于工作流外部进行独立监督，Response Engine 则在动作执行阶段再次做策略和安全检查。多层职责分离使任一模块发生判断偏差时，后续仍存在阻断或纠正机会。")

    h2(doc, "3.2  系统总体架构")
    p_body(doc, "如图3-1所示，系统自上而下划分为安全数据与环境层、实时感知与检测层、智能体决策层、可信执行层和监督反馈层。五层之间以结构化事件、工具计划、证据和审计结果为主要数据契约。各层只通过明确的数据对象交互，避免大模型直接跨层访问底层执行接口。")
    add_figure(doc, "fig-arch-overview.png", "图3-1  系统总体架构")
    add_table(
        doc,
        ["层级", "主要组件", "核心职责"],
        [
            ["安全数据与环境层", "syslog / API / WAF / Agent / 可对接 NDR、EDR", "提供日志、流量、端点和外部情报输入"],
            ["实时感知与检测层", "Kafka / Flink / Sigma / CEP", "校验、去重、评分、规则检测和攻击链关联"],
            ["智能体决策层", "Audit-LLM / RAG / Memory", "拆解问题、规划工具、获取证据、形成研判"],
            ["可信执行层", "Stabilizer / MCP Guard / SecurityGuard / Response", "约束工具调用并安全执行响应动作"],
            ["监督反馈层", "Grounding / CAD / Feedback / Self-Play", "验证结论、熔断风险、沉淀经验并持续演进"],
        ],
        widths=[2000, 3200, 3112],
        title="表3-1  五层架构职责",
    )
    p_body(doc, "五层架构既是功能划分，也是安全边界划分。特别是智能体决策层和可信执行层被刻意分开：前者可以提出动作，但无权直接完成高影响操作；后者不负责重新理解威胁，而是依据注册表、权限、策略和审批状态决定动作是否能够执行。")

    h2(doc, "3.3  事件生命周期")
    p_body(doc, "系统使用 eventId 标识业务事件。Kafka Header 携带 traceparent，Flink 通过 TraceUtil 建立追踪，Backend 将 traceparent 写入事件上下文并延续到前端追踪入口。事件从接入到复盘依次经过校验、检测、研判、监督、响应和归档阶段，如图3-2所示。")
    add_figure(doc, "fig-data-lifecycle.png", "图3-2  安全事件端到端生命周期")
    p_body(doc, "原始日志进入系统后不会直接成为 Agent 结论，而是依次形成 validated event、enriched event、alert/audit task、tool evidence、audit result 和 response record。每一阶段都保留上一步关键标识，从而能够回答：这个告警从哪里来、为什么被升级、Agent 调了什么、依据什么做出判断、最终执行了什么。")

    h2(doc, "3.4  关键技术取舍")
    add_table(
        doc,
        ["取舍", "选择", "主要理由", "代价"],
        [
            ["数据通道", "Kafka + Flink，而非仅 REST 同步", "支持解耦、背压、重放、横向扩展和 CEP", "部署复杂度与 Java 维护成本提高"],
            ["LLM 调度", "四层 Audit-LLM + CAD，而非单次调用", "每层产生可验证结构化产物，便于审计与定位错误", "调用链更长，增加时延和调试复杂度"],
            ["工具安全", "自建 MCP Guard + SecurityGuard", "MCP 协议本身不解决“该不该调用”的授权与风险问题", "策略与权限规则需要持续维护"],
        ],
        widths=[1400, 2500, 2600, 1812],
        title="表3-2  关键技术取舍与代价",
    )
    p_body(doc, "技术取舍的核心原则不是追求组件越多越好，而是针对安全运营的具体约束做权衡。Kafka + Flink 提高了部署复杂度，但换来了事件解耦、重放和 CEP；四层 Audit-LLM 增加调用时延，但换来了阶段产物和可定位性；MCP Guard 与 SecurityGuard 增加策略维护工作，但能够把 Agent 的工具使用从“模型自行决定”转化为“平台统一授权”。")


def ch4(doc):
    h1(doc, "四、多源安全事件感知与实时检测")
    h2(doc, "4.1  多源日志接入")
    p_body(doc, "系统以 Kafka 主题 security-logs-raw 作为主要原始日志入口，syslog-adapter、HTTP API 和 log_simulator 均可生成标准事件并携带 API Key。HTTP 入口 /api/logs/ingest 保留用于演示与单点测试，核心生产链路则采用 Kafka 与 Flink 解耦接入方和处理方。")
    p_body(doc, "接入层的首要任务是把不同来源的安全数据转换为统一 SecurityEvent，而不是立即判断威胁。标准事件至少需要能够描述时间、来源、事件类型、严重度、网络实体和原始消息等关键上下文，并保留数据源标识。API Key 的作用不仅是简单鉴权，也为后续来源信誉、拒绝审计和问题定位提供基础。系统将未认证或结构异常的数据在进入 Agent 前隔离，避免不可信输入直接参与大模型研判。")

    h2(doc, "4.2  LogValidation 校验流水线")
    p_body(doc, "Flink Job1 按顺序完成 JSON 解析、Schema 校验、API Key 认证、字段标准化、60 秒去重和数据源信誉评分。解析或校验失败的事件进入 security-logs-rejected，并携带 rejectionType、rejectionReason、rawMessage 与 rejectedAt 等信息；通过校验的事件进入 security-logs-validated。该设计使非法数据与可信事件在进入智能研判前就被隔离。")
    p_body(doc, "LogValidation 采用顺序校验是为了让错误尽可能早地被定位。JSON 无法解析时无需继续做 Schema 和认证；结构合法后再验证必填字段、枚举、IP 与时间戳等约束；数据源认证通过后才进入标准化、去重与信誉处理。60 秒去重用于抑制短时间内完全重复的事件，字段标准化则解决 severity、eventType 和时间格式差异，使异常评分与规则匹配获得稳定输入。")

    h2(doc, "4.3  异常评分与智能路由")
    p_body(doc, "Flink Job2 使用事件时间水印处理一定范围内的乱序事件，并基于源 IP 维护状态进行多维异常评分。当前评分由频率、严重度与时段组成：5 分钟滑窗事件数超过阈值增加频率分，critical/high/medium 等严重度映射不同权重，0—5 点事件额外增加时段风险，最终得分限制在 0—1。高分、高严重度或 CEP 命中事件进入 security-alerts；中分事件进入 security-audit-queue；所有富化事件写入 security-events-enriched。")
    p_body(doc, "异常评分的定位是快速分流而非替代完整威胁判断。并非所有日志都需要经过 LLM，只有达到审计条件的事件才进入复杂分析。三路输出实现“告警、审计、存储”职责分离，同一高危事件可以在被快速告警的同时保留完整事件并进入审计。")

    h2(doc, "4.4  CEP 攻击链关联")
    p_body(doc, "单条事件往往不足以描述完整攻击过程，因此系统使用 Flink CEP 将具有时间和顺序关系的事件关联为攻击链。当前定义了 port_scan_to_c2、lateral_movement 与 data_exfil 三类模式，分别覆盖“端口扫描 → 暴力破解 → C2 信标”“可疑登录 → 文件访问 → 横向移动”和“文件访问 → 数据外泄”等路径。")
    p_body(doc, "CEP 的价值在于将多个看似普通的事件提升为具有攻击语义的序列。例如端口扫描本身可能只是侦察，暴力破解也可能是单独事件，但在限定时间窗内进一步出现 C2 信标时，三者组合能够形成更强的攻击链证据。扩展原则仍应保持“可解释规则先形成候选攻击链，再交给 Agent 做语义补全与处置研判”。")

    h2(doc, "4.5  Kafka Topic 设计")
    add_table(
        doc,
        ["Topic", "写入者", "读取者", "用途"],
        [
            ["security-logs-raw", "syslog-adapter / simulator", "Flink Job1", "原始未校验日志"],
            ["security-logs-validated", "Flink Job1", "Flink Job2", "已通过校验、待评分"],
            ["security-logs-rejected", "Flink Job1", "归档/审计", "拒绝事件及原因"],
            ["security-events-enriched", "Flink Job2", "Backend", "富化全量事件"],
            ["security-alerts", "Flink Job2", "Backend", "高优先级告警"],
            ["security-audit-queue", "Flink Job2", "Backend", "中分待 LLM 审计"],
            ["security-audit-results", "Backend", "前端/归档", "LLM 审计结果"],
            ["security-logs-dlq", "Flink", "人工", "死信兜底"],
            ["security-cep-partial", "Flink", "提示/审计", "攻击链部分匹配"],
            ["security-sigma-hit", "Flink / Sigma", "聚合", "Sigma 命中去抖聚合"],
        ],
        widths=[2600, 2000, 1600, 2112],
        title="表4-1  Kafka Topic 矩阵",
    )
    p_body(doc, "Topic 按事件阶段而不是业务页面划分，使生产者与消费者之间保持松耦合。raw、validated 和 rejected 描述输入可信化过程，enriched、alerts 和 audit-queue 描述检测分流结果，audit-results 描述智能审计输出。对故障排查而言，可以沿 Topic 顺序判断事件在哪一阶段停止；对扩展而言，新消费者只需订阅对应 Topic 而无需改动上游生产者。")

    h2(doc, "4.6  Sigma 规则检测")
    p_body(doc, "Sigma 引擎以 pySigma 为默认模式，通过 SigmaCollection 加载 YAML 规则并转换为可执行谓词；当 pySigma 不可用时可降级到 legacy Python 字典规则。项目内置 SIG-001 至 SIG-011 等规则，覆盖登录爆破、路径遍历、SQL 注入、Webshell、XSS、SSRF、命令注入、异常外发、可疑进程、横向移动和权限提升等场景。")
    p_body(doc, "Sigma 规则提供了与大模型互补的确定性检测能力。对于登录爆破、Web 攻击、异常外发和横向移动等已知模式，规则命中具有稳定、可重复和可审计的优势；Agent 则主要处理规则无法直接解释的上下文、关联关系和响应策略。规则命中结果还可作为 Agent 的显式证据，而不是只生成一个无来源的风险标签。")


def ch5(doc):
    h1(doc, "五、安全审计智能体设计")
    h2(doc, "5.1  从单次问答到分层研判")
    p_body(doc, "普通“告警 → LLM → 结论”模式将问题理解、工具选择、证据获取和最终判断混合在一次生成中，一旦输出错误，很难判断错误发生在计划、工具调用还是结论阶段。本项目将安全审计拆分为 Decomposer、ToolBuilder、Executor 和 Reviewer 四层，并由 Sub-Auditor 提供平行多视角交叉验证。")
    add_figure(doc, "fig-audit-pipeline.png", "图5-1  Audit-LLM 四层研判流水线")
    p_body(doc, "四层流水线的核心价值是把一次不可见、难定位的生成过程拆成多个可检查的工程节点。Decomposer 只负责确定还需要验证哪些问题，ToolBuilder 只负责选择用什么能力验证，Executor 负责安全地获取事实，Reviewer 再基于事实形成最终判断。每层输入输出均可以落日志、回放和单独测试。")

    h2(doc, "5.2  Decomposer：任务拆解")
    p_body(doc, "Decomposer 接收 AnomalyReport 或富化事件，将复杂安全问题拆解为结构化子问题，例如攻击类型、影响范围、紧急程度、需要补充的资产信息、是否存在关联攻击阶段等。其输出 structured_subproblems[] 不直接执行动作，而是为后续工具规划提供明确目标，从而避免模型在缺少证据时直接跳到最终结论。")
    p_body(doc, "任务拆解应尽量围绕可验证事实。例如“是否存在横向移动”可以拆成源主机是否出现异常身份登录、是否访问新的主机或文件资源、是否存在对应进程或网络连接等子问题。复杂事件如果一次性把所有上下文交给模型，容易导致注意力分散和工具调用失控；拆分后可以给每个子任务定义优先级和所需证据。")

    h2(doc, "5.3  ToolBuilder：工具规划")
    p_body(doc, "ToolBuilder 根据子问题、事件上下文和可用工具清单生成 tool_plan[]。典型工具包括 RAG 检索、Sigma 重检测、资产查询和案例检索。该层把“需要知道什么”转化为“应该调用什么”，并将具体调用交给 Executor，而非由自然语言结论直接触发真实工具。")
    p_body(doc, "若 RAG 已能回答技战术解释问题，就不应无意义调用具有真实环境影响的执行工具；若事件缺少资产归属，则优先查询资产而不是直接生成封禁建议。工具规划结果随后仍会经过 Stabilizer 和 Guard，因此 ToolBuilder 的输出属于候选计划而不是授权结果。")

    h2(doc, "5.4  Executor：受控执行与证据收集")
    p_body(doc, "Executor 是实际工具调用的执行层，但不直接信任大模型原始输出。调用计划首先进入 Stabilizer 完成结构修复、工具名归一和参数强转，再依次经过 MCP Guard 的注册、权限、参数与策略检查，以及 SecurityGuard 的意图、序列、频率和上下文审查。所有检查通过后才执行真实工具，并将返回结果写入证据轨迹供 Reviewer 与 CAD 复核。")
    p_body(doc, "工具执行结果被统一封装为可审计证据，包括成功结果、失败原因、关键字段和调用上下文。失败也不会被静默丢弃，而是进入 evidence_trail，供 Reviewer 判断是否需要换工具、补充查询或降低结论置信度。“工具没返回数据”本身也成为可解释状态，而不是诱导模型自行补全不存在的事实。")

    h2(doc, "5.5  Reviewer：结果复核")
    p_body(doc, "Reviewer 读取事件、子问题、工具结果和已有证据，检查是否存在威胁遗漏、证据冲突、置信度不足或幻觉风险，并形成 final_verdict、confidence 与建议 actions。它会比较 structured_subproblems 与 tool_results，确认关键问题是否都获得证据；比较不同工具结果是否矛盾；检查 final_verdict 是否超出了已获取事实。")
    p_body(doc, "若证据不足，Reviewer 可以要求补充验证而不是强制输出确定结论。对安全运营而言，“UNKNOWN / 证据不足”通常比一个过度自信的错误结论更安全。主流程完成后 CAD 仍会再次检查关键 claim，因此 Reviewer 与 CAD 分别承担工作流内质量控制和工作流外独立监督。")

    h2(doc, "5.6  结构化决策轨迹")
    add_table(
        doc,
        ["阶段", "结构化产物", "审计意义"],
        [
            ["发现异常", "AnomalyReport / SecurityEvent", "保留原始事实和规则/评分来源"],
            ["提出假设", "structured_subproblems[]", "把复杂事件拆成可验证问题"],
            ["规划验证", "tool_plan[]", "记录为何需要某类工具或知识"],
            ["执行取证", "tool_results[]", "保存真实工具返回与错误信息"],
            ["形成判断", "final_verdict + confidence", "给出结论与风险水平"],
            ["独立监督", "cad_report", "验证 claim 与 evidence 的一致性"],
        ],
        widths=[1600, 3000, 3712],
        title="表5-1  安全审计结构化决策轨迹",
    )
    p_body(doc, "结构化决策轨迹把一次安全研判拆成若干可回放的状态。测试不必只断言最终文本是否正确，还可以检查子问题是否完整、工具计划是否越权、Evidence 是否包含必要字段、Reviewer 是否在证据不足时降低置信度，以及 CAD 是否正确识别不一致 claim。")


def ch6(doc):
    h1(doc, "六、Agent 可信工具调用与自审计机制")
    h2(doc, "6.1  工具调用风险模型")
    p_body(doc, "当 Agent 具有真实安全工具调用能力时，风险不再局限于回答错误，而会扩展为工具幻觉、参数异常、角色越权、危险命令拼接、重复调用、频率失控、上下文不匹配以及缺乏证据的错误响应。为此，项目将调用合法性、行为合理性与结论可信性拆分为不同防线，避免单点安全检查承担全部职责。")
    add_figure(doc, "fig-guard-layers.png", "图6-1  Agent 工具调用与结论使用的可信防线")
    p_body(doc, "风险模型按照“格式风险—授权风险—行为风险—证据风险—系统性风险”逐层展开。五道防线分别针对不同风险面：Registry 拒绝不存在工具，Permission 拒绝越权，Validator 拒绝参数错误，SecurityGuard 拒绝危险行为序列，Grounding 拒绝无证据 claim，CAD 则在更高层判断整条流水线是否应该继续自动运行。")

    h2(doc, "6.2  Stabilizer：输出稳定化")
    add_table(
        doc,
        ["步骤", "模块", "处理内容"],
        [
            ["1", "json_repair.py", "截取首段 JSON、处理尾随逗号与常见转义错误"],
            ["2", "tool_resolver.py", "工具名归一，例如 nmap → security_tool.nmap"],
            ["3", "param_coercer.py", "参数类型强转，例如字符串“80”转为整数 80"],
            ["4", "stabilizer.py / Schema", "完成编排与最终 Schema 校验"],
        ],
        widths=[900, 2400, 5012],
        title="表6-1  Stabilizer 四步处理",
    )
    p_body(doc, "Stabilizer 位于模型输出和权限判断之间，其目标是把可修复的不稳定与必须拒绝的不合法区分开。例如工具名存在已知别名、数字参数以字符串形式返回时可以规范化；但如果修复后仍不满足 Schema，系统应明确失败，而不能继续猜测模型意图。Stabilizer 不负责权限和业务策略，其输出仍然只是标准化调用对象。")

    h2(doc, "6.3  MCP Guard：四层调用控制")
    p_body(doc, "MCP Guard 的目标是回答“这个调用是否被允许”。第一层 Tool Registry 仅允许调用已注册工具；第二层 Permission Manager 基于角色执行 RBAC；第三层 Validator 使用 Pydantic 对参数进行结构和类型验证；第四层 Policy Engine 根据规则组合进行最终判定。超出自动规则边界的请求可进入 approval_queue，所有调用由 call_logger 记录。")
    add_table(
        doc,
        ["层", "控制问题", "拦截示例"],
        [
            ["Registry", "工具是否真实存在并已注册", "模型生成不存在的 delete_everything 工具"],
            ["Permission", "当前角色是否有资格调用", "只读审计角色尝试执行封禁"],
            ["Validator", "参数结构与类型是否正确", "端口为非法字符串、IP 格式不合法"],
            ["Policy", "调用是否符合安全策略", "高风险目标、阈值、组合规则不满足"],
        ],
        widths=[1600, 2800, 3912],
        title="表6-2  MCP Guard 四层控制职责",
    )

    h2(doc, "6.4  SecurityGuard：动态行为防护")
    p_body(doc, "SecurityGuard 与 MCP Guard 的职责不同：MCP Guard 偏向工具注册、角色权限、参数和规则层的合法性；SecurityGuard 关注“在当前上下文中是否应该执行”。其 intent_checker、sequence_guard、rate_limiter 与 context_manager 分别约束危险意图、异常调用序列、超频调用和上下文不一致行为。")
    p_body(doc, "某个 block_ip 工具在权限和参数上都合法，但如果 Agent 在短时间内连续封禁大量地址、先执行侦察后突然触发破坏性动作，或当前事件目标与调用对象不一致，仍可能存在风险。静态 RBAC 无法充分表达这些动态条件，因此需要序列、频率和上下文层面的检查。")

    h2(doc, "6.5  Grounding：证据约束")
    p_body(doc, "Grounding Verifier 解决“结论是否有证据”的问题。系统优先对 evidence_trail 中的 claim 进行程序化字段溯源，再使用知识库证据交叉验证，必要时才使用 LLM 进行复核。该机制避免简单采用“再问一个模型判断上一个模型是否正确”的单一监督方式。")
    p_body(doc, "例如“源 IP 在过去 5 分钟出现高频失败登录”应能够回溯到事件字段和聚合结果，“该行为对应某 ATT&CK 技术”应能引用知识库条目，“目标资产为关键服务器”应来自资产查询而不是模型猜测。程序化溯源优先于 LLM 复核，可以减少“模型监督模型”带来的同源偏差。")

    h2(doc, "6.6  CAD：独立监督与熔断")
    p_body(doc, "CAD 位于主 Audit-LLM 流水线之外。主审计流程结束后，CAD 对证据轨迹中的关键断言进行穿透验证，并综合计算幻觉风险与证据完整度；熔断器持续累计审计风险指标，当风险超过阈值时暂停大模型自动审计，降级为 Sigma 与异常评分规则路径，冷却约 5 分钟后进入半开试探。")
    p_body(doc, "CAD 的独立性体现在它不参与主 Agent 的计划和执行，而是在主流程完成后基于已有产物重新检查关键断言。它可以从 PostgreSQL、Qdrant 等数据源穿透验证，而不是直接接受 Reviewer 的文字结论。这样即使主 Agent 多个阶段形成一致但错误的叙述，CAD 仍有机会从原始事实发现偏差。")

    h2(doc, "6.7  人工审批与调用审计")
    p_body(doc, "对于自动规则无法安全放行的调用，系统保留人工审批通道。低风险且策略允许的动作可自动执行，中风险动作进入审批，高风险或破坏性动作直接拒绝。无论自动还是人工路径，调用请求、判定结果、实际工具结果和后续响应均写入审计记录。审批单应携带威胁摘要、建议动作、目标资产、风险等级、关键 Evidence 和 Guard 判定，使审批者能够基于结构化信息快速决策。")


def ch7(doc):
    h1(doc, "七、安全领域知识增强")
    h2(doc, "7.1  知识库内容与来源")
    p_body(doc, "项目的 RAG 知识库面向安全研判而非通用问答。启动期 seed_knowledge_base 预置 MITRE 条目、Playbook、Windows/Linux/网络/云安全基线以及典型 CVE；同时提供 MITRE/CAPEC STIX 异步全量与增量导入，并允许内部文档通过 HTTP 入口提交。知识库内容按照“攻击知识、处置知识、环境基线和内部经验”组织。")
    p_body(doc, "不同来源具有不同可信级别，因此知识导入不能只关注向量化效果，还需要保留来源、版本、审批状态和更新时间等元数据。Agent 在引用知识时应尽可能保留文档标识，使结论能够回到原始知识条目，而不是只返回一段无法追踪来源的生成文本。")

    h2(doc, "7.2  Hybrid RAG 检索")
    p_body(doc, "检索流程由 Query Transform、Embedding、Hybrid Search、RRF 融合、Rerank、Context Builder 与 Evidence Verifier 构成。Qdrant 作为首选混合检索后端，使用 dense、BM25 sparse 与服务端 Fusion.RRF；当 Qdrant 不可用时，系统可降级到 pgvector + ts_rank 并在进程内执行 rrf_fuse。对于 CVE、T-ID、哈希等精确词，系统设置词法短路，避免密集向量近邻淹没精确匹配结果。")
    add_figure(doc, "fig-rag-pipeline.png", "图7-1  安全领域 Hybrid RAG 检索与证据验证")
    p_body(doc, "安全检索同时存在语义相似和精确标识两类需求。自然语言威胁描述更适合 dense embedding，CVE 编号、ATT&CK Technique ID、哈希和命令片段则更依赖词法精确匹配。最终进入 Agent Prompt 的内容是筛选后的有限证据，而不是整个知识库，从而控制上下文长度并减少低相关文档对模型判断的干扰。")

    h2(doc, "7.3  重排与降级策略")
    p_body(doc, "RAG 重排采用三级降级：优先调用 HTTP cross-encoder；不可用时采用 overlap、title_hit、exact 等特征进行无网络重排；仍需要时可退化到 LLM list-rerank。降级必须被显式记录，避免把降级结果误认为与正常路径同等可信。Retriever 日志可记录本次使用的重排方式、检索耗时和降级原因，Reviewer 或 CAD 在证据质量较低时也可以相应降低置信度。")

    h2(doc, "7.4  知识库防投毒")
    p_body(doc, "内部知识并非上传后立即进入 Agent 上下文。系统设置 pending、approved、signed_import 与 rejected 等状态：内部文档默认 pending，需要第二人审批后变为 approved；签名来源可进入 signed_import；被拒绝内容标记为 rejected。检索阶段再次过滤未审批文档，形成“写入审批 + 检索过滤”的双重控制。")
    p_body(doc, "如果攻击者能够提交伪造的内部文档并立即被 Agent 检索，后续所有基于该文档的分析与响应都有可能受到影响。因此，系统把知识写入和知识可检索状态分离。Self-Play 漏报反哺写入的知识同样需要审批后才进入生产检索。")

    h2(doc, "7.5  双向量存储与降级")
    add_table(
        doc,
        ["维度", "Qdrant", "pgvector"],
        [
            ["主要数据", "RAG chunks + agent memories", "knowledge_chunks.embedding + memories.embedding"],
            ["混合检索", "首选，服务端 Fusion.RRF", "进程内 rrf_fuse 兜底"],
            ["维度防御", "Collection 创建时 size=embedding_dim", "SQL vector_dims() 校验"],
            ["故障处理", "连接失败时返回空并降级", "作为常驻兜底路径"],
        ],
        widths=[1600, 3300, 3412],
        title="表7-1  Qdrant 与 pgvector 分工",
    )
    p_body(doc, "Qdrant 与 pgvector 并行并不是简单复制数据，而是形成“主检索能力 + 数据库兜底”的分工。两条路径都设置 embedding 维度防御，防止模型或配置变化后错误维度数据静默写入。")


def ch8(doc):
    h1(doc, "八、自动响应与安全处置闭环")
    h2(doc, "8.1  响应总体流程")
    p_body(doc, "威胁研判完成后，response_orchestrator.on_threat_detected() 进入响应决策链。Policy Engine 先匹配预置策略，再根据动作风险确定自动执行、提交审批或拒绝；通过 SecurityGuard 后，Response Executor 继续执行命令白名单、资产白名单、execution_modes 与 safe_executor 二次校验，随后调用 ssh_firewall 或 transport 完成真实执行，并由 post_validator 验证结果。")
    p_body(doc, "响应流程采用“先形成动作意图，再进行执行授权”的两阶段模式。即使 Agent 研判正确，系统仍不会省略执行面的安全检查；反之，即使执行失败，也能通过日志和验证结果回传给后续复盘。")

    h2(doc, "8.2  策略与风险分级")
    add_table(
        doc,
        ["威胁类型", "策略动作", "风险控制"],
        [
            ["端口扫描", "临时封禁约 30 min", "策略匹配 + SecurityGuard + TTL"],
            ["SSH 爆破", "临时封禁约 1 h", "双白名单 + 执行后校验"],
            ["C2 信标", "高优先级封禁约 24 h", "高风险策略控制 + 完整审计"],
            ["数据外泄", "告警并等待审批", "避免破坏性自动处置"],
        ],
        widths=[1800, 2800, 3712],
        title="表8-1  典型响应策略示例",
    )
    p_body(doc, "策略分级综合考虑威胁紧急程度、动作影响范围和可恢复性。端口扫描或 SSH 爆破可以采用具有 TTL 的临时封禁，因为动作范围较小且能够自动回收；C2 信标需要更高优先级处理但仍要求完整审计；数据外泄涉及业务连续性和证据保全，默认等待审批比直接执行破坏性隔离更稳妥。")

    h2(doc, "8.3  决策与执行分离")
    p_body(doc, "项目将“决定做什么”和“实际执行”设计为两个阶段。Agent 或 Policy Engine 生成的动作只表示响应意图，真实执行还需通过 SecurityGuard、command_whitelist、asset_whitelist、safe_executor 和 post_validator。决策层输出应采用结构化 Action Plan，例如动作类型、目标、持续时间、理由和证据引用，而不是直接返回 shell 命令。")
    p_body(doc, "分离后，Policy Engine 可以在不触达真实设备的情况下完成单元测试和策略回放，Executor 也可以在 dry-run 或 soft 模式下验证命令生成与权限边界。对竞赛演示而言，可以明确展示“Agent 提出建议”和“平台批准并执行”是两个不同事件。")

    h2(doc, "8.4  TTL 与回滚")
    p_body(doc, "每个已执行动作写入 response_logs，并保留 rollback_token。对于临时封禁等具有时效性的动作，ttl_manager 安排到期回收；若执行造成误影响，可根据 rollback_token 进行反向撤销。响应完成后告警状态更新为 responded，并可绑定 case、进入 Post-Mortem 与 FeedbackLoop。")
    p_body(doc, "回滚并不等同于所有动作都可完全恢复，因此策略设计仍应优先选择可逆动作。系统需要记录执行前关键状态和 post_validator 结果，确保发生误处置时能够判断回滚是否成功。")


def ch9(doc):
    h1(doc, "九、SuperAgent 自主闭环设计")
    h2(doc, "9.1  SuperAgent 定义")
    p_body(doc, "本项目中的 SuperAgent 不是单个无限权限模型，而是由流式感知、四层智能研判、受控工具调用、环境反馈和独立监督共同组成的复合智能体。其核心能力是理解安全事件后自主拆解任务、选择工具、读取工具结果、更新判断，并在证据不足或结果矛盾时重新规划。")
    p_body(doc, "SuperAgent 的“超级”不来源于无限工具数量或无限权限，而来源于能够跨多个阶段组织任务并根据反馈调整计划。实时检测提供初始 Observation，Decomposer 与 ToolBuilder 形成 Plan，Executor 在受控条件下 Act，Reviewer 与 Grounding 对结果 Review，必要时再回到 Replan。只有在“能自主完成任务”和“能被约束、解释与停止”同时成立时，系统才具备可信自主运营意义。")

    h2(doc, "9.2  多源安全数据协同")
    p_body(doc, "SuperAgent 的上下文由 SecurityEvent、资产信息、RAG 知识、历史 Memory、Sigma/CEP 检测结果和工具返回证据共同构成；NDR、EDR、ThreatIntel、Phishing、Sandbox 等组件在当前工程中作为可对接能力并默认关闭。该边界保证文档不将接口能力描述为已经内置运行的外部产品。")
    p_body(doc, "多源协同的重点不是简单把更多数据拼进 Prompt，而是围绕同一 eventId 和实体关系组织上下文。事件日志提供发生了什么，资产信息解释目标价值和归属，Sigma/CEP 提供确定性检测依据，RAG 提供攻击知识与处置知识，历史 Memory 提供类似事件经验，工具结果则补充当前环境事实。")

    h2(doc, "9.3  自主规划与工具选择")
    p_body(doc, "Decomposer 将复杂攻击事件转化为待验证问题，ToolBuilder 再依据工具注册表和任务上下文形成计划。这样，Agent 的推理过程以结构化问题、工具计划、证据和结论形式被保存，而不是依赖不可审计的自由文本过程。")
    p_body(doc, "自主规划应受任务目标和预算边界约束。ToolBuilder 需要优先选择能够最快补足关键证据的工具，避免无目的遍历全部工具；对高成本或高风险工具，则应在证据不足时保持谨慎。计划还可以定义依赖关系，例如只有资产查询确认目标属于受管资产后，才允许继续生成响应建议。")

    h2(doc, "9.4  观测、反馈与重新规划")
    p_body(doc, "Executor 调用工具后，返回值不是简单拼接到回答，而是进入 evidence_trail；Reviewer 判断证据是否足以支持当前结论，若发现遗漏或冲突，则重新生成验证任务。重新规划的触发条件应来自明确反馈，例如工具执行失败、关键字段缺失、不同证据互相矛盾、Grounding 无法支持关键 claim 或 Reviewer 判断置信度不足。")
    p_body(doc, "触发后 Agent 只补充当前缺失的验证任务，而不是无条件重跑整个流程。该闭环还与 SecurityGuard 的序列和频率控制协同：即使 Reviewer 要求重试，新的工具调用仍需重新经过 Guard，防止“重规划”成为绕过限流和权限的路径。")

    h2(doc, "9.5  闭环边界")
    p_body(doc, "赛题提出挑战“零人工干预”的安全运营极限，但真实安全响应具有业务影响。本项目选择风险分级：可验证、可回滚的低风险动作允许自动闭环；超出策略边界的动作进入人工审批；高风险或破坏性动作拒绝执行。自动闭环的边界由动作风险、可逆性、资产敏感度和证据完整度共同决定，而不是仅由模型置信度决定。")
    p_body(doc, "这种边界设计使“零人工干预”成为可逐步扩展的能力，而不是一次性开放全部权限。随着真实环境测试增加，可以根据误报、回滚和审批数据调整自动化范围，在保证安全的前提下逐步提高 Agent 自主处置比例。")


def ch10(doc):
    h1(doc, "十、Self-Play 红蓝对抗与持续演进")
    h2(doc, "10.1  设计目标")
    p_body(doc, "固定检测规则面对新型攻击时需要人工持续维护。Self-Play 模块在隔离仿真环境中构造“红队规划攻击—蓝队检测—漏报学习—候选规则审核—影子验证—规则提升”闭环，用于探索检测能力的持续演进。该模块默认 self_play_inject=False，仿真事件仅在 self-play session 内流转，不触发生产审计、案例或告警。")
    add_figure(doc, "fig-selfplay-loop.png", "图10-1  Self-Play 红蓝对抗与规则持续演进")
    p_body(doc, "Self-Play 的核心问题是如何把发现漏报转化为可安全使用的新检测能力。如果只生成更多攻击样本而不形成规则改进，系统无法积累；如果直接让模型写规则进入生产，又可能扩大误报或被合成数据特征过拟合。因此，模块同时设计攻击生成、漏报学习和规则治理三部分。")

    h2(doc, "10.2  Red Agent 与仿真环境")
    p_body(doc, "RedAgent 从课程目录 L0—L6、RAG/LLM 或词法兜底中规划攻击场景，SimEnv 将计划物化为带 ground-truth 和 fingerprint 的 MaterializedEvent。当前仿真为进程内拓扑，不真正启动漏洞容器，也不调用 nmap、hydra、sqlmap 等真实攻击工具，确保红队训练与生产执行面隔离。")
    p_body(doc, "Red Agent 的任务是生成具有可解释攻击意图和 ground-truth 的场景，而不是执行真实入侵。由于当前不运行真实漏洞容器和攻击工具，Self-Play 的结果主要用于验证检测逻辑与规则学习流程，不能等同于真实攻防环境效果。")

    h2(doc, "10.3  Blue Observer 与漏报学习")
    p_body(doc, "BlueObserver 复用生产 Sigma 和 Overlay 检测器，并在 inject=True 时可选用 Audit-LLM。NoveltyIndex 根据历史指纹衡量新颖度；BlueLearner 仅从 is_attack 且未检测到的 FN 样本生成 LearnedRule，并写入 overlay 与候选规则表，而不直接修改正式 Sigma。这样学习器负责提出候选，Reviewer 负责证明候选值得进入下一阶段。")

    h2(doc, "10.4  规则审核与影子期")
    add_table(
        doc,
        ["门", "检查内容", "目的"],
        [
            ["G0", "退化/恒真/空规则检测", "阻止无意义规则"],
            ["G1", "同伴规则 Jaccard 重复检测", "避免候选规则重复"],
            ["G1b", "与现有 Sigma token 重复检测", "避免重复写入生产规则"],
            ["G2", "FP Replay 控制误报率", "避免过宽规则进入生产"],
            ["G3", "可迁移性检查", "要求包含至少一个非合成 message/url token"],
            ["G4", "大模型语义复核（fail-open）", "判断规则是否有意义、是否具备生产价值"],
            ["G5", "历史对局 Replay A/B（fail-open）", "验证规则对历史攻击的实际命中能力"],
        ],
        widths=[900, 3200, 4212],
        title="表10-1  Self-Play 候选规则审核机制",
    )
    p_body(doc, "通过审核的规则进入 shadow 状态并写入 rules_selfplay_shadow 目录，默认影子期 24 小时；到期后再次执行 G2 复检，满足条件则 promoted，否则 dismissed。该状态机避免 Self-Play 学到的规则直接污染生产检测。")

    h2(doc, "10.5  评分指标")
    add_table(
        doc,
        ["指标", "计算方式", "含义"],
        [
            ["ASR", "fn / attacks", "红队攻击成功率"],
            ["Recall", "tp / attacks", "蓝队召回率"],
            ["Precision", "tp / (tp + fp)", "蓝队精确率"],
            ["Novelty", "1 - max_jaccard", "攻击新颖度"],
            ["MTTD", "TP 的检测时延均值", "平均发现时间"],
            ["Compounding", "规避攻击被 overlay 抓住 / 规避攻击总数", "衡量自学习有效率"],
        ],
        widths=[1800, 3200, 3312],
        title="表10-2  Self-Play 单回合指标",
    )
    p_body(doc, "指标同时覆盖红队效果、蓝队检测质量、发现速度和学习收益。单看 Recall 不能完整评价 Self-Play。例如通过极宽规则提高 Recall 可能导致 Precision 下降，因此规则审核仍需结合 FP Replay。设计口径示例为：blue 为 recall≥0.7 且 asr≤0.35，red 为 asr≥0.5，其余为 draw。当前材料未将空指标写成已达阈值。")


def ch11(doc):
    h1(doc, "十一、数据与状态设计")
    h2(doc, "11.1  核心数据对象")
    p_body(doc, "系统围绕 SecurityEvent 建立贯穿检测、审计、响应与复盘的数据对象。Alert 表示高优先级安全事件；AuditTask 保存审计任务；ToolCall 与 Evidence 记录外部工具和证据；AuditResult 保存智能体结论；ResponseAction 记录处置；Case 组织事件生命周期；Memory 用于历史上下文与经验检索。")
    p_body(doc, "核心对象按照“事实、任务、证据、结论、动作、案例”组织。SecurityEvent 是事实根。Memory 与普通日志的区别在于它服务后续 Agent 上下文和经验检索，而不是替代原始事实。设计应保证 Evidence 能追溯到 ToolCall 或事件字段，AuditResult 能追溯到 Evidence，ResponseAction 能追溯到 AuditResult 或策略，从而形成面向审计的有向关系链。")

    h2(doc, "11.2  Evidence Trail 与 Audit Trail")
    p_body(doc, "evidence_trail 是 Audit-LLM 内部的证据主线，保存各层产生的结构化子问题、工具计划、工具返回和结论依据；audit_trail 是系统审计主线，面向事后追踪保存 CAD、调用控制、响应和审批记录。两者与 eventId、trace_id 一起构成“事件事实—智能研判—执行动作”的可追踪链路。")
    p_body(doc, "Evidence Trail 面向“这个结论为什么成立”，因此重点记录事实与推理输入；Audit Trail 面向“系统做过什么”，因此重点记录模块调用、权限判定、审批、状态转换和执行结果。在复盘场景中，分析人员可以先从 Case/Alert 定位事件，再沿 Audit Trail 找到 Agent 与响应操作，随后通过 Evidence Trail 查看关键结论的事实来源。")

    h2(doc, "11.3  Trace 设计")
    add_table(
        doc,
        ["阶段", "载体", "用途"],
        [
            ["事件入口", "eventId", "业务事件全局唯一标识"],
            ["Kafka", "traceparent Header", "跨消息链路传播"],
            ["Flink", "TraceUtil.startSpan()", "写入 OTel 追踪"],
            ["Backend", "raw_data._traceparent", "关联入库、审计与响应"],
            ["Frontend", "/api/trace/{traceparent}", "查询 Tempo 链路"],
        ],
        widths=[1800, 2800, 3712],
        title="表11-1  trace_id 贯穿位置",
    )
    p_body(doc, "Trace 解决的是分布式组件之间的技术链路追踪，与 eventId 的业务语义互补。eventId 负责标识同一个安全事件，traceparent 负责串联一次处理请求经过了哪些服务和耗时多少。当一个事件被多次审计或重新规划时，可以保留同一业务事件标识，同时产生不同处理 span。")

    h2(doc, "11.4  主要数据表")
    add_table(
        doc,
        ["表", "用途", "关键字段"],
        [
            ["security_events", "事件主表", "event_type / severity / src_ip / anomaly_score / status"],
            ["memories", "Agent 记忆", "agent_id / content / embedding"],
            ["knowledge_docs / knowledge_chunks", "知识库文档与分块", "source / status / embedding"],
            ["response_logs", "响应执行日志", "action / rollback_token / ttl"],
            ["assets", "资产", "ip / hostname / criticality"],
            ["data_sources", "数据源", "api_key_hash / source_type / enabled"],
            ["cad_reports", "CAD 报告", "hallucination_risk / evidence_completeness"],
            ["audit_trail", "审计轨迹", "actor / action / decision / reason"],
            ["approval_tickets", "审批工单", "tool / args / status / decided_by"],
            ["work_orders / security_cases", "工单与案例", "status / priority / assignee"],
        ],
        widths=[2800, 2200, 3312],
        title="表11-2  核心数据表（节选）",
    )
    p_body(doc, "字段约定方面，标识采用自增或 UUID，时间使用带时区时间戳，文本和 JSONB 字段给出默认值以避免空值判断扩散，向量字段使用 pgvector。Qdrant 保存 RAG 分块与 Agent 记忆的混合检索副本，Redis 承担限流、JWT 黑名单、TTL 回收和缓存。")

    h2(doc, "11.5  状态一致性原则")
    p_body(doc, "系统关键状态采用显式枚举而不是依赖自然语言，例如 Self-Play learned rule 的 candidate、shadow、promoted、dismissed。状态转换应由单一业务动作驱动并附带审计信息，减少路由层、编排层和数据库之间状态不一致的风险。candidate 规则只允许审核，不应直接被生产加载；shadow 允许观测但不等价于 promoted；响应动作只有在执行与验证完成后才能更新为相应完成状态。")


def ch12(doc):
    h1(doc, "十二、系统工程实现与部署")
    h2(doc, "12.1  技术栈")
    add_table(
        doc,
        ["类别", "组件", "当前作用"],
        [
            ["消息与流处理", "Kafka 3.7（KRaft）", "消息总线、重放、分级 Topic"],
            ["消息与流处理", "Flink 1.19.3 / Java 11", "校验、异常评分、CEP、阈值聚合"],
            ["后端", "FastAPI + SQLAlchemy + asyncpg", "业务 API、Kafka 消费、审计与响应编排"],
            ["数据", "PostgreSQL + pgvector / Qdrant / Redis", "事件、向量、记忆、缓存与 TTL"],
            ["前端", "React 19 + TypeScript + Tailwind 4", "监控、审计、运营与 SSE 实时界面"],
            ["安全执行", "paramiko / iptables", "SSH 与防火墙动作"],
            ["可观测", "Prometheus / Grafana / OTel / Tempo", "指标、追踪和健康监控"],
            ["LLM", "OpenAI 兼容 API", "Agent 与 RAG 相关模型调用"],
        ],
        widths=[1800, 2800, 3712],
        title="表12-1  主要技术组件",
    )
    p_body(doc, "技术选型围绕实时、异步、可审计和可部署展开。系统没有把所有能力集中在单一框架中，而是通过消息、HTTP API 和统一数据对象连接。技术栈较完整也带来部署复杂度，因此使用 Docker Compose 统一服务编排，并通过独立开关关闭当前不需要的外部能力。")

    h2(doc, "12.2  后端与前端模块组织")
    p_body(doc, "FastAPI 后端按入口基础设施、事件接入、Audit-LLM、响应引擎、MCP Guard、SecurityGuard、RAG、Sigma、可观测和可对接能力等模块组织。事件接入模块只负责事件进入与分发，agents 负责研判，mcp_guard 与 security_guard 负责调用边界，response_engine 负责真实处置，rag 负责知识检索，observability 负责追踪与健康状态。")
    p_body(doc, "前端采用 React 19 + TypeScript，页面覆盖登录、首页值班台、日志中心、监控、安全审计、响应中心、知识库、运营工单/案例/复盘，以及流量、加密流量、威胁情报、沙箱、EDR 等可对接能力界面。控制面通过 REST 完成查询与审批，事件流通过 SSE 推送。")

    h2(doc, "12.3  容器化部署")
    p_body(doc, "系统通过 docker-compose.yml 组织 PostgreSQL、Redis、Kafka、Schema Registry、Flink JobManager/TaskManager、Backend、Frontend、Kafka UI、Nginx、Prometheus、Grafana、Tempo 与 OTel Collector。开发环境通过源码构建，生产环境通过 docker-compose.prod.yml 与 IMAGE_TAG 使用预构建镜像。Flink Job Submitter 负责核心作业启动。")
    p_body(doc, "部署拓扑划分为数据面、应用面、安全边界、Flink 集群、可观测面和执行面，体现数据处理与真实执行之间的网络和权限边界。生产覆盖文件与 IMAGE_TAG 用于区分开发构建和正式镜像，使竞赛演示环境与后续部署能够使用相同编排结构。")

    h2(doc, "12.4  端口与安全加固")
    add_table(
        doc,
        ["服务", "端口", "访问范围", "安全防护"],
        [
            ["Frontend", "3001", "对外服务", "Nginx 隐藏版本与安全响应头"],
            ["Flink Dashboard 反代", "3002", "管理端访问", "HTTP Basic Auth"],
            ["Backend API", "8001", "对外服务", "JWT + 限流"],
            ["Kafka UI", "18082", "管理端访问", "LOGIN_FORM 认证"],
            ["Kafka SASL_SSL", "9093", "授权数据源访问", "TLS + SCRAM-SHA-512"],
            ["Kafka 本机", "9094", "宿主机内部", "仅限维护与调试工具访问"],
            ["PostgreSQL", "5433", "宿主机/容器内部", "密码认证，不直接暴露公网"],
            ["Redis", "6380", "宿主机/容器内部", "requirepass + protected-mode"],
            ["Flink REST", "8081", "容器内部", "不直接暴露，经 3002 反向代理访问"],
        ],
        widths=[2200, 1100, 2200, 2812],
        title="表12-2  容器化部署服务端口与网络暴露策略",
    )
    p_body(doc, "端口暴露遵循“必要服务对外、基础设施尽量本机或反代”的原则。端口加固与 Agent 工具安全属于两个层面，前者保护平台基础设施，后者保护智能体执行行为，二者共同构成系统安全边界。")

    h2(doc, "12.5  可观测性")
    p_body(doc, "系统按 Metrics、Logs、Traces 三层建设可观测性：Flink 与 Backend 输出 Prometheus 指标；后端日志采用结构化 JSON；OpenTelemetry 追踪送入 Tempo。pipeline_tracer.py 负责 trace_id 贯穿，health_monitor.py 对组件健康探活，watchdog.py 在关键异步任务异常退出时尝试拉起。")
    p_body(doc, "Metrics 用于回答系统是否健康、吞吐和延迟如何，Logs 用于回答具体模块发生了什么，Traces 用于回答一次事件处理经过了哪些组件。三类信息通过 eventId、trace_id 和模块字段关联，可以从告警页面逐步下钻到服务状态和调用链。")


def ch13(doc):
    h1(doc, "十三、系统测试与实验验证")
    h2(doc, "13.1  测试组织")
    p_body(doc, "测试体系按模块契约和风险面组织，覆盖架构统一性、案例生命周期、日志标准化、可观测性、响应执行安全、提示词完整性、向量存储、LLM 增强以及 NDR/EDR/Phishing 等外部能力的离线 mock。2026 年 9 月 9 日在本机 Docker Compose 全栈环境下完成全方位验证（自动化回归 + 运行时探活 + 界面实测）。")
    add_figure(doc, "fig-test-layers.png", "图13-1  测试沿事件生命周期分层")

    h2(doc, "13.2  自动化回归结果")
    add_table(
        doc,
        ["项", "结果"],
        [
            ["后端自动化", "收集 867 例，通过 850 例（98.0%），失败 14 例，跳过 3 例"],
            ["运行时容器", "Compose 22 个全部 Running；Kafka / PostgreSQL / Redis / Qdrant 健康检查通过"],
            ["接口探活", "匿名接口符合鉴权；登录后主路径可达"],
            ["前端", "16 个路由均可渲染；TypeScript 检查 0 错误"],
            ["失败归因", "环境 10、隔离/契约 3、真实代码 1"],
            ["总体判定", "可参赛演示（PASS_WITH_FINDINGS）"],
        ],
        widths=[2200, 6112],
        title="表13-1  测试结论一览（2026-09-09）",
    )
    add_table(
        doc,
        ["模块", "文件", "通过", "失败", "跳过"],
        [
            ["架构 / 生命周期", "7", "78", "2", "0"],
            ["接入 / 日志", "4", "19", "0", "0"],
            ["检测", "12", "73", "5", "0"],
            ["Audit-LLM", "20", "176", "3", "0"],
            ["守卫 / 安全", "13", "111", "0", "0"],
            ["响应 / 遏制", "13", "154", "3", "0"],
            ["RAG / 向量", "4", "25", "0", "3"],
            ["可观测性", "7", "68", "0", "0"],
            ["自博弈", "7", "95", "0", "0"],
            ["外部能力", "6", "36", "1", "0"],
            ["基础设施", "4", "15", "0", "0"],
        ],
        widths=[2400, 1400, 1504, 1504, 1504],
        title="表13-2  分模块回归摘要",
    )
    p_body(doc, "守卫、自博弈、可观测性三个高风险桶全部通过，是本次最有说服力的回归信号。失败项已作诚实分类：10 例为环境路径污染，3 例为测试隔离/契约问题，1 例为真实代码缺陷（audit_single.py 内联 system prompt）。本文不以 98% 通过率替代效果指标，也不虚构吞吐、P95 或误报率。")

    h2(doc, "13.3  功能测试设计")
    add_table(
        doc,
        ["场景", "输入/条件", "期望结果"],
        [
            ["非法 JSON", "原始日志无法解析", "进入 rejected/DLQ，记录拒绝原因"],
            ["错误 API Key", "来源未授权", "Job1 拒绝，不进入 validated"],
            ["重复事件", "相同 srcIp + eventType + messageHash，60s 内重复", "去重后仅保留有效事件"],
            ["高危事件", "severity=high 或 score≥0.6", "进入 alerts，同时触发审计与响应路径"],
            ["CEP 攻击链", "按时间顺序注入指定事件序列", "命中对应攻击链并输出告警"],
            ["幻觉工具", "LLM 生成未注册工具名", "MCP Guard Registry 拒绝"],
            ["越权调用", "低权限角色执行高风险动作", "Permission 拒绝或转审批"],
            ["证据不足", "结论无法从事件/工具/RAG 证据支持", "Grounding/CAD 提高风险或触发熔断"],
            ["响应回滚", "执行临时封禁后撤销", "根据 rollback_token 反向处理"],
        ],
        widths=[1600, 3400, 3312],
        title="表13-3  关键功能测试用例",
    )
    p_body(doc, "功能测试沿端到端事件生命周期设计正向与反向用例。正向用例验证正常日志能够完成校验、评分、审计和响应；反向用例故意注入非法 JSON、错误 API Key、重复事件、幻觉工具和越权动作，验证系统是否在正确阶段拒绝并记录原因。")

    h2(doc, "13.4  Agent 安全测试")
    p_body(doc, "Agent 安全测试分别覆盖结构不稳定、工具幻觉、越权、参数非法、调用超频、危险序列、上下文不匹配和无依据结论。测试目标不是只验证最终是否成功，而是确认请求在正确的一层被拦截，并留下可回溯的拒绝原因。")
    p_body(doc, "需要特别关注绕过组合而不仅是单点错误。例如工具名合法但参数指向未授权资产、单次调用合法但连续调用形成危险序列、Prompt Injection 诱导模型修改工具参数、RAG 中出现恶意指令文本等，都应验证最终是否仍被 Validator、SecurityGuard、Grounding 或其他边界拦截。当前单点闸门已有自动化覆盖，组合绕过尚未系统化成攻击组合套件，作为明确缺口保留。")

    h2(doc, "13.5  性能与稳定性验证建议")
    add_table(
        doc,
        ["层级", "指标", "采集方式"],
        [
            ["Kafka/Flink", "吞吐、处理时延、Checkpoint 成功率、Backpressure", "Flink Metrics + Prometheus"],
            ["Agent", "平均审计耗时、工具调用次数、重规划次数", "Audit Trail"],
            ["RAG", "检索耗时、降级次数、重排路径分布", "Retriever 日志"],
            ["Guard", "拒绝率、误拒绝、审批率、限流触发", "Call Logger / Approval"],
            ["Response", "执行成功率、回滚成功率、TTL 回收", "response_logs"],
            ["CAD", "hallucination_risk、evidence_completeness、熔断次数", "cad_reports"],
        ],
        widths=[1600, 3600, 3112],
        title="表13-4  建议持续采集的性能指标",
    )
    p_body(doc, "性能测试应覆盖数据面和智能体面两种不同瓶颈。Kafka/Flink 更关注吞吐、Backpressure 和 Checkpoint，Agent/RAG 更关注单事件审计时延、模型调用次数和降级路径，Guard/Response 更关注判定开销、执行成功率与回滚能力。不同层使用统一平均延迟容易掩盖真实瓶颈。本文不将探活时延外推为生产吞吐。")


def ch14(doc):
    h1(doc, "十四、项目创新点")
    p_body(doc, "项目创新不以组件数量多为主要依据，而集中在如何让安全 Agent 在拥有真实行动能力后仍然保持可验证与可控制。")

    h2(doc, "14.1  多层可信工具调用体系")
    p_body(doc, "Stabilizer 先处理输出结构不稳定，MCP Guard 再完成工具注册、RBAC、参数和策略检查，SecurityGuard 最后结合意图、序列、频率和上下文判断调用合理性。三层形成“能否解析—是否有权—当前是否应该执行”的逐级控制，避免单一白名单承担全部风险。")
    p_body(doc, "与只做工具白名单相比，该体系能够处理“工具存在但角色无权”“角色有权但参数非法”“单次合法但连续行为危险”等更细粒度问题，也为人工审批提供结构化风险依据。其目标是让 Agent 具备真实行动能力，而不是为了安全而完全取消工具调用。")

    h2(doc, "14.2  Evidence-driven 自审计")
    p_body(doc, "系统要求重要结论通过 evidence_trail 绑定原始事件、工具结果和知识证据，Reviewer 在主工作流内复核，Grounding 负责证据约束，CAD 在主工作流外再次穿透验证并具备熔断能力。该设计把“模型自信”与“证据充分”分离。")
    p_body(doc, "模型给出 0.95 confidence 不能替代事件字段、工具结果和知识来源；相反，即使模型置信度中等，只要关键 Evidence 完整且多源一致，结论仍具有较高可验证性。该机制使“模型是否正确”转化为更可操作的问题：哪些 claim 被支持、哪些证据缺失、风险是否允许系统继续自动运行。")

    h2(doc, "14.3  研判与真实处置一体化闭环")
    p_body(doc, "项目从 Kafka/Flink 的实时检测出发，将 Agent 研判结果连接到 Response Engine，并在真实执行前引入审批、双白名单、safe_executor 和 post_validator，执行后通过 response_logs、TTL 和 rollback_token 保留恢复路径。")
    p_body(doc, "许多 Agent 演示停留在给出处置建议，而本项目进一步连接 Response Engine，使研判可以进入真实执行流程；同时又通过 Policy、Approval、SecurityGuard、双白名单、Safe Executor 和 Post Validator 把执行链拆成多个可控节点。所谓一体化不仅是模块连通，更是事实、决策和执行状态能够相互回流。")

    h2(doc, "14.4  Self-Play 驱动检测演进")
    p_body(doc, "Self-Play 不是直接让模型修改生产规则，而是在隔离仿真中生成攻击样本，从漏报中产生候选规则，再通过退化检测、重复检测、FP Replay、可迁移性、大模型语义复核、历史回放和影子期逐步提升。其创新点在于把学习能力置于受控规则生命周期中。")
    p_body(doc, "这种设计特别适合安全检测，因为规则错误的代价不仅是回答不好，还可能造成大量误报或错误处置。通过隔离仿真、FP Replay 和影子期，系统把创新能力与生产稳定性分开验证。")


def ch15(doc):
    h1(doc, "十五、同类方案对比")
    p_body(doc, "为突出系统定位，本项目与传统 SIEM 和单 LLM Agent 从实时检测、语义理解、工具控制、证据验证、真实响应和持续演进等维度进行对比。该对比不是否定成熟 SIEM，而是说明本项目主要补充 AI 原生研判与 Agent 自我保护能力。")
    add_table(
        doc,
        ["能力维度", "传统 SIEM", "单 LLM Agent", "本项目"],
        [
            ["实时流处理", "强", "通常较弱", "Kafka + Flink"],
            ["规则与攻击链", "强/中", "依赖提示词", "Sigma + CEP"],
            ["复杂语义研判", "较弱", "强", "四层 Audit-LLM"],
            ["自主规划", "通常无", "有", "Decomposer + ToolBuilder"],
            ["工具调用控制", "非 Agent 场景", "通常较弱", "MCP Guard + SecurityGuard"],
            ["证据校验", "依赖规则/人工", "容易缺少", "Grounding + Evidence Trail"],
            ["独立监督", "通常无", "Agent 自监督通常无", "CAD + Circuit Breaker"],
            ["自动处置", "半自动/编排", "直接调用风险高", "策略 + 审批 + 双白名单 + 回滚"],
            ["持续学习", "人工维护规则", "不稳定", "Self-Play 候选规则生命周期"],
            ["大规模检索", "成熟产品强", "弱", "不是项目核心优势"],
        ],
        widths=[1800, 1800, 2100, 2612],
        title="表15-1  传统 SIEM、单 LLM Agent 与本项目对比",
    )
    p_body(doc, "传统 SIEM 在大规模日志检索、规则运营和成熟生态上优势明显；单 LLM Agent 具备较强语义理解和灵活规划能力，但若直接连接工具会面临权限、证据和执行风险。本项目的目标是在保留流式检测与规则能力的基础上，为 Agent 增加可信工具调用、独立监督和受控响应。作品边界明确：它不是替代 Splunk、Elastic 等成熟平台，而是在安全运营自动化中探索“能行动且受控制”的可信 Agent 控制层和闭环机制。")


def ch16(doc):
    h1(doc, "十六、总结与展望")
    h2(doc, "16.1  项目总结")
    p_body(doc, "守望平台已形成从安全事件接入、实时校验、异常评分、CEP 攻击链与 Sigma 检测，到 Audit-LLM 智能研判、Hybrid RAG、受控工具调用、Grounding/CAD 独立监督、Response Engine 真实响应与 Self-Play 持续演进的完整设计。系统通过结构化证据和多级安全边界，使 Agent 不仅能够分析安全事件，还能够在可审计、可回滚、可熔断的条件下执行安全动作。")
    p_body(doc, "从系统结构看，本项目已经形成三条相互连接的主线：第一条是 Kafka/Flink/Sigma/CEP 组成的确定性数据与检测主线，第二条是 Audit-LLM/RAG/Memory 组成的智能研判主线，第三条是 Guard/Response/Grounding/CAD/Self-Play 组成的可信执行与反馈主线。三条主线围绕统一事件、证据和审计标识衔接。")
    p_body(doc, "项目希望证明的核心结论不是“大模型可以替代安全运营”，而是“大模型可以在确定性检测底座和严格安全边界内承担更复杂的自主研判与工具协同任务”。通过分层 Agent、证据驱动、自审计、可回滚响应和受控持续学习，系统将安全 Agent 从单次问答原型推进到可部署、可追踪和可演进的工程形态。")

    h2(doc, "16.2  后续方向")
    p_body(doc, "第一，继续扩展多源安全数据关联，在真实 EDR、NDR、身份、资产与防火墙数据接入后验证跨域攻击链。第二，针对 Prompt Injection、工具描述注入、RAG 投毒和多工具组合攻击继续完善 Agent 安全策略。第三，扩大 Self-Play 课程目录、历史回放样本和生产影子数据，建立更稳定的规则提升评价机制。第四，在竞赛环境中完成指定安全大模型底座的适配与实机验证，使现有 Agent 编排、Guard 与闭环机制保持一致能力。")
    p_body(doc, "后续优化应优先围绕真实数据和真实部署验证展开，补充吞吐、延迟、误报、回滚与熔断数据，在不放松安全边界的前提下，逐步提高系统可自动完成的安全运营任务比例。")


def ch_ref(doc):
    h1(doc, "参考文献")
    refs = [
        "[1] MITRE. MITRE ATT&CK[EB/OL]. https://attack.mitre.org/.",
        "[2] MITRE. Common Attack Pattern Enumeration and Classification (CAPEC)[EB/OL]. https://capec.mitre.org/.",
        "[3] Apache Software Foundation. Apache Kafka Documentation[EB/OL]. https://kafka.apache.org/documentation/.",
        "[4] Apache Software Foundation. Apache Flink Documentation[EB/OL]. https://nightlies.apache.org/flink/flink-docs-stable/.",
        "[5] SigmaHQ. Sigma — Generic Signature Format for SIEM Systems[EB/OL]. https://github.com/SigmaHQ/sigma.",
        "[6] OpenTelemetry Authors. OpenTelemetry Specification[EB/OL]. https://opentelemetry.io/docs/specs/otel/.",
        "[7] Qdrant. Qdrant Vector Search Engine Documentation[EB/OL]. https://qdrant.tech/documentation/.",
        "[8] FastAPI. FastAPI Documentation[EB/OL]. https://fastapi.tiangolo.com/.",
        "[9] 守望项目组. 守望——基于多智能体编排的安全运营平台设计文档[R]. 湖南科技大学, 2026.",
        "[10] 守望项目组. 守望平台全方位测试报告 V1.0[R]. 湖南科技大学, 2026-09-09.",
    ]
    for r in refs:
        p = doc.add_paragraph()
        add_run(p, r, FANGSONG, 12)
        fmt_para(p, align=WD_ALIGN_PARAGRAPH.LEFT, before=0, after=4, line=1.5, first=0)
        p.paragraph_format.left_indent = Cm(0.74)
        p.paragraph_format.first_line_indent = Cm(-0.74)


def main():
    if not FIG.exists():
        raise SystemExit(f"missing figures dir: {FIG}")
    doc = Document()
    setup_styles(doc)
    sec0 = doc.sections[0]
    apply_page(sec0)
    sec0.different_first_page_header_footer = False
    set_header_footer(sec0, "", show_page=False)
    # 封面页眉页脚留空
    for p in sec0.header.paragraphs:
        p.clear()
    for p in sec0.footer.paragraphs:
        p.clear()

    build_cover(doc)

    # 正文节
    sec1 = doc.add_section(WD_SECTION.NEW_PAGE)
    apply_page(sec1)
    set_header_footer(sec1, "系统设计说明书　　守望——基于多智能体编排的安全运营平台", show_page=True)
    # 页码从 1 开始
    sectPr = sec1._sectPr
    old = sectPr.find(qn("w:pgNumType"))
    if old is not None:
        sectPr.remove(old)
    pgNum = OxmlElement("w:pgNumType")
    pgNum.set(qn("w:start"), "1")
    insert_el(sectPr, pgNum, SECTPR_ORDER)

    ch_abstract(doc)
    ch_toc(doc)
    ch1(doc)
    ch2(doc)
    ch3(doc)
    ch4(doc)
    ch5(doc)
    ch6(doc)
    ch7(doc)
    ch8(doc)
    ch9(doc)
    ch10(doc)
    ch11(doc)
    ch12(doc)
    ch13(doc)
    ch14(doc)
    ch15(doc)
    ch16(doc)
    ch_ref(doc)

    doc.core_properties.title = "系统设计说明书——守望基于多智能体编排的安全运营平台"
    doc.core_properties.author = "湖南科技大学守望项目组"
    doc.core_properties.subject = "湖南省第22届大学生计算机程序设计竞赛 应用开发类"
    doc.core_properties.category = "系统设计说明书"

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    doc.save(str(OUT_PATH))
    _ensure_png_content_type(OUT_PATH)
    import shutil
    shutil.copy2(OUT_PATH, OUT_COPY)
    print(f"OK -> {OUT_PATH}")
    print(f"OK -> {OUT_COPY}")


def _ensure_png_content_type(path):
    import zipfile
    from io import BytesIO
    from xml.etree import ElementTree as ET

    NS = "http://schemas.openxmlformats.org/package/2006/content-types"
    ET.register_namespace("", NS)
    buf = BytesIO()
    with zipfile.ZipFile(path, "r") as zin:
        names = zin.namelist()
        ctypes = zin.read("[Content_Types].xml")
        root = ET.fromstring(ctypes)
        has_png = any(
            el.get("Extension", "").lower() == "png" for el in root
        )
        if not has_png:
            el = ET.Element("{%s}Default" % NS)
            el.set("Extension", "png")
            el.set("ContentType", "image/png")
            root.insert(0, el)
        new_xml = ET.tostring(root, encoding="utf-8", xml_declaration=True)
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zout:
            for name in names:
                data = zin.read(name)
                if name == "[Content_Types].xml":
                    data = new_xml
                elif name == "word/settings.xml":
                    txt = data.decode("utf-8")
                    txt = txt.replace('<w:zoom w:val="bestFit"/>', '<w:zoom w:val="bestFit" w:percent="100"/>')
                    data = txt.encode("utf-8")
                zout.writestr(name, data)
    path.write_bytes(buf.getvalue())


if __name__ == "__main__":
    main()
