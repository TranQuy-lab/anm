#!/usr/bin/env python3
# md2pdf_report.py — chuyển BÁO_CÁO_NGHIÊN_CỨU.md → PDF A4 vector (ReportLab + DejaVu)
# Light triage theo pdf skill: báo cáo học thuật, font DejaVu (đủ tiếng Việt), bảng Paragraph-wrap,
# ảnh scale theo available width, metadata đầy đủ.
import re, html, os
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
                                Image, Preformatted, KeepTogether, HRFlowable)

BASE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(BASE, "..", "BÁO_CÁO_NGHIÊN_CỨU.md")
OUT = os.path.join(BASE, "..", "BÁO_CÁO_NGHIÊN_CỨU.pdf")

FD = "/usr/share/fonts/truetype/dejavu"
pdfmetrics.registerFont(TTFont("DejaVu", f"{FD}/DejaVuSans.ttf"))
pdfmetrics.registerFont(TTFont("DejaVu-Bold", f"{FD}/DejaVuSans-Bold.ttf"))
pdfmetrics.registerFont(TTFont("DejaVu-Italic", f"{FD}/DejaVuSans-Oblique.ttf"))
pdfmetrics.registerFont(TTFont("DejaVu-Mono", f"{FD}/DejaVuSansMono.ttf"))

S = {
    "title": ParagraphStyle("t", fontName="DejaVu-Bold", fontSize=17, leading=22, alignment=TA_CENTER, spaceAfter=6),
    "subtitle": ParagraphStyle("st", fontName="DejaVu-Bold", fontSize=12.5, leading=17, alignment=TA_CENTER, textColor=colors.HexColor("#0F3B5F"), spaceAfter=10),
    "meta": ParagraphStyle("m", fontName="DejaVu", fontSize=9.5, leading=13, alignment=TA_CENTER, textColor=colors.HexColor("#555555"), spaceAfter=4),
    "h1": ParagraphStyle("h1", fontName="DejaVu-Bold", fontSize=13.5, leading=17, spaceBefore=16, spaceAfter=6, textColor=colors.HexColor("#0F3B5F")),
    "h2": ParagraphStyle("h2", fontName="DejaVu-Bold", fontSize=11.5, leading=15, spaceBefore=12, spaceAfter=4),
    "body": ParagraphStyle("b", fontName="DejaVu", fontSize=9.8, leading=14.2, spaceAfter=5, alignment=TA_LEFT),
    "li": ParagraphStyle("li", fontName="DejaVu", fontSize=9.8, leading=14, leftIndent=14, bulletIndent=4, spaceAfter=3),
    "code": ParagraphStyle("c", fontName="DejaVu-Mono", fontSize=7.3, leading=10.3, backColor=colors.HexColor("#F4F6F8"), borderPadding=5, leftIndent=6, spaceBefore=4, spaceAfter=6),
    "cap": ParagraphStyle("cap", fontName="DejaVu-Italic", fontSize=8.5, leading=11, alignment=TA_CENTER, textColor=colors.HexColor("#555555"), spaceAfter=8),
}

PAGE_W, PAGE_H = A4
MARGIN = 2.0 * cm
AVAIL = PAGE_W - 2 * MARGIN

def inline(md: str) -> str:
    t = html.escape(md)
    t = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", t)
    t = re.sub(r"(?<!\*)\*([^*]+)\*(?!\*)", r"<i>\1</i>", t)
    t = re.sub(r"`([^`]+)`", r'<font face="DejaVu-Mono" size="8.6">\1</font>', t)
    t = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r"\1", t)   # link → chỉ giữ text
    return t

def table_flow(rows):
    ncol = max(len(r) for r in rows)
    rows = [r + [""] * (ncol - len(r)) for r in rows]
    # độ rộng: tỉ lệ theo số ký tự trung bình, đảm bảo tổng = AVAIL
    w = [max(12, min(58, sum(len(c) for c in col) / max(1, len(col)) + 4)) for col in zip(*rows)]
    tot = sum(w)
    colw = [x / tot * AVAIL for x in w]
    data = []
    for i, r in enumerate(rows):
        sty = S["h2"] if i == 0 else S["body"]
        data.append([Paragraph(inline(c), sty) for c in r])
    tb = Table(data, colWidths=colw, hAlign="CENTER", repeatRows=1)
    tb.setStyle(TableStyle([
        ("GRID", (0,0), (-1,-1), 0.4, colors.HexColor("#B9C4CE")),
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#E8EEF4")),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("TOPPADDING", (0,0), (-1,-1), 3), ("BOTTOMPADDING", (0,0), (-1,-1), 3),
        ("LEFTPADDING", (0,0), (-1,-1), 4), ("RIGHTPADDING", (0,0), (-1,-1), 4),
    ]))
    return tb

story, lines = [], []
raw = open(SRC, encoding="utf-8").read().splitlines()
# gộp dòng liền nhau thành 1 đoạn (markdown hard-wrap) trước khi parse block
blocks, buf = [], []
def is_block_start(l):
    return (l.startswith(("#", "```", "|", "- ", "![", "---")) or
            bool(re.match(r"^\d+\. ", l)) or not l.strip())
for ln in raw:
    if is_block_start(ln):
        if buf: blocks.append(" ".join(buf)); buf = []
        blocks.append(ln)
    else:
        buf.append(ln.strip())
if buf: blocks.append(" ".join(buf))
lines = blocks

i, first_h1 = 0, True
while i < len(lines):
    ln = lines[i]
    if ln.startswith("```"):
        j = i + 1; buf = []
        while j < len(lines) and not lines[j].startswith("```"):
            buf.append(lines[j].replace("⇄", "<->")); j += 1
        story.append(Preformatted("\n".join(buf), S["code"])); i = j + 1; continue
    if ln.startswith("|") and i + 1 < len(lines) and re.match(r"^\|[\s\-|:]+\|$", lines[i+1]):
        j = i; rows = []
        while j < len(lines) and lines[j].startswith("|"):
            if not re.match(r"^\|[\s\-|:]+\|$", lines[j]):
                rows.append([c.strip() for c in lines[j].strip("|").split("|")])
            j += 1
        story.append(table_flow(rows)); story.append(Spacer(1, 6)); i = j; continue
    m = re.match(r"!\[(.*)\]\((.*)\)", ln)
    if m:
        p = os.path.normpath(os.path.join(BASE, "..", m.group(2)))
        if os.path.exists(p):
            from reportlab.lib.utils import ImageReader
            ir = ImageReader(p); iw, ih = ir.getSize()
            w = AVAIL; h = ih * w / iw
            img = Image(p, width=w, height=h)
            cap = Paragraph(m.group(1) or "", S["cap"])
            story.append(KeepTogether([Spacer(1, 4), img, cap]))
        i += 1; continue
    if ln.startswith("!["):  # ảnh không tồn tại → bỏ
        i += 1; continue
    if ln.startswith("### "): story.append(Paragraph(inline(ln[4:]), S["h2"])); i += 1; continue
    if ln.startswith("## "):
        story.append(Paragraph(inline(ln[3:]), S["h1"])); i += 1; continue
    if ln.startswith("# "):
        st = S["title"] if first_h1 else S["h1"]; first_h1 = False
        story.append(Paragraph(inline(ln[2:]), st)); i += 1; continue
    if ln.startswith("---"):
        story.append(HRFlowable(width="100%", thickness=0.6, color=colors.HexColor("#B9C4CE"), spaceBefore=8, spaceAfter=8)); i += 1; continue
    if ln.startswith("- "):
        story.append(Paragraph(inline(ln[2:]), S["li"], bulletText="•")); i += 1; continue
    m = re.match(r"^(\d+)\. (.*)$", ln)
    if m:
        story.append(Paragraph(inline(m.group(2)), S["li"], bulletText=f"{m.group(1)}.")); i += 1; continue
    if ln.startswith("*") and ln.endswith("*") and not ln.startswith("**"):
        story.append(Paragraph(inline(ln), S["cap"])); i += 1; continue
    if ln.strip():
        story.append(Paragraph(inline(ln), S["body"]))
    i += 1

doc = SimpleDocTemplate(OUT, pagesize=A4, leftMargin=MARGIN, rightMargin=MARGIN,
                        topMargin=1.8*cm, bottomMargin=1.8*cm,
                        title="Báo cáo nghiên cứu: Tác động mạng của mật mã hậu lượng tử và khả năng nhận dạng lưu lượng",
                        author="Z.ai", subject="PQC × network measurement × traffic classification drift (đề tài T1)",
                        creator="ReportLab (pdf skill, Report route)")
doc.build(story)
print("PDF written:", OUT, os.path.getsize(OUT), "bytes")
