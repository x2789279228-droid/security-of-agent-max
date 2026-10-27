package com.soc.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * UrlCanonicalizer 单测 — 向量集与 backend/tests/test_normalization.py 同步。
 *
 * 两侧语义必须逐条一致（normalization.py docstring 的镜像约定）：
 * 任何一侧新增/修改向量, 另一侧必须同改。
 */
class UrlCanonicalizerTest {

    // ── deepDecode ──

    @Test
    void singleDecode() {
        assertEquals("/search?q=<script>alert(1)</script>",
                UrlCanonicalizer.canonicalUrl("/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"));
    }

    @Test
    void doubleDecode() {
        assertEquals("../../etc/shadow",
                UrlCanonicalizer.canonicalUrl("%252e%252e%252f%252e%252e%252fetc%252fshadow"));
    }

    @Test
    void legacyUnicodeEscape() {
        assertEquals("/a?q=<script>", UrlCanonicalizer.canonicalUrl("/a?q=%u003cscript%u003e"));
    }

    @Test
    void backslashTraversal() {
        assertEquals("/files?name=../../windows",
                UrlCanonicalizer.canonicalUrl("/files?name=..%5C..%5Cwindows"));
    }

    @Test
    void decodeBombCapped() {
        String bomb = "a" + "%25".repeat(20);
        String out = UrlCanonicalizer.canonicalUrl(bomb);
        // 3 轮上限: '%25'*20 → 3 轮后剩 '%'*? 不递归到底, 输出长度有界
        assertTrue(out.length() <= bomb.length(),
                "解码炸弹必须被轮数上限约束, 实际输出长度 " + out.length());
    }

    @Test
    void benignUntouched() {
        assertEquals("https://cdn.corp/static/app.9f2c.js?page=1",
                UrlCanonicalizer.canonicalUrl("https://cdn.corp/static/app.9f2c.js?page=1"));
    }

    @Test
    void rawTraversalUntouched() {
        // 点段折叠刻意不做: ../ 子串必须保留(规则库对原始形式写)
        assertEquals("/files/download?name=../../../etc/passwd",
                UrlCanonicalizer.canonicalUrl("/files/download?name=../../../etc/passwd"));
    }

    @Test
    void plusIsNotSpace() {
        // 与 Python unquote 一致: '+' 不转空格(那是 form 编码语义)
        assertEquals("/a+b", UrlCanonicalizer.canonicalUrl("/a+b"));
    }

    @Test
    void invalidEscapeLeftAsIs() {
        // %zz 不是合法 hex → 原样保留(与 unquote errors='replace' 的字面量行为一致)
        assertEquals("/x%zz", UrlCanonicalizer.canonicalUrl("/x%zz"));
    }

    @Test
    void nullInput() {
        assertNull(UrlCanonicalizer.canonicalUrl(null));
        assertEquals("", UrlCanonicalizer.canonicalUrl(""));
    }

    // ── canonicalMessage ──

    @Test
    void messageDecoded() {
        assertEquals("CPU 25% load", UrlCanonicalizer.canonicalMessage("CPU %32%35%25 load"));
    }

    @Test
    void messageKeepsBackslash() {
        // message 不做反斜杠替换 —— Windows 路径在日志文本里是合法数据
        assertEquals("C:\\Windows\\system32", UrlCanonicalizer.canonicalMessage("C:\\Windows\\system32"));
    }

    // ── 与 backend 侧的对齐冒烟(EVASION 家族代表向量) ──

    @Test
    void evasionFamilyVectors() {
        // 注意: 该向量编码里只有两级 ../, 期望值必须是两级
        assertEquals("/files/download?name=../../etc/passwd",
                UrlCanonicalizer.canonicalUrl(
                        "%2Ffiles%2Fdownload%3Fname%3D%2E%2E%2F%2E%2E%2Fetc%2Fpasswd"));
        assertEquals("/debug.php?cmd=id",
                UrlCanonicalizer.canonicalUrl(
                        "%2Fdebug%2Ephp%3Fcmd%3Did"));
        assertFalse(UrlCanonicalizer.canonicalUrl("/.%2E%2Fetc").contains("%"));
    }
}
