package com.soc.util;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * URL 匹配规范形 — backend/normalization.py 的 Java 镜像（LogValidationJob 用）。
 *
 * <h2>为什么 Flink 侧也要一份</h2>
 * 引擎侧的规范化（Python, sigma_engine 匹配视图）是检测正确性的权威实现；
 * 本类把**同一语义**应用到校验管道：validated 事件的 rawData 里附加
 * {@code _urlCanonical}（只增不改，原始 url 不动），供下游分析/对账使用，
 * 并让两侧语义有可对照的测试证据。两侧的向量集保持同步 ——
 * 任何一侧改语义必须两侧同改并跑两侧测试（见 normalization.py 模块 docstring）。
 *
 * <h2>语义（与 Python 镜像逐条对应）</h2>
 * <ul>
 *   <li>受限多轮 percent 解码：稳定即停，最多 3 轮（防解码炸弹）；</li>
 *   <li>支持旧式 {@code %uXXXX} 编码；</li>
 *   <li>NUL 字节剥离；</li>
 *   <li>反斜杠→斜杠（{@code ..\..\windows} 与 {@code ../../etc} 同义）；</li>
 *   <li>刻意<b>不做</b>：路径点段折叠（会把 {@code ../} 消掉, 对原始形式
 *       写的规则库是回归）、HTML 实体、Unicode NFKC、'+'→空格
 *       （{@code URLDecoder} 会把 '+' 解成空格, 因此本类手写 percent 解码,
 *       <b>不要</b>换回 URLDecoder）。</li>
 * </ul>
 */
public final class UrlCanonicalizer {

    /** percent 解码轮数上限（与 normalization.MAX_DECODE_ROUNDS 一致）。 */
    public static final int MAX_DECODE_ROUNDS = 3;

    private static final Pattern UNICODE_ESCAPE = Pattern.compile("%u([0-9a-fA-F]{4})");
    private static final Charset UTF8 = StandardCharsets.UTF_8;

    private UrlCanonicalizer() {
    }

    /** 一轮解码：先 %uXXXX 再 percent 解码（无效 UTF-8 字节序列替换为 U+FFFD）。 */
    private static String decodeRound(String text) {
        if (text.indexOf('%') < 0) {
            return text;
        }
        Matcher m = UNICODE_ESCAPE.matcher(text);
        if (m.find()) {
            StringBuffer sb = new StringBuffer(text.length());
            do {
                m.appendReplacement(sb,
                        Matcher.quoteReplacement(String.valueOf((char) Integer.parseInt(m.group(1), 16))));
            } while (m.find());
            m.appendTail(sb);
            text = sb.toString();
        }
        return percentDecode(text);
    }

    /** 手写 percent 解码：'+' 不转空格（与 Python urllib.parse.unquote 语义一致）。 */
    private static String percentDecode(String text) {
        if (text.indexOf('%') < 0) {
            return text;
        }
        java.io.ByteArrayOutputStream buf = new java.io.ByteArrayOutputStream(text.length());
        int i = 0;
        int len = text.length();
        while (i < len) {
            char c = text.charAt(i);
            if (c == '%' && i + 2 < len) {
                int hi = hexVal(text.charAt(i + 1));
                int lo = hexVal(text.charAt(i + 2));
                if (hi >= 0 && lo >= 0) {
                    buf.write((hi << 4) | lo);
                    i += 3;
                    continue;
                }
            }
            // 非 %XX 序列：字符按 UTF-8 原样写入（按 code point 迭代, 兼容增补平面）
            int cp = text.codePointAt(i);
            if (cp <= 0x7F) {
                buf.write(cp);
            } else {
                byte[] encoded = new String(Character.toChars(cp)).getBytes(UTF8);
                buf.write(encoded, 0, encoded.length);
            }
            i += Character.charCount(cp);
        }
        // malformed UTF-8 字节序列由 String 构造器替换为 U+FFFD（= Python errors="replace"）
        return new String(buf.toByteArray(), UTF8);
    }

    private static int hexVal(char c) {
        if (c >= '0' && c <= '9') {
            return c - '0';
        }
        if (c >= 'a' && c <= 'f') {
            return c - 'a' + 10;
        }
        if (c >= 'A' && c <= 'F') {
            return c - 'A' + 10;
        }
        return -1;
    }

    /**
     * 受限多轮 percent 解码：稳定即停，最多 {@value #MAX_DECODE_ROUNDS} 轮。
     * 语义对应 Python {@code normalization.deep_decode}。
     */
    public static String deepDecode(String text) {
        if (text == null || text.isEmpty()) {
            return text;
        }
        String cur = text;
        for (int i = 0; i < MAX_DECODE_ROUNDS; i++) {
            String next = decodeRound(cur);
            if (next.equals(cur)) {
                break;
            }
            cur = next;
        }
        return cur;
    }

    /**
     * URL 匹配规范形：受限解码 → NUL 剥离 → 反斜杠归一。
     * 语义对应 Python {@code normalization.canonical_url}。
     */
    public static String canonicalUrl(String value) {
        if (value == null || value.isEmpty()) {
            return value;
        }
        if (value.indexOf('%') < 0 && value.indexOf('\\') < 0 && value.indexOf('\0') < 0) {
            return value;
        }
        String out = deepDecode(value);
        out = out.replace("\0", "").replace('\\', '/');
        return out.equals(value) ? value : out;
    }

    /**
     * message 匹配规范形：受限解码 + NUL 剥离（不做路径归一/反斜杠替换）。
     * 语义对应 Python {@code normalization.canonical_message}。
     */
    public static String canonicalMessage(String value) {
        if (value == null || value.isEmpty()) {
            return value;
        }
        if (value.indexOf('%') < 0 && value.indexOf('\0') < 0) {
            return value;
        }
        String out = deepDecode(value).replace("\0", "");
        return out.equals(value) ? value : out;
    }
}
