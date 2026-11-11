/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shiro.util;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Canonicalizes request paths so request filtering, filter chain resolution and path matching all
 * make the same routing decision.
 *
 * <p>The rules are intentionally strict:</p>
 * <ul>
 *     <li>Percent-encoded octets are decoded once. Any remaining valid escape sequence means the
 *     path was encoded more than once and is rejected as an ambiguous alias.</li>
 *     <li>Backslashes are treated as path separators and canonicalized to {@code '/'}.</li>
 *     <li>Duplicate separators are collapsed. Empty segments are ignored, as they are by
 *     {@link AntPathMatcher}.</li>
 *     <li>{@code "."} segments are removed and {@code ".."} segments are resolved. Traversal
 *     above the root is rejected.</li>
 *     <li>Control characters, malformed UTF-8 escapes and invalid paths are rejected.</li>
 * </ul>
 *
 * <p>Normal duplicate slashes, trailing slashes, case configuration and Ant wildcard syntax
 * remain compatible because normalization never changes case and never interprets wildcard
 * characters.</p>
 *
 * @since 3.0
 */
public final class PathNormalizer {

    /**
     * Canonical path separator.
     */
    public static final char SEPARATOR = '/';

    /**
     * Alternative separator used by some containers.
     */
    public static final char BACKSLASH_SEPARATOR = '\\';

    private static final int HEX_RADIX = 16;
    private static final int DECIMAL_RADIX = 10;

    private PathNormalizer() {
    }

    /**
     * Normalizes a request path using the shared security rules.
     *
     * @param path the path to normalize
     * @return the canonical path, or {@code null} when the input is {@code null}
     * @throws PathNormalizationException when the path is ambiguous, malformed or traverses above
     *                                    the root
     */
    public static String normalize(String path) {
        if (path == null) {
            return null;
        }

        String decoded = decodeAndValidate(path);
        return canonicalize(decoded, path);
    }

    private static String decodeAndValidate(String path) {
        String decoded = percentDecode(path);
        if (containsPercentEncoding(decoded)) {
            throw new PathNormalizationException("Repeated percent-encoding is not allowed: " + path);
        }
        rejectControlCharacters(decoded, path);
        return decoded;
    }

    private static String canonicalize(String decoded, String original) {
        String normalized = decoded.replace(BACKSLASH_SEPARATOR, SEPARATOR);
        if (normalized.isEmpty()) {
            return "/";
        }
        if (!normalized.startsWith(String.valueOf(SEPARATOR))) {
            normalized = SEPARATOR + normalized;
        }

        boolean trailingSlash = normalized.length() > 1 && normalized.endsWith(String.valueOf(SEPARATOR));
        List<String> segments = new ArrayList<>();
        for (String segment : normalized.split(String.valueOf(SEPARATOR), -1)) {
            addSegment(segments, segment, original);
        }

        if (segments.isEmpty()) {
            return "/";
        }

        return joinSegments(segments, trailingSlash, normalized.length());
    }

    private static void addSegment(List<String> segments, String segment, String original) {
        if (segment.isEmpty() || ".".equals(segment)) {
            return;
        }
        if ("..".equals(segment)) {
            if (segments.isEmpty()) {
                throw new PathNormalizationException("Path traversal above root: " + original);
            }
            segments.remove(segments.size() - 1);
            return;
        }
        segments.add(segment);
    }

    private static String joinSegments(List<String> segments, boolean trailingSlash, int capacity) {
        StringBuilder builder = new StringBuilder(capacity);
        for (String segment : segments) {
            builder.append(SEPARATOR).append(segment);
        }
        if (trailingSlash) {
            builder.append(SEPARATOR);
        }
        return builder.toString();
    }

    /**
     * Normalizes a path for matching. Relative values such as Ant patterns, URLs and matcher test
     * fixtures are returned unchanged. Request paths that cannot be normalized fail closed by
     * returning {@code null}.
     *
     * @param path the path to normalize
     * @return the canonical path, the original non-request path, or {@code null} when unsafe
     */
    public static String normalizeForMatch(String path) {
        if (path == null) {
            return null;
        }
        if (path.startsWith(String.valueOf(SEPARATOR)) || path.indexOf(BACKSLASH_SEPARATOR) >= 0) {
            try {
                return normalize(path);
            } catch (PathNormalizationException e) {
                return null;
            }
        }
        return path;
    }

    /**
     * Returns {@code true} when the path contains an encoding sequence that would only appear
     * after more than one decode pass. Such paths are ambiguous aliases and must fail closed.
     *
     * @param path the path to inspect
     * @return {@code true} when the path is multiply encoded or malformed
     */
    public static boolean isAmbiguous(String path) {
        if (path == null || path.isEmpty()) {
            return false;
        }
        try {
            return containsPercentEncoding(percentDecode(path));
        } catch (PathNormalizationException e) {
            return true;
        }
    }

    /**
     * Returns {@code true} when the path contains a {@code "."} or {@code ".."} segment. Both
     * forward and backslash separators are recognized.
     *
     * @param path the path to inspect
     * @return {@code true} when a dot segment is present
     */
    public static boolean hasDotSegments(String path) {
        if (path == null) {
            return false;
        }

        int start = 0;
        int length = path.length();
        for (int i = 0; i <= length; i++) {
            if (i == length || path.charAt(i) == SEPARATOR || path.charAt(i) == BACKSLASH_SEPARATOR) {
                String segment = path.substring(start, i);
                if (".".equals(segment) || "..".equals(segment)) {
                    return true;
                }
                start = i + 1;
            }
        }
        return false;
    }

    private static String percentDecode(String path) {
        StringBuilder decoded = new StringBuilder(path.length());
        int length = path.length();
        int index = 0;
        while (index < length) {
            char current = path.charAt(index);
            if (current != '%' || !isEscapeSequence(path, index)) {
                decoded.append(current);
                index++;
                continue;
            }

            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            while (isEscapeSequence(path, index)) {
                bytes.write(hexValue(path.charAt(index + 1)) * HEX_RADIX + hexValue(path.charAt(index + 2)));
                index += 3;
            }
            decoded.append(decodeUtf8(bytes.toByteArray(), path));
        }
        return decoded.toString();
    }

    private static String decodeUtf8(byte[] bytes, String path) {
        CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
        try {
            CharBuffer buffer = decoder.decode(ByteBuffer.wrap(bytes));
            return buffer.toString();
        } catch (CharacterCodingException e) {
            throw new PathNormalizationException("Invalid percent-encoded UTF-8 sequence: " + path, e);
        }
    }

    private static boolean containsPercentEncoding(String path) {
        for (int i = 0; i < path.length(); i++) {
            if (path.charAt(i) == '%' && isEscapeSequence(path, i)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isEscapeSequence(String path, int index) {
        return index + 2 < path.length()
                && path.charAt(index) == '%'
                && isHexDigit(path.charAt(index + 1))
                && isHexDigit(path.charAt(index + 2));
    }

    private static boolean isHexDigit(char character) {
        return isDecimalDigit(character) || isLowerHexLetter(character) || isUpperHexLetter(character);
    }

    private static boolean isDecimalDigit(char character) {
        return character >= '0' && character <= '9';
    }

    private static boolean isLowerHexLetter(char character) {
        return character >= 'a' && character <= 'f';
    }

    private static boolean isUpperHexLetter(char character) {
        return character >= 'A' && character <= 'F';
    }

    private static int hexValue(char character) {
        if (isDecimalDigit(character)) {
            return character - '0';
        }
        if (isLowerHexLetter(character)) {
            return character - 'a' + DECIMAL_RADIX;
        }
        return character - 'A' + DECIMAL_RADIX;
    }

    private static void rejectControlCharacters(String path, String original) {
        for (int i = 0; i < path.length(); i++) {
            char current = path.charAt(i);
            if (current < '\u0020' || current == '\u007f') {
                throw new PathNormalizationException("Control character in path: " + original);
            }
        }
    }

    /**
     * Raised when a path cannot be safely canonicalized.
     */
    public static class PathNormalizationException extends IllegalStateException {

        private static final long serialVersionUID = 1L;

        public PathNormalizationException(String message) {
            super(message);
        }

        public PathNormalizationException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
