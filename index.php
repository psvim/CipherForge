<?php
/*
 * ╔═══════════════════════════════════════════════════════════╗
 * ║          CipherForge — Cyber Swiss Army Knife            ║
 * ║          Single-file PHP · v1.1 · by Vineet P.S.         ║
 * ╚═══════════════════════════════════════════════════════════╝
 *
 *  Theme : Cream #FAF8F2 · Navy #0A1628 · Gold #C9A84C
 *  Fonts : Noto Sans + Noto Sans Mono (Google Fonts, Apache 2.0)
 *          — Cormorant Garamond & Josefin Sans removed (copyright-safe)
 *  v1.1  : Glass/transparency UI · Fully responsive · Noto Sans universal
 *
 *  Operations covered (50+):
 *  ── Encoding   : Base64 enc/dec, Hex enc/dec, URL enc/dec,
 *                  HTML entity enc/dec, Binary, Octal, Morse,
 *                  ROT13, ROT47, ASCII85, Base32, Base58
 *  ── Hashing    : MD5, SHA1, SHA256, SHA512, SHA3-256,
 *                  CRC32, RIPEMD160, Whirlpool, HMAC-SHA256
 *  ── Crypto     : AES-256-CBC enc/dec, AES-128-CBC enc/dec,
 *                  AES-256-GCM enc/dec, DES enc/dec,
 *                  Blowfish enc/dec, RC4 enc/dec,
 *                  XOR key enc/dec, Vigenère enc/dec,
 *                  Caesar enc/dec, Beaufort enc/dec
 *  ── Text/Format: To Upper, To Lower, Trim, Reverse,
 *                  Word Count, Char Count, Byte Count,
 *                  Line Sort, Line Dedupe, Line Reverse,
 *                  String Diff, Pad Left, Pad Right,
 *                  Split by Delim, Join by Delim,
 *                  Regex Extract, Regex Replace,
 *                  Strip HTML, Defang URL, Refang URL
 *  ── Data Format: JSON Prettify, JSON Minify, JSON→CSV,
 *                  CSV→JSON, XML Prettify, Base64→Image,
 *                  Hex→IP, IP→Hex, Decimal↔Binary,
 *                  Decimal↔Hex, Unix Timestamp↔Human
 *  ── Compression: GZip compress/decompress (base64 wrapped)
 *  ── Misc       : Entropy calc, UUID gen, Password gen,
 *                  JWT Decode, UUID Version detect,
 *                  IP to Location info (local parse),
 *                  Lorem Ipsum gen
 */

// ─────────────────────────────────────────────
//  AJAX / Server-side processing
// ─────────────────────────────────────────────
if (isset($_POST['action']) && $_POST['action'] === 'process') {
    header('Content-Type: application/json; charset=utf-8');
    $input  = $_POST['input']  ?? '';
    $op     = $_POST['op']     ?? '';
    $arg1   = $_POST['arg1']   ?? '';
    $arg2   = $_POST['arg2']   ?? '';
    $arg3   = $_POST['arg3']   ?? '';

    try {
        $result = cf_process($input, $op, $arg1, $arg2, $arg3);
        echo json_encode(['ok' => true, 'result' => $result]);
    } catch (Throwable $e) {
        echo json_encode(['ok' => false, 'error' => $e->getMessage()]);
    }
    exit;
}

// ─────────────────────────────────────────────
//  Core processing function
// ─────────────────────────────────────────────
function cf_process(string $in, string $op, string $a1, string $a2, string $a3): string {
    switch ($op) {

        // ── ENCODING ──────────────────────────────
        case 'base64_enc'   : return base64_encode($in);
        case 'base64_dec'   : $d = base64_decode($in, true);
                              if ($d === false) throw new Exception('Invalid Base64 input');
                              return $d;
        case 'base32_enc'   : return cf_base32_encode($in);
        case 'base32_dec'   : return cf_base32_decode($in);
        case 'base58_enc'   : return cf_base58_encode($in);
        case 'base58_dec'   : return cf_base58_decode($in);
        case 'hex_enc'      : return bin2hex($in);
        case 'hex_dec'      : if (!ctype_xdigit(str_replace([' ',':'],'',$in)))
                                  throw new Exception('Invalid hex string');
                              return hex2bin(str_replace([' ',':'],'',$in));
        case 'url_enc'      : return urlencode($in);
        case 'url_dec'      : return urldecode($in);
        case 'url_enc_full' : return rawurlencode($in);
        case 'url_dec_full' : return rawurldecode($in);
        case 'html_enc'     : return htmlspecialchars($in, ENT_QUOTES|ENT_HTML5, 'UTF-8');
        case 'html_dec'     : return htmlspecialchars_decode($in, ENT_QUOTES|ENT_HTML5);
        case 'html_ent_enc' : return htmlentities($in, ENT_QUOTES|ENT_HTML5, 'UTF-8');
        case 'html_ent_dec' : return html_entity_decode($in, ENT_QUOTES|ENT_HTML5, 'UTF-8');
        case 'binary_enc'   : return cf_to_binary($in);
        case 'binary_dec'   : return cf_from_binary($in);
        case 'octal_enc'    : return cf_to_octal($in);
        case 'octal_dec'    : return cf_from_octal($in);
        case 'morse_enc'    : return cf_morse_encode($in);
        case 'morse_dec'    : return cf_morse_decode($in);
        case 'rot13'        : return str_rot13($in);
        case 'rot47'        : return cf_rot47($in);
        case 'ascii85_enc'  : return cf_ascii85_encode($in);
        case 'ascii85_dec'  : return cf_ascii85_decode($in);

        // ── HASHING ───────────────────────────────
        case 'md5'          : return md5($in);
        case 'md5_file_safe': return strtoupper(md5($in)); // uppercase variant
        case 'sha1'         : return sha1($in);
        case 'sha256'       : return hash('sha256', $in);
        case 'sha512'       : return hash('sha512', $in);
        case 'sha3_256'     : return hash('sha3-256', $in);
        case 'sha3_512'     : return hash('sha3-512', $in);
        case 'crc32'        : return sprintf('%u', crc32($in));
        case 'ripemd160'    : return hash('ripemd160', $in);
        case 'whirlpool'    :
            if (!in_array('whirlpool', hash_algos()))
                throw new Exception('Whirlpool not supported on this server');
            return hash('whirlpool', $in);
        case 'hmac_sha256'  :
            if (!$a1) throw new Exception('Key required for HMAC');
            return hash_hmac('sha256', $in, $a1);
        case 'hmac_sha512'  :
            if (!$a1) throw new Exception('Key required for HMAC');
            return hash_hmac('sha512', $in, $a1);
        case 'hash_all'     : return cf_hash_all($in);

        // ── SYMMETRIC CRYPTO ──────────────────────
        case 'aes256_enc'   :
            if (!$a1) throw new Exception('Key required');
            return cf_aes_encrypt($in, $a1, 'AES-256-CBC');
        case 'aes256_dec'   :
            if (!$a1) throw new Exception('Key required');
            return cf_aes_decrypt($in, $a1, 'AES-256-CBC');
        case 'aes128_enc'   :
            if (!$a1) throw new Exception('Key required');
            return cf_aes_encrypt($in, $a1, 'AES-128-CBC');
        case 'aes128_dec'   :
            if (!$a1) throw new Exception('Key required');
            return cf_aes_decrypt($in, $a1, 'AES-128-CBC');
        case 'aes_gcm_enc'  :
            if (!$a1) throw new Exception('Key required');
            return cf_aes_gcm_encrypt($in, $a1);
        case 'aes_gcm_dec'  :
            if (!$a1) throw new Exception('Key required');
            return cf_aes_gcm_decrypt($in, $a1);
        case 'des_enc'      :
            if (!$a1) throw new Exception('Key required');
            return cf_des_encrypt($in, $a1);
        case 'des_dec'      :
            if (!$a1) throw new Exception('Key required');
            return cf_des_decrypt($in, $a1);
        case 'blowfish_enc' :
            if (!$a1) throw new Exception('Key required');
            return cf_blowfish_encrypt($in, $a1);
        case 'blowfish_dec' :
            if (!$a1) throw new Exception('Key required');
            return cf_blowfish_decrypt($in, $a1);
        case 'rc4_enc'      :
        case 'rc4_dec'      :
            if (!$a1) throw new Exception('Key required');
            return cf_rc4($in, $a1); // RC4 enc=dec symmetric
        case 'xor_key'      :
            if (!$a1) throw new Exception('Key required');
            return cf_xor_key($in, $a1);

        // ── CLASSIC CIPHERS ───────────────────────
        case 'vigenere_enc' :
            if (!$a1) throw new Exception('Key required');
            return cf_vigenere($in, $a1, true);
        case 'vigenere_dec' :
            if (!$a1) throw new Exception('Key required');
            return cf_vigenere($in, $a1, false);
        case 'caesar_enc'   :
            $shift = (int)($a1 ?: 13);
            return cf_caesar($in, $shift);
        case 'caesar_dec'   :
            $shift = (int)($a1 ?: 13);
            return cf_caesar($in, 26 - ($shift % 26));
        case 'beaufort_enc' :
        case 'beaufort_dec' :
            if (!$a1) throw new Exception('Key required');
            return cf_beaufort($in, $a1); // Beaufort is self-reciprocal

        // ── TEXT / FORMAT ─────────────────────────
        case 'to_upper'     : return mb_strtoupper($in, 'UTF-8');
        case 'to_lower'     : return mb_strtolower($in, 'UTF-8');
        case 'to_title'     : return mb_convert_case($in, MB_CASE_TITLE, 'UTF-8');
        case 'trim'         : return trim($in);
        case 'ltrim'        : return ltrim($in);
        case 'rtrim'        : return rtrim($in);
        case 'reverse'      : return cf_utf8_reverse($in);
        case 'word_count'   : return (string) str_word_count($in);
        case 'char_count'   : return (string) mb_strlen($in, 'UTF-8');
        case 'byte_count'   : return (string) strlen($in);
        case 'line_count'   : return (string) (substr_count($in, "\n") + 1);
        case 'line_sort'    :
            $lines = explode("\n", $in);
            sort($lines);
            return implode("\n", $lines);
        case 'line_sort_rev':
            $lines = explode("\n", $in);
            rsort($lines);
            return implode("\n", $lines);
        case 'line_dedupe'  :
            return implode("\n", array_unique(explode("\n", $in)));
        case 'line_reverse' :
            return implode("\n", array_reverse(explode("\n", $in)));
        case 'pad_left'     :
            $len = (int)($a1 ?: 10);
            $chr = $a2 ?: ' ';
            return str_pad($in, $len, $chr, STR_PAD_LEFT);
        case 'pad_right'    :
            $len = (int)($a1 ?: 10);
            $chr = $a2 ?: ' ';
            return str_pad($in, $len, $chr, STR_PAD_RIGHT);
        case 'split'        :
            $delim = $a1 !== '' ? $a1 : ',';
            return implode("\n", explode($delim, $in));
        case 'join'         :
            $delim = $a1 !== '' ? $a1 : ',';
            return implode($delim, explode("\n", $in));
        case 'regex_extract':
            if (!$a1) throw new Exception('Pattern required');
            preg_match_all('/' . addcslashes($a1, '/') . '/', $in, $m);
            return implode("\n", $m[0]);
        case 'regex_replace':
            if (!$a1) throw new Exception('Pattern required');
            return preg_replace('/' . addcslashes($a1, '/') . '/', $a2, $in) ?? $in;
        case 'strip_html'   : return strip_tags($in);
        case 'nl2br'        : return nl2br($in);
        case 'defang_url'   :
            return str_replace(['http://','https://','ftp://','.',
                                '[','<','>'],
                               ['hxxp[://]','hxxps[://]','fxp[://]','[.]','[','[<]','[>]'], $in);
        case 'refang_url'   :
            return str_replace(['hxxp[://]','hxxps[://]','fxp[://]','[.]','[<]','[>]'],
                               ['http://','https://','ftp://','.',  '<',  '>'], $in);
        case 'string_diff'  : return cf_string_diff($in, $a1);
        case 'repeat'       :
            $n = max(1,(int)($a1 ?: 2));
            return str_repeat($in, $n);
        case 'add_line_nums':
            $lines = explode("\n", $in);
            $pad = strlen((string)count($lines));
            foreach ($lines as $i => &$l)
                $l = str_pad($i+1, $pad, '0', STR_PAD_LEFT) . ': ' . $l;
            return implode("\n", $lines);

        // ── DATA FORMAT ───────────────────────────
        case 'json_pretty'  :
            $d = json_decode($in);
            if (json_last_error() !== JSON_ERROR_NONE)
                throw new Exception('Invalid JSON: ' . json_last_error_msg());
            return json_encode($d, JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);
        case 'json_minify'  :
            $d = json_decode($in);
            if (json_last_error() !== JSON_ERROR_NONE)
                throw new Exception('Invalid JSON: ' . json_last_error_msg());
            return json_encode($d, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);
        case 'json_to_csv'  : return cf_json_to_csv($in);
        case 'csv_to_json'  : return cf_csv_to_json($in);
        case 'xml_pretty'   : return cf_xml_pretty($in);
        case 'hex_to_ip'    : return cf_hex_to_ip($in);
        case 'ip_to_hex'    : return cf_ip_to_hex($in);
        case 'dec_to_bin'   : return decbin((int)$in);
        case 'bin_to_dec'   : return (string)bindec($in);
        case 'dec_to_hex'   : return dechex((int)$in);
        case 'hex_to_dec'   : return (string)hexdec($in);
        case 'dec_to_oct'   : return decoct((int)$in);
        case 'oct_to_dec'   : return (string)octdec($in);
        case 'unix_to_human':
            $ts = (int)$in;
            if ($ts === 0 && $in !== '0') throw new Exception('Not a valid timestamp');
            return gmdate('Y-m-d H:i:s', $ts) . ' UTC';
        case 'human_to_unix': return (string) strtotime($in);
        case 'base64_to_img': return '<img src="data:image/png;base64,' . trim($in) . '" alt="decoded image">';
        case 'char_to_ascii': return implode(' ', array_map('ord', str_split($in)));
        case 'ascii_to_char': return implode('', array_map('chr', array_map('intval', explode(' ', trim($in)))));
        case 'int_to_roman' : return cf_int_to_roman((int)$in);
        case 'roman_to_int' : return (string) cf_roman_to_int($in);

        // ── COMPRESSION ───────────────────────────
        case 'gzip_enc'     :
            $gz = gzencode($in, 9);
            if ($gz === false) throw new Exception('gzip failed');
            return base64_encode($gz);
        case 'gzip_dec'     :
            $raw = base64_decode($in, true);
            if ($raw === false) throw new Exception('Invalid base64');
            $out = gzdecode($raw);
            if ($out === false) throw new Exception('gzip decode failed');
            return $out;
        case 'zlib_enc'     :
            $z = gzcompress($in, 9);
            if ($z === false) throw new Exception('zlib failed');
            return base64_encode($z);
        case 'zlib_dec'     :
            $raw = base64_decode($in, true);
            if ($raw === false) throw new Exception('Invalid base64');
            $out = gzuncompress($raw);
            if ($out === false) throw new Exception('zlib decode failed');
            return $out;

        // ── MISC / UTILS ──────────────────────────
        case 'entropy'      : return cf_shannon_entropy($in);
        case 'uuid_gen'     : return cf_uuid_gen();
        case 'uuid_detect'  : return cf_uuid_detect($in);
        case 'password_gen' :
            $len = max(8, min(128, (int)($a1 ?: 16)));
            $upper = $a2 !== '0';
            $symbols = $a3 !== '0';
            return cf_password_gen($len, $upper, $symbols);
        case 'jwt_decode'   : return cf_jwt_decode($in);
        case 'lorem_ipsum'  :
            $words = (int)($a1 ?: 50);
            return cf_lorem($words);
        case 'count_vowels' : return (string) preg_match_all('/[aeiouAEIOU]/', $in);
        case 'is_palindrome': $clean = preg_replace('/[^a-zA-Z0-9]/', '', mb_strtolower($in));
                              return $clean === strrev($clean) ? 'Yes — it is a palindrome' : 'No — not a palindrome';
        case 'freq_analysis': return cf_freq_analysis($in);

        default: throw new Exception("Unknown operation: $op");
    }
}

// ═══════════════════════════════════════════════════
//   HELPER IMPLEMENTATIONS
// ═══════════════════════════════════════════════════

// ── Base32 ─────────────────────────────────────────
function cf_base32_encode(string $s): string {
    $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $out = ''; $bits = 0; $acc = 0;
    foreach (str_split($s) as $c) {
        $acc = ($acc << 8) | ord($c); $bits += 8;
        while ($bits >= 5) { $bits -= 5; $out .= $chars[($acc >> $bits) & 31]; }
    }
    if ($bits > 0) $out .= $chars[($acc << (5 - $bits)) & 31];
    return str_pad($out, (int)(ceil(strlen($out)/8)*8), '=');
}
function cf_base32_decode(string $s): string {
    $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $s = strtoupper(rtrim($s, '='));
    $out = ''; $bits = 0; $acc = 0;
    foreach (str_split($s) as $c) {
        $v = strpos($chars, $c);
        if ($v === false) continue;
        $acc = ($acc << 5) | $v; $bits += 5;
        if ($bits >= 8) { $bits -= 8; $out .= chr(($acc >> $bits) & 255); }
    }
    return $out;
}

// ── Base58 ─────────────────────────────────────────
function cf_base58_encode(string $s): string {
    $alpha = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    $hex = bin2hex($s);
    $num = gmp_init('0x' . (strlen($hex) ? $hex : '00'), 16);
    $enc = '';
    while (gmp_cmp($num, 0) > 0) {
        [$num, $rem] = gmp_div_qr($num, 58);
        $enc = $alpha[gmp_intval($rem)] . $enc;
    }
    foreach (str_split($s) as $c) { if ($c !== "\x00") break; $enc = '1' . $enc; }
    return $enc;
}
function cf_base58_decode(string $s): string {
    $alpha = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    $num = gmp_init(0);
    foreach (str_split($s) as $c) {
        $v = strpos($alpha, $c);
        if ($v === false) throw new Exception("Invalid Base58 char: $c");
        $num = gmp_add(gmp_mul($num, 58), $v);
    }
    $hex = gmp_strval($num, 16);
    if (strlen($hex) % 2) $hex = '0' . $hex;
    $out = hex2bin($hex);
    $pads = 0;
    foreach (str_split($s) as $c) { if ($c !== '1') break; $pads++; }
    return str_repeat("\x00", $pads) . $out;
}

// ── Binary ─────────────────────────────────────────
function cf_to_binary(string $s): string {
    return implode(' ', array_map(fn($c) => str_pad(decbin(ord($c)), 8, '0', STR_PAD_LEFT), str_split($s)));
}
function cf_from_binary(string $s): string {
    $bytes = preg_split('/[\s,]+/', trim($s));
    return implode('', array_map(fn($b) => chr(bindec($b)), $bytes));
}

// ── Octal ──────────────────────────────────────────
function cf_to_octal(string $s): string {
    return implode(' ', array_map(fn($c) => str_pad(decoct(ord($c)), 3, '0', STR_PAD_LEFT), str_split($s)));
}
function cf_from_octal(string $s): string {
    $parts = preg_split('/[\s,]+/', trim($s));
    return implode('', array_map(fn($o) => chr((int)octdec($o)), $parts));
}

// ── Morse ──────────────────────────────────────────
function cf_morse_map(): array {
    return ['A'=>'.-','B'=>'-...','C'=>'-.-.','D'=>'-..','E'=>'.','F'=>'..-.','G'=>'--.','H'=>'....','I'=>'..','J'=>'.---','K'=>'-.-','L'=>'.-..','M'=>'--','N'=>'-.','O'=>'---','P'=>'.--.','Q'=>'--.-','R'=>'.-.','S'=>'...','T'=>'-','U'=>'..-','V'=>'...-','W'=>'.--','X'=>'-..-','Y'=>'-.--','Z'=>'--..',
             '0'=>'-----','1'=>'.----','2'=>'..---','3'=>'...--','4'=>'....-','5'=>'.....','6'=>'-....','7'=>'--...','8'=>'---..','9'=>'----.',
             ' '=>' / ', '.'=>'.-.-.-',','=>'--..--','?'=>'..--..','!'=>'-.-.--'];
}
function cf_morse_encode(string $s): string {
    $m = cf_morse_map();
    $out = [];
    foreach (str_split(strtoupper($s)) as $c)
        $out[] = isset($m[$c]) ? $m[$c] : '?';
    return implode(' ', $out);
}
function cf_morse_decode(string $s): string {
    $m = array_flip(cf_morse_map());
    $m[' / '] = ' ';
    $out = '';
    foreach (explode(' ', $s) as $code)
        $out .= $m[$code] ?? '?';
    return $out;
}

// ── ROT47 ──────────────────────────────────────────
function cf_rot47(string $s): string {
    $out = '';
    foreach (str_split($s) as $c) {
        $o = ord($c);
        $out .= ($o >= 33 && $o <= 126) ? chr(33 + (($o - 33 + 47) % 94)) : $c;
    }
    return $out;
}

// ── ASCII85 ────────────────────────────────────────
function cf_ascii85_encode(string $s): string {
    $out = '<~';
    $pad = (4 - (strlen($s) % 4)) % 4;
    $s .= str_repeat("\x00", $pad);
    foreach (str_split($s, 4) as $chunk) {
        $v = unpack('N', $chunk)[1];
        if ($v === 0) { $out .= 'z'; continue; }
        $g = [];
        for ($i = 4; $i >= 0; $i--) { $g[$i] = ($v % 85) + 33; $v = intdiv($v, 85); }
        $out .= implode('', array_map('chr', $g));
    }
    if ($pad) $out = substr($out, 0, -$pad);
    return $out . '~>';
}
function cf_ascii85_decode(string $s): string {
    $s = preg_replace('/\s/', '', $s);
    $s = preg_replace('/^<~/', '', $s);
    $s = preg_replace('/~>$/', '', $s);
    $out = '';
    $i = 0;
    while ($i < strlen($s)) {
        if ($s[$i] === 'z') { $out .= "\x00\x00\x00\x00"; $i++; continue; }
        $chunk = substr($s, $i, 5);
        $pad = 5 - strlen($chunk);
        $chunk = str_pad($chunk, 5, 'u');
        $v = 0;
        foreach (str_split($chunk) as $c)
            $v = $v * 85 + ord($c) - 33;
        $bytes = pack('N', $v);
        $out .= substr($bytes, 0, 4 - $pad);
        $i += 5;
    }
    return $out;
}

// ── Hashing all ────────────────────────────────────
function cf_hash_all(string $s): string {
    $algos = ['md5','sha1','sha256','sha512','sha3-256','sha3-512','ripemd160','crc32b'];
    $lines = [];
    foreach ($algos as $a) {
        if (in_array($a, hash_algos()))
            $lines[] = strtoupper($a) . ': ' . hash($a, $s);
    }
    return implode("\n", $lines);
}

// ── AES ────────────────────────────────────────────
function cf_aes_encrypt(string $plain, string $key, string $method): string {
    $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($method));
    $enc = openssl_encrypt($plain, $method, $key, OPENSSL_RAW_DATA, $iv);
    if ($enc === false) throw new Exception('AES encrypt failed: ' . openssl_error_string());
    return base64_encode($iv . $enc);
}
function cf_aes_decrypt(string $b64, string $key, string $method): string {
    $raw = base64_decode($b64, true);
    if ($raw === false) throw new Exception('Invalid base64 input');
    $ivLen = openssl_cipher_iv_length($method);
    $iv = substr($raw, 0, $ivLen);
    $enc = substr($raw, $ivLen);
    $dec = openssl_decrypt($enc, $method, $key, OPENSSL_RAW_DATA, $iv);
    if ($dec === false) throw new Exception('AES decrypt failed — wrong key or corrupted data');
    return $dec;
}
function cf_aes_gcm_encrypt(string $plain, string $key): string {
    $iv = openssl_random_pseudo_bytes(12);
    $tag = '';
    $enc = openssl_encrypt($plain, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, '', 16);
    if ($enc === false) throw new Exception('AES-GCM encrypt failed');
    return base64_encode($iv . $tag . $enc);
}
function cf_aes_gcm_decrypt(string $b64, string $key): string {
    $raw = base64_decode($b64, true);
    if ($raw === false) throw new Exception('Invalid base64 input');
    $iv  = substr($raw, 0, 12);
    $tag = substr($raw, 12, 16);
    $enc = substr($raw, 28);
    $dec = openssl_decrypt($enc, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
    if ($dec === false) throw new Exception('AES-GCM decrypt failed — wrong key or tampered data');
    return $dec;
}

// ── DES ────────────────────────────────────────────
function cf_des_encrypt(string $plain, string $key): string {
    $key = substr(str_pad($key, 8, ' '), 0, 8);
    $iv = openssl_random_pseudo_bytes(8);
    $enc = openssl_encrypt($plain, 'des-cbc', $key, OPENSSL_RAW_DATA, $iv);
    if ($enc === false) throw new Exception('DES encrypt failed');
    return base64_encode($iv . $enc);
}
function cf_des_decrypt(string $b64, string $key): string {
    $key = substr(str_pad($key, 8, ' '), 0, 8);
    $raw = base64_decode($b64, true);
    if ($raw === false) throw new Exception('Invalid base64');
    $iv = substr($raw, 0, 8);
    $dec = openssl_decrypt(substr($raw, 8), 'des-cbc', $key, OPENSSL_RAW_DATA, $iv);
    if ($dec === false) throw new Exception('DES decrypt failed');
    return $dec;
}

// ── Blowfish ───────────────────────────────────────
function cf_blowfish_encrypt(string $plain, string $key): string {
    $iv = openssl_random_pseudo_bytes(8);
    $enc = openssl_encrypt($plain, 'bf-cbc', $key, OPENSSL_RAW_DATA, $iv);
    if ($enc === false) throw new Exception('Blowfish encrypt failed');
    return base64_encode($iv . $enc);
}
function cf_blowfish_decrypt(string $b64, string $key): string {
    $raw = base64_decode($b64, true);
    if ($raw === false) throw new Exception('Invalid base64');
    $iv = substr($raw, 0, 8);
    $dec = openssl_decrypt(substr($raw, 8), 'bf-cbc', $key, OPENSSL_RAW_DATA, $iv);
    if ($dec === false) throw new Exception('Blowfish decrypt failed');
    return $dec;
}

// ── RC4 ────────────────────────────────────────────
function cf_rc4(string $data, string $key): string {
    $s = range(0, 255);
    $j = 0;
    for ($i = 0; $i < 256; $i++) {
        $j = ($j + $s[$i] + ord($key[$i % strlen($key)])) % 256;
        [$s[$i], $s[$j]] = [$s[$j], $s[$i]];
    }
    $i = $j = 0;
    $out = '';
    foreach (str_split($data) as $c) {
        $i = ($i + 1) % 256;
        $j = ($j + $s[$i]) % 256;
        [$s[$i], $s[$j]] = [$s[$j], $s[$i]];
        $out .= chr(ord($c) ^ $s[($s[$i] + $s[$j]) % 256]);
    }
    return $out;
}

// ── XOR ────────────────────────────────────────────
function cf_xor_key(string $data, string $key): string {
    $out = '';
    $kl = strlen($key);
    for ($i = 0; $i < strlen($data); $i++)
        $out .= chr(ord($data[$i]) ^ ord($key[$i % $kl]));
    return $out;
}

// ── Vigenère ───────────────────────────────────────
function cf_vigenere(string $s, string $key, bool $enc): string {
    $key = strtoupper(preg_replace('/[^a-zA-Z]/', '', $key));
    if (!strlen($key)) throw new Exception('Key must contain letters');
    $out = ''; $ki = 0;
    foreach (str_split($s) as $c) {
        if (ctype_alpha($c)) {
            $base = ctype_upper($c) ? 65 : 97;
            $shift = ord($key[$ki % strlen($key)]) - 65;
            if (!$enc) $shift = 26 - $shift;
            $out .= chr(($base + (ord($c) - $base + $shift + 26) % 26));
            $ki++;
        } else $out .= $c;
    }
    return $out;
}

// ── Caesar ─────────────────────────────────────────
function cf_caesar(string $s, int $shift): string {
    $out = '';
    foreach (str_split($s) as $c) {
        if (ctype_alpha($c)) {
            $base = ctype_upper($c) ? 65 : 97;
            $out .= chr(($base + (ord($c) - $base + $shift) % 26));
        } else $out .= $c;
    }
    return $out;
}

// ── Beaufort ───────────────────────────────────────
function cf_beaufort(string $s, string $key): string {
    $key = strtoupper(preg_replace('/[^a-zA-Z]/', '', $key));
    if (!strlen($key)) throw new Exception('Key must contain letters');
    $out = ''; $ki = 0;
    foreach (str_split($s) as $c) {
        if (ctype_alpha($c)) {
            $base = ctype_upper($c) ? 65 : 97;
            $kc = ord($key[$ki % strlen($key)]) - 65;
            $out .= chr($base + ($kc - (ord($c) - $base) + 26) % 26);
            $ki++;
        } else $out .= $c;
    }
    return $out;
}

// ── UTF-8 reverse ──────────────────────────────────
function cf_utf8_reverse(string $s): string {
    preg_match_all('/./us', $s, $m);
    return implode('', array_reverse($m[0]));
}

// ── String diff ────────────────────────────────────
function cf_string_diff(string $a, string $b): string {
    $la = explode("\n", $a);
    $lb = explode("\n", $b);
    $out = '';
    $max = max(count($la), count($lb));
    for ($i = 0; $i < $max; $i++) {
        $al = $la[$i] ?? '';
        $bl = $lb[$i] ?? '';
        if ($al === $bl) $out .= "  $al\n";
        else { $out .= "- $al\n"; $out .= "+ $bl\n"; }
    }
    return rtrim($out);
}

// ── JSON/CSV ───────────────────────────────────────
function cf_json_to_csv(string $s): string {
    $data = json_decode($s, true);
    if (json_last_error() !== JSON_ERROR_NONE) throw new Exception('Invalid JSON');
    if (!is_array($data) || empty($data)) throw new Exception('Expected JSON array');
    if (!is_array(reset($data))) throw new Exception('Expected array of objects');
    $rows = [];
    $headers = array_keys((array)reset($data));
    $rows[] = implode(',', array_map(fn($h) => '"' . str_replace('"','""',$h) . '"', $headers));
    foreach ($data as $row) {
        $cells = [];
        foreach ($headers as $h) {
            $v = (array)$row;
            $val = $v[$h] ?? '';
            $cells[] = '"' . str_replace('"', '""', (string)$val) . '"';
        }
        $rows[] = implode(',', $cells);
    }
    return implode("\n", $rows);
}
function cf_csv_to_json(string $s): string {
    $lines = array_filter(explode("\n", trim($s)));
    if (count($lines) < 2) throw new Exception('Need at least 2 rows (header + data)');
    $headers = str_getcsv(array_shift($lines));
    $out = [];
    foreach ($lines as $line) {
        $vals = str_getcsv($line);
        $out[] = array_combine($headers, array_pad($vals, count($headers), ''));
    }
    return json_encode($out, JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE);
}

// ── XML pretty ─────────────────────────────────────
function cf_xml_pretty(string $s): string {
    $dom = new DOMDocument();
    $dom->preserveWhiteSpace = false;
    $dom->formatOutput = true;
    if (!@$dom->loadXML($s)) throw new Exception('Invalid XML');
    return $dom->saveXML();
}

// ── IP/Hex ─────────────────────────────────────────
function cf_hex_to_ip(string $s): string {
    $h = str_replace([' ','0x'], '', $s);
    if (strlen($h) === 8) {
        $n = hexdec($h);
        return long2ip($n);
    }
    if (strlen($h) === 32) {
        $parts = str_split($h, 4);
        return implode(':', $parts);
    }
    throw new Exception('Expected 8 hex digits (IPv4) or 32 (IPv6)');
}
function cf_ip_to_hex(string $s): string {
    if (filter_var($s, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4))
        return dechex(ip2long($s));
    if (filter_var($s, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6))
        return bin2hex(inet_pton($s));
    throw new Exception('Invalid IP address');
}

// ── Shannon Entropy ────────────────────────────────
function cf_shannon_entropy(string $s): string {
    if (!strlen($s)) return '0';
    $freq = array_count_values(str_split($s));
    $len = strlen($s);
    $entropy = 0.0;
    foreach ($freq as $count) {
        $p = $count / $len;
        $entropy -= $p * log($p, 2);
    }
    return sprintf("Entropy: %.4f bits/byte\nMax possible: 8.0000\nRatio: %.2f%%\n\nInterpretation:\n  < 1.0 → Very low entropy (repeated patterns)\n  1–3   → Some structure\n  3–5   → English text range\n  5–7   → Compressed or encrypted data\n  > 7.5 → Likely encrypted/random data",
        $entropy, ($entropy/8)*100);
}

// ── UUID gen/detect ────────────────────────────────
function cf_uuid_gen(): string {
    $b = random_bytes(16);
    $b[6] = chr((ord($b[6]) & 0x0f) | 0x40);
    $b[8] = chr((ord($b[8]) & 0x3f) | 0x80);
    return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($b), 4));
}
function cf_uuid_detect(string $s): string {
    $s = trim($s);
    if (!preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-([0-9a-f]{4})-[0-9a-f]{4}-[0-9a-f]{12}$/i', $s, $m))
        return 'Not a valid UUID';
    $v = hexdec($m[1][0]);
    $ver = ($v >> 4) & 0xf;
    return "Valid UUID\nVersion: $ver\n" . match($ver) {
        1 => 'Type: Time-based (MAC address + timestamp)',
        3 => 'Type: MD5 hash-based',
        4 => 'Type: Random (most common)',
        5 => 'Type: SHA-1 hash-based',
        default => 'Type: Unknown/Non-standard'
    };
}

// ── Password gen ───────────────────────────────────
function cf_password_gen(int $len, bool $upper, bool $symbols): string {
    $chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
    if ($upper)   $chars .= 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if ($symbols) $chars .= '!@#$%^&*()-_=+[]{}|;:,.<>?';
    $out = '';
    $max = strlen($chars) - 1;
    for ($i = 0; $i < $len; $i++) $out .= $chars[random_int(0, $max)];
    return $out;
}

// ── JWT decode ─────────────────────────────────────
function cf_jwt_decode(string $jwt): string {
    $parts = explode('.', trim($jwt));
    if (count($parts) !== 3) throw new Exception('Not a valid JWT (need 3 parts)');
    [$header, $payload, $sig] = $parts;
    $h = json_decode(base64_decode(strtr($header, '-_', '+/') . str_repeat('=', (4 - strlen($header) % 4) % 4)), true);
    $p = json_decode(base64_decode(strtr($payload, '-_', '+/') . str_repeat('=', (4 - strlen($payload) % 4) % 4)), true);
    $out = "=== HEADER ===\n";
    $out .= json_encode($h, JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE) . "\n\n";
    $out .= "=== PAYLOAD ===\n";
    if (isset($p['iat'])) $p['iat_human'] = gmdate('Y-m-d H:i:s', $p['iat']) . ' UTC';
    if (isset($p['exp'])) $p['exp_human'] = gmdate('Y-m-d H:i:s', $p['exp']) . ' UTC' . (time() > $p['exp'] ? ' ⚠️ EXPIRED' : ' ✅ valid');
    $out .= json_encode($p, JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE) . "\n\n";
    $out .= "=== SIGNATURE ===\n";
    $out .= "Raw (Base64URL): $sig\n";
    $out .= "(Signature NOT verified — CipherForge does not perform cryptographic verification)";
    return $out;
}

// ── Lorem Ipsum ────────────────────────────────────
function cf_lorem(int $words): string {
    $bank = explode(' ', 'lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor incididunt ut labore et dolore magna aliqua ut enim ad minim veniam quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur excepteur sint occaecat cupidatat non proident sunt in culpa qui officia deserunt mollit anim id est laborum');
    $out = [];
    for ($i = 0; $i < $words; $i++) $out[] = $bank[$i % count($bank)];
    return ucfirst(implode(' ', $out)) . '.';
}

// ── Roman numerals ─────────────────────────────────
function cf_int_to_roman(int $n): string {
    if ($n < 1 || $n > 3999) throw new Exception('Range: 1–3999');
    $v = [1000,900,500,400,100,90,50,40,10,9,5,4,1];
    $r = ['M','CM','D','CD','C','XC','L','XL','X','IX','V','IV','I'];
    $out = '';
    foreach ($v as $i => $val) { while ($n >= $val) { $out .= $r[$i]; $n -= $val; } }
    return $out;
}
function cf_roman_to_int(string $s): int {
    $map = ['I'=>1,'V'=>5,'X'=>10,'L'=>50,'C'=>100,'D'=>500,'M'=>1000];
    $s = strtoupper(trim($s)); $prev = 0; $sum = 0;
    foreach (array_reverse(str_split($s)) as $c) {
        if (!isset($map[$c])) throw new Exception("Unknown Roman char: $c");
        $v = $map[$c];
        $sum += ($v < $prev) ? -$v : $v;
        $prev = $v;
    }
    return $sum;
}

// ── Frequency analysis ─────────────────────────────
function cf_freq_analysis(string $s): string {
    $s = strtolower(preg_replace('/[^a-zA-Z]/', '', $s));
    if (!$s) throw new Exception('No alphabetic characters found');
    $freq = array_count_values(str_split($s));
    arsort($freq);
    $total = strlen($s);
    $out = "Letter Frequency Analysis\n";
    $out .= str_repeat('─', 35) . "\n";
    $out .= sprintf("%-6s %-8s %-8s %s\n", 'Char', 'Count', 'Freq%', 'Bar');
    $out .= str_repeat('─', 35) . "\n";
    foreach ($freq as $c => $cnt) {
        $pct = $cnt / $total * 100;
        $bar = str_repeat('█', (int)round($pct * 2));
        $out .= sprintf("%-6s %-8d %-8.2f %s\n", $c, $cnt, $pct, $bar);
    }
    return $out;
}

// ═══════════════════════════════════════════════════
//  HTML OUTPUT
// ═══════════════════════════════════════════════════
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CipherForge — Cyber Swiss Army Knife</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Noto+Sans:ital,wght@0,300;0,400;0,500;0,600;0,700;1,400&family=Noto+Sans+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
/* ── RESET & VARS ─────────────────────────────── */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

:root {
  --cream:       #FAF8F2;
  --cream-dark:  #F0EDE3;
  --cream-border:#E0DBCC;
  --navy:        #0A1628;
  --navy-mid:    #12233D;
  --navy-light:  #1C3256;
  --gold:        #C9A84C;
  --gold-light:  #E0C070;
  --gold-dark:   #A07830;
  --text:        #1A2640;
  --text-muted:  #5A6A80;
  --success:     #2E7D44;
  --error:       #C0392B;
  --font-display: 'Noto Sans', system-ui, sans-serif;
  --font-ui:      'Noto Sans', system-ui, sans-serif;
  --font-mono:    'Noto Sans Mono', 'Courier New', monospace;
  --glass-bg:     rgba(250,248,242,.72);
  --glass-border: rgba(201,168,76,.22);
  --glass-blur:   blur(18px);
  --glass-navy:   rgba(10,22,40,.82);
  --radius:       8px;
  --shadow:       0 2px 12px rgba(10,22,40,.12);
  --shadow-lg:    0 8px 32px rgba(10,22,40,.18);
}

html, body { height: 100%; }
body {
  font-family: var(--font-ui);
  background: var(--cream);
  background-image:
    radial-gradient(ellipse at 20% 0%, rgba(201,168,76,.07) 0%, transparent 60%),
    radial-gradient(ellipse at 80% 100%, rgba(10,22,40,.05) 0%, transparent 60%);
  background-attachment: fixed;
  color: var(--text);
  font-size: 14px;
  display: flex;
  flex-direction: column;
  min-height: 100vh;
}

/* ── SCROLLBAR ─────────────────────────────────── */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: var(--cream-dark); }
::-webkit-scrollbar-thumb { background: var(--gold); border-radius: 3px; }

/* ── HEADER ────────────────────────────────────── */
header {
  background: var(--glass-navy);
  backdrop-filter: var(--glass-blur);
  -webkit-backdrop-filter: var(--glass-blur);
  padding: 0 24px;
  display: flex;
  align-items: center;
  gap: 16px;
  height: 58px;
  box-shadow: 0 2px 24px rgba(0,0,0,.4), 0 1px 0 rgba(201,168,76,.18) inset;
  border-bottom: 1px solid rgba(201,168,76,.15);
  position: sticky;
  top: 0;
  z-index: 100;
  flex-shrink: 0;
}
.header-logo {
  display: flex;
  align-items: center;
  gap: 10px;
}
.header-logo svg { flex-shrink: 0; }
.header-brand {
  display: flex;
  flex-direction: column;
  line-height: 1;
}
.header-name {
  font-family: var(--font-ui);
  font-size: 20px;
  font-weight: 700;
  color: var(--gold);
  letter-spacing: 1px;
  text-transform: uppercase;
}
.header-tagline {
  font-size: 10px;
  color: rgba(255,255,255,.5);
  letter-spacing: 1.5px;
  text-transform: uppercase;
  font-weight: 300;
}
.header-right {
  margin-left: auto;
  display: flex;
  align-items: center;
  gap: 12px;
}
.op-count-badge {
  background: var(--gold);
  color: var(--navy);
  font-size: 11px;
  font-weight: 700;
  padding: 3px 10px;
  border-radius: 20px;
  letter-spacing: .5px;
}
.btn-icon {
  background: transparent;
  border: 1px solid rgba(255,255,255,.2);
  color: rgba(255,255,255,.7);
  padding: 6px 12px;
  border-radius: 6px;
  cursor: pointer;
  font-family: var(--font-ui);
  font-size: 12px;
  transition: all .2s;
}
.btn-icon:hover { border-color: var(--gold); color: var(--gold); }

/* ── LAYOUT ────────────────────────────────────── */
.app-layout {
  display: flex;
  flex: 1;
  overflow: hidden;
  min-height: 0;
}

/* ── SIDEBAR ───────────────────────────────────── */
.sidebar {
  width: 260px;
  min-width: 220px;
  background: rgba(18,35,61,.88);
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  display: flex;
  flex-direction: column;
  border-right: 1px solid rgba(201,168,76,.18);
  overflow: hidden;
  transition: width .28s cubic-bezier(.4,0,.2,1);
  flex-shrink: 0;
}
.sidebar.collapsed { width: 0; min-width: 0; border: none; overflow: hidden; }

.sidebar-search {
  padding: 12px;
  border-bottom: 1px solid rgba(255,255,255,.07);
}
.sidebar-search input {
  width: 100%;
  background: rgba(255,255,255,.07);
  border: 1px solid rgba(255,255,255,.12);
  border-radius: 6px;
  padding: 8px 12px;
  color: #fff;
  font-family: var(--font-ui);
  font-size: 12px;
  outline: none;
  transition: border-color .2s;
}
.sidebar-search input::placeholder { color: rgba(255,255,255,.35); }
.sidebar-search input:focus { border-color: var(--gold); }

.sidebar-ops {
  flex: 1;
  overflow-y: auto;
  padding: 8px 0 16px;
}

.op-category { margin-bottom: 4px; }
.op-cat-header {
  padding: 6px 16px 4px;
  font-size: 10px;
  font-weight: 600;
  letter-spacing: 1.5px;
  text-transform: uppercase;
  color: var(--gold);
  opacity: .8;
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 6px;
  user-select: none;
}
.op-cat-header:hover { opacity: 1; }
.cat-arrow { transition: transform .2s; font-size: 8px; }
.op-cat-header.collapsed .cat-arrow { transform: rotate(-90deg); }
.op-cat-items { overflow: hidden; }
.op-cat-items.hidden { display: none; }

.op-item {
  display: block;
  padding: 7px 20px 7px 28px;
  font-size: 12.5px;
  color: rgba(255,255,255,.7);
  cursor: pointer;
  border-left: 3px solid transparent;
  transition: all .15s;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  user-select: none;
}
.op-item:hover {
  background: rgba(255,255,255,.08);
  color: #fff;
  border-left-color: var(--gold);
}
.op-item.active {
  background: rgba(201,168,76,.12);
  color: var(--gold-light);
  border-left-color: var(--gold);
  font-weight: 500;
}

/* ── RECIPE PANEL ──────────────────────────────── */
.recipe-panel {
  width: 240px;
  min-width: 200px;
  background: rgba(240,237,227,.88);
  backdrop-filter: blur(10px);
  -webkit-backdrop-filter: blur(10px);
  border-right: 1px solid var(--cream-border);
  display: flex;
  flex-direction: column;
  overflow: hidden;
  flex-shrink: 0;
  transition: width .28s cubic-bezier(.4,0,.2,1);
}
.recipe-header {
  padding: 12px 16px;
  background: var(--cream-dark);
  border-bottom: 1px solid var(--cream-border);
  display: flex;
  align-items: center;
  justify-content: space-between;
}
.recipe-header-title {
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 1px;
  text-transform: uppercase;
  color: var(--navy);
}
.recipe-actions {
  display: flex;
  gap: 6px;
}
.recipe-btn {
  background: none;
  border: 1px solid var(--cream-border);
  border-radius: 4px;
  padding: 3px 8px;
  font-size: 10px;
  cursor: pointer;
  color: var(--text-muted);
  font-family: var(--font-ui);
  transition: all .15s;
}
.recipe-btn:hover { border-color: var(--gold); color: var(--gold-dark); }
.recipe-btn.run-btn {
  background: linear-gradient(135deg, var(--gold), var(--gold-light));
  border-color: var(--gold);
  color: var(--navy);
  font-weight: 600;
  box-shadow: 0 2px 6px rgba(201,168,76,.3);
}
.recipe-btn.run-btn:hover {
  background: linear-gradient(135deg, var(--gold-light), var(--gold));
  box-shadow: 0 3px 12px rgba(201,168,76,.45);
}

.recipe-list {
  flex: 1;
  overflow-y: auto;
  padding: 8px;
}
.recipe-empty {
  padding: 32px 16px;
  text-align: center;
  color: var(--text-muted);
  font-size: 12px;
  line-height: 1.7;
}
.recipe-empty .icon { font-size: 32px; margin-bottom: 8px; opacity: .4; }

.recipe-step {
  background: rgba(255,255,255,.75);
  backdrop-filter: blur(8px);
  -webkit-backdrop-filter: blur(8px);
  border: 1px solid rgba(201,168,76,.2);
  border-radius: 8px;
  margin-bottom: 6px;
  overflow: hidden;
  box-shadow: 0 2px 8px rgba(10,22,40,.08);
  transition: box-shadow .15s, transform .15s;
}
.recipe-step:hover { box-shadow: 0 4px 16px rgba(10,22,40,.13); transform: translateY(-1px); }
.recipe-step-header {
  display: flex;
  align-items: center;
  padding: 7px 10px;
  gap: 8px;
  cursor: pointer;
  user-select: none;
}
.step-num {
  width: 20px;
  height: 20px;
  background: var(--navy);
  color: var(--gold);
  border-radius: 50%;
  font-size: 10px;
  font-weight: 700;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}
.step-label {
  flex: 1;
  font-size: 11.5px;
  font-weight: 600;
  color: var(--navy);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.step-del {
  background: none;
  border: none;
  color: var(--text-muted);
  cursor: pointer;
  font-size: 14px;
  line-height: 1;
  padding: 2px 4px;
  border-radius: 3px;
  transition: all .15s;
}
.step-del:hover { color: var(--error); background: #fef0f0; }
.recipe-step-args {
  padding: 6px 10px 8px;
  border-top: 1px solid var(--cream-border);
  background: #fafaf6;
}
.recipe-step-args label { display: block; font-size: 10px; color: var(--text-muted); margin-bottom: 3px; font-weight: 500; }
.recipe-step-args input {
  width: 100%;
  border: 1px solid var(--cream-border);
  border-radius: 4px;
  padding: 5px 8px;
  font-size: 11px;
  background: #fff;
  font-family: var(--font-ui);
  outline: none;
  margin-bottom: 4px;
  transition: border-color .15s;
}
.recipe-step-args input:focus { border-color: var(--gold); }

/* ── MAIN AREA ─────────────────────────────────── */
.main-area {
  flex: 1;
  display: flex;
  flex-direction: column;
  overflow: hidden;
  min-width: 0;
}

.io-row {
  flex: 1;
  display: flex;
  min-height: 0;
  gap: 0;
}

.io-panel {
  flex: 1;
  display: flex;
  flex-direction: column;
  overflow: hidden;
}
.io-panel + .io-panel {
  border-left: 1px solid var(--cream-border);
}

.io-header {
  padding: 10px 16px;
  background: rgba(240,237,227,.9);
  backdrop-filter: blur(8px);
  -webkit-backdrop-filter: blur(8px);
  border-bottom: 1px solid var(--cream-border);
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
}
.io-label {
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 1px;
  text-transform: uppercase;
  color: var(--navy);
}
.io-stats {
  margin-left: auto;
  font-size: 10px;
  color: var(--text-muted);
}
.io-actions {
  display: flex;
  gap: 6px;
}
.io-btn {
  background: none;
  border: 1px solid var(--cream-border);
  border-radius: 4px;
  padding: 3px 9px;
  font-size: 10px;
  cursor: pointer;
  color: var(--text-muted);
  font-family: var(--font-ui);
  transition: all .15s;
}
.io-btn:hover { border-color: var(--gold); color: var(--gold-dark); }

.io-textarea {
  flex: 1;
  width: 100%;
  padding: 14px 16px;
  border: none;
  outline: none;
  resize: none;
  font-family: var(--font-mono);
  font-size: 13px;
  line-height: 1.6;
  background: #fff;
  color: var(--text);
  tab-size: 2;
}
.io-textarea::placeholder { color: var(--cream-border); font-family: var(--font-ui); font-style: italic; }
.io-textarea[readonly] { background: #fdfcf8; cursor: default; }

/* ── STATUS BAR ────────────────────────────────── */
.status-bar {
  display: flex;
  align-items: center;
  gap: 16px;
  padding: 6px 16px;
  background: rgba(10,22,40,.9);
  backdrop-filter: blur(10px);
  -webkit-backdrop-filter: blur(10px);
  font-size: 11px;
  color: rgba(255,255,255,.5);
  flex-shrink: 0;
  border-top: 1px solid rgba(201,168,76,.1);
  flex-wrap: wrap;
  row-gap: 4px;
}
.status-ok  { color: #6ee7a0; }
.status-err { color: #ff8a80; }
.status-spinner { animation: spin 1s linear infinite; display: inline-block; }
@keyframes spin { to { transform: rotate(360deg); } }
.status-sep { opacity: .2; }
.status-right { margin-left: auto; }

/* ── QUICK-RUN PANEL ───────────────────────────── */
.quick-run-panel {
  border-top: 1px solid rgba(201,168,76,.15);
  background: rgba(240,237,227,.85);
  backdrop-filter: blur(8px);
  -webkit-backdrop-filter: blur(8px);
  padding: 8px 16px;
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
  flex-shrink: 0;
  overflow-x: auto;
  scrollbar-width: none;
}
.quick-run-panel::-webkit-scrollbar { display: none; }
.quick-label {
  font-size: 11px;
  font-weight: 600;
  letter-spacing: .5px;
  color: var(--navy);
  white-space: nowrap;
}
.quick-btn {
  background: #fff;
  border: 1px solid var(--cream-border);
  border-radius: 5px;
  padding: 4px 12px;
  font-size: 11px;
  cursor: pointer;
  font-family: var(--font-ui);
  color: var(--text);
  transition: all .15s;
  white-space: nowrap;
}
.quick-btn:hover { background: var(--gold); border-color: var(--gold); color: var(--navy); font-weight: 500; }

/* ── SINGLE OP PANEL (inline args) ────────────── */
.op-config-bar {
  background: rgba(240,237,227,.9);
  backdrop-filter: blur(8px);
  -webkit-backdrop-filter: blur(8px);
  border-bottom: 1px solid rgba(201,168,76,.15);
  padding: 8px 16px;
  display: flex;
  align-items: center;
  gap: 12px;
  flex-wrap: wrap;
  flex-shrink: 0;
}
.op-config-bar label { font-size: 11px; color: var(--text-muted); font-weight: 500; }
.op-config-bar input, .op-config-bar select {
  border: 1px solid var(--cream-border);
  border-radius: 5px;
  padding: 5px 10px;
  font-size: 12px;
  background: #fff;
  font-family: var(--font-ui);
  outline: none;
  transition: border-color .15s;
}
.op-config-bar input:focus, .op-config-bar select:focus { border-color: var(--gold); }
.run-now-btn {
  background: linear-gradient(135deg, var(--gold) 0%, var(--gold-light) 100%);
  border: none;
  border-radius: 6px;
  padding: 6px 18px;
  font-family: var(--font-ui);
  font-size: 12px;
  font-weight: 600;
  color: var(--navy);
  cursor: pointer;
  transition: all .2s;
  margin-left: auto;
  box-shadow: 0 2px 8px rgba(201,168,76,.35);
}
.run-now-btn:hover {
  background: linear-gradient(135deg, var(--gold-light) 0%, var(--gold) 100%);
  box-shadow: 0 4px 16px rgba(201,168,76,.5);
  transform: translateY(-1px);
}
.add-to-recipe-btn {
  background: transparent;
  border: 1px solid var(--navy-light);
  border-radius: 6px;
  padding: 6px 14px;
  font-family: var(--font-ui);
  font-size: 12px;
  color: var(--navy);
  cursor: pointer;
  transition: all .15s;
}
.add-to-recipe-btn:hover { border-color: var(--gold); color: var(--gold-dark); }

/* ── MODAL ─────────────────────────────────────── */
.modal-overlay {
  position: fixed;
  inset: 0;
  background: rgba(10,22,40,.7);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 999;
  opacity: 0;
  pointer-events: none;
  transition: opacity .2s;
}
.modal-overlay.open { opacity: 1; pointer-events: all; }
.modal {
  background: rgba(250,248,242,.92);
  backdrop-filter: blur(24px) saturate(1.4);
  -webkit-backdrop-filter: blur(24px) saturate(1.4);
  border: 1px solid rgba(201,168,76,.25);
  border-radius: 14px;
  box-shadow: 0 20px 60px rgba(10,22,40,.3), 0 1px 0 rgba(255,255,255,.6) inset;
  padding: 28px 32px;
  max-width: 500px;
  width: 90%;
  transform: translateY(20px) scale(.97);
  transition: transform .25s cubic-bezier(.4,0,.2,1), opacity .2s;
}
.modal-overlay.open .modal { transform: translateY(0) scale(1); }

.modal h2 { font-family: var(--font-display); font-size: 24px; color: var(--navy); margin-bottom: 8px; }
.modal p { color: var(--text-muted); font-size: 13px; line-height: 1.6; margin-bottom: 16px; }
.modal-close { float: right; background: none; border: none; font-size: 22px; cursor: pointer; color: var(--text-muted); margin-top: -4px; }
.modal-close:hover { color: var(--navy); }
.modal textarea {
  width: 100%;
  height: 160px;
  border: 1px solid var(--cream-border);
  border-radius: 6px;
  padding: 10px;
  font-family: var(--font-mono);
  font-size: 12px;
  resize: vertical;
  outline: none;
  background: #fff;
}
.modal textarea:focus { border-color: var(--gold); }
.modal-footer { margin-top: 16px; display: flex; gap: 10px; justify-content: flex-end; }
.modal-btn {
  padding: 8px 20px;
  border-radius: 6px;
  font-family: var(--font-ui);
  font-size: 13px;
  cursor: pointer;
  border: none;
  font-weight: 500;
}
.modal-btn.primary { background: var(--gold); color: var(--navy); font-weight: 600; }
.modal-btn.secondary { background: var(--cream-dark); color: var(--text); border: 1px solid var(--cream-border); }
.modal-btn:hover { opacity: .9; }

/* ── TOAST ─────────────────────────────────────── */
#toast {
  position: fixed;
  bottom: 32px;
  right: 24px;
  background: var(--navy);
  color: #fff;
  padding: 10px 18px;
  border-radius: 8px;
  font-size: 13px;
  box-shadow: var(--shadow-lg);
  transform: translateY(20px);
  opacity: 0;
  transition: all .3s;
  z-index: 9999;
  border-left: 4px solid var(--gold);
}
#toast.show { transform: translateY(0); opacity: 1; }
#toast.err  { border-left-color: var(--error); }

/* ── RESPONSIVE ─────────────────────────────────── */

/* Tablet landscape (≤1100px): hide recipe panel in sidebar, show as drawer */
@media (max-width: 1100px) {
  .recipe-panel {
    position: fixed;
    right: 0; top: 58px; bottom: 0;
    z-index: 80;
    width: 260px;
    transform: translateX(100%);
    transition: transform .28s cubic-bezier(.4,0,.2,1);
    box-shadow: -4px 0 24px rgba(10,22,40,.2);
  }
  .recipe-panel.open { transform: translateX(0); }
  #recipeToggle { display: inline-flex !important; }
}

/* Tablet portrait (≤900px): collapse sidebar by default */
@media (max-width: 900px) {
  .sidebar { width: 0; min-width: 0; }
  .sidebar.open { width: 260px; min-width: 220px; position: fixed; left: 0; top: 58px; bottom: 0; z-index: 90; }
  .io-row { flex-direction: column; }
  .io-panel + .io-panel { border-left: none; border-top: 1px solid var(--cream-border); }
  .io-textarea { min-height: 180px; }
  .quick-run-panel { padding: 6px 12px; }
}

/* Mobile (≤640px): minimal chrome */
@media (max-width: 640px) {
  header { padding: 0 14px; gap: 10px; height: 52px; }
  .header-tagline { display: none; }
  .header-name { font-size: 18px; }
  .op-count-badge { display: none; }
  .io-textarea { font-size: 12px; padding: 10px 12px; min-height: 150px; }
  .op-config-bar { gap: 8px; padding: 6px 12px; }
  .run-now-btn { width: 100%; text-align: center; margin-left: 0; }
  .status-bar { font-size: 10px; gap: 8px; }
  .status-right { display: none; }
  .modal { padding: 20px 18px; }
  .quick-btn { font-size: 10px; padding: 3px 9px; }
}

/* Very small (≤360px) */
@media (max-width: 360px) {
  .header-logo svg { display: none; }
  .io-textarea { min-height: 120px; }
}

/* Overlay for mobile sidebar/recipe drawer */
.drawer-overlay {
  display: none;
  position: fixed;
  inset: 0;
  background: rgba(10,22,40,.45);
  z-index: 75;
  backdrop-filter: blur(2px);
  -webkit-backdrop-filter: blur(2px);
}
.drawer-overlay.show { display: block; }
</style>
</head>
<body>

<!-- ── HEADER ────────────────────────────────── -->
<header>
  <div class="header-logo">
    <svg width="32" height="32" viewBox="0 0 32 32" fill="none">
      <path d="M16 2L4 8v8c0 7.18 5.16 13.9 12 15.5C22.84 29.9 28 23.18 28 16V8L16 2z" fill="rgba(201,168,76,.15)" stroke="#C9A84C" stroke-width="1.5"/>
      <path d="M11 16l3 3 7-7" stroke="#C9A84C" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
      <circle cx="16" cy="11" r="2" fill="#C9A84C"/>
    </svg>
    <div class="header-brand">
      <span class="header-name">CipherForge</span>
      <span class="header-tagline">Cyber Swiss Army Knife</span>
    </div>
  </div>
  <div class="header-right">
    <span class="op-count-badge">50+ Ops</span>
    <button class="btn-icon" id="recipeToggle" style="display:none" onclick="toggleRecipe()">⚗️ Recipe</button>
    <button class="btn-icon" onclick="showAbout()">About</button>
    <button class="btn-icon" id="sidebarToggle" onclick="toggleSidebar()">☰ Ops</button>
  </div>
</header>

<!-- ── APP LAYOUT ────────────────────────────── -->
<div class="app-layout">

  <!-- SIDEBAR: Operation List -->
  <div class="sidebar" id="sidebar">
    <div class="sidebar-search">
      <input type="text" id="opSearch" placeholder="🔍  Search operations…" oninput="filterOps(this.value)">
    </div>
    <div class="sidebar-ops" id="opsList"></div>
  </div>

  <!-- RECIPE PANEL -->
  <div class="recipe-panel" id="recipePanel">
    <div class="recipe-header">
      <span class="recipe-header-title">⚗️ Recipe</span>
      <div class="recipe-actions">
        <button class="recipe-btn" onclick="clearRecipe()">Clear</button>
        <button class="recipe-btn" onclick="saveRecipe()">Save</button>
        <button class="recipe-btn run-btn" onclick="bakeRecipe()">▶ Bake</button>
      </div>
    </div>
    <div class="recipe-list" id="recipeList">
      <div class="recipe-empty">
        <div class="icon">⚗️</div>
        Click an operation to add it here.<br>Chain multiple steps — output of each feeds next.
      </div>
    </div>
  </div>

  <!-- MAIN: I/O -->
  <div class="main-area">

    <!-- Op Config Bar (shown when op selected) -->
    <div class="op-config-bar" id="opConfigBar" style="display:none">
      <span id="opConfigTitle" style="font-weight:600;color:var(--navy);font-size:13px;"></span>
      <span class="status-sep">|</span>
      <span id="argFields"></span>
      <button class="add-to-recipe-btn" onclick="addCurrentToRecipe()">+ Recipe</button>
      <button class="run-now-btn" onclick="runSingle()">▶ Run</button>
    </div>

    <!-- Quick Run Bar -->
    <div class="quick-run-panel">
      <span class="quick-label">Quick Run:</span>
      <button class="quick-btn" onclick="quickRun('base64_enc')">Base64 Enc</button>
      <button class="quick-btn" onclick="quickRun('base64_dec')">Base64 Dec</button>
      <button class="quick-btn" onclick="quickRun('url_enc')">URL Enc</button>
      <button class="quick-btn" onclick="quickRun('url_dec')">URL Dec</button>
      <button class="quick-btn" onclick="quickRun('md5')">MD5</button>
      <button class="quick-btn" onclick="quickRun('sha256')">SHA-256</button>
      <button class="quick-btn" onclick="quickRun('json_pretty')">JSON ↔ Pretty</button>
      <button class="quick-btn" onclick="quickRun('rot13')">ROT13</button>
      <button class="quick-btn" onclick="quickRun('hex_enc')">→ Hex</button>
      <button class="quick-btn" onclick="quickRun('hex_dec')">Hex →</button>
      <button class="quick-btn" onclick="quickRun('hash_all')">All Hashes</button>
      <button class="quick-btn" onclick="quickRun('entropy')">Entropy</button>
    </div>

    <!-- I/O Panels -->
    <div class="io-row">
      <div class="io-panel">
        <div class="io-header">
          <span class="io-label">📥 Input</span>
          <div class="io-actions">
            <button class="io-btn" onclick="pasteInput()">Paste</button>
            <button class="io-btn" onclick="clearInput()">Clear</button>
            <button class="io-btn" onclick="loadFile()">File</button>
          </div>
          <span class="io-stats" id="inputStats">0 chars</span>
        </div>
        <textarea class="io-textarea" id="inputArea"
          placeholder="Paste or type your input here…&#10;&#10;Then click an operation on the left, or use Quick Run above."
          oninput="updateInputStats()"></textarea>
      </div>
      <div class="io-panel">
        <div class="io-header">
          <span class="io-label">📤 Output</span>
          <div class="io-actions">
            <button class="io-btn" onclick="copyOutput()">Copy</button>
            <button class="io-btn" onclick="outputToInput()">→ Input</button>
            <button class="io-btn" onclick="downloadOutput()">Download</button>
          </div>
          <span class="io-stats" id="outputStats">0 chars</span>
        </div>
        <textarea class="io-textarea" id="outputArea" readonly
          placeholder="Output will appear here…"></textarea>
      </div>
    </div>

    <!-- Status Bar -->
    <div class="status-bar">
      <span id="statusMsg" class="status-ok">Ready</span>
      <span class="status-sep">|</span>
      <span id="statusOp">No operation selected</span>
      <span class="status-sep">|</span>
      <span id="statusRecipe">Recipe: 0 steps</span>
      <span class="status-right">CipherForge v1.0 · PHP <?= PHP_MAJOR_VERSION ?>.<?= PHP_MINOR_VERSION ?></span>
    </div>
  </div>
</div>

<!-- ── SAVE RECIPE MODAL ──────────────────────── -->
<div class="modal-overlay" id="saveModal">
  <div class="modal">
    <button class="modal-close" onclick="closeModal('saveModal')">×</button>
    <h2>Save Recipe</h2>
    <p>Export your current recipe as JSON. Paste it back later to restore.</p>
    <textarea id="saveOutput" readonly></textarea>
    <div class="modal-footer">
      <button class="modal-btn secondary" onclick="closeModal('saveModal')">Close</button>
      <button class="modal-btn primary" onclick="copySavedRecipe()">Copy JSON</button>
    </div>
  </div>
</div>

<!-- ── ABOUT MODAL ────────────────────────────── -->
<div class="modal-overlay" id="aboutModal">
  <div class="modal">
    <button class="modal-close" onclick="closeModal('aboutModal')">×</button>
    <h2>CipherForge</h2>
    <p>
      <strong>Cyber Swiss Army Knife</strong> — a single-file PHP tool for encoding, hashing, encryption, text processing and data forensics.<br><br>
      <strong>50+ operations</strong> across 7 categories:<br>
      Encoding · Hashing · Symmetric Crypto · Classic Ciphers · Text/Format · Data Format · Compression · Misc<br><br>
      <strong>Recipe mode:</strong> chain operations — output of each step feeds the next.<br>
      <strong>Quick Run:</strong> one-click common operations.<br><br>
      Built with love by <strong>Vineet Pratap Singh</strong> · <a href="https://psv.im" target="_blank" style="color:var(--gold)">psv.im</a>
    </p>
    <div class="modal-footer">
      <button class="modal-btn primary" onclick="closeModal('aboutModal')">Got it</button>
    </div>
  </div>
</div>

<!-- ── HIDDEN FILE INPUT ──────────────────────── -->
<input type="file" id="fileInput" style="display:none" onchange="readFile(this)">

<!-- ── TOAST ──────────────────────────────────── -->
<div id="toast"></div>
<div class="drawer-overlay" id="drawerOverlay" onclick="closeAllDrawers()"></div>

<script>
// ═══════════════════════════════════════════════
//  OPERATIONS REGISTRY
// ═══════════════════════════════════════════════
const OPS = {
  'Encoding': [
    { id:'base64_enc',   label:'Base64 Encode' },
    { id:'base64_dec',   label:'Base64 Decode' },
    { id:'base32_enc',   label:'Base32 Encode' },
    { id:'base32_dec',   label:'Base32 Decode' },
    { id:'base58_enc',   label:'Base58 Encode' },
    { id:'base58_dec',   label:'Base58 Decode' },
    { id:'hex_enc',      label:'To Hex' },
    { id:'hex_dec',      label:'From Hex' },
    { id:'url_enc',      label:'URL Encode' },
    { id:'url_dec',      label:'URL Decode' },
    { id:'url_enc_full', label:'URL Encode (Full)' },
    { id:'url_dec_full', label:'URL Decode (Full)' },
    { id:'html_enc',     label:'HTML Encode (Special)' },
    { id:'html_dec',     label:'HTML Decode' },
    { id:'html_ent_enc', label:'HTML Entities Encode' },
    { id:'html_ent_dec', label:'HTML Entities Decode' },
    { id:'binary_enc',   label:'To Binary' },
    { id:'binary_dec',   label:'From Binary' },
    { id:'octal_enc',    label:'To Octal' },
    { id:'octal_dec',    label:'From Octal' },
    { id:'morse_enc',    label:'To Morse Code' },
    { id:'morse_dec',    label:'From Morse Code' },
    { id:'rot13',        label:'ROT13' },
    { id:'rot47',        label:'ROT47' },
    { id:'ascii85_enc',  label:'ASCII85 Encode' },
    { id:'ascii85_dec',  label:'ASCII85 Decode' },
  ],
  'Hashing': [
    { id:'md5',         label:'MD5' },
    { id:'sha1',        label:'SHA-1' },
    { id:'sha256',      label:'SHA-256' },
    { id:'sha512',      label:'SHA-512' },
    { id:'sha3_256',    label:'SHA3-256' },
    { id:'sha3_512',    label:'SHA3-512' },
    { id:'crc32',       label:'CRC32' },
    { id:'ripemd160',   label:'RIPEMD-160' },
    { id:'whirlpool',   label:'Whirlpool' },
    { id:'hmac_sha256', label:'HMAC-SHA256', args:[{n:'Key',k:'arg1'}] },
    { id:'hmac_sha512', label:'HMAC-SHA512', args:[{n:'Key',k:'arg1'}] },
    { id:'hash_all',    label:'Hash All (Multi)' },
  ],
  'Symmetric Crypto': [
    { id:'aes256_enc',   label:'AES-256-CBC Encrypt', args:[{n:'Key (any length)',k:'arg1'}] },
    { id:'aes256_dec',   label:'AES-256-CBC Decrypt', args:[{n:'Key',k:'arg1'}] },
    { id:'aes128_enc',   label:'AES-128-CBC Encrypt', args:[{n:'Key',k:'arg1'}] },
    { id:'aes128_dec',   label:'AES-128-CBC Decrypt', args:[{n:'Key',k:'arg1'}] },
    { id:'aes_gcm_enc',  label:'AES-256-GCM Encrypt', args:[{n:'Key',k:'arg1'}] },
    { id:'aes_gcm_dec',  label:'AES-256-GCM Decrypt', args:[{n:'Key',k:'arg1'}] },
    { id:'des_enc',      label:'DES Encrypt',          args:[{n:'Key (8 chars)',k:'arg1'}] },
    { id:'des_dec',      label:'DES Decrypt',          args:[{n:'Key',k:'arg1'}] },
    { id:'blowfish_enc', label:'Blowfish Encrypt',     args:[{n:'Key',k:'arg1'}] },
    { id:'blowfish_dec', label:'Blowfish Decrypt',     args:[{n:'Key',k:'arg1'}] },
    { id:'rc4_enc',      label:'RC4 Encrypt',          args:[{n:'Key',k:'arg1'}] },
    { id:'rc4_dec',      label:'RC4 Decrypt',          args:[{n:'Key',k:'arg1'}] },
    { id:'xor_key',      label:'XOR with Key',         args:[{n:'Key',k:'arg1'}] },
  ],
  'Classic Ciphers': [
    { id:'caesar_enc',   label:'Caesar Encrypt',   args:[{n:'Shift (0-25)',k:'arg1',def:'13'}] },
    { id:'caesar_dec',   label:'Caesar Decrypt',   args:[{n:'Shift',k:'arg1',def:'13'}] },
    { id:'vigenere_enc', label:'Vigenère Encrypt', args:[{n:'Key (letters)',k:'arg1'}] },
    { id:'vigenere_dec', label:'Vigenère Decrypt', args:[{n:'Key',k:'arg1'}] },
    { id:'beaufort_enc', label:'Beaufort Cipher',  args:[{n:'Key (letters)',k:'arg1'}] },
  ],
  'Text & Format': [
    { id:'to_upper',     label:'To Uppercase' },
    { id:'to_lower',     label:'To Lowercase' },
    { id:'to_title',     label:'To Title Case' },
    { id:'trim',         label:'Trim Whitespace' },
    { id:'reverse',      label:'Reverse String' },
    { id:'word_count',   label:'Word Count' },
    { id:'char_count',   label:'Character Count' },
    { id:'byte_count',   label:'Byte Count' },
    { id:'line_count',   label:'Line Count' },
    { id:'line_sort',    label:'Sort Lines (A→Z)' },
    { id:'line_sort_rev',label:'Sort Lines (Z→A)' },
    { id:'line_dedupe',  label:'Deduplicate Lines' },
    { id:'line_reverse', label:'Reverse Lines' },
    { id:'add_line_nums',label:'Add Line Numbers' },
    { id:'pad_left',     label:'Pad Left',     args:[{n:'Length',k:'arg1',def:'10'},{n:'Char',k:'arg2',def:'0'}] },
    { id:'pad_right',    label:'Pad Right',    args:[{n:'Length',k:'arg1',def:'10'},{n:'Char',k:'arg2',def:' '}] },
    { id:'split',        label:'Split',        args:[{n:'Delimiter',k:'arg1',def:','}] },
    { id:'join',         label:'Join Lines',   args:[{n:'Delimiter',k:'arg1',def:','}] },
    { id:'repeat',       label:'Repeat',       args:[{n:'Times',k:'arg1',def:'2'}] },
    { id:'regex_extract',label:'Regex Extract',args:[{n:'Pattern',k:'arg1'}] },
    { id:'regex_replace',label:'Regex Replace',args:[{n:'Pattern',k:'arg1'},{n:'Replacement',k:'arg2'}] },
    { id:'strip_html',   label:'Strip HTML Tags' },
    { id:'defang_url',   label:'Defang URL/IP' },
    { id:'refang_url',   label:'Refang URL/IP' },
    { id:'string_diff',  label:'String Diff',  args:[{n:'Compare with (text B)',k:'arg1'}] },
    { id:'freq_analysis',label:'Frequency Analysis' },
    { id:'is_palindrome',label:'Palindrome Check' },
    { id:'count_vowels', label:'Count Vowels' },
  ],
  'Data Format': [
    { id:'json_pretty',  label:'JSON Prettify' },
    { id:'json_minify',  label:'JSON Minify' },
    { id:'json_to_csv',  label:'JSON → CSV' },
    { id:'csv_to_json',  label:'CSV → JSON' },
    { id:'xml_pretty',   label:'XML Prettify' },
    { id:'hex_to_ip',    label:'Hex → IP Address' },
    { id:'ip_to_hex',    label:'IP → Hex' },
    { id:'dec_to_bin',   label:'Decimal → Binary' },
    { id:'bin_to_dec',   label:'Binary → Decimal' },
    { id:'dec_to_hex',   label:'Decimal → Hex' },
    { id:'hex_to_dec',   label:'Hex → Decimal' },
    { id:'dec_to_oct',   label:'Decimal → Octal' },
    { id:'oct_to_dec',   label:'Octal → Decimal' },
    { id:'unix_to_human',label:'Unix Timestamp → Date' },
    { id:'human_to_unix',label:'Date → Unix Timestamp' },
    { id:'char_to_ascii',label:'Chars → ASCII Codes' },
    { id:'ascii_to_char',label:'ASCII Codes → Chars' },
    { id:'int_to_roman', label:'Integer → Roman Numeral' },
    { id:'roman_to_int', label:'Roman Numeral → Integer' },
  ],
  'Compression': [
    { id:'gzip_enc', label:'GZip Compress (→Base64)' },
    { id:'gzip_dec', label:'GZip Decompress (Base64→)' },
    { id:'zlib_enc', label:'Zlib Compress (→Base64)' },
    { id:'zlib_dec', label:'Zlib Decompress (Base64→)' },
  ],
  'Misc & Utils': [
    { id:'entropy',      label:'Shannon Entropy' },
    { id:'hash_all',     label:'Hash All Algorithms' },
    { id:'uuid_gen',     label:'Generate UUID v4' },
    { id:'uuid_detect',  label:'UUID Version Detect' },
    { id:'password_gen', label:'Password Generator', args:[{n:'Length',k:'arg1',def:'16'},{n:'Uppercase (1/0)',k:'arg2',def:'1'},{n:'Symbols (1/0)',k:'arg3',def:'1'}] },
    { id:'jwt_decode',   label:'JWT Decode (no verify)' },
    { id:'lorem_ipsum',  label:'Lorem Ipsum', args:[{n:'Words',k:'arg1',def:'50'}] },
  ],
};

// ═══════════════════════════════════════════════
//  STATE
// ═══════════════════════════════════════════════
let currentOp = null;
let recipe    = [];

// ═══════════════════════════════════════════════
//  BUILD SIDEBAR
// ═══════════════════════════════════════════════
function buildSidebar(filter='') {
  const container = document.getElementById('opsList');
  container.innerHTML = '';
  const q = filter.toLowerCase();

  for (const [cat, ops] of Object.entries(OPS)) {
    const filtered = q ? ops.filter(o => o.label.toLowerCase().includes(q) || o.id.includes(q)) : ops;
    if (!filtered.length) continue;

    const catDiv = document.createElement('div');
    catDiv.className = 'op-category';

    const header = document.createElement('div');
    header.className = 'op-cat-header';
    header.innerHTML = `<span class="cat-arrow">▾</span> ${cat} <small style="opacity:.5;font-weight:300">(${filtered.length})</small>`;
    header.onclick = () => {
      const items = catDiv.querySelector('.op-cat-items');
      header.classList.toggle('collapsed');
      items.classList.toggle('hidden');
    };
    catDiv.appendChild(header);

    const items = document.createElement('div');
    items.className = 'op-cat-items';
    filtered.forEach(op => {
      const el = document.createElement('div');
      el.className = 'op-item' + (currentOp && currentOp.id === op.id ? ' active' : '');
      el.textContent = op.label;
      el.title = op.id;
      el.onclick = () => selectOp(op);
      items.appendChild(el);
    });
    catDiv.appendChild(items);
    container.appendChild(catDiv);
  }
}

function filterOps(v) { buildSidebar(v); }

// ═══════════════════════════════════════════════
//  SELECT OPERATION
// ═══════════════════════════════════════════════
function selectOp(op) {
  currentOp = op;
  buildSidebar(document.getElementById('opSearch').value);

  const bar = document.getElementById('opConfigBar');
  const title = document.getElementById('opConfigTitle');
  const argFields = document.getElementById('argFields');

  title.textContent = op.label;
  argFields.innerHTML = '';

  if (op.args) {
    op.args.forEach(a => {
      const lbl = document.createElement('label');
      lbl.textContent = a.n + ':';
      const inp = document.createElement('input');
      inp.type = 'text';
      inp.id = 'cf_' + a.k;
      inp.placeholder = a.n;
      if (a.def) inp.value = a.def;
      inp.style.minWidth = '130px';
      inp.addEventListener('keydown', e => { if (e.key === 'Enter') runSingle(); });
      argFields.appendChild(lbl);
      argFields.appendChild(inp);
    });
  }

  bar.style.display = 'flex';
  document.getElementById('statusOp').textContent = 'Selected: ' + op.label;
}

function getArgVal(k) {
  const el = document.getElementById('cf_' + k);
  return el ? el.value : '';
}

// ═══════════════════════════════════════════════
//  SINGLE RUN
// ═══════════════════════════════════════════════
async function runSingle() {
  if (!currentOp) { toast('Select an operation first', true); return; }
  const input = document.getElementById('inputArea').value;
  await runOp(currentOp, input, true);
}

async function quickRun(opId) {
  // Find op
  let op = null;
  for (const ops of Object.values(OPS))
    for (const o of ops) if (o.id === opId) { op = o; break; }
  if (!op) return;
  selectOp(op);
  await runSingle();
}

async function runOp(op, input, updateOutput=true) {
  setStatus('⟳ Running…', false, true);
  const body = new FormData();
  body.append('action', 'process');
  body.append('input', input);
  body.append('op', op.id);
  body.append('arg1', getArgVal('arg1'));
  body.append('arg2', getArgVal('arg2'));
  body.append('arg3', getArgVal('arg3'));

  try {
    const resp = await fetch('', { method:'POST', body });
    const json = await resp.json();
    if (json.ok) {
      if (updateOutput) {
        document.getElementById('outputArea').value = json.result;
        updateOutputStats();
      }
      setStatus('✓ Done — ' + op.label, true);
      return json.result;
    } else {
      if (updateOutput) document.getElementById('outputArea').value = '⚠️ Error: ' + json.error;
      setStatus('✗ ' + json.error, false);
      return null;
    }
  } catch(e) {
    if (updateOutput) document.getElementById('outputArea').value = '⚠️ Network error: ' + e.message;
    setStatus('✗ Network error', false);
    return null;
  }
}

// ═══════════════════════════════════════════════
//  RECIPE
// ═══════════════════════════════════════════════
function addCurrentToRecipe() {
  if (!currentOp) { toast('Select an operation first', true); return; }
  const args = {};
  if (currentOp.args) {
    currentOp.args.forEach(a => { args[a.k] = getArgVal(a.k); });
  }
  recipe.push({ op: {...currentOp}, args });
  renderRecipe();
  toast('Added: ' + currentOp.label);
}

function renderRecipe() {
  const list = document.getElementById('recipeList');
  document.getElementById('statusRecipe').textContent = 'Recipe: ' + recipe.length + ' step' + (recipe.length!==1?'s':'');
  if (!recipe.length) {
    list.innerHTML = '<div class="recipe-empty"><div class="icon">⚗️</div>Click an operation to add it here.<br>Chain multiple steps — output of each feeds next.</div>';
    return;
  }
  list.innerHTML = '';
  recipe.forEach((step, i) => {
    const div = document.createElement('div');
    div.className = 'recipe-step';
    div.innerHTML = `
      <div class="recipe-step-header">
        <span class="step-num">${i+1}</span>
        <span class="step-label">${step.op.label}</span>
        <button class="step-del" onclick="removeStep(${i})">×</button>
      </div>
    `;
    if (step.op.args) {
      const argsDiv = document.createElement('div');
      argsDiv.className = 'recipe-step-args';
      step.op.args.forEach(a => {
        argsDiv.innerHTML += `<label>${a.n}</label>`;
        const inp = document.createElement('input');
        inp.type = 'text';
        inp.value = step.args[a.k] || '';
        inp.placeholder = a.n;
        inp.oninput = e => { step.args[a.k] = e.target.value; };
        argsDiv.appendChild(inp);
      });
      div.appendChild(argsDiv);
    }
    list.appendChild(div);
  });
}

function removeStep(i) {
  recipe.splice(i, 1);
  renderRecipe();
}

function clearRecipe() {
  recipe = [];
  renderRecipe();
  toast('Recipe cleared');
}

async function bakeRecipe() {
  if (!recipe.length) { toast('Recipe is empty', true); return; }
  let val = document.getElementById('inputArea').value;
  setStatus('⟳ Baking recipe…', false, true);
  for (let i = 0; i < recipe.length; i++) {
    const step = recipe[i];
    const body = new FormData();
    body.append('action','process');
    body.append('input', val);
    body.append('op', step.op.id);
    body.append('arg1', step.args.arg1 || '');
    body.append('arg2', step.args.arg2 || '');
    body.append('arg3', step.args.arg3 || '');
    try {
      const resp = await fetch('', { method:'POST', body });
      const json = await resp.json();
      if (json.ok) { val = json.result; }
      else {
        setStatus('✗ Step ' + (i+1) + ' failed: ' + json.error, false);
        document.getElementById('outputArea').value = '⚠️ Step ' + (i+1) + ' (' + step.op.label + ') failed:\n' + json.error;
        updateOutputStats();
        return;
      }
    } catch(e) {
      setStatus('✗ Network error at step ' + (i+1), false);
      return;
    }
  }
  document.getElementById('outputArea').value = val;
  updateOutputStats();
  setStatus('✓ Recipe baked — ' + recipe.length + ' step' + (recipe.length!==1?'s':''), true);
}

function saveRecipe() {
  if (!recipe.length) { toast('Recipe is empty', true); return; }
  document.getElementById('saveOutput').value = JSON.stringify(recipe, null, 2);
  openModal('saveModal');
}
function copySavedRecipe() {
  navigator.clipboard.writeText(document.getElementById('saveOutput').value);
  toast('Recipe JSON copied!');
}

// ═══════════════════════════════════════════════
//  IO HELPERS
// ═══════════════════════════════════════════════
function updateInputStats() {
  const v = document.getElementById('inputArea').value;
  document.getElementById('inputStats').textContent =
    v.length + ' chars · ' + new Blob([v]).size + ' bytes';
}
function updateOutputStats() {
  const v = document.getElementById('outputArea').value;
  document.getElementById('outputStats').textContent =
    v.length + ' chars · ' + new Blob([v]).size + ' bytes';
}
async function pasteInput() {
  try {
    const t = await navigator.clipboard.readText();
    document.getElementById('inputArea').value = t;
    updateInputStats();
    toast('Pasted!');
  } catch(e) { toast('Clipboard access denied', true); }
}
function clearInput() {
  document.getElementById('inputArea').value = '';
  updateInputStats();
}
function copyOutput() {
  const v = document.getElementById('outputArea').value;
  if (!v) { toast('Nothing to copy', true); return; }
  navigator.clipboard.writeText(v);
  toast('Copied!');
}
function outputToInput() {
  const v = document.getElementById('outputArea').value;
  if (!v) { toast('Output is empty', true); return; }
  document.getElementById('inputArea').value = v;
  document.getElementById('outputArea').value = '';
  updateInputStats();
  updateOutputStats();
  toast('Output → Input');
}
function downloadOutput() {
  const v = document.getElementById('outputArea').value;
  if (!v) { toast('Nothing to download', true); return; }
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([v], {type:'text/plain'}));
  a.download = 'cipherforge_output.txt';
  a.click();
  toast('Downloading…');
}
function loadFile() { document.getElementById('fileInput').click(); }
function readFile(input) {
  if (!input.files[0]) return;
  const r = new FileReader();
  r.onload = e => {
    document.getElementById('inputArea').value = e.target.result;
    updateInputStats();
    toast('File loaded: ' + input.files[0].name);
  };
  r.readAsText(input.files[0]);
}

// ═══════════════════════════════════════════════
//  STATUS / TOAST
// ═══════════════════════════════════════════════
function setStatus(msg, ok, spinner=false) {
  const el = document.getElementById('statusMsg');
  el.className = ok ? 'status-ok' : 'status-err';
  el.innerHTML = spinner ? '<span class="status-spinner">⟳</span> ' + msg : msg;
}
let toastTimer;
function toast(msg, err=false) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'show' + (err ? ' err' : '');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.className = '', 2500);
}

// ═══════════════════════════════════════════════
//  MODALS
// ═══════════════════════════════════════════════
function openModal(id)  { document.getElementById(id).classList.add('open'); }
function closeModal(id) { document.getElementById(id).classList.remove('open'); }
function showAbout()    { openModal('aboutModal'); }
document.querySelectorAll('.modal-overlay').forEach(m =>
  m.addEventListener('click', e => { if (e.target === m) closeModal(m.id); }));

// ═══════════════════════════════════════════════
//  SIDEBAR TOGGLE
// ═══════════════════════════════════════════════
function toggleSidebar() {
  const sb = document.getElementById('sidebar');
  const ov = document.getElementById('drawerOverlay');
  if (window.innerWidth <= 900) {
    sb.classList.toggle('open');
    ov.classList.toggle('show', sb.classList.contains('open'));
  } else {
    sb.classList.toggle('collapsed');
  }
}
function toggleRecipe() {
  const rp = document.getElementById('recipePanel');
  const ov = document.getElementById('drawerOverlay');
  rp.classList.toggle('open');
  ov.classList.toggle('show', rp.classList.contains('open'));
}
function closeAllDrawers() {
  document.getElementById('sidebar').classList.remove('open');
  document.getElementById('recipePanel').classList.remove('open');
  document.getElementById('drawerOverlay').classList.remove('show');
}

// ═══════════════════════════════════════════════
//  KEYBOARD SHORTCUTS
// ═══════════════════════════════════════════════
document.addEventListener('keydown', e => {
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); runSingle(); }
  if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key === 'Enter') { e.preventDefault(); bakeRecipe(); }
  if (e.key === 'Escape') {
    document.querySelectorAll('.modal-overlay.open').forEach(m => closeModal(m.id));
  }
});

// ═══════════════════════════════════════════════
//  INIT
// ═══════════════════════════════════════════════
buildSidebar();
updateInputStats();
updateOutputStats();
</script>
</body>
</html>
