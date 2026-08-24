import json,struct,random,base64,time
xxtea_delta = 0x9E3779B9
std_base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
perms_b64 = "Dkdpgh4ZKsQB80/Mfvw36XI1R25+WUAlEi7NLboqYTOPuzmFjJnryx9HVGcaStCe"

template = {
    "navigator": {
        "appCodeName": "Mozilla", "appName": "Netscape", "platform": "Win32",
        "product": "Gecko", "productSub": "20030107",
        "hardwareConcurrency": 16, "cpuClass": False, "maxTouchPoints": 0,
        "oscpu": False, "vendor": "Google Inc.", "vendorSub": "",
        "doNotTrack": False, "vibrate": True, "credentials": True,
        "storage": True, "requestMediaKeySystemAccess": True, "bluetooth": True,
    },
    "window": {
        "Image": True, "innerHeight": 720, "innerWidth": 1280,
        "screenX": 10, "screenY": 10, "isSecureContext": True,
        "devicePixelRatio": 1.0000000149011612, "toolbar": True,
        "locationbar": True, "ActiveXObject": False, "external": True,
        "mozRTCPeerConnection": False, "postMessage": True,
        "webkitRequestAnimationFrame": True, "BluetoothUUID": True,
        "netscape": False,
    },
    "document": {
        "characterSet": "UTF-8", "compatMode": "CSS1Compat",
        "documentMode": False, "layers": False, "images": True,
        "location": "www.tiktok.com",
    },
    "webgl": {
        "supportedExtensions": [
            "ANGLE_instanced_arrays", "EXT_blend_minmax", "EXT_clip_control",
            "EXT_color_buffer_half_float", "EXT_depth_clamp",
            "EXT_disjoint_timer_query", "EXT_float_blend", "EXT_frag_depth",
            "EXT_polygon_offset_clamp", "EXT_shader_texture_lod",
            "EXT_texture_compression_bptc", "EXT_texture_compression_rgtc",
            "EXT_texture_filter_anisotropic",
            "EXT_texture_mirror_clamp_to_edge", "EXT_sRGB",
            "KHR_parallel_shader_compile", "OES_element_index_uint",
            "OES_fbo_render_mipmap", "OES_standard_derivatives",
            "OES_texture_float", "OES_texture_float_linear",
            "OES_texture_half_float", "OES_texture_half_float_linear",
            "OES_vertex_array_object", "WEBGL_blend_func_extended",
            "WEBGL_color_buffer_float", "WEBGL_compressed_texture_s3tc",
            "WEBGL_compressed_texture_s3tc_srgb", "WEBGL_debug_renderer_info",
            "WEBGL_debug_shaders", "WEBGL_depth_texture", "WEBGL_draw_buffers",
        ],
        "antialias": True, "blueBits": 8, "depthBits": 24, "greenBits": 8,
        "maxAnisotropy": 16, "maxCombinedTextureImageUnits": 32,
        "maxCubeMapTextureSize": 16384, "maxFragmentUniformVectors": 1024,
        "maxRenderbufferSize": 16384, "maxTextureImageUnits": 16,
        "maxTextureSize": 16384, "maxVaryingVectors": 30,
        "maxVertexAttribs": 16, "maxVertexTextureImageUnits": 16,
        "maxVertexUniformVectors": 4096, "maxViewportDims": [32767, 32767],
        "redBits": 8, "renderer": "WebKit WebGL", "vendor": "WebKit",
        "version": "WebGL 1.0 (OpenGL ES 2.0 Chromium)",
    },
    "gpu": "Google Inc. (AMD)/ANGLE (AMD, AMD Radeon(TM) Graphics (0x0000164E) "
           "Direct3D11 vs_5_0 ps_5_0, D3D11)",
    "plugins": "PDF Viewerinternal-pdf-viewerapplication/pdftext/pdf##"
               "Chrome PDF Viewerinternal-pdf-viewerapplication/pdftext/pdf",
}

def _w(v):
    return v & 0xFFFFFFFF

def _mx(e, y, z, p, u, key):
    return _w(((((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^
               ((e ^ y) + (key[(p & 3) ^ u] ^ z))))

def xxtea_encrypt(t, key):
    a = len(t)
    if a < 2:
        return t
    v = a - 1
    o = t[v]; e = 0
    for _ in range(6 + 52 // a):
        e = _w(e + xxtea_delta); u = (e >> 2) & 3
        for c in range(v):
            i = t[c + 1]
            o = t[c] = _w(t[c] + _mx(e, i, o, c, u, key))
        i = t[0]
        o = t[v] = _w(t[v] + _mx(e, i, o, v, u, key))
    return t

def xxtea_decrypt(t, key):
    a = len(t)
    if a < 2:
        return t
    v = a - 1
    q = 6 + 52 // a
    e = _w(q * xxtea_delta); y = t[0]
    for _ in range(q):
        u = (e >> 2) & 3
        for p in range(v, 0, -1):
            z = t[p - 1]
            t[p] = _w(t[p] - _mx(e, y, z, p, u, key)); y = t[p]
        z = t[v]
        t[0] = _w(t[0] - _mx(e, y, z, 0, u, key)); y = t[0]
        e = _w(e - xxtea_delta)
    return t


def _to_words(data, include_len):
    n = len(data)
    pad = data + b'\x00' * ((4 - len(data) % 4) % 4)
    w = list(struct.unpack('<%dI' % (len(pad) // 4), pad))
    if include_len:
        w.append(n)
    return w


def _words_to_bytes(words):
    return b''.join(struct.pack('<I', w) for w in words)


def _b64(data, permuted=False):
    s = base64.b64encode(data).decode()
    if permuted:
        s = s.translate(str.maketrans(std_base64, perms_b64))
    return s


def get_X_Mssdk_Info(fingerprint=None, seed=None, permuted_b64=False,
                     seed_prefix=True, rng=None, user_agent=None, *args, **kwargs):
    rng = rng or random.Random()
    fp = json.loads(json.dumps(template))
    if user_agent:
        if "Macintosh" in user_agent:
            fp["navigator"]["platform"] = "MacIntel"
        elif "Windows" in user_agent:
            fp["navigator"]["platform"] = "Win32"
        elif "Linux" in user_agent:
            fp["navigator"]["platform"] = "Linux x86_64"
    if fingerprint:
        for k, v in fingerprint.items():
            if isinstance(v, dict) and k in fp:
                fp[k].update(v)
            else:
                fp[k] = v
    fp["timestamp"] = int(time.time() * 1000)

    payload = json.dumps(fp, separators=(",", ":")).encode()

    if seed is None:
        seed = bytes(rng.randint(65, 122) for _ in range(4))
    elif isinstance(seed, str):
        seed = seed.encode()
    key = _to_words(seed, False)
    while len(key) < 4:
        key.append(0)

    pt = _to_words(payload, True)
    enc = xxtea_encrypt(list(pt), key)
    enc_bytes = _words_to_bytes(enc)

    if seed_prefix:
        return seed.decode('latin1') + _b64(enc_bytes, permuted_b64)
    return _b64(enc_bytes, permuted_b64)


get_x_mssdk_info = get_X_Mssdk_Info

if __name__ == "__main__":
    tok = get_X_Mssdk_Info()
    print("X-Mssdk-Info:", tok[:], "")
