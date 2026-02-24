(function() {
  const PACK = {"cipher":"tYU54mZXZBIS2qT2/ezu","offset":"6cvDmZSQOcVT/HbZOf4Z","pad":"sI8hKN0BKU2eo3ywPIIx","perm":"nylFASR/eTl7+6lSpuCtkK8moKDriKh3ykLPq48I/1Kejh63fcN6IDGHTGLMRU7mp9iEp/7baza2/Cu1ZAquLFpvvcKrjm8pFcjBiQU/Hpe58z39shncCXiwYrt3Rsluac2LA221XQxcivFFXyKuP4b4simE3mdEqLUTzCdvn3fWfsnZ34WFr8iaQ2F630DrkHmGpYnILWLeK7hKMr033p792mAzfqqZDOzePfEMRymncBI9/m3vxPbHu4LZUr+Iqf0nD75N+nNGo0jKQa5UkK8uCqNDuACfABOF1AIc452G+hN1vov93Q7cFbh1e4gEAeQwe8VRkdMUnw6urWRFkg==","salts":{"cipher":73,"offset":149,"pad":211,"perm":39},"tag":3984800216};

  function b64ToBytes(text) {
    const raw = atob(text);
    const out = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i += 1) {
      out[i] = raw.charCodeAt(i);
    }
    return out;
  }

  function deobfuscate(bytes, salt) {
    const out = new Uint8Array(bytes.length);
    for (let i = 0; i < bytes.length; i += 1) {
      out[i] = bytes[i] ^ ((salt + i * 29) & 255);
    }
    return out;
  }

  function deriveKey(cfg, trace) {
    const canonical = cfg.targets.map((v) => Number(v).toFixed(3)).join('|') +
      '|' + Number(cfg.tolerance).toFixed(3) +
      '|cadence-v3|' + trace.length;
    let h = 0x811c9dc5 >>> 0;
    for (let i = 0; i < canonical.length; i += 1) {
      h ^= canonical.charCodeAt(i);
      h = Math.imul(h, 0x01000193) >>> 0;
    }
    const out = new Uint8Array(32);
    let x = h >>> 0;
    for (let i = 0; i < out.length; i += 1) {
      x ^= (x << 13) >>> 0;
      x ^= x >>> 17;
      x ^= (x << 5) >>> 0;
      out[i] = x & 255;
    }
    return out;
  }

  function checksum(plain, key) {
    let x = 0x9e3779b9 >>> 0;
    for (let i = 0; i < plain.length; i += 1) {
      const add = (plain[i] + ((key[i % key.length] << ((i % 4) * 8)) >>> 0)) >>> 0;
      x = (x + add) >>> 0;
      x = ((x << 7) | (x >>> 25)) >>> 0;
    }
    return x >>> 0;
  }

  window.__cadenceDecode = function(input) {
    if (!input || !input.cfg) {
      throw new Error('missing_input');
    }
    const cfg = input.cfg;
    const trace = Array.isArray(input.trace) ? input.trace : [];
    if (!Array.isArray(cfg.targets) || trace.length !== cfg.targets.length) {
      throw new Error('trace_length_mismatch');
    }
    for (let i = 0; i < cfg.targets.length; i += 1) {
      const target = Number(cfg.targets[i]);
      const delta = Number(trace[i]);
      const tol = Number(cfg.tolerance);
      if (!Number.isFinite(delta) || Math.abs(delta - target) > tol + 0.001) {
        throw new Error('trace_out_of_window');
      }
    }

    const key = deriveKey(cfg, trace);
    const cipher = deobfuscate(b64ToBytes(PACK.cipher), PACK.salts.cipher);
    const offset = deobfuscate(b64ToBytes(PACK.offset), PACK.salts.offset);
    const pad = deobfuscate(b64ToBytes(PACK.pad), PACK.salts.pad);
    const perm = deobfuscate(b64ToBytes(PACK.perm), PACK.salts.perm);
    if (cipher.length !== offset.length || cipher.length !== pad.length) {
      throw new Error('payload_length_mismatch');
    }

    const inv = new Uint8Array(256);
    for (let i = 0; i < perm.length; i += 1) {
      inv[perm[i]] = i;
    }

    const plain = new Uint8Array(cipher.length);
    for (let i = 0; i < cipher.length; i += 1) {
      let v = inv[cipher[i]];
      v = (v - offset[i] - ((i * 17) & 255) + 512) & 255;
      v = v ^ key[i % key.length] ^ pad[i];
      plain[i] = v;
    }

    if (checksum(plain, key) !== (PACK.tag >>> 0)) {
      throw new Error('integrity_check_failed');
    }
    return new TextDecoder().decode(plain);
  };
})();
