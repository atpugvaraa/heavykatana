(() => {
  // call_recorder_katana.js
  //
  // Call recorder tweak for the heavykatana JS-injection chain. Records audio
  // via AVAudioRecorder injected into SpringBoard. Saves the recording to
  // /private/var/tmp/callrec_<timestamp>.caf
  //
  // For security research purposes only.
  //
  // The recording duration is selected in index.html's duration picker and
  // propagated through the worker postMessage chain into
  // globalThis.__callrec_duration before this payload is sent to the target
  // process. Accepted values: 10–600 (seconds). Defaults to 60 if unset.

  const DURATION = (() => {
    let d = Number(globalThis.__callrec_duration);
    if (!isFinite(d) || d < 10) d = 60;
    if (d > 600) d = 600;
    return Math.floor(d);
  })();

  // ──── Native Bridge ────────────────────────────────────────────────
  // Exact same pattern as powercuff_light.js — wraps the shared
  // nativeCallBuff / invoker() primitives provided by the injection chain.

  class Native {
    static #baseAddr;
    static #dlsymAddr;
    static #memcpyAddr;
    static #mallocAddr;
    static mem = 0n;
    static memSize = 0x4000;
    static #argMem = 0n;
    static #argPtr = 0n;
    static #dlsymCache = {};

    static init() {
      const buff = new BigUint64Array(nativeCallBuff);
      this.#baseAddr = buff[20];
      this.#dlsymAddr = buff[21];
      this.#memcpyAddr = buff[22];
      this.#mallocAddr = buff[23];
      this.mem = this.#nativeCallAddr(this.#mallocAddr, BigInt(this.memSize));
      this.#argMem = this.#nativeCallAddr(this.#mallocAddr, 0x1000n);
      this.#argPtr = this.#argMem;
    }

    static write(ptr, buff) {
      if (!ptr) return false;
      const buff8 = new Uint8Array(nativeCallBuff);
      let offs = 0;
      let left = buff.byteLength;
      while (left) {
        let len = left;
        if (len > 0x1000) len = 0x1000;
        buff8.set(new Uint8Array(buff, offs, len), 0x1000);
        this.#nativeCallAddr(this.#memcpyAddr, ptr + BigInt(offs), this.#baseAddr + 0x1000n, BigInt(len));
        left -= len;
        offs += len;
      }
      return true;
    }

    static read(ptr, length) {
      if (!ptr) return null;
      const buff = new ArrayBuffer(length);
      const buff8 = new Uint8Array(buff);
      let offs = 0;
      let left = length;
      while (left) {
        let len = left;
        if (len > 0x1000) len = 0x1000;
        this.#nativeCallAddr(this.#memcpyAddr, this.#baseAddr + 0x1000n, ptr + BigInt(offs), BigInt(len));
        buff8.set(new Uint8Array(nativeCallBuff, 0x1000, len), offs);
        left -= len;
        offs += len;
      }
      return buff;
    }

    static readPtr(ptr) {
      const dv = new DataView(this.read(ptr, 8));
      return dv.getBigUint64(0, true);
    }

    static writeString(ptr, str) {
      this.write(ptr, this.stringToBytes(str, true));
    }

    static stringToBytes(str, nullTerminated = false) {
      const buff = new ArrayBuffer(str.length + (nullTerminated ? 1 : 0));
      const s8 = new Uint8Array(buff);
      for (let i = 0; i < str.length; i++) s8[i] = str.charCodeAt(i);
      if (nullTerminated) s8[str.length] = 0;
      return s8.buffer;
    }

    static #toNative(value) {
      if (!value) return 0n;
      if (typeof value === "string") {
        const ptr = this.#argPtr;
        this.writeString(ptr, value);
        this.#argPtr += BigInt(value.length + 1);
        return ptr;
      }
      if (typeof value === "bigint") return value;
      return BigInt(value);
    }

    static #dlsym(name) {
      if (!name) return 0n;
      let addr = this.#dlsymCache[name];
      if (addr) return addr;
      const RTLD_DEFAULT = 0xfffffffffffffffen;
      const nameBytes = this.stringToBytes(name, true);
      const buff8 = new Uint8Array(nativeCallBuff);
      buff8.set(new Uint8Array(nameBytes), 0x1000);
      addr = this.#nativeCallAddr(this.#dlsymAddr, RTLD_DEFAULT, this.#baseAddr + 0x1000n);
      if (addr) this.#dlsymCache[name] = addr;
      return addr;
    }

    static #nativeCallAddr(addr, x0 = 0n, x1 = 0n, x2 = 0n, x3 = 0n, x4 = 0n, x5 = 0n, x6 = 0n, x7 = 0n) {
      const buff = new BigInt64Array(nativeCallBuff);
      buff[0] = addr;
      buff[100] = x0;
      buff[101] = x1;
      buff[102] = x2;
      buff[103] = x3;
      buff[104] = x4;
      buff[105] = x5;
      buff[106] = x6;
      buff[107] = x7;
      invoker();
      return buff[200];
    }

    static callSymbol(name, x0, x1, x2, x3, x4, x5, x6, x7) {
      this.#argPtr = this.#argMem;
      x0 = this.#toNative(x0);
      x1 = this.#toNative(x1);
      x2 = this.#toNative(x2);
      x3 = this.#toNative(x3);
      x4 = this.#toNative(x4);
      x5 = this.#toNative(x5);
      x6 = this.#toNative(x6);
      x7 = this.#toNative(x7);
      const funcAddr = this.#dlsym(name);
      const ret64 = this.#nativeCallAddr(funcAddr, x0, x1, x2, x3, x4, x5, x6, x7);
      this.#argPtr = this.#argMem;
      if (ret64 < 0xffffffffn && ret64 > -0xffffffffn) return Number(ret64);
      return ret64;
    }
  }

  // ──── Helpers ──────────────────────────────────────────────────────

  function u64(v) {
    if (!v) return 0n;
    return BigInt.asUintN(64, BigInt(v));
  }

  function isNonZero(v) {
    return u64(v) !== 0n;
  }

  const STATUS_FILE = "/private/var/mobile/Media/Downloads/.callrec_status";
  function log(msg, safariStatus = null) {
    try {
      const tagged = "[CALLREC] " + msg;
      const ptr = Native.callSymbol("malloc", BigInt(tagged.length + 1));
      if (!ptr) return;
      Native.writeString(ptr, tagged);
      Native.callSymbol("syslog", 5, "%s", ptr);
      Native.callSymbol("free", ptr);

      // Report to Safari bridge if a status message is provided
      if (safariStatus) {
        const O_WRONLY = 1;
        const O_CREAT = 0x0200;
        const O_TRUNC = 0x0400;
        let fd = Native.callSymbol("open", STATUS_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0o666n);
        if (Number(fd) >= 0) {
          let sPtr = Native.callSymbol("malloc", BigInt(safariStatus.length + 1));
          Native.writeString(sPtr, safariStatus);
          Native.callSymbol("write", fd, sPtr, BigInt(safariStatus.length));
          Native.callSymbol("free", sPtr);
          Native.callSymbol("close", fd);
        }
      }
    } catch (_) {}
  }

  function vibrate() {
    try {
      // 1519 is "Peak" haptic feedback actuation
      Native.callSymbol("AudioServicesPlaySystemSound", 1519n);
    } catch(e) {}
  }

  function sel(name) {
    return Native.callSymbol("sel_registerName", name);
  }

  function objc(obj, selectorName, ...args) {
    return Native.callSymbol("objc_msgSend", obj, sel(selectorName), ...args);
  }

  // CFStringCreateWithCString — same pattern as powercuff_light.js cfstr()
  function cfstr(str) {
    return Native.callSymbol("CFStringCreateWithCString", 0n, str, 0x08000100);
  }

  // CFNumberCreate with kCFNumberSInt32Type (3)
  function cfnum32(val) {
    // Write the int32 value into mem, then create CFNumber pointing at it
    const buf = new ArrayBuffer(4);
    new DataView(buf).setInt32(0, val, true);
    Native.write(Native.mem + 0x3000n, buf);
    return Native.callSymbol("CFNumberCreate", 0n, 3, Native.mem + 0x3000n);
  }

  // CFNumberCreate with kCFNumberFloat64Type (13)
  function cfnumF64(val) {
    const buf = new ArrayBuffer(8);
    new DataView(buf).setFloat64(0, val, true);
    Native.write(Native.mem + 0x3000n, buf);
    return Native.callSymbol("CFNumberCreate", 0n, 13, Native.mem + 0x3000n);
  }

  function canRespond(obj, selectorName) {
    if (!isNonZero(obj)) return false;
    const ret = objc(obj, "respondsToSelector:", sel(selectorName));
    return isNonZero(ret);
  }

  // ──── Core Recording Logic ─────────────────────────────────────────

  function startRecording() {
    log("=== call_recorder_katana entry === duration=" + DURATION + "s");

    // 1. Load AVFoundation framework
    const RTLD_NOW = 0x2n;
    let avfHandle = Native.callSymbol("dlopen",
      "/System/Library/Frameworks/AVFoundation.framework/AVFoundation",
      RTLD_NOW);
    if (!isNonZero(avfHandle)) {
      log("dlopen AVFoundation FAILED");
      return false;
    }
    log("AVFoundation loaded handle=0x" + u64(avfHandle).toString(16));

    // Also load AudioToolbox for format constants
    let atHandle = Native.callSymbol("dlopen",
      "/System/Library/Frameworks/AudioToolbox.framework/AudioToolbox",
      RTLD_NOW);
    log("AudioToolbox loaded handle=0x" + u64(atHandle).toString(16));

    // 2. Set up AVAudioSession for recording
    let sessionClass = Native.callSymbol("objc_getClass", "AVAudioSession");
    if (!isNonZero(sessionClass)) {
      log("AVAudioSession class not found");
      return false;
    }
    log("AVAudioSession class=0x" + u64(sessionClass).toString(16));

    let session = objc(sessionClass, "sharedInstance");
    if (!isNonZero(session)) {
      log("AVAudioSession sharedInstance returned nil");
      return false;
    }
    log("session=0x" + u64(session).toString(16));

    // Use PlayAndRecord (not Record) — SpringBoard on iOS 18.x does not
    // hold a com.apple.security.microphone-access entitlement, but the
    // PlayAndRecord category with MixWithOthers option can acquire a
    // recording-capable audio unit inside a system process. This is the
    // same trick used by VoiceMemos / FaceTime internals.
    let categoryStr = cfstr("AVAudioSessionCategoryPlayAndRecord");
    if (!isNonZero(categoryStr)) {
      log("Failed to create category CFString");
      return false;
    }

    // Allocate an error pointer (NSError **) so we can read back failures
    let errPtrBuf = Native.callSymbol("calloc", 1n, 8n);

    // setCategory:withOptions:error:
    // AVAudioSessionCategoryOptionMixWithOthers = 0x1
    // AVAudioSessionCategoryOptionDefaultToSpeaker = 0x2
    let setCatResult = objc(session, "setCategory:withOptions:error:",
      categoryStr, 0x1n | 0x2n, errPtrBuf);
    log("setCategory result=" + setCatResult);

    // Set mode to VoiceChat - this is the key for FaceTime/Cellular call quality
    // and ensuring the Echo Cancellation logic is active.
    let modeStr = cfstr("AVAudioSessionModeVoiceChat");
    let setModeResult = objc(session, "setMode:error:", modeStr, errPtrBuf);
    log("setMode (VoiceChat) result=" + setModeResult);
    log("Initializing...", "Initializing Engine...");

    // Check if setCategory failed and log the NSError
    let catErr = Native.readPtr(errPtrBuf);
    if (isNonZero(catErr)) {
      // Try to read [NSError localizedDescription]
      try {
        let errDesc = objc(catErr, "localizedDescription");
        if (isNonZero(errDesc)) {
          let errCStr = objc(errDesc, "UTF8String");
          if (isNonZero(errCStr)) {
            let errData = Native.read(errCStr, 256);
            let errBytes = new Uint8Array(errData);
            let errStr = '';
            for (let i = 0; i < errBytes.length && errBytes[i] !== 0; i++)
              errStr += String.fromCharCode(errBytes[i]);
            log("setCategory ERROR: " + errStr);
          }
        }
      } catch (e) { log("setCategory error read failed: " + e); }
    }

    // Zero out the error pointer for reuse
    let zeroBuf = new ArrayBuffer(8);
    Native.write(errPtrBuf, zeroBuf);

    // Activate the session
    let setActiveResult = objc(session, "setActive:withOptions:error:", 1n, 0n, errPtrBuf);
    log("setActive result=" + setActiveResult);

    // Check setActive errors
    let activeErr = Native.readPtr(errPtrBuf);
    if (isNonZero(activeErr)) {
      try {
        let errDesc = objc(activeErr, "localizedDescription");
        if (isNonZero(errDesc)) {
          let errCStr = objc(errDesc, "UTF8String");
          if (isNonZero(errCStr)) {
            let errData = Native.read(errCStr, 256);
            let errBytes = new Uint8Array(errData);
            let errStr = '';
            for (let i = 0; i < errBytes.length && errBytes[i] !== 0; i++)
              errStr += String.fromCharCode(errBytes[i]);
            log("setActive ERROR: " + errStr);
          }
        }
      } catch (e) { log("setActive error read failed: " + e); }
    }

    // 3. Build the output file path in user-accessible Downloads folder
    //    Using /private/var/mobile/Media/Downloads/ to bypass SpringBoard
    //    sandbox restrictions on /tmp which often fail on iOS 18.x.
    const baseDir = "/private/var/mobile/Media/Downloads";
    let timestamp = Date.now();
    let filePath = baseDir + "/callrec_" + timestamp + ".caf";
    log("output path: " + filePath);

    // Diagnostic: verify base directory is reachable
    let dirCheck = Native.callSymbol("access", baseDir, 0n);
    if (Number(dirCheck) !== 0) {
      log("WARNING: Downloads directory not reachable (access=" + dirCheck + "), attempting recording anyway...");
    } else {
      log("Downloads directory reachable (OK)");
    }

    // Create NSURL from file path
    let nsStringClass = Native.callSymbol("objc_getClass", "NSString");
    let pathNSString = objc(nsStringClass, "stringWithUTF8String:", filePath);
    if (!isNonZero(pathNSString)) {
      log("Failed to create NSString for path");
      return false;
    }

    let nsurlClass = Native.callSymbol("objc_getClass", "NSURL");
    let fileURL = objc(nsurlClass, "fileURLWithPath:", pathNSString);
    if (!isNonZero(fileURL)) {
      log("Failed to create NSURL");
      return false;
    }
    log("fileURL=0x" + u64(fileURL).toString(16));

    // 4. Build recording settings NSDictionary
    //    Keys:
    //      AVFormatIDKey              = kAudioFormatAppleLossless (1634492771 / 'alac')
    //      AVSampleRateKey            = 44100.0
    //      AVNumberOfChannelsKey      = 1
    //      AVEncoderAudioQualityKey   = AVAudioQualityHigh (0x60)
    //
    // We use CFDictionary (toll-free bridged to NSDictionary) for simpler construction.

    let formatIdKey = cfstr("AVFormatIDKey");
    let sampleRateKey = cfstr("AVSampleRateKey");
    let numChannelsKey = cfstr("AVNumberOfChannelsKey");
    let qualityKey = cfstr("AVEncoderAudioQualityKey");

    // kAudioFormatAppleLossless = 'alac' = 0x616C6163
    let formatIdVal = cfnum32(0x616C6163);
    let sampleRateVal = cfnumF64(44100.0);
    let numChannelsVal = cfnum32(1);
    let qualityVal = cfnum32(0x60); // AVAudioQualityHigh

    if (!isNonZero(formatIdKey) || !isNonZero(sampleRateKey) ||
        !isNonZero(numChannelsKey) || !isNonZero(qualityKey)) {
      log("Failed to create settings key CFStrings");
      return false;
    }
    if (!isNonZero(formatIdVal) || !isNonZero(sampleRateVal) ||
        !isNonZero(numChannelsVal) || !isNonZero(qualityVal)) {
      log("Failed to create settings value CFNumbers");
      return false;
    }

    // Build NSDictionary via +[NSDictionary dictionaryWithObjects:forKeys:count:]
    //
    // We write the 4 key pointers and 4 value pointers into native memory,
    // then call the class method.
    let nsdictClass = Native.callSymbol("objc_getClass", "NSDictionary");

    // Allocate space for 4 keys + 4 values = 8 pointers = 64 bytes
    let keysPtr = Native.callSymbol("malloc", 64n);
    let valsPtr = Native.callSymbol("malloc", 64n);

    // Write keys array
    let keysBuf = new ArrayBuffer(32);
    let keysView = new DataView(keysBuf);
    keysView.setBigUint64(0, u64(formatIdKey), true);
    keysView.setBigUint64(8, u64(sampleRateKey), true);
    keysView.setBigUint64(16, u64(numChannelsKey), true);
    keysView.setBigUint64(24, u64(qualityKey), true);
    Native.write(keysPtr, keysBuf);

    // Write values array
    let valsBuf = new ArrayBuffer(32);
    let valsView = new DataView(valsBuf);
    valsView.setBigUint64(0, u64(formatIdVal), true);
    valsView.setBigUint64(8, u64(sampleRateVal), true);
    valsView.setBigUint64(16, u64(numChannelsVal), true);
    valsView.setBigUint64(24, u64(qualityVal), true);
    Native.write(valsPtr, valsBuf);

    let settings = objc(nsdictClass, "dictionaryWithObjects:forKeys:count:",
      valsPtr, keysPtr, 4n);
    Native.callSymbol("free", keysPtr);
    Native.callSymbol("free", valsPtr);

    if (!isNonZero(settings)) {
      log("Failed to create settings NSDictionary");
      return false;
    }
    log("settings dict=0x" + u64(settings).toString(16));

    // 5. Create AVAudioRecorder
    let recorderClass = Native.callSymbol("objc_getClass", "AVAudioRecorder");
    if (!isNonZero(recorderClass)) {
      log("AVAudioRecorder class not found");
      return false;
    }

    // alloc
    let recorder = objc(recorderClass, "alloc");
    if (!isNonZero(recorder)) {
      log("AVAudioRecorder alloc failed");
      return false;
    }

    // initWithURL:settings:error: — reuse errPtrBuf for diagnostics
    Native.write(errPtrBuf, zeroBuf); // clear error pointer
    recorder = objc(recorder, "initWithURL:settings:error:", fileURL, settings, errPtrBuf);
    if (!isNonZero(recorder)) {
      // Try to read the error for diagnostics
      let initErr = Native.readPtr(errPtrBuf);
      if (isNonZero(initErr)) {
        try {
          let errDesc = objc(initErr, "localizedDescription");
          if (isNonZero(errDesc)) {
            let errCStr = objc(errDesc, "UTF8String");
            if (isNonZero(errCStr)) {
              let errData = Native.read(errCStr, 256);
              let errBytes = new Uint8Array(errData);
              let errStr = '';
              for (let i = 0; i < errBytes.length && errBytes[i] !== 0; i++)
                errStr += String.fromCharCode(errBytes[i]);
              log("initWithURL ERROR: " + errStr);
            }
          }
        } catch (e) { log("initWithURL error read failed: " + e); }
      }
      log("AVAudioRecorder initWithURL:settings:error: returned nil — check audio session / sandbox permissions");
      Native.callSymbol("free", errPtrBuf);
      return false;
    }
    log("recorder=0x" + u64(recorder).toString(16));

    // 6. Prepare and record
    let prepareOk = objc(recorder, "prepareToRecord");
    log("prepareToRecord=" + prepareOk);
    if (!isNonZero(prepareOk)) {
      log("prepareToRecord failed — recorder not ready");
      // Continue anyway, record() might still work depending on state
    }

    // NOTE: recordForDuration: takes an NSTimeInterval (double) argument
    // which ARM64 passes in float register d0. Our native call bridge
    // only populates integer registers x0–x7, so the double would be
    // garbage. We use plain record() + usleep loop instead. The usleep
    // loop uses 500ms chunks to avoid watchdog kills when the injection
    // thread is held for >30s on iOS 18.x.
    let recordOk = objc(recorder, "record");
    log("record=" + recordOk + " — recording for " + DURATION + "s...");

    if (!isNonZero(recordOk)) {
      log("record returned NO — recording failed to start", "ERROR: Recording Failed");
      Native.callSymbol("free", errPtrBuf);
      return false;
    }

    // Success Signal
    vibrate(); 
    log("Recording started", "Recording Pro Active... | " + filePath);

    // 7. Wait for the recording to complete using short usleep intervals
    // instead of one long blocking sleep(). Each iteration sleeps 500ms
    // to keep the thread responsive and avoid watchdog timeout.
    let totalWaitUs = DURATION * 1000000;
    let intervalUs = 500000;  // 500ms chunks
    let elapsedUs = 0;
    log("waiting " + DURATION + "s for recording (" + (totalWaitUs / intervalUs) + " x 500ms)...");
    while (elapsedUs < totalWaitUs) {
      Native.callSymbol("usleep", BigInt(intervalUs));
      elapsedUs += intervalUs;
    }

    // 8. Stop recording (no-op if recordForDuration already stopped it)
    let isRecording = objc(recorder, "isRecording");
    if (isNonZero(isRecording)) {
      objc(recorder, "stop");
      log("recording stopped manually");
    } else {
      log("recording already stopped (recordForDuration auto-stop)");
    }

    // 9. Verify the file was created by checking with access()
    let accessResult = Native.callSymbol("access", filePath, 0n); // F_OK
    if (Number(accessResult) === 0) {
      log("SUCCESS: recording saved to " + filePath, "Recording Saved! | " + filePath);
      vibrate(); 
      Native.callSymbol("usleep", 100000n);
      vibrate(); // Double pulse on success

      // Get file size for logging
      let statBuf = Native.callSymbol("malloc", 256n);
      let statResult = Native.callSymbol("stat", filePath, statBuf);
      if (Number(statResult) === 0) {
        let statData = Native.read(BigInt(statBuf), 144);
        let fileSize = Number(new DataView(statData).getBigUint64(96, true));
        log("file size: " + fileSize + " bytes");
      }
      Native.callSymbol("free", statBuf);

      // Set permissions so the file is accessible
      Native.callSymbol("chmod", filePath, 0o777n);
    } else {
      log("WARNING: recording file not found at " + filePath + " (access() failed)");
    }

    // 10. Deactivate audio session
    objc(session, "setActive:withOptions:error:", 0n, 0x1n, 0n);
    log("audio session deactivated");
    Native.callSymbol("free", errPtrBuf);

    return true;
  }

  // ──── Entry Point ──────────────────────────────────────────────────

  try {
    log("=== call_recorder_katana.js loaded === duration=" + DURATION + "s");
    Native.init();
    log("Native.init ok, baseAddr=0x" + new BigUint64Array(nativeCallBuff)[20].toString(16));

    // Sanity check: verify we can reach AVFoundation classes
    let probe = Native.callSymbol("objc_getClass", "AVAudioSession");
    log("probe AVAudioSession=0x" + u64(probe).toString(16) + (probe ? " (OK)" : " (MISSING)"));

    const ok = startRecording();
    log("call_recorder_katana result=" + ok + " duration=" + DURATION + "s");
  } catch (e) {
    log("fatal: " + String(e) + " stack: " + (e.stack || "N/A"));
  }
})();
