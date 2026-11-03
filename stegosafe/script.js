
"use strict";

/*
  StegoSafe
  ----------
  Image steganography using RGB least significant bits.
  Optional encryption: AES-256-GCM.
  Password derivation: PBKDF2 with SHA-256.

  Payload format:
  Byte 0-3 : Magic signature "STG1"
  Byte 4   : Format version
  Byte 5   : Flags (0 = plain, 1 = encrypted)
  Byte 6-9 : Payload length (unsigned 32-bit big-endian)
  Byte 10+ : Message payload

  Encrypted payload:
  16 bytes salt + 12 bytes IV + AES-GCM ciphertext/tag
*/

(() => {
  const MAGIC = new Uint8Array([0x53, 0x54, 0x47, 0x31]);
  const VERSION = 1;
  const HEADER_SIZE = 10;
  const SALT_SIZE = 16;
  const IV_SIZE = 12;
  const PBKDF2_ITERATIONS = 250000;
  const MAX_FILE_SIZE = 20 * 1024 * 1024;
  const MAX_IMAGE_PIXELS = 40000000;
  const MAX_MESSAGE_BYTES = 100000;

  const encoder = new TextEncoder();
  const decoder = new TextDecoder("utf-8", { fatal: true });

  const $ = (id) => document.getElementById(id);

  const state = {
    cover: null,
    stego: null,
    outputUrl: null,
    coverUrl: null,
    stegoUrl: null,
    detectedPayload: null,
    isBusy: false
  };

  /* -------------------------------------------------------
     BASIC HELPERS
  ------------------------------------------------------- */

  function setStatus(elementId, message, type = "") {
    const element = $(elementId);
    if (!element) return;

    element.textContent = message;
    element.className = "status";

    if (type) {
      element.classList.add(type);
    }
  }

  function formatBytes(bytes) {
    if (!Number.isFinite(bytes) || bytes < 0) return "0 B";
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) {
      return `${(bytes / 1024).toFixed(1)} KB`;
    }
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  }

  function setBusy(value) {
    state.isBusy = value;

    $("hideButton").disabled = value || !state.cover;
    $("extractButton").disabled = value || !state.stego;
  }

  function showElement(id, visible) {
    $(id).classList.toggle("hidden", !visible);
  }

  function revokeObjectUrl(url) {
    if (url) {
      URL.revokeObjectURL(url);
    }
  }

  function randomBytes(length) {
    const bytes = new Uint8Array(length);
    crypto.getRandomValues(bytes);
    return bytes;
  }

  function ensureBrowserSupport() {
    if (!window.crypto || !crypto.subtle || !crypto.getRandomValues) {
      throw new Error(
        "Web Crypto API is unavailable. Use a modern browser in a secure context such as HTTPS or localhost."
      );
    }

    if (!window.TextEncoder || !window.TextDecoder) {
      throw new Error("This browser does not support UTF-8 encoding.");
    }
  }

  function checkFile(file) {
    if (!file) {
      throw new Error("Please select an image file.");
    }

    const allowedTypes = [
      "image/png",
      "image/jpeg",
      "image/webp"
    ];

    if (!allowedTypes.includes(file.type)) {
      throw new Error("Unsupported file. Please select PNG, JPEG or WebP.");
    }

    if (file.size > MAX_FILE_SIZE) {
      throw new Error("Image is too large. Maximum file size is 20 MB.");
    }

    if (file.size === 0) {
      throw new Error("The selected file is empty.");
    }
  }

  /* -------------------------------------------------------
     IMAGE LOADING
  ------------------------------------------------------- */

  function loadImageFile(file) {
    return new Promise((resolve, reject) => {
      const objectUrl = URL.createObjectURL(file);
      const image = new Image();

      image.onload = () => {
        try {
          const width = image.naturalWidth;
          const height = image.naturalHeight;

          if (!width || !height) {
            throw new Error("The selected image has invalid dimensions.");
          }

          if (width * height > MAX_IMAGE_PIXELS) {
            throw new Error("Image dimensions are too large to process safely.");
          }

          const canvas = document.createElement("canvas");
          canvas.width = width;
          canvas.height = height;

          const context = canvas.getContext("2d", {
            willReadFrequently: true
          });

          if (!context) {
            throw new Error("Canvas is not supported by this browser.");
          }

          context.drawImage(image, 0, 0);

          const imageData = context.getImageData(
            0,
            0,
            width,
            height
          );

          URL.revokeObjectURL(objectUrl);

          resolve({
            imageData,
            width,
            height,
            file
          });
        } catch (error) {
          URL.revokeObjectURL(objectUrl);
          reject(error);
        }
      };

      image.onerror = () => {
        URL.revokeObjectURL(objectUrl);
        reject(new Error("Could not read this image. The file may be damaged."));
      };

      image.src = objectUrl;
    });
  }

  function makePreview(file, imageElement, boxId, urlKey) {
    revokeObjectUrl(state[urlKey]);

    const url = URL.createObjectURL(file);
    state[urlKey] = url;

    imageElement.src = url;
    showElement(boxId, true);
  }

  /* -------------------------------------------------------
     CAPACITY
  ------------------------------------------------------- */

  function getCapacityBytes(imageData) {
    const availableBits = imageData.data.length / 4 * 3;
    const totalBytes = Math.floor(availableBits / 8);

    return Math.max(0, totalBytes - HEADER_SIZE);
  }

  function updateCapacity() {
    const message = $("secretMessage").value;
    const messageBytes = encoder.encode(message).length;

    $("characterCount").textContent =
      `${message.length.toLocaleString()} / 100000`;

    $("messageSize").textContent = formatBytes(messageBytes);

    if (!state.cover) {
      $("capacityValue").textContent = "--";
      $("hideButton").disabled = true;
      return;
    }

    const capacity = getCapacityBytes(state.cover.imageData);

    $("capacityValue").textContent = formatBytes(capacity);

    const password = $("hidePassword").value;
    const encryptedOverhead = password ? SALT_SIZE + IV_SIZE + 16 : 0;
    const estimatedSize = messageBytes + encryptedOverhead;

    const fits = estimatedSize <= capacity;
    const hasMessage = messageBytes > 0;

    $("hideButton").disabled =
      state.isBusy || !fits || !hasMessage;

    if (!hasMessage) {
      setStatus("hideStatus", "Enter a message to continue.");
    } else if (!fits) {
      setStatus(
        "hideStatus",
        "Message is too large for this image. Choose a larger image.",
        "error"
      );
    } else {
      setStatus("hideStatus", "Image capacity is sufficient.", "success");
    }
  }

  /* -------------------------------------------------------
     CRYPTOGRAPHY
  ------------------------------------------------------- */

  async function deriveEncryptionKey(password, salt) {
    const passwordBytes = encoder.encode(password);

    const passwordKey = await crypto.subtle.importKey(
      "raw",
      passwordBytes,
      "PBKDF2",
      false,
      ["deriveKey"]
    );

    return crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt,
        iterations: PBKDF2_ITERATIONS,
        hash: "SHA-256"
      },
      passwordKey,
      {
        name: "AES-GCM",
        length: 256
      },
      false,
      ["encrypt", "decrypt"]
    );
  }

  async function encryptMessage(messageBytes, password) {
    const salt = randomBytes(SALT_SIZE);
    const iv = randomBytes(IV_SIZE);

    const key = await deriveEncryptionKey(password, salt);

    const encryptedBuffer = await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv,
        tagLength: 128
      },
      key,
      messageBytes
    );

    const encryptedBytes = new Uint8Array(encryptedBuffer);
    const result = new Uint8Array(
      SALT_SIZE + IV_SIZE + encryptedBytes.length
    );

    result.set(salt, 0);
    result.set(iv, SALT_SIZE);
    result.set(encryptedBytes, SALT_SIZE + IV_SIZE);

    return result;
  }

  async function decryptMessage(payload, password) {
    if (payload.length < SALT_SIZE + IV_SIZE + 16) {
      throw new Error("Encrypted payload is incomplete or corrupted.");
    }

    const salt = payload.slice(0, SALT_SIZE);
    const iv = payload.slice(SALT_SIZE, SALT_SIZE + IV_SIZE);
    const ciphertext = payload.slice(SALT_SIZE + IV_SIZE);

    const key = await deriveEncryptionKey(password, salt);

    try {
      const decryptedBuffer = await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv,
          tagLength: 128
        },
        key,
        ciphertext
      );

      return new Uint8Array(decryptedBuffer);
    } catch {
      throw new Error(
        "Decryption failed. The password may be incorrect or the image may be damaged."
      );
    }
  }

  /* -------------------------------------------------------
     PAYLOAD HEADER
  ------------------------------------------------------- */

  function createHeader(payloadLength, encrypted) {
    if (
      !Number.isSafeInteger(payloadLength) ||
      payloadLength < 0 ||
      payloadLength > 0xffffffff
    ) {
      throw new Error("Payload is too large.");
    }

    const header = new Uint8Array(HEADER_SIZE);

    header.set(MAGIC, 0);
    header[4] = VERSION;
    header[5] = encrypted ? 1 : 0;

    new DataView(header.buffer).setUint32(
      6,
      payloadLength,
      false
    );

    return header;
  }

  function parseHeader(header) {
    if (header.length !== HEADER_SIZE) {
      throw new Error("Invalid payload header.");
    }

    for (let i = 0; i < MAGIC.length; i++) {
      if (header[i] !== MAGIC[i]) {
        throw new Error("No StegoSafe message was found in this image.");
      }
    }

    const version = header[4];
    const flags = header[5];

    if (version !== VERSION) {
      throw new Error("Unsupported StegoSafe payload version.");
    }

    if (flags !== 0 && flags !== 1) {
      throw new Error("Invalid payload encryption flag.");
    }

    const payloadLength = new DataView(
      header.buffer,
      header.byteOffset,
      header.byteLength
    ).getUint32(6, false);

    return {
      encrypted: flags === 1,
      payloadLength
    };
  }

  /* -------------------------------------------------------
     LSB ENCODING AND DECODING
  ------------------------------------------------------- */

  function encodeLSB(imageData, bytes) {
    const totalBits = bytes.length * 8;
    const availableBits = (imageData.data.length / 4) * 3;

    if (totalBits > availableBits) {
      throw new Error("The image does not have enough capacity.");
    }

    const output = new Uint8ClampedArray(imageData.data);
    let bitIndex = 0;

    for (let i = 0; i < output.length && bitIndex < totalBits; i++) {
      // Skip alpha channel.
      if (i % 4 === 3) continue;

      const byteIndex = Math.floor(bitIndex / 8);
      const bitPosition = 7 - (bitIndex % 8);
      const bit = (bytes[byteIndex] >> bitPosition) & 1;

      output[i] = (output[i] & 0xfe) | bit;
      bitIndex++;
    }

    return new ImageData(
      output,
      imageData.width,
      imageData.height
    );
  }

  function readLSBBytes(imageData, byteLength) {
    if (
      !Number.isSafeInteger(byteLength) ||
      byteLength < 0
    ) {
      throw new Error("Invalid payload length.");
    }

    const requiredBits = byteLength * 8;
    const availableBits = (imageData.data.length / 4) * 3;

    if (requiredBits > availableBits) {
      throw new Error("The declared payload exceeds image capacity.");
    }

    const result = new Uint8Array(byteLength);
    let bitIndex = 0;

    for (
      let i = 0;
      i < imageData.data.length && bitIndex < requiredBits;
      i++
    ) {
      if (i % 4 === 3) continue;

      const bit = imageData.data[i] & 1;
      const byteIndex = Math.floor(bitIndex / 8);
      const bitPosition = 7 - (bitIndex % 8);

      result[byteIndex] |= bit << bitPosition;
      bitIndex++;
    }

    return result;
  }

  /* -------------------------------------------------------
     PNG EXPORT
  ------------------------------------------------------- */

  function imageDataToPNG(imageData) {
    return new Promise((resolve, reject) => {
      const canvas = document.createElement("canvas");
      canvas.width = imageData.width;
      canvas.height = imageData.height;

      const context = canvas.getContext("2d");

      if (!context) {
        reject(new Error("Could not create the output canvas."));
        return;
      }

      context.putImageData(imageData, 0, 0);

      canvas.toBlob((blob) => {
        if (!blob) {
          reject(new Error("PNG image generation failed."));
          return;
        }

        resolve(blob);
      }, "image/png");
    });
  }

  /* -------------------------------------------------------
     HIDE MESSAGE
  ------------------------------------------------------- */

  async function hideMessage() {
    if (state.isBusy) return;

    try {
      ensureBrowserSupport();

      if (!state.cover) {
        throw new Error("Please upload a cover image first.");
      }

      const message = $("secretMessage").value;

      if (!message.trim()) {
        throw new Error("Please enter a message before hiding it.");
      }

      const messageBytes = encoder.encode(message);

      if (messageBytes.length > MAX_MESSAGE_BYTES) {
        throw new Error("Message is too long.");
      }

      const password = $("hidePassword").value;
      const encrypted = password.length > 0;

      setBusy(true);
      setStatus("hideStatus", "Preparing message...", "loading");

      let payload;

      if (encrypted) {
        setStatus(
          "hideStatus",
          "Encrypting message with AES-256-GCM...",
          "loading"
        );

        payload = await encryptMessage(messageBytes, password);
      } else {
        payload = messageBytes;
      }

      const capacity = getCapacityBytes(state.cover.imageData);

      if (payload.length > capacity) {
        throw new Error(
          `Message requires ${formatBytes(payload.length)}, but image capacity is ${formatBytes(capacity)}.`
        );
      }

      setStatus(
        "hideStatus",
        "Embedding message into image...",
        "loading"
      );

      const header = createHeader(payload.length, encrypted);
      const completePayload = new Uint8Array(
        header.length + payload.length
      );

      completePayload.set(header, 0);
      completePayload.set(payload, header.length);

      const encodedImage = encodeLSB(
        state.cover.imageData,
        completePayload
      );

      const pngBlob = await imageDataToPNG(encodedImage);

      revokeObjectUrl(state.outputUrl);

      state.outputUrl = URL.createObjectURL(pngBlob);

      $("outputPreview").src = state.outputUrl;
      $("outputFileName").textContent = "stegosafe-image.png";
      $("outputFileSize").textContent = formatBytes(pngBlob.size);

      showElement("emptyOutput", false);
      showElement("outputBox", true);

      setStatus(
        "hideStatus",
        encrypted
          ? "Message encrypted and hidden successfully."
          : "Message hidden successfully.",
        "success"
      );
    } catch (error) {
      setStatus(
        "hideStatus",
        error.message || "Unable to hide the message.",
        "error"
      );
    } finally {
      setBusy(false);
      updateCapacity();
    }
  }

  /* -------------------------------------------------------
     DOWNLOAD
  ------------------------------------------------------- */

  function downloadOutput() {
    if (!state.outputUrl) {
      setStatus("hideStatus", "Generate an image before downloading.", "error");
      return;
    }

    const link = document.createElement("a");
    link.href = state.outputUrl;
    link.download = "stegosafe-image.png";

    document.body.appendChild(link);
    link.click();
    link.remove();
  }

  /* -------------------------------------------------------
     PAYLOAD DETECTION
  ------------------------------------------------------- */

  function inspectImage(imageData) {
    const header = readLSBBytes(imageData, HEADER_SIZE);
    const metadata = parseHeader(header);

    const capacity = getCapacityBytes(imageData);

    if (metadata.payloadLength > capacity) {
      throw new Error(
        "Payload length is invalid. The image may be damaged or modified."
      );
    }

    if (
      metadata.encrypted &&
      metadata.payloadLength < SALT_SIZE + IV_SIZE + 16
    ) {
      throw new Error("Encrypted payload is incomplete.");
    }

    const payload = readLSBBytes(
      imageData,
      HEADER_SIZE + metadata.payloadLength
    ).slice(HEADER_SIZE);

    return {
      encrypted: metadata.encrypted,
      payload
    };
  }

  function setPayloadState(title, description, type = "") {
    $("payloadTitle").textContent = title;
    $("payloadDescription").textContent = description;

    const indicator = $("payloadIndicator");
    indicator.className = "";

    if (type) {
      indicator.classList.add(type);
    }
  }

  /* -------------------------------------------------------
     EXTRACT MESSAGE
  ------------------------------------------------------- */

  async function extractMessage() {
    if (state.isBusy) return;

    try {
      ensureBrowserSupport();

      if (!state.stego) {
        throw new Error("Please upload an image first.");
      }

      if (!state.detectedPayload) {
        throw new Error("No valid payload has been detected.");
      }

      setBusy(true);
      showElement("recoveredBox", false);

      let messageBytes;

      if (state.detectedPayload.encrypted) {
        const password = $("extractPassword").value;

        if (!password) {
          throw new Error("Enter the password to decrypt this message.");
        }

        setStatus("extractStatus", "Decrypting message...", "loading");

        messageBytes = await decryptMessage(
          state.detectedPayload.payload,
          password
        );
      } else {
        messageBytes = state.detectedPayload.payload;
      }

      let recoveredText;

      try {
        recoveredText = decoder.decode(messageBytes);
      } catch {
        throw new Error(
          "The recovered data is not valid UTF-8 text. The image may be damaged."
        );
      }

      $("recoveredMessage").textContent = recoveredText;
      showElement("recoveredBox", true);

      setStatus(
        "extractStatus",
        "Message recovered successfully.",
        "success"
      );
    } catch (error) {
      setStatus(
        "extractStatus",
        error.message || "Message extraction failed.",
        "error"
      );
    } finally {
      setBusy(false);
    }
  }

  /* -------------------------------------------------------
     COVER IMAGE HANDLING
  ------------------------------------------------------- */

  async function handleCoverFile(file) {
    try {
      checkFile(file);

      setStatus("coverStatus", "Loading image...", "loading");

      const loaded = await loadImageFile(file);

      state.cover = loaded;

      $("coverFileName").textContent = file.name;
      $("coverDimensions").textContent =
        `${loaded.width} × ${loaded.height}`;

      $("coverFileInfo").classList.remove("hidden");

      makePreview(
        file,
        $("coverPreview"),
        "coverPreviewBox",
        "coverUrl"
      );

      setStatus("coverStatus", "Cover image ready.", "success");

      $("hideButton").disabled = false;
      updateCapacity();
    } catch (error) {
      state.cover = null;
      $("coverInput").value = "";
      showElement("coverFileInfo", false);
      showElement("coverPreviewBox", false);

      setStatus(
        "coverStatus",
        error.message || "Could not load image.",
        "error"
      );

      updateCapacity();
    }
  }

  function clearCover() {
    state.cover = null;
    $("coverInput").value = "";
    $("secretMessage").value = "";
    $("hidePassword").value = "";

    revokeObjectUrl(state.coverUrl);
    state.coverUrl = null;

    $("coverPreview").removeAttribute("src");

    showElement("coverFileInfo", false);
    showElement("coverPreviewBox", false);

    setStatus("coverStatus", "No image selected.");
    setStatus("hideStatus", "");

    updateCapacity();
  }

  /* -------------------------------------------------------
     STEGO IMAGE HANDLING
  ------------------------------------------------------- */

  async function handleStegoFile(file) {
    try {
      checkFile(file);

      setStatus("stegoStatus", "Loading and inspecting image...", "loading");

      const loaded = await loadImageFile(file);

      state.stego = loaded;
      state.detectedPayload = null;

      $("stegoFileName").textContent = file.name;
      $("stegoDimensions").textContent =
        `${loaded.width} × ${loaded.height}`;

      $("stegoFileInfo").classList.remove("hidden");

      makePreview(
        file,
        $("stegoPreview"),
        "stegoPreviewBox",
        "stegoUrl"
      );

      const detected = inspectImage(loaded.imageData);

      state.detectedPayload = detected;

      $("extractButton").disabled = false;

      if (detected.encrypted) {
        setPayloadState(
          "Encrypted payload detected",
          "AES-256-GCM protected message found.",
          "encrypted"
        );

        showElement("extractPasswordGroup", true);
      } else {
        setPayloadState(
          "Plain-text payload detected",
          "A StegoSafe message was found in this image.",
          "active"
        );

        showElement("extractPasswordGroup", false);
      }

      $("extractPassword").value = "";

      setStatus(
        "stegoStatus",
        "Image inspected successfully.",
        "success"
      );

      setStatus("extractStatus", "");
      showElement("recoveredBox", false);
    } catch (error) {
      state.stego = null;
      state.detectedPayload = null;

      $("stegoInput").value = "";

      showElement("stegoFileInfo", false);
      showElement("stegoPreviewBox", false);
      showElement("extractPasswordGroup", false);
      showElement("recoveredBox", false);

      $("extractButton").disabled = true;

      setPayloadState(
        "No valid payload",
        error.message || "No StegoSafe message found.",
        "error"
      );

      setStatus(
        "stegoStatus",
        error.message || "Could not inspect image.",
        "error"
      );

      setStatus("extractStatus", "");
    }
  }

  function clearStego() {
    state.stego = null;
    state.detectedPayload = null;

    $("stegoInput").value = "";
    $("extractPassword").value = "";

    revokeObjectUrl(state.stegoUrl);
    state.stegoUrl = null;

    $("stegoPreview").removeAttribute("src");

    showElement("stegoFileInfo", false);
    showElement("stegoPreviewBox", false);
    showElement("extractPasswordGroup", false);
    showElement("recoveredBox", false);

    $("extractButton").disabled = true;

    setPayloadState(
      "Waiting for image",
      "Upload an image to inspect its hidden data."
    );

    setStatus("stegoStatus", "No image selected.");
    setStatus("extractStatus", "");
  }

  /* -------------------------------------------------------
     CLEAR HIDE WORKSPACE
  ------------------------------------------------------- */

  function clearHideWorkspace() {
    clearCover();

    $("secretMessage").value = "";
    $("hidePassword").value = "";

    revokeObjectUrl(state.outputUrl);
    state.outputUrl = null;

    $("outputPreview").removeAttribute("src");

    showElement("outputBox", false);
    showElement("emptyOutput", true);

    updateCapacity();
  }

  /* -------------------------------------------------------
     TABS
  ------------------------------------------------------- */

  function switchTab(mode) {
    const hideMode = mode === "hide";

    $("hideSection").classList.toggle("hidden", !hideMode);
    $("extractSection").classList.toggle("hidden", hideMode);

    $("hideTab").classList.toggle("active", hideMode);
    $("extractTab").classList.toggle("active", !hideMode);
  }

  /* -------------------------------------------------------
     DRAG AND DROP
  ------------------------------------------------------- */

  function setupDragAndDrop(areaId, handler) {
    const area = $(areaId);

    ["dragenter", "dragover"].forEach((eventName) => {
      area.addEventListener(eventName, (event) => {
        event.preventDefault();
        event.stopPropagation();
        area.classList.add("dragging");
      });
    });

    ["dragleave", "drop"].forEach((eventName) => {
      area.addEventListener(eventName, (event) => {
        event.preventDefault();
        event.stopPropagation();
        area.classList.remove("dragging");
      });
    });

    area.addEventListener("drop", (event) => {
      const file = event.dataTransfer.files[0];

      if (file) {
        handler(file);
      }
    });
  }

  /* -------------------------------------------------------
     PASSWORD VISIBILITY
  ------------------------------------------------------- */

  function setupPasswordButtons() {
    document.querySelectorAll(".show-password").forEach((button) => {
      button.addEventListener("click", () => {
        const input = $(button.dataset.target);

        if (!input) return;

        const shouldShow = input.type === "password";

        input.type = shouldShow ? "text" : "password";
        button.textContent = shouldShow ? "HIDE" : "SHOW";
      });
    });
  }

  /* -------------------------------------------------------
     COPY MESSAGE
  ------------------------------------------------------- */

  async function copyRecoveredMessage() {
    const text = $("recoveredMessage").textContent;

    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
      } else {
        const temporary = document.createElement("textarea");
        temporary.value = text;
        temporary.style.position = "fixed";
        temporary.style.opacity = "0";

        document.body.appendChild(temporary);
        temporary.select();

        const copied = document.execCommand("copy");
        temporary.remove();

        if (!copied) {
          throw new Error("Copy command was not successful.");
        }
      }

      $("copyButton").textContent = "Copied";

      window.setTimeout(() => {
        $("copyButton").textContent = "Copy";
      }, 1500);
    } catch {
      setStatus(
        "extractStatus",
        "Could not copy automatically. Select and copy the message manually.",
        "error"
      );
    }
  }

  /* -------------------------------------------------------
     EVENT LISTENERS
  ------------------------------------------------------- */

  function initializeEvents() {
    $("hideTab").addEventListener("click", () => switchTab("hide"));
    $("extractTab").addEventListener("click", () => switchTab("extract"));

    $("coverInput").addEventListener("change", (event) => {
      const file = event.target.files[0];
      if (file) handleCoverFile(file);
    });

    $("stegoInput").addEventListener("change", (event) => {
      const file = event.target.files[0];
      if (file) handleStegoFile(file);
    });

    $("removeCover").addEventListener("click", clearCover);
    $("removeStego").addEventListener("click", clearStego);

    $("secretMessage").addEventListener("input", updateCapacity);
    $("hidePassword").addEventListener("input", updateCapacity);

    $("hideButton").addEventListener("click", hideMessage);
    $("downloadButton").addEventListener("click", downloadOutput);
    $("clearHideButton").addEventListener("click", clearHideWorkspace);

    $("extractButton").addEventListener("click", extractMessage);
    $("clearExtractButton").addEventListener("click", clearStego);
    $("copyButton").addEventListener("click", copyRecoveredMessage);

    setupDragAndDrop("coverDrop", handleCoverFile);
    setupDragAndDrop("stegoDrop", handleStegoFile);

    setupPasswordButtons();
  }

  /* -------------------------------------------------------
     INITIALIZATION
  ------------------------------------------------------- */

  function initialize() {
    initializeEvents();
    updateCapacity();

    try {
      ensureBrowserSupport();
    } catch (error) {
      setStatus("hideStatus", error.message, "error");
      setStatus("extractStatus", error.message, "error");
    }
  }

  initialize();
})();
