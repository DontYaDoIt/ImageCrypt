const imageInput = document.getElementById("imageInput");
const dropZone = document.getElementById("dropZone");
const passwordInput = document.getElementById("password");
const confirmPasswordInput = document.getElementById("confirmPassword");
const showPasswordButton = document.getElementById("showPassword");
const meterFill = document.getElementById("meterFill");
const passwordHint = document.getElementById("passwordHint");
const encryptButton = document.getElementById("encryptButton");
const decryptButton = document.getElementById("decryptButton");
const resetButton = document.getElementById("resetButton");
const downloadButton = document.getElementById("downloadButton");
const statusText = document.getElementById("status");
const sourceCanvas = document.getElementById("sourceCanvas");
const outputCanvas = document.getElementById("outputCanvas");
const sourceEmpty = document.getElementById("sourceEmpty");
const outputEmpty = document.getElementById("outputEmpty");
const originalInfo = document.getElementById("originalInfo");
const outputInfo = document.getElementById("outputInfo");
const sourceType = document.getElementById("sourceType");

const sourceContext = sourceCanvas.getContext("2d", {
  willReadFrequently: true
});
const outputContext = outputCanvas.getContext("2d", {
  willReadFrequently: true
});

const textEncoder = new TextEncoder();

const MAGIC = textEncoder.encode("PXLKPNG2");
const VERSION = 2;
const KDF_ID_PBKDF2_SHA256 = 1;
const CIPHER_ID_AES_256_GCM = 1;
const PBKDF2_ITERATIONS = 600000;
const SALT_LENGTH = 16;
const IV_LENGTH = 12;
const GCM_TAG_BYTES = 16;
const HEADER_SIZE = 60;
const MIN_PASSWORD_LENGTH = 12;
const MAX_PIXEL_COUNT = 20000000;

let loadedFileName = "image";
let hasImage = false;
let hasOutput = false;
let isBusy = false;
let loadedImageIsLocked = false;
let outputMode = "";

function setStatus(message, type = "") {
  statusText.textContent = message;
  statusText.className = `status ${type}`.trim();
}

function nextPaint() {
  return new Promise((resolve) => {
    requestAnimationFrame(() => requestAnimationFrame(resolve));
  });
}

function setBusy(busy) {
  isBusy = busy;
  imageInput.disabled = busy;
  passwordInput.disabled = busy;
  confirmPasswordInput.disabled = busy;
  resetButton.disabled = busy;
  showPasswordButton.disabled = busy;
  updateButtons();
}

function updateButtons() {
  const hasPassword = passwordInput.value.length > 0;
  const canUseImage = hasImage && hasPassword && !isBusy;

  encryptButton.disabled = !canUseImage;
  decryptButton.disabled = !canUseImage;
  downloadButton.disabled = !hasOutput || isBusy;
}

function updatePasswordMeter() {
  const password = passwordInput.value;
  let score = 0;

  if (password.length >= 12) score += 1;
  if (password.length >= 16) score += 1;
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score += 1;
  if (/\d/.test(password)) score += 1;
  if (/[^A-Za-z0-9]/.test(password)) score += 1;

  const widths = ["0%", "20%", "40%", "60%", "80%", "100%"];
  const labels = [
    "Use a long, unique password.",
    "Very weak",
    "Weak",
    "Fair",
    "Strong",
    "Very strong"
  ];
  const colors = [
    "#596170",
    "#e05b5b",
    "#df814e",
    "#d8b64d",
    "#69c987",
    "#55df92"
  ];

  meterFill.style.width = widths[score];
  meterFill.style.background = colors[score];
  passwordHint.textContent = labels[score];
}

function bytesEqual(first, second) {
  if (first.length !== second.length) return false;

  for (let index = 0; index < first.length; index += 1) {
    if (first[index] !== second[index]) return false;
  }

  return true;
}

function fillSecureRandom(target) {
  const maximumChunk = 65536;

  for (let offset = 0; offset < target.length; offset += maximumChunk) {
    crypto.getRandomValues(
      target.subarray(offset, Math.min(offset + maximumChunk, target.length))
    );
  }

  return target;
}

async function deriveEncryptionKey(password, salt, iterations, usages) {
  const passwordMaterial = await crypto.subtle.importKey(
    "raw",
    textEncoder.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt,
      iterations
    },
    passwordMaterial,
    {
      name: "AES-GCM",
      length: 256
    },
    false,
    usages
  );
}

function createHeader({
  iterations,
  width,
  height,
  plainLength,
  cipherLength,
  salt,
  iv
}) {
  const header = new Uint8Array(HEADER_SIZE);
  const view = new DataView(header.buffer);

  header.set(MAGIC, 0);
  header[8] = VERSION;
  header[9] = KDF_ID_PBKDF2_SHA256;
  header[10] = CIPHER_ID_AES_256_GCM;
  header[11] = 0;

  view.setUint32(12, iterations, false);
  view.setUint32(16, width, false);
  view.setUint32(20, height, false);
  view.setUint32(24, plainLength, false);
  view.setUint32(28, cipherLength, false);

  header.set(salt, 32);
  header.set(iv, 48);

  return header;
}

function readHeader(header) {
  if (header.length < HEADER_SIZE) {
    throw new Error("This image is too small to be a PixelLock file.");
  }

  if (!bytesEqual(header.subarray(0, MAGIC.length), MAGIC)) {
    throw new Error("This is not a PixelLock encrypted PNG.");
  }

  const view = new DataView(
    header.buffer,
    header.byteOffset,
    header.byteLength
  );

  const version = header[8];
  const kdfId = header[9];
  const cipherId = header[10];
  const iterations = view.getUint32(12, false);
  const width = view.getUint32(16, false);
  const height = view.getUint32(20, false);
  const plainLength = view.getUint32(24, false);
  const cipherLength = view.getUint32(28, false);
  const salt = header.slice(32, 48);
  const iv = header.slice(48, 60);

  if (version !== VERSION) {
    throw new Error(`Unsupported PixelLock version: ${version}.`);
  }

  if (
    kdfId !== KDF_ID_PBKDF2_SHA256 ||
    cipherId !== CIPHER_ID_AES_256_GCM
  ) {
    throw new Error("Unsupported PixelLock encryption method.");
  }

  if (iterations < 100000 || iterations > 5000000) {
    throw new Error("The encrypted file contains invalid key settings.");
  }

  if (
    width < 1 ||
    height < 1 ||
    width * height > MAX_PIXEL_COUNT ||
    plainLength !== width * height * 4 ||
    cipherLength !== plainLength + GCM_TAG_BYTES
  ) {
    throw new Error("The encrypted image metadata is invalid.");
  }

  return {
    version,
    iterations,
    width,
    height,
    plainLength,
    cipherLength,
    salt,
    iv
  };
}

function extractRgbBytes(imageData, requestedLength) {
  const availableLength = Math.floor(imageData.data.length / 4) * 3;

  if (requestedLength > availableLength) {
    throw new Error("The encrypted PNG is incomplete or damaged.");
  }

  const result = new Uint8Array(requestedLength);
  let outputOffset = 0;

  for (
    let inputOffset = 0;
    inputOffset < imageData.data.length && outputOffset < requestedLength;
    inputOffset += 4
  ) {
    result[outputOffset++] = imageData.data[inputOffset];

    if (outputOffset < requestedLength) {
      result[outputOffset++] = imageData.data[inputOffset + 1];
    }

    if (outputOffset < requestedLength) {
      result[outputOffset++] = imageData.data[inputOffset + 2];
    }
  }

  return result;
}

function appearsToBeLockedImage() {
  if (!hasImage) return false;

  const neededPixels = Math.ceil(MAGIC.length / 3);
  const imageData = sourceContext.getImageData(0, 0, neededPixels, 1);
  const bytes = extractRgbBytes(imageData, MAGIC.length);

  return bytesEqual(bytes, MAGIC);
}

function calculateCarrierDimensions(byteLength, originalWidth, originalHeight) {
  const pixelCount = Math.ceil(byteLength / 3);
  const originalAspect = originalWidth / originalHeight;
  const safeAspect = Math.max(0.3, Math.min(3.5, originalAspect));

  let width = Math.ceil(Math.sqrt(pixelCount * safeAspect));
  let height = Math.ceil(pixelCount / width);

  while (width * height * 3 < byteLength) {
    height += 1;
  }

  return { width, height };
}

function writePayloadToCarrier(payload, width, height) {
  const carrier = outputContext.createImageData(width, height);
  const randomRgb = fillSecureRandom(new Uint8Array(width * height * 3));

  let rgbOffset = 0;

  for (let pixelOffset = 0; pixelOffset < carrier.data.length; pixelOffset += 4) {
    carrier.data[pixelOffset] = randomRgb[rgbOffset++];
    carrier.data[pixelOffset + 1] = randomRgb[rgbOffset++];
    carrier.data[pixelOffset + 2] = randomRgb[rgbOffset++];
    carrier.data[pixelOffset + 3] = 255;
  }

  let payloadOffset = 0;

  for (
    let pixelOffset = 0;
    pixelOffset < carrier.data.length && payloadOffset < payload.length;
    pixelOffset += 4
  ) {
    carrier.data[pixelOffset] = payload[payloadOffset++];

    if (payloadOffset < payload.length) {
      carrier.data[pixelOffset + 1] = payload[payloadOffset++];
    }

    if (payloadOffset < payload.length) {
      carrier.data[pixelOffset + 2] = payload[payloadOffset++];
    }
  }

  outputCanvas.width = width;
  outputCanvas.height = height;
  outputContext.putImageData(carrier, 0, 0);
}

async function lockImage() {
  if (!hasImage) {
    setStatus("Choose an image first.", "error");
    return;
  }

  if (!crypto?.subtle) {
    setStatus(
      "Web Crypto is unavailable. Open this page through HTTPS or localhost.",
      "error"
    );
    return;
  }

  const password = passwordInput.value;
  const confirmation = confirmPasswordInput.value;

  if (password.length < MIN_PASSWORD_LENGTH) {
    setStatus(
      `Use at least ${MIN_PASSWORD_LENGTH} characters for the password.`,
      "error"
    );
    return;
  }

  if (password !== confirmation) {
    setStatus("The password confirmation does not match.", "error");
    return;
  }

  const width = sourceCanvas.width;
  const height = sourceCanvas.height;
  const pixelCount = width * height;

  if (pixelCount > MAX_PIXEL_COUNT) {
    setStatus(
      "This image is too large for safe in-browser processing. Use a smaller image.",
      "error"
    );
    return;
  }

  setBusy(true);
  setStatus("Creating a random salt and deriving the encryption key…", "working");
  await nextPaint();

  try {
    const imageData = sourceContext.getImageData(0, 0, width, height);
    const plainPixels = new Uint8Array(imageData.data);
    const salt = fillSecureRandom(new Uint8Array(SALT_LENGTH));
    const iv = fillSecureRandom(new Uint8Array(IV_LENGTH));
    const cipherLength = plainPixels.length + GCM_TAG_BYTES;

    const header = createHeader({
      iterations: PBKDF2_ITERATIONS,
      width,
      height,
      plainLength: plainPixels.length,
      cipherLength,
      salt,
      iv
    });

    const key = await deriveEncryptionKey(
      password,
      salt,
      PBKDF2_ITERATIONS,
      ["encrypt"]
    );

    setStatus("Encrypting every pixel with AES-256-GCM…", "working");
    await nextPaint();

    const encryptedBuffer = await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv,
        additionalData: header,
        tagLength: 128
      },
      key,
      plainPixels
    );

    const encrypted = new Uint8Array(encryptedBuffer);
    const payload = new Uint8Array(header.length + encrypted.length);
    payload.set(header, 0);
    payload.set(encrypted, header.length);

    const carrierSize = calculateCarrierDimensions(
      payload.length,
      width,
      height
    );

    writePayloadToCarrier(payload, carrierSize.width, carrierSize.height);

    outputCanvas.style.display = "block";
    outputEmpty.style.display = "none";
    outputInfo.textContent =
      `${carrierSize.width} × ${carrierSize.height} encrypted carrier`;
    outputMode = "encrypted";
    hasOutput = true;

    setStatus(
      "Image locked successfully. Save the PNG and keep the password.",
      "success"
    );
  } catch (error) {
    console.error(error);
    setStatus(
      "Encryption failed. The image may be too large for this browser.",
      "error"
    );
  } finally {
    setBusy(false);
  }
}

async function reverseImage() {
  if (!hasImage) {
    setStatus("Choose an encrypted PixelLock PNG first.", "error");
    return;
  }

  if (!crypto?.subtle) {
    setStatus(
      "Web Crypto is unavailable. Open this page through HTTPS or localhost.",
      "error"
    );
    return;
  }

  if (!loadedImageIsLocked) {
    setStatus("The loaded image is not a PixelLock encrypted PNG.", "error");
    return;
  }

  const password = passwordInput.value;

  if (!password) {
    setStatus("Enter the encryption password.", "error");
    return;
  }

  setBusy(true);
  setStatus("Reading and validating the encrypted image…", "working");
  await nextPaint();

  try {
    const carrierData = sourceContext.getImageData(
      0,
      0,
      sourceCanvas.width,
      sourceCanvas.height
    );

    const header = extractRgbBytes(carrierData, HEADER_SIZE);
    const metadata = readHeader(header);
    const totalPayloadLength = HEADER_SIZE + metadata.cipherLength;
    const payload = extractRgbBytes(carrierData, totalPayloadLength);
    const ciphertext = payload.slice(HEADER_SIZE);

    setStatus("Deriving the password key and authenticating the image…", "working");
    await nextPaint();

    const key = await deriveEncryptionKey(
      password,
      metadata.salt,
      metadata.iterations,
      ["decrypt"]
    );

    const decryptedBuffer = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: metadata.iv,
        additionalData: header,
        tagLength: 128
      },
      key,
      ciphertext
    );

    const restoredPixels = new Uint8ClampedArray(decryptedBuffer);

    if (restoredPixels.length !== metadata.plainLength) {
      throw new Error("The decrypted pixel length is invalid.");
    }

    outputCanvas.width = metadata.width;
    outputCanvas.height = metadata.height;

    const restoredImage = new ImageData(
      restoredPixels,
      metadata.width,
      metadata.height
    );

    outputContext.putImageData(restoredImage, 0, 0);
    outputCanvas.style.display = "block";
    outputEmpty.style.display = "none";
    outputInfo.textContent =
      `${metadata.width} × ${metadata.height} authenticated restoration`;
    outputMode = "restored";
    hasOutput = true;

    setStatus("Password accepted. The original pixels were restored.", "success");
  } catch (error) {
    console.error(error);

    if (error?.name === "OperationError") {
      setStatus(
        "Wrong password, damaged PNG, or modified encrypted pixels.",
        "error"
      );
    } else {
      setStatus(error?.message || "The encrypted image could not be reversed.", "error");
    }
  } finally {
    setBusy(false);
  }
}

function canvasToBlob(canvas) {
  return new Promise((resolve, reject) => {
    canvas.toBlob((blob) => {
      if (blob) {
        resolve(blob);
      } else {
        reject(new Error("The browser could not create the PNG."));
      }
    }, "image/png");
  });
}

async function saveOutput() {
  if (!hasOutput) {
    setStatus("Create an output image before saving.", "error");
    return;
  }

  setBusy(true);
  setStatus("Preparing the PNG…", "working");

  try {
    const blob = await canvasToBlob(outputCanvas);
    const baseName = loadedFileName
      .replace(/\.[^.]+$/, "")
      .replace(/-locked$/i, "")
      .replace(/-restored$/i, "");

    const fileName =
      outputMode === "encrypted"
        ? `${baseName}-locked.png`
        : `${baseName}-restored.png`;

    const file = new File([blob], fileName, { type: "image/png" });

    let canNativeShare = false;

    try {
      canNativeShare =
        Boolean(navigator.share) &&
        Boolean(navigator.canShare) &&
        navigator.canShare({ files: [file] });
    } catch {
      canNativeShare = false;
    }

    if (canNativeShare) {
      await navigator.share({
        files: [file],
        title: "PixelLock Image"
      });

      setStatus(
        "PNG opened in the share sheet. Choose Save Image or Save to Files.",
        "success"
      );
      return;
    }

    const blobUrl = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = blobUrl;
    link.download = fileName;
    link.style.display = "none";
    document.body.appendChild(link);
    link.click();
    link.remove();

    window.setTimeout(() => URL.revokeObjectURL(blobUrl), 60000);
    setStatus("PNG download started.", "success");
  } catch (error) {
    if (error?.name === "AbortError") {
      setStatus("Save was canceled.");
    } else {
      console.error(error);

      try {
        const fallbackUrl = outputCanvas.toDataURL("image/png");
        const opened = window.open(fallbackUrl, "_blank");

        if (opened) {
          setStatus(
            "The PNG opened in a new tab. Hold or right-click it to save.",
            "success"
          );
        } else {
          setStatus(
            "The browser blocked the save window. Allow pop-ups and retry.",
            "error"
          );
        }
      } catch (fallbackError) {
        console.error(fallbackError);
        setStatus("This browser could not save the PNG.", "error");
      }
    }
  } finally {
    setBusy(false);
  }
}

function clearOutput() {
  outputContext.clearRect(0, 0, outputCanvas.width, outputCanvas.height);
  outputCanvas.width = 0;
  outputCanvas.height = 0;
  outputCanvas.style.display = "none";
  outputEmpty.style.display = "block";
  outputInfo.textContent = "Nothing generated";
  outputMode = "";
  hasOutput = false;
}

function loadImage(file) {
  if (!file || !file.type.startsWith("image/")) {
    setStatus("Choose a valid image file.", "error");
    return;
  }

  const objectUrl = URL.createObjectURL(file);
  const image = new Image();

  image.onerror = () => {
    URL.revokeObjectURL(objectUrl);
    setStatus("The selected file is not a readable image.", "error");
  };

  image.onload = () => {
    URL.revokeObjectURL(objectUrl);

    const pixelCount = image.naturalWidth * image.naturalHeight;

    if (pixelCount > MAX_PIXEL_COUNT) {
      setStatus(
        "This image is too large for safe in-browser processing.",
        "error"
      );
      return;
    }

    sourceCanvas.width = image.naturalWidth;
    sourceCanvas.height = image.naturalHeight;
    sourceContext.clearRect(0, 0, sourceCanvas.width, sourceCanvas.height);
    sourceContext.drawImage(image, 0, 0);

    sourceCanvas.style.display = "block";
    sourceEmpty.style.display = "none";

    loadedFileName = file.name || "image";
    hasImage = true;
    loadedImageIsLocked = appearsToBeLockedImage();

    originalInfo.textContent =
      `${image.naturalWidth} × ${image.naturalHeight} · ` +
      `${(file.size / 1024 / 1024).toFixed(2)} MB`;

    sourceType.textContent = loadedImageIsLocked
      ? "PixelLock encrypted"
      : "Normal image";

    clearOutput();

    setStatus(
      loadedImageIsLocked
        ? "Encrypted PixelLock PNG detected. Enter the password and press Reverse Image."
        : "Normal image loaded. Enter and confirm a strong password to lock it.",
      "success"
    );

    updateButtons();
  };

  image.src = objectUrl;
}

function resetApp() {
  imageInput.value = "";
  passwordInput.value = "";
  confirmPasswordInput.value = "";

  sourceContext.clearRect(0, 0, sourceCanvas.width, sourceCanvas.height);
  sourceCanvas.width = 0;
  sourceCanvas.height = 0;
  sourceCanvas.style.display = "none";
  sourceEmpty.style.display = "block";

  originalInfo.textContent = "Nothing selected";
  sourceType.textContent = "—";

  hasImage = false;
  loadedImageIsLocked = false;
  loadedFileName = "image";

  clearOutput();
  updatePasswordMeter();
  setStatus("Select an image to begin.");
  updateButtons();
}

imageInput.addEventListener("change", () => {
  loadImage(imageInput.files[0]);
});

passwordInput.addEventListener("input", () => {
  updatePasswordMeter();
  updateButtons();
});

confirmPasswordInput.addEventListener("input", updateButtons);

showPasswordButton.addEventListener("click", () => {
  const show = passwordInput.type === "password";
  const nextType = show ? "text" : "password";

  passwordInput.type = nextType;
  confirmPasswordInput.type = nextType;
  showPasswordButton.textContent = show ? "Hide" : "Show";
});

encryptButton.addEventListener("click", lockImage);
decryptButton.addEventListener("click", reverseImage);
downloadButton.addEventListener("click", saveOutput);
resetButton.addEventListener("click", resetApp);

["dragenter", "dragover"].forEach((eventName) => {
  dropZone.addEventListener(eventName, (event) => {
    event.preventDefault();
    dropZone.classList.add("dragging");
  });
});

["dragleave", "drop"].forEach((eventName) => {
  dropZone.addEventListener(eventName, (event) => {
    event.preventDefault();
    dropZone.classList.remove("dragging");
  });
});

dropZone.addEventListener("drop", (event) => {
  loadImage(event.dataTransfer.files[0]);
});

window.addEventListener("beforeunload", () => {
  passwordInput.value = "";
  confirmPasswordInput.value = "";
});

if (!window.crypto?.subtle) {
  setStatus(
    "Web Crypto is unavailable. Run this page through HTTPS or localhost.",
    "error"
  );
}

updatePasswordMeter();
updateButtons();
