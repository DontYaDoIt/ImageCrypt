const imageInput = document.getElementById("imageInput");
const dropZone = document.getElementById("dropZone");
const passwordInput = document.getElementById("password");
const showPasswordButton = document.getElementById("showPassword");
const strengthInput = document.getElementById("strength");
const strengthValue = document.getElementById("strengthValue");
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

const sourceContext = sourceCanvas.getContext("2d", { willReadFrequently: true });
const outputContext = outputCanvas.getContext("2d", { willReadFrequently: true });

let loadedFileName = "image";
let hasImage = false;
let hasOutput = false;

function setStatus(message, type = "") {
  statusText.textContent = message;
  statusText.className = `status ${type}`.trim();
}

function updateButtons() {
  const ready = hasImage && passwordInput.value.length > 0;
  encryptButton.disabled = !ready;
  decryptButton.disabled = !ready;
  downloadButton.disabled = !hasOutput;
}

function hashPassword(password, strength, width, height) {
  let hash = 2166136261 >>> 0;
  const text = `${password}|${strength}|${width}x${height}`;

  for (let index = 0; index < text.length; index += 1) {
    hash ^= text.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }

  return hash >>> 0;
}

function createRandom(seed) {
  let state = seed >>> 0;

  return function random() {
    state += 0x6d2b79f5;
    let value = state;
    value = Math.imul(value ^ (value >>> 15), value | 1);
    value ^= value + Math.imul(value ^ (value >>> 7), value | 61);
    return ((value ^ (value >>> 14)) >>> 0) / 4294967296;
  };
}

function buildPermutation(length, random) {
  const permutation = new Uint32Array(length);

  for (let index = 0; index < length; index += 1) {
    permutation[index] = index;
  }

  for (let index = length - 1; index > 0; index -= 1) {
    const swapIndex = Math.floor(random() * (index + 1));
    const temporary = permutation[index];
    permutation[index] = permutation[swapIndex];
    permutation[swapIndex] = temporary;
  }

  return permutation;
}

function transformImage(mode) {
  if (!hasImage) {
    setStatus("Choose an image first.", "error");
    return;
  }

  const password = passwordInput.value;

  if (!password) {
    setStatus("Enter a password.", "error");
    return;
  }

  const width = sourceCanvas.width;
  const height = sourceCanvas.height;
  const strength = Number(strengthInput.value);
  const original = sourceContext.getImageData(0, 0, width, height);
  const result = outputContext.createImageData(width, height);
  const pixelCount = width * height;
  const random = createRandom(hashPassword(password, strength, width, height));
  const permutation = buildPermutation(pixelCount, random);

  const xorBytes = new Uint8Array(pixelCount * 3);
  for (let index = 0; index < xorBytes.length; index += 1) {
    xorBytes[index] = Math.floor(random() * 256);
  }

  const rounds = strength;

  if (mode === "encrypt") {
    let working = new Uint8ClampedArray(original.data);

    for (let round = 0; round < rounds; round += 1) {
      const shuffled = new Uint8ClampedArray(working.length);

      for (let pixel = 0; pixel < pixelCount; pixel += 1) {
        const destination = permutation[pixel];
        const sourceOffset = pixel * 4;
        const destinationOffset = destination * 4;
        const keyOffset = pixel * 3;

        shuffled[destinationOffset] = working[sourceOffset] ^ xorBytes[keyOffset];
        shuffled[destinationOffset + 1] = working[sourceOffset + 1] ^ xorBytes[keyOffset + 1];
        shuffled[destinationOffset + 2] = working[sourceOffset + 2] ^ xorBytes[keyOffset + 2];
        shuffled[destinationOffset + 3] = working[sourceOffset + 3];
      }

      working = shuffled;
    }

    result.data.set(working);
    setStatus("Image locked. Download it as PNG.", "success");
  } else {
    let working = new Uint8ClampedArray(original.data);

    for (let round = 0; round < rounds; round += 1) {
      const restored = new Uint8ClampedArray(working.length);

      for (let pixel = 0; pixel < pixelCount; pixel += 1) {
        const encryptedPixel = permutation[pixel];
        const sourceOffset = encryptedPixel * 4;
        const destinationOffset = pixel * 4;
        const keyOffset = pixel * 3;

        restored[destinationOffset] = working[sourceOffset] ^ xorBytes[keyOffset];
        restored[destinationOffset + 1] = working[sourceOffset + 1] ^ xorBytes[keyOffset + 1];
        restored[destinationOffset + 2] = working[sourceOffset + 2] ^ xorBytes[keyOffset + 2];
        restored[destinationOffset + 3] = working[sourceOffset + 3];
      }

      working = restored;
    }

    result.data.set(working);
    setStatus("Reverse completed. A wrong password produces scrambled pixels.", "success");
  }

  outputCanvas.width = width;
  outputCanvas.height = height;
  outputContext.putImageData(result, 0, 0);
  outputCanvas.style.display = "block";
  outputEmpty.style.display = "none";
  hasOutput = true;
  updateButtons();
}

function loadImage(file) {
  if (!file || !file.type.startsWith("image/")) {
    setStatus("Please choose a valid image file.", "error");
    return;
  }

  const reader = new FileReader();

  reader.onerror = () => setStatus("The image could not be read.", "error");

  reader.onload = () => {
    const image = new Image();

    image.onerror = () => setStatus("The selected file is not a readable image.", "error");

    image.onload = () => {
      sourceCanvas.width = image.naturalWidth;
      sourceCanvas.height = image.naturalHeight;
      sourceContext.clearRect(0, 0, sourceCanvas.width, sourceCanvas.height);
      sourceContext.drawImage(image, 0, 0);

      sourceCanvas.style.display = "block";
      sourceEmpty.style.display = "none";
      outputCanvas.style.display = "none";
      outputEmpty.style.display = "block";

      loadedFileName = file.name.replace(/\.[^.]+$/, "") || "image";
      originalInfo.textContent = `${image.naturalWidth} × ${image.naturalHeight}`;
      hasImage = true;
      hasOutput = false;

      setStatus("Image loaded. Enter a password, then lock or reverse it.", "success");
      updateButtons();
    };

    image.src = reader.result;
  };

  reader.readAsDataURL(file);
}

imageInput.addEventListener("change", () => loadImage(imageInput.files[0]));

passwordInput.addEventListener("input", updateButtons);

showPasswordButton.addEventListener("click", () => {
  const showing = passwordInput.type === "text";
  passwordInput.type = showing ? "password" : "text";
  showPasswordButton.textContent = showing ? "👁" : "🙈";
});

strengthInput.addEventListener("input", () => {
  strengthValue.textContent = strengthInput.value;
});

encryptButton.addEventListener("click", () => transformImage("encrypt"));
decryptButton.addEventListener("click", () => transformImage("decrypt"));

downloadButton.addEventListener("click", async () => {
  if (!hasOutput) {
    setStatus("Create an output image before downloading.", "error");
    return;
  }

  downloadButton.disabled = true;
  setStatus("Preparing PNG...");

  try {
    const blob = await new Promise((resolve, reject) => {
      outputCanvas.toBlob((result) => {
        if (result) {
          resolve(result);
        } else {
          reject(new Error("The browser could not create the PNG."));
        }
      }, "image/png");
    });

    const fileName = `${loadedFileName}-pixellock.png`;
    const file = new File([blob], fileName, { type: "image/png" });

    // iPhone/iPad browsers work more reliably through the native share sheet.
    if (
      navigator.share &&
      navigator.canShare &&
      navigator.canShare({ files: [file] })
    ) {
      await navigator.share({
        files: [file],
        title: "PixelLock Image"
      });

      setStatus("PNG opened in the share sheet. Choose Save Image or Save to Files.", "success");
      return;
    }

    // Standard desktop and Android browser download.
    const blobUrl = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = blobUrl;
    link.download = fileName;
    link.style.display = "none";
    document.body.appendChild(link);
    link.click();
    link.remove();

    // Keep the URL alive briefly because Safari may process the click later.
    window.setTimeout(() => URL.revokeObjectURL(blobUrl), 60000);
    setStatus("PNG download started.", "success");
  } catch (error) {
    if (error && error.name === "AbortError") {
      setStatus("Save was canceled.");
    } else {
      console.error(error);

      // Last fallback: open the PNG so it can be held/saved manually.
      try {
        const fallbackUrl = outputCanvas.toDataURL("image/png");
        const openedWindow = window.open(fallbackUrl, "_blank");

        if (openedWindow) {
          setStatus("The PNG opened in a new tab. Hold the image to save it.", "success");
        } else {
          setStatus("The browser blocked the save window. Allow pop-ups and try again.", "error");
        }
      } catch (fallbackError) {
        console.error(fallbackError);
        setStatus("This browser could not save the PNG.", "error");
      }
    }
  } finally {
    downloadButton.disabled = !hasOutput;
  }
});

resetButton.addEventListener("click", () => {
  imageInput.value = "";
  passwordInput.value = "";
  sourceContext.clearRect(0, 0, sourceCanvas.width, sourceCanvas.height);
  outputContext.clearRect(0, 0, outputCanvas.width, outputCanvas.height);
  sourceCanvas.style.display = "none";
  outputCanvas.style.display = "none";
  sourceEmpty.style.display = "block";
  outputEmpty.style.display = "block";
  originalInfo.textContent = "";
  hasImage = false;
  hasOutput = false;
  setStatus("Select an image to begin.");
  updateButtons();
});

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
