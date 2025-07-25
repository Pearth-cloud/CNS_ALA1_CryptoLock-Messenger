let rsaKeyPair;
let encryptedAESKeyBase64, encryptedData = { iv: null, ciphertext: null };

// Generate RSA Keypair
async function generateKeys() {
  rsaKeyPair = await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"]
  );
}

// Toggle light/dark mode with label
function toggleMode() {
  const body = document.body;
  const label = document.getElementById("modeLabel");
  body.classList.toggle("light");
  const isLight = body.classList.contains("light");
  if (label) label.textContent = isLight ? "Light Mode" : "Dark Mode";
}

// Passphrase auth
function checkPassphrase() {
  const pass = document.getElementById("passphraseInput").value;
  if (pass === "secure123") {
    document.getElementById("loginScreen").style.display = "none";
    document.getElementById("mainApp").style.display = "block";
  } else {
    alert("❌ Incorrect passphrase.");
  }
}

// Encrypt
async function encryptMessage() {
  const message = document.getElementById("message").value;
  if (!message) return alert("Please enter a message.");

  const enc = new TextEncoder();
  const encodedMessage = enc.encode(message);

  const aesKey = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 128 },
    true,
    ["encrypt", "decrypt"]
  );

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, encodedMessage);
  encryptedData = { iv, ciphertext };

  const rawAESKey = await crypto.subtle.exportKey("raw", aesKey);
  const encryptedAESKey = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, rsaKeyPair.publicKey, rawAESKey);

  encryptedAESKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(encryptedAESKey)));
  const encryptedTextBase64 = btoa(String.fromCharCode(...new Uint8Array(ciphertext)));

  document.getElementById("encryptedKey").innerText = encryptedAESKeyBase64;
  document.getElementById("encryptedText").innerText = encryptedTextBase64;
  document.getElementById("decryptedText").innerText = "🔒 Encrypted. Click 'Decrypt' to view.";
}

// Decrypt
async function decryptMessage() {
  if (!encryptedData.iv || !encryptedData.ciphertext || !encryptedAESKeyBase64) {
    return alert("Nothing to decrypt.");
  }

  try {
    const encryptedKeyBytes = Uint8Array.from(atob(encryptedAESKeyBase64), c => c.charCodeAt(0));
    const rawAESKey = await crypto.subtle.decrypt(
      { name: "RSA-OAEP" },
      rsaKeyPair.privateKey,
      encryptedKeyBytes
    );

    const aesKey = await crypto.subtle.importKey("raw", rawAESKey, { name: "AES-GCM" }, false, ["decrypt"]);

    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: encryptedData.iv },
      aesKey,
      encryptedData.ciphertext
    );

    const dec = new TextDecoder();
    document.getElementById("decryptedText").innerText = dec.decode(decrypted);
  } catch (err) {
    document.getElementById("decryptedText").innerText = "❌ Failed to decrypt.";
  }
}

// Share encrypted blob
function copyBlob() {
  const message = document.getElementById("message").value;
  if (!message) return alert("Message is empty.");
  const blob = btoa(message);
  const link = `${location.origin}${location.pathname}#blob=${blob}`;
  navigator.clipboard.writeText(link);
  alert("🔗 Link copied to clipboard!");
}

// On page load
window.onload = () => {
  generateKeys();

  const isLight = document.body.classList.contains("light");
  const label = document.getElementById("modeLabel");
  if (label) label.textContent = isLight ? "Light Mode" : "Dark Mode";

  if (window.location.hash.startsWith("#blob=")) {
    const blob = window.location.hash.substring(6);
    document.getElementById("message").value = atob(blob);
    window.location.hash = "";
  }
};
