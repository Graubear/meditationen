/**
 * meditation-player.js
 *
 * Browser player for AES-256-GCM encrypted MP3 files using the GMA1 format:
 *   bytes 0..3   : ASCII "GMA1"
 *   byte  4      : version (currently 1)
 *   bytes 5..16  : 12-byte AES-GCM IV
 *   bytes 17..   : ciphertext including the 16-byte GCM authentication tag
 *
 * Public API:
 *   MeditationPlayer.setKey("<Base64 AES-256 key>");
 *   MeditationPlayer.setBaseUrl("https://example.github.io/repo/");
 *   MeditationPlayer.init();
 *
 * HTML:
 *   <div class="meditation-player"
 *        data-title="Vergebung"
 *        data-file="enc_audio/vergebung.mp3.enc"></div>
 *
 *   <div class="meditation-playlist"
 *        data-title="Wanne"
 *        data-files="
 *          enc_audio/PARTS/teil1.mp3.enc;
 *          pause:30;
 *          enc_audio/PARTS/teil2.mp3.enc
 *        "></div>
 */
(function (global) {
    "use strict";

    const MAGIC = "GMA1";
    const VERSION = 1;
    const HEADER_BYTES = 17;
    const GCM_TAG_BYTES = 16;

    let keyBase64 = null;
    let importedKeyPromise = null;
    let defaultBaseUrl = null;
    const instances = new Set();

    function setKey(value) {
        if (typeof value !== "string" || value.trim() === "") {
            throw new Error("MeditationPlayer.setKey(...) benötigt einen Base64-Schlüssel.");
        }

        const bytes = base64ToBytes(value);

        if (bytes.length !== 32) {
            throw new Error(
                `Der AES-256-Schlüssel muss 32 Byte lang sein, ist aber ${bytes.length} Byte lang.`
            );
        }

        keyBase64 = value.trim();
        importedKeyPromise = null;
    }

    function setBaseUrl(value) {
        if (value == null || String(value).trim() === "") {
            defaultBaseUrl = null;
            return;
        }

        const normalized = String(value).trim();
        defaultBaseUrl = normalized.endsWith("/") ? normalized : normalized + "/";
    }

    function init(root = document) {
        injectStyles(root);

        const elements = root.querySelectorAll(
            ".meditation-player, .meditation-playlist"
        );

        for (const element of elements) {
            if (element.dataset.meditationInitialized === "true") {
                continue;
            }

            element.dataset.meditationInitialized = "true";

            try {
                const instance = element.classList.contains("meditation-playlist")
                    ? new PlaylistPlayer(element)
                    : new SinglePlayer(element);

                instances.add(instance);
            } catch (error) {
                console.error("MeditationPlayer:", error);
                renderInitializationError(element, error);
            }
        }
    }

    function disposeAll() {
        for (const instance of instances) {
            instance.dispose();
        }
        instances.clear();
    }

    class BasePlayer {
        constructor(container) {
            this.container = container;
            this.objectUrl = null;
            this.disposed = false;
            this.loadToken = 0;

            this.baseUrl =
                container.dataset.baseUrl?.trim() ||
                defaultBaseUrl ||
                document.baseURI;

            this.title = container.dataset.title?.trim() || "Meditation";

            this.renderBase();
        }

        renderBase() {
            this.container.replaceChildren();
            this.container.classList.add("mp-root");

            this.titleElement = document.createElement("div");
            this.titleElement.className = "mp-title";
            this.titleElement.textContent = this.title;

            this.loadButton = document.createElement("button");
            this.loadButton.type = "button";
            this.loadButton.className = "mp-load-button";
            this.loadButton.textContent = "Audio laden";

            this.statusElement = document.createElement("div");
            this.statusElement.className = "mp-status";
            this.statusElement.setAttribute("aria-live", "polite");

            this.audio = document.createElement("audio");
            this.audio.className = "mp-audio";
            this.audio.controls = true;
            this.audio.preload = "none";
            this.audio.hidden = true;

            this.container.append(
                this.titleElement,
                this.loadButton,
                this.statusElement,
                this.audio
            );
        }

        resolveFile(file) {
            try {
                return new URL(file, this.baseUrl).href;
            } catch (error) {
                throw new Error(`Ungültiger Dateipfad: ${file}`, { cause: error });
            }
        }

        async decryptFile(file, token) {
            ensureKeyWasSet();

            const url = this.resolveFile(file);
            const response = await fetch(url);

            if (!response.ok) {
                throw new Error(`Download fehlgeschlagen: HTTP ${response.status} (${url})`);
            }

            const encryptedFile = new Uint8Array(await response.arrayBuffer());

            if (token !== this.loadToken || this.disposed) {
                throw new CancelledError();
            }

            if (encryptedFile.length < HEADER_BYTES + GCM_TAG_BYTES) {
                throw new Error("Die verschlüsselte Datei ist zu kurz.");
            }

            const magic = String.fromCharCode(
                encryptedFile[0],
                encryptedFile[1],
                encryptedFile[2],
                encryptedFile[3]
            );

            if (magic !== MAGIC) {
                throw new Error(
                    `Ungültiger Dateikopf: erwartet "${MAGIC}", erhalten "${magic}".`
                );
            }

            const version = encryptedFile[4];

            if (version !== VERSION) {
                throw new Error(`Nicht unterstützte GMA-Version: ${version}.`);
            }

            const iv = encryptedFile.slice(5, 17);
            const ciphertext = encryptedFile.slice(17);
            const cryptoKey = await getCryptoKey();

            if (token !== this.loadToken || this.disposed) {
                throw new CancelledError();
            }

            try {
                return await crypto.subtle.decrypt(
                    {
                        name: "AES-GCM",
                        iv,
                        tagLength: 128
                    },
                    cryptoKey,
                    ciphertext
                );
            } catch (error) {
                throw new Error(
                    "Entschlüsselung fehlgeschlagen. Schlüssel, Header oder Datei stimmen nicht überein.",
                    { cause: error }
                );
            }
        }

        setAudioBuffer(buffer) {
            this.revokeObjectUrl();

            const blob = new Blob([buffer], { type: "audio/mpeg" });
            this.objectUrl = URL.createObjectURL(blob);

            this.audio.src = this.objectUrl;
            this.audio.hidden = false;
            this.audio.load();
        }

        async tryPlay() {
            try {
                await this.audio.play();
                return true;
            } catch (error) {
                console.warn("MeditationPlayer: Wiedergabe wurde blockiert.", error);
                this.setStatus("Geladen – bitte Play drücken.", false);
                return false;
            }
        }

        setStatus(message, isError = false) {
            this.statusElement.textContent = message || "";
            this.statusElement.classList.toggle("mp-error", isError);
        }

        setLoading(isLoading) {
            this.loadButton.disabled = isLoading;
            this.container.classList.toggle("mp-loading", isLoading);
        }

        beginLoad() {
            this.loadToken += 1;
            return this.loadToken;
        }

        revokeObjectUrl() {
            if (this.objectUrl !== null) {
                URL.revokeObjectURL(this.objectUrl);
                this.objectUrl = null;
            }
        }

        dispose() {
            this.disposed = true;
            this.loadToken += 1;
            this.audio.pause();
            this.audio.removeAttribute("src");
            this.audio.load();
            this.revokeObjectUrl();
        }
    }

    class SinglePlayer extends BasePlayer {
        constructor(container) {
            super(container);

            this.file = container.dataset.file?.trim();

            if (!this.file) {
                throw new Error(
                    'Ein Einzelplayer benötigt "data-file".'
                );
            }

            this.audio.loop = true;
            this.loadButton.textContent = "Audio laden";
            this.loadButton.addEventListener("click", () => this.load());
        }

        async load() {
            const token = this.beginLoad();
            this.setLoading(true);
            this.setStatus("Audio wird geladen und entschlüsselt …");

            try {
                const buffer = await this.decryptFile(this.file, token);

                if (token !== this.loadToken || this.disposed) {
                    return;
                }

                this.setAudioBuffer(buffer);
                this.setLoading(false);
                this.loadButton.hidden = true;
                this.setStatus("");
                await this.tryPlay();
            } catch (error) {
                if (!(error instanceof CancelledError)) {
                    console.error("MeditationPlayer:", error);
                    this.setStatus(error.message || "Audio konnte nicht geladen werden.", true);
                    this.setLoading(false);
                }
            }
        }
    }

    class PlaylistPlayer extends BasePlayer {
        constructor(container) {
            super(container);

            const source = container.dataset.files || "";
            this.entries = parsePlaylist(source, this.resolveFile.bind(this));
            this.trackCount = this.entries.filter(entry => entry.type === "track").length;

            if (this.trackCount === 0) {
                throw new Error(
                    'Eine Playlist benötigt mindestens eine Datei in "data-files".'
                );
            }

            this.audio.loop = false;
            this.sequenceIndex = -1;
            this.pauseToken = 0;

            this.trackInfo = document.createElement("div");
            this.trackInfo.className = "mp-track-info";
            this.trackInfo.textContent = `Teil 1 von ${this.trackCount}`;
            this.container.append(this.trackInfo);

            this.loadButton.textContent = "Playlist laden";
            this.loadButton.addEventListener("click", () => this.start());
            this.audio.addEventListener("ended", () => this.advance());
        }

        async start() {
            this.loadButton.hidden = true;
            this.sequenceIndex = -1;
            this.pauseToken += 1;
            await this.advance();
        }

        async advance() {
            if (this.disposed) {
                return;
            }

            const localPauseToken = ++this.pauseToken;

            while (++this.sequenceIndex < this.entries.length) {
                const entry = this.entries[this.sequenceIndex];

                if (entry.type === "pause") {
                    this.audio.pause();
                    this.setStatus("");
                    await this.runPause(entry.seconds, localPauseToken);

                    if (
                        this.disposed ||
                        localPauseToken !== this.pauseToken
                    ) {
                        return;
                    }

                    continue;
                }

                await this.loadTrack(entry);
                return;
            }

            this.finishPlaylist();
        }

        async loadTrack(entry) {
            const token = this.beginLoad();
            this.setLoading(true);
            this.setStatus("Teil wird geladen und entschlüsselt …");
            this.trackInfo.textContent =
                `Teil ${entry.trackNumber} von ${this.trackCount}`;

            try {
                const buffer = await this.decryptFile(entry.file, token);

                if (token !== this.loadToken || this.disposed) {
                    return;
                }

                this.setAudioBuffer(buffer);
                this.setLoading(false);
                this.setStatus("");
                await this.tryPlay();
            } catch (error) {
                if (!(error instanceof CancelledError)) {
                    console.error("MeditationPlayer:", error);
                    this.setLoading(false);
                    this.setStatus(error.message || "Teil konnte nicht geladen werden.", true);
                    this.loadButton.hidden = false;
                    this.loadButton.disabled = false;
                    this.loadButton.textContent = "Playlist neu starten";
                }
            }
        }

        async runPause(seconds, token) {
            const wholeSeconds = Math.max(0, Math.ceil(seconds));

            for (let remaining = wholeSeconds; remaining > 0; remaining--) {
                if (this.disposed || token !== this.pauseToken) {
                    return;
                }

                this.trackInfo.textContent =
                    `Pause – noch ${remaining} Sekunde${remaining === 1 ? "" : "n"}`;

                await sleep(1000);
            }
        }

        finishPlaylist() {
            this.audio.pause();
            this.setStatus("");
            this.trackInfo.textContent = "Playlist beendet";
            this.loadButton.hidden = false;
            this.loadButton.disabled = false;
            this.loadButton.textContent = "Playlist erneut starten";
            this.sequenceIndex = -1;
        }

        dispose() {
            this.pauseToken += 1;
            super.dispose();
        }
    }

    function parsePlaylist(source, resolveFile) {
        const rawEntries = source
            .split(/[;\n]+/)
            .map(value => value.trim())
            .filter(Boolean);

        const entries = [];
        let trackNumber = 0;

        for (const rawEntry of rawEntries) {
            const pauseMatch = rawEntry.match(/^pause\s*:?\s*(\d+(?:[.,]\d+)?)$/i);

            if (pauseMatch) {
                const seconds = Number(pauseMatch[1].replace(",", "."));

                if (!Number.isFinite(seconds) || seconds < 0) {
                    throw new Error(`Ungültige Pause: ${rawEntry}`);
                }

                entries.push({ type: "pause", seconds });
                continue;
            }

            trackNumber += 1;
            entries.push({
                type: "track",
                file: resolveFile(rawEntry),
                trackNumber
            });
        }

        return entries;
    }

    function ensureKeyWasSet() {
        if (!keyBase64) {
            throw new Error(
                "Kein Schlüssel gesetzt. Zuerst MeditationPlayer.setKey(...) aufrufen."
            );
        }

        if (!global.crypto?.subtle) {
            throw new Error(
                "Dieser Browser unterstützt die Web Crypto API nicht."
            );
        }
    }

    function getCryptoKey() {
        ensureKeyWasSet();

        if (!importedKeyPromise) {
            const bytes = base64ToBytes(keyBase64);

            importedKeyPromise = crypto.subtle.importKey(
                "raw",
                bytes,
                { name: "AES-GCM" },
                false,
                ["decrypt"]
            );
        }

        return importedKeyPromise;
    }

    function base64ToBytes(base64) {
        const normalized = String(base64).replace(/\s+/g, "");
        let binary;

        try {
            binary = atob(normalized);
        } catch (error) {
            throw new Error("Der Schlüssel ist kein gültiger Base64-String.", {
                cause: error
            });
        }

        const bytes = new Uint8Array(binary.length);

        for (let index = 0; index < binary.length; index++) {
            bytes[index] = binary.charCodeAt(index);
        }

        return bytes;
    }

    function sleep(milliseconds) {
        return new Promise(resolve => setTimeout(resolve, milliseconds));
    }

    function injectStyles(root) {
        const documentRef = root.ownerDocument || root;

        if (documentRef.getElementById("meditation-player-styles")) {
            return;
        }

        const style = documentRef.createElement("style");
        style.id = "meditation-player-styles";
        style.textContent = `
            .mp-root {
                box-sizing: border-box;
                width: 100%;
                font-family: sans-serif;
            }

            .mp-title {
                margin-bottom: 6px;
                font-weight: 600;
            }

            .mp-load-button {
                cursor: pointer;
                padding: 7px 12px;
            }

            .mp-load-button:disabled {
                cursor: progress;
            }

            .mp-status {
                min-height: 1.2em;
                margin-top: 8px;
                font-size: 13px;
            }

            .mp-error {
                color: #a40000;
            }

            .mp-audio {
                display: block;
                width: 100%;
                margin-top: 10px;
            }

            .mp-track-info {
                margin-top: 6px;
                text-align: center;
                font-size: 14px;
            }
        `;

        documentRef.head.append(style);
    }

    function renderInitializationError(element, error) {
        element.replaceChildren();
        element.classList.add("mp-root");

        const message = document.createElement("div");
        message.className = "mp-status mp-error";
        message.textContent =
            error?.message || "Player konnte nicht initialisiert werden.";

        element.append(message);
    }

    class CancelledError extends Error {
        constructor() {
            super("Vorgang abgebrochen.");
            this.name = "CancelledError";
        }
    }

    global.MeditationPlayer = Object.freeze({
        setKey,
        setBaseUrl,
        init,
        disposeAll
    });

    global.addEventListener("beforeunload", disposeAll);
})(window);
