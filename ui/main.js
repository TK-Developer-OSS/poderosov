// PoderosoV front end: the tabs, the terminals and the dialogs around them.
// The backend owns the connections; this file only shows them and passes
// the user's input along.

const { invoke, Channel } = window.__TAURI__.core;
const clipboard = window.__TAURI__.clipboardManager;
const fileDialog = window.__TAURI__.dialog;

// The backend stops reading from the server while too much output is waiting
// to be drawn. It is told what has been drawn in steps of this many bytes.
const ACK_BYTES = 32 * 1024;

const LAST_LOGIN_KEY = 'poderosov.lastLogin';

const TERMINAL_OPTIONS = {
  cursorBlink: true,
  fontFamily: '"Courier New", "MS Gothic", Menlo, "DejaVu Sans Mono", monospace',
  fontSize: 12,
  theme: {
    background: '#ffffff',
    foreground: '#000000',
    cursor: '#000000',
    cursorAccent: '#ffffff',
    selectionBackground: '#0078d7',
    selectionForeground: '#ffffff',
    selectionInactiveBackground: '#c8c8c8',
    black: '#000000',
    red: '#c00000',
    green: '#008000',
    yellow: '#808000',
    blue: '#0000c0',
    magenta: '#c000c0',
    cyan: '#008080',
    white: '#c0c0c0',
    brightBlack: '#808080',
    brightRed: '#ff0000',
    brightGreen: '#00c000',
    brightYellow: '#c0c000',
    brightBlue: '#0000ff',
    brightMagenta: '#ff00ff',
    brightCyan: '#00c0c0',
    brightWhite: '#ffffff',
  },
};

// What to tell the user for each way `ssh_connect` can fail.
const FAILURES = {
  connect: 'ホストに接続できませんでした。',
  timeout: 'ホストへの接続がタイムアウトしました。',
  hostKeyRejected: 'ホスト鍵が承認されなかったため、接続を中止しました。',
  knownHosts: 'ホスト鍵の登録ファイルを読み書きできませんでした。',
  privateKey: '鍵ファイルを読み込めませんでした。ファイルとパスフレーズを確認してください。',
  authFailed: '認証に失敗しました。アカウントとパスフレーズを確認してください。',
  ptyRefused: 'サーバーが端末の割り当てを拒否しました。',
  protocol: 'SSH接続を確立できませんでした。',
};

const HOST_KEY_UNKNOWN =
  'このホストには初めて接続します。ホスト鍵を登録して接続を続けますか？';
const HOST_KEY_CHANGED =
  '警告: このホストの鍵が、登録されているものと異なります。' +
  'サーバーが再インストールされたか、別のホストになりすまされている可能性があります。' +
  '登録されている鍵を置き換えて接続を続けますか？';

const $ = (id) => document.getElementById(id);

const tabBar = $('tabs');
const paneArea = $('panes');
const welcome = $('welcome');
const statusBar = $('status');

const login = {
  dialog: $('login'),
  form: $('login-form'),
  fields: $('login-fields'),
  host: $('login-host'),
  port: $('login-port'),
  user: $('login-user'),
  auth: $('login-auth'),
  passphrase: $('login-passphrase'),
  keyPath: $('login-key'),
  browse: $('login-browse'),
  term: $('login-term'),
  message: $('login-message'),
  ok: $('login-ok'),
  cancel: $('login-cancel'),
};

const hostKey = {
  dialog: $('host-key'),
  message: $('host-key-message'),
  host: $('host-key-host'),
  algorithm: $('host-key-algorithm'),
  fingerprint: $('host-key-fingerprint'),
  no: $('host-key-no'),
};

const contextMenu = {
  element: $('context-menu'),
  copy: $('menu-copy'),
  paste: $('menu-paste'),
};

// ---- sessions ----

/** Sessions that have a tab, by id. */
const sessions = new Map();
/** The session whose terminal is in front, if any. */
let active = null;
/** The session the login dialog is waiting on, if any. */
let connecting = null;
let nextSessionId = 1;

class Session {
  constructor({ host, port, user }) {
    this.id = nextSessionId++;
    this.host = host;
    this.port = port;
    this.user = user;
    /** A shell is running at the other end. */
    this.open = false;
    /** Once the other end is gone: `{ error, early }`, see `ended`. */
    this.end = null;
    /** Bytes of output drawn since the backend was last told. */
    this.drawn = 0;
    this.tab = null;
    this.removed = false;

    this.pane = document.createElement('div');
    this.pane.className = 'pane';
    paneArea.append(this.pane);

    this.terminal = new Terminal(TERMINAL_OPTIONS);
    this.fitter = new FitAddon.FitAddon();
    this.terminal.loadAddon(this.fitter);
    this.terminal.open(this.pane);
    this.fitter.fit();

    this.terminal.onData((text) => this.send('session_write', { data: text }));
    this.terminal.onBinary((text) => {
      const data = Array.from(text, (char) => char.charCodeAt(0));
      this.send('session_write_bytes', { data });
    });
    this.terminal.onResize(({ cols, rows }) => {
      this.send('session_resize', { cols, rows });
      if (this === active) showStatus();
    });

    this.channel = new Channel();
    this.channel.onmessage = (message) => this.receive(message);
  }

  /** Logs in and starts a shell. Rejects with the backend's description of what went wrong. */
  async connect({ auth, term }) {
    const { cols, rows } = this.terminal;
    await invoke('ssh_connect', {
      id: this.id,
      request: { host: this.host, port: this.port, user: this.user, auth, term, cols, rows },
      onEvent: this.channel,
    });
    // Output, and even the end of the session, can get here before this does.
    this.open = this.end === null;
    // the window may have been resized while the login was under way
    if (this.terminal.cols !== cols || this.terminal.rows !== rows) {
      this.send('session_resize', { cols: this.terminal.cols, rows: this.terminal.rows });
    }
  }

  send(command, args) {
    if (this.open) invoke(command, { id: this.id, ...args }).catch(reportError);
  }

  /** Handles whatever the backend sends on this session's channel. */
  receive(message) {
    // output already on its way when the tab was closed
    if (this.removed) return;
    if (message instanceof ArrayBuffer) {
      const output = new Uint8Array(message);
      this.terminal.write(output, () => this.acknowledge(output.length));
    } else if (message.type === 'hostKey') {
      askAboutHostKey(this, message);
    } else if (message.type === 'closed') {
      this.ended(message.error);
    }
  }

  acknowledge(bytes) {
    this.drawn += bytes;
    if (this.drawn >= ACK_BYTES) {
      invoke('session_ack', { id: this.id, bytes: this.drawn }).catch(reportError);
      this.drawn = 0;
    }
  }

  /** The other end is gone: `error` says why unless it was an ordinary logout. */
  ended(error) {
    this.open = false;
    // `early`: over before its tab was even shown, e.g. an account without a shell
    this.end = { error, early: this.tab === null };
    if (this.tab) this.showEnd();
  }

  showEnd() {
    const { error, early } = this.end;
    if (error === null && !early) {
      // As in Poderosa, a session that logs out takes its tab with it.
      this.remove();
      return;
    }
    // Left on screen so that whatever the server said last can be read. The
    // reason may come from the server: keep control characters out of the terminal.
    const reason = error === null ? '' : `: ${error.replace(/[\u0000-\u001f\u007f-\u009f]/g, ' ')}`;
    this.terminal.options.disableStdin = true;
    this.terminal.write(`\r\n\x1b[0;31m接続が切断されました${reason}\x1b[0m\x1b[?25l\r\n`);
    this.tab.querySelector('.tab-title').textContent = `${this.host} (切断)`;
    if (this === active) showStatus();
  }

  showTab() {
    this.tab = document.createElement('div');
    this.tab.className = 'tab';
    this.tab.setAttribute('role', 'tab');
    this.tab.title = this.description;

    const title = document.createElement('span');
    title.className = 'tab-title';
    title.textContent = this.host;

    const close = document.createElement('button');
    close.type = 'button';
    close.className = 'tab-close';
    close.title = '閉じる';
    close.textContent = '×';
    close.addEventListener('click', (event) => {
      event.stopPropagation();
      this.close();
    });

    this.tab.append(title, close);
    this.tab.addEventListener('click', () => activate(this));
    tabBar.append(this.tab);
    sessions.set(this.id, this);
    if (this.end) this.showEnd();
  }

  /** Closes the session from this side and removes its tab. */
  close() {
    invoke('session_close', { id: this.id }).catch(reportError);
    this.remove();
  }

  /** Takes the session off the screen. */
  remove() {
    this.open = false;
    this.removed = true;
    sessions.delete(this.id);
    this.tab?.remove();
    this.pane.remove();
    this.terminal.dispose();
    if (this === active) {
      active = null;
      activate([...sessions.values()].at(-1) ?? null);
    }
  }

  get description() {
    const port = this.port === 22 ? '' : `:${this.port}`;
    return `${this.user}@${this.host}${port}`;
  }
}

function activate(session) {
  if (active) {
    active.pane.classList.remove('active');
    active.tab?.classList.remove('active');
  }
  active = session;
  if (active) {
    active.pane.classList.add('active');
    active.tab?.classList.add('active');
    active.terminal.focus();
  }
  welcome.hidden = sessions.size > 0;
  showStatus();
}

/** Brings the next (or, with -1, the previous) tab to the front. */
function cycleTabs(step) {
  const open = [...sessions.values()];
  if (open.length < 2) return;
  const index = open.indexOf(active);
  activate(open[(index + step + open.length) % open.length]);
}

function showStatus() {
  statusBar.classList.remove('error');
  if (!active) {
    statusBar.textContent = '';
    return;
  }
  const { cols, rows } = active.terminal;
  const state = active.open ? '' : '  切断';
  statusBar.textContent = `${active.description}  SSH2  ${cols}x${rows}${state}`;
}

function reportError(error) {
  statusBar.classList.add('error');
  statusBar.textContent = typeof error === 'string' ? error : (error?.message ?? String(error));
}

// Terminals follow the size of the window, in front or not, so that the
// other end always knows how much room there is.
new ResizeObserver(() => {
  requestAnimationFrame(() => {
    for (const session of sessions.values()) session.fitter.fit();
    connecting?.fitter.fit();
  });
}).observe(paneArea);

// ---- login dialog ----

function openLogin() {
  if (login.dialog.open) return;
  restoreLastLogin();
  updateAuthFields();
  showLoginMessage('');
  login.passphrase.value = '';
  login.dialog.showModal();
  const firstEmpty = [login.host, login.user].find((field) => !field.value);
  (firstEmpty ?? login.passphrase).focus();
}

function updateAuthFields() {
  const usesKey = login.auth.value === 'publicKey';
  login.keyPath.disabled = !usesKey;
  login.keyPath.required = usesKey;
  login.browse.disabled = !usesKey;
}

function showLoginMessage(text, busy = false) {
  login.message.textContent = text;
  login.message.classList.toggle('busy', busy);
}

function setLoginBusy(busy) {
  login.fields.disabled = busy;
  login.ok.disabled = busy;
}

function describeFailure(failure) {
  // anything but the backend's own failure object is a bug worth seeing as it is
  if (typeof failure !== 'object' || failure === null || !('kind' in failure)) {
    return String(failure);
  }
  const lines = [FAILURES[failure.kind] ?? failure.kind];
  if (failure.kind === 'authFailed' && failure.methods.length > 0) {
    lines.push(`サーバーが受け付ける認証方法: ${failure.methods.join(', ')}`);
  }
  if (failure.detail) lines.push(failure.detail);
  return lines.join('\n');
}

/** The last connection's settings, without its secrets, prefill the dialog. */
function restoreLastLogin() {
  let last;
  try {
    last = JSON.parse(localStorage.getItem(LAST_LOGIN_KEY));
  } catch {
    return;
  }
  if (!last) return;
  login.host.value = last.host ?? '';
  login.port.value = last.port ?? 22;
  login.user.value = last.user ?? '';
  login.auth.value = last.auth === 'publicKey' ? 'publicKey' : 'password';
  login.keyPath.value = last.keyPath ?? '';
  if ([...login.term.options].some((option) => option.value === last.term)) {
    login.term.value = last.term;
  }
}

function rememberLogin() {
  const last = {
    host: login.host.value.trim(),
    port: Number(login.port.value),
    user: login.user.value.trim(),
    auth: login.auth.value,
    keyPath: login.keyPath.value.trim(),
    term: login.term.value,
  };
  localStorage.setItem(LAST_LOGIN_KEY, JSON.stringify(last));
}

login.form.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (connecting) return;

  const target = {
    host: login.host.value.trim(),
    port: Number(login.port.value),
    user: login.user.value.trim(),
  };
  const auth =
    login.auth.value === 'publicKey'
      ? { method: 'publicKey', keyPath: login.keyPath.value.trim(), passphrase: login.passphrase.value }
      : { method: 'password', password: login.passphrase.value };
  rememberLogin();

  // The terminal exists before the connection so that the server can be told
  // its real size; it only gets a tab once the login has succeeded.
  const session = new Session(target);
  connecting = session;
  setLoginBusy(true);
  showLoginMessage('接続中...', true);
  try {
    await session.connect({ auth, term: login.term.value });
  } catch (failure) {
    session.remove();
    showLoginMessage(failure?.kind === 'cancelled' ? '' : describeFailure(failure));
    return;
  } finally {
    connecting = null;
    setLoginBusy(false);
    // a host key question about an attempt that is over has no one to answer to
    if (hostKey.dialog.open) hostKey.dialog.close();
  }

  login.passphrase.value = '';
  login.dialog.close();
  session.showTab();
  activate(session);
});

/** Cancel, or Esc: abandons a login in progress, otherwise closes the dialog. */
function cancelLogin() {
  if (connecting) {
    // `ssh_connect` then fails with kind "cancelled" and the form comes back
    invoke('session_close', { id: connecting.id }).catch(reportError);
  } else {
    login.dialog.close();
  }
}

login.cancel.addEventListener('click', cancelLogin);
login.dialog.addEventListener('cancel', (event) => {
  event.preventDefault();
  cancelLogin();
});
login.dialog.addEventListener('close', () => active?.terminal.focus());
login.auth.addEventListener('change', updateAuthFields);
login.browse.addEventListener('click', async () => {
  try {
    const path = await fileDialog.open({ title: '秘密鍵ファイルの選択', multiple: false, directory: false });
    if (path) login.keyPath.value = path;
  } catch (error) {
    showLoginMessage(String(error));
  }
});
$('new-connection').addEventListener('click', openLogin);

// ---- host key prompt ----

function askAboutHostKey(session, key) {
  hostKey.dialog.classList.toggle('changed', key.changed);
  hostKey.message.textContent = key.changed ? HOST_KEY_CHANGED : HOST_KEY_UNKNOWN;
  hostKey.host.textContent = key.port === 22 ? key.host : `${key.host}:${key.port}`;
  hostKey.algorithm.textContent = key.algorithm;
  hostKey.fingerprint.textContent = key.fingerprint;

  // Esc leaves the previous answer in returnValue, so it has to start out empty.
  hostKey.dialog.returnValue = '';
  hostKey.dialog.onclose = () => {
    const accept = hostKey.dialog.returnValue === 'yes';
    invoke('host_key_reply', { id: session.id, accept }).catch(reportError);
  };
  hostKey.dialog.showModal();
  hostKey.no.focus();
}

// ---- clipboard ----

async function copySelection() {
  const text = active?.terminal.getSelection();
  if (text) await clipboard.writeText(text);
}

async function pasteClipboard() {
  const session = active;
  if (!session?.open) return;
  let text;
  try {
    text = await clipboard.readText();
  } catch {
    return; // the clipboard holds something other than text
  }
  // paste() rather than a plain write: it honours bracketed paste mode
  if (text) session.terminal.paste(text);
}

function showContextMenu(event) {
  event.preventDefault();
  if (!active) return;
  contextMenu.copy.disabled = !active.terminal.hasSelection();
  contextMenu.paste.disabled = !active.open;
  contextMenu.element.hidden = false;
  const { offsetWidth, offsetHeight } = contextMenu.element;
  const left = Math.min(event.clientX, window.innerWidth - offsetWidth - 2);
  const top = Math.min(event.clientY, window.innerHeight - offsetHeight - 2);
  contextMenu.element.style.left = `${Math.max(0, left)}px`;
  contextMenu.element.style.top = `${Math.max(0, top)}px`;
}

function hideContextMenu() {
  contextMenu.element.hidden = true;
}

function runFromMenu(action) {
  return () => {
    hideContextMenu();
    action().catch(reportError);
    active?.terminal.focus();
  };
}

paneArea.addEventListener('contextmenu', showContextMenu);
// keeps the focus, and with it the selection highlight, in the terminal
contextMenu.element.addEventListener('mousedown', (event) => event.preventDefault());
contextMenu.copy.addEventListener('click', runFromMenu(copySelection));
contextMenu.paste.addEventListener('click', runFromMenu(pasteClipboard));
window.addEventListener('blur', hideContextMenu);
window.addEventListener(
  'mousedown',
  (event) => {
    if (!contextMenu.element.contains(event.target)) hideContextMenu();
  },
  true,
);
// The webview's own menu (reload, print, ...) has no place here. Text fields keep theirs.
window.addEventListener('contextmenu', (event) => {
  if (!event.target.closest('input')) event.preventDefault();
});

// ---- keyboard ----

// Poderosa's defaults. Matched on the physical key, since Alt changes the
// character some layouts produce.
const SHORTCUTS = [
  { code: 'KeyN', alt: true, run: openLogin },
  { code: 'KeyC', alt: true, run: copySelection },
  { code: 'KeyV', alt: true, run: pasteClipboard },
  { code: 'Tab', ctrl: true, run: () => cycleTabs(1) },
  { code: 'Tab', ctrl: true, shift: true, run: () => cycleTabs(-1) },
];

function matches(shortcut, event) {
  return (
    event.code === shortcut.code &&
    event.altKey === Boolean(shortcut.alt) &&
    event.ctrlKey === Boolean(shortcut.ctrl) &&
    event.shiftKey === Boolean(shortcut.shift) &&
    !event.metaKey
  );
}

/** Keys the webview would act on itself: reload, find, print, zoom, caret browsing. */
function isWebviewShortcut(event) {
  if (['F3', 'F5', 'F7'].includes(event.key)) return true;
  const codes = ['KeyF', 'KeyG', 'KeyP', 'KeyR', 'KeyU', 'Equal', 'Minus', 'Digit0'];
  return event.ctrlKey && !event.altKey && codes.includes(event.code);
}

// Capturing, so that these are seen before the terminal turns the key into input.
window.addEventListener(
  'keydown',
  (event) => {
    if (event.isComposing) return;
    hideContextMenu();
    // Stops the webview, not the terminal: F5 or Ctrl+R still reach the shell.
    if (isWebviewShortcut(event)) event.preventDefault();
    if (document.querySelector('dialog[open]')) return;

    const shortcut = SHORTCUTS.find((candidate) => matches(candidate, event));
    if (!shortcut) return;
    event.preventDefault();
    event.stopPropagation();
    Promise.resolve(shortcut.run()).catch(reportError);
  },
  true,
);

window.addEventListener('error', (event) => reportError(event.message));
window.addEventListener('unhandledrejection', (event) => reportError(event.reason));
