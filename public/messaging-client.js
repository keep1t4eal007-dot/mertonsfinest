(function () {
  "use strict";

  var root = document.getElementById("app");
  var user = null;
  var artists = [];
  var conversations = [];
  var activeId = "";
  var authMode = "login";
  var socket = null;
  var serverReady = false;
  var pendingArtistId = "";
  var renderVersion = 0;
  var defaultApiBase = /(^localhost$|^127\.0\.0\.1$|\.onrender\.com$)/i.test(window.location.hostname) ? window.location.origin : "";
  var apiBase = String(window.SCENESPOOL_API_URL || defaultApiBase).replace(/\/$/, "");
  var apiToken = "";
  try { apiToken = sessionStorage.getItem("scenespoolApiToken") || ""; } catch (_) {}

  function escapeHtml(value) {
    return String(value == null ? "" : value).replace(/[&<>"']/g, function (char) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[char];
    });
  }

  async function api(path, method, body, extraHeaders) {
    if (!apiBase) throw new Error("The shared server has not been connected yet.");
    var options = {
      method: method || "GET",
      credentials: "omit",
      headers: {}
    };
    if (apiToken) options.headers.Authorization = "Bearer " + apiToken;
    if (body !== undefined) {
      if ((window.Blob && body instanceof window.Blob) || body instanceof ArrayBuffer || body instanceof Uint8Array) {
        options.headers["Content-Type"] = body.type || "application/octet-stream";
        options.body = body;
      } else {
        options.headers["Content-Type"] = "application/json";
        options.body = JSON.stringify(body);
      }
    }
    if (extraHeaders) Object.keys(extraHeaders).forEach(function (key) { options.headers[key] = extraHeaders[key]; });
    var response = await fetch(apiBase + "/api" + path, options);
    var result = await response.json().catch(function () { return {}; });
    if (!response.ok) {
      var failure = new Error(result.error || "The server could not complete that request.");
      failure.status = response.status;
      throw failure;
    }
    return result;
  }

  function notify(message) {
    var toast = document.getElementById("toast");
    if (!toast) return;
    toast.textContent = message;
    toast.classList.add("show");
    clearTimeout(notify.timer);
    notify.timer = setTimeout(function () { toast.classList.remove("show"); }, 2800);
  }

  function setMessagesNav() {
    document.querySelectorAll(".nav-link").forEach(function (item) {
      item.classList.toggle("active", item.dataset.view === "messages");
    });
  }

  function formattedTime(value, short) {
    if (!value) return "";
    var date = new Date(value);
    if (Number.isNaN(date.getTime())) return "";
    var sameDay = date.toDateString() === new Date().toDateString();
    if (sameDay) return date.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" });
    return date.toLocaleDateString("en-GB", short
      ? { day: "numeric", month: "short" }
      : { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });
  }

  function initials(name) {
    return String(name || "Artist").trim().split(/\s+/).map(function (part) {
      return part.charAt(0);
    }).join("").slice(0, 2).toUpperCase();
  }

  function titleFor(chat) {
    return chat.title || chat.name || "Artist chat";
  }

  function conversationList() {
    if (!conversations.length) {
      return '<div class="chat-list-empty">No conversations yet. Message an artist or start a group chat.</div>';
    }
    return conversations.map(function (chat) {
      var last = chat.latest;
      var preview = last ? last.text : "Start the conversation";
      var isGroup = chat.type === "group";
      return '<button class="chat-list-item ' + (chat.id === activeId ? "active" : "") +
        '" type="button" data-open-chat="' + escapeHtml(chat.id) + '">' +
        '<span class="chat-list-avatar ' + (isGroup ? "group" : "") + '">' +
        (isGroup ? "✦" : escapeHtml(initials(titleFor(chat)))) + '</span>' +
        '<span class="chat-list-copy"><strong>' + escapeHtml(titleFor(chat)) + '</strong>' +
        '<small>' + (isGroup ? (chat.participants.length + " artists · ") : "") +
        escapeHtml(preview.slice(0, 62)) + (preview.length > 62 ? "…" : "") + '</small></span>' +
        '<time>' + escapeHtml(formattedTime(last ? last.createdAt : chat.updatedAt, true)) + '</time></button>';
    }).join("");
  }

  function messageThread(chat, messages) {
    var otherMembers = (chat.participants || []).filter(function (member) {
      return Number(member.id) !== Number(user.id);
    });
    var detail = chat.type === "group"
      ? (chat.participants || []).map(function (member) { return member.displayName; }).join(" · ")
      : (otherMembers[0] ? "@" + String(otherMembers[0].handle || "artist").replace(/^@/, "") : "");
    var contents = messages.length ? messages.map(function (message) {
      var mine = Number(message.senderId) === Number(user.id);
      return '<div class="chat-message ' + (mine ? "mine" : "") + '">' +
        '<div class="chat-message-author">' + escapeHtml(mine ? "You" : message.senderName) + '</div>' +
        '<div class="chat-message-bubble">' + escapeHtml(message.text).replace(/\n/g, "<br>") + '</div>' +
        '<time>' + escapeHtml(formattedTime(message.createdAt, false)) + '</time></div>';
    }).join("") : '<div class="chat-thread-empty"><span>♫</span><strong>Start the conversation.</strong>' +
      '<p>Share a link, idea or a quick hello with ' + escapeHtml(titleFor(chat)) + '.</p></div>';
    return '<div class="chat-conversation-head"><div><div class="eyebrow">' +
      (chat.type === "group" ? "Group chat" : "Direct message") + '</div><h2>' +
      escapeHtml(titleFor(chat)) + '</h2><p>' + escapeHtml(detail) + '</p></div></div>' +
      '<div class="messages-preview-note"><span>i</span><p>Messages are stored on the shared server and sent over HTTPS. They are not end-to-end encrypted.</p></div>' +
      '<div class="chat-thread" id="chatThread" aria-live="polite">' + contents +
      '</div><form class="chat-compose" id="chatComposeForm" data-chat-id="' +
      escapeHtml(chat.id) + '"><label class="sr-only" for="chatMessageText">Write a message</label>' +
      '<textarea id="chatMessageText" name="message" maxlength="2000" required rows="2" ' +
      'placeholder="Write a message…"></textarea><div><small>Visible to conversation members · sent over HTTPS</small>' +
      '<button class="btn btn-dark" type="submit">Send ↗</button></div></form>';
  }

  function authPage(error) {
    var register = authMode === "register";
    var fields = register
      ? '<label class="chat-form-label">Artist name<input class="chat-create-input" name="displayName" required maxlength="60" autocomplete="name"></label>' +
        '<label class="chat-form-label">Handle<input class="chat-create-input" name="handle" required minlength="3" maxlength="24" pattern="[A-Za-z0-9_]{3,24}" placeholder="yourhandle" autocomplete="username"></label>' +
        '<label class="chat-form-label">Genre<input class="chat-create-input" name="genre" required maxlength="60" placeholder="UK Rap, R&B, Afrobeats…"></label>' +
        '<label class="chat-form-label">City<input class="chat-create-input" name="city" required maxlength="80" placeholder="London"></label>'
      : "";
    return '<section class="messages-page"><div class="messages-heading"><div><div class="eyebrow">Artist-to-artist messages</div>' +
      '<h1>Your <em>messages.</em></h1><p>Sign in to message artists and make group chats.</p></div></div>' +
      '<div class="messages-preview-note"><span>✦</span><p><strong>About messages:</strong> chats are stored on the shared server and visible to conversation members. They are not end-to-end encrypted.</p></div>' +
      '<div class="chat-auth-wrap"><div class="chat-create-card"><div class="eyebrow">' +
      (register ? "Join the community" : "Welcome back") + '</div><h2>' +
      (register ? "Create your artist account." : "Sign in to your account.") + '</h2>' +
      '<p>Use one account for your artist profile and conversations.</p>' +
      '<form id="chatAuthForm" data-mode="' + (register ? "register" : "login") + '">' +
      fields + '<label class="chat-form-label">Email<input class="chat-create-input" name="email" type="email" required maxlength="254" autocomplete="email"></label>' +
      '<label class="chat-form-label">Password<input class="chat-create-input" name="password" type="password" required minlength="' +
      (register ? "12" : "1") + '" maxlength="200" autocomplete="' + (register ? "new-password" : "current-password") + '">' +
      (register ? '<span class="chat-auth-hint">Use at least 12 characters.</span>' : "") + '</label>' +
      '<p class="chat-create-error" id="chatAuthError" role="status">' + escapeHtml(error || "") + '</p>' +
      '<div class="chat-create-actions"><button class="btn btn-outline" type="button" data-auth-mode="' +
      (register ? "login" : "register") + '">' + (register ? "I already have an account" : "Create an account") +
      '</button><button class="btn btn-dark" type="submit">' + (register ? "Create account ↗" : "Sign in ↗") +
      '</button></div></form></div></div></section>';
  }

  function offlinePage() {
    return '<section class="messages-page"><div class="messages-heading"><div><div class="eyebrow">Artist-to-artist messages</div>' +
      '<h1>Your <em>messages.</em></h1><p>Private conversations and group chats.</p></div></div>' +
      '<div class="messages-preview-note"><span>✦</span><p><strong>Shared server required:</strong> open this site from its hosted server address to sign in and send messages.</p></div>' +
      '<div class="chat-empty"><span>♫</span><h2>The messaging server is not connected.</h2>' +
      '<p>This file preview has no shared accounts or online message storage. Deploy the server package and open its website address to use artist messaging.</p></div></section>';
  }

  function socketConnect() {
    if (socket) return;
    if (!window.io && apiBase) {
      if (!socketConnect.loading) {
        socketConnect.loading = true;
        var script = document.createElement("script");
        script.src = apiBase + "/socket.io/socket.io.js";
        script.onload = function () { socketConnect.loading = false; socketConnect(); };
        script.onerror = function () { socketConnect.loading = false; };
        document.head.appendChild(script);
      }
      return;
    }
    if (!window.io) return;
    socket = window.io(apiBase, { auth: { token: apiToken }, transports: ["websocket", "polling"] });
    socket.on("message:new", function (event) {
      if (event && document.querySelector(".messages-page")) renderMessages();
    });
    socket.on("connect_error", function () {});
  }

  async function renderMessages(error) {
    var version = ++renderVersion;
    root = document.getElementById("app");
    if (!root) return;
    setMessagesNav();
    root.innerHTML = '<section class="messages-page"><div class="chat-empty"><span>♫</span><h2>Opening your messages…</h2></div></section>';
    try {
      if (!serverReady) {
        await api("/health");
        serverReady = true;
      }
      if (user === null) {
        var account = await api("/auth/me");
        user = account.user;
      }
      if (version !== renderVersion) return;
      if (!user) {
        root.innerHTML = authPage(error);
        return;
      }
      socketConnect();
      var result = await Promise.all([api("/conversations"), api("/artists")]);
      conversations = result[0].conversations || [];
      artists = result[1].artists || [];
      if (!conversations.some(function (chat) { return chat.id === activeId; })) {
        activeId = conversations.length ? conversations[0].id : "";
      }
      var active = conversations.find(function (chat) { return chat.id === activeId; });
      var messages = [];
      if (active) {
        var storedMessages = (await api("/conversations/" + encodeURIComponent(active.id) + "/messages")).messages || [];
        messages = storedMessages;
      }
      if (version !== renderVersion) return;
      root.innerHTML = '<section class="messages-page"><div class="messages-heading"><div><div class="eyebrow">Make the next move together</div>' +
        '<h1>Your <em>messages.</em></h1><p>Direct conversations and group chats with UK artists.</p></div>' +
        '<div class="messages-actions"><button class="btn btn-outline" type="button" data-new-chat="direct">New message +</button>' +
        '<button class="btn btn-dark" type="button" data-new-chat="group">New group +</button></div></div>' +
        '<div class="messages-preview-note"><span>✦</span><p><strong>About messages:</strong> messages are stored on the shared server and visible to conversation members. They are sent over HTTPS but are not end-to-end encrypted.</p></div>' +
        '<div class="messages-layout"><aside class="chat-sidebar"><div class="chat-sidebar-title"><span>Conversations</span><span>' +
        conversations.length + '</span></div><div class="chat-list">' + conversationList() + '</div></aside>' +
        '<section class="chat-panel" aria-label="Conversation">' +
        (active ? messageThread(active, messages) : '<div class="chat-empty"><span>♫</span><h2>Your next link-up starts here.</h2>' +
          '<p>Choose an artist to message, or start a group chat for your next project.</p>' +
          '<div><button class="btn btn-outline" type="button" data-new-chat="direct">New message +</button>' +
          '<button class="btn btn-dark" type="button" data-new-chat="group">New group +</button></div></div>') +
        '</section></div><div class="chat-create-backdrop hidden" id="chatCreateBackdrop"></div>' +
        '<div class="chat-account-line">Signed in as ' + escapeHtml(user.displayName) +
        ' · <button type="button" data-chat-logout>Sign out</button> · ' +
        '<button type="button" data-delete-account>Delete account</button></div></section>';
      var thread = document.getElementById("chatThread");
      if (thread) thread.scrollTop = thread.scrollHeight;
    } catch (failure) {
      if (version !== renderVersion) return;
      if (!serverReady) {
        root.innerHTML = offlinePage();
      } else if (failure.status === 401) {
        user = null;
        authMode = "login";
        root.innerHTML = authPage("Your session ended. Sign in again to continue.");
      } else if (!user && serverReady) {
        root.innerHTML = authPage(error || failure.message);
      } else {
        root.innerHTML = '<section class="messages-page"><div class="messages-preview-note"><span>✦</span><p>' +
          escapeHtml(failure.message || "The message service is unavailable. Try again.") + '</p></div>' +
          '<button class="btn btn-outline" type="button" data-retry-messages>Try again</button></section>';
      }
    }
  }

  async function showCreator(mode) {
    if (!user) return renderMessages();
    try {
      artists = (await api("/artists")).artists || [];
      var backdrop = document.getElementById("chatCreateBackdrop");
      if (!backdrop) return;
      var group = mode === "group";
      var people = artists.map(function (artist) {
        return '<label class="chat-person-option"><input type="checkbox" name="participants" value="' +
          escapeHtml(artist.id) + '"><span class="chat-person-avatar">' +
          escapeHtml(initials(artist.displayName)) + '</span><span><strong>' +
          escapeHtml(artist.displayName) + '</strong><small>' + escapeHtml(artist.genre) +
          ' · ' + escapeHtml(artist.city) + '</small></span></label>';
      }).join("");
      backdrop.innerHTML = '<div class="chat-create-card" role="dialog" aria-modal="true" aria-labelledby="chatCreateTitle">' +
        '<button class="chat-create-close" type="button" aria-label="Close" data-close-chat-create>×</button>' +
        '<div class="eyebrow">' + (group ? "Make something together" : "Reach out directly") + '</div>' +
        '<h2 id="chatCreateTitle">' + (group ? "Start a group chat." : "Start a conversation.") + '</h2>' +
        '<p>' + (group ? "Bring collaborators into one project conversation." : "Choose an artist to open a direct conversation.") + '</p>' +
        '<form id="chatCreateForm" data-mode="' + (group ? "group" : "direct") + '">' +
        (group
          ? '<label class="chat-form-label" for="chatGroupName">Group name <span>optional</span></label>' +
            '<input class="chat-create-input" id="chatGroupName" name="groupName" maxlength="50" placeholder="e.g. Video shoot planning">' +
            '<div class="chat-form-label chat-select-label">Choose artists <span>Select at least one</span></div>' +
            '<div class="chat-people-list">' + (people || '<div class="chat-list-empty">No other artist accounts yet. Invite people to create an account first.</div>') + '</div>'
          : '<label class="chat-form-label" for="chatPerson">Choose an artist</label>' +
            '<select class="chat-create-input" id="chatPerson" name="person" required><option value="">Select someone in the network</option>' +
            artists.map(function (artist) {
              return '<option value="' + escapeHtml(artist.id) + '">' + escapeHtml(artist.displayName) +
                ' · ' + escapeHtml(artist.genre) + ' · ' + escapeHtml(artist.city) + '</option>';
            }).join("") + '</select>') +
        '<p class="chat-create-error" id="chatCreateError" role="status"></p><div class="chat-create-actions">' +
        '<button class="btn btn-outline" type="button" data-close-chat-create>Cancel</button>' +
        '<button class="btn btn-dark" type="submit">' + (group ? "Create group ↗" : "Open conversation ↗") +
        '</button></div></form></div>';
      backdrop.classList.remove("hidden");
      var focus = backdrop.querySelector(group ? "#chatGroupName" : "#chatPerson");
      if (focus) focus.focus();
    } catch (error) {
      notify(error.message);
    }
  }

  async function openDirect(personId) {
    if (!user) {
      pendingArtistId = personId;
      return renderMessages();
    }
    if (!/^\d+$/.test(String(personId))) {
      notify("Choose a signed-up artist account to start a shared conversation.");
      return showCreator("direct");
    }
    try {
      var result = await api("/conversations/direct", "POST", { artistId: Number(personId) });
      activeId = result.conversationId;
      if (socket) socket.emit("conversation:join", activeId);
      await renderMessages();
    } catch (error) {
      notify(error.message);
    }
  }

  async function submitAuth(form) {
    var data = Object.fromEntries(new FormData(form).entries());
    var mode = form.dataset.mode;
    try {
      var result = await api(mode === "register" ? "/auth/register" : "/auth/login", "POST", data);
      apiToken = result.token || "";
      if (apiToken) {
        try { sessionStorage.setItem("scenespoolApiToken", apiToken); } catch (_) {}
      }
      user = result.user;
      serverReady = true;
      socket = null;
      await renderMessages();
    } catch (error) {
      var errorNode = document.getElementById("chatAuthError");
      if (errorNode) errorNode.textContent = error.message;
    }
  }

  async function submitCreator(form) {
    var formData = new FormData(form);
    try {
      var result;
      if (form.dataset.mode === "direct") {
        var artistId = Number(formData.get("person"));
        if (!artistId) throw new Error("Choose an artist to continue.");
        result = await api("/conversations/direct", "POST", { artistId: artistId });
      } else {
        var participantIds = formData.getAll("participants").map(Number);
        if (!participantIds.length) throw new Error("Choose at least one artist for the group.");
        result = await api("/conversations/group", "POST", {
          name: String(formData.get("groupName") || "").trim(),
          participantIds: participantIds
        });
      }
      activeId = result.conversationId;
      if (socket) socket.emit("conversation:join", activeId);
      await renderMessages();
    } catch (error) {
      var errorNode = document.getElementById("chatCreateError");
      if (errorNode) errorNode.textContent = error.message;
    }
  }

  async function sendMessage(form) {
    var text = String(new FormData(form).get("message") || "").trim();
    if (!text) return;
    try {
      var chat = conversations.find(function (item) { return item.id === form.dataset.chatId; });
      if (!chat) throw new Error("Open the conversation again before sending a message.");
      await api("/conversations/" + encodeURIComponent(chat.id) + "/messages", "POST", { text: text, clientId: window.crypto.randomUUID() });
      await renderMessages();
      var composer = document.getElementById("chatMessageText");
      if (composer) composer.focus();
    } catch (error) {
      notify(error.message);
    }
  }

  async function logout() {
    try {
      await api("/auth/logout", "POST", {});
    } catch (_) {}
    if (socket) socket.disconnect();
    socket = null;
    apiToken = "";
    try { sessionStorage.removeItem("scenespoolApiToken"); } catch (_) {}
    user = null;
    conversations = [];
    activeId = "";
    authMode = "login";
    await renderMessages();
  }

  async function deleteAccount() {
    if (!window.confirm("Delete your account, public profile, tracks and messages sent from this account? This cannot be undone.")) return;
    var password = window.prompt("Enter your sign-in password to confirm account deletion.");
    if (!password) return;
    try {
      await api("/auth/account", "DELETE", { password: password });
      await logout();
    } catch (error) {
      notify(error.message || "Your account could not be deleted.");
    }
  }

  function closeCreator() {
    var backdrop = document.getElementById("chatCreateBackdrop");
    if (backdrop) backdrop.classList.add("hidden");
  }

  document.addEventListener("click", function (event) {
    var target = event.target;
    if (!target || !target.closest) return;
    var nav = target.closest('[data-view="messages"]');
    var message = target.closest("[data-message]");
    var open = target.closest("[data-open-chat]");
    var newChat = target.closest("[data-new-chat]");
    var close = target.closest("[data-close-chat-create]");
    var authToggle = target.closest("[data-auth-mode]");
    var logoutButton = target.closest("[data-chat-logout]");
    var deleteAccountButton = target.closest("[data-delete-account]");
    var retry = target.closest("[data-retry-messages]");
    var backdrop = target.id === "chatCreateBackdrop";
    if (!(nav || message || open || newChat || close || authToggle || logoutButton || deleteAccountButton || retry || backdrop)) return;
    event.preventDefault();
    event.stopImmediatePropagation();
    if (nav) return renderMessages();
    if (message) return openDirect(message.dataset.message);
    if (open) {
      activeId = open.dataset.openChat;
      return renderMessages();
    }
    if (newChat) return showCreator(newChat.dataset.newChat);
    if (close || backdrop) return closeCreator();
    if (authToggle) {
      authMode = authToggle.dataset.authMode;
      return renderMessages();
    }
    if (logoutButton) return logout();
    if (deleteAccountButton) return deleteAccount();
    if (retry) {
      serverReady = false;
      user = null;
      return renderMessages();
    }
  }, true);

  document.addEventListener("submit", function (event) {
    var form = event.target;
    if (!form || !form.id) return;
    if (form.id !== "chatAuthForm" && form.id !== "chatCreateForm" && form.id !== "chatComposeForm") return;
    event.preventDefault();
    event.stopImmediatePropagation();
    if (form.id === "chatAuthForm") return submitAuth(form);
    if (form.id === "chatCreateForm") return submitCreator(form);
    return sendMessage(form);
  }, true);

  document.addEventListener("keydown", function (event) {
    if (event.key === "Escape") closeCreator();
  }, true);

  window.SceneSpoolMessaging = {
    render: renderMessages,
    api: api,
    getToken: function () { return apiToken; },
    getUser: function () { return user; },
    refresh: function () { user = null; serverReady = false; return renderMessages(); }
  };
})();
