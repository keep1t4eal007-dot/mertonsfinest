(function () {
  "use strict";

  var defaultApiUrl = /(^localhost$|^127\.0\.0\.1$|\.onrender\.com$)/i.test(window.location.hostname) ? window.location.origin : "";
  var apiUrl = String(window.SCENESPOOL_API_URL || defaultApiUrl).replace(/\/$/, "");
  var remoteTracks = [];
  var loaded = false;

  function esc(value) {
    return String(value == null ? "" : value).replace(/[&<>"']/g, function (char) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[char];
    });
  }

  function initials(value) {
    return String(value || "").split(/\s+/).map(function (part) { return part[0] || ""; }).join("").slice(0, 2).toUpperCase();
  }

  function personFromApi(person) {
    return {
      id: "artist-" + person.id,
      serverId: String(person.id),
      name: person.displayName,
      handle: person.handle ? "@" + String(person.handle).replace(/^@/, "") : "",
      genre: person.genre,
      city: person.city,
      looking: person.looking || "",
      bio: person.bio || "",
      color: person.color || "#d8e4d2",
      photo: person.photo || "",
      initials: initials(person.displayName)
    };
  }

  function updateRadio(tracks) {
    if (typeof radioTracks === "undefined" || !Array.isArray(radioTracks)) return;
    var fixed = radioTracks.filter(function (track) { return !track.selfHosted; });
    var uploaded = tracks.map(function (track) {
      return {
        id: "upload-" + track.id,
        title: track.title,
        artist: track.artistName,
        genre: track.genre || "UK artist upload",
        selfHosted: true,
        audioUrl: apiUrl + track.audioUrl
      };
    });
    radioTracks.splice(0, radioTracks.length, ...fixed, ...uploaded);
    if (typeof radioQueue !== "undefined") radioQueue = [];
    var label = document.querySelector(".radio-label");
    if (label) label.textContent = "UK DISCOVERY ROTATION · " + radioTracks.length + " TRACKS";
  }

  async function refreshDirectoryAndMusic() {
    if (!apiUrl || !window.SceneSpoolMessaging) return;
    var api = window.SceneSpoolMessaging.api;
    var results = await Promise.all([api("/artists"), api("/tracks")]);
    window.SceneSpoolSharedProfiles = (results[0].artists || []).map(personFromApi);
    remoteTracks = results[1].tracks || [];
    updateRadio(remoteTracks);
    loaded = true;
    if (document.querySelector("#directoryMembers") || document.querySelector("#members")) {
      if (typeof window.render === "function") window.render();
    }
  }

  function formatDuration(value) {
    var seconds = Math.max(0, Math.floor(Number(value) || 0));
    return Math.floor(seconds / 60) + ":" + String(seconds % 60).padStart(2, "0");
  }

  function currentArtistId() {
    return Number(window.SceneSpoolMessaging && window.SceneSpoolMessaging.getUser()?.id || 0);
  }

  function renderMusicShelf() {
    var list = document.getElementById("musicTrackList");
    if (!list) return;
    var currentId = currentArtistId();
    var count = document.getElementById("musicTrackCount");
    if (count) count.textContent = remoteTracks.length + (remoteTracks.length === 1 ? " TRACK" : " TRACKS") + " · 10:00 MAX";
    list.innerHTML = remoteTracks.length ? remoteTracks.map(function (track) {
      var own = currentId && Number(track.artistId) === currentId;
      var url = apiUrl + track.audioUrl;
      return '<article class="music-track"><div><div class="music-track-title">' + esc(track.title) + '</div>' +
        '<div class="music-track-meta">' + formatDuration(track.duration) + ' · ' + esc(track.artistName) + ' · ' + esc(track.fileName || "Audio track") + '</div></div>' +
        (own ? '<button class="music-track-remove" type="button" data-remove-track="' + esc(track.id) + '">Remove</button>' : '') +
        '<audio controls preload="none" src="' + esc(url) + '" aria-label="Play ' + esc(track.title) + ' by ' + esc(track.artistName) + '"></audio></article>';
    }).join("") : '<div class="music-empty">No artist uploads yet. Add the first track to start the shared shelf.</div>';
    var help = document.querySelector(".music-upload-help");
    if (help) help.textContent = "Tracks up to 10 minutes are shared with the community. Sign in through Messages to upload. Files are limited to 20 MB; the shared shelf has a storage cap.";
  }

  async function saveProfile(form) {
    var error = document.getElementById("profileFormError");
    error.textContent = "";
    var messaging = window.SceneSpoolMessaging;
    if (!messaging || !messaging.getToken()) {
      error.textContent = "Sign in or create an artist account in Messages before publishing a shared profile.";
      return;
    }
    var fields = new FormData(form);
    var photo = clearPhotoOnSave ? "" : (draftPhotoData || "");
    var file = document.getElementById("artistPhoto")?.files?.[0];
    if (file) {
      try { photo = await imageToDataURL(file); }
      catch (failure) { error.textContent = failure.message || "That photo could not be prepared."; return; }
    }
    var name = String(fields.get("name") || "").trim();
    var handle = String(fields.get("handle") || "").trim().replace(/^@/, "");
    if (!handle) handle = name.toLowerCase().replace(/[^a-z0-9]+/g, "").slice(0, 24);
    try {
      var result = await messaging.api("/artists/me", "PATCH", {
        displayName: name,
        handle: handle,
        genre: String(fields.get("genre") || "").trim(),
        city: String(fields.get("city") || "").trim(),
        looking: String(fields.get("looking") || "").trim(),
        bio: String(fields.get("bio") || "").trim(),
        color: String(fields.get("color") || "#d8e4d2"),
        photo: photo
      });
      var saved = personFromApi(result.artist);
      window.SceneSpoolSharedProfiles = (window.SceneSpoolSharedProfiles || []).filter(function (person) {
        return person.serverId !== saved.serverId;
      }).concat(saved);
      form.reset();
      closeModal();
      draftPhotoData = "";
      clearPhotoOnSave = false;
      if (typeof goView === "function") goView("directory");
      if (typeof showToast === "function") showToast("Your artist profile is now shared with the community.");
      await refreshDirectoryAndMusic();
    } catch (failure) {
      error.textContent = failure.message || "Your profile could not be saved. Please try again.";
    }
  }

  async function saveTrack(form) {
    var status = document.getElementById("musicUploadStatus");
    var button = document.getElementById("saveTrackButton");
    var input = document.getElementById("musicFile");
    var file = input && input.files && input.files[0];
    var messaging = window.SceneSpoolMessaging;
    if (!messaging || !messaging.getToken()) {
      status.textContent = "Sign in or create an artist account in Messages before uploading a shared track.";
      status.classList.add("error");
      return;
    }
    if (!file || selectedTrackDuration == null || selectedTrackDuration > 600) {
      status.textContent = "Choose an audio file that is 10 minutes or shorter.";
      status.classList.add("error");
      return;
    }
    if (file.size > 20 * 1024 * 1024) {
      status.textContent = "Each track must be 20 MB or smaller.";
      status.classList.add("error");
      return;
    }
    button.disabled = true;
    status.classList.remove("error");
    status.textContent = "Uploading your track to the shared shelf…";
    try {
      var title = String(document.getElementById("musicTrackName").value || "").trim();
      await messaging.api("/tracks?title=" + encodeURIComponent(title), "POST", file, {
        "X-File-Name": encodeURIComponent(file.name)
      });
      form.reset();
      selectedTrackDuration = null;
      status.textContent = "Your track is now available to artists across the community.";
      await refreshDirectoryAndMusic();
      renderMusicShelf();
    } catch (failure) {
      status.textContent = failure.message || "Your track could not be uploaded. Please try again.";
      status.classList.add("error");
    } finally {
      button.disabled = false;
    }
  }

  async function removeTrack(id) {
    try {
      await window.SceneSpoolMessaging.api("/tracks/" + encodeURIComponent(id), "DELETE", {});
      remoteTracks = remoteTracks.filter(function (track) { return track.id !== id; });
      renderMusicShelf();
      updateRadio(remoteTracks);
    } catch (failure) {
      var status = document.getElementById("musicUploadStatus");
      if (status) {
        status.textContent = failure.message || "This track could not be removed.";
        status.classList.add("error");
      }
    }
  }

  var originalPlayRadioTrack = typeof window.playRadioTrack === "function" ? window.playRadioTrack : null;
  if (originalPlayRadioTrack) {
    window.playRadioTrack = async function (index, autoplay) {
      var track = radioTracks[index];
      var audio = document.getElementById("artistRadioAudio");
      var frame = document.getElementById("radioFrame");
      if (!track || !track.selfHosted) {
        if (audio) { audio.pause(); audio.classList.add("hidden"); }
        if (frame) frame.style.display = "block";
        return originalPlayRadioTrack(index, autoplay);
      }
      if (typeof autoplay === "undefined") autoplay = true;
      if (!audio) {
        audio = document.createElement("audio");
        audio.id = "artistRadioAudio";
        audio.controls = true;
        audio.className = "artist-radio-audio";
        audio.style.width = "100%";
        document.querySelector(".radio-frame-wrap").appendChild(audio);
        audio.addEventListener("ended", function () { window.playRadioTrack(nextRadioIndex(), true); });
        audio.addEventListener("play", function () { radioIsPlaying = true; updateRadioLabels(radioIndex); });
        audio.addEventListener("pause", function () { radioIsPlaying = false; updateRadioLabels(radioIndex); });
      }
      if (radioWidget) radioWidget.pause();
      if (typeof radioIndex !== "undefined" && radioIndex >= 0 && radioIndex !== index) radioHistory.push(radioIndex);
      radioHistory = radioHistory.slice(-20);
      radioIndex = index;
      radioIsPlaying = Boolean(autoplay);
      document.getElementById("radioUnavailable").classList.add("hidden");
      updateRadioLabels(index);
      if (frame) frame.style.display = "none";
      audio.classList.remove("hidden");
      if (audio.src !== track.audioUrl) audio.src = track.audioUrl;
      if (autoplay) await audio.play().catch(function () {});
      else audio.pause();
    };
  }

  document.addEventListener("submit", function (event) {
    if (event.target && event.target.id === "profileForm") {
      event.preventDefault();
      event.stopImmediatePropagation();
      saveProfile(event.target);
    } else if (event.target && event.target.id === "musicUploadForm") {
      event.preventDefault();
      event.stopImmediatePropagation();
      saveTrack(event.target);
    }
  }, true);

  document.addEventListener("click", function (event) {
    var button = event.target.closest("[data-remove-track]");
    if (!button) return;
    event.preventDefault();
    event.stopImmediatePropagation();
    removeTrack(button.dataset.removeTrack);
  }, true);

  window.renderMusicShelf = renderMusicShelf;
  window.SceneSpoolLiveFeatures = {
    refresh: refreshDirectoryAndMusic,
    renderMusicShelf: renderMusicShelf,
    saveProfile: saveProfile,
    loaded: function () { return loaded; }
  };

  if (apiUrl) {
    refreshDirectoryAndMusic().then(renderMusicShelf).catch(function () {
      var status = document.getElementById("musicUploadStatus");
      if (status) {
        status.textContent = "The shared music server is connecting. Try again shortly.";
        status.classList.add("error");
      }
    });
  }
})();
