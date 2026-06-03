/* MalGuard — frontend logikasi */
(function () {
    "use strict";

    // ── Mobil menyu ──
    var toggle = document.getElementById("navToggle");
    var links = document.getElementById("navLinks");
    if (toggle && links) {
        toggle.addEventListener("click", function () {
            links.classList.toggle("open");
        });
    }

    // ── CSRF cookie o'qish ──
    function getCookie(name) {
        var value = "; " + document.cookie;
        var parts = value.split("; " + name + "=");
        if (parts.length === 2) return parts.pop().split(";").shift();
        return "";
    }

    // ── Upload bloki ──
    var dz = document.getElementById("dropzone");
    if (!dz) return;

    var input = document.getElementById("fileInput");
    var chip = document.getElementById("fileChip");
    var chipName = document.getElementById("fileChipName");
    var scanBtn = document.getElementById("scanBtn");
    var resultBox = document.getElementById("resultBox");
    var uploadBox = document.getElementById("uploadBox");
    var maxMb = parseInt(dz.dataset.maxMb || "32", 10);
    var selectedFile = null;

    dz.addEventListener("click", function () { input.click(); });

    ["dragenter", "dragover"].forEach(function (ev) {
        dz.addEventListener(ev, function (e) { e.preventDefault(); dz.classList.add("dragover"); });
    });
    ["dragleave", "drop"].forEach(function (ev) {
        dz.addEventListener(ev, function (e) { e.preventDefault(); dz.classList.remove("dragover"); });
    });
    dz.addEventListener("drop", function (e) {
        if (e.dataTransfer.files.length) setFile(e.dataTransfer.files[0]);
    });
    input.addEventListener("change", function () {
        if (input.files.length) setFile(input.files[0]);
    });

    function setFile(file) {
        if (file.size > maxMb * 1024 * 1024) {
            alert("Fayl juda katta. Maksimal hajm: " + maxMb + " MB.");
            return;
        }
        selectedFile = file;
        chipName.textContent = file.name + "  (" + humanSize(file.size) + ")";
        chip.classList.add("show");
        scanBtn.disabled = false;
    }

    function humanSize(b) {
        var u = ["B", "KB", "MB", "GB"]; var i = 0;
        while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
        return b.toFixed(1) + " " + u[i];
    }

    scanBtn.addEventListener("click", function () {
        if (!selectedFile) return;
        startScan(selectedFile);
    });

    function startScan(file) {
        // Yuklash holatini ko'rsatish
        uploadBox.style.display = "none";
        resultBox.style.display = "block";
        resultBox.innerHTML =
            '<div class="card card-glow"><div class="card-body text-center" style="padding:3rem 1.5rem">' +
            '<div class="spinner mb-3"></div>' +
            '<h3>Fayl tekshirilmoqda...</h3>' +
            '<p class="text-dim">VirusTotal · Hybrid Analysis · MalwareBazaar manbalari so\'rovlanmoqda. ' +
            'Bu bir necha soniya davom etishi mumkin.</p>' +
            '</div></div>';

        var fd = new FormData();
        fd.append("file", file);

        fetch(SCAN_URL, {
            method: "POST",
            headers: { "X-CSRFToken": getCookie("csrftoken") },
            body: fd,
        })
            .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, data: d }; }); })
            .then(function (res) {
                if (res.ok && res.data.success) {
                    renderResult(res.data);
                } else {
                    renderError(res.data.error || "Noma'lum xatolik");
                }
            })
            .catch(function () { renderError("Server bilan bog'lanib bo'lmadi."); });
    }

    function renderResult(d) {
        var lvl = d.verdict || "unknown";
        var bar = Math.max(0, Math.min(100, d.danger_score || 0));
        resultBox.innerHTML =
            '<div class="card card-glow">' +
            '<div class="card-header"><i class="bi bi-clipboard-check"></i> TEKSHIRUV NATIJASI</div>' +
            '<div class="card-body">' +
            '<div class="text-center mb-3">' +
            '<div style="font-size:3rem">' + (d.verdict_emoji || "⚪") + '</div>' +
            '<span class="verdict verdict-' + lvl + '">' + (d.verdict_label || "Noma\'lum") + '</span>' +
            '</div>' +
            '<div class="mb-1"><b>Xavf darajasi: ' + bar + '/100</b></div>' +
            '<div class="meter mb-3"><div class="meter-fill lvl-' + lvl + '" style="width:' + bar + '%"></div></div>' +
            '<pre>' + escapeHtml(d.summary || "") + '</pre>' +
            '<div class="text-center mt-3">' +
            '<a href="' + d.result_url + '" class="btn btn-primary"><i class="bi bi-file-earmark-text"></i> Batafsil hisobot</a> ' +
            '<button class="btn btn-outline" onclick="location.reload()"><i class="bi bi-arrow-repeat"></i> Yangi fayl</button>' +
            '</div></div></div>';
    }

    function renderError(msg) {
        resultBox.innerHTML =
            '<div class="card card-glow"><div class="card-body text-center" style="padding:2.5rem 1.5rem">' +
            '<div style="font-size:2.6rem">⚠️</div>' +
            '<h3 class="text-red">Xatolik</h3>' +
            '<p class="text-dim">' + escapeHtml(msg) + '</p>' +
            '<button class="btn btn-outline mt-2" onclick="location.reload()"><i class="bi bi-arrow-repeat"></i> Qaytadan urinish</button>' +
            '</div></div>';
    }

    function escapeHtml(s) {
        return (s || "").replace(/[&<>"']/g, function (c) {
            return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
        });
    }
})();
