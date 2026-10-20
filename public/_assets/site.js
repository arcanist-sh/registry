// registry.arcanist.sh page behaviour: the footer colour-scheme switch, copy buttons, and closing header menus.
// Everything works without this script; it only adds conveniences.
(function () {
  var root = document.documentElement;
  var KEY = "tanuki-theme";
  var mq = window.matchMedia("(prefers-color-scheme: dark)");

  function current() {
    try { var s = localStorage.getItem(KEY); return s === "light" || s === "dark" ? s : "auto"; } catch (e) { return "auto"; }
  }
  function apply(v) {
    root.setAttribute("data-theme", v === "auto" ? (mq.matches ? "dark" : "light") : v);
    root.setAttribute("data-theme-setting", v);
  }

  var scheme = document.querySelector(".scheme");
  if (scheme) {
    var paint = function () {
      var c = current();
      scheme.querySelectorAll("button").forEach(function (b) { b.setAttribute("aria-pressed", String(b.getAttribute("data-scheme") === c)); });
    };
    scheme.addEventListener("click", function (e) {
      var b = e.target.closest("button");
      if (!b) return;
      var v = b.getAttribute("data-scheme");
      try { if (v === "auto") localStorage.removeItem(KEY); else localStorage.setItem(KEY, v); } catch (err) {}
      apply(v);
      paint();
    });
    mq.addEventListener("change", function () { if (current() === "auto") apply("auto"); });
    scheme.hidden = false;
    paint();
  }

  // Copy buttons: <button class="copy" data-copy="id-of-pre">
  document.querySelectorAll("[data-copy]").forEach(function (btn) {
    var el = document.getElementById(btn.getAttribute("data-copy"));
    if (!el || !navigator.clipboard) return;
    btn.hidden = false;
    btn.addEventListener("click", function () {
      navigator.clipboard.writeText(el.textContent.replace(/\n$/, "")).then(function () {
        btn.textContent = "Copied";
        setTimeout(function () { btn.textContent = "Copy"; }, 1400);
      });
    });
  });

  // Header menus are <details>; close them on outside click and Escape.
  var groups = document.querySelectorAll(".nav__group");
  document.addEventListener("click", function (e) {
    groups.forEach(function (g) { if (!g.contains(e.target)) g.removeAttribute("open"); });
  });
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape") groups.forEach(function (g) { g.removeAttribute("open"); });
  });
})();
