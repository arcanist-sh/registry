// Runs in <head> before first paint: apply the saved colour scheme (same key and values as arcanist.sh).
(function () {
  var v = "auto";
  try { v = localStorage.getItem("tanuki-theme") || "auto"; } catch (e) {}
  if (v !== "light" && v !== "dark") v = "auto";
  var dark = v === "dark" || (v === "auto" && window.matchMedia("(prefers-color-scheme: dark)").matches);
  document.documentElement.setAttribute("data-theme", dark ? "dark" : "light");
  document.documentElement.setAttribute("data-theme-setting", v);
})();
