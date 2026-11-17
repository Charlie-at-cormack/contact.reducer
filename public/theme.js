// Runs before the page paints, so it never flashes the wrong theme. Light unless the person chose dark.
// Shared by the tracker and the agent's review page (same key on the same address).
(function () {
  var t = 'light';
  try { if (localStorage.getItem('cmk-theme') === 'dark') t = 'dark'; } catch (e) {}
  document.documentElement.setAttribute('data-theme', t);
})();
