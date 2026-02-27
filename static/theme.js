/* CYRBER Theme Toggle — load in <head> before <style> to prevent flash */
(function(){
  var stored = localStorage.getItem('cyrber_theme');
  var manual = localStorage.getItem('cyrber_theme_manual') === '1';
  var systemPref = window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';

  /* If user manually picked a theme, respect it. Otherwise follow system. */
  var theme = (manual && stored) ? stored : systemPref;
  document.documentElement.setAttribute('data-theme', theme);

  function updateIcon(t) {
    var icon = document.querySelector('.theme-toggle-icon');
    if (icon) icon.textContent = t === 'dark' ? '\u2600' : '\u263E';
  }

  function applyTheme(t) {
    document.documentElement.setAttribute('data-theme', t);
    localStorage.setItem('cyrber_theme', t);
    updateIcon(t);
  }

  /* Manual toggle — sets manual flag so system changes won't override */
  window.toggleTheme = function(){
    var current = document.documentElement.getAttribute('data-theme') || 'dark';
    var next = current === 'dark' ? 'light' : 'dark';
    localStorage.setItem('cyrber_theme_manual', '1');
    applyTheme(next);
  };

  /* Auto-switch: follow browser/OS theme when user hasn't manually overridden.
     Double-click the toggle to reset to auto mode. */
  window.resetThemeAuto = function(){
    localStorage.removeItem('cyrber_theme_manual');
    localStorage.removeItem('cyrber_theme');
    var sys = window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
    applyTheme(sys);
  };

  /* Listen for OS/browser theme changes */
  window.matchMedia('(prefers-color-scheme: light)').addEventListener('change', function(e) {
    if (localStorage.getItem('cyrber_theme_manual') !== '1') {
      applyTheme(e.matches ? 'light' : 'dark');
    }
  });

  document.addEventListener('DOMContentLoaded', function(){
    updateIcon(theme);
    /* Double-click theme toggle = reset to auto */
    var btn = document.querySelector('.theme-toggle');
    if (btn) btn.addEventListener('dblclick', function(){ window.resetThemeAuto(); });

    /* ── Dropdown navigation — click toggle ── */
    var navItems = document.querySelectorAll('.nav-item');
    navItems.forEach(function(item) {
      var trigger = item.querySelector('span, a');
      var dropdown = item.querySelector('.nav-dropdown');
      if (!dropdown || !trigger) return;

      trigger.addEventListener('click', function(e) {
        /* Only intercept top-level nav triggers, not dropdown links */
        if (e.target.closest('.nav-dropdown')) return;
        e.preventDefault();
        e.stopPropagation();

        /* Close all others */
        document.querySelectorAll('.nav-dropdown.open').forEach(function(d) {
          if (d !== dropdown) d.classList.remove('open');
        });

        dropdown.classList.toggle('open');
      });
    });

    /* Click outside closes all */
    document.addEventListener('click', function(e) {
      if (!e.target.closest('.cyrber-nav')) {
        document.querySelectorAll('.nav-dropdown.open').forEach(function(d) {
          d.classList.remove('open');
        });
      }
    });

    /* Escape closes all */
    document.addEventListener('keydown', function(e) {
      if (e.key === 'Escape') {
        document.querySelectorAll('.nav-dropdown.open').forEach(function(d) {
          d.classList.remove('open');
        });
      }
    });
  });
})();
