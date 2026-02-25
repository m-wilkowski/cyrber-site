/* CYRBER Theme Toggle — load in <head> before <style> to prevent flash */
(function(){
  var stored = localStorage.getItem('cyrber_theme');
  var theme = stored || (window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
  document.documentElement.setAttribute('data-theme', theme);

  window.toggleTheme = function(){
    var current = document.documentElement.getAttribute('data-theme') || 'dark';
    var next = current === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('cyrber_theme', next);
    var icon = document.querySelector('.theme-toggle-icon');
    if(icon) icon.textContent = next === 'dark' ? '\u2600' : '\u263E';
  };

  document.addEventListener('DOMContentLoaded', function(){
    var icon = document.querySelector('.theme-toggle-icon');
    if(icon) icon.textContent = theme === 'dark' ? '\u2600' : '\u263E';
  });
})();
