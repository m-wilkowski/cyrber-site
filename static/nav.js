/* CYRBER — Shared Navigation (nav.js)
   Dual mode: Expert (EN + latin) / Client (PL)
   Renders into #cyrber-nav-root, manages dropdowns, auth, theme toggle. */
(function() {
  'use strict';

  /* ── EXPERT NAV (operator/admin default) ── */
  var EXPERT_NAV = [
    { id: 'missions', label: 'MISSIONS', items: [
      { label: 'Operations', type: 'label' },
      { href: '/overview',  text: '\u25C6 Overview' },
      { href: '/missions',  text: '\u2605 Missions' },
      { href: '/dashboard', text: '\uD83D\uDCCA Dashboard' },
      { href: '/theatrum',  text: '\uD83C\uDFAF Theatrum' },
      { href: '/scheduler', text: '\u23F0 Scheduler' }
    ]},
    { id: 'ratio', label: 'RATIO', items: [
      { label: 'Infrastructure \u00B7 Code \u00B7 CVE', type: 'label' },
      { href: '/scan',     text: '\uD83D\uDD0D Scan' },
      { href: '/findings', text: '\uD83D\uDCCC Findings' },
      { href: '/topology', text: '\uD83D\uDDFA Topology' },
      { href: '/osint',    text: '\uD83C\uDF10 OSINT' },
      { href: '/verify',   text: '\u2713 Verify' }
    ]},
    { id: 'animus', label: 'ANIMUS', items: [
      { label: 'People \u00B7 Habits \u00B7 Behaviour', type: 'label' },
      { href: '/phishing', text: '\uD83C\uDFA3 Phishing' }
    ]},
    { id: 'fatum', label: 'FATUM', items: [
      { label: 'History \u00B7 Context \u00B7 Physical', type: 'label' },
      { href: '/hardware', text: '\u26A1 Hardware Bridge' }
    ]},
    { id: 'mirror', label: 'MIRROR', items: [
      { label: 'Organization Intelligence', type: 'label' },
      { href: '/mirror', text: '\uD83E\uDDEC Security Genome' }
    ]},
    { id: 'proof', label: 'PROOF', items: [
      { label: 'Audit \u00B7 Compliance \u00B7 Insurance', type: 'label' },
      { href: '/proof',       text: '\uD83D\uDD12 Living Proof' },
      { href: '/compliance',  text: '\u2696 Compliance' },
      { href: '/proof#feed',  text: '\uD83D\uDCE1 Insurance Feed' }
    ]},
    { id: 'chronicle', label: 'CHRONICLE', items: [
      { label: 'Probabilistic Future', type: 'label' },
      { href: '/chronicle',       text: '\uD83D\uDCC5 30/60/90 Forecast' },
      { href: '/chronicle#peers', text: '\uD83D\uDC65 Sector Peers <span class="dropdown-badge soon">Q4 2026</span>' },
      { href: '/chronicle#apt',   text: '\uD83C\uDFDB APT Correlation <span class="dropdown-badge soon">Q4 2026</span>' }
    ]}
  ];

  var EXPERT_PATH_MAP = {
    '/overview': 'missions', '/missions': 'missions', '/dashboard': 'missions',
    '/theatrum': 'missions', '/scheduler': 'missions', '/mission-control': 'missions',
    '/command-center': 'missions', '/admin': 'missions', '/organizations': 'missions',
    '/ui': 'ratio', '/scan': 'ratio', '/findings': 'ratio', '/topology': 'ratio',
    '/osint': 'ratio', '/verify': 'ratio',
    '/phishing': 'animus',
    '/hardware': 'fatum',
    '/mirror': 'mirror',
    '/proof': 'proof', '/compliance': 'proof',
    '/chronicle': 'chronicle'
  };

  /* ── CLIENT NAV (viewer default, PL) ── */
  var CLIENT_NAV = [
    { id: 'cl-overview', href: '/overview',   text: 'PRZEGL\u0104D' },
    { id: 'cl-missions', label: 'MISJE', items: [
      { href: '/missions', text: 'Nowa misja' },
      { href: '/theatrum', text: 'Theatrum Belli' }
    ]},
    { id: 'cl-findings',   href: '/findings',   text: 'ZAGRO\u017BENIA' },
    { id: 'cl-compliance', href: '/compliance',  text: 'COMPLIANCE' },
    { id: 'cl-reports',   href: '/reports',     text: 'RAPORTY' }
  ];

  var CLIENT_PATH_MAP = {
    '/overview': 'cl-overview',
    '/missions': 'cl-missions', '/theatrum': 'cl-missions',
    '/findings': 'cl-findings',
    '/compliance': 'cl-compliance',
    '/reports': 'cl-reports'
  };

  /* ── STATE ── */
  var _navMode = null;   // 'expert' | 'client'
  var _userRole = null;  // from /auth/me
  var _isOperator = false;
  var _username = '\u2014';
  var _dropdownsInitOnce = false;

  /* ── HELPERS ── */
  function getToken() { return localStorage.getItem('cyrber_token'); }

  function resolveMode() {
    var stored = localStorage.getItem('cyrber_nav_mode');
    if (stored === 'expert' || stored === 'client') return stored;
    // default by role
    if (_userRole === 'admin' || _userRole === 'operator' || _isOperator) return 'expert';
    return 'client';
  }

  /* ── RENDER ── */
  function buildExpertNav() {
    var path = window.location.pathname;
    var activeSection = EXPERT_PATH_MAP[path];
    // scan detail prefix fallback
    if (!activeSection && path.indexOf('/scan/') === 0) activeSection = 'ratio';

    var html = '';
    for (var i = 0; i < EXPERT_NAV.length; i++) {
      var sec = EXPERT_NAV[i];
      var cls = 'nav-item ' + sec.id;
      if (sec.id === activeSection) cls += ' active';
      html += '<div class="' + cls + '">';
      html += '<span>' + sec.label + ' &#9662;</span>';
      html += '<div class="nav-dropdown">';
      for (var j = 0; j < sec.items.length; j++) {
        var it = sec.items[j];
        if (it.type === 'label') {
          html += '<div class="dropdown-label">' + it.label + '</div>';
        } else {
          html += '<a href="' + it.href + '">' + it.text + '</a>';
        }
      }
      html += '</div></div>';
    }
    return html;
  }

  function buildClientNav() {
    var path = window.location.pathname;
    var activeId = CLIENT_PATH_MAP[path];

    var html = '';
    for (var i = 0; i < CLIENT_NAV.length; i++) {
      var item = CLIENT_NAV[i];
      var cls = 'nav-item client-item ' + item.id;
      if (item.id === activeId) cls += ' active';

      if (item.items) {
        // dropdown
        html += '<div class="' + cls + '">';
        html += '<span>' + item.label + ' &#9662;</span>';
        html += '<div class="nav-dropdown">';
        for (var j = 0; j < item.items.length; j++) {
          html += '<a href="' + item.items[j].href + '">' + item.items[j].text + '</a>';
        }
        html += '</div></div>';
      } else {
        // direct link
        html += '<div class="' + cls + '">';
        html += '<a href="' + item.href + '">' + item.text + '</a>';
        html += '</div>';
      }
    }
    return html;
  }

  function render() {
    var root = document.getElementById('cyrber-nav-root');
    if (!root) return;

    var isClient = (_navMode === 'client');
    var navClass = 'cyrber-nav' + (isClient ? ' cyrber-nav-client' : '');
    var linksHtml = isClient ? buildClientNav() : buildExpertNav();

    // toggle button
    var toggleHtml;
    if (isClient) {
      toggleHtml = '<button class="nav-mode-toggle nav-mode-expert" onclick="_cyrberToggleNav()" title="Tryb eksperta">\u2699 Expert</button>';
    } else {
      toggleHtml = '<button class="nav-mode-toggle nav-mode-client" onclick="_cyrberToggleNav()" title="Tryb klienta">\u2190 Klient</button>';
    }

    // right panel
    var rightHtml = '<div style="display:flex;align-items:center;gap:10px;margin-left:auto;flex-shrink:0;">'
      + toggleHtml
      + '<button class="theme-toggle" onclick="toggleTheme()" title="Toggle theme"><span class="theme-toggle-icon"></span></button>'
      + '<span id="nav-username" style="font-family:\'Share Tech Mono\',monospace;font-size:12px;color:var(--text-muted);">' + _username + '</span>'
      + '<a href="/organizations" class="nav-admin-icon" id="operatorNavLink" title="Operator Panel" style="' + ((_isOperator || _userRole === 'admin') ? '' : 'display:none;') + '">&#9881;</a>'
      + '<a href="/admin" class="nav-admin-icon" id="adminNavLink" title="Admin" style="' + (_userRole === 'admin' ? '' : 'display:none;') + '">&#9881;</a>'
      + '<a href="#" onclick="localStorage.removeItem(\'cyrber_token\');localStorage.removeItem(\'cyrber_user\');window.location.href=\'/login\'" style="color:var(--red);font-size:11px;text-decoration:none;letter-spacing:.08em;font-family:\'Share Tech Mono\',monospace;">LOGOUT</a>'
      + '</div>';

    root.innerHTML = '<nav class="' + navClass + '">'
      + '<a href="/overview" class="nav-logo">'
      + '<img src="/static/logo.jpg" alt="CYRBER">'
      + '<span class="nav-logo-text">CYRBER</span>'
      + '</a>'
      + '<div class="nav-links">' + linksHtml + '</div>'
      + rightHtml
      + '</nav>';

    // re-init dropdowns
    _dropdownsInitOnce = false;
    initDropdowns();

    // update theme icon
    if (typeof updateThemeIcon === 'function') updateThemeIcon();
  }

  /* ── TOGGLE ── */
  window._cyrberToggleNav = function() {
    _navMode = (_navMode === 'expert') ? 'client' : 'expert';
    localStorage.setItem('cyrber_nav_mode', _navMode);
    render();
  };

  /* ── DROPDOWNS ── */
  function initDropdowns() {
    if (_dropdownsInitOnce) return;
    _dropdownsInitOnce = true;

    var items = document.querySelectorAll('.nav-item');
    items.forEach(function(item) {
      var trigger = item.querySelector('span');
      var dropdown = item.querySelector('.nav-dropdown');
      if (!trigger || !dropdown) return;
      trigger.style.cursor = 'pointer';
      trigger.style.userSelect = 'none';
      trigger.addEventListener('click', function(e) {
        e.stopPropagation();
        e.preventDefault();
        var allDD = document.querySelectorAll('.nav-dropdown');
        var isOpen = dropdown.style.display === 'block';
        allDD.forEach(function(d) { d.style.display = 'none'; });
        if (!isOpen) {
          var rect = trigger.getBoundingClientRect();
          dropdown.style.display = 'block';
          dropdown.style.left = rect.left + 'px';
          dropdown.style.top = '56px';
        }
      });
    });
    document.addEventListener('click', function() {
      document.querySelectorAll('.nav-dropdown').forEach(function(d) {
        d.style.display = 'none';
      });
    });
    document.addEventListener('keydown', function(e) {
      if (e.key === 'Escape') {
        document.querySelectorAll('.nav-dropdown').forEach(function(d) {
          d.style.display = 'none';
        });
      }
    });
  }

  /* ── INIT ── */
  function initNav() {
    var token = getToken();

    // Sync render with placeholder username
    _navMode = resolveMode();
    render();

    if (!token) return;

    // Async: fetch user info and update
    fetch('/auth/me', { headers: { 'Authorization': 'Bearer ' + token } })
      .then(function(r) { return r.json(); })
      .then(function(u) {
        _username = u.username || '';
        _userRole = u.role || null;
        _isOperator = !!u.is_operator;
        localStorage.setItem('cyrber_user', _username);

        // Re-resolve mode (role may change default)
        var stored = localStorage.getItem('cyrber_nav_mode');
        if (!stored) _navMode = resolveMode();

        render();
      })
      .catch(function() {});
  }

  // Run immediately (script is loaded sync in body)
  initNav();
})();
