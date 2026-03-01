/* CYRBER — Global Configuration (cyrber-config.js)
   Package name mapping, shared constants. */
var PACKAGE_NAMES = {
  'SPECULATOR': { display: 'SCOUT',   subtitle: 'Speculator', color: '#6B7280' },
  'EXCUBITOR':  { display: 'GUARD',   subtitle: 'Excubitor',  color: '#3B82F6' },
  'HARUSPEX':   { display: 'AUGUR',   subtitle: 'Haruspex',   color: '#F59E0B' },
  'PRAEFECTUS': { display: 'COMMAND', subtitle: 'Praefectus', color: '#EF4444' }
};

function getPackageDisplay(packageKey) {
  var pkg = PACKAGE_NAMES[packageKey] || { display: packageKey || '—', subtitle: '', color: '#6B7280' };
  return pkg;
}

function renderPackageBadge(packageKey) {
  var pkg = getPackageDisplay(packageKey);
  return '<span class="pkg-name" style="color:' + pkg.color + '">' + pkg.display + '</span>' +
    (pkg.subtitle ? '<span class="pkg-subtitle">' + pkg.subtitle + '</span>' : '');
}
